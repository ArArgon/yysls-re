"""
HD payload encodings -- there are two, and a decoder must auto-detect.

See docs/hd-store.md section 5. Merged from two parallel modules with identical
helper sets; the dialect is now a flag rather than a separate implementation.

  TLV  tag/length/value, nested objects and arrays. Starts with 0x0a or 0x09.
  FTV  a flat stream of (field_id, type_code, payload).

The two type tables are NOT the same numbering -- 0x04 is u64 in TLV and u8 in
FTV. They are kept strictly separate below.

Post-zstd payloads are not encrypted; strings are readable. The strings are the
point: many are canonical VFS paths (see `collect_path_candidates`).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterator

# --- TLV tags ---------------------------------------------------------------
TLV_OBJECT = 0x0A
TLV_ARRAY = 0x09
TLV_STRING = 0x08
TLV_BYTES = 0x28
TLV_U8, TLV_U16, TLV_U32, TLV_U64 = 0x01, 0x02, 0x03, 0x04
TLV_F32, TLV_F64 = 0x05, 0x06
TLV_NULL, TLV_FALSE, TLV_TRUE = 0x0B, 0x0C, 0x0D
TLV_PADDING = 0x00

# --- FTV type codes (a DIFFERENT numbering) ---------------------------------
FTV_FALSE, FTV_TRUE = 0x00, 0x01
FTV_U16, FTV_U8 = 0x02, 0x04
FTV_U32, FTV_U64 = 0x0C, 0x10
FTV_F32, FTV_F64 = 0x14, 0x18
FTV_STRING = 0x20
FTV_INNER_ARRAY = 0x24

# Graph-like payloads open with this 8-byte header. It can also REAPPEAR
# mid-payload separating token groups, so treat it as a group separator.
GRAPH_HEADER_LEN = 8
_GRAPH_W0, _GRAPH_W1, _GRAPH_W3 = 0x0003, 0x2800, 0x0101


class Dialect(str, Enum):
    TLV = "tlv"
    FTV = "ftv"


class PayloadError(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    tag: int
    kind: str
    offset: int
    size: int
    value: Any
    field_id: int | None = None  # FTV only


def _u16(buf: bytes, off: int) -> int:
    if off + 2 > len(buf):
        raise PayloadError(f"EOF reading u16 at {off}")
    return struct.unpack_from("<H", buf, off)[0]


def _fixed(buf: bytes, off: int, fmt: str, size: int, what: str):
    if off + size > len(buf):
        raise PayloadError(f"EOF reading {what} at {off}")
    return struct.unpack_from(fmt, buf, off)[0]


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------


def has_graph_header(buf: bytes, off: int = 0) -> bool:
    if off + GRAPH_HEADER_LEN > len(buf):
        return False
    w0, w1, _, w3 = struct.unpack_from("<HHHH", buf, off)
    return w0 == _GRAPH_W0 and w1 == _GRAPH_W1 and w3 == _GRAPH_W3


def detect_dialect(buf: bytes) -> Dialect:
    """
    Pick the dialect from the first byte, skipping any graph header.

    TLV payloads open with a container tag; anything else is FTV.
    """
    off = GRAPH_HEADER_LEN if has_graph_header(buf) else 0
    if off < len(buf) and buf[off] in (TLV_OBJECT, TLV_ARRAY):
        return Dialect.TLV
    return Dialect.FTV


# --------------------------------------------------------------------------
# TLV
# --------------------------------------------------------------------------


def parse_tlv_token(buf: bytes, off: int) -> tuple[Token, int]:
    if off >= len(buf):
        raise PayloadError("EOF reading tag")
    tag = buf[off]

    if tag in (TLV_OBJECT, TLV_ARRAY):
        # NOTE: this counts TOKENS, not pairs. A map with three key/value
        # pairs has item_count == 6.
        count = _u16(buf, off + 1)
        pos = off + 3
        items: list[Token] = []
        for _ in range(count):
            child, pos = parse_tlv_token(buf, pos)
            items.append(child)
        kind = "obj" if tag == TLV_OBJECT else "arr"
        return Token(tag=tag, kind=kind, offset=off, size=pos - off, value=items), pos

    if tag in (TLV_STRING, TLV_BYTES):
        length = _u16(buf, off + 1)
        start, end = off + 3, off + 3 + length
        if end > len(buf):
            raise PayloadError(f"EOF reading {length} payload bytes at {off}")
        kind = "str" if tag == TLV_STRING else "bytes"
        return Token(tag=tag, kind=kind, offset=off, size=end - off, value=buf[start:end]), end

    simple: dict[int, tuple[str, str, int]] = {
        TLV_U8: ("u8", "<B", 1),
        TLV_U16: ("u16", "<H", 2),
        TLV_U32: ("u32", "<I", 4),
        TLV_U64: ("u64", "<Q", 8),
        TLV_F32: ("f32", "<f", 4),
        TLV_F64: ("f64", "<d", 8),
    }
    if tag in simple:
        kind, fmt, size = simple[tag]
        value = _fixed(buf, off + 1, fmt, size, kind)
        return Token(tag=tag, kind=kind, offset=off, size=1 + size, value=value), off + 1 + size

    literals = {TLV_NULL: ("null", None), TLV_FALSE: ("bool", False), TLV_TRUE: ("bool", True)}
    if tag in literals:
        kind, value = literals[tag]
        return Token(tag=tag, kind=kind, offset=off, size=1, value=value), off + 1

    raise PayloadError(f"unknown TLV tag {tag:#04x} at {off}")


# --------------------------------------------------------------------------
# FTV
# --------------------------------------------------------------------------


def parse_ftv_token(buf: bytes, off: int) -> tuple[Token, int]:
    """
    Parse one `field_id, type_code, payload` token.

    `field_id` is an unmapped byte namespace -- correlating it with the field
    names in the index* schema blocks is an open question.
    """
    if off + 2 > len(buf):
        raise PayloadError("EOF reading FTV token header")
    field_id, type_code = buf[off], buf[off + 1]
    body = off + 2

    def token(kind: str, size: int, value: Any) -> tuple[Token, int]:
        return (
            Token(
                tag=type_code, kind=kind, offset=off, size=(body - off) + size,
                value=value, field_id=field_id,
            ),
            body + size,
        )

    # The False/True assignment for 0x00/0x01 is unconfirmed.
    if type_code in (FTV_FALSE, FTV_TRUE):
        return token("bool", 0, type_code == FTV_TRUE)

    simple: dict[int, tuple[str, str, int]] = {
        FTV_U8: ("u8", "<B", 1),
        FTV_U16: ("u16", "<H", 2),
        FTV_U32: ("u32", "<I", 4),
        FTV_U64: ("u64", "<Q", 8),
        FTV_F32: ("f32", "<f", 4),
        FTV_F64: ("f64", "<d", 8),
    }
    if type_code in simple:
        kind, fmt, size = simple[type_code]
        return token(kind, size, _fixed(buf, body, fmt, size, kind))

    if type_code == FTV_STRING:
        length = _u16(buf, body)
        start, end = body + 2, body + 2 + length
        if end > len(buf):
            raise PayloadError(f"EOF reading FTV string at {off}")
        return token("str", 2 + length, buf[start:end])

    if type_code == FTV_INNER_ARRAY:
        # The one place the dialects meet: a nested array using the TLV
        # PRIMITIVE subset.
        count = _u16(buf, body)
        pos = body + 2
        items: list[Token] = []
        for _ in range(count):
            child, pos = parse_tlv_token(buf, pos)
            items.append(child)
        return (
            Token(
                tag=type_code, kind="arr", offset=off, size=pos - off,
                value=items, field_id=field_id,
            ),
            pos,
        )

    raise PayloadError(f"unknown FTV type code {type_code:#04x} at {off}")


# --------------------------------------------------------------------------
# Streams
# --------------------------------------------------------------------------


def parse(
    buf: bytes,
    *,
    dialect: Dialect | None = None,
    max_tokens: int = 200_000,
    max_resyncs: int = 1_000,
) -> tuple[list[Token], int, str | None]:
    """
    Best-effort parse of a whole payload.

    Returns `(tokens, bytes_consumed, error_or_None)`. Parsing is best-effort
    by design: payloads contain padding and repeated group headers, and a
    partial parse still yields usable strings.
    """
    if dialect is None:
        dialect = detect_dialect(buf)
    parse_token = parse_tlv_token if dialect is Dialect.TLV else parse_ftv_token

    tokens: list[Token] = []
    pos = 0
    error: str | None = None
    resyncs = 0

    while pos < len(buf) and len(tokens) < max_tokens:
        if has_graph_header(buf, pos):
            pos += GRAPH_HEADER_LEN
            continue
        # In TLV, 0x00 is unambiguously padding. In FTV it is a legal
        # field_id, so it may only be skipped as a RECOVERY step (below) --
        # skipping it eagerly would corrupt the stream.
        if dialect is Dialect.TLV and buf[pos] == TLV_PADDING:
            pos += 1
            continue
        try:
            token, pos = parse_token(buf, pos)
        except PayloadError as exc:
            if (
                dialect is Dialect.FTV
                and buf[pos] == TLV_PADDING
                and resyncs < max_resyncs
            ):
                pos += 1
                resyncs += 1
                continue
            error = str(exc)
            break
        tokens.append(token)

    return tokens, pos, error


def iter_tokens(tokens: list[Token]) -> Iterator[Token]:
    """Walk tokens depth-first, descending into containers."""
    for token in tokens:
        yield token
        if isinstance(token.value, list):
            yield from iter_tokens(token.value)


def collect_strings(tokens: list[Token], *, encoding: str = "utf-8") -> list[str]:
    out: list[str] = []
    for token in iter_tokens(tokens):
        if token.kind == "str" and isinstance(token.value, bytes):
            try:
                out.append(token.value.decode(encoding))
            except UnicodeDecodeError:
                continue
    return out


def collect_path_candidates(tokens: list[Token], *, max_len: int = 220) -> list[str]:
    """
    Filter strings down to plausible VFS paths.

    This is the payoff of the whole HD chain: these strings are canonical VFS
    paths, so hashing them (messiah.vfs.fileid) and joining against the index
    recovers real filenames. See docs/hd-store.md section 6.

    Deliberately loose -- a false positive costs one failed lookup, a false
    negative loses a path.
    """
    seen: set[str] = set()
    out: list[str] = []
    for value in collect_strings(tokens):
        if not (0 < len(value) <= max_len):
            continue
        if "/" not in value or value.startswith("/"):
            continue
        if any(ch in value for ch in "\n\r\t\\ "):
            continue
        if not value[0].isalnum():
            continue
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def to_python(token: Token) -> Any:
    """Convert a token tree into plain Python values."""
    if isinstance(token.value, list):
        return [to_python(child) for child in token.value]
    if token.kind == "str" and isinstance(token.value, bytes):
        return token.value.decode("utf-8", errors="replace")
    return token.value

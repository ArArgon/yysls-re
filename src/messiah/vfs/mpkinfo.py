"""
The binary .mpkinfo VFS index.

See docs/mpkinfo-index.md. Layout, all little-endian:

    u32 magic == 3
    u32 file_nums
    entry[file_nums]:  u32 s0, s1, offset, size, packed    (20 bytes)
    u64 trailer0, trailer1

    file_id  = (s1 << 32) | s0
    pack_id  = packed >> 1
    typeflag = packed & 1

Not every file with an .mpkinfo extension is one of these -- some are HEXB_
text wrappers holding integrity metadata. `read_index_bytes` sniffs for that;
`parse_integrity_meta` decodes it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from messiah.codec import hexwrap
from messiah.vfs.fileid import join_file_id_i64, join_file_id_u64

MAGIC = 3
HEADER_SIZE = 8
ENTRY_SIZE = 20
TRAILER_SIZE = 16


@dataclass(frozen=True)
class MpkInfoHeader:
    magic: int
    file_nums: int
    # Two u64s whose meaning is unresolved. They differ between indexes, so
    # they encode something per-index rather than being padding.
    trailer0: int
    trailer1: int


@dataclass(frozen=True)
class MpkInfoEntry:
    s0: int
    s1: int
    offset: int
    size: int
    packed: int

    @property
    def file_id_u64(self) -> int:
        return join_file_id_u64(self.s0, self.s1)

    @property
    def file_id_i64(self) -> int:
        return join_file_id_i64(self.s0, self.s1)

    @property
    def pack_id(self) -> int:
        """Note: `packed >> 1`. Older code used `// 2`, dropping the type flag."""
        return self.packed >> 1

    @property
    def typeflag(self) -> int:
        """
        Semantics unconfirmed. A placeholder use is confirmed (see
        `is_placeholder`); "Patch vs LT" is NOT confirmed. Do not build
        container-resolution logic on this.
        """
        return self.packed & 1

    @property
    def is_placeholder(self) -> bool:
        """
        Zero-length entries are placeholders, not parse failures.

        Note not every zero-size entry has a zero offset -- see `is_empty`,
        which is the safer test when you only care about "has no bytes".
        """
        return self.offset == 0 and self.size == 0

    @property
    def is_empty(self) -> bool:
        """Carries no payload, whatever its offset says."""
        return self.size == 0


@dataclass(frozen=True)
class IntegrityMeta:
    """The HEXB_ variant: integrity/chunking metadata, not an index."""

    content_md5: str
    file_md5: str
    offsets: list[int]


def is_binary_index(path: Path) -> bool:
    """Sniff whether this is a binary index or a HEXB_ wrapper."""
    with path.open("rb") as fh:
        head = fh.read(8)
    if hexwrap.has_hex_prefix(head):
        return False
    return len(head) >= 4 and struct.unpack_from("<I", head, 0)[0] == MAGIC


def read_index_bytes(path: Path) -> bytes:
    """Read an index, transparently unwrapping a HEX_/HEXB_ envelope."""
    raw = path.read_bytes()
    if hexwrap.has_hex_prefix(raw):
        return hexwrap.decode(raw.decode("utf-8", errors="ignore"))
    return raw


def parse(path: Path) -> tuple[MpkInfoHeader, Iterator[MpkInfoEntry]]:
    """
    Parse a binary index.

    Raises ValueError with a pointed message when handed the HEXB_ variant,
    which otherwise looks like corruption.
    """
    data = read_index_bytes(path)

    if len(data) < HEADER_SIZE:
        raise ValueError(f"{path}: too small to be an .mpkinfo index")

    magic, file_nums = struct.unpack_from("<II", data, 0)
    if magic != MAGIC:
        raise ValueError(
            f"{path}: bad magic {magic}, expected {MAGIC}. "
            "If this file starts with HEX_/HEXB_ it is integrity metadata, "
            "not an index -- use parse_integrity_meta()."
        )

    trailer_off = HEADER_SIZE + file_nums * ENTRY_SIZE
    expected = trailer_off + TRAILER_SIZE
    if expected > len(data):
        raise ValueError(
            f"{path}: truncated: file_nums={file_nums} implies {expected} bytes, got {len(data)}"
        )

    t0, t1 = struct.unpack_from("<QQ", data, trailer_off)
    header = MpkInfoHeader(magic=magic, file_nums=file_nums, trailer0=t0, trailer1=t1)

    def _iter() -> Iterator[MpkInfoEntry]:
        for i in range(file_nums):
            off = HEADER_SIZE + i * ENTRY_SIZE
            s0, s1, item_off, item_size, packed = struct.unpack_from("<IIIII", data, off)
            yield MpkInfoEntry(s0=s0, s1=s1, offset=item_off, size=item_size, packed=packed)

    return header, _iter()


def parse_integrity_meta(path: Path) -> IntegrityMeta:
    """
    Decode the HEXB_ variant: msgpack with md5 digests and a list of offsets.

    Which file the offsets describe is unresolved.
    """
    obj = hexwrap.decode_msgpack(path.read_bytes())

    def _get(key: str):
        return obj.get(key.encode()) if isinstance(obj, dict) else None

    def _text(value) -> str:
        return value.decode("ascii") if isinstance(value, bytes) else str(value)

    return IntegrityMeta(
        content_md5=_text(_get("content_md5")),
        file_md5=_text(_get("file_md5")),
        offsets=list(_get("offsets") or []),
    )


def max_extent_by_pack(entries: Iterator[MpkInfoEntry]) -> dict[int, int]:
    """
    Per pack id, the maximum `offset + size`.

    Compare against the pack's physical size: equal means physical offsets;
    greater means the pack is EZST-chunked and offsets are logical
    (docs/ezst.md).
    """
    out: dict[int, int] = {}
    for entry in entries:
        if entry.is_empty:
            continue
        end = entry.offset + entry.size
        if end > out.get(entry.pack_id, 0):
            out[entry.pack_id] = end
    return out

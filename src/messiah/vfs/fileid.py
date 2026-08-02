"""
VFS path -> 64-bit file id.

See docs/file-id.md. Summary:

    file_id_u64 = (hi32 << 32) | lo32
    hi32 = MurmurHash3_x86_32(path_utf8, seed=0)   # the FULL path
    lo32 = tail_sig(strip_last_extension(path))    # extension STRIPPED

The asymmetry is deliberate and is what makes `lo32` useful as a constraint
filter when guessing at unknown paths (see `tail_sig_constraint`).

Note this is Murmur3 *x86-32* over a path. Content hashing uses Murmur3-128
folded to 64 bits over file bytes -- a different function, see
messiah.codec.contenthash.
"""

from __future__ import annotations

import struct
from typing import Iterable

U32_MASK = 0xFFFFFFFF
U64_MASK = 0xFFFFFFFFFFFFFFFF

# Murmur3 x86-32 constants. These double as search signatures when locating the
# hash routine in a binary -- see docs/methodology.md.
_C1 = 0xCC9E2D51
_C2 = 0x1B873593
_MIX = 0xE6546B64
_FMIX1 = 0x85EBCA6B
_FMIX2 = 0xC2B2AE35

# The GUID fast path triggers on "xx/<36-char-guid>" with an optional
# single-char extension.
_GUID_LEN = 0x27
_GUID_LEN_EXT = 0x29


def _rotl32(x: int, r: int) -> int:
    return ((x << r) & U32_MASK) | (x >> (32 - r))


def _fmix32(h: int) -> int:
    h ^= h >> 16
    h = (h * _FMIX1) & U32_MASK
    h ^= h >> 13
    h = (h * _FMIX2) & U32_MASK
    h ^= h >> 16
    return h


def murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit. Returns an int in [0, 2**32)."""
    length = len(data)
    nblocks = length // 4
    h1 = seed & U32_MASK

    for i in range(nblocks):
        k1 = struct.unpack_from("<I", data, i * 4)[0]
        k1 = (k1 * _C1) & U32_MASK
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & U32_MASK
        h1 ^= k1
        h1 = _rotl32(h1, 13)
        h1 = (h1 * 5 + _MIX) & U32_MASK

    tail = data[nblocks * 4 :]
    k1 = 0
    for i, b in enumerate(tail):
        k1 ^= b << (8 * i)
    if tail:
        k1 = (k1 * _C1) & U32_MASK
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & U32_MASK
        h1 ^= k1

    h1 ^= length
    return _fmix32(h1)


def strip_last_extension(path_bytes: bytes) -> bytes:
    """
    Cut at the last '.', but only when it follows the last '/'.

    Without the slash check a directory component containing a dot (``a.b/c``)
    would be truncated.
    """
    last_dot = path_bytes.rfind(b".")
    if last_dot == -1:
        return path_bytes
    last_slash = path_bytes.rfind(b"/")
    if last_slash != -1 and last_dot < last_slash:
        return path_bytes
    return path_bytes[:last_dot]


def tail_sig(path_no_ext: bytes) -> int:
    """
    The low 32 bits: last three bytes plus a truncated length.

    Has a fast path for GUID-shaped names, which returns the four bytes right
    after the "xx/" prefix instead.
    """
    n = len(path_no_ext)

    if n in (_GUID_LEN, _GUID_LEN_EXT) and path_no_ext[2:3] == b"/":
        return (
            (path_no_ext[3] << 24)
            | (path_no_ext[4] << 16)
            | (path_no_ext[5] << 8)
            | path_no_ext[6]
        )

    if n >= 3:
        return (
            (path_no_ext[n - 1] << 24)
            | (path_no_ext[n - 2] << 16)
            | (path_no_ext[n - 3] << 8)
            | (n & 0xFF)
        )
    if n == 2:
        return (path_no_ext[1] << 24) | (path_no_ext[0] << 16) | (n & 0xFF)
    if n == 1:
        return (path_no_ext[0] << 24) | (n & 0xFF)
    return 0


def file_id_u64(path: str, *, encoding: str = "utf-8") -> int:
    """Compute the file id as an unsigned 64-bit integer."""
    path_bytes = path.encode(encoding)
    hi32 = murmur3_x86_32(path_bytes, 0)
    lo32 = tail_sig(strip_last_extension(path_bytes))
    return ((hi32 << 32) | lo32) & U64_MASK


def file_id_i64(path: str, *, encoding: str = "utf-8") -> int:
    """Compute the file id as a signed int64, matching how SQLite stores it."""
    return u64_to_i64(file_id_u64(path, encoding=encoding))


def u64_to_i64(x: int) -> int:
    """Reinterpret a u64 as signed. Required before any join against SQLite."""
    return x - (1 << 64) if x >= (1 << 63) else x


def i64_to_u64(x: int) -> int:
    """Reinterpret a signed int64 as unsigned."""
    return x & U64_MASK


def split_file_id_u64(file_id: int) -> tuple[int, int]:
    """Return the (s0, s1) halves as stored in a .mpkinfo entry."""
    return (file_id & U32_MASK, (file_id >> 32) & U32_MASK)


def join_file_id_u64(s0: int, s1: int) -> int:
    """Rebuild a file id from .mpkinfo entry halves."""
    return ((s1 & U32_MASK) << 32) | (s0 & U32_MASK)


def join_file_id_i64(s0: int, s1: int) -> int:
    """Rebuild a file id from .mpkinfo entry halves, as signed."""
    return u64_to_i64(join_file_id_u64(s0, s1))


def batch_file_id_i64(paths: Iterable[str], *, encoding: str = "utf-8") -> list[int]:
    return [file_id_i64(p, encoding=encoding) for p in paths]


# --------------------------------------------------------------------------
# Path recovery helpers
# --------------------------------------------------------------------------


def tail_sig_constraint(file_id: int) -> tuple[bytes, int]:
    """
    Decompose a target id's low half into the constraint a candidate path must
    satisfy *before* it is worth hashing.

    Returns ``(suffix, length_mod_256)`` where ``suffix`` is the final three
    bytes of the extension-stripped path.

    This is the cheap filter that makes dictionary attacks tractable: reject on
    a string comparison and a length check, and only Murmur-hash survivors.
    Meaningless for GUID-shaped paths, which take the other branch.
    """
    lo32 = file_id & U32_MASK
    suffix = bytes(((lo32 >> 24) & 0xFF, (lo32 >> 16) & 0xFF, (lo32 >> 8) & 0xFF))
    # tail_sig packs the last byte first, so undo that ordering.
    return suffix[::-1], lo32 & 0xFF


def matches_tail_sig(path: str, file_id: int, *, encoding: str = "utf-8") -> bool:
    """Cheap pre-filter: does this candidate satisfy the target's low half?"""
    no_ext = strip_last_extension(path.encode(encoding))
    return tail_sig(no_ext) == (file_id & U32_MASK)

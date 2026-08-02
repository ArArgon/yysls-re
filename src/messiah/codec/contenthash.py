"""
The 64-bit content hash stored in the indexes.

See docs/content-hash.md.

    for each chunk:  acc ^= (mmh3_128(chunk) >> 64) ^ (mmh3_128(chunk) & U64)

Two things are easy to get wrong:

- The 128-bit result is folded by XOR-ing its halves, not truncated.
- Chunk size is chosen from the payload size, and LARGER files use the SMALLER
  chunk. Getting that backwards produces correct hashes for small files and
  wrong ones for large files -- a "mostly works" failure.

This is Murmur3-*128* over file bytes. Path hashing uses Murmur3 x86-32 over a
string; see messiah.vfs.fileid.
"""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO

U64_MASK = 0xFFFFFFFFFFFFFFFF

# Files at or above the threshold use the small chunk; everything else uses the
# large one (and is therefore hashed in a single chunk).
LARGE_FILE_THRESHOLD = 0x400000  # 4 MiB
CHUNK_SIZE_LARGE_FILE = 0x200000  # 2 MiB
CHUNK_SIZE_SMALL_FILE = 0x2000000  # 32 MiB


def chunk_size_for(size: int) -> int:
    """Select the chunk size the way the game does."""
    return CHUNK_SIZE_LARGE_FILE if size >= LARGE_FILE_THRESHOLD else CHUNK_SIZE_SMALL_FILE


def content_hash_u64(data: bytes, *, chunk_size: int | None = None) -> int:
    """Content hash of an in-memory payload, as an unsigned 64-bit int."""
    import mmh3

    if chunk_size is None:
        chunk_size = chunk_size_for(len(data))

    acc = 0
    for i in range(0, len(data), chunk_size):
        h = mmh3.hash128(data[i : i + chunk_size])
        acc ^= (h >> 64) ^ (h & U64_MASK)
    return acc & U64_MASK


def content_hash_i64(data: bytes, *, chunk_size: int | None = None) -> int:
    """Content hash as a signed int64, matching how SQLite stores it."""
    from messiah.vfs.fileid import u64_to_i64

    return u64_to_i64(content_hash_u64(data, chunk_size=chunk_size))


def content_hash_stream(fh: BinaryIO, size: int) -> int:
    """
    Hash a stream without holding the whole payload in memory.

    `size` must be the true payload size -- it selects the chunk size, so a
    wrong value silently produces a wrong hash.
    """
    import mmh3

    chunk_size = chunk_size_for(size)
    acc = 0
    remaining = size
    while remaining > 0:
        chunk = fh.read(min(chunk_size, remaining))
        if not chunk:
            raise ValueError(f"stream ended {remaining} bytes early")
        remaining -= len(chunk)
        h = mmh3.hash128(chunk)
        acc ^= (h >> 64) ^ (h & U64_MASK)
    return acc & U64_MASK


def content_hash_file(path: Path) -> int:
    """Content hash of a whole file on disk."""
    size = path.stat().st_size
    with path.open("rb") as fh:
        return content_hash_stream(fh, size)


def verify(data: bytes, expected: int) -> bool:
    """
    Check a payload against a hash from an index, ignoring signedness.

    A match validates the whole extraction chain: index parse, container
    resolution, offset arithmetic, and wrapper decoding.
    """
    from messiah.vfs.fileid import i64_to_u64

    return content_hash_u64(data) == i64_to_u64(expected)

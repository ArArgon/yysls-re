"""
HD container format (the `index{n}` / `data{n}` files).

See docs/hd-store.md sections 1-2.

    u32le magic = 0xDEADBEEF
    u32le version = 1
    u32le count
    u32le reserved = 0
    u32le offsets[count]        RELATIVE to the data region, not absolute
    u8    data_region[]

    base = 16 + 4*count
    block i spans [base + offsets[i-1], base + offsets[i])

Each block is a 9-byte header plus a zstd frame:

    u32le a = (compressed_len   << 8) | 0x04
    u32le b = (decompressed_len << 8) | 0x00
    u8    flags

Note the lengths are shifted left by 8 with a tag in the low byte -- read them
as `a >> 8`, not as plain integers.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from messiah.codec import zstdutil

HD_MAGIC = 0xDEADBEEF
CONTAINER_HEADER_SIZE = 16
BLOCK_HEADER_SIZE = 9


@dataclass(frozen=True)
class ContainerHeader:
    magic: int
    version: int
    count: int
    reserved: int
    base: int


@dataclass(frozen=True)
class Block:
    index: int
    start: int  # absolute file offset
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class BlockHeader:
    compressed_len: int
    decompressed_len: int
    a_tag: int
    b_tag: int
    flags: int
    zstd_offset: int


def parse_container(path: Path) -> tuple[ContainerHeader, list[int]]:
    """
    Parse the container header and offset table.

    Validates `offsets[-1] == data_len`. If that fails the `count`/`base`
    arithmetic is wrong and everything downstream would be garbage, so this
    raises rather than continuing.
    """
    file_size = path.stat().st_size
    with path.open("rb") as fh:
        head = fh.read(CONTAINER_HEADER_SIZE)
        if len(head) != CONTAINER_HEADER_SIZE:
            raise ValueError(f"{path}: truncated container header")

        magic, version, count, reserved = struct.unpack("<IIII", head)
        if magic != HD_MAGIC:
            raise ValueError(f"{path}: bad magic {magic:#x}, expected {HD_MAGIC:#x}")

        base = CONTAINER_HEADER_SIZE + 4 * count
        raw = fh.read(4 * count)
        if len(raw) != 4 * count:
            raise ValueError(f"{path}: truncated offset table (count={count})")
        offsets = list(struct.unpack(f"<{count}I", raw))

    data_len = file_size - base
    if offsets and offsets[-1] != data_len:
        raise ValueError(
            f"{path}: offsets[-1]={offsets[-1]} != data_len={data_len}; "
            "container header arithmetic is wrong"
        )

    header = ContainerHeader(
        magic=magic, version=version, count=count, reserved=reserved, base=base
    )
    return header, offsets


def iter_blocks(path: Path) -> Iterator[Block]:
    header, offsets = parse_container(path)
    prev = 0
    for i, end in enumerate(offsets):
        yield Block(index=i, start=header.base + prev, end=header.base + int(end))
        prev = int(end)


def read_block(path: Path, block: Block) -> bytes:
    with path.open("rb") as fh:
        fh.seek(block.start)
        data = fh.read(block.size)
    if len(data) != block.size:
        raise ValueError(f"{path}: short read at block {block.index}")
    return data


def get_block(path: Path, index: int) -> Block:
    header, offsets = parse_container(path)
    if not 0 <= index < len(offsets):
        raise IndexError(f"{path}: block {index} out of range (count={header.count})")
    start = offsets[index - 1] if index > 0 else 0
    return Block(index=index, start=header.base + start, end=header.base + offsets[index])


def parse_block_header(block_bytes: bytes, *, search: bool = False) -> BlockHeader | None:
    """
    Parse a block header.

    The zstd frame follows the 9-byte header. `search=True` locates the frame
    by magic instead of assuming the fixed offset -- slower, but a useful
    fallback if the header layout ever changes.
    """
    if len(block_bytes) < BLOCK_HEADER_SIZE:
        return None

    a = struct.unpack_from("<I", block_bytes, 0)[0]
    b = struct.unpack_from("<I", block_bytes, 4)[0]

    zstd_offset = BLOCK_HEADER_SIZE
    if search or block_bytes[BLOCK_HEADER_SIZE : BLOCK_HEADER_SIZE + 4] != zstdutil.ZSTD_MAGIC:
        found = zstdutil.find_frame(block_bytes)
        if found == -1:
            return None
        zstd_offset = found

    return BlockHeader(
        compressed_len=a >> 8,
        decompressed_len=b >> 8,
        a_tag=a & 0xFF,
        b_tag=b & 0xFF,
        flags=block_bytes[8],
        zstd_offset=zstd_offset,
    )


def decompress_block(block_bytes: bytes) -> tuple[BlockHeader, bytes] | None:
    """
    Decompress one block, validating against its declared length.

    Returns None when the block has no recognisable header or frame.
    """
    header = parse_block_header(block_bytes)
    if header is None:
        return None

    try:
        data, _ = zstdutil.decompress_with_trailer(block_bytes[header.zstd_offset :])
    except Exception:
        return None

    if header.decompressed_len and len(data) != header.decompressed_len:
        return None
    return header, data


def read_and_decompress(path: Path, index: int) -> bytes:
    """Read block `index` from `path` and return its decompressed payload."""
    result = decompress_block(read_block(path, get_block(path, index)))
    if result is None:
        raise ValueError(f"{path}: block {index} did not decompress")
    return result[1]

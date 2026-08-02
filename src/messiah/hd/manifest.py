"""
HD MANIFEST -- the registry mapping keys to (container, block).

See docs/hd-store.md section 3.

    u16 v1, u16 v2, u32 unk0
    u32 count_pool2, count_table, count_pool3, count_pool1   <- NOT pool order
    pool1, pool2, pool3    strings of (u16 len + bytes), each 8-byte ALIGNED
    record_table           count_table records of 32 bytes (8 x u32le)
    trailer                includes the container filenames

Two traps: the pool counts appear in the header out of order, and the 8-byte
alignment means you cannot walk a pool by length alone.

Returns objects. (The previous implementation dumped a dozen fixed filenames to
a directory and then re-read them by name, which coupled four scripts to a
file-layout contract.)
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from messiah.codec import zstdutil

HEADER_SIZE = 24
RECORD_SIZE = 32
NO_POINTER = 0xFFFFFFFF

# `u7` selects which pool `u0` indexes. Other values exist and are undecoded,
# and many records have `u0` outside both pools.
POOL_DISCRIMINATOR = {0x400: 1, 0x800: 2}


@dataclass(frozen=True)
class ManifestHeader:
    v1: int
    v2: int
    unk0: int
    count_pool1: int
    count_pool2: int
    count_pool3: int
    count_table: int


@dataclass(frozen=True)
class Record:
    """One 32-byte record. Only u2 and u7 are decoded."""

    index: int
    u0: int
    u1: int
    u2: int
    u3: int
    u4: int
    u5: int
    u6: int
    u7: int

    @property
    def has_pointer(self) -> bool:
        return self.u2 != NO_POINTER

    @property
    def data_file_id(self) -> int | None:
        return None if not self.has_pointer else self.u2 & 0xFFFF

    @property
    def block_index(self) -> int | None:
        return None if not self.has_pointer else (self.u2 >> 16) & 0xFFFF

    @property
    def pool(self) -> int | None:
        """Which pool `u0` indexes, or None when `u7` is an undecoded kind."""
        return POOL_DISCRIMINATOR.get(self.u7)


@dataclass
class Manifest:
    header: ManifestHeader
    pool1: list[str]
    pool2: list[str]
    pool3: list[str]
    records: list[Record]
    container_names: list[str]

    def pool_for(self, number: int) -> list[str]:
        return {1: self.pool1, 2: self.pool2, 3: self.pool3}[number]

    def find_key(self, key: str) -> list[tuple[int, int]]:
        """Locate a key across the pools. Returns [(pool_number, index)]."""
        out = []
        for number in (1, 2, 3):
            pool = self.pool_for(number)
            try:
                out.append((number, pool.index(key)))
            except ValueError:
                continue
        return out

    def records_for_key(self, key: str) -> Iterator[Record]:
        """
        Yield pointer records for a key.

        Matches on both the key's pool index and the pool discriminator, so a
        coincidental index collision in the other pool is not returned.
        """
        for pool_number, key_index in self.find_key(key):
            for record in self.records:
                if (
                    record.has_pointer
                    and record.u0 == key_index
                    and record.pool == pool_number
                ):
                    yield record


def _align8(offset: int) -> int:
    return (offset + 7) & ~7


def _read_pool(buf: bytes, offset: int, count: int) -> tuple[list[str], int]:
    out: list[str] = []
    for _ in range(count):
        if offset + 2 > len(buf):
            raise ValueError("manifest truncated inside a string pool")
        length = struct.unpack_from("<H", buf, offset)[0]
        offset += 2
        out.append(buf[offset : offset + length].decode("utf-8", errors="replace"))
        offset = _align8(offset + length)
    return out, offset


def _read_container_names(trailer: bytes, *, limit: int = 256) -> list[str]:
    """
    Recover container filenames from the trailer.

    Scans for `u16 len + printable ASCII` runs and keeps those matching the
    container naming convention. (The previous implementation searched for the
    literal bytes of specific instance names, which pinned it to one install.)
    """
    name_re = re.compile(r"\A(?:index|data)\d+\Z")
    out: list[str] = []
    offset = 0

    while offset + 2 <= len(trailer) and len(out) < limit:
        length = struct.unpack_from("<H", trailer, offset)[0]
        if 0 < length <= 64 and offset + 2 + length <= len(trailer):
            raw = trailer[offset + 2 : offset + 2 + length]
            if all(0x20 <= b <= 0x7E for b in raw):
                text = raw.decode("ascii")
                if name_re.match(text) and text not in out:
                    out.append(text)
                    offset += 2 + length
                    continue
        offset += 1

    return out


def decompress(path: Path) -> bytes:
    """
    Decompress the MANIFEST.

    It is not a plain zstd file -- it opens with the container magic and embeds
    a frame a short way in. Locate the frame by magic; the offset is not fixed.
    """
    raw = path.read_bytes()
    offset = zstdutil.find_frame(raw)
    if offset == -1:
        raise ValueError(f"{path}: no zstd frame found")
    data, _ = zstdutil.decompress_with_trailer(raw[offset:])
    return data


def parse(path: Path) -> Manifest:
    """Parse the MANIFEST into pools, records, and container names."""
    data = decompress(path)
    if len(data) < HEADER_SIZE:
        raise ValueError(f"{path}: decompressed payload too short for a header")

    v1, v2, unk0, count_pool2, count_table, count_pool3, count_pool1 = struct.unpack_from(
        "<HHIIIII", data, 0
    )
    header = ManifestHeader(
        v1=v1, v2=v2, unk0=unk0,
        count_pool1=count_pool1, count_pool2=count_pool2,
        count_pool3=count_pool3, count_table=count_table,
    )

    offset = HEADER_SIZE
    pool1, offset = _read_pool(data, offset, count_pool1)
    pool2, offset = _read_pool(data, offset, count_pool2)
    pool3, offset = _read_pool(data, offset, count_pool3)

    table_end = offset + count_table * RECORD_SIZE
    if table_end > len(data):
        raise ValueError(
            f"{path}: record table overruns payload "
            f"({count_table} records need {table_end} bytes, have {len(data)})"
        )

    records = [
        Record(i, *struct.unpack_from("<8I", data, offset + i * RECORD_SIZE))
        for i in range(count_table)
    ]

    return Manifest(
        header=header,
        pool1=pool1,
        pool2=pool2,
        pool3=pool3,
        records=records,
        container_names=_read_container_names(data[table_end:]),
    )

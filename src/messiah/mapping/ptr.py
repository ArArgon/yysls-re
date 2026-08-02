"""
Pointer encodings inside the opaque path-mapping table.

See docs/path-mapping-table.md sections 2 and 4.

Two encodings coexist:

  Paged     hib selects an 8 MiB page, low 24 bits are the offset within it.
            Appears BOTH little-endian (group-root area) and big-endian
            (sorted key->pointer arrays, where the page byte is visible first).

  0xBB      a constant tag byte with a direct 24-bit offset.

The valid page-byte range is DERIVED from the blob's size, not hardcoded -- a
larger blob in a future build extends it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

PAGE_SIZE = 0x800000  # 8 MiB

# The lowest page byte observed. Pages run upward from here, one per PAGE_SIZE
# of blob. Treated as a default because it is an observation, not a constant.
DEFAULT_BASE_HIB = 0x47

BB_TAG = 0xBB
BB_RECORD_SIZE = 8


@dataclass(frozen=True)
class PagedPointerScheme:
    """
    The paged-pointer parameters for one blob.

    Build with `for_blob_size` rather than assuming a fixed range.
    """

    base_hib: int
    page_count: int
    page_size: int = PAGE_SIZE

    @property
    def valid_hibs(self) -> range:
        return range(self.base_hib, self.base_hib + self.page_count)

    def is_pointer(self, value: int) -> bool:
        return ((value >> 24) & 0xFF) in self.valid_hibs

    def to_offset(self, value: int) -> int:
        hib = (value >> 24) & 0xFF
        if hib not in self.valid_hibs:
            raise ValueError(f"not a paged pointer: {value:#010x} (page byte {hib:#04x})")
        return (hib - self.base_hib) * self.page_size + (value & 0xFFFFFF)


def for_blob_size(
    blob_size: int,
    *,
    base_hib: int = DEFAULT_BASE_HIB,
    page_count: int | None = None,
) -> PagedPointerScheme:
    """
    Build a scheme for a blob.

    By default the page count is `ceil(blob_size / PAGE_SIZE)`, i.e. enough
    pages to address the whole blob. This is a permissive UPPER BOUND, not an
    observation.

    Caveat worth knowing: on the one blob ever measured, the page bytes that
    actually appeared covered FEWER pages than its size requires -- pointers
    were never seen targeting the tail. Why is an open question (see
    docs/path-mapping-table.md). The consequence is practical: the derived
    range accepts page bytes that have never been observed, which is safe for
    decoding a known-good pointer but adds false positives when brute-force
    scanning. Pass an explicit `page_count` to tighten it.
    """
    if page_count is None:
        page_count = max(1, -(-blob_size // PAGE_SIZE))
    return PagedPointerScheme(base_hib=base_hib, page_count=page_count)


def read_u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_u32be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


@dataclass(frozen=True)
class GroupPointer:
    """
    An 8-byte `[u32le key][u32le ptr]` record near the start of the blob.

    `key_hi16` varies and looks like a hash or check value -- it is NOT a
    member count. Groups can produce multiple hits, so candidates need scoring
    rather than first-match.
    """

    table_offset: int
    key: int
    group_id: int
    key_hi16: int
    pointer: int
    target_offset: int


def scan_group_pointers(
    data: bytes,
    scheme: PagedPointerScheme,
    *,
    start: int = 0,
    end: int | None = None,
    step: int = 4,
    group_range: range | None = None,
) -> list[GroupPointer]:
    """
    Scan for group-root pointer records.

    `group_range` bounds the plausible group ids; pass the range actually seen
    in the patchlist rather than a remembered constant.
    """
    end = len(data) if end is None else min(end, len(data))
    out: list[GroupPointer] = []

    for offset in range(start, max(start, end - 8), step):
        key = read_u32le(data, offset)
        group_id = key & 0xFFFF
        if group_range is not None and group_id not in group_range:
            continue
        if group_id == 0:
            continue

        pointer = read_u32le(data, offset + 4)
        if not scheme.is_pointer(pointer):
            continue

        out.append(
            GroupPointer(
                table_offset=offset,
                key=key,
                group_id=group_id,
                key_hi16=(key >> 16) & 0xFFFF,
                pointer=pointer,
                target_offset=scheme.to_offset(pointer),
            )
        )
    return out


@dataclass(frozen=True)
class IdPointer:
    """
    An `[u16le a][u16le id][u32be ptr]` record mapping a symbol id to an offset.

    These bridge the u16 symbols that dict-block decoding produces but that
    fall outside the token corpus range. Confirmed to resolve; the targets are
    still undecoded.
    """

    table_offset: int
    a: int
    id: int
    pointer: int
    target_offset: int


def find_id_pointers(
    data: bytes,
    scheme: PagedPointerScheme,
    target_id: int,
    *,
    limit: int = 64,
) -> list[IdPointer]:
    """Find records mapping `target_id` to an offset."""
    needle = struct.pack("<H", target_id)
    out: list[IdPointer] = []
    pos = data.find(needle, 2)

    while pos != -1 and len(out) < limit:
        offset = pos - 2
        if offset >= 0 and offset + 8 <= len(data):
            pointer = read_u32be(data, offset + 4)
            if scheme.is_pointer(pointer):
                out.append(
                    IdPointer(
                        table_offset=offset,
                        a=struct.unpack_from("<H", data, offset)[0],
                        id=target_id,
                        pointer=pointer,
                        target_offset=scheme.to_offset(pointer),
                    )
                )
        pos = data.find(needle, pos + 1)
    return out


@dataclass(frozen=True)
class BBRecord:
    """
    An 8-byte 0xBB-tagged record: a 4-byte key mapped to a 24-bit offset.

        u16le key_a, u16le off_lo16, u8 off_hi8, u8 tag=0xBB, u16le key_b

    The key is `le(key_a) + le(key_b)` -- four RAW bytes. Non-printable bytes
    occur, so never read it as a C string.
    """

    table_offset: int
    key: bytes
    pointer: int


def parse_bb_record(data: bytes, offset: int) -> BBRecord | None:
    if offset + BB_RECORD_SIZE > len(data) or data[offset + 5] != BB_TAG:
        return None
    key_a, off_lo16 = struct.unpack_from("<HH", data, offset)
    off_hi8 = data[offset + 4]
    key_b = struct.unpack_from("<H", data, offset + 6)[0]
    return BBRecord(
        table_offset=offset,
        key=struct.pack("<H", key_a) + struct.pack("<H", key_b),
        pointer=(off_hi8 << 16) | off_lo16,
    )


def recover_bb_table(data: bytes, hint_offset: int, *, max_records: int = 100_000) -> list[BBRecord]:
    """
    Recover a whole 0xBB table from a pointer landing anywhere inside it.

    Internal pointers frequently target the middle of a table rather than its
    start -- probably binary-search anchors. So scan outward on the record
    stride, preserving the alignment the hint implies.
    """
    if parse_bb_record(data, hint_offset) is None:
        raise ValueError(f"no 0xBB record at {hint_offset:#x}")

    start = hint_offset
    while start - BB_RECORD_SIZE >= 0 and parse_bb_record(data, start - BB_RECORD_SIZE):
        start -= BB_RECORD_SIZE

    out: list[BBRecord] = []
    offset = start
    while len(out) < max_records:
        record = parse_bb_record(data, offset)
        if record is None:
            break
        out.append(record)
        offset += BB_RECORD_SIZE
    return out

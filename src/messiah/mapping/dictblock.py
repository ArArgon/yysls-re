"""
Front-coded dictionary blocks in the opaque path-mapping table.

See docs/path-mapping-table.md section 3.

Both variants share one logical structure:

    u16le N
    u16le dict_ids[N]
    <stream>

    seq = prev[:prefix_len] + [dict_ids[x] for x in suffix_symbols]

The stream encoding differs by dictionary size:

    N <= 255   a byte stream (the marker must fit in a byte)
    N >  255   uLEB128 varints

In both, a symbol `v >= N` terminates the current record and sets the next
record's `prefix_len = v - N`; `v < N` is a dictionary index.

For small-N blocks the u16 header splits into `N` (low byte) and an opaque
block type (high byte) -- useful for validating that a pointer landed on a
real block.

NOTE: this is REAL uLEB128 (high bit = continue). Lua chunks use an inverted
varint where the high bit means stop -- see messiah.lua.luac.read_varint. Do
not share a decoder between them.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

SMALL_N_LIMIT = 255

# Upper bound on a plausible large-N dictionary size, used to disambiguate the
# leading u16 (see detect_small_n). A tuning value, not a format constant.
MAX_LARGE_N = 8192

# Guards against a bad pointer producing an unbounded walk.
DEFAULT_MAX_RECORDS = 100_000
DEFAULT_MAX_SYMBOLS = 65_536


@dataclass(frozen=True)
class BlockHeader:
    offset: int
    dict_n: int
    block_type: int | None  # small-N only
    dict_ids: list[int]
    stream_offset: int

    @property
    def is_small_n(self) -> bool:
        return self.dict_n <= SMALL_N_LIMIT


@dataclass(frozen=True)
class Record:
    index: int
    ids: list[int]


def read_uleb128(data: bytes, pos: int, *, end: int | None = None) -> tuple[int, int]:
    """Standard uLEB128: high bit set means continue."""
    end = len(data) if end is None else end
    value = 0
    shift = 0
    while True:
        if pos >= end:
            raise EOFError("uLEB128 ran past end of block")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 35:
            raise ValueError("uLEB128 value too large")


def detect_small_n(data: bytes, offset: int, *, max_large_n: int = MAX_LARGE_N) -> bool:
    """
    Decide whether a block uses the small-N or large-N encoding.

    The leading u16 is genuinely ambiguous: for small-N it is
    `(block_type << 8) | N`, which can be an arbitrarily large number, while
    for large-N it is N itself. A size test alone therefore misclassifies any
    large-N block whose N is not a multiple of 256.

    So: only consider large-N when the u16 is a plausible dictionary size, and
    confirm by probing the varint stream for a record delimiter (a value
    >= N) near the start. Absurdly large values mean it is not large-N.
    """
    if offset + 2 > len(data):
        raise ValueError(f"no room for a block header at {offset:#x}")

    first = struct.unpack_from("<H", data, offset)[0]
    if first <= SMALL_N_LIMIT or first > max_large_n:
        return True

    dict_end = offset + 2 + 2 * first
    if dict_end >= len(data):
        return True

    pos = dict_end
    limit = min(len(data), dict_end + 0x4000)
    try:
        for _ in range(64):
            value, pos = read_uleb128(data, pos, end=limit)
            if value >= first:
                return False  # found a delimiter: large-N confirmed
            if value > first + 0x10000:
                return True  # implausible symbol: not large-N
    except (EOFError, ValueError):
        return True
    return True


def parse_header(data: bytes, offset: int, *, small_n: bool | None = None) -> BlockHeader:
    """
    Parse a block header.

    Pass `small_n` explicitly when the caller knows the variant; otherwise it
    is resolved by `detect_small_n`.
    """
    if offset + 2 > len(data):
        raise ValueError(f"no room for a block header at {offset:#x}")

    raw = struct.unpack_from("<H", data, offset)[0]

    if small_n is None:
        small_n = detect_small_n(data, offset)

    if small_n:
        dict_n = raw & 0xFF
        block_type = (raw >> 8) & 0xFF
    else:
        dict_n = raw
        block_type = None

    if dict_n == 0:
        raise ValueError(f"dict_n is 0 at {offset:#x} -- not a dict block")

    dict_start = offset + 2
    dict_end = dict_start + 2 * dict_n
    if dict_end > len(data):
        raise ValueError(f"dictionary at {offset:#x} overruns the blob")

    dict_ids = list(struct.unpack_from(f"<{dict_n}H", data, dict_start))
    return BlockHeader(
        offset=offset,
        dict_n=dict_n,
        block_type=block_type,
        dict_ids=dict_ids,
        stream_offset=dict_end,
    )


def iter_records(
    data: bytes,
    header: BlockHeader,
    *,
    end: int | None = None,
    max_records: int = DEFAULT_MAX_RECORDS,
    max_symbols: int = DEFAULT_MAX_SYMBOLS,
) -> Iterator[Record]:
    """
    Decode front-coded records from a block.

    Each record is a list of dictionary ids; resolving those to strings is a
    separate (and still unsolved) step -- see docs/path-mapping-table.md.
    """
    end = len(data) if end is None else min(end, len(data))
    dict_n = header.dict_n
    dict_ids = header.dict_ids
    small = header.is_small_n

    pos = header.stream_offset
    previous: list[int] = []
    current: list[int] = []
    prefix_len = 0
    started = False
    index = 0

    while pos < end and index < max_records:
        if small:
            value = data[pos]
            pos += 1
        else:
            try:
                value, pos = read_uleb128(data, pos, end=end)
            except EOFError:
                break

        if value < dict_n:
            current.append(dict_ids[value])
            if len(current) > max_symbols:
                raise ValueError(f"record at {header.offset:#x} exceeded the symbol cap")
            continue

        # A terminator: emit the record built so far, then start the next one.
        if started:
            record = previous[:prefix_len] + current
            yield Record(index=index, ids=record)
            index += 1
            previous = record

        prefix_len = value - dict_n
        if prefix_len > len(previous):
            # A bad pointer, or the block ended -- stop rather than emit noise.
            break
        current = []
        started = True

    if started and current and index < max_records:
        yield Record(index=index, ids=previous[:prefix_len] + current)


def decode_block(
    data: bytes,
    offset: int,
    *,
    end: int | None = None,
    max_records: int = DEFAULT_MAX_RECORDS,
) -> tuple[BlockHeader, list[Record]]:
    """Parse a block header and decode its records."""
    header = parse_header(data, offset)
    records = list(iter_records(data, header, end=end, max_records=max_records))
    return header, records


def looks_like_block(data: bytes, offset: int) -> bool:
    """
    Cheap validity check for a candidate block offset.

    Used to confirm that a pointer recovered elsewhere actually lands on a
    dict block -- pointers from the 0xBB tables have been observed to do so.
    """
    try:
        parse_header(data, offset)
        return True
    except (ValueError, struct.error):
        return False

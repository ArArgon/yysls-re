"""
The LuaText on-disk wrapper.

See docs/lua-bytecode.md sections 2-3.

    u32le decoded_size
    u8    lz4_block[]      RAW LZ4 block -- no frame header

Includes a pure-Python LZ4 block decompressor so there is no lz4 dependency;
frame-based decoders cannot read these anyway.

The two bytes at offset 4 are very often `f6 03`. That is the first LZ4 token,
NOT a magic number -- see `SIGNATURE_OFFSET_HINT`. Do not detect on it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

# Stock Lua 5.4 chunk header. The whole header is stock; only the opcode table
# differs (see messiah.lua.luac).
LUA_SIGNATURE = b"\x1bLua"
LUA_VERSION = 0x54
LUA_FORMAT = 0x00
LUAC_DATA = b"\x19\x93\r\n\x1a\n"
LUAC_SIZES = b"\x04\x08\x08"  # Instruction, lua_Integer, lua_Number
LUAC_INT = (0x5678).to_bytes(8, "little")
LUAC_NUM = struct.pack("<d", 370.5)

CHUNK_HEADER = LUA_SIGNATURE + bytes([LUA_VERSION, LUA_FORMAT]) + LUAC_DATA
HEADER_LEN = 31  # through LUAC_NUM, before nupvalues

# In a packed blob the Lua signature typically appears here: 4 bytes of size
# plus 2 bytes of LZ4 token. Used for carving, never for validation.
SIGNATURE_OFFSET_HINT = 6


class LZ4BlockError(ValueError):
    pass


@dataclass(frozen=True)
class LuaTextPacked:
    decoded_size: int
    lz4_block: bytes


def lz4_block_decompress(src: bytes, dst_size: int) -> bytes:
    """
    Decompress a raw LZ4 block, producing exactly `dst_size` bytes.

    Matches must be copied byte-by-byte: LZ4 permits overlapping matches
    (offset < match_len) as a run-length encoding, so a slice copy is wrong.
    """
    if dst_size < 0:
        raise LZ4BlockError("negative dst_size")
    if dst_size == 0:
        return b""

    out = bytearray(dst_size)
    out_pos = 0
    src_pos = 0

    def need(n: int) -> None:
        if src_pos + n > len(src):
            raise LZ4BlockError(
                f"unexpected end of block: need {n} at {src_pos:#x}, have {len(src):#x}"
            )

    while out_pos < dst_size:
        need(1)
        token = src[src_pos]
        src_pos += 1

        lit_len = token >> 4
        if lit_len == 0xF:
            while True:
                need(1)
                b = src[src_pos]
                src_pos += 1
                lit_len += b
                if b != 0xFF:
                    break

        if lit_len:
            if out_pos + lit_len > dst_size:
                raise LZ4BlockError(f"literal overruns output at {out_pos}")
            need(lit_len)
            out[out_pos : out_pos + lit_len] = src[src_pos : src_pos + lit_len]
            out_pos += lit_len
            src_pos += lit_len
            if out_pos == dst_size:
                break

        need(2)
        offset = struct.unpack_from("<H", src, src_pos)[0]
        src_pos += 2
        if offset == 0:
            raise LZ4BlockError("invalid match offset 0")
        if offset > out_pos:
            raise LZ4BlockError(f"match offset {offset} exceeds output {out_pos}")

        match_len = (token & 0x0F) + 4
        if (token & 0x0F) == 0xF:
            while True:
                need(1)
                b = src[src_pos]
                src_pos += 1
                match_len += b
                if b != 0xFF:
                    break

        if out_pos + match_len > dst_size:
            raise LZ4BlockError(f"match overruns output at {out_pos}")

        for _ in range(match_len):
            out[out_pos] = out[out_pos - offset]
            out_pos += 1

    return bytes(out)


def parse_packed(blob: bytes) -> LuaTextPacked:
    if len(blob) < 4:
        raise LZ4BlockError("blob too short for the size field")
    return LuaTextPacked(decoded_size=struct.unpack_from("<I", blob, 0)[0], lz4_block=blob[4:])


def unpack(blob: bytes) -> bytes:
    """Unpack a LuaText blob into a Lua 5.4 chunk."""
    packed = parse_packed(blob)
    return lz4_block_decompress(packed.lz4_block, packed.decoded_size)


def validate_chunk(buf: bytes) -> tuple[bool, str]:
    """
    Check a decoded buffer against the stock Lua 5.4 header.

    The fixed check values make false positives essentially impossible, which
    is what makes the carving heuristic in `carve` safe.
    """
    if len(buf) < HEADER_LEN:
        return False, "too short for a chunk header"
    if buf[:4] != LUA_SIGNATURE:
        return False, "missing Lua signature"
    if buf[4] != LUA_VERSION:
        return False, f"version {buf[4]:#04x}, expected {LUA_VERSION:#04x}"
    if buf[5] != LUA_FORMAT:
        return False, f"format {buf[5]:#04x}, expected 0"
    if buf[6:12] != LUAC_DATA:
        return False, "LUAC_DATA mismatch"
    if buf[12:15] != LUAC_SIZES:
        return False, f"size bytes {buf[12:15].hex()}, expected {LUAC_SIZES.hex()}"
    if buf[15:23] != LUAC_INT:
        return False, "LUAC_INT mismatch"
    if buf[23:31] != LUAC_NUM:
        return False, "LUAC_NUM mismatch"
    return True, "ok"


def carve(data: bytes) -> Iterator[tuple[int, bytes]]:
    """
    Recover LuaText blobs from arbitrary bytes without an index.

    Scans for the chunk header, assumes the wrapper starts six bytes earlier,
    and yields only candidates whose decompressed output validates. Yields
    `(wrapper_offset, decoded_chunk)`.
    """
    pos = data.find(CHUNK_HEADER)
    while pos != -1:
        start = pos - SIGNATURE_OFFSET_HINT
        if start >= 0:
            try:
                decoded_size = struct.unpack_from("<I", data, start)[0]
                decoded = lz4_block_decompress(data[start + 4 :], decoded_size)
                if validate_chunk(decoded)[0]:
                    yield start, decoded
            except (LZ4BlockError, struct.error):
                pass
        pos = data.find(CHUNK_HEADER, pos + 1)

"""
Remap the game's extended Lua 5.4 opcodes back to stock.

See docs/lua-bytecode.md section 5.

The game INSERTS opcodes into Lua 5.4's table rather than appending them, so
every stock opcode after the first insertion is shifted. A stock disassembler
therefore produces plausible but completely wrong output rather than failing --
which is why remapping is mandatory, not cosmetic.

Merged from two former modules that carried duplicate copies of this table.
`CUSTOM_OPCODES` below is the single source of truth.

The table was derived from the `luaP_opnames` pointer array in an unobfuscated
binary. It is the item here MOST likely to change between builds: re-derive by
finding that array (pointers to short uppercase ASCII names) and reading it in
order -- each name's index IS its opcode number.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from messiah.lua.luatext import (
    CHUNK_HEADER,
    HEADER_LEN,
    LUA_SIGNATURE,
    validate_chunk,
)

# Lua 5.4 uses a 7-bit opcode field (5.1-5.3 used 6), which is what leaves room
# for the insertions.
OP_MASK = 0x7F

# Stock Lua 5.4 opcodes, in order. Index == opcode number.
STD_OPCODES = [
    "MOVE", "LOADI", "LOADF", "LOADK", "LOADKX", "LOADFALSE", "LFALSESKIP",
    "LOADTRUE", "LOADNIL", "GETUPVAL", "SETUPVAL", "GETTABUP", "GETTABLE",
    "GETI", "GETFIELD", "SETTABUP", "SETTABLE", "SETI", "SETFIELD", "NEWTABLE",
    "SELF", "ADDI", "ADDK", "SUBK", "MULK", "MODK", "POWK", "DIVK", "IDIVK",
    "BANDK", "BORK", "BXORK", "SHRI", "SHLI", "ADD", "SUB", "MUL", "MOD",
    "POW", "DIV", "IDIV", "BAND", "BOR", "BXOR", "SHL", "SHR", "MMBIN",
    "MMBINI", "MMBINK", "UNM", "BNOT", "NOT", "LEN", "CONCAT", "CLOSE", "TBC",
    "JMP", "EQ", "LT", "LE", "EQK", "EQI", "LTI", "LEI", "GTI", "GEI", "TEST",
    "TESTSET", "CALL", "TAILCALL", "RETURN", "RETURN0", "RETURN1", "FORLOOP",
    "FORPREP", "TFORPREP", "TFORCALL", "TFORLOOP", "SETLIST", "CLOSURE",
    "VARARG", "VARARGPREP", "EXTRAARG",
]

STD = {name: i for i, name in enumerate(STD_OPCODES)}

# The game's opcode table: index is the custom opcode, value is the stock
# equivalent (or None where no equivalent is known).
#
# Only the inserted opcodes are listed explicitly; everything else keeps stock
# order, displaced by the insertions. Semantically the insertions are
# optimisation variants -- specialised table access and dict/list "proxy"
# containers. Collapsing them to the generic form is lossy but correct.
CUSTOM_OPCODES: list[tuple[str, int | None]] = [
    ("MOVE", STD["MOVE"]),                          # 0
    ("LOADI", STD["LOADI"]),                        # 1
    ("LOADF", STD["LOADF"]),                        # 2
    ("LOADK", STD["LOADK"]),                        # 3
    ("LOADKX", STD["LOADKX"]),                      # 4
    ("LOADFALSE", STD["LOADFALSE"]),                # 5
    ("LFALSESKIP", STD["LFALSESKIP"]),              # 6
    ("LOADTRUE", STD["LOADTRUE"]),                  # 7
    ("LOADNIL", STD["LOADNIL"]),                    # 8
    ("GETUPVAL", STD["GETUPVAL"]),                  # 9
    ("SETUPVAL", STD["SETUPVAL"]),                  # 10
    ("GETTABUP", STD["GETTABUP"]),                  # 11
    ("GETTABUPDOT", STD["GETTABUP"]),               # 12  inserted
    ("GETTABUPFAST", STD["GETTABUP"]),              # 13  inserted
    ("GETTABLE", STD["GETTABLE"]),                  # 14
    ("GETI", STD["GETI"]),                          # 15
    ("GETFIELD", STD["GETFIELD"]),                  # 16
    ("GETFIELDDOT", STD["GETFIELD"]),               # 17  inserted
    ("GETFIELDFAST", STD["GETFIELD"]),              # 18  inserted
    ("SETTABUP", STD["SETTABUP"]),                  # 19
    ("SETTABUPDOT", STD["SETTABUP"]),               # 20  inserted
    ("SETTABLE", STD["SETTABLE"]),                  # 21
    ("SETI", STD["SETI"]),                          # 22
    ("SETFIELD", STD["SETFIELD"]),                  # 23
    ("SETFIELDDOT", STD["SETFIELD"]),               # 24  inserted
    ("SETDICTPROXYUP", STD["SETTABUP"]),            # 25  inserted
    ("SETDICTPROXY", STD["SETTABLE"]),              # 26  inserted
    ("SETDICTPROXYI", STD["SETI"]),                 # 27  inserted
    ("SETDICTPROXYFIELD", STD["SETFIELD"]),         # 28  inserted
    ("NEWTABLE", STD["NEWTABLE"]),                  # 29
    ("NEWLIST", STD["NEWTABLE"]),                   # 30  inserted
    ("NEWDICT", STD["NEWTABLE"]),                   # 31  inserted
    ("NEWLISTPROXY", STD["NEWTABLE"]),              # 32  inserted
    ("NEWDICTPROXY", STD["NEWTABLE"]),              # 33  inserted
    ("SELF", STD["SELF"]),                          # 34
    ("ADDI", STD["ADDI"]),                          # 35
    ("ADDK", STD["ADDK"]),                          # 36
    ("SUBK", STD["SUBK"]),                          # 37
    ("MULK", STD["MULK"]),                          # 38
    ("MODK", STD["MODK"]),                          # 39
    ("POWK", STD["POWK"]),                          # 40
    ("DIVK", STD["DIVK"]),                          # 41
    ("IDIVK", STD["IDIVK"]),                        # 42
    ("BANDK", STD["BANDK"]),                        # 43
    ("BORK", STD["BORK"]),                          # 44
    ("BXORK", STD["BXORK"]),                        # 45
    ("SHRI", STD["SHRI"]),                          # 46
    ("SHLI", STD["SHLI"]),                          # 47
    ("ADD", STD["ADD"]),                            # 48
    ("SUB", STD["SUB"]),                            # 49
    ("MUL", STD["MUL"]),                            # 50
    ("MOD", STD["MOD"]),                            # 51
    ("POW", STD["POW"]),                            # 52
    ("DIV", STD["DIV"]),                            # 53
    ("IDIV", STD["IDIV"]),                          # 54
    ("BAND", STD["BAND"]),                          # 55
    ("BOR", STD["BOR"]),                            # 56
    ("BXOR", STD["BXOR"]),                          # 57
    ("SHL", STD["SHL"]),                            # 58
    ("SHR", STD["SHR"]),                            # 59
    ("MMBIN", STD["MMBIN"]),                        # 60
    ("MMBINI", STD["MMBINI"]),                      # 61
    ("MMBINK", STD["MMBINK"]),                      # 62
    ("UNM", STD["UNM"]),                            # 63
    ("BNOT", STD["BNOT"]),                          # 64
    ("NOT", STD["NOT"]),                            # 65
    ("LEN", STD["LEN"]),                            # 66
    ("CONCAT", STD["CONCAT"]),                      # 67
    ("CLOSE", STD["CLOSE"]),                        # 68
    ("TBC", STD["TBC"]),                            # 69
    ("JMP", STD["JMP"]),                            # 70
    ("EQ", STD["EQ"]),                              # 71
    ("LT", STD["LT"]),                              # 72
    ("LE", STD["LE"]),                              # 73
    ("EQK", STD["EQK"]),                            # 74
    ("EQI", STD["EQI"]),                            # 75
    ("LTI", STD["LTI"]),                            # 76
    ("LEI", STD["LEI"]),                            # 77
    ("GTI", STD["GTI"]),                            # 78
    ("GEI", STD["GEI"]),                            # 79
    ("TEST", STD["TEST"]),                          # 80
    ("TESTSET", STD["TESTSET"]),                    # 81
    ("CALL", STD["CALL"]),                          # 82
    ("TAILCALL", STD["TAILCALL"]),                  # 83
    ("RETURN", STD["RETURN"]),                      # 84
    ("RETURN0", STD["RETURN0"]),                    # 85
    ("RETURN1", STD["RETURN1"]),                    # 86
    ("FORLOOP", STD["FORLOOP"]),                    # 87
    ("FORPREP", STD["FORPREP"]),                    # 88
    ("TFORPREP", STD["TFORPREP"]),                  # 89
    ("TFORCALL", STD["TFORCALL"]),                  # 90
    ("TFORLOOP", STD["TFORLOOP"]),                  # 91
    ("SETLIST", STD["SETLIST"]),                    # 92
    ("LISTSETLIST", STD["SETLIST"]),                # 93  inserted
    ("CLOSURE", STD["CLOSURE"]),                    # 94
    ("VARARG", STD["VARARG"]),                      # 95
    ("VARARGPREP", STD["VARARGPREP"]),              # 96
    ("EXTRAARG", STD["EXTRAARG"]),                  # 97
    ("LDAD", None),                                 # 98  never observed
    ("MMBIN_LDAD", None),                           # 99  never observed
]

# These encode an opcode in their C field, which must be remapped too.
# Skipping this leaves metamethod dispatch pointing at the wrong operation --
# and because they are rare, the output still looks fine on a casual read.
MMBIN_CUSTOM_OPS = frozenset({60, 61, 62, 99})

# Constant tags (stock Lua 5.4).
CONST_NIL, CONST_FALSE, CONST_TRUE = 0x00, 0x01, 0x11
CONST_INT, CONST_FLOAT = 0x03, 0x13
CONST_SHORT_STR, CONST_LONG_STR = 0x04, 0x14


@dataclass
class ConvertResult:
    data: bytes
    warnings: list[str] = field(default_factory=list)


class ChunkError(ValueError):
    pass


# --------------------------------------------------------------------------
# Chunk walking
# --------------------------------------------------------------------------


def read_varint(buf: bytes | bytearray, pos: int) -> tuple[int, int]:
    """
    Lua 5.4's `loadUnsigned`.

    NOTE the inverted terminator: the high bit set means STOP, not continue.
    This is backwards from uLEB128 (used by messiah.mapping.dictblock). Getting
    it wrong desyncs the parse a few bytes in.
    """
    x = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        x = (x << 7) | (b & 0x7F)
        if b & 0x80:
            return x, pos
    raise ChunkError("truncated varint")


def skip_string(buf: bytes | bytearray, pos: int) -> int:
    """Strings are `varint size`; size 0 means absent, else `size - 1` bytes."""
    size, pos = read_varint(buf, pos)
    return pos + size - 1 if size > 0 else pos


def remap_instruction(instr: int) -> tuple[int, str, bool]:
    """Remap one instruction word. Returns (new_instr, opcode_name, remapped)."""
    op = instr & OP_MASK
    if op >= len(CUSTOM_OPCODES):
        return instr, f"?{op}", False

    name, std_op = CUSTOM_OPCODES[op]
    if std_op is None:
        return instr, name, False

    new_instr = (instr & ~OP_MASK) | std_op

    if op in MMBIN_CUSTOM_OPS:
        c_val = (new_instr >> 24) & 0xFF
        if c_val < len(CUSTOM_OPCODES):
            _, c_std = CUSTOM_OPCODES[c_val]
            if c_std is not None:
                new_instr = (new_instr & 0x00FFFFFF) | (c_std << 24)

    return new_instr, name, True


def _process_proto(buf: bytearray, pos: int, warnings: list[str]) -> int:
    pos = skip_string(buf, pos)  # source
    _, pos = read_varint(buf, pos)  # linedefined
    _, pos = read_varint(buf, pos)  # lastlinedefined
    pos += 3  # numparams, is_vararg, maxstacksize

    n_code, pos = read_varint(buf, pos)
    for i in range(n_code):
        instr = struct.unpack_from("<I", buf, pos)[0]
        new_instr, name, ok = remap_instruction(instr)
        if not ok:
            warnings.append(f"unmapped opcode {instr & OP_MASK} ({name}) at code[{i}]")
        struct.pack_into("<I", buf, pos, new_instr)
        pos += 4

    n_k, pos = read_varint(buf, pos)
    for _ in range(n_k):
        tag = buf[pos]
        pos += 1
        if tag in (CONST_NIL, CONST_FALSE, CONST_TRUE):
            pass
        elif tag in (CONST_INT, CONST_FLOAT):
            pos += 8
        elif tag in (CONST_SHORT_STR, CONST_LONG_STR):
            pos = skip_string(buf, pos)
        else:
            raise ChunkError(f"unknown constant tag {tag:#04x} at {pos - 1:#x}")

    n_up, pos = read_varint(buf, pos)
    pos += n_up * 3  # instack, idx, kind

    n_p, pos = read_varint(buf, pos)
    for _ in range(n_p):
        pos = _process_proto(buf, pos, warnings)

    n, pos = read_varint(buf, pos)  # lineinfo
    pos += n
    n, pos = read_varint(buf, pos)  # abslineinfo
    for _ in range(n):
        _, pos = read_varint(buf, pos)
        _, pos = read_varint(buf, pos)
    n, pos = read_varint(buf, pos)  # locvars
    for _ in range(n):
        pos = skip_string(buf, pos)
        _, pos = read_varint(buf, pos)
        _, pos = read_varint(buf, pos)
    n, pos = read_varint(buf, pos)  # upvalue names
    for _ in range(n):
        pos = skip_string(buf, pos)

    return pos


def convert(data: bytes) -> ConvertResult:
    """
    Convert a chunk to stock Lua 5.4 opcodes.

    The header is already stock, so only the instruction streams change. Any
    bytes preceding the signature are stripped.
    """
    off = data.find(LUA_SIGNATURE)
    if off < 0:
        raise ChunkError("no Lua signature found")

    chunk = bytearray(data[off:])
    ok, reason = validate_chunk(chunk)
    if not ok:
        raise ChunkError(f"not a valid chunk: {reason}")

    warnings: list[str] = []
    _process_proto(chunk, HEADER_LEN + 1, warnings)  # +1 skips nupvalues
    return ConvertResult(data=bytes(chunk), warnings=warnings)


def convert_packed(blob: bytes) -> ConvertResult:
    """Unpack a LuaText blob and convert it in one step."""
    from messiah.lua.luatext import unpack

    return convert(unpack(blob))


__all__ = [
    "CHUNK_HEADER",
    "CUSTOM_OPCODES",
    "STD_OPCODES",
    "OP_MASK",
    "ChunkError",
    "ConvertResult",
    "convert",
    "convert_packed",
    "read_varint",
    "remap_instruction",
]

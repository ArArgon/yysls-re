# Lua bytecode: LuaText wrapper, chunk format, custom opcodes

**Scope:** the two layers between an MPK payload and a disassemblable Lua chunk —
the on-disk LZ4 wrapper, and the Lua 5.4 chunk with a non-standard opcode table.

**Prerequisites:** [vfs-model.md](vfs-model.md) to reach the payload bytes.
Script payloads are indexed by **literal path** rather than hashed id — see
[patchdb.md](patchdb.md) §2 for how to find them.

**Implementation:** `messiah.lua.luatext` (wrapper), `messiah.lua.luac` (opcodes)

---

## 1. Two layers

1. **On disk** — `LuaTextPacked`: a 4-byte size followed by a raw LZ4 block.
2. **Decoded** — a **stock Lua 5.4 binary chunk** in every respect *except* the
   opcode numbering, which the game extends.

Static recovery is therefore: read payload → LZ4-unpack → remap opcodes → feed to
stock Lua 5.4 tooling.

## 2. The `LuaTextPacked` wrapper

```c
struct LuaTextPacked {
    uint32_t decoded_size_le;  // size of the decoded Lua chunk
    uint8_t  lz4_block[];      // RAW LZ4 block — no frame header
};
```

It is a **raw LZ4 block**, not an LZ4 frame. Standard frame-based decoders reject
it; you need block-mode decompression with an explicit output size (which is what
the `decoded_size` field is for).

### `f6 03` is not a magic number

The two bytes at offset 4 are very often `f6 03`, and this has repeatedly been
mistaken for a `u16le` magic of `0x03f6`. **It is not a format field.** It is the
first LZ4 token, and it recurs only because every decoded chunk starts with the
same ~18-byte Lua header:

- token `0xF6` → literal-length nibble `0xF` (extended), match-length nibble
  `0x6`; LZ4 match lengths carry a **+4 minimum**, so `6 + 4 = 10` bytes
- extension byte `0x03` → literal length = 15 + 3 = **18**

Those 18 literals are the Lua header. The stream then uses a match at offset 1 to
copy 10 zero bytes — the high bytes of `LUAC_INT` and the **low** bytes of
`LUAC_NUM` (`370.5` is `00 00 00 00 00 28 77 40` little-endian).

That arithmetic is also why the visible `\x1bLua` signature usually sits at file
offset **+6**: 4 bytes of `decoded_size`, 2 bytes of LZ4 token.

**Do not use `f6 03` as a detection signature.** It is common but not
guaranteed — a consequence of this payload and this encoder, not part of the
format. §6 gives a sound alternative.

### The signature is visible but the blob is not loadable

Because those header bytes appear as *literals* early in the LZ4 stream, a
packed blob looks tantalisingly like a chunk in a hex dump. **It is not one.**
Feeding the raw payload — or the bytes from `+6` — to a Lua loader is a mistake
people make precisely *because* the signature is visible.

The tell: the stored payload size is **smaller** than the wrapper's
`decoded_size`, and the runtime loads the larger one. Decode the wrapper first;
no header check applies to the packed form.

## 3. The decoded chunk header

```
1b 4c 75 61   "\x1bLua"
54            version = Lua 5.4
00            format
19 93 0d 0a 1a 0a    LUAC_DATA
04 08 08      sizeof: Instruction=4, lua_Integer=8, lua_Number=8
<8 bytes>     LUAC_INT  == 0x5678
<8 bytes>     LUAC_NUM  == 370.5   (IEEE754 double)
<1 byte>      nupvalues
```

All little-endian.

> **Correction.** The three size bytes **are** stock Lua 5.4 — `lundump.c`
> checks exactly `Instruction`, `lua_Integer`, `lua_Number`. An earlier note
> called this a yysls deviation and mislabelled the fields as
> `int`/`size_t`/`lua_Integer`. It is not a deviation: **the header is entirely
> stock, and the opcode table is the only incompatibility.**

A second earlier claim — that the game binary and the launcher binary accept
*different* header variants — is **not supported** by the evidence recorded for
it, which lists identical checks for both. Treat it as unverified. Both binaries
carry their own copy of the loader, so re-check per binary rather than assuming
either sameness or difference.

## 4. Prototype encoding (stock Lua 5.4)

```c
Proto {
    String   source;              // varint sz, then sz-1 bytes
    Unsigned linedefined, lastlinedefined;
    uint8_t  numparams, is_vararg, maxstacksize;

    Unsigned n_code;   uint32_t code[n_code];      // LE instruction words
    Unsigned n_k;      Constant k[n_k];            // tagged, see below
    Unsigned n_up;     uint8_t  updesc[n_up][3];   // instack, idx, kind
    Unsigned n_p;      Proto    p[n_p];            // recursive

    Unsigned n_lineinfo;     uint8_t lineinfo[n_lineinfo];
    Unsigned n_abslineinfo;  { Unsigned pc, line; }[n_abslineinfo];
    Unsigned n_locvars;      { String name; Unsigned startpc, endpc; }[n_locvars];
    Unsigned n_upnames;      String[n_upnames];
}
```

### Varint — note the inverted terminator

```
x = 0
repeat:
    b = next_byte()
    x = (x << 7) | (b & 0x7f)
until (b & 0x80) != 0        # high bit set means STOP, not continue
```

This is backwards from the usual uLEB128 convention, where the high bit means
*continue*. It is also big-endian in its bit order. Getting this wrong desyncs the
whole parse a few bytes in — a common cause of "unknown constant type" errors.

### Strings

`sz = varint()`; `sz == 0` means absent/NULL; otherwise read `sz - 1` bytes. There
is no trailing NUL.

### Constant tags

| Tag | Type |
|---|---|
| `0x00` | nil |
| `0x01` | false |
| `0x11` | true |
| `0x03` | integer (8 bytes) |
| `0x13` | float (8 bytes) |
| `0x04` | short string |
| `0x14` | long string |

## 5. Instructions and the custom opcode table

Instructions are 32-bit little-endian words. The opcode is the **low 7 bits**:

```
op = instr & 0x7f
```

The 7-bit field is a Lua 5.4 property, and it leaves room for the extensions
below. Version bytes and opcode widths:

| VM | version byte | opcode bits |
|---|---|---|
| Lua 5.1 / 5.2 / 5.3 | `0x51` / `0x52` / `0x53` | 6 |
| Lua 5.4 | `0x54` | **7** |

5.1–5.3 also differ in prototype and debug encoding, so **tooling written for
them will mis-parse 5.4 chunks rather than reject them** — another silently
wrong result.

**Luau is not involved.** It was considered and ruled out: Luau uses an entirely
different bytecode format, while these chunks match Lua 5.4's header and check
values exactly.

### How the table is extended

The game **inserts** extra opcodes into Lua 5.4's table rather than appending
them. Every stock opcode after the first insertion is therefore **shifted**, which
is why a stock disassembler produces plausible but completely wrong output rather
than failing outright.

Remapping means rewriting each instruction's opcode field to the stock index. The
inserted opcodes and their nearest stock equivalent:

| custom | name | → stock | rationale |
|---:|---|---|---|
| 12 | `GETTABUPDOT` | `GETTABUP` | alias |
| 13 | `GETTABUPFAST` | `GETTABUP` | alias |
| 17 | `GETFIELDDOT` | `GETFIELD` | alias |
| 18 | `GETFIELDFAST` | `GETFIELD` | alias |
| 20 | `SETTABUPDOT` | `SETTABUP` | alias |
| 24 | `SETFIELDDOT` | `SETFIELD` | alias |
| 25 | `SETDICTPROXYUP` | `SETTABUP` | dict proxy |
| 26 | `SETDICTPROXY` | `SETTABLE` | dict proxy |
| 27 | `SETDICTPROXYI` | `SETI` | dict proxy |
| 28 | `SETDICTPROXYFIELD` | `SETFIELD` | dict proxy |
| 30 | `NEWLIST` | `NEWTABLE` | constructor alias |
| 31 | `NEWDICT` | `NEWTABLE` | constructor alias |
| 32 | `NEWLISTPROXY` | `NEWTABLE` | constructor alias |
| 33 | `NEWDICTPROXY` | `NEWTABLE` | constructor alias |
| 93 | `LISTSETLIST` | `SETLIST` | list helper |
| 98 | `LDAD` | **unknown** | never observed in samples |
| 99 | `MMBIN_LDAD` | **unknown** | never observed in samples |

All other custom indices correspond 1:1 to a stock opcode, in stock order,
displaced by the insertions above. The authoritative full table is
`CUSTOM_OPCODES` in `messiah.lua.luac`.

Semantically these are optimisation variants — specialised table access, and
dict/list "proxy" containers. Collapsing them to their generic equivalent is
lossy but produces correct, readable output.

### The MMBIN quirk

`MMBIN`, `MMBINI`, and `MMBINK` encode **an opcode in their `C` field**. That
field must be remapped too, using the same table. Remapping only the opcode field
leaves metamethod dispatch pointing at the wrong operation — and because these
instructions are relatively rare, the resulting output looks fine on a casual read.

### The table's provenance

The mapping was derived from the `luaP_opnames` pointer table in an unobfuscated
binary. To re-derive it on a new build, find that table (an array of pointers to
short uppercase ASCII opcode names) and read it in order — the index of each name
*is* its opcode number.

**This is the item most likely to change between builds.** Re-derive rather than
trust; the names and their stock equivalents are durable, the indices are not.

## 6. Carving without an index

When you cannot resolve payloads through an index, carve heuristically:

1. Scan for the header bytes `\x1bLua\x54\x00\x19\x93\r\n\x1a\n`.
2. For a hit at `sig_off`, treat `sig_off - 6` as the `LuaTextPacked` start.
3. Read `u32le decoded_size` there; LZ4-block-decompress from `sig_off - 2`.
4. Validate the output against the §3 header.

Step 4 is what makes this safe — the header has enough fixed bytes
(`LUAC_INT`, `LUAC_NUM`) that false positives essentially cannot survive it.

Note that non-LuaText payloads may sit behind additional wrappers
([ezst.md](ezst.md), `HEX_`) before any Lua bytes appear.

## 7. Tooling gotchas

- Disassemble with **Lua 5.4.7** `luac -l -l`. Homebrew's `luac` is 5.5 and
  **cannot read 5.4 chunks** — it fails in a way that looks like your remapping
  broke the file.
- **`luajit-decompiler-v2` does not apply here.** It targets LuaJIT bytecode;
  these are Lua 5.4 chunks. A copy of it vendored in an earlier tree is a trap.
- Runtime dumping validates static recovery: hook `luaU_undump` and capture its
  input. Locate it by **signature scan** for the name-prefix check (it compares
  the first byte of `name` against `'@'`, `'='`, and `0x1b`) rather than by
  address — see `messiah.frida.dump_lua`. The header validator is a **separate
  routine called early** from `luaU_undump`, so follow that call to reach it.

  > **A runtime dump is only ground truth when the sizes agree.** Dumps and
  > packed blobs can come from *different game versions*, so compare a dump
  > against a static unpack only when the wrapper's `decoded_size` equals the
  > dumped chunk size. A mismatch usually means mismatched versions, not a bug
  > in your unpacker — this has cost real time.

- The launcher's size-byte checks sit next to the literal strings
  `"Instruction"`, `"lua_Integer"`, `"lua_Number"`, which makes them usable
  anchors for finding the header validator.

## 8. Open questions

- What do `LDAD` and `MMBIN_LDAD` actually do? Neither appears in any sample, so
  their operand layout is unknown and remapping them is currently impossible.
- Do the "proxy" opcodes imply a runtime table representation that differs from
  stock Lua enough to matter when re-injecting modified bytecode?

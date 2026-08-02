# Methodology: techniques, anchors, and traps

**Scope:** how to re-derive this knowledge against a **new build**. Everything
here is deliberately build-independent — no addresses, because addresses are the
first thing to rot.

**Prerequisites:** none.

---

## 1. The core discipline: anchor on strings and signatures

Function addresses change every build. Strings, constants, and instruction idioms
do not. Every location procedure in these docs is expressed as a search.

The standard radare2 loop:

```sh
r2 -e bin.cache=true -e bin.relocs.apply=true <binary>
aaa
```

```r2
izz~<Name>          # find the string
axt @ <str_addr>    # who references it
pdf @ <fcn>         # disassemble the referencing function
```

Useful search forms: `/v8 <u64>` for a value, `/x <hex bytes>` for raw bytes,
`/a <instruction>` for an assembly idiom.

## 2. Durable string anchors

These names appear in the binaries and survive rebuilds:

| String | Leads to |
|---|---|
| `MPatch` | the Lua API registration routine ([launcher-api.md](launcher-api.md)) |
| `ParsePatchList`, `ParseFileList`, `ParseIgnoreList` | the patchlist msgpack ingest path — `ParsePatchList` dispatches on map keys to the other two |
| `MurmurHash` / `Messiah` (demangled symbol) | the hash routine, in builds that keep symbols |
| `ListDir` | the VFS listing chain — see §5 |
| `FileDispatcher` | the C++ filesystem hub, `Messiah::FileDispatcher`, with `ListDir` / `OpenFile` / `OpenFileData` / `GetSubFileSystem` / `FileExist` |
| `acp_to_utf8` (demangled symbol) | the ANSI→UTF-8 normaliser on the `ListDir` path |
| `XorExcrypt`, `ZipDecompress` | the two distinct crypto primitives |
| `.mpkinfo` | index-path construction helpers |
| `LuaText/`, `LocalData/Patch/LT`, `Package/LT` | Lua storage paths. Two separate initialisers build path roots — one from `LocalData/Patch/LT`, one from `Package/LT` + `LuaText` — and they are the entry point to the packed-stream decoder |
| `patch mpk entry collision` | an assert beside the file-id builder's callers |

Those parser names are usable as anchors because they are **stored into a
parser-state struct** on error (alongside a byte offset), not merely printed —
which also identifies the state struct.

Two more identification tricks:

- **Read the embedded PDB path** (`rabin2 -I`). It carries the internal project
  name and is the quickest confirmation that you have an unobfuscated build.
- **The `HEX_`/`HEXB_` decoder sits adjacent to the content-loading pipeline**,
  so finding one gives you a neighbourhood for the other.

## 3. Durable constant anchors

Constants are even better than strings — they identify an *algorithm*:

| Constant | Identifies |
|---|---|
| `0xCC9E2D51`, `0x1B873593`, `0xE6546B64` | MurmurHash3 x86-32 core |
| `0x85EBCA6B`, `0xC2B2AE35` | Murmur3 finaliser |
| `0xcbf29ce484222325` / `0x100000001b3` | FNV-1a 64 basis / prime — used by the patchlist parser's internal hash table |
| `0x6f666e696b706d2e` | the ASCII bytes of `.mpkinfo` as a qword immediate |
| `0x431bde82d7b634db` with a shift of 0x12 on the high half | MSVC's magic for **division by 1,000,000** — i.e. `field4` splitting. It equals `floor(2^82/1e6)+1`, and the shift means a **total** shift of `64 + 0x12 = 82`; knowing the derivation lets you recognise a *variant* magic on a rebuild rather than only this literal. Search `/x db34b6d782de1b43`. Noisy (unit conversions use it too), so confirm by context |
| `0xDEADBEEF` | HD container magic |
| `cmp dword [reg], 0x42584548` (`'HEXB'`) | the wrapper decode dispatcher; it also tests `'HEX_'` |
| msgpack map headers: fixmap `0x80..0x8f` (low nibble = count), map16 `0xde`, map32 `0xdf` | confirms you have found a msgpack map reader — the shape-check for the patchlist parser |
| `1073741823` (`2^30 - 1`) | the "sorted resource v2" address mask — see §6 |

Instruction idioms worth searching when hunting a decoder:

- uLEB128: `and eax, 0x7f` paired with `test al, 0x80`
- paged pointers: `shr eax, 0x18`, `and eax, 0xffffff`

## 4. Traps that have actually cost time

### The registration-order trap

**In the Lua binding idiom, the callback pointer is pushed *before* the name it
belongs to.** Reading the pointer that follows a name shifts every attribution by
one. This produced a documented wrong conclusion — that `XorExcrypt` was the
base64+zlib pipeline — which then propagated into several notes.

Generalise it: **do not trust adjacency.** Confirm an attribution independently.
Argument count is a cheap, effective discriminator.

### Inflate is not proof

Short windows of arbitrary base64-ish text sometimes raw-inflate into
low-entropy output (long single-character runs). A successful decompress is not
evidence of a real payload — require the result to parse as msgpack or JSON.

### Extension is not format

Files carrying an `.mpkinfo` extension may be binary indexes *or* `HEXB_` text
wrappers. Sniff the magic; never dispatch on the filename.

### Two different varints

Lua chunks use a varint whose high bit means **stop**
([lua-bytecode.md](lua-bytecode.md) §4). The mapping table uses real uLEB128,
where the high bit means **continue** ([path-mapping-table.md](path-mapping-table.md)
§3). They look identical and are not. Never share a decoder.

### Two different Murmur hashes

Path → id uses Murmur3 **x86-32**. Content hashing uses Murmur3 **128**, folded.
Same family, different function, different input.

### Pointers land mid-structure

Internal pointers frequently target a position *inside* a table rather than its
start — probably binary-search anchors. Recover run bounds by scanning outward on
the record stride at the correct alignment.

## 5. `ListDir` as a pressure point

The single best idea for the path-recovery problem.

The game can open files by hashing a path, so opening does not require a name
registry. But **directory listing does** — you cannot enumerate and stringify
entries without one. So `ListDir` must touch whatever internal registry exists.

The chain to follow: Lua `ListDir` binding → a wrapper that ACP→UTF-8 normalises
the argument → a large path parser/dispatcher that builds an internal path object
and routes to a concrete filesystem implementation. **The concrete implementation
that enumerates entries is where a hidden id→path registry would live.**

That chain has been mapped; the terminal enumeration function has not been
analysed. It remains the most promising unexplored lead.

## 6. Use the shipped Lua, not just the binary

A repeatedly effective move: **the game's own Lua answers questions the native
code obscures.**

Confirmed examples:

- `field4`'s split into `(group, index)` was confirmed from **`parse_order_spec`**
  in the patch-fetcher script — a tiny function doing an explicit divide and
  modulo by 1,000,000. Disassembled, it is ~11 instructions: `DIVK 1000000`,
  `MODK 1000000`, return two values. The native parser treats `field4` as an
  opaque integer and would never have told you.
- The `meta` obfuscation (`transform_string`) is Lua-side; the native code only
  provides the XOR primitive.
- The mapping-table blob ids, which appear **nowhere** as immediates in the
  launcher binary, *do* appear as 64-bit constants in a shipped patcher stage
  script. "Not in the binary" does not mean "not in the client".

To use this: dump Lua at runtime by hooking `luaU_undump`, convert to stock
opcodes, then disassemble. See [lua-bytecode.md](lua-bytecode.md).

**Scan Lua constant pools, not just disassembly.** A compiled chunk's constant
table holds 64-bit integer literals, so searching every dumped `.luac` for a
target i64 finds which script references a value — that is exactly how the blob
ids above were located after the binary search came up empty.

Beware the patch fetcher's **"sorted resource v2"** addressing, gated behind a
`_use_sort_res_v2` flag. It treats the address as a bitfield with a 30-bit
shift and a mask of `2^30 - 1` (`1073741823`). It is a **different** scheme from
`field4` — which stays below `2^28` in observed installs — and the two are not
interchangeable. When hunting `field4` consumers, stay on the non-v2 branches.

## 7. Runtime dumping

Hook `luaU_undump` and capture its input buffer. Locate it by **signature scan**,
not RVA: it compares the first byte of the chunk name against `'@'` (0x40),
`'='` (0x3d), and `0x1b`. That three-way compare is distinctive and stable.

`messiah.frida.dump_lua` implements exactly this, with a fallback that xrefs the
`binary string` error message. Treat it as the house style for any new hook:
**a script with a hardcoded address is already broken.**

## 8. Cross-check invariants

Re-run these against any new build; each one validates a whole layer:

| Invariant | Validates |
|---|---|
| per pack, `max(offset+size) == pack file size` — **except for EZST-chunked packs, where it exceeds it by design** ([ezst.md](ezst.md) §1) | index parse + container resolution |
| `.mpkinfo` entry size == patchlist `filelist` size for the same id | both index parsers agree |
| HD `offsets[-1] == data_len` | HD container header arithmetic |
| extracted payload's content hash == the index's hash | **the entire chain**, end to end |

The last one is the strongest available test — see
[content-hash.md](content-hash.md) §5.

## 9. Tooling gotchas

- **Lua 5.4.7 `luac -l -l`** is required for disassembly. Homebrew's `luac` is
  5.5 and cannot read 5.4 chunks; it fails in a way that looks like your
  conversion broke the file. Build 5.4.7 from source.
- **`luajit-decompiler-v2` does not apply.** It targets LuaJIT; these are Lua 5.4
  chunks. A copy vendored into an earlier tree was a standing trap.
- **Dependency-free fallbacks** for cross-checking a suspected decode bug:
  `openssl enc -aes-256-ecb -d -nopad -nosalt -K <hex>` and `zstd -d --stdout`.

## 10. Resolution ordering

When looking up bytes for an id, prefer sources in this order:

1. `Patch.mpkdb` — authoritative for base packs.
2. `.mpkinfo` caches — update and LT packs.
3. Detect EZST-chunked containers and switch to logical offsets
   ([ezst.md](ezst.md)).

Build a unified SQLite index over both families rather than querying each
separately; it makes "where are the bytes for this id" a single query and makes
the disjointness of the two namespaces visible.

Generated indexes and corpora are **derived data** — regenerate them, never commit
them. They are install-specific and go stale silently.

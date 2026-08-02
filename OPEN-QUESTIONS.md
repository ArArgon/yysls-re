# Open questions

Ordered roughly by value. Each entry states what is *known* — the constraints
matter as much as the question, because they rule out approaches that look
obvious.

---

## 1. Filename recovery (the big one)

**Question:** recover VFS paths for the assets that are keyed only by hash — the
overwhelming majority.

**Why it is hard:** `file_id` is one-way. There is no id→path table anywhere in
the indexes.

**What is known:**

- The hash is fully understood ([file-id.md](docs/file-id.md)), so
  path→id is cheap and any candidate can be tested instantly.
- The low half is a **constraint filter**: a candidate must end with a specific
  3-byte suffix (extension stripped) and match a length residue *before* you
  hash it. This makes dictionary attacks far cheaper than they look.
- Four cleartext sources already exist: patchlist `mapping_ignorelist`,
  path-keyed `filelist` entries, TEXT-keyed `Patch.mpkdb` rows, and strings
  recovered from decoded Lua.

**Most promising untried lead:** **HD store payload strings**
([hd-store.md](docs/hd-store.md) §6). These are canonical VFS paths, they exist
in bulk, and harvesting them is mechanical — decompress every `data*` block,
parse the payload, collect string tokens, filter for path shapes, hash, join.
This has been demonstrated on individual payloads but never run at scale.

**Second lead:** the `ListDir` chain ([methodology.md](docs/methodology.md) §5).
Directory listing cannot work without an internal name registry, so the terminal
enumeration function must touch one. The chain has been mapped; the final
function has not been analysed.

---

## 2. The `(group, index) → path` mapping

**Question:** what decodes `field4` into a path, and where does it live?

**What is known:**

- The split into `(group_id, index)` is confirmed from shipped Lua.
- `index` is exactly dense `0..N-1` per group.
- For **pure** groups the rank-by-offset model reproduces `index` exactly. For
  **mixed** groups — those spanning many physical packs — it does not, and the
  true ordering key is unknown.
- A large on-disk structure with group-root pointers, front-coded dictionary
  blocks, and several pointer encodings has been decoded structurally
  ([path-mapping-table.md](docs/path-mapping-table.md)) — but its symbol
  sequences resolve to token-corpus strings that hash to **nothing**.
- **Key negative result:** the token corpus entries are not paths. Hashing all of
  them yields zero matches. They are components of a secondary encoding.
- The blob ids are absent from the launcher binary but **present as constants in
  a shipped patcher stage script** — so follow the Lua, not the binary.

**Most promising untried lead:** the u16-id → pointer records
([path-mapping-table.md](docs/path-mapping-table.md) §4). These bridge the
"unknown symbols" produced by dict-block decoding to concrete addresses. The
targets are still binary and undecoded — but this is the only confirmed link
from the unresolved symbols to anything.

---

## 3. HD store gaps

- **Undecoded record kinds.** Only two `u7` pool discriminators are known, and
  many records have `u0` outside both pools — so the known values do not cover
  the table.
- **`field_id` → name.** FTV payloads key fields by an unmapped byte namespace.
  The `index*` blocks contain field-name string tables. Correlating the two is
  the obvious move and has not been attempted.
- **MANIFEST trailer** structure beyond the container filename lists.
- **Unexplained content:** the HD directory also holds plain JSON assets and
  named blobs, and zlib-framed data has been observed — none of it explained by
  the container format.

---

## 4. Smaller unresolved items

| Item | Doc |
|---|---|
| `.mpkinfo` `typeflag` semantics (only a placeholder use is confirmed) | [mpkinfo-index.md](docs/mpkinfo-index.md) |
| `.mpkinfo` trailer: two u64s, per-index, meaning unknown | [mpkinfo-index.md](docs/mpkinfo-index.md) |
| Which file the `HEXB_` integrity `offsets` list describes | [mpkinfo-index.md](docs/mpkinfo-index.md) §4 |
| `Patch.mpkdb.pak.v0` — a group id, but of what? | [patchdb.md](docs/patchdb.md) §3 |
| Whether `pak` per-chunk hashes use the same chunking rule | [content-hash.md](docs/content-hash.md) §3 |
| EZST per-block trailing bytes: metadata or padding? | [ezst.md](docs/ezst.md) §2 |
| `ZZZ4` — is it a chunked-pack header? | [ezst.md](docs/ezst.md) §3 |
| Whether other `meta` keys exist in other builds | [patchdb.md](docs/patchdb.md) §4 |
| What `LDAD` / `MMBIN_LDAD` do — never observed, so unremappable | [lua-bytecode.md](docs/lua-bytecode.md) §8 |
| Whether the auxiliary `CCCCZZZ4` dictionary is referenced at all | [path-mapping-table.md](docs/path-mapping-table.md) §6 |

---

## Resolved — do not re-open

These were open long enough to appear in older notes as unknowns. They are not.

- **The custom Luac format.** Solved: the opcode table is fully mapped and the
  remapper reproduces stock Lua 5.4 chunks. Only two never-observed opcodes
  remain unmapped.
- **The `LuaText` packed stream.** Solved: `u32` size + raw LZ4 block. There is
  no `0x03f6` magic — that is an LZ4 token.
- **`Patch.mpkdb.meta`.** Solved: `transform_string`, split at `len % 17`, XOR
  with the ASCII keys `"43"` / `"53"`.
- **`.mpkinfo` files with "bad magic".** Solved: they are `HEXB_` msgpack
  integrity wrappers, not indexes.
- **The `.mpkinfo` fifth field.** It is `packed`, not `patch_id`.
- **The EZST second u32.** It is the decompressed size, not a file id.

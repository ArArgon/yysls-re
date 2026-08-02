# The patchlist manifest

**Scope:** the `HEX_`/`HEXB_` transport wrapper, the msgpack manifest inside it,
and the `field4` grouping key.

**Prerequisites:** [file-id.md](file-id.md) — especially the signed/unsigned
distinction, which is where joins against this data usually go wrong.

**Implementation:** `messiah.codec.hexwrap`, `messiah.vfs.patchlist`

---

## 1. The `HEX_` / `HEXB_` transport wrapper

Several config and manifest files on disk are ASCII text beginning with `HEX_` or
`HEXB_`. Decode chain:

1. Strip the prefix, **base64-decode** the remainder — standard `A-Za-z0-9+/`
   alphabet, not a custom one.
2. **XOR** with the repeating key `netease_hex_xor_encrypt_key` (27 bytes).
3. **zlib**-inflate.
4. Parse the result — **msgpack** for patchlists, JSON for configs.

The same wrapper appears on patchlists, `patch_config.json`, `essential.txt`, and
on some files carrying an `.mpkinfo` extension (see
[mpkinfo-index.md](mpkinfo-index.md) §4). Always sniff the prefix rather than
trusting the extension.

Natively this is the `ZipDecompress` callback — **not** `XorExcrypt`, which is a
different primitive with a different key. See [patchdb.md](patchdb.md) §5.

An encoder counterpart (deflate → XOR → base64) also exists in the binary.

> **False-positive warning.** Short windows of arbitrary base64-looking text can
> occasionally raw-inflate into low-entropy output (long runs of one character).
> A successful inflate is *not* proof you found a real payload — require the
> result to parse as msgpack or JSON.

## 2. Manifest structure

The decoded msgpack root is a map keyed by **package name**. Package names are
deployment-specific — discover them from the decoded map, never hardcode them.

Each package contains three sub-maps:

| Key | Contents |
|---|---|
| `pak_filelist` | `pak_id → [size, hash]`. At least a subset is chunk-level metadata: every `Patch.mpkdb.pak` hash has been found here, but not the reverse |
| `filelist` | the per-file manifest, see §3 |
| `mapping_ignorelist` | plain path strings — a free cleartext path corpus |

## 3. `filelist` entry shapes

Keys are **either** a numeric `file_id` (the vast majority) **or** a literal path
string.

### Numeric-keyed

```
filelist[file_id] = [size, hash64, [pak_id, offset], field4]
```

`[pak_id, offset]` locates the bytes inside a downloadable chunk blob, which
joins onward through `pak_filelist` into `Patch.mpkdb.pak` — see
[patchdb.md](patchdb.md) §3.

### Path-keyed

```
[size, hash64]                                  small index-like blobs
[size, hash64, [pak_id0, -1, pak_id1, -1, ...]] large standalone files
```

The second shape represents a file assembled by concatenating whole chunk blobs.

Path-keyed entries fall into a stable set of top-level namespaces —
`BinPatch/`, `Other/`, `HD/`, `TroyConfig/`, `Shader/`, `LuaText/`, `AILab/`,
plus bare no-slash names for container files themselves (`LT{n}.mpk`,
`LT{n}.mpkinfo`, `Patch{n}.mpk`, `TinyFiles_*.mpkinfo`).

Two things follow from that list:

- `HD/*` members appear here, which proves the HD store is delivered through the
  same patch pipeline. See [hd-store.md](hd-store.md).
- Container files are themselves patchable objects — the patcher handles them as
  **literal paths**, so they are generally not in `Patch.mpkdb` under a hashed id.
  Do not expect a path-keyed entry to resolve via `file_id`.

## 4. The signed/unsigned trap

**Patchlist ids are unsigned u64 in msgpack. `Patch.mpkdb` stores them as signed
i64.** Join without converting and roughly half your rows silently vanish — the
half with the high bit set. Convert before every join.

## 5. `field4`

The fourth element of a numeric-keyed entry is a composite:

```
group_id = field4 // 1_000_000
index    = field4 %  1_000_000
```

This split is **confirmed** from shipped game Lua, which parses it with an
explicit divide and modulo by one million.

### Structural invariants

- Within every `group_id`, `index` is exactly dense `0 .. N-1` — minimum zero,
  distinct count equals row count, maximum equals count minus one. It is a true
  index, not a sparse tag.
- `group_id` is bounded by the same range as base-pack ids.
- `group_id` is **not** equal to the physical pack id from `Patch.mpkdb`. They
  agree only for a minority of rows, so it is a *logical* grouping, not a
  location.

### The rank model

For **pure** groups — those whose members all live in a single pack whose id
equals the `group_id` — `index` is the 0-based rank of the file when the group's
members are ordered by physical offset. Verify with:

```sql
-- info0.v2 = pack id, info0.v6 = offset within the pack (see patchdb.md)
select count(*) from info0 where v2 = :group_id and v6 < :offset;
-- equals index
```

Substituting `group_id` for the pack id is valid **only** for pure groups.

This explains both the density of `index` and the bounded range of `group_id`.

### Mixed groups break it

Some groups span many physical packs. For those, ordering by offset does **not**
reproduce `index`, so the rank model is not the general rule — it is a special
case that happens to cover the pure groups.

The true ordering key for mixed groups is **unresolved**. Record what has been
eliminated so it is not re-tested: **ruled out** are ordering by file offset and
by `(pack, offset)`. **Never tried** are ordering by `file_id`, by content hash,
and by a stable build-time index. The required extra layer is the suspected
purpose of the structure in [path-mapping-table.md](path-mapping-table.md).

### What `group_id` might mean

Three candidate readings, none confirmed:

1. the **pre-compaction pack assignment** — where the file lived before a repack;
2. an **index-file number** used by the launcher's MPK cache APIs (note
   `AddPatchMpkEntryByMpkinfo` and friends in [launcher-api.md](launcher-api.md));
3. a **content-category bucket** used by the patch planner.

A concrete untried experiment: cross-check `group_id` against the pack ids in the
update-pack cache indexes, to see whether it names a base-pack *parent* of
update-pack content.

A useful diagnostic is to report, for a given `field4`: the patchlist row, the
physical location, the rank within the pack, the rank within the group, and the
count of distinct packs the group spans. The last number tells you immediately
whether you are looking at a pure or mixed group.

## 6. Path recovery yield

Three cleartext sources come out of this format, and together they form the seed
corpus for hashing and joining:

1. every `mapping_ignorelist` entry,
2. every path-keyed `filelist` key,
3. (from the other index) `Patch.mpkdb` rows with a TEXT id column.

Build a corpus of `(source, package, path, file_id_u64, file_id_i64,
resolved-location-if-any)` and it answers both "what is this path's id" and
"does this path actually exist locally".

# The VFS model

**Scope:** how the game's asset filesystem is put together — what a container is,
which index describes which container, and the invariant decode chain. Read this
first; every other format doc slots into the picture drawn here.

**Prerequisites:** none.

---

## 1. The one thing to internalise

**`.mpk` containers are dumb byte blobs. They contain no filenames, no directory,
no table of contents.** A container is a concatenation of payload slices and
nothing else.

Everything that makes it a *filesystem* lives in **external indexes**. An index
maps an opaque 64-bit `file_id` to a `(container, offset, size)` triple. Lose the
index and the container is unreadable — there is no in-band structure to recover.

This single fact drives the whole design: there is no "open the mpk and list it"
operation, and any tool that appears to do so is really parsing an index.

## 2. The invariant extraction chain

Every read, regardless of container type, is these four steps:

1. **Parse an index** — `.mpkinfo`, `Patch.mpkdb`, or the patchlist msgpack.
2. **Resolve the container** the index refers to, by naming convention (§4).
3. **Read bytes** at `offset .. offset+size`.
4. **Decode wrappers** if present — `EZST`, `HEX_`, `HEXB_`, `LuaText` packing.

Step 3 has one important subtlety: for some containers those offsets address a
*logical* decompressed stream rather than physical file bytes. See
[ezst.md](ezst.md) for the diagnostic and the fix.

## 3. Who indexes what

Two index families cover **largely disjoint** namespaces. This is a durable
structural property, not a coincidence of one install — do not assume an id found
in one will appear in the other.

| Index | Authoritative for | Doc |
|---|---|---|
| `Patch.mpkdb` (SQLite) | the base packs | [patchdb.md](patchdb.md) |
| `*.mpkinfo` (binary) | `Resources`, `LT*`, update packs, cache indexes | [mpkinfo-index.md](mpkinfo-index.md) |
| patchlist msgpack | download chunks (`pak`), plus some literal path keys | [patchlist.md](patchlist.md) |

The patchlist's numeric key set has been observed to be a *superset* of the
`Patch.mpkdb` integer ids — it describes what the patcher can fetch, while
`Patch.mpkdb` describes what is currently unpacked locally.

## 4. Naming conventions (patterns, never instances)

Container resolution is by convention. Record the **shape**, and discover the
instances at runtime — never hardcode a number:

| Index seen | Container to open |
|---|---|
| `Resources.mpkinfo` | `Resources.mpk` (install root) |
| `LT{n}.mpkinfo` | `LT{n}.mpk` (patch root) |
| `Patch{n}.mpkinfo` | `Patch{n}.mpk` (patch root) |
| `MpkCached_*` / `TinyFiles_*` | `Patch{pack_id}.mpk`, from each entry's `pack_id` |
| `Patch.mpkdb` row | `Patch{v2}.mpk`, from the row's pack column |
| HD store | `data{n}` / `index{n}` under the HD root |

Typical install layout, again as a shape:

```
<install root>/
    Resources.mpk, Resources.mpkinfo
    LocalData/Patch/           <- patch root: the primary VFS
        Patch.mpkdb
        Patch{n}.mpk, LT{n}.mpk, LT{n}.mpkinfo
        MpkCached_<pkg>.{n}.mpkinfo, TinyFiles_<pkg>.{n}.mpkinfo
        patchlist_<pkg>.txt, sub_patchlist_<pkg>.txt   (HEXB_ wrapped;
                                   the sub_ copy has been observed to be
                                   byte-identical -- parse one, not both)
        patch_config.json, essential.txt               (HEX_ wrapped)
        LuaText/...            <- some Lua chunks sit here as loose files
        HD/                    <- separate container family, see hd-store.md
```

### Base packs vs update packs

The pack-id space splits in two, and the distinction matters because it tells you
which index to trust:

- **Base packs** — the low end of the id space, shipped with the install,
  indexed by `Patch.mpkdb`. These ids appeared stable across the builds
  observed, but that is an observation, not a guarantee.
- **Update packs** — much higher ids, minted per release, indexed by the
  `.mpkinfo` caches. These are frequently the EZST-chunked ones.

The split is by **magnitude**, not by a fixed digit count — do not encode a
threshold. Classify a pack by which index describes it, not by its number.

> **Which pack holds a given asset is not stable.** Resolve it through the index
> every time. A pack number remembered from a previous build is worthless, and a
> hardcoded one is a bug.

## 5. The opaque key

Assets are keyed by a 64-bit `file_id` derived from the VFS path by hashing —
see [file-id.md](file-id.md). Because the derivation is one-way, **most assets
have no recoverable filename**. A small minority are stored under literal text
paths instead of hashes; those are the seeds for path recovery.

The `file_id` appears in three encodings, and mixing them up is a common bug:

- split as two u32 halves (`s0` low, `s1` high) in `.mpkinfo`
- **unsigned** u64 in patchlist msgpack keys
- **signed** i64 in SQLite (`Patch.mpkdb`)

Converting unsigned↔signed is mandatory before joining patchlist to `Patch.mpkdb`.

## 6. Cross-check invariants

These hold structurally and are worth re-running against any new build — they
catch a misparsed index immediately:

- Per base pack, `max(offset + size)` over its rows equals that pack's file size.
- An `.mpkinfo` entry's `size` matches the patchlist `filelist` size for the same id.
- For an HD container, the final offset entry equals the data-region length.
- If a pack's `max(offset + size)` *exceeds* its physical size, the offsets are
  logical and the pack is EZST-chunked — not corrupt.

## 7. Path recovery: the open problem

The overwhelming majority of ids have no path string anywhere in the manifests.
Known cleartext sources, in rough order of yield:

1. Patchlist `mapping_ignorelist` entries — plain path strings.
2. Patchlist `filelist` entries keyed by a literal path rather than an id.
3. `Patch.mpkdb` rows whose id column is TEXT (script paths, flagged by the
   script column).
4. **String values inside HD store payloads** — these are canonical VFS paths and
   are the most scalable untapped source. See [hd-store.md](hd-store.md).
5. Strings harvested from binaries and decoded Lua.
6. **Manifests shipped *inside* containers.** At least one payload carved from a
   pack is a manifest with the same package → `filelist` shape as the on-disk
   patchlist — but encoded as **JSON** rather than msgpack. Manifests are not
   only found beside the packs, and the in-band copy uses a different encoding.
   This is a promising and largely unexplored source.

The method is always the same: harvest a candidate path, compute its `file_id`,
and join against the indexes. See [file-id.md](file-id.md) for a filter that makes
guessing cheap, and [path-mapping-table.md](path-mapping-table.md) for the
in-progress work on a suspected on-disk mapping structure.

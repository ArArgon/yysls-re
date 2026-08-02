# The `.mpkinfo` binary index

**Scope:** the binary index format that maps `file_id` to a location inside an
`.mpk` container, plus the ASCII variant that shares the extension but is not an
index at all.

**Prerequisites:** [file-id.md](file-id.md) for the key; [vfs-model.md](vfs-model.md)
for which container an index refers to.

**Implementation:** `messiah.vfs.mpkinfo` · spec copy at `ksy/mpkinfo.ksy`

---

## 1. Sniff before you parse

**Not every file with an `.mpkinfo` extension is a binary index.** Some are ASCII
text beginning with `HEXB_` (or `HEX_`). Parsing those as binary yields a "bad
magic" error that looks like corruption but is not.

Always check the leading bytes first:

- starts with `HEX_` / `HEXB_` → it is a wrapped payload, see §4
- first u32 is `3` → binary index, see §2

This trips people up because the two kinds sit side by side in the same
directory under near-identical names. In the cases observed, the wrapper
occupied the **last-numbered member** of a numbered family (`<family>.N`) while
the lower-numbered siblings were binary indexes — a useful positional hint, not
a rule.

## 2. Binary layout

All little-endian.

```
u32   magic        == 3
u32   file_nums
entry[file_nums]:
    u32  s0        file_id low half
    u32  s1        file_id high half
    u32  offset    within the referenced container
    u32  size
    u32  packed    bit-packed pack id + type flag
u64   trailer0
u64   trailer1
```

Entry stride is 20 bytes; the trailer is 16 bytes. Total size is therefore
`8 + 20*file_nums + 16`, which is a cheap sanity check on `file_nums` before you
allocate anything.

### The `packed` field

```
pack_id  = packed >> 1
typeflag = packed & 1
```

> **Correction.** This field was long documented as `patch_id` and decoded as
> `packed // 2`. That happens to give the right pack id but silently discards the
> type flag. The bit-packed reading was confirmed from launcher code. Any older
> note or generated parser using `patch_id` / `// 2` is wrong.

`typeflag` semantics are **not** established. What is confirmed:

- Entries with `typeflag == 1` have been observed as placeholders, with both
  `offset` and `size` zero.
- Large cache indexes have been observed with `typeflag` uniformly zero.

It is *not* confirmed to mean "Patch vs LT". Treat it as unknown with a known
placeholder use, and do not build resolution logic on it.

### Trailer

Two u64 values follow the entries. Their meaning is unresolved. They are worth
recording when inventorying an index — they differ between files, so they encode
something per-index rather than being padding.

## 3. Resolving the container

The index does not name its container. Resolution is by convention on the
*index's own filename*, plus the per-entry `pack_id`:

| Index filename | Container |
|---|---|
| `Resources.mpkinfo` | `Resources.mpk` in the install root |
| `LT{n}.mpkinfo` | `LT{n}.mpk` in the patch root |
| `MpkCached_*` / `TinyFiles_*` | `Patch{pack_id}.mpk`, per entry |

Because a cache index can point at many different packs, resolution is per-entry,
not per-file. See `messiah.vfs.containers` — never hardcode a pack number.

**Offsets may be logical.** If an index's `max(offset + size)` for a pack exceeds
that pack's physical size, the container is EZST-chunked and the offsets address
a decompressed stream. See [ezst.md](ezst.md).

## 4. The `HEXB_` variant: integrity metadata

Files that decode via the `HEX_`/`HEXB_` chain (see [patchlist.md](patchlist.md)
§1) yield **msgpack**, not an index. The decoded map has these keys:

- `content_md5` — 32-character ASCII hex digest, hypothesised to cover the
  **decoded payload / raw index content**
- `file_md5` — 32-character ASCII hex digest, hypothesised to cover the
  **wrapper file or the target `.mpkinfo`**
- `offsets` — list of integers, hypothesised to be chunk boundaries

Neither digest binding is confirmed. Taken together this looks like integrity
and chunking metadata, most plausibly for resumable download or patcher staging.

Which concrete file the offsets describe is **unresolved**. The naming suggests a
relationship to the sibling numbered indexes in the same family, but that has not
been confirmed.

## 5. Cross-checks

- An entry's `size` should equal the patchlist `filelist` size for the same
  `file_id`. This validates both parsers at once.
- Entries with `offset == 0 && size == 0` are placeholders, not failures.
  **But not every zero-size entry has a zero offset** — some carry a non-zero
  offset with `size == 0`. When computing extents or extracting, test
  `size == 0` rather than the stricter both-zero condition.
- Cross-references between the index families run **both ways**, and checking
  only one direction hides half the picture:
  - some non-zero index entries have no counterpart in the patchlist — these are
    bootstrap blobs indexed in the container index and nowhere else;
  - some patchlist numeric ids are absent from the index but **do** resolve in
    `Patch.mpkdb`. One hypothesis for that group is a cross-pack delta registry;
    it is unconfirmed.

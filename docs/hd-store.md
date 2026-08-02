# The HD store

**Scope:** the container family under the patch root's `HD/` directory — a
completely separate storage system from MPK, with its own container format,
registry, and two inner serialization dialects.

**Prerequisites:** [vfs-model.md](vfs-model.md) for context on how HD relates to
the MPK system.

**Implementation:** `messiah.hd.store`, `messiah.hd.manifest`, `messiah.hd.payload`

---

## 0. Why this matters beyond itself

The HD store is delivered through the same patch pipeline as everything else (its
members appear as path-keyed patchlist entries), but it is **not** MPK. Its keys
do not map to MPK `file_id`s.

Its strategic value is §5: **string values inside HD payloads are canonical VFS
paths.** That makes the HD store the largest untapped source of cleartext paths
for the id→path recovery problem — an independent corpus you can hash and join.

## 1. Container format

Files come in two families, `index{n}` and `data{n}`, sharing one outer layout:

```
u32le magic    = 0xDEADBEEF
u32le version  = 1
u32le count                 number of blocks
u32le reserved = 0
u32le offsets[count]        monotonic
u8    data_region[]

base     = 16 + 4*count
data_len = file_size - base
```

**Offsets are relative to the data region, not absolute file offsets.** This is
the single easiest thing to get wrong. Block `i` spans:

```
start = 0 if i == 0 else offsets[i-1]
end   = offsets[i]
bytes = file[base + start : base + end]
```

### Validation invariant

`offsets[-1] == data_len`

If that holds, your `count` and `base` arithmetic are right. If it does not, stop
— everything downstream will be garbage. Check it before parsing any block.

## 2. Per-block header

Every block, in both families, is a 9-byte header followed by a zstd frame:

```
u32le a     = (compressed_len   << 8) | 0x04
u32le b     = (decompressed_len << 8) | 0x00
u8    flags                              observed always 0
zstd frame at block offset 9
```

The lengths are stored **shifted left by 8** with a tag byte in the low position —
so read them as `a >> 8`, not as plain integers. Consistency checks:

- `compressed_len == block_size - 9`
- `decompressed_len == len(zstd_decompress(block[9:]))`

## 3. `MANIFEST` — the registry

`MANIFEST` is not a plain zstd file. It opens with the same `0xDEADBEEF` + version
and has a zstd frame embedded a short distance in — **find the frame by scanning
for the zstd magic `28 B5 2F FD`**, do not assume a fixed offset.

Decompressed payload:

```
u16 v1
u16 v2
u32 unk0
u32 count_pool2
u32 count_table
u32 count_pool3
u32 count_pool1        <- note the pool counts are NOT in pool order

pool1, pool2, pool3    each: count strings of (u16 len + bytes), 8-byte aligned
record_table           count_table records, each 32 bytes = 8 x u32le
trailer                includes the literal container filenames
```

Two traps: the pool counts appear in the header in the order 2, table, 3, 1 — not
1, 2, 3. And each string is padded to an 8-byte boundary, so you cannot walk the
pool by length alone.

The trailer contains the literal `index*` / `data*` filenames as strings, which is
a convenient way to discover the container set. Its full structure beyond those
name lists is **unresolved**.

### Record table

Each 32-byte record is eight u32 fields, `u0 .. u7`. Two are decoded:

**`u2` — the location pointer.** `0xFFFFFFFF` means "no pointer". Otherwise:

```
data_file_id = u2 & 0xFFFF
block_idx    = (u2 >> 16) & 0xFFFF
```

**`u7` — the pool discriminator**, selecting which pool `u0` indexes:

| `u7` | `u0` indexes | key namespaces observed |
|---|---|---|
| `0x400` | pool1 | mostly a dotted `AL.*` namespace, plus smaller ones like `building_prefabs.*`, `dialog_timelines.*` |
| `0x800` | pool2 | a `spaces.*` namespace |

The namespace column is how you pick a pool from a key alone, without searching
both.

`0x401` and `0x801` have also been observed and are **not decoded**. Their
pairing with the two known values suggests the low bit is a flag over a pool
selector — the obvious first hypothesis to test. Many records also have `u0`
outside both pool ranges, so these four values do not cover the table.

### Lookup procedure

1. Find the key's index in the appropriate pool (see the namespace column).
2. Filter records where `u0 == key_index`, `u7 == expected`, and
   `u2 != 0xFFFFFFFF`.
3. Resolve `data{data_file_id}`, take block `block_idx`, decompress.

Container names follow the `data{n}` / `index{n}` convention — resolve by
formatting the id, with no special cases. (An earlier implementation carried a
special-case branch for one particular id that was a no-op.)

## 4. `index*` blocks are schemas, not a search index

Despite the name, `index*` blocks do **not** provide a global key→location
lookup — that lives only in the MANIFEST record table.

What they contain is per-record schema: many decompress to a simple `u16` string
table of **field names**. Others decompress to larger fixed-size binary tables,
presumably a richer schema encoding.

An `index{n}` block often shares its block index with the corresponding
`data{n}` block, which is the likely mechanism for pairing a payload with its
schema — but that relationship is **unconfirmed**.

## 5. Inner payload encodings — there are two

After decompressing a `data*` block the bytes are still encoded. They are **not
encrypted**: strings are readable and numbers parse cleanly. But there are two
different formats, and a decoder must auto-detect.

Detect by the first byte: `0x0a` or `0x09` (optionally after a graph header)
means TLV; anything else means FTV.

Two caveats:

- **TLV parsing can succeed accidentally on an FTV payload**, producing
  plausible nonsense. Keep a manual dialect override and use it when output
  looks wrong.
- The reverse is loud, not silent: an FTV payload fed to the TLV parser
  typically dies immediately with an unknown tag **at offset 0**. That
  signature is a reliable "this is actually FTV" diagnostic.

### 5a. TLV — tag/length/value

All little-endian.

| Tag | Meaning |
|---|---|
| `0x0a` | **object**: `u16 item_count`, then that many child tokens |
| `0x09` | **array**: `u16 elem_count`, then that many child tokens |
| `0x08` | string: `u16 len` + bytes |
| `0x28` | bytes: `u16 len` + raw bytes — **weakly attested**: seen only once, though it parses cleanly and fits the stream |
| `0x01` | u8 |
| `0x02` | u16 |
| `0x03` | u32 |
| `0x04` | u64 |
| `0x05` | f32 |
| `0x06` | f64 |
| `0x0b` | null |
| `0x0c` | false |
| `0x0d` | true |
| `0x00` | padding between token groups — skip |

> **`item_count` counts tokens, not pairs.** An object used as a map with three
> key/value pairs has `item_count = 6`. Halve it before pairing, or you will read
> past the end of the object.

Maps are objects where `item_count` is **even** and the even-indexed children
are strings; that is a convention, not a distinct tag, so check both conditions
before pairing.

**Optional 8-byte graph header.** Graph-like payloads begin with:

```
u16le 0x0003   u16le 0x2800   u16le <variable>   u16le 0x0101
```

The same 8 bytes can **reappear mid-payload**, separating token groups — so treat
it as a group separator, not just a file prefix.

### 5b. FTV — field/type/value

A flat stream of `u8 field_id`, `u8 type_code`, payload.

| `type_code` | Payload |
|---|---|
| `0x00` / `0x01` | none — bool-ish. The working assumption is `0x00` = False, `0x01` = True (which is what the implementation encodes), but this is **unconfirmed** |
| `0x04` | u8 |
| `0x02` | u16 |
| `0x0c` | u32 |
| `0x10` | u64 |
| `0x14` | f32 |
| `0x18` | f64 |
| `0x20` | string: `u16le len` + bytes |
| `0x24` | nested primitive array: `u16le count`, then TLV primitive tokens |

Note the type codes are **not** the same numbering as the TLV tags — `0x04` is u8
here but u64 there. Keep the two tables strictly separate.

`0x24` payloads nest the *primitive subset* of the TLV encoding above (tags
`0x01`–`0x06`, `0x08`, `0x28`) — the only place the two dialects meet.

`field_id` is an unsigned byte namespace that is largely **unmapped**. Two
partial observations exist: one id frequently precedes `dict(config_id=...)`
strings, and another precedes dotted class-like names ending in `Handler`.
Mapping the namespace against the field names in the `index*` schema blocks is
the obvious next step and has not been done.

`0x00` bytes appear between tokens as padding — but **`0x00` is also a legal
`field_id`**, so it must not be skipped eagerly. Skip it only as a *recovery*
step after a token fails to parse; skipping it unconditionally corrupts the
stream. (In TLV, by contrast, `0x00` is unambiguous padding.)

## 6. Harvesting paths

`u64` values in these payloads are internal ids or enums — they have not matched
any MPK `file_id`. Do **not** treat them as ids.

The **strings** are the prize. Collect every string token, filter for
path-shaped candidates, compute `file_id` ([file-id.md](file-id.md)), and look
them up in `Patch.mpkdb`. Validated examples of this working end to end include
skeleton and graph asset paths recovered from behaviour payloads and confirmed
present in the patch packs.

## 7. Open questions

- The undecoded `u7` record kinds (start with the `0x401`/`0x801` low-bit
  hypothesis), and how records with out-of-range `u0` are addressed.
- Whether some payload types have **additional sections after the token
  stream** that are not modelled as tokens at all.
- The MANIFEST trailer's structure past the filename lists.
- Whether `index*` schema blocks are *required* to fully interpret FTV payloads
  (i.e. whether `field_id` → name is recoverable).
- The HD store also contains plain JSON assets and named blobs alongside the
  containers, and zlib-framed data has been observed — neither is explained by the
  format above.

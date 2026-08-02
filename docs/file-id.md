# file_id: VFS path → u64

**Scope:** the one-way function that turns a VFS path into the opaque 64-bit key
used by every index, and the constraint filter that makes reversing it tractable.

**Prerequisites:** none. [vfs-model.md](vfs-model.md) explains where these keys
are used.

**Implementation:** `messiah.vfs.fileid`

---

## 1. The algorithm

`file_id` is **not** a plain hash. It is two independent 32-bit halves glued
together, and only the high half is a hash:

```
file_id_u64 = (hi32 << 32) | lo32

hi32 = MurmurHash3_x86_32(path_utf8_bytes, seed = 0)     # the whole path
lo32 = TailSig(strip_last_extension(path_utf8_bytes))    # extension stripped!
```

The asymmetry is the important part: `hi32` sees the **full path**, `lo32` sees
the path **with its extension removed**.

### TailSig

For a byte string of length `n`, the general case packs the last three bytes plus
a truncated length:

```
lo32 = (b[n-1] << 24) | (b[n-2] << 16) | (b[n-3] << 8) | (n & 0xFF)
```

Shorter inputs degrade by **leaving the vacated slots empty**, rather than
shifting bytes down:

```
n == 2:  (b[1] << 24) | (b[0] << 16) | n      # the <<8 slot stays zero
n == 1:  (b[0] << 24) | n
n == 0:  0
```

That is easy to get wrong — the natural reimplementation packs `n == 2` as
`(b[1] << 16) | (b[0] << 8) | n`, which is a different value.

### GUID fast-path

Paths shaped like a two-character prefix, a slash, and a 36-character GUID take a
different branch, which is why so many GUID-named assets share structure. It
triggers when the length equals 39 or 41 (the latter being the GUID plus a
one-character extension) **and** byte index 2 is `/`. Then:

```
lo32 = big_endian_u32(b[3:7])      # the first four bytes after "xx/"
```

Structurally, the GUID test lives in the **builder**, not in `TailSig`: the
builder checks the shape and *either* returns the four bytes *or* calls
`TailSig` on the stripped path.

> **Unresolved discrepancy.** Disassembly notes say the length is tested on the
> **full** path, before stripping. Both the previous and current
> implementations test **after** stripping. The two agree on the documented
> shapes (a bare GUID, and a GUID plus a one-character extension `.6`) because
> that branch reads the same four bytes either way — but they diverge for other
> shapes, e.g. a GUID with a three-character extension.
>
> This has been checked against every cleartext path available and **no path
> triggers the divergence**, so the data cannot decide it. Treat it as open; if
> you find a GUID-shaped path with a longer extension that fails to resolve,
> this is the first thing to try.

Note also that under launcher semantics the four bytes come from the full path,
while under the current implementation they come from the stripped path — the
same ambiguity, stated in terms of the source buffer.

### Extension stripping caveat

"Strip the extension" means cut at the **last** `.`, but only if that dot comes
after the last `/`. Otherwise a directory component containing a dot
(`a.b/c`) would be truncated incorrectly.

## 2. Signed vs unsigned

The same value appears in three encodings. Joins fail silently if you mix them:

| Source | Encoding |
|---|---|
| `.mpkinfo` | two u32 halves, `file_id = (s1 << 32) \| s0` |
| patchlist msgpack keys | **unsigned** u64 |
| `Patch.mpkdb` id column | **signed** i64 (SQLite has no u64) |

Convert with two's complement: subtract `2^64` when the value is `>= 2^63`.

## 3. Why this matters for path recovery

`lo32` is a **cheap constraint filter**, and it is the single most useful
consequence of this design.

Given a target `file_id`, any candidate path must satisfy — before you compute a
single hash:

- **the suffix.** `TailSig` packs the **last** byte into the **top** byte, so the
  three suffix bytes come out *reversed* relative to path order. In path order
  the required suffix is:

  ```
  (lo32 >> 8) & 0xFF, (lo32 >> 16) & 0xFF, (lo32 >> 24) & 0xFF
  ```

  Read `lo32 >> 8` as a big-endian triple and you get the suffix backwards,
  which matches nothing — this is an easy and silent mistake. Use
  `messiah.vfs.fileid.tail_sig_constraint`, which returns the suffix already in
  path order.

- **the length.** `len(path_without_extension) & 0xFF` equals `lo32 & 0xFF`.

That prunes a dictionary attack enormously: you filter candidates by a suffix and
a length residue using plain string operations, and only Murmur-hash the handful
that survive. When guessing at unknown paths, always apply the `lo32` constraint
first.

The GUID fast-path is similarly informative in reverse: a `lo32` that looks like
four printable ASCII bytes with no plausible length byte suggests a GUID-shaped
path rather than a normal one.

## 4. Re-finding the builder in a new binary

Do not hunt for an address. Anchor on behaviour:

- Find the Murmur3 implementation by its constants: `0xCC9E2D51`, `0x1B873593`,
  `0xE6546B64`, and the finaliser's `0x85EBCA6B` / `0xC2B2AE35`.
- The file-id builder is the function that calls it and then merges the result
  with a second, much simpler helper — that helper is `TailSig`.
- The builder's callers are the MPK entry-table insert paths. A shipping assert
  string about *patch mpk entry collision* sits in that neighbourhood and makes a
  good string xref anchor.

See [methodology.md](methodology.md) for the general string-xref workflow.

## 5. Known negative result

Blob ids observed in the mapping-table work do **not** appear as immediate
constants anywhere in the launcher binary — searching for them as u64 values or
as raw bytes in either endianness returns nothing.

They **do**, however, appear as 64-bit constants in the shipped patcher Lua. So
"absent from the binary" meant "the client knows them from script", not "the
client never uses them" — a distinction that initially read as a dead end and
was not. Always check the Lua before concluding something is absent; see
[methodology.md](methodology.md) §6.

This still rules out "grep the exe for the id" as a shortcut for finding the
*loader*, which is why the `lo32` constraint filter is the practical way in.

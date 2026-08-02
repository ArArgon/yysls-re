# Content hashing

**Scope:** the 64-bit content hash stored in the indexes, and how to reproduce it.

**Prerequisites:** none.

**Implementation:** `messiah.codec.contenthash`

---

## 1. Algorithm

MurmurHash3-**128** per chunk, folded to 64 bits, XOR-accumulated across chunks:

```python
acc = 0
for chunk in chunks(data, chunk_size):
    h = mmh3.hash128(chunk)                    # 128-bit
    acc ^= (h >> 64) ^ (h & 0xFFFFFFFFFFFFFFFF)   # fold halves, then accumulate
return acc                                      # unsigned 64-bit
```

Two properties worth noting, because both are unusual:

- The fold is **XOR of the two 64-bit halves**, not a truncation. Truncating gives
  a plausible-looking wrong answer.
- Chunks are combined with **XOR**, which is order-independent. The hash cannot
  detect chunk reordering — only content changes within a chunk.

Note this is a *different* hash from the one in [file-id.md](file-id.md), which is
MurmurHash3-**x86-32** over a path string. Same family, different function,
different input. Do not reuse one implementation for the other.

## 2. Chunk size depends on file size

The chunk size is selected from the payload's own length, and the relationship is
counter-intuitive — **larger files use the smaller chunk**:

```
chunk_size = 2 MiB   if size >= 4 MiB
             32 MiB  otherwise
```

Because the second branch's chunk is larger than its own threshold, small files
are always hashed in a single chunk, and the loop collapses to one fold. The
branch only matters for files over the 4 MiB threshold, which get genuinely
chunked.

Getting this backwards produces correct hashes for every small file and wrong
hashes for every large one — a failure mode that looks like "mostly works".

## 3. Where the value appears

- `Patch.mpkdb.info0` content-hash column — see [patchdb.md](patchdb.md).
- Patchlist `filelist` entries carry a hash in the same position.
- `Patch.mpkdb.pak` per-chunk hash column, which is the join key into the
  patchlist's `pak_filelist`.

Whether the `pak` table's per-chunk hash uses this same rule or a different
variant is **unresolved** — it has not been verified end to end.

## 4. Signedness

SQLite stores these as signed i64. Compute unsigned, then convert before
comparing, exactly as with `file_id`. Comparing an unsigned Python int against a
negative SQLite value silently never matches.

## 5. Using it as a verification oracle

This hash is the best end-to-end check available for the whole extraction stack,
because it validates *content* rather than structure. If you extract a payload and
its hash matches the index, then the index parse, the container resolution, the
offset arithmetic, and any wrapper decoding were all correct.

Use it exactly that way when porting or when validating against a new build: walk
a pack's entries, extract each, hash, and compare. A pack that matches on every
entry is proof the whole chain is right; a pack that matches on small files but
not large ones points straight at the chunk-size rule in §2.

# The opaque path-mapping table

**Scope:** a large compressed lookup structure shipped inside one of the base
packs, strongly suspected to hold the missing `(group, index) → path` mapping.
This is the main **unsolved** area; the encodings below are decoded, but the
end-to-end path recovery is not.

**Prerequisites:** [patchlist.md](patchlist.md) §5 for what `field4` is and why
this structure matters.

**Implementation:** `messiah.mapping.ptr`, `messiah.mapping.dictblock`

> **On naming.** Earlier notes named this after the pack number it happened to
> occupy in one build. That number is minted per release and is meaningless now.
> Locate the blobs by their *structure* (§1), not by a remembered pack or file id.

---

## 1. The blobs and how to find them

Three related objects have been observed in the base packs. None of their ids
appear as constants in the launcher binary (see [file-id.md](file-id.md) §5), so
they must be found by content:

| Blob | Recognisable by |
|---|---|
| **Token corpus** | `u32[6]` header; pure ASCII after it |
| **Large table** | tens of MiB; leading zero page; paged-pointer records |
| **Auxiliary dictionary** | `CCCCZZZ4` magic; contains readable `;`-separated lists of asset-type words, plus other embedded strings |

The token corpus and the large table share a `lo32` tail signature — their
paths end in the same three characters (extension stripped) with the same
length residue, which is a usable constraint if you ever guess at their names
([file-id.md](file-id.md) §3). The auxiliary dictionary does **not** share it
and lives in a different pack.

The auxiliary dictionary's asset-type words resemble the 4-byte keys seen in
the large table's dictionary runs (§4), which is the reason it is suspected
relevant at all — though no reference from the table to it has been found.

### Token corpus format

```
u32 header[6]        header[5] (at offset 0x14) == text_len
text at 0x18         text_len bytes
```

The text is `;`-separated tokens, heavy in `/`, and containing **no `.` at all** —
the tokens are extensionless.

**Key negative result:** hashing these tokens as if they were VFS paths yields
**zero** matches against the index. Not a few — zero. So the tokens are *path
components* consumed by a secondary encoding, not paths themselves. This rules out
the obvious approach and is the main reason the mapping is still unsolved.

**Second negative result:** the large table contains **no token-corpus text**.
It has incidental ASCII fragments, but no direct substrings from the corpus. So
the two are linked by *index*, not by embedded text — "grep the table for token
strings" is also ruled out.

## 2. Paged pointers

Many u32 values in the large table are self-describing pointers:

```
hib   = v >> 24          selects a page
off24 = v & 0xFFFFFF     offset within the page
file_off = (hib - BASE_HIB) * PAGE_SIZE + off24
```

`PAGE_SIZE` is 8 MiB. The page bytes form a short contiguous run starting at
some base value.

Deriving the count from the blob size (`ceil(blob_size / PAGE_SIZE)`) is a safe
**upper bound**, but note an unexplained observation: on the one blob ever
measured, the page bytes that actually appeared covered *fewer* pages than its
size requires — pointers were never seen targeting the tail. So a derived range
is permissive. That is fine for decoding a pointer you already trust; it admits
extra false positives when brute-force scanning, so tighten to the observed set
for that.

**Both byte orders occur.** Little-endian in the group-pointer area near the
start; **big-endian** in the sorted key→pointer arrays, which is why the page byte
is visible as the *first* byte of those records in a hex dump. Detecting a
plausible page byte at either end is the cheapest way to tell which you are
looking at.

### Dictionary runs: 4-byte key → paged pointer

Distinct from the `0xBB` tables (§4), the blob holds contiguous runs of 8-byte
records pairing a **4-byte ASCII-ish key** with a **paged pointer** — asset-type
words (mesh/material/LOD-like tokens) are typical.

To *discover* these with no prior hint, scan the whole blob on **8-byte
alignment** for runs of consecutive records where the key is ASCII-ish and the
u32's high byte is a valid page byte, with a minimum-run threshold to suppress
noise. That is a different operation from §5, which recovers a run's *bounds*
given a pointer landing inside it — you need both.

## 3. Front-coded dictionary blocks

Pointed-to sub-blocks hold records compressed by front-coding against a
per-block dictionary. There are two variants with the **same logical structure**
but different stream encodings, selected by the dictionary size `N`.

Common header:

```
u16le N
u16le dict_ids[N]
<stream>
```

Record expansion is identical in both:

```
seq = prev[:prefix_len] + [dict_ids[x] for x in suffix_symbols]
```

### Small-N (`N <= 255`) — byte stream

Each stream byte `v`:

- `v >= N` → **terminate** the current record; the next record's
  `prefix_len = v - N`
- `v < N` → a dictionary index appended to the current record's suffix

The scheme only works while `N <= 255`, since the marker must fit in a byte.

### Large-N (`N > 255`) — uLEB128 stream

Identical discrimination, but the stream is **uLEB128 varints** instead of bytes:

- `v >= N` → terminate, `prefix_len = v - N`
- `v < N` → dictionary index

Note this is real uLEB128 (high bit = continue), unlike the *inverted* varint used
in Lua chunks ([lua-bytecode.md](lua-bytecode.md) §4). Do not share a decoder.

### Block tag

A small-N block begins with a `u16` that splits into a dictionary count and a
block-type byte — the low byte is `N` and the high byte is a type code. This is
what lets you validate that a pointer actually lands on a dict block.

## 4. Auxiliary index structures

### Group-root pointers

Near the start of the large table are 8-byte records `[u32le key][u32le ptr]`
where `key & 0xFFFF` falls in the same range as `field4`'s `group_id`, and `ptr`
is a paged pointer. This looks like the `group_id → group root` half of the
suspected mapping.

Caveats that cost time if ignored:

- The upper half of `key` varies and looks like a hash or check value; it is
  **not** a member count.
- Some groups produce **multiple** hits, so candidates need scoring rather than
  first-match.

### What a group root points at, and how to select within it

The pointer targets a long **sorted array of 8-byte records**:

```
[u32le key][u32be ptr]        ptr's first byte is a page byte
```

Note the mixed endianness within one record — that is what makes these arrays
easy to spot in a hex dump.

Group roots land in a **cluster** of page-local runs (4 KiB-aligned) rather than
one contiguous run. The selection procedure that worked:

1. Collect the cluster's runs — the group's index space is split across them.
2. The run keys are **start indices**, and the ranges are **disjoint** per page,
   so merge the cluster into one ordered key list.
3. **Bisect** on those start keys to find the run, hence the dict block, that
   contains the index you want.
4. Decode that block and take the record.

> **Selecting the wrong run fails silently with plausible output** — you get
> nonsense token sequences that look like real data rather than an error. If
> decoded strings look almost-right, suspect run selection before suspecting the
> dict-block decoder.

Whether these sorted arrays are per-group, globally partitioned, or internal
nodes of a B-tree/trie is still unknown.

### u16 id → pointer records

Dict-block decoding produces some u16 symbols that fall **outside** the token
corpus index range. These behave like extra vocabulary or macros, and they are
resolvable: elsewhere in the blob are 8-byte records

```
[u16le a][u16le id][u32be ptr]        ptr's first byte is a page byte
```

giving `id → pointer → offset`. This is a confirmed bridge from the unknown
symbols to concrete addresses. The targets still look binary and have not been
decoded into strings — this is the most promising unexplored thread.

### `0xBB` 24-bit pointer tables

A second pointer encoding, using a constant tag byte instead of paged addressing:

```
u16le key_a
u16le off_lo16
u8    off_hi8
u8    tag = 0xBB
u16le key_b

ptr24     = (off_hi8 << 16) | off_lo16      direct offset into the blob
key_bytes = le(key_a) + le(key_b)           4 raw bytes
```

**Treat the key as raw bytes, not a string.** Keys are often ASCII-ish, but
non-printable bytes occur; a C-string reading truncates them.

To find these tables: bytes `[2..5]` read as a little-endian u32 always have
`0xBB` as the **high** byte, so scanning for u32s of the form `0xBB??????` locates
candidate records cheaply.

These act as indexes from a 4-byte key to a dict-block offset — pointers from
them have been observed to land exactly on a valid small-N dict-block tag, which
is a good self-check.

Open: whether `0xBB` addressing is limited to the first 16 MiB (the 24-bit reach)
and whether other tag bytes cover other regions.

## 5. Pointers land mid-table

A recurring structural quirk, worth stating once because it affects every parser
here: **an internal pointer often targets a position *inside* a table rather than
its first record.** It is probably a binary-search anchor or bucket hint.

So tooling must not assume the target is a run start. Recover the run bounds by
scanning outward from the target on the record stride, respecting the alignment
the records actually use (which is not necessarily zero mod stride).

## 6. What is still unknown

- How decoded symbol sequences become **real VFS paths**. Two renderings have
  been tried and **both produce zero hash matches**: joining the tokens with
  `/`, and plain concatenation. So the sequences are not simply token-index
  lists — they need further expansion (unresolved symbols, extra tables,
  punctuation insertion), or they may be *programs* to be executed rather than
  data to be joined. That last reading is worth taking seriously.
- Whether the sorted key→pointer arrays are per-group, globally partitioned, or
  internal nodes of a B-tree/trie.
- **How a dict block's extent is determined.** Decoding needs an end bound, and
  nothing recorded explains where it comes from — only that earlier work
  somehow had one.
- Whether any `key4` values are substrings of corpus tokens, and whether the
  paired u32s index the token list.
- The semantics of the 4-byte `0xBB` keys — possibly a bigram code rather than
  text.
- Whether the auxiliary `CCCCZZZ4` dictionary is referenced by the large table at
  all.
- Where the runtime decoder is. No native routine that loads and decodes these
  blobs has been found, and the ids are not immediates in the launcher binary —
  but they **do** appear as 64-bit constants in a shipped patcher stage script.
  So the client does know about them, most likely as "essential dictionary"
  inputs. Follow the Lua, not the binary: that stage script is the best lead on
  who consumes them and how.

### Hunting a native decoder

If you do look, search for the primitives rather than the data:

- uLEB128 loop idioms — `and eax, 0x7f` paired with `test al, 0x80`
- paged-pointer idioms — `shr eax, 0x18`, `and eax, 0xffffff`

Both are noisy on their own. Anchor first on *where the blobs are loaded*, then
narrow by call chain. See [methodology.md](methodology.md).

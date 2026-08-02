# `Patch.mpkdb` — the base-pack index

**Scope:** the SQLite database that is authoritative for base-pack contents, its
column semantics, and the obfuscation on its `meta` row.

**Prerequisites:** [file-id.md](file-id.md) for the id column's encoding.

**Implementation:** `messiah.vfs.patchdb`

---

## 1. Tables

| Table | Role |
|---|---|
| `info0` | one row per stored payload slice — the actual index |
| `info1` | observed empty |
| `pak` | chunk metadata for downloadable blobs |
| `meta` | a single obfuscated key/value row |

Columns are named `v0`, `v1`, … — the schema carries no semantics, so the mapping
below is reverse-engineered and is the only thing that makes the DB readable.

## 2. `info0` — the index

| Column | Meaning |
|---|---|
| `v0` | file identifier — **signed i64** hash, or TEXT for a literal path |
| `v1` | payload size |
| `v2` | pack id → the payload lives in `Patch{v2}.mpk` |
| `v3` | content hash, see [content-hash.md](content-hash.md) |
| `v4` | unknown; observed uniformly zero |
| `v5` | script flag — set on the TEXT-path rows |
| `v6` | byte offset within the pack |

### The TEXT rows are the important minority

`v0` is *not* uniformly integer. A small number of rows store a **literal path
string** instead of a hash, and those rows carry `v5 = 1`. They have been observed
to be script paths under the `LuaText/` namespace, concentrated in a single low
base pack.

For those rows the DB key **is** the path — no hashing is involved, and looking
them up by computed `file_id` will fail. Any query must branch on `typeof(v0)`.

These rows matter far beyond their count: they are cleartext paths, which makes
them seed material for path recovery and a ready-made correctness test for a
`file_id` implementation.

> Do not record how many such rows exist — the count is per-build. Query
> `select count(*) from info0 where typeof(v0)='text'` when you need it.

### Validation invariant

For each pack id, `max(v6 + v1)` over its rows equals that pack's physical file
size. This is a strong, cheap check that the DB and the on-disk packs agree. If
the computed maximum *exceeds* the file size, the pack is EZST-chunked and the
offsets are logical — see [ezst.md](ezst.md).

## 3. `pak` — download chunks

| Column | Meaning |
|---|---|
| `v0` | chunk-group identifier — **unresolved** |
| `v1` | chunk index within the group, apparently **1-based** (matters when reassembling in order) |
| `v2` | chunk size — usually 2 MiB, with a smaller final chunk. Note this matches the small-file chunk size in [content-hash.md](content-hash.md) §2 |
| `v3` | chunk hash — the join key |

Every `pak.v3` has been observed to appear in the patchlist's `pak_filelist` hash
set, and for those matches the patchlist size equals `pak.v2`. This join is what
grounds an abstract `pak_id` to a concrete chunk group:

```
patchlist filelist[file_id][2] = [pak_id, offset]
    -> pak_filelist[pak_id] = [size, hash]
        -> join Patch.mpkdb.pak on v3 == hash
            -> recover (group v0, chunk index v1)
```

`pak.v0` does not appear to be a `file_id` — no overlap with `info0.v0` has been
observed. What it identifies is an open question.

## 4. `meta` — obfuscated, and solved

> **Correction.** This row was long documented as "encoding unknown". It is
> decoded. The confusion came from mis-attributing a native callback; see §5.

The table's columns are literally `key` and `val`, both BLOBs.

The obfuscation is `transform_string`, taken from the game's own Lua — the
`PatchMpkDB` class in the patcher's `patchmpk_db` script, whose path under the
script namespace makes it easy to re-find in a Lua dump:

```
transform_string(data):
    headlen = len(data) % 17
    return XorExcrypt(data[:headlen], "43") + XorExcrypt(data[headlen:], "53")
```

where `XorExcrypt` is a length-preserving repeating-key XOR:

```
out[i] = data[i] ^ key[i % len(key)]
```

Two details make this work:

- The Lua call passes the **numbers** 43 and 53, but the native side coerces
  arguments with `luaL_checklstring`, so the key is the two ASCII bytes `"43"` /
  `"53"` — not the byte values 43 and 53.
- The split point is `len % 17` of the **whole** blob, so head and tail use
  different keys at a data-dependent boundary.

The transform is symmetric — encoding and decoding are the same operation. It is
applied to **both** the key and the value of every row.

`PatchMpkDB:get_meta()` selects all rows, applies `transform_string` to key and
value, and JSON-decodes the result. The write path, `update_meta(k, v)`, is the
mirror image and shows **why** the plaintext is JSON: it does
`transform_string(k)` and `transform_string(json_encode(v))`, then an
insert-or-replace. To write a row back you must JSON-encode *before*
transforming.

The decoded key observed so far is `"status"`, whose value is a JSON object with
the fields `compact_list`, `essential_list_md5`, `sort_version`, and
`verifying_list`. Whether other keys exist in other builds or install types is
untested — hence `read_meta` returns every row rather than assuming one.

Beware when probing blobs like this: see the false-positive warning in
[patchlist.md](patchlist.md) §1, which came out of exactly this task.

## 5. `XorExcrypt` is not the `HEX_` pipeline

This is worth stating explicitly because getting it wrong cost real time:

- **`XorExcrypt`** — plain repeating-key XOR. Used by `transform_string` for the
  `meta` row. Symmetric.
- **`ZipDecompress`** — base64 → XOR with `netease_hex_xor_encrypt_key` → zlib.
  This is the `HEX_` / `HEXB_` pipeline described in [patchlist.md](patchlist.md).

They are different callbacks with different keys. The mis-attribution came from a
registration-idiom trap: **the callback pointer is pushed immediately *before* the
name assignment**, so reading the pointer that appears next to a name in source
order attributes it to the wrong function. See [methodology.md](methodology.md).

A separate encoder pipeline (deflate → XOR → base64) also exists in the binary.

### Re-finding it in a new build

1. `izz~XorExcrypt` to locate the name string.
2. `aa; aac; axt @ <str>` to find the registration routine.
3. Look **backwards** from the name assignment for the `lea` / push pair that
   supplies the callback pointer.
4. Confirm by behaviour, not position. `XorExcrypt` takes **two** Lua arguments
   (it checks `argc >= 2`) and delegates to a small repeating-XOR loop;
   `ZipDecompress` delegates to the base64 → XOR → inflate chain. Argument count
   and callee shape are both cheap discriminators.

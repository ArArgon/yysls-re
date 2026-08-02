# EZST blocks and chunked packs

**Scope:** the `EZST` compressed-block wrapper, and the "logical offsets" model
that makes some packs readable.

**Prerequisites:** [vfs-model.md](vfs-model.md) for the extraction chain.

**Implementation:** `messiah.codec.ezst`

---

## 1. The diagnostic that sends you here

> For a given pack, `max(offset + size)` across its index entries **exceeds the
> pack's physical file size.**

This looks like a corrupt index or a wrong-container bug. It is neither. It means
the pack is **chunked** and its index offsets address a *logical decompressed
stream*, not physical file bytes.

Apply this check whenever extraction produces garbage or a short read. It is
cheap and it distinguishes the two cases definitively.

## 2. Block format

```
"EZST"                  4 bytes, magic
u32le decompressed_size expected size of the zstd frame
payload                 zstd frame, with an encrypted prefix
```

**There is a sibling magic, `ZSTD`**, with the identical 8-byte header but an
**unencrypted** payload — skip the decrypt step and decompress directly. It is
rare, but a decoder that accepts only `EZST` reports it as a corrupt block
rather than a variant.

> **Correction.** The second field is the **decompressed size**. It was long
> documented as a `file_id`; it is not, and treating it as an id will silently
> mis-key everything.

### The partially-encrypted payload

Only the **head** of the payload is encrypted, which is a cheap-obfuscation
pattern rather than real confidentiality:

```
n = min(floor_to_16(len(payload)), 256)
payload[:n]  <- AES-256-ECB decrypt with the fixed key
payload[n:]  <- untouched
```

The 16-byte flooring matters: ECB requires block alignment, so a payload shorter
than 16 bytes has nothing encrypted at all.

The key is a fixed 32-byte constant compiled into the client. It is durable across
builds so far — see `messiah.codec.ezst` for the value.

After decrypting that prefix, the whole payload is one zstd frame.

### Trailing bytes

Some blocks carry extra bytes **after** the zstd frame ends. Decompress with a
streaming decompressor and capture the unused remainder rather than assuming the
frame runs to the block boundary — a one-shot decompress that demands exact input
length will fail on these.

There is a **second, independent reason** streaming is required: many of these
frames omit zstd's optional frame-content-size field, so one-shot APIs that need
the output size up front cannot decompress them at all.

What the trailer contains is **unresolved** (per-chunk metadata? padding?).

## 3. A pack is many blocks, not one

A chunked `.mpk` contains **thousands** of back-to-back `EZST` blocks. The logical
stream is the concatenation of their decompressed contents:

```
logical = decompress(block0) || decompress(block1) || ...
```

Index `(offset, size)` pairs address that concatenation. So reading a file means:

1. Build a chunk map: for each block, its physical position and its logical span.
2. Find the blocks overlapping `[offset, offset+size)`.
3. Decompress just those and slice.

### The magic is not a reliable boundary marker

An unvalidated scan — "find every `EZST`, read each declared size" — is fast and
**wrong**. Those four bytes also occur by chance inside compressed and encrypted
payload data, so some hits are not block starts.

The boundary must be *validated*, and the size field is the oracle that does it:
treat the next magic occurrence as a candidate end, try to decode, and if the
decompressed length does not match `decompressed_size`, reject that candidate
and scan for the next occurrence. A block start that never yields a valid decode
was itself a false positive — resync forward.

This is why `decompressed_size` matters beyond allocation: **it is what makes
the chunk walk sound.** A fast unvalidated pass is only safe for rough sizing,
never for building a map you will read through.

### `ZZZ4`

Some chunked packs begin with the bytes `ZZZ4` before the first `EZST` block.
Whether this is a container header for the chunked format is **unresolved**. Do
not rely on it for detection — scan for `EZST` instead, since not every chunked
pack starts with it.

### Two more open questions

- Some packs have a **logical stream larger than any referenced `offset+size`** —
  the index does not address the whole decompressed stream. Unexplained.
- Where the runtime's authoritative chunk map lives on the binary side is
  unknown. Everything here is reconstructed from the on-disk bytes.

## 4. Choosing physical vs logical extraction

Detection should be a property of the container, not of a single entry:

- Base packs indexed by `Patch.mpkdb` → physical.
- `.mpkinfo`-indexed containers that are *not* EZST-heavy → physical.
- EZST-heavy containers → **logical, always** — even when a particular entry's
  `offset + size` happens to fit inside the physical file. That coincidence is
  common for early entries and produces plausible-looking garbage.

Annotate extracted entries with which mode was used; when an extraction is wrong,
that flag is the first thing to check.

## 5. Where else EZST appears

EZST is not only a pack-level thing — individual payloads stored inside ordinary
containers can also be EZST-wrapped. So step 4 of the extraction chain
([vfs-model.md](vfs-model.md) §2) should sniff for the magic on every payload,
independent of whether the container itself was chunked.

## 6. Dependency-free fallbacks

Both primitives have CLI equivalents, useful when the Python packages are
unavailable or when cross-checking a suspected decode bug:

```bash
openssl enc -aes-256-ecb -d -nopad -nosalt -K <hex-key>
zstd -d -q --stdout
```

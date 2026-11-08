# Texture containers

**Scope:** the container that holds 2D texture pixel data — the single most common
payload type after meshes — and how to turn it into a viewable image.

**Prerequisites:** [ezst.md](ezst.md) for the per-mip block codec.

**Implementation:** `messiah.codec.texture`

---

## 1. Recognising one

A texture container begins with the four bytes `02 02 02 01`. It appears both as a
raw index payload and, less often, wrapped in a standalone EZST block — so check the
magic *after* undoing any outer wrapper.

## 2. Layout

All little-endian.

```
0x00  u8[4]  magic       = 02 02 02 01
0x04  u8     unknown     observed 1
0x05  u8     format      EPixelFormat, see §3
0x06  u8     mip_count
0x07  u8     flags       observed 0, 4, 8 — unresolved
0x08  u8[4]  unknown     a handful of distinct values, unresolved
0x0c  u16    width
0x0e  u16    height
0x10  u8[16] zero
0x20  u32    total       = file size - 0x20
0x24  u8     01
0x25  u8     format      repeats 0x05
0x26  u8     mip_count   repeats 0x06
0x27  u8     00
0x28  mip records, smallest level first
...   u8[16] trailer     unresolved
```

Each mip record:

```
u32  blob        size of this record from the EZST magic to the start of the next
                 record's header (so payload_len = blob - 24)
u16  w, h        this level's dimensions
u16  depth       observed 0
u16  pitch       bytes per row of blocks (BC) or pixels
u32  raw         decoded byte count of this level; 0 means no local pixel data
EZST block       "EZST" u32 raw, then payload_len bytes — decode per ezst.md
```

Two traps:

- Records run **smallest → largest**. DDS and most tools want largest first.
- The last record's `blob` also covers the 16-byte file trailer, so a naive
  `payload = blob - 8` reads 16 bytes too many on the final level. Use `blob - 24`
  everywhere and stop when `pos + 16 == len(buf)`.

Validate each level with `len(decoded) == raw`. A mismatch means a mis-stepped
record, not a corrupt file.

## 3. Pixel formats

`format` indexes the engine's `EPixelFormat` enum (the same numbering that older
Messiah titles expose). Values observed so far, with the bytes per 4x4 block or
per pixel that let you cross-check `raw` against `w * h`:

| value | name | storage |
|---|---|---|
| 2 | A16B16G16R16F | 8 B/px |
| 3 | R8G8B8A8 | 4 B/px |
| 25 | BC7 | 16 B per 4x4 block (1 B/px) |
| 55 | — | `raw == 0` on every record: pixel data is not in the container |

The full enum (BC1..BC7, ASTC, ETC, float formats) is 70 entries; only the above
have been seen in PC packs. Format 55 records carry real dimensions and a pitch but
no payload, so the pixels live elsewhere — plausibly the HD store or a streaming
pack. Unresolved.

Multiple records at the top size have been observed for some flags values; treat
them as array/cube layers rather than assuming records == mip levels.

## 4. Converting

Decode the largest level, then:

- `R8G8B8A8`: raw bytes are already RGBA8 rows.
- block formats: wrap in a DDS header with a DX10 extension
  (`DXGI_FORMAT_BC7_UNORM = 98`, etc.). Pillow decodes BC1–BC7 from such a DDS.
- `A16B16G16R16F`: write DDS (`DXGI_FORMAT_R16G16B16A16_FLOAT = 10`); Pillow does
  not decode it.

Whether BC7 data is sRGB or linear is not recorded anywhere obvious; `flags` is the
natural suspect.

## 5. Where textures live

In the install observed, texture containers were roughly a third of all `Patch.mpkdb`
rows, the majority of `Resources.mpk`, and absent from the `MpkCached_*` update packs
(which held meshes, animations and particles). Resolve through the indexes as usual;
do not rely on this distribution.

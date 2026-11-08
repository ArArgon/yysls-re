# Documentation index

Each doc is self-contained — it states its own scope and prerequisites, and you
can load any one of them alone. Read on demand rather than end to end.

## Reading order for someone learning this cold

1. **[vfs-model.md](vfs-model.md)** — start here. Containers, indexes, and the
   four-step extraction chain that everything else fits into.
2. **[file-id.md](file-id.md)** — the opaque key. Needed before any index makes
   sense.
3. **[mpkinfo-index.md](mpkinfo-index.md)** — the simplest index format.
4. **[patchdb.md](patchdb.md)** — the SQLite index for base packs.
5. **[patchlist.md](patchlist.md)** — the manifest, its transport wrapper, and
   `field4`.

After that, read what your task needs:

- **[ezst.md](ezst.md)** — when extraction produces garbage or a short read.
- **[content-hash.md](content-hash.md)** — to verify an extraction is correct.
- **[lua-bytecode.md](lua-bytecode.md)** — for scripts: the LZ4 wrapper, the Lua
  5.4 chunk, and the custom opcode table.
- **[texture.md](texture.md)** — the `02 02 02 01` texture container: header, per-mip
  EZST blocks, pixel formats, DDS/PNG conversion.
- **[hd-store.md](hd-store.md)** — the separate `HD/` container family, and the
  best untapped source of cleartext paths.
- **[path-mapping-table.md](path-mapping-table.md)** — the main unsolved area.
- **[launcher-api.md](launcher-api.md)** — the native API surface exposed to Lua.
- **[methodology.md](methodology.md)** — how to re-derive all of this against a
  new build. **Read this before touching a new binary.**

## By question

| Question | Doc |
|---|---|
| How do I get bytes out of a container? | [vfs-model.md](vfs-model.md) |
| What is this 64-bit number? | [file-id.md](file-id.md) |
| Can I recover the filename? | [vfs-model.md](vfs-model.md) §7, then [hd-store.md](hd-store.md) §6 |
| Why does `offset + size` exceed the file size? | [ezst.md](ezst.md) §1 |
| How do I view a texture? | [texture.md](texture.md) |
| Did my extraction work? | [content-hash.md](content-hash.md) §5 |
| Why is my Lua disassembly nonsense? | [lua-bytecode.md](lua-bytecode.md) §5 |
| Where did this address in an old note go? | [methodology.md](methodology.md) §1 |

## Conventions used throughout

- **Patterns, not instances.** Container names appear as shapes
  (`Patch{pack_id}.mpk`), never as remembered numbers. Which pack holds an asset
  is not stable across builds — always resolve through an index.
- **No addresses.** Every "where is it" is a search recipe, not an offset.
- **Corrections are marked.** Blocks beginning with **Correction** record a claim
  that older notes got wrong. They are kept visible because the wrong version is
  still in circulation elsewhere.
- **Unresolved things say so.** "Unresolved" and "unconfirmed" are used
  deliberately — do not build on them without re-verifying.

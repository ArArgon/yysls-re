# messiah

Reverse-engineering notes and tooling for the asset and patch filesystem of a
NetEase game built on the Messiah engine.

This is a **distillation**. It keeps the durable knowledge — format specs,
algorithms, and a library that implements them — and deliberately drops
everything tied to one particular build.

## What is here

- **[docs/](docs/)** — twelve self-contained format and methodology documents.
  Start at [docs/README.md](docs/README.md).
- **`src/messiah/`** — a Python library implementing the formats, plus thin CLIs.
- **`ksy/`** — a Kaitai spec for the `.mpkinfo` index, kept as documentation.

## What is deliberately not here

- **Game data.** No `.mpk`, `.mpkdb`, `.mpkinfo`, or install trees.
- **Binaries.** No executables or disassembler databases.
- **Extracts.** No carved payloads, dumped bytecode, or decoded manifests.
- **Generated indexes.** No SQLite databases or path corpora — these are derived
  data. Regenerate them; they go stale silently.

The `.gitignore` is written to make committing any of the above difficult.

## The one rule

**Nothing in this repo names a specific pack, file id, offset, or binary
address.**

Those change every release, and pinning knowledge to them is what made the
previous working tree hard to carry forward. What is recorded instead:

- naming *conventions* (`Patch{pack_id}.mpk`, `LT{n}.mpk`, `data{n}`) — structural
- *how to re-find* a routine (string xrefs, constant signatures, instruction
  idioms) — instead of where it was once
- algorithm constants (hash seeds, fixed keys, format magic) — genuinely durable

Which pack holds a given asset is **not** stable. Resolve it through an index
every time.

## Quick start

```bash
uv sync

# Discover what containers an install actually has — nothing is assumed.
uv run messiah-inventory --install-root /path/to/game

# Build a queryable id -> (container, offset, size) index.
uv run messiah-build-index --install-root /path/to/game --out-db /tmp/vfs.sqlite

# Extract by id or by literal path.
uv run messiah-extract --install-root /path/to/game --vfs-db /tmp/vfs.sqlite \
    --file-id <id> --out /tmp/payload.bin --decode
```

Every CLI takes `--install-root` and has no default path.

## Verifying it works

Extract a payload and check its content hash against the index. That single test
validates index parsing, container resolution, offset arithmetic, and wrapper
decoding at once — see [docs/content-hash.md](docs/content-hash.md) §5.

## State of the work

Solved and implemented: the `.mpkinfo` index, the `Patch.mpkdb` schema including
its obfuscated `meta` row, the `HEX_`/`HEXB_` transport, EZST blocks and chunked
packs, content hashing, the path→id hash, the LuaText wrapper, the custom Lua 5.4
opcode table, and the HD store down to both payload dialects.

Open: recovering filenames for the great majority of assets, which are keyed only
by hash. See [OPEN-QUESTIONS.md](OPEN-QUESTIONS.md).

# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

Reverse-engineering knowledge and tooling for the asset/patch filesystem of a
NetEase game built on the Messiah engine. It holds **durable knowledge** — format
specs, algorithms, and a library that reads them — distilled from a much larger
working tree.

This repo contains **no game data**. Binaries, `.mpk` containers, extracts, and
generated indexes live outside it and are gitignored. Everything here should
remain valid against a **new build** of the game.

## Docs are loaded on demand

`docs/` totals more than you want in context at once. Load the one you need.
`docs/README.md` has the full index and a reading order; below is the router.

| Read this | When |
|---|---|
| `docs/vfs-model.md` | orienting; you need the container/index mental model |
| `docs/file-id.md` | anything involving the 64-bit key, hashing paths, or joins |
| `docs/mpkinfo-index.md` | parsing `.mpkinfo`, or it "has bad magic" |
| `docs/patchdb.md` | querying `Patch.mpkdb`, or decoding its `meta` row |
| `docs/patchlist.md` | `HEX_`/`HEXB_` wrappers, the msgpack manifest, `field4` |
| `docs/ezst.md` | a pack's `offset+size` exceeds its file size; extraction yields garbage |
| `docs/content-hash.md` | verifying an extraction; reproducing the stored hash |
| `docs/lua-bytecode.md` | `.luac` files, the LuaText wrapper, disassembly that looks wrong |
| `docs/hd-store.md` | anything under `HD/`; harvesting cleartext paths |
| `docs/path-mapping-table.md` | the unsolved `(group,index) → path` mapping |
| `docs/launcher-api.md` | what the native layer exposes to Lua |
| `docs/methodology.md` | **before touching a new binary** — search recipes, traps |

## Working rules

**Never hardcode a container name, pack number, file id, offset, or binary
address.** These change every release and are the reason the previous tree
decayed. Resolve containers through `messiah.vfs.containers`, and express "where
is this function" as a signature or string-xref search.

Naming conventions (`Patch{pack_id}.mpk`, `LT{n}.mpk`, `data{n}`) are structural
and fine to encode. Specific instances are not.

When a doc says **unresolved** or **unconfirmed**, treat it as an open question,
not a fact to build on. When a doc has a **Correction** block, the wrong version
is still circulating in older material — do not "fix" it back.

## Layout

```
docs/           the knowledge (see router above)
src/messiah/    the library
    vfs/        container resolution, file ids, the three index formats
    codec/      HEX_ wrapper, EZST, zstd helper, content hash
    lua/        LuaText LZ4 wrapper, custom-opcode remapping
    hd/         HD container, MANIFEST, payload dialects
    mapping/    the opaque path-mapping table's encodings
    frida/      runtime instrumentation (signature-scanned, no RVAs)
    cli/        thin entry points; logic belongs in the modules above
ksy/            Kaitai spec for .mpkinfo, kept as documentation
```

## Python

`uv` project. Install with `uv sync`. CLIs are exposed as `messiah-*` console
scripts (see `pyproject.toml`); all of them take `--install-root` and have no
default path.

`src/messiah/frida/` is deliberately named `frida` — as `messiah.frida` it does
not shadow the pip `frida` package that its host script imports. Do not move it
to the top level.

## Verifying a change

The strongest check is the content hash: extract a payload and confirm its hash
matches the index. That validates index parsing, container resolution, offset
arithmetic, and wrapper decoding in one step. See `docs/content-hash.md` §5.

"""
Extract Lua scripts and convert them to stock Lua 5.4.

Two modes:

  --install-root   pull path-keyed script rows out of Patch.mpkdb
  --carve          scan an arbitrary file for LuaText blobs

Output can be fed to Lua 5.4.7 `luac -l -l`. Note Homebrew's luac is 5.5 and
cannot read 5.4 chunks.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from messiah.lua import luac, luatext
from messiah.vfs import patchdb
from messiah.vfs.containers import ContainerResolver, PackKind

# Scripts live under this namespace. A durable string anchor -- unlike the pack
# that happens to hold them, which changes.
SCRIPT_NAMESPACE = "LuaText/"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--install-root", type=Path)
    source.add_argument("--carve", type=Path, help="Scan this file for LuaText blobs.")

    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--raw", action="store_true", help="Also write packed and decoded forms.")
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    return _carve(args) if args.carve else _from_install(args)


def _from_install(args) -> int:
    resolver = ContainerResolver(args.install_root)
    db_path = resolver.patchdb_path()
    if db_path is None:
        print(f"no patch database found under {args.install_root}")
        return 1

    conn = patchdb.connect(db_path)
    ok = failed = 0
    try:
        for row in patchdb.iter_path_keyed(conn):
            path = str(row.file_id)
            if not path.startswith(SCRIPT_NAMESPACE):
                continue

            container = resolver.for_pack_id(row.pack_id, kind=PackKind.PATCH)
            if container is None:
                print(f"  {path}: pack {row.pack_id} not on disk")
                failed += 1
                continue

            with container.open("rb") as fh:
                fh.seek(row.offset)
                packed = fh.read(row.size)

            out_path = args.out_dir / path
            out_path.parent.mkdir(parents=True, exist_ok=True)

            if args.raw:
                out_path.with_suffix(out_path.suffix + ".packed.bin").write_bytes(packed)

            try:
                decoded = luatext.unpack(packed)
                if args.raw:
                    out_path.with_suffix(out_path.suffix + ".luac").write_bytes(decoded)
                result = luac.convert(decoded)
            except (luatext.LZ4BlockError, luac.ChunkError) as exc:
                print(f"  {path}: {exc}")
                failed += 1
                continue

            out_path.with_suffix(out_path.suffix + ".std.luac").write_bytes(result.data)
            for warning in result.warnings:
                print(f"  {path}: {warning}")
            ok += 1
    finally:
        conn.close()

    print(f"converted {ok} script(s), {failed} failed -> {args.out_dir}")
    return 0 if ok else 1


def _carve(args) -> int:
    data = args.carve.read_bytes()
    count = 0
    for offset, decoded in luatext.carve(data):
        out_path = args.out_dir / f"carved_{offset:#010x}.std.luac"
        try:
            result = luac.convert(decoded)
        except luac.ChunkError as exc:
            print(f"  {offset:#x}: {exc}")
            continue
        out_path.write_bytes(result.data)
        for warning in result.warnings:
            print(f"  {offset:#x}: {warning}")
        count += 1

    print(f"carved {count} chunk(s) from {args.carve} -> {args.out_dir}")
    return 0 if count else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""
Convert Lua chunks from the game's opcode table to stock Lua 5.4.

Accepts either a decoded chunk or a LuaText-packed blob (auto-detected).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from messiah.lua import luac as luac_mod
from messiah.lua import luatext


def convert_bytes(data: bytes) -> luac_mod.ConvertResult:
    """
    Convert, unpacking the LuaText wrapper first if present.

    Detection must VALIDATE a chunk, not merely find the signature: a packed
    blob contains `\\x1bLua` a few bytes in (the LZ4 stream starts with the
    chunk header as literals), so a substring test misclassifies every packed
    blob as already decoded.
    """
    offset = data.find(luatext.LUA_SIGNATURE)
    if offset != -1 and luatext.validate_chunk(data[offset:])[0]:
        return luac_mod.convert(data)
    return luac_mod.convert_packed(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path, nargs="+")
    parser.add_argument("-o", "--out", type=Path, help="Output file (single input only).")
    parser.add_argument("--out-dir", type=Path, help="Output directory for multiple inputs.")
    args = parser.parse_args()

    if args.out and len(args.inputs) > 1:
        parser.error("--out takes a single input; use --out-dir for several")

    ok = failed = 0
    for source in args.inputs:
        try:
            result = convert_bytes(source.read_bytes())
        except (luac_mod.ChunkError, luatext.LZ4BlockError) as exc:
            print(f"ERROR {source}: {exc}")
            failed += 1
            continue

        if args.out:
            destination = args.out
        else:
            name = source.name.removesuffix(".luac") + ".std.luac"
            destination = (args.out_dir / name) if args.out_dir else source.with_name(name)

        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(result.data)

        for warning in result.warnings:
            print(f"WARNING {source}: {warning}")
        print(f"{source} -> {destination}")
        ok += 1

    if failed:
        print(f"{ok} converted, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

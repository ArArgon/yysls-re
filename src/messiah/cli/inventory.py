"""
Report what containers an install actually has.

Nothing is assumed to exist: containers are discovered by naming convention
and classified by sniffing, so a build with entirely new pack numbers works
without a code change.
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from messiah.vfs import mpkinfo as mpkinfo_mod
from messiah.vfs import patchdb
from messiah.vfs.containers import ContainerResolver, ContainerRole


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--verbose", action="store_true", help="Per-index detail.")
    args = parser.parse_args()

    resolver = ContainerResolver(args.install_root)
    containers = resolver.discover()

    if not containers:
        print(f"No containers found under {args.install_root}")
        return 1

    print(f"install root: {args.install_root}")
    print(f"patch root:   {resolver.patch_root}")
    print()

    by_role = Counter(c.role.value for c in containers)
    for role, count in sorted(by_role.items()):
        print(f"  {role:12s} {count}")
    print()

    packs = [c for c in containers if c.role is ContainerRole.PACK and c.pack_id is not None]
    if packs:
        ids = sorted(c.pack_id for c in packs)
        print(f"pack ids: {len(ids)} total, range {ids[0]}..{ids[-1]}")
        print()

    for container in containers:
        if container.role is ContainerRole.INTEGRITY:
            print(f"  {container.name}: HEXB_ integrity metadata, not an index")
        elif container.role is ContainerRole.INDEX and args.verbose:
            try:
                header, entries = mpkinfo_mod.parse(container.path)
            except ValueError as exc:
                print(f"  {container.name}: parse failed: {exc}")
                continue
            target = resolver.for_index(container.path)
            target_desc = target.name if target else "per-entry pack_id"
            print(f"  {container.name}: {header.file_nums} entries -> {target_desc}")

            extents = mpkinfo_mod.max_extent_by_pack(entries)
            for pack_id, extent in sorted(extents.items())[:5]:
                pack = resolver.for_pack_id(pack_id)
                if pack is None:
                    continue
                physical = pack.stat().st_size
                note = " LOGICAL (EZST-chunked)" if extent > physical else ""
                print(f"      pack {pack_id}: max extent {extent} vs {physical} on disk{note}")

    db_path = resolver.patchdb_path()
    if db_path is not None:
        conn = patchdb.connect(db_path)
        try:
            (rows,) = conn.execute("select count(*) from info0").fetchone()
            (text_rows,) = conn.execute(
                "select count(*) from info0 where typeof(v0)='text'"
            ).fetchone()
            print()
            print(f"  {db_path.name}: {rows} info0 rows, {text_rows} keyed by literal path")
            if args.verbose:
                extents = patchdb.max_extent_by_pack(conn)
                mismatched = 0
                for pack_id, extent in sorted(extents.items()):
                    pack = resolver.for_pack_id(pack_id)
                    if pack is not None and extent > pack.stat().st_size:
                        mismatched += 1
                print(f"      {mismatched} packs use logical (EZST) offsets")
        finally:
            conn.close()

    for path in resolver.patchlist_paths():
        print(f"  {path.name}: patchlist manifest")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

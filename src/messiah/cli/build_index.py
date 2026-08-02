"""Build the unified id -> (container, offset, size) SQLite index."""

from __future__ import annotations

import argparse
from pathlib import Path

from messiah.vfs import index


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--out-db", type=Path, required=True)
    parser.add_argument(
        "--patchlist",
        type=Path,
        default=None,
        help="Also export a patchlist manifest to a sibling .patchlist.sqlite",
    )
    args = parser.parse_args()

    counts = index.build(args.install_root, args.out_db)
    print(f"wrote {args.out_db}")
    for source, count in sorted(counts.items()):
        print(f"  {source}: {count}")

    if args.patchlist is not None:
        from messiah.vfs import patchlist as patchlist_mod

        manifest = patchlist_mod.load(args.patchlist)
        out = args.out_db.with_suffix(".patchlist.sqlite")
        patchlist_mod.export_sqlite(manifest, out)
        print(f"wrote {out}")
        print(patchlist_mod.summarize(manifest))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
Extract a payload by file id or by literal path.

Handles physical and logical (EZST-chunked) addressing, and can verify the
result against the index's content hash -- which validates the whole chain.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from messiah.codec import contenthash
from messiah.vfs import index
from messiah.vfs.fileid import file_id_i64, u64_to_i64


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vfs-db", type=Path, required=True, help="From messiah-build-index.")
    parser.add_argument("--out", type=Path, required=True)

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--path", help="VFS path (hashed, or matched literally).")
    target.add_argument("--file-id", help="File id: decimal, or 0x-prefixed unsigned hex.")

    parser.add_argument("--decode", action="store_true", help="Peel EZST/HEX_ wrappers.")
    parser.add_argument("--verify", action="store_true", help="Check the content hash.")
    args = parser.parse_args()

    if args.file_id is not None:
        raw = int(args.file_id, 0)
        file_id = u64_to_i64(raw) if raw >= (1 << 63) else raw
        locations = index.lookup(args.vfs_db, file_id=file_id)
        described = f"file_id {file_id}"
    else:
        locations = index.lookup(args.vfs_db, path=args.path)
        described = f"{args.path} (file_id {file_id_i64(args.path)})"

    if not locations:
        print(f"not found: {described}")
        return 1

    location = locations[0]
    if len(locations) > 1:
        print(f"note: {len(locations)} locations found; using {location.container.name}")

    data = index.read(location)
    print(
        f"{location.container.name} offset={location.offset} size={location.size} "
        f"addressing={location.addressing}"
    )

    if args.verify:
        expected = _expected_hash(args.vfs_db, location)
        if expected is None:
            print("  verify: no stored hash available for this entry")
        elif contenthash.verify(data, expected):
            print("  verify: content hash OK")
        else:
            print("  verify: CONTENT HASH MISMATCH")
            return 2

    if args.decode:
        decoded = index.decode_wrappers(data)
        if decoded is not data:
            print(f"  decoded wrapper: {len(data)} -> {len(decoded)} bytes")
        data = decoded

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(data)
    print(f"wrote {args.out} ({len(data)} bytes)")
    return 0


def _expected_hash(db: Path, location: index.Location) -> int | None:
    """The content hash lives in Patch.mpkdb, not in the unified index."""
    import sqlite3

    if location.file_id is None:
        return None
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        row = conn.execute(
            "SELECT index_file FROM entries WHERE file_id_i64 = ? AND source = 'patchdb'",
            (location.file_id,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None

    from messiah.vfs import patchdb

    src = patchdb.connect(Path(row[0]))
    try:
        found = patchdb.lookup_by_file_id(src, location.file_id)
        return found.content_hash if found else None
    finally:
        src.close()


if __name__ == "__main__":
    raise SystemExit(main())

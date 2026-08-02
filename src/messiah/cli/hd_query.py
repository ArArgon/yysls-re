"""
Query the HD store: resolve a key, decode its payload, harvest paths.

The `--harvest-paths` mode is the interesting one. HD payload strings are
canonical VFS paths, which makes the HD store the largest untapped source of
cleartext names for the id-to-path problem. See docs/hd-store.md section 6.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from messiah.hd import manifest as manifest_mod
from messiah.hd import payload as payload_mod
from messiah.hd import store
from messiah.vfs.containers import ContainerResolver


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-root", type=Path, required=True)

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--key", help="Resolve one manifest key.")
    mode.add_argument("--list-pools", action="store_true", help="Summarise the string pools.")
    mode.add_argument(
        "--harvest-paths",
        action="store_true",
        help="Sweep every data block for path-shaped strings.",
    )

    parser.add_argument("--out", type=Path, help="Write results here instead of stdout.")
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()

    resolver = ContainerResolver(args.install_root)
    manifest_path = resolver.hd_root / resolver.convention.hd_manifest
    if not manifest_path.exists():
        print(f"no HD manifest at {manifest_path}")
        return 1

    manifest = manifest_mod.parse(manifest_path)

    if args.list_pools:
        return _list_pools(manifest)
    if args.key:
        return _query_key(manifest, resolver, args)
    return _harvest_paths(resolver, args)


def _list_pools(manifest: manifest_mod.Manifest) -> int:
    print(f"pool1: {len(manifest.pool1)}  pool2: {len(manifest.pool2)}  pool3: {len(manifest.pool3)}")
    print(f"records: {len(manifest.records)}")
    print(f"containers: {', '.join(manifest.container_names) or '(none recovered)'}")

    undecoded = {r.u7 for r in manifest.records if r.has_pointer and r.pool is None}
    if undecoded:
        kinds = ", ".join(f"{value:#x}" for value in sorted(undecoded)[:10])
        print(f"undecoded u7 record kinds: {kinds}")
    return 0


def _query_key(manifest: manifest_mod.Manifest, resolver: ContainerResolver, args) -> int:
    records = list(manifest.records_for_key(args.key))
    if not records:
        print(f"key not found or has no pointer records: {args.key}")
        return 1

    for record in records[: args.limit]:
        container = resolver.hd_container(record.data_file_id)
        print(f"  record {record.index}: data{record.data_file_id} block {record.block_index}")
        if container is None:
            print("      container not on disk")
            continue

        try:
            data = store.read_and_decompress(container, record.block_index)
        except (ValueError, IndexError) as exc:
            print(f"      decompress failed: {exc}")
            continue

        tokens, consumed, error = payload_mod.parse(data)
        dialect = payload_mod.detect_dialect(data)
        print(f"      {len(data)} bytes, dialect={dialect.value}, consumed={consumed}")
        if error:
            print(f"      parse stopped: {error}")

        for candidate in payload_mod.collect_path_candidates(tokens)[: args.limit]:
            print(f"      path: {candidate}")
    return 0


def _harvest_paths(resolver: ContainerResolver, args) -> int:
    containers = [
        c.path
        for c in resolver.discover()
        if c.role.value == "hd_data"
    ]
    if not containers:
        print("no HD data containers found")
        return 1

    found: set[str] = set()
    for container in containers:
        try:
            blocks = list(store.iter_blocks(container))
        except ValueError as exc:
            print(f"{container.name}: {exc}")
            continue

        for block in blocks:
            result = store.decompress_block(store.read_block(container, block))
            if result is None:
                continue
            tokens, _, _ = payload_mod.parse(result[1])
            found.update(payload_mod.collect_path_candidates(tokens))

        print(f"{container.name}: {len(found)} unique path candidates so far")

    ordered = sorted(found)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text("\n".join(ordered) + "\n", encoding="utf-8")
        print(f"wrote {args.out} ({len(ordered)} candidates)")
    else:
        for candidate in ordered[: args.limit]:
            print(candidate)
        if len(ordered) > args.limit:
            print(f"... and {len(ordered) - args.limit} more (use --out)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

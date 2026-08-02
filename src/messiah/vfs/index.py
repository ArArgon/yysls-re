"""
A unified SQLite index over both index families, plus extraction.

See docs/vfs-model.md section 3 and docs/methodology.md section 10.

Patch.mpkdb and the .mpkinfo caches cover largely DISJOINT namespaces, so
"where are the bytes for this id" needs both. This builds one table over both
and records, per container, whether its offsets are physical or logical.

The generated database is derived data -- regenerate it, never commit it.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from messiah.codec import ezst
from messiah.vfs import mpkinfo as mpkinfo_mod
from messiah.vfs import patchdb
from messiah.vfs.containers import Container, ContainerResolver, ContainerRole, PackKind

SOURCE_PATCHDB = "patchdb"
SOURCE_MPKINFO = "mpkinfo"

ADDRESSING_PHYSICAL = "physical"
ADDRESSING_LOGICAL = "logical"  # EZST-chunked; see docs/ezst.md

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE entries (
  file_id_i64 INTEGER NOT NULL,
  source      TEXT NOT NULL,
  container   TEXT NOT NULL,
  offset      INTEGER NOT NULL,
  size        INTEGER NOT NULL,
  addressing  TEXT NOT NULL,
  pack_id     INTEGER,
  index_file  TEXT
);

CREATE TABLE path_entries (
  path      TEXT NOT NULL,
  container TEXT NOT NULL,
  offset    INTEGER NOT NULL,
  size      INTEGER NOT NULL,
  pack_id   INTEGER
);

CREATE INDEX idx_entries_file_id ON entries(file_id_i64);
CREATE INDEX idx_entries_container ON entries(container);
CREATE INDEX idx_path_entries_path ON path_entries(path);
"""


@dataclass(frozen=True)
class Location:
    file_id: int | None
    path: str | None
    container: Path
    offset: int
    size: int
    addressing: str

    @property
    def is_logical(self) -> bool:
        return self.addressing == ADDRESSING_LOGICAL


def classify_addressing(container: Path, max_extent: int | None) -> str:
    """
    Decide whether a container's index offsets are physical or logical.

    The authoritative test is the extent check from docs/ezst.md section 1: if
    the largest `offset + size` exceeds the physical file, the offsets address
    a decompressed stream.

    Scanning for EZST magic is NOT sufficient on its own -- ordinary base packs
    contain many EZST-wrapped *payloads*, so the magic is common in containers
    that are not chunked at all. It is only used as a fallback when no index
    extent is available.
    """
    try:
        physical = container.stat().st_size
    except OSError:
        return ADDRESSING_PHYSICAL

    if max_extent is not None:
        return ADDRESSING_LOGICAL if max_extent > physical else ADDRESSING_PHYSICAL

    try:
        return ADDRESSING_LOGICAL if ezst.looks_chunked(container) else ADDRESSING_PHYSICAL
    except OSError:
        return ADDRESSING_PHYSICAL


def build(install_root: Path, out_db: Path) -> dict[str, int]:
    """Build the unified index. Returns row counts per source."""
    resolver = ContainerResolver(install_root)
    containers = resolver.discover()

    # Pass 1: gather each container's maximum extent across every index that
    # references it, so addressing can be classified before any row is written.
    extents = _collect_extents(resolver, containers)
    addressing = {
        container: classify_addressing(container, extent)
        for container, extent in extents.items()
    }

    out_db.parent.mkdir(parents=True, exist_ok=True)
    out_db.unlink(missing_ok=True)

    conn = sqlite3.connect(out_db)
    counts = {SOURCE_PATCHDB: 0, SOURCE_MPKINFO: 0, "paths": 0}
    try:
        conn.executescript(_SCHEMA)
        counts.update(_ingest_patchdb(conn, resolver, containers, addressing))
        counts[SOURCE_MPKINFO] = _ingest_mpkinfo(conn, resolver, containers, addressing)
        conn.commit()
    finally:
        conn.close()

    return counts


def _collect_extents(
    resolver: ContainerResolver, containers: list[Container]
) -> dict[Path, int]:
    """Maximum `offset + size` per container, across all indexes."""
    extents: dict[Path, int] = {}

    def record(container: Path, extent: int) -> None:
        if extent > extents.get(container, 0):
            extents[container] = extent

    db_path = next((c.path for c in containers if c.role is ContainerRole.PATCHDB), None)
    if db_path is not None:
        conn = patchdb.connect(db_path)
        try:
            for pack_id, extent in patchdb.max_extent_by_pack(conn).items():
                container = resolver.for_pack_id(pack_id, kind=PackKind.PATCH)
                if container is not None and extent is not None:
                    record(container, extent)
        finally:
            conn.close()

    for container in containers:
        if container.role is not ContainerRole.INDEX:
            continue
        try:
            _, entries = mpkinfo_mod.parse(container.path)
        except ValueError:
            continue
        fixed_target = resolver.for_index(container.path)
        for pack_id, extent in mpkinfo_mod.max_extent_by_pack(entries).items():
            target = fixed_target or resolver.for_pack_id(pack_id, kind=PackKind.PATCH)
            if target is not None:
                record(target, extent)

    return extents


def _addressing_for(container: Path, addressing: dict[Path, str]) -> str:
    return addressing.get(container, ADDRESSING_PHYSICAL)


def _ingest_patchdb(
    conn: sqlite3.Connection,
    resolver: ContainerResolver,
    containers: list[Container],
    addressing: dict[Path, str],
) -> dict[str, int]:
    db_path = next((c.path for c in containers if c.role is ContainerRole.PATCHDB), None)
    if db_path is None:
        return {SOURCE_PATCHDB: 0, "paths": 0}

    id_rows, path_rows = [], []
    src = patchdb.connect(db_path)
    try:
        for row in patchdb.iter_info0(src):
            container = resolver.for_pack_id(row.pack_id, kind=PackKind.PATCH)
            if container is None:
                continue
            if row.is_path_keyed:
                path_rows.append((row.file_id, str(container), row.offset, row.size, row.pack_id))
            else:
                id_rows.append(
                    (row.file_id, SOURCE_PATCHDB, str(container), row.offset, row.size,
                     _addressing_for(container, addressing), row.pack_id, str(db_path))
                )
    finally:
        src.close()

    conn.executemany(
        "INSERT INTO entries(file_id_i64,source,container,offset,size,addressing,pack_id,index_file)"
        " VALUES (?,?,?,?,?,?,?,?)",
        id_rows,
    )
    conn.executemany(
        "INSERT INTO path_entries(path,container,offset,size,pack_id) VALUES (?,?,?,?,?)",
        path_rows,
    )
    return {SOURCE_PATCHDB: len(id_rows), "paths": len(path_rows)}


def _ingest_mpkinfo(
    conn: sqlite3.Connection,
    resolver: ContainerResolver,
    containers: list[Container],
    addressing: dict[Path, str],
) -> int:
    total = 0
    for container in containers:
        if container.role is not ContainerRole.INDEX:
            continue

        try:
            _, entries = mpkinfo_mod.parse(container.path)
        except ValueError:
            continue

        # Some index names determine their container; cache indexes do not, and
        # resolve per entry from the entry's own pack id.
        fixed_target = resolver.for_index(container.path)

        rows = []
        for entry in entries:
            if entry.is_placeholder:
                continue
            target = fixed_target or resolver.for_pack_id(entry.pack_id, kind=PackKind.PATCH)
            if target is None:
                continue
            rows.append(
                (entry.file_id_i64, SOURCE_MPKINFO, str(target), entry.offset, entry.size,
                 _addressing_for(target, addressing), entry.pack_id, str(container.path))
            )

        conn.executemany(
            "INSERT INTO entries(file_id_i64,source,container,offset,size,addressing,pack_id,index_file)"
            " VALUES (?,?,?,?,?,?,?,?)",
            rows,
        )
        total += len(rows)
    return total


# --------------------------------------------------------------------------
# Query and extract
# --------------------------------------------------------------------------


def lookup(db: Path, *, file_id: int | None = None, path: str | None = None) -> list[Location]:
    """
    Find every recorded location for an id or path.

    Prefers Patch.mpkdb rows, which are authoritative for base packs.
    """
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        out: list[Location] = []
        if path is not None:
            for container, offset, size in conn.execute(
                "SELECT container, offset, size FROM path_entries WHERE path = ?", (path,)
            ):
                out.append(
                    Location(None, path, Path(container), offset, size, ADDRESSING_PHYSICAL)
                )
            if out:
                return out
            from messiah.vfs.fileid import file_id_i64

            file_id = file_id_i64(path)

        if file_id is not None:
            for source, container, offset, size, addressing in conn.execute(
                "SELECT source, container, offset, size, addressing FROM entries"
                " WHERE file_id_i64 = ? ORDER BY source = ? DESC",
                (file_id, SOURCE_PATCHDB),
            ):
                out.append(
                    Location(file_id, path, Path(container), offset, size, addressing)
                )
        return out
    finally:
        conn.close()


def read(location: Location) -> bytes:
    """Read a payload, honouring physical vs logical addressing."""
    if location.is_logical:
        return ezst.read_logical_range(location.container, location.offset, location.size)

    with location.container.open("rb") as fh:
        fh.seek(location.offset)
        data = fh.read(location.size)
    if len(data) != location.size:
        raise ValueError(
            f"{location.container}: short read at {location.offset} "
            f"(wanted {location.size}, got {len(data)})"
        )
    return data


def decode_wrappers(data: bytes) -> bytes:
    """
    Peel any known wrapper off an extracted payload.

    Payloads inside ordinary containers can still be EZST- or HEX_-wrapped,
    independent of whether the container itself was chunked.
    """
    from messiah.codec import hexwrap

    if ezst.is_ezst(data):
        return ezst.decode(data).data
    if hexwrap.has_hex_prefix(data):
        return hexwrap.decode(data)
    return data

"""
The patchlist manifest.

See docs/patchlist.md. Decoded shape:

    { <package>: { pak_filelist, filelist, mapping_ignorelist } }

    filelist[file_id] = [size, hash, [pak_id, offset], field4]     numeric key
    filelist[path]    = [size, hash]                               path key
                      | [size, hash, [pak_id, -1, pak_id, -1, ...]]

Package names are discovered from the decoded map, never hardcoded -- the
previous implementation had them baked in at seven call sites.

The ids are UNSIGNED u64 in msgpack and SIGNED i64 in SQLite. Everything here
normalises to signed on the way in, because joining without converting silently
drops every row with the high bit set.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from messiah.codec import hexwrap
from messiah.vfs.fileid import u64_to_i64

FIELD4_GROUP_SCALE = 1_000_000


@dataclass(frozen=True)
class FileEntry:
    """A numeric-keyed filelist entry."""

    file_id: int  # signed
    size: int
    content_hash: int  # signed
    pak_id: int | None
    pak_offset: int | None
    field4: int | None

    @property
    def group_id(self) -> int | None:
        return None if self.field4 is None else self.field4 // FIELD4_GROUP_SCALE

    @property
    def index(self) -> int | None:
        return None if self.field4 is None else self.field4 % FIELD4_GROUP_SCALE


@dataclass(frozen=True)
class PathEntry:
    """A path-keyed filelist entry -- handled as a literal path by the patcher."""

    path: str
    size: int
    content_hash: int
    chunks: list[int] | None


@dataclass(frozen=True)
class PakEntry:
    pak_id: int
    size: int
    chunk_hash: int  # signed; joins to Patch.mpkdb.pak.v3


def split_field4(field4: int) -> tuple[int, int]:
    """
    Split field4 into (group_id, index).

    Confirmed from shipped Lua, which does exactly this divide and modulo.
    """
    return divmod(field4, FIELD4_GROUP_SCALE)


def _to_i64(x: int) -> int:
    return u64_to_i64(x) if x >= (1 << 63) else x


def _text(x: Any) -> str:
    return x.decode("utf-8", errors="replace") if isinstance(x, bytes) else str(x)


def _normalize(obj: Any) -> Any:
    """Bytes keys/values become str; integer keys stay integers."""
    if isinstance(obj, dict):
        return {(_text(k) if isinstance(k, bytes) else k): _normalize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize(x) for x in obj]
    if isinstance(obj, bytes):
        return _text(obj)
    return obj


def load(path: Path) -> dict[str, Any]:
    """Decode a patchlist file through its HEX_/HEXB_ wrapper."""
    import msgpack

    raw = hexwrap.decode(path.read_bytes())
    obj = msgpack.unpackb(raw, raw=False, strict_map_key=False)
    if not isinstance(obj, dict):
        raise TypeError(f"unexpected patchlist root type: {type(obj)}")
    return {_text(k): v for k, v in _normalize(obj).items()}


def packages(patchlist: dict[str, Any]) -> list[str]:
    """
    Discover package names from the decoded manifest.

    A package is any top-level value that looks like a package block. Never
    assume a fixed set -- deployments differ and names change.
    """
    return [
        name
        for name, block in patchlist.items()
        if isinstance(block, dict)
        and any(k in block for k in ("filelist", "pak_filelist", "mapping_ignorelist"))
    ]


def iter_file_entries(patchlist: dict[str, Any], package: str) -> Iterator[FileEntry]:
    filelist = patchlist.get(package, {}).get("filelist", {})
    if not isinstance(filelist, dict):
        return
    for key, value in filelist.items():
        if not isinstance(key, int):
            continue
        if not (isinstance(value, (list, tuple)) and len(value) == 4):
            continue
        size, content_hash, loc, field4 = value
        if not (isinstance(size, int) and isinstance(content_hash, int)):
            continue

        pak_id = pak_off = None
        if isinstance(loc, (list, tuple)) and len(loc) == 2 and all(isinstance(x, int) for x in loc):
            pak_id, pak_off = int(loc[0]), int(loc[1])

        yield FileEntry(
            file_id=_to_i64(key),
            size=int(size),
            content_hash=_to_i64(int(content_hash)),
            pak_id=pak_id,
            pak_offset=pak_off,
            field4=int(field4) if isinstance(field4, int) else None,
        )


def iter_path_entries(patchlist: dict[str, Any], package: str) -> Iterator[PathEntry]:
    filelist = patchlist.get(package, {}).get("filelist", {})
    if not isinstance(filelist, dict):
        return
    for key, value in filelist.items():
        if isinstance(key, int):
            continue
        if not (isinstance(value, (list, tuple)) and len(value) in (2, 3)):
            continue
        chunks = None
        if len(value) == 3 and isinstance(value[2], (list, tuple)):
            chunks = [int(x) for x in value[2] if isinstance(x, int)]
        yield PathEntry(
            path=_text(key),
            size=int(value[0]),
            content_hash=_to_i64(int(value[1])),
            chunks=chunks,
        )


def iter_pak_entries(patchlist: dict[str, Any], package: str) -> Iterator[PakEntry]:
    pak_filelist = patchlist.get(package, {}).get("pak_filelist", {})
    if not isinstance(pak_filelist, dict):
        return
    for key, value in pak_filelist.items():
        if not isinstance(key, int):
            continue
        if not (isinstance(value, (list, tuple)) and len(value) == 2):
            continue
        size, chunk_hash = value
        if not (isinstance(size, int) and isinstance(chunk_hash, int)):
            continue
        yield PakEntry(pak_id=key, size=int(size), chunk_hash=_to_i64(int(chunk_hash)))


def iter_ignorelist(patchlist: dict[str, Any], package: str) -> Iterator[str]:
    """Plain path strings -- a free cleartext corpus for path recovery."""
    entries = patchlist.get(package, {}).get("mapping_ignorelist", [])
    if isinstance(entries, list):
        for entry in entries:
            yield _text(entry)


def summarize(patchlist: dict[str, Any]) -> str:
    lines = []
    for package in packages(patchlist):
        block = patchlist[package]
        lines.append(
            f"{package}: filelist={len(block.get('filelist', {}))} "
            f"pak_filelist={len(block.get('pak_filelist', {}))} "
            f"mapping_ignorelist={len(block.get('mapping_ignorelist', []))}"
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# SQLite export
# --------------------------------------------------------------------------

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE pak_filelist (
  pkg TEXT NOT NULL, pak_id INTEGER NOT NULL,
  size INTEGER NOT NULL, hash_i64 INTEGER NOT NULL,
  PRIMARY KEY (pkg, pak_id)
);

CREATE TABLE mapping_ignorelist (pkg TEXT NOT NULL, path TEXT NOT NULL);

CREATE TABLE filelist_id (
  pkg TEXT NOT NULL, file_id_i64 INTEGER NOT NULL,
  size INTEGER NOT NULL, hash_i64 INTEGER NOT NULL,
  pak_id INTEGER, pak_off INTEGER, field4 INTEGER,
  PRIMARY KEY (pkg, file_id_i64)
);

CREATE TABLE filelist_path (
  pkg TEXT NOT NULL, path TEXT NOT NULL,
  size INTEGER NOT NULL, hash_i64 INTEGER NOT NULL, chunks_json TEXT,
  PRIMARY KEY (pkg, path)
);

CREATE INDEX idx_filelist_id_pak ON filelist_id(pkg, pak_id);
CREATE INDEX idx_filelist_id_field4 ON filelist_id(pkg, field4);
"""


def export_sqlite(patchlist: dict[str, Any], out_db: Path) -> None:
    """Materialise the manifest for joining. Derived data -- do not commit it."""
    out_db.parent.mkdir(parents=True, exist_ok=True)
    out_db.unlink(missing_ok=True)

    conn = sqlite3.connect(out_db)
    try:
        conn.executescript(_SCHEMA)
        for package in packages(patchlist):
            conn.executemany(
                "INSERT INTO pak_filelist(pkg,pak_id,size,hash_i64) VALUES (?,?,?,?)",
                [(package, e.pak_id, e.size, e.chunk_hash) for e in iter_pak_entries(patchlist, package)],
            )
            conn.executemany(
                "INSERT INTO mapping_ignorelist(pkg,path) VALUES (?,?)",
                [(package, p) for p in iter_ignorelist(patchlist, package)],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO filelist_id"
                "(pkg,file_id_i64,size,hash_i64,pak_id,pak_off,field4) VALUES (?,?,?,?,?,?,?)",
                [
                    (package, e.file_id, e.size, e.content_hash, e.pak_id, e.pak_offset, e.field4)
                    for e in iter_file_entries(patchlist, package)
                ],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO filelist_path"
                "(pkg,path,size,hash_i64,chunks_json) VALUES (?,?,?,?,?)",
                [
                    (package, e.path, e.size, e.content_hash,
                     json.dumps(e.chunks) if e.chunks is not None else None)
                    for e in iter_path_entries(patchlist, package)
                ],
            )
        conn.commit()
    finally:
        conn.close()

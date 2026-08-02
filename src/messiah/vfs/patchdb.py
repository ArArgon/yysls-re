"""
Patch.mpkdb -- the SQLite index for base packs.

See docs/patchdb.md. The schema names columns v0..v6 with no semantics, so the
mapping below is what makes the database readable:

    info0: v0=file id (i64, or TEXT path), v1=size, v2=pack id,
           v3=content hash, v4=unknown/zero, v5=script flag, v6=offset
    pak:   v0=chunk group, v1=chunk index, v2=chunk size, v3=chunk hash
    meta:  one obfuscated key/value row (see transform_string)

The id column is NOT uniformly integer. A minority of rows key on a literal
path instead, flagged by the script column; for those the path IS the key and
hashing does not apply. Any query must branch on typeof(v0).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from messiah.codec.hexwrap import xor_bytes

# transform_string splits the blob at len % 17 and XORs the halves with these
# two keys. They are the ASCII digits, not the byte values: the Lua caller
# passes numbers, and the native side coerces them with luaL_checklstring.
META_SPLIT_MODULUS = 17
META_HEAD_KEY = b"43"
META_TAIL_KEY = b"53"


@dataclass(frozen=True)
class Info0Row:
    """One stored payload slice."""

    file_id: int | str  # int64 hash, or a literal path for script rows
    size: int
    pack_id: int
    content_hash: int
    unknown: int
    script_flag: int
    offset: int

    @property
    def is_path_keyed(self) -> bool:
        """True when the DB key is a literal path rather than a hash."""
        return isinstance(self.file_id, str)

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True)
class PakRow:
    """A downloadable chunk. `group` is unresolved -- it is not a file id."""

    group: int
    chunk_index: int
    size: int
    chunk_hash: int


def connect(patchdb: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{patchdb}?mode=ro", uri=True)


# --------------------------------------------------------------------------
# info0
# --------------------------------------------------------------------------

_INFO0_COLUMNS = "v0, v1, v2, v3, v4, v5, v6"


def _row(values) -> Info0Row:
    v0, v1, v2, v3, v4, v5, v6 = values
    return Info0Row(
        file_id=v0,
        size=v1,
        pack_id=v2,
        content_hash=v3,
        unknown=v4,
        script_flag=v5,
        offset=v6,
    )


def iter_info0(conn: sqlite3.Connection) -> Iterator[Info0Row]:
    for values in conn.execute(f"select {_INFO0_COLUMNS} from info0"):
        yield _row(values)


def lookup_by_file_id(conn: sqlite3.Connection, file_id: int) -> Info0Row | None:
    """
    Look up by hashed id.

    `file_id` must be SIGNED -- SQLite has no u64. Convert with
    messiah.vfs.fileid.u64_to_i64 first.
    """
    values = conn.execute(
        f"select {_INFO0_COLUMNS} from info0 where v0 = ?", (file_id,)
    ).fetchone()
    return _row(values) if values else None


def lookup_by_path(conn: sqlite3.Connection, path: str) -> Info0Row | None:
    """
    Look up a path-keyed row by its literal path.

    Tries the literal key first, then the hashed id -- a path can be stored
    either way and callers rarely know which.
    """
    values = conn.execute(
        f"select {_INFO0_COLUMNS} from info0 where v0 = ?", (path,)
    ).fetchone()
    if values:
        return _row(values)

    from messiah.vfs.fileid import file_id_i64

    return lookup_by_file_id(conn, file_id_i64(path))


def iter_path_keyed(conn: sqlite3.Connection) -> Iterator[Info0Row]:
    """
    Rows keyed by a literal path.

    Few in number but high value: they are cleartext paths, which makes them
    both seed material for path recovery and a correctness test for a file_id
    implementation.
    """
    for values in conn.execute(
        f"select {_INFO0_COLUMNS} from info0 where typeof(v0) = 'text'"
    ):
        yield _row(values)


def max_extent_by_pack(conn: sqlite3.Connection) -> dict[int, int]:
    """
    Per pack, `max(offset + size)`.

    Should equal that pack's physical file size. Greater means the pack is
    EZST-chunked and offsets are logical (docs/ezst.md).
    """
    return {
        pack_id: end
        for pack_id, end in conn.execute("select v2, max(v6 + v1) from info0 group by v2")
    }


def rank_in_pack_by_offset(conn: sqlite3.Connection, pack_id: int, offset: int) -> int:
    """
    0-based rank of a payload within its pack, ordered by offset.

    For "pure" groups this equals patchlist field4's index -- see
    docs/patchlist.md section 5. It does not hold for mixed groups.
    """
    (count,) = conn.execute(
        "select count(*) from info0 where v2 = ? and v6 < ?", (pack_id, offset)
    ).fetchone()
    return count


# --------------------------------------------------------------------------
# pak
# --------------------------------------------------------------------------


def iter_pak(conn: sqlite3.Connection) -> Iterator[PakRow]:
    for v0, v1, v2, v3 in conn.execute("select v0, v1, v2, v3 from pak"):
        yield PakRow(group=v0, chunk_index=v1, size=v2, chunk_hash=v3)


def pak_by_hash(conn: sqlite3.Connection) -> dict[int, PakRow]:
    """
    Index the pak table by chunk hash -- the join key into the patchlist's
    pak_filelist. See docs/patchdb.md section 3.
    """
    return {row.chunk_hash: row for row in iter_pak(conn)}


# --------------------------------------------------------------------------
# meta
# --------------------------------------------------------------------------


def transform_string(blob: bytes) -> bytes:
    """
    The meta obfuscation, taken from the game's own Lua.

        headlen = len(data) % 17
        XorExcrypt(data[:headlen], "43") + XorExcrypt(data[headlen:], "53")

    Symmetric: encoding and decoding are the same operation. Applied to both
    the key and the value of every row.
    """
    headlen = len(blob) % META_SPLIT_MODULUS
    return xor_bytes(blob[:headlen], META_HEAD_KEY) + xor_bytes(blob[headlen:], META_TAIL_KEY)


def read_meta(conn: sqlite3.Connection) -> dict[str, object]:
    """
    Decode the meta table. Values are JSON.

    The only key observed so far is "status"; whether others exist in other
    builds is untested, so this returns every row rather than assuming one.
    """
    out: dict[str, object] = {}
    for key_blob, val_blob in conn.execute("select key, val from meta"):
        key = transform_string(bytes(key_blob)).decode("utf-8", errors="replace")
        raw = transform_string(bytes(val_blob))
        try:
            out[key] = json.loads(raw.decode("utf-8"))
        except Exception:
            out[key] = {
                "__raw_utf8__": raw.decode("utf-8", errors="replace"),
                "__raw_hex__": raw.hex(),
            }
    return out

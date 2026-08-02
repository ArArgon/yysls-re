"""
Container discovery and resolution.

This module exists to kill one specific class of bug: hardcoded container
names. The previous tooling had `Patch{n}.mpk` built into three separate call
sites, a forced "Resources.mpk" override that ignored its own arguments, and
three byte-identical copies of an HD resolver with a dead special case.

The rule (docs/vfs-model.md section 4): naming *conventions* are structural and
may be encoded; specific *instances* may not. Which pack holds an asset is not
stable across builds, so instances are always discovered from disk.

Usage:

    resolver = ContainerResolver(install_root)
    for container in resolver.discover():
        ...
    pack = resolver.for_pack_id(entry.pack_id, kind=PackKind.PATCH)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# --------------------------------------------------------------------------
# Conventions
# --------------------------------------------------------------------------


class PackKind(str, Enum):
    PATCH = "patch"
    LT = "lt"
    RESOURCES = "resources"


class ContainerRole(str, Enum):
    PACK = "pack"  # a .mpk holding payload bytes
    INDEX = "index"  # a .mpkinfo binary index
    INTEGRITY = "integrity"  # a HEXB_-wrapped .mpkinfo
    PATCHDB = "patchdb"  # the SQLite index
    PATCHLIST = "patchlist"  # a HEXB_-wrapped msgpack manifest
    HD_DATA = "hd_data"
    HD_INDEX = "hd_index"
    HD_MANIFEST = "hd_manifest"


@dataclass(frozen=True)
class NamingConvention:
    """
    Structural naming patterns. Override if a future build renames things.

    Every field is a shape, never an instance.
    """

    # Where the patch system lives, relative to the install root.
    patch_subdir: str = "LocalData/Patch"
    hd_subdir: str = "HD"

    resources_pack: str = "Resources.mpk"
    resources_index: str = "Resources.mpkinfo"

    patch_pack: str = "Patch{pack_id}.mpk"
    lt_pack: str = "LT{pack_id}.mpk"
    lt_index: str = "LT{pack_id}.mpkinfo"

    patchdb: str = "Patch.mpkdb"
    patchlist_glob: str = "*patchlist*.txt"

    hd_data: str = "data{n}"
    hd_index: str = "index{n}"
    hd_manifest: str = "MANIFEST"

    # An index filename matching one of these resolves to the named pack.
    # Anything else is a cache index whose entries carry their own pack_id.
    index_to_pack: tuple[tuple[str, str], ...] = (
        (r"Resources\.mpkinfo", "Resources.mpk"),
        (r"LT(\d+)\.mpkinfo", "LT{0}.mpk"),
        (r"Patch(\d+)\.mpkinfo", "Patch{0}.mpk"),
    )

    hd_data_re: str = r"data(\d+)"
    hd_index_re: str = r"index(\d+)"


DEFAULT = NamingConvention()


@dataclass(frozen=True)
class Container:
    path: Path
    role: ContainerRole
    pack_id: int | None = None
    kind: PackKind | None = None

    @property
    def name(self) -> str:
        return self.path.name


# --------------------------------------------------------------------------
# Resolver
# --------------------------------------------------------------------------


class ContainerResolver:
    """
    Discovers what an install actually contains and resolves index -> pack.

    Nothing is assumed to exist. `discover()` reports only what is on disk, so
    a build with entirely new pack numbers works without a code change.
    """

    def __init__(self, install_root: Path, convention: NamingConvention = DEFAULT):
        self.install_root = Path(install_root)
        self.convention = convention
        self._patch_root: Path | None = None

    # -- roots ------------------------------------------------------------

    @property
    def patch_root(self) -> Path:
        """
        The patch directory.

        Tries the conventional subdirectory, then falls back to the install
        root itself -- extracted samples are often a flat directory rather than
        a full install tree.
        """
        if self._patch_root is None:
            candidate = self.install_root / self.convention.patch_subdir
            if candidate.is_dir():
                self._patch_root = candidate
            else:
                self._patch_root = self.install_root
        return self._patch_root

    @property
    def hd_root(self) -> Path:
        return self.patch_root / self.convention.hd_subdir

    def _search_dirs(self) -> list[Path]:
        dirs = [self.install_root]
        if self.patch_root != self.install_root:
            dirs.append(self.patch_root)
        return dirs

    # -- discovery --------------------------------------------------------

    def discover(self) -> list[Container]:
        """Enumerate every container present, classified by role."""
        found: list[Container] = []
        seen: set[Path] = set()

        def add(container: Container) -> None:
            if container.path not in seen and container.path.exists():
                seen.add(container.path)
                found.append(container)

        for directory in self._search_dirs():
            if not directory.is_dir():
                continue

            for path in sorted(directory.glob("*.mpk")):
                pack_id, kind = self._classify_pack(path.name)
                add(Container(path=path, role=ContainerRole.PACK, pack_id=pack_id, kind=kind))

            for path in sorted(directory.glob("*.mpkinfo")):
                # Import here to avoid a circular import at module load.
                from messiah.vfs import mpkinfo as mpkinfo_mod

                role = (
                    ContainerRole.INDEX
                    if mpkinfo_mod.is_binary_index(path)
                    else ContainerRole.INTEGRITY
                )
                add(Container(path=path, role=role))

            for path in sorted(directory.glob(self.convention.patchlist_glob)):
                add(Container(path=path, role=ContainerRole.PATCHLIST))

            patchdb = directory / self.convention.patchdb
            if patchdb.exists():
                add(Container(path=patchdb, role=ContainerRole.PATCHDB))

        found.extend(self._discover_hd(seen))
        return found

    def _discover_hd(self, seen: set[Path]) -> list[Container]:
        if not self.hd_root.is_dir():
            return []

        out: list[Container] = []
        data_re = re.compile(self.convention.hd_data_re + r"\Z")
        index_re = re.compile(self.convention.hd_index_re + r"\Z")

        for path in sorted(self.hd_root.iterdir()):
            if path in seen or not path.is_file():
                continue
            if path.name == self.convention.hd_manifest:
                out.append(Container(path=path, role=ContainerRole.HD_MANIFEST))
            elif (m := data_re.match(path.name)) is not None:
                out.append(
                    Container(path=path, role=ContainerRole.HD_DATA, pack_id=int(m.group(1)))
                )
            elif (m := index_re.match(path.name)) is not None:
                out.append(
                    Container(path=path, role=ContainerRole.HD_INDEX, pack_id=int(m.group(1)))
                )
        return out

    def _classify_pack(self, name: str) -> tuple[int | None, PackKind | None]:
        if name == self.convention.resources_pack:
            return None, PackKind.RESOURCES
        for kind, template in (
            (PackKind.PATCH, self.convention.patch_pack),
            (PackKind.LT, self.convention.lt_pack),
        ):
            pattern = re.escape(template).replace(r"\{pack_id\}", r"(\d+)")
            if (m := re.fullmatch(pattern, name)) is not None:
                return int(m.group(1)), kind
        return None, None

    # -- resolution -------------------------------------------------------

    def find(self, name: str) -> Path | None:
        """Locate a file by name in any search directory."""
        for directory in self._search_dirs():
            candidate = directory / name
            if candidate.exists():
                return candidate
        return None

    def for_pack_id(self, pack_id: int, kind: PackKind = PackKind.PATCH) -> Path | None:
        """Resolve a pack id to a container path, or None if absent."""
        if kind is PackKind.RESOURCES:
            return self.find(self.convention.resources_pack)
        template = (
            self.convention.patch_pack if kind is PackKind.PATCH else self.convention.lt_pack
        )
        return self.find(template.format(pack_id=pack_id))

    def for_index(self, index_path: Path) -> Path | None:
        """
        Resolve an index file to its container, when the index name determines
        it.

        Returns None for cache indexes (`MpkCached_*`, `TinyFiles_*`), whose
        entries each carry their own pack id -- use `for_pack_id` per entry.
        """
        for pattern, template in self.convention.index_to_pack:
            if (m := re.fullmatch(pattern, index_path.name)) is not None:
                return self.find(template.format(*m.groups()))
        return None

    def hd_container(self, file_id: int, *, index: bool = False) -> Path | None:
        """
        Resolve an HD data or index container by id.

        Plain formatting, no special cases. (An earlier implementation carried
        a special-case branch for one id that was a no-op, duplicated three
        times.)
        """
        template = self.convention.hd_index if index else self.convention.hd_data
        candidate = self.hd_root / template.format(n=file_id)
        return candidate if candidate.exists() else None

    def patchdb_path(self) -> Path | None:
        return self.find(self.convention.patchdb)

    def patchlist_paths(self) -> list[Path]:
        out: list[Path] = []
        for directory in self._search_dirs():
            if directory.is_dir():
                out.extend(sorted(directory.glob(self.convention.patchlist_glob)))
        return out

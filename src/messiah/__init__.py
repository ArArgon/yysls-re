"""
Reader and decoder for the Messiah engine's MPK asset/patch filesystem.

Start with docs/vfs-model.md. The short version: .mpk containers are dumb byte
blobs with no filenames inside; every listing comes from an external index that
maps an opaque 64-bit file id to (container, offset, size).

Subpackages:
    vfs      container resolution, file ids, and the three index formats
    codec    HEX_ transport wrapper, EZST blocks, zstd helper, content hash
    lua      LuaText LZ4 wrapper and custom-opcode remapping
    hd       the separate HD container family
    mapping  encodings of the opaque path-mapping table
    frida    runtime instrumentation
    cli      thin entry points

Never hardcode a container name, pack number, file id, offset, or binary
address -- these change every release. Resolve through
messiah.vfs.containers.ContainerResolver.
"""

__version__ = "0.1.0"

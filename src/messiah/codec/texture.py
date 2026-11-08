"""
Texture containers (magic 02 02 02 01).

See docs/texture.md.

    header (0x28 bytes): format @5, mip_count @6, width/height @0x0c
    mip records, smallest first:
        u32 blob | u16 w | u16 h | u16 depth | u16 pitch | u32 raw | EZST block
        payload_len = blob - 24
    16-byte trailer
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import ezst

TEXTURE_MAGIC = b"\x02\x02\x02\x01"

# EPixelFormat value -> (name, DXGI_FORMAT, bytes per block (BC) or per pixel, is_block)
PIXEL_FORMATS: dict[int, tuple[str, int | None, int, bool]] = {
    1: ("A32R32G32B32F", 2, 16, False),
    2: ("A16B16G16R16F", 10, 8, False),
    3: ("R8G8B8A8", 28, 4, False),
    11: ("L8", 61, 1, False),
    13: ("A8", 65, 1, False),
    18: ("BC1", 71, 8, True),
    19: ("BC2", 74, 16, True),
    20: ("BC3", 77, 16, True),
    21: ("BC4", 80, 8, True),
    22: ("BC5", 83, 16, True),
    23: ("BC6H_SF", 96, 16, True),
    24: ("BC6H_UF", 95, 16, True),
    25: ("BC7", 98, 16, True),
}


@dataclass(frozen=True)
class MipLevel:
    width: int
    height: int
    depth: int
    pitch: int
    raw_size: int
    data: bytes  # empty when raw_size == 0 (no local pixel data)


@dataclass(frozen=True)
class Texture:
    pixel_format: int
    mip_count: int
    width: int
    height: int
    flags: int
    levels: list[MipLevel]
    warnings: list[str] = field(default_factory=list)

    @property
    def format_name(self) -> str:
        info = PIXEL_FORMATS.get(self.pixel_format)
        return info[0] if info else f"format_{self.pixel_format}"

    def top_levels(self) -> list[MipLevel]:
        """Largest level(s) with data. Several at one size means array/cube layers."""
        levels = [m for m in self.levels if m.data]
        if not levels:
            return []
        top = max(m.width * m.height for m in levels)
        return [m for m in levels if m.width * m.height == top]


def is_texture(blob: bytes) -> bool:
    return blob[:4] == TEXTURE_MAGIC


def parse(buf: bytes) -> Texture:
    """Parse a texture container, decoding every mip level that has data."""
    if not is_texture(buf) or len(buf) < 0x28:
        raise ValueError("not a texture container")
    pixel_format, mip_count, flags = buf[5], buf[6], buf[7]
    width, height = struct.unpack_from("<HH", buf, 0x0C)
    levels: list[MipLevel] = []
    warnings: list[str] = []
    pos = 0x28
    while pos + 16 <= len(buf):
        blob, w, h, depth, pitch, raw = struct.unpack_from("<IHHHHI", buf, pos)
        pos += 16
        if not ezst.is_ezst(buf[pos : pos + 4]):
            warnings.append(f"expected EZST at {pos}")
            break
        payload_len = max(0, blob - 24)
        data = b""
        if raw:
            try:
                data = ezst.decode(buf[pos : pos + 8 + payload_len], verify_size=False).data
            except Exception as e:  # noqa: BLE001 - keep going, report per level
                warnings.append(f"level {w}x{h}: {e}")
            if len(data) != raw:
                warnings.append(f"level {w}x{h}: decoded {len(data)} bytes, header says {raw}")
        levels.append(MipLevel(w, h, depth, pitch, raw, data))
        pos += 8 + payload_len
        if pos + 16 == len(buf):  # trailer
            pos = len(buf)
            break
    if pos != len(buf):
        warnings.append(f"record walk ended at {pos} of {len(buf)}")
    return Texture(pixel_format, mip_count, width, height, flags, levels, warnings)


def dds(level: MipLevel, pixel_format: int) -> bytes:
    """Wrap one level in a DDS (DX10 header). Raises for formats without a DXGI mapping."""
    info = PIXEL_FORMATS.get(pixel_format)
    if not info or info[1] is None:
        raise ValueError(f"no DXGI mapping for pixel format {pixel_format}")
    flags = 0x1 | 0x2 | 0x4 | 0x1000 | 0x80000  # caps|height|width|pixelformat|linearsize
    header = struct.pack("<4sIIIIIII", b"DDS ", 124, flags, level.height, level.width, len(level.data), 0, 0)
    header += b"\0" * 44
    header += struct.pack("<II4sIIIII", 32, 0x4, b"DX10", 0, 0, 0, 0, 0)
    header += struct.pack("<IIIII", 0x1000, 0, 0, 0, 0)
    header += struct.pack("<IIIII", info[1], 3, 0, 1, 0)  # dxgi, TEXTURE2D, misc, array=1, misc2
    return header + level.data

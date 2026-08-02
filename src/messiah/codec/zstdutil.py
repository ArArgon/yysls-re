"""
One zstd helper, replacing six near-identical copies that had drifted apart.

Prefers the `zstandard` package and falls back to the `zstd` CLI, so decoding
works in a bare environment (useful when cross-checking a suspected bug).
"""

from __future__ import annotations

import subprocess

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def find_frame(data: bytes, start: int = 0) -> int:
    """
    Locate the first zstd frame at or after `start`; -1 if absent.

    Use this rather than assuming a fixed offset -- containers that embed a
    frame after a header (HD MANIFEST, for one) do not put it at a constant
    position.
    """
    return data.find(ZSTD_MAGIC, start)


def decompress(payload: bytes, *, expected_size: int | None = None) -> bytes:
    """
    Decompress exactly one zstd frame, requiring it to consume all input.

    Raises if the frame is truncated or if trailing bytes remain. When a
    container appends bytes after the frame, use `decompress_with_trailer`.
    """
    data, trailer = decompress_with_trailer(payload)
    if trailer:
        raise ValueError(f"{len(trailer)} trailing bytes after zstd frame")
    if expected_size is not None and len(data) != expected_size:
        raise ValueError(f"zstd size mismatch: expected {expected_size}, got {len(data)}")
    return data


def decompress_with_trailer(payload: bytes) -> tuple[bytes, bytes]:
    """
    Decompress one frame and return `(data, trailing_bytes)`.

    Needed because some containers append bytes after the frame ends. A
    one-shot decompressor that demands exact input length fails on those.
    """
    try:
        import zstandard as zstd
    except ImportError:
        return _decompress_cli(payload), b""

    # Many frames omit the optional content-size field, so a streaming
    # decompressor is required -- one-shot APIs need that field.
    dobj = zstd.ZstdDecompressor().decompressobj()
    data = dobj.decompress(payload)
    if not dobj.eof:
        raise ValueError("truncated zstd frame: end-of-frame not reached")
    return data, dobj.unused_data


def _decompress_cli(payload: bytes) -> bytes:
    proc = subprocess.run(
        ["zstd", "-d", "-q", "--stdout"],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", errors="ignore").strip()
        raise ValueError(f"zstd CLI failed: {msg}")
    return proc.stdout

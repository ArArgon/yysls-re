"""
EZST blocks and the logical-stream model for chunked packs.

See docs/ezst.md.

    "EZST" | u32le decompressed_size | payload
    payload[:min(floor16(len), 256)] is AES-256-ECB encrypted; the rest is not
    after decrypting that prefix, the whole payload is one zstd frame

A chunked .mpk holds thousands of these back to back. Index (offset, size)
pairs then address the CONCATENATION of their decompressed contents -- a
"logical" stream that is larger than the physical file.

Merged from two former modules; a third divergent reimplementation of the
chunk-boundary walk has been dropped in favour of this one.
"""

from __future__ import annotations

import mmap
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from . import zstdutil

EZST_MAGIC = b"EZST"

# A sibling variant with the SAME 8-byte header but an unencrypted payload.
# Rare, but rejecting it looks like a corrupt block rather than a variant.
ZSTD_MAGIC = b"ZSTD"

BLOCK_MAGICS = (EZST_MAGIC, ZSTD_MAGIC)

# Fixed 32-byte AES-256 key compiled into the client. Durable across builds so
# far. Only the head of each payload is encrypted, so this is obfuscation
# rather than confidentiality.
EZST_AES_KEY = struct.pack(
    "<4Q",
    0x556A586E32723575,
    0x38782F913F152867,
    0x2D3B615062536756,
    0x6B59703373367639,
)

MAX_ENCRYPTED_PREFIX = 256

# Some chunked packs open with these bytes before the first block. Whether it
# is a real container header is unresolved -- do not detect on it.
CHUNKED_PACK_HINT = b"ZZZ4"


@dataclass(frozen=True)
class EzstDecoded:
    decompressed_size: int
    data: bytes
    trailer: bytes


@dataclass(frozen=True)
class EzstBlock:
    """One block's physical extent and its span in the logical stream."""

    phys_off: int
    phys_end: int
    logical_off: int
    decompressed_size: int
    trailer_len: int

    @property
    def phys_size(self) -> int:
        return self.phys_end - self.phys_off

    @property
    def logical_end(self) -> int:
        return self.logical_off + self.decompressed_size


# --------------------------------------------------------------------------
# Single block
# --------------------------------------------------------------------------


def encrypted_prefix_len(payload_len: int) -> int:
    """
    How much of a payload is encrypted.

    Floored to 16 bytes because ECB needs block alignment -- a payload under 16
    bytes has nothing encrypted at all.
    """
    return min((payload_len // 16) * 16, MAX_ENCRYPTED_PREFIX)


def _aes_ecb_decrypt(data: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES

        return AES.new(EZST_AES_KEY, AES.MODE_ECB).decrypt(data)
    except ImportError:
        pass

    proc = subprocess.run(
        ["openssl", "enc", "-aes-256-ecb", "-d", "-nopad", "-nosalt", "-K", EZST_AES_KEY.hex()],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", errors="ignore").strip()
        raise ValueError(f"openssl AES decrypt failed: {msg}")
    return proc.stdout


def is_ezst(blob: bytes) -> bool:
    """True for either block magic (encrypted EZST or plain ZSTD)."""
    return blob[:4] in BLOCK_MAGICS


def decode(blob: bytes, *, verify_size: bool = True) -> EzstDecoded:
    """
    Decode one block, handling both magics.

    `verify_size` is not merely a sanity check: the size field is the oracle
    that validates a candidate block boundary during the chunk walk, so
    `iter_blocks` relies on a mismatch raising here.
    """
    magic = blob[:4]
    if magic not in BLOCK_MAGICS:
        raise ValueError(f"not an EZST/ZSTD block (magic {magic!r})")
    if len(blob) < 8:
        raise ValueError("block truncated")

    decompressed_size = struct.unpack_from("<I", blob, 4)[0]
    payload = blob[8:]

    # Only the EZST variant encrypts its payload head.
    if magic == EZST_MAGIC:
        n = encrypted_prefix_len(len(payload))
        if n:
            payload = _aes_ecb_decrypt(payload[:n]) + payload[n:]

    data, trailer = zstdutil.decompress_with_trailer(payload)

    if verify_size and len(data) != decompressed_size:
        raise ValueError(f"size mismatch: expected {decompressed_size}, got {len(data)}")
    return EzstDecoded(decompressed_size=decompressed_size, data=data, trailer=trailer)


# --------------------------------------------------------------------------
# Chunked packs
# --------------------------------------------------------------------------


def looks_chunked(path: Path, *, probe_bytes: int = 1 << 20, min_blocks: int = 4) -> bool:
    """
    Heuristic: does this container hold EZST blocks?

    Detection must be per CONTAINER, not per entry. An entry whose
    offset+size happens to fit inside the physical file is common early on and
    reading it physically yields plausible-looking garbage.
    """
    with path.open("rb") as fh:
        head = fh.read(probe_bytes)
    count = 0
    pos = head.find(EZST_MAGIC)
    while pos != -1 and count < min_blocks:
        count += 1
        pos = head.find(EZST_MAGIC, pos + 4)
    return count >= min_blocks


def iter_blocks(path: Path) -> Iterator[EzstBlock]:
    """
    Walk a chunked pack, yielding validated blocks with running logical offsets.

    Block ends are found by scanning for the next magic. Because those bytes
    can also occur inside compressed data, a candidate end is accepted only if
    the block decodes; otherwise the scan advances to the next occurrence.
    """
    with path.open("rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            size = mm.size()
            pos = mm.find(EZST_MAGIC, 0)
            if pos == -1:
                raise ValueError(f"{path}: no EZST blocks found")

            logical = 0
            while pos < size:
                nxt = mm.find(EZST_MAGIC, pos + 4)
                resynced = False

                while True:
                    end = size if nxt == -1 else nxt
                    try:
                        dec = decode(mm[pos:end], verify_size=True)
                    except Exception:
                        if nxt == -1:
                            # This start was a false positive; resync forward.
                            nxt_start = mm.find(EZST_MAGIC, pos + 1)
                            if nxt_start == -1:
                                return
                            pos = nxt_start
                            resynced = True
                            break
                        nxt = mm.find(EZST_MAGIC, nxt + 1)
                        continue

                    yield EzstBlock(
                        phys_off=pos,
                        phys_end=end,
                        logical_off=logical,
                        decompressed_size=dec.decompressed_size,
                        trailer_len=len(dec.trailer),
                    )
                    logical += dec.decompressed_size
                    pos = end
                    break

                if resynced:
                    continue
                if pos >= size:
                    break
        finally:
            mm.close()


def build_chunk_map(path: Path) -> list[EzstBlock]:
    """Materialise the block map so repeated reads do not rescan the file."""
    return list(iter_blocks(path))


def logical_size(path: Path) -> int:
    """Total size of the decompressed logical stream."""
    total = 0
    for block in iter_blocks(path):
        total = block.logical_end
    return total


def read_logical_range(
    path: Path,
    logical_off: int,
    size: int,
    *,
    chunk_map: list[EzstBlock] | None = None,
) -> bytes:
    """
    Read `size` bytes at `logical_off` from the logical stream.

    Only blocks overlapping the range are decompressed. Pass a `chunk_map` from
    `build_chunk_map` when reading many entries from one pack.
    """
    if logical_off < 0 or size < 0:
        raise ValueError("negative logical_off/size")
    if size == 0:
        return b""

    start, end = logical_off, logical_off + size
    blocks = chunk_map if chunk_map is not None else iter_blocks(path)
    out = bytearray()

    with path.open("rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            for block in blocks:
                if block.logical_end <= start:
                    continue
                if block.logical_off >= end:
                    break

                data = decode(mm[block.phys_off : block.phys_end], verify_size=True).data
                lo = max(0, start - block.logical_off)
                hi = min(block.decompressed_size, end - block.logical_off)
                out.extend(data[lo:hi])
        finally:
            mm.close()

    if len(out) != size:
        raise ValueError(f"short read: wanted {size}, got {len(out)}")
    return bytes(out)

"""
The HEX_ / HEXB_ text wrapper.

    strip prefix -> base64 -> XOR(repeating key) -> zlib -> msgpack | JSON

See docs/patchlist.md section 1.

Natively this is the `ZipDecompress` callback. It is NOT `XorExcrypt`, which is
a bare repeating-key XOR with a different key -- see messiah.vfs.patchdb.

Applied to: patchlist manifests, patch_config, essential lists, and some files
carrying an .mpkinfo extension. Always sniff the prefix; never dispatch on the
file extension.
"""

from __future__ import annotations

import base64
import json
import zlib

# The base64 alphabet is standard, not custom.
NETEASE_HEX_XOR_KEY = b"netease_hex_xor_encrypt_key"

_PREFIXES = ("HEXB_", "HEX_")


def has_hex_prefix(data: bytes | str) -> bool:
    """Cheap sniff. Use this instead of trusting a filename."""
    if isinstance(data, bytes):
        head = data[:8].lstrip()
        return any(head.startswith(p.encode()) for p in _PREFIXES)
    return any(data.lstrip().startswith(p) for p in _PREFIXES)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """Length-preserving repeating-key XOR. Symmetric."""
    if not key:
        raise ValueError("empty XOR key")
    out = bytearray(data)
    for i in range(len(out)):
        out[i] ^= key[i % len(key)]
    return bytes(out)


def decode(text: bytes | str, *, key: bytes = NETEASE_HEX_XOR_KEY) -> bytes:
    """
    Decode a HEX_/HEXB_ payload to its raw inflated bytes.

    The prefix is optional -- bare base64 bodies decode fine.
    """
    if isinstance(text, bytes):
        text = text.decode("ascii", errors="strict")
    text = text.strip()

    for prefix in _PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break

    return zlib.decompress(xor_bytes(base64.b64decode(text), key))


def decode_json(text: bytes | str, *, key: bytes = NETEASE_HEX_XOR_KEY):
    """Decode a HEX_-wrapped JSON config."""
    return json.loads(decode(text, key=key))


def decode_msgpack(text: bytes | str, *, key: bytes = NETEASE_HEX_XOR_KEY):
    """
    Decode a HEXB_-wrapped msgpack manifest.

    `strict_map_key=False` is required: manifest maps are keyed by 64-bit
    integers. Keys come back UNSIGNED -- convert with
    messiah.vfs.fileid.u64_to_i64 before joining against SQLite.
    """
    import msgpack

    return msgpack.unpackb(decode(text, key=key), raw=True, strict_map_key=False)


def encode(payload: bytes, *, prefix: str = "HEXB_", key: bytes = NETEASE_HEX_XOR_KEY) -> str:
    """Inverse of `decode`. A native encoder pipeline also exists in the client."""
    return prefix + base64.b64encode(xor_bytes(zlib.compress(payload), key)).decode("ascii")

"""Keyed authenticated wrapper for the plaintext v1 signer checkpoints.

The Lamport (:meth:`pqattest.OneTimeSigner.checkpoint`), W-OTS
(:meth:`pqattest.WOTSOneTimeSigner.checkpoint`) and Merkle
(:meth:`pqattest.MerkleSigner.checkpoint`) checkpoints all serialise the
signing key in the clear and end in a plain SHA-256 checksum that only
detects accidental corruption. :func:`auth_wrap` adds an outer
HMAC-SHA-256 envelope so a party holding the shared key can tell whether a
checkpoint was altered by someone without the key; :func:`auth_unwrap`
verifies the tag and hands the original checkpoint bytes back.

The envelope authenticates but does **not** encrypt (the payload stays
readable), and it is stateless: it neither stops the same blob from being
copied or replayed nor detects a rollback to an older checkpoint — those
guards remain the caller's responsibility (atomic storage, monotonic
metadata, etc.).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

__all__ = ["auth_wrap", "auth_unwrap"]

_AUTH_MAGIC = b"PQAAUTH\0"
_AUTH_VERSION = 1
_AUTH_HEADER_BYTES = 8 + 1 + 1 + 4
_AUTH_TAG_BYTES = 32  # HMAC-SHA-256 output length

# Scheme name -> (envelope identifier, magic prefix of the wrapped checkpoint).
# The magic bytes match the v1 checkpoint codecs in the lamport, wots and
# merkle modules; they are restated here so this module owns the envelope's
# scheme table without importing the package init.
_SCHEMES: dict[str, tuple[int, bytes]] = {
    "lamport": (1, b"PQALCP\0\0"),
    "wots": (2, b"PQAWCP\0\0"),
    "merkle": (3, b"PQAMSCP\0"),
}
_SCHEME_IDS: dict[int, tuple[str, bytes]] = {
    identifier: (name, magic) for name, (identifier, magic) in _SCHEMES.items()
}


def _coerce_bytes(value: Any, label: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    raise TypeError(f"{label} must be bytes or bytearray")


def _validate_key(key: Any) -> bytes:
    key_bytes = _coerce_bytes(key, "key")
    if not key_bytes:
        raise ValueError("key must not be empty")
    return key_bytes


def auth_wrap(checkpoint: Any, *, scheme: Any, key: Any) -> bytes:
    """Wrap a plaintext v1 signer checkpoint in a keyed authenticated envelope.

    ``checkpoint`` must be ``bytes`` or ``bytearray`` holding the output of
    one of the three existing checkpoint serialisers; ``key`` must be a
    non-empty ``bytes``/``bytearray`` shared secret; ``scheme`` is
    keyword-only and one of ``"lamport"``, ``"wots"`` or ``"merkle"``.
    A non-bytes ``checkpoint``/``key`` or a non-str ``scheme`` raises
    ``TypeError``; an empty key, an unknown scheme or a checkpoint whose
    magic does not match the named scheme raises ``ValueError``.

    The v1 envelope layout is: the 8-byte magic ``b"PQAAUTH\\0"``; one byte
    each for the version (1) and the scheme identifier (lamport=1, wots=2,
    merkle=3); the payload length as 4 big-endian bytes; the original
    checkpoint payload unchanged; and finally the 32-byte
    ``HMAC-SHA-256(key, all preceding bytes)`` tag. Encoding is
    deterministic: the same checkpoint, scheme and key always produce the
    same bytes. The payload is not encrypted — the envelope only lets a
    key holder detect keyless tampering.
    """
    payload = _coerce_bytes(checkpoint, "checkpoint")
    key_bytes = _validate_key(key)
    if not isinstance(scheme, str):
        raise TypeError("scheme must be a string")
    try:
        identifier, payload_magic = _SCHEMES[scheme]
    except KeyError:
        raise ValueError(f"unknown scheme: {scheme!r}") from None
    if len(payload) < len(payload_magic):
        raise ValueError("checkpoint is too short to contain a scheme magic")
    if payload[: len(payload_magic)] != payload_magic:
        raise ValueError(f"checkpoint magic does not match scheme {scheme!r}")
    body = (
        _AUTH_MAGIC
        + bytes((_AUTH_VERSION, identifier))
        + len(payload).to_bytes(4, "big")
        + payload
    )
    return body + hmac.new(key_bytes, body, hashlib.sha256).digest()


def auth_unwrap(data: Any, *, key: Any, expect: Any = None) -> tuple[str, bytes]:
    """Verify an authenticated envelope and return ``(scheme, checkpoint)``.

    ``data`` must be ``bytes`` or ``bytearray`` produced by
    :func:`auth_wrap` and ``key`` a non-empty ``bytes``/``bytearray`` shared
    secret; the keyword-only ``expect`` may name a scheme
    (``"lamport"``/``"wots"``/``"merkle"``) that the envelope identifier
    must then match. Wrong parameter types raise ``TypeError``; an empty
    key, an unknown ``expect`` scheme, a bad envelope magic, version or
    scheme identifier, a length field that does not match the content,
    truncation, trailing data, a payload magic that does not match its
    scheme identifier, an identifier different from ``expect`` or a bad
    HMAC tag raises ``ValueError`` and nothing is returned.

    The tag is checked with :func:`hmac.compare_digest` before any payload
    byte is trusted; only afterwards is the payload magic checked against
    the scheme identifier. The returned checkpoint is the exact payload
    passed to :func:`auth_wrap` (as ``bytes``), ready for the matching
    ``from_checkpoint``. The envelope authenticates but does not encrypt
    and does not prevent copying, replay or rollback of an older valid blob.
    """
    blob = _coerce_bytes(data, "data")
    key_bytes = _validate_key(key)
    if expect is not None:
        if not isinstance(expect, str):
            raise TypeError("expect must be a scheme name string or None")
        if expect not in _SCHEMES:
            raise ValueError(f"unknown expected scheme: {expect!r}")

    minimum_length = _AUTH_HEADER_BYTES + _AUTH_TAG_BYTES
    if len(blob) < minimum_length:
        raise ValueError("authenticated checkpoint is truncated")
    if blob[:8] != _AUTH_MAGIC:
        raise ValueError("bad authenticated checkpoint magic")
    if blob[8] != _AUTH_VERSION:
        raise ValueError(f"unsupported authenticated checkpoint version: {blob[8]}")
    identifier = blob[9]
    try:
        scheme, payload_magic = _SCHEME_IDS[identifier]
    except KeyError:
        raise ValueError(f"unknown scheme identifier: {identifier}") from None
    payload_length = int.from_bytes(blob[10:14], "big")
    expected_length = _AUTH_HEADER_BYTES + payload_length + _AUTH_TAG_BYTES
    if len(blob) < expected_length:
        raise ValueError("authenticated checkpoint is truncated")
    if len(blob) > expected_length:
        raise ValueError("trailing data after the authenticated checkpoint")

    body, tag = blob[:-_AUTH_TAG_BYTES], blob[-_AUTH_TAG_BYTES:]
    expected_tag = hmac.new(key_bytes, body, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("authenticated checkpoint tag mismatch")

    payload = blob[_AUTH_HEADER_BYTES : _AUTH_HEADER_BYTES + payload_length]
    if payload_length < len(payload_magic) or payload[: len(payload_magic)] != payload_magic:
        raise ValueError("payload magic does not match the envelope scheme")
    if expect is not None and scheme != expect:
        raise ValueError(f"envelope scheme {scheme!r} does not match expected {expect!r}")
    return scheme, bytes(payload)

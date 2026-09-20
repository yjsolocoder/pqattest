"""Optional authenticated wrapper for the existing plaintext signer checkpoints.

The three signer checkpoints (``OneTimeSigner.checkpoint`` for Lamport,
``WOTSOneTimeSigner.checkpoint`` for W-OTS and ``MerkleSigner.checkpoint`` for
Merkle-aggregated W-OTS) are serialised in the clear and protected only by a
plain SHA-256 checksum, which detects accidental corruption but not a
deliberate rewrite. :func:`auth_wrap` places any of those checkpoints inside a
versioned v1 envelope authenticated with ``HMAC-SHA-256`` under a caller
supplied key; :func:`auth_unwrap` verifies the tag in constant time and only
then hands the original checkpoint bytes back.

The envelope authenticates but does not encrypt: the wrapped checkpoint still
contains the private key material in the clear. It also does not establish
freshness, so copying, replaying or rolling back an old legitimately sealed
checkpoint is not detected — callers remain responsible for secure storage
and for atomically advancing their persisted state.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

__all__ = ["auth_wrap", "auth_unwrap"]

_AUTH_MAGIC = b"PQAAUTH\0"
_AUTH_VERSION = 1
_AUTH_HEADER_BYTES = 8 + 1 + 1 + 4
_TAG_BYTES = 32

# Scheme name, v1 identifier, and the magic of the checkpoint payload it seals.
# The payload magics must stay byte-identical to the ``_CHECKPOINT_MAGIC``
# constants of the three existing checkpoint codecs.
_SCHEMES = (
    ("lamport", 1, b"PQALCP\0\0"),
    ("wots", 2, b"PQAWCP\0\0"),
    ("merkle", 3, b"PQAMSCP\0"),
)
_SCHEME_BY_NAME = {name: (identifier, payload_magic) for name, identifier, payload_magic in _SCHEMES}
_SCHEME_BY_ID = {identifier: (name, payload_magic) for name, identifier, payload_magic in _SCHEMES}


def _as_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{label} must be bytes or bytearray")
    return bytes(value)


def _nonempty_key(key: Any) -> bytes:
    material = _as_bytes(key, "key")
    if not material:
        raise ValueError("key must not be empty")
    return material


def auth_wrap(checkpoint: Any, *, scheme: Any, key: Any) -> bytes:
    """Seal an existing Lamport, W-OTS or Merkle checkpoint in an authenticated v1 envelope.

    ``checkpoint`` must be the ``bytes``/``bytearray`` output of one of the
    existing ``checkpoint()`` methods and ``key`` must be non-empty
    ``bytes``/``bytearray``; wrong types raise ``TypeError`` and an empty key
    raises ``ValueError``. ``scheme`` is keyword-only and must be one of the
    strings ``"lamport"``, ``"wots"`` or ``"merkle"`` (a non-string raises
    ``TypeError``, an unknown name ``ValueError``); the checkpoint's own
    8-byte magic must match that scheme, otherwise ``ValueError``.

    The deterministic v1 layout is: the 8-byte magic ``b"PQAAUTH\\0"``; the
    version byte (1); one scheme identifier byte (1 for lamport, 2 for wots,
    3 for merkle); the payload length as 4 big-endian bytes; the original
    checkpoint bytes verbatim; and finally the 32-byte
    ``HMAC-SHA-256(key, all preceding bytes)`` tag.

    The envelope authenticates tampering only to holders of ``key`` — it does
    not encrypt the payload and gives no protection against copying, replay
    or rollback of an old sealed checkpoint.
    """
    payload = _as_bytes(checkpoint, "checkpoint")
    key_material = _nonempty_key(key)
    if not isinstance(scheme, str):
        raise TypeError("scheme must be one of 'lamport', 'wots' or 'merkle'")
    entry = _SCHEME_BY_NAME.get(scheme)
    if entry is None:
        raise ValueError(f"unknown scheme: {scheme!r}; expected 'lamport', 'wots' or 'merkle'")
    identifier, payload_magic = entry
    if not payload.startswith(payload_magic):
        raise ValueError(f"checkpoint magic does not match scheme {scheme!r}")
    body = (
        _AUTH_MAGIC
        + bytes((_AUTH_VERSION, identifier))
        + len(payload).to_bytes(4, "big")
        + payload
    )
    return body + hmac.new(key_material, body, hashlib.sha256).digest()


def auth_unwrap(data: Any, *, key: Any, expect: Any = None) -> tuple[str, bytes]:
    """Verify an authenticated checkpoint envelope and return the original payload.

    ``data`` must be ``bytes``/``bytearray`` and ``key`` must be non-empty
    ``bytes``/``bytearray``; wrong types raise ``TypeError`` and an empty key
    raises ``ValueError``. On success the return value is
    ``(scheme, checkpoint)`` where ``scheme`` is ``"lamport"``, ``"wots"`` or
    ``"merkle"`` and ``checkpoint`` is the exact bytes passed to
    :func:`auth_wrap`, ready for the matching ``from_checkpoint``. If
    ``expect`` is given (keyword-only) it must be a scheme name string (a
    non-string raises ``TypeError``) and equal to the envelope's scheme,
    otherwise ``ValueError``.

    A bad envelope magic, an unknown version or scheme identifier, a payload
    length that does not match the content, truncation, trailing data, a
    payload magic that does not match the declared scheme, an ``expect``
    mismatch or an HMAC tag mismatch — including using the wrong key — raises
    ``ValueError`` and no payload is returned. The tag is compared with
    :func:`hmac.compare_digest`, and the payload magic is only inspected after
    the tag verifies.
    """
    blob = _as_bytes(data, "data")
    key_material = _nonempty_key(key)
    if expect is not None and not isinstance(expect, str):
        raise TypeError("expect must be a scheme name string")
    if len(blob) < _AUTH_HEADER_BYTES + _TAG_BYTES:
        raise ValueError("authenticated checkpoint is truncated")
    if blob[:8] != _AUTH_MAGIC:
        raise ValueError("bad authenticated checkpoint magic")
    if blob[8] != _AUTH_VERSION:
        raise ValueError(f"unsupported authenticated checkpoint version: {blob[8]}")
    identifier = blob[9]
    entry = _SCHEME_BY_ID.get(identifier)
    if entry is None:
        raise ValueError(f"unknown scheme identifier: {identifier}")
    name, payload_magic = entry
    payload_length = int.from_bytes(blob[10:14], "big")
    body_end = _AUTH_HEADER_BYTES + payload_length
    if len(blob) < body_end + _TAG_BYTES:
        raise ValueError("authenticated checkpoint is truncated")
    if len(blob) > body_end + _TAG_BYTES:
        raise ValueError("trailing data after the authenticated checkpoint")
    body, tag = blob[:body_end], blob[body_end:]
    expected_tag = hmac.new(key_material, body, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("authenticated checkpoint tag mismatch")
    payload = body[_AUTH_HEADER_BYTES:]
    if not payload.startswith(payload_magic):
        raise ValueError(f"payload magic does not match scheme {name!r}")
    if expect is not None and expect != name:
        raise ValueError(f"scheme mismatch: expected {expect!r}, got {name!r}")
    return name, payload

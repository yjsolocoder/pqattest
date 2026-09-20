"""Keyed authenticated wrappers for the plaintext v1 signer checkpoints.

The Lamport (:meth:`pqattest.OneTimeSigner.checkpoint`), W-OTS
(:meth:`pqattest.WOTSOneTimeSigner.checkpoint`) and Merkle
(:meth:`pqattest.MerkleSigner.checkpoint`) checkpoints all serialise the
signing key in the clear and end in a plain SHA-256 checksum that only
detects accidental corruption. :func:`auth_wrap` adds an outer
HMAC-SHA-256 envelope so a party holding the shared key can tell whether a
checkpoint was altered by someone without the key; :func:`auth_unwrap`
verifies the tag and hands the original checkpoint bytes back.

:func:`auth_state_wrap`/:func:`auth_state_unwrap` are the version 2
envelope: the same magic, key and scheme rules, plus an 8-byte
``generation`` counter. A caller that persists the highest accepted
generation in trustworthy storage can pass ``min_generation`` on unseal to
refuse a checkpoint older than the floor, turning rollback into a detectable
error. The floor itself is only as good as the storage that holds it.

The envelopes authenticate but do **not** encrypt (the payload stays
readable). They remain stateless on their own: v1 gives no replay or
rollback protection at all, and v2 cannot detect replay within one
generation or a rollback that rewinds the external floor together with the
checkpoint — those guards remain the caller's responsibility (atomic
storage, a trustworthy monotonic counter, etc.).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

__all__ = [
    "auth_wrap",
    "auth_unwrap",
    "auth_state_wrap",
    "auth_state_unwrap",
]

_AUTH_MAGIC = b"PQAAUTH\0"
_AUTH_VERSION = 1
_STATE_VERSION = 2
_AUTH_HEADER_BYTES = 8 + 1 + 1 + 4
_STATE_HEADER_BYTES = 8 + 1 + 1 + 8 + 4
_GENERATION_BYTES = 8
_UINT64_MAX = 2**64 - 1
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


def _validate_generation(generation: Any) -> int:
    if isinstance(generation, bool) or not isinstance(generation, int):
        raise TypeError("generation must be a non-boolean integer")
    if not 0 <= generation <= _UINT64_MAX:
        raise ValueError("generation must be between 0 and 2**64 - 1")
    return generation


def auth_state_wrap(checkpoint: Any, *, scheme: Any, key: Any, generation: Any) -> bytes:
    """Wrap a plaintext v1 signer checkpoint in a version 2 state envelope.

    Behaves like :func:`auth_wrap` — same ``checkpoint``/``key``/``scheme``
    constraints, same checkpoint-magic check, same deterministic,
    authenticated-but-unencrypted properties — but additionally binds a
    keyword-only ``generation`` into the header. ``generation`` must be a
    non-boolean integer in ``0..2**64 - 1``; a boolean, a non-``int`` or an
    out-of-range value raises ``TypeError``/``ValueError`` respectively.
    Other parameter errors are identical to :func:`auth_wrap`.

    The v2 envelope layout is: the 8-byte magic ``b"PQAAUTH\\0"``; one byte
    each for the version (2) and the scheme identifier (lamport=1, wots=2,
    merkle=3); the generation as 8 big-endian bytes; the payload length as
    4 big-endian bytes; the original checkpoint payload unchanged; and
    finally the 32-byte ``HMAC-SHA-256(key, all preceding bytes)`` tag.
    Encoding is deterministic: the same checkpoint, scheme, key and
    generation always produce the same bytes. The payload is not encrypted.
    """
    payload = _coerce_bytes(checkpoint, "checkpoint")
    key_bytes = _validate_key(key)
    generation_value = _validate_generation(generation)
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
        + bytes((_STATE_VERSION, identifier))
        + generation_value.to_bytes(_GENERATION_BYTES, "big")
        + len(payload).to_bytes(4, "big")
        + payload
    )
    return body + hmac.new(key_bytes, body, hashlib.sha256).digest()


def auth_state_unwrap(
    data: Any,
    *,
    key: Any,
    expect: Any = None,
    min_generation: Any = None,
) -> tuple[str, int, bytes]:
    """Verify a version 2 state envelope and return ``(scheme, generation, payload)``.

    ``data`` must be ``bytes`` or ``bytearray`` produced by
    :func:`auth_state_wrap` and ``key`` a non-empty ``bytes``/``bytearray``
    shared secret; the keyword-only ``expect`` may name a scheme the
    envelope identifier must match. ``min_generation`` is ``None`` (the
    default: no floor) or a non-boolean ``uint64``; when given, an envelope
    whose generation is below the floor is rejected. Wrong parameter types
    raise ``TypeError``; an empty key, a bad/unknown ``min_generation`` or
    ``expect``, a bad envelope magic, any version other than 2 (a v1 blob
    is refused rather than parsed), an unknown scheme identifier, a length
    field that does not match the content, truncation, trailing data, a
    payload magic that does not match its scheme identifier, an identifier
    different from ``expect``, a bad HMAC tag or a generation below
    ``min_generation`` raises ``ValueError`` and nothing is returned.

    The tag is checked with :func:`hmac.compare_digest` before any payload
    byte is trusted; only afterwards are the payload magic, the scheme and
    ``expect`` checked, and the generation floor applied last. The returned
    payload is the exact checkpoint passed to :func:`auth_state_wrap` (as
    ``bytes``), ready for the matching ``from_checkpoint``. The envelope
    authenticates but does not encrypt: a same-generation blob can still be
    replayed, and an attacker who can also roll the externally stored floor
    backwards defeats the check — the floor must live in trustworthy
    storage the caller controls.
    """
    blob = _coerce_bytes(data, "data")
    key_bytes = _validate_key(key)
    if expect is not None:
        if not isinstance(expect, str):
            raise TypeError("expect must be a scheme name string or None")
        if expect not in _SCHEMES:
            raise ValueError(f"unknown expected scheme: {expect!r}")
    if min_generation is not None:
        # Same non-boolean uint64 rule as wrap, via the shared validator.
        floor = _validate_generation(min_generation)
    else:
        floor = None

    minimum_length = _STATE_HEADER_BYTES + _AUTH_TAG_BYTES
    if len(blob) < minimum_length:
        raise ValueError("authenticated state checkpoint is truncated")
    if blob[:8] != _AUTH_MAGIC:
        raise ValueError("bad authenticated checkpoint magic")
    if blob[8] != _STATE_VERSION:
        raise ValueError(f"unsupported authenticated checkpoint version: {blob[8]}")
    identifier = blob[9]
    try:
        scheme, payload_magic = _SCHEME_IDS[identifier]
    except KeyError:
        raise ValueError(f"unknown scheme identifier: {identifier}") from None
    generation = int.from_bytes(blob[10:18], "big")
    payload_length = int.from_bytes(blob[18:22], "big")
    expected_length = _STATE_HEADER_BYTES + payload_length + _AUTH_TAG_BYTES
    if len(blob) < expected_length:
        raise ValueError("authenticated state checkpoint is truncated")
    if len(blob) > expected_length:
        raise ValueError("trailing data after the authenticated state checkpoint")

    body, tag = blob[:-_AUTH_TAG_BYTES], blob[-_AUTH_TAG_BYTES:]
    expected_tag = hmac.new(key_bytes, body, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("authenticated state checkpoint tag mismatch")

    payload = blob[_STATE_HEADER_BYTES : _STATE_HEADER_BYTES + payload_length]
    if payload_length < len(payload_magic) or payload[: len(payload_magic)] != payload_magic:
        raise ValueError("payload magic does not match the envelope scheme")
    if expect is not None and scheme != expect:
        raise ValueError(f"envelope scheme {scheme!r} does not match expected {expect!r}")
    if floor is not None and generation < floor:
        raise ValueError(
            f"checkpoint generation {generation} is below the minimum {floor}"
        )
    return scheme, generation, bytes(payload)

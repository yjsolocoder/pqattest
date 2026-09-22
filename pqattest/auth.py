"""Keyed authenticated wrappers for the plaintext v1 signer checkpoints.

The Lamport (:meth:`pqattest.OneTimeSigner.checkpoint`), W-OTS
(:meth:`pqattest.WOTSOneTimeSigner.checkpoint`) and Merkle
(:meth:`pqattest.MerkleSigner.checkpoint`) checkpoints all serialise the
signing key in the clear and end in a plain SHA-256 checksum that only
detects accidental corruption. :func:`auth_wrap` adds an outer
HMAC-SHA-256 envelope so a party holding the shared key can tell whether a
checkpoint was altered by someone without the key; :func:`auth_unwrap`
verifies the tag and hands the original checkpoint bytes back.

:func:`auth_state_wrap` / :func:`auth_state_unwrap` are the version 2
envelope: the same magic, authentication and v1 parameter rules, plus an
8-byte unsigned *generation*. :func:`auth_state_unwrap` can refuse a blob
whose generation is below a caller-supplied floor, which lets a trusted
monotonic counter detect rollback across unwraps (the floor itself is not
stored in the envelope and must live in trusted storage).

Both envelopes authenticate but do **not** encrypt (the payload stays
readable), and a same-generation replay, or a rollback that also rewinds
the trusted floor, remains undetectable.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Callable

__all__ = [
    "auth_wrap",
    "auth_unwrap",
    "auth_state_wrap",
    "auth_state_unwrap",
]

_AUTH_MAGIC = b"PQAAUTH\0"
_AUTH_TAG_BYTES = 32  # HMAC-SHA-256 output length
_UINT64_MAX = 2**64 - 1

# v1 envelope: magic, version, scheme identifier, 4-byte payload length.
_AUTH_V1_VERSION = 1
_AUTH_V1_HEADER_BYTES = 8 + 1 + 1 + 4

# v2 envelope: magic, version, scheme identifier, 8-byte generation, 4-byte
# payload length.
_AUTH_V2_VERSION = 2
_AUTH_V2_HEADER_BYTES = 8 + 1 + 1 + 8 + 4

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


def _validate_generation(value: Any, label: str) -> int:
    """Coerce a keyword argument that must be a non-boolean uint64."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be a non-boolean integer between 0 and 2**64-1")
    if not 0 <= value <= _UINT64_MAX:
        raise ValueError(f"{label} must be between 0 and 2**64-1")
    return value


def _validate_expect(expect: Any) -> None:
    if expect is None:
        return
    if not isinstance(expect, str):
        raise TypeError("expect must be a scheme name string or None")
    if expect not in _SCHEMES:
        raise ValueError(f"unknown expected scheme: {expect!r}")


def _check_payload_magic(payload: bytes, payload_magic: bytes, scheme: str) -> None:
    if len(payload) < len(payload_magic) or payload[: len(payload_magic)] != payload_magic:
        raise ValueError("payload magic does not match the envelope scheme")


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
    _check_payload_magic(payload, payload_magic, scheme)
    body = (
        _AUTH_MAGIC
        + bytes((_AUTH_V1_VERSION, identifier))
        + len(payload).to_bytes(4, "big")
        + payload
    )
    return body + hmac.new(key_bytes, body, hashlib.sha256).digest()


def auth_unwrap(data: Any, *, key: Any, expect: Any = None) -> tuple[str, bytes]:
    """Verify a v1 authenticated envelope and return ``(scheme, checkpoint)``.

    ``data`` must be ``bytes`` or ``bytearray`` produced by
    :func:`auth_wrap` and ``key`` a non-empty ``bytes``/``bytearray`` shared
    secret; the keyword-only ``expect`` may name a scheme
    (``"lamport"``/``"wots"``/``"merkle"``) that the envelope identifier
    must then match. Wrong parameter types raise ``TypeError``; an empty
    key, an unknown ``expect`` scheme, a bad envelope magic, version or
    scheme identifier, a length field that does not match the content,
    truncation, trailing data, a payload magic that does not match its
    scheme identifier, an identifier different from ``expect`` or a bad
    HMAC tag raises ``ValueError`` and nothing is returned. A v2 envelope
    (from :func:`auth_state_wrap`) is rejected as an unsupported version.

    The tag is checked with :func:`hmac.compare_digest` before any payload
    byte is trusted; only afterwards is the payload magic checked against
    the scheme identifier. The returned checkpoint is the exact payload
    passed to :func:`auth_wrap` (as ``bytes``), ready for the matching
    ``from_checkpoint``. The envelope authenticates but does not encrypt
    and does not prevent copying, replay or rollback of an older valid blob.
    """
    blob = _coerce_bytes(data, "data")
    key_bytes = _validate_key(key)
    _validate_expect(expect)

    minimum_length = _AUTH_V1_HEADER_BYTES + _AUTH_TAG_BYTES
    if len(blob) < minimum_length:
        raise ValueError("authenticated checkpoint is truncated")
    if blob[:8] != _AUTH_MAGIC:
        raise ValueError("bad authenticated checkpoint magic")
    if blob[8] != _AUTH_V1_VERSION:
        raise ValueError(f"unsupported authenticated checkpoint version: {blob[8]}")
    identifier = blob[9]
    try:
        scheme, payload_magic = _SCHEME_IDS[identifier]
    except KeyError:
        raise ValueError(f"unknown scheme identifier: {identifier}") from None
    payload_length = int.from_bytes(blob[10:14], "big")
    expected_length = _AUTH_V1_HEADER_BYTES + payload_length + _AUTH_TAG_BYTES
    if len(blob) < expected_length:
        raise ValueError("authenticated checkpoint is truncated")
    if len(blob) > expected_length:
        raise ValueError("trailing data after the authenticated checkpoint")

    body, tag = blob[:-_AUTH_TAG_BYTES], blob[-_AUTH_TAG_BYTES:]
    expected_tag = hmac.new(key_bytes, body, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("authenticated checkpoint tag mismatch")

    payload = blob[_AUTH_V1_HEADER_BYTES : _AUTH_V1_HEADER_BYTES + payload_length]
    _check_payload_magic(payload, payload_magic, scheme)
    if expect is not None and scheme != expect:
        raise ValueError(f"envelope scheme {scheme!r} does not match expected {expect!r}")
    return scheme, bytes(payload)


def auth_state_wrap(
    checkpoint: Any, *, scheme: Any, key: Any, generation: Any
) -> bytes:
    """Wrap a checkpoint in the version 2 authenticated, generation-tagged envelope.

    Behaves exactly like :func:`auth_wrap` — same ``checkpoint``, ``scheme``
    and ``key`` constraints and the same checkpoint-magic check — but
    additionally binds a keyword-only ``generation``: a non-boolean integer
    from ``0`` to ``2**64 - 1`` (a wrong type raises ``TypeError``, an
    out-of-range value ``ValueError``).

    The v2 envelope layout is: the 8-byte magic ``b"PQAAUTH\\0"``; one byte
    each for the version (2) and the scheme identifier (lamport=1, wots=2,
    merkle=3); the generation as 8 big-endian bytes; the payload length as
    4 big-endian bytes; the original checkpoint payload unchanged; and
    finally the 32-byte ``HMAC-SHA-256(key, all preceding bytes)`` tag.
    Encoding is deterministic: identical inputs produce identical bytes.
    The payload is not encrypted, and the generation only helps a caller
    that tracks a trusted high-water mark — it proves nothing on its own.
    """
    payload = _coerce_bytes(checkpoint, "checkpoint")
    key_bytes = _validate_key(key)
    generation_value = _validate_generation(generation, "generation")
    if not isinstance(scheme, str):
        raise TypeError("scheme must be a string")
    try:
        identifier, payload_magic = _SCHEMES[scheme]
    except KeyError:
        raise ValueError(f"unknown scheme: {scheme!r}") from None
    _check_payload_magic(payload, payload_magic, scheme)
    body = (
        _AUTH_MAGIC
        + bytes((_AUTH_V2_VERSION, identifier))
        + generation_value.to_bytes(8, "big")
        + len(payload).to_bytes(4, "big")
        + payload
    )
    return body + hmac.new(key_bytes, body, hashlib.sha256).digest()


def _auth_state_verify(data: Any, key_bytes: bytes) -> bytes:
    """Verify the v2 HMAC tag of ``data`` and return the authenticated body.

    Only the tag is checked here — with :func:`hmac.compare_digest` — so no
    field of the returned body has been parsed or trusted yet; callers must
    run :func:`_auth_state_parse` before using any of it.
    """
    blob = _coerce_bytes(data, "data")
    if len(blob) < _AUTH_TAG_BYTES:
        raise ValueError("authenticated checkpoint is truncated")
    body, tag = blob[:-_AUTH_TAG_BYTES], blob[-_AUTH_TAG_BYTES:]
    expected_tag = hmac.new(key_bytes, body, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("authenticated checkpoint tag mismatch")
    return body


def _auth_state_parse(
    body: bytes, *, expect: Any, min_generation: Any
) -> tuple[str, int, bytes]:
    """Parse an authenticated v2 body into ``(scheme, generation, payload)``.

    ``body`` must already have passed :func:`_auth_state_verify`; the scheme
    (including ``expect``), payload magic and generation floor are checked
    here, after authentication.
    """
    if len(body) < _AUTH_V2_HEADER_BYTES:
        raise ValueError("authenticated checkpoint is truncated")
    if body[:8] != _AUTH_MAGIC:
        raise ValueError("bad authenticated checkpoint magic")
    if body[8] != _AUTH_V2_VERSION:
        raise ValueError(f"unsupported authenticated checkpoint version: {body[8]}")
    identifier = body[9]
    try:
        scheme, payload_magic = _SCHEME_IDS[identifier]
    except KeyError:
        raise ValueError(f"unknown scheme identifier: {identifier}") from None
    generation = int.from_bytes(body[10:18], "big")
    payload_length = int.from_bytes(body[18:22], "big")
    expected_length = _AUTH_V2_HEADER_BYTES + payload_length
    if len(body) < expected_length:
        raise ValueError("authenticated checkpoint is truncated")
    if len(body) > expected_length:
        raise ValueError("trailing data after the authenticated checkpoint")

    payload = body[_AUTH_V2_HEADER_BYTES:expected_length]
    _check_payload_magic(payload, payload_magic, scheme)
    if expect is not None and scheme != expect:
        raise ValueError(f"envelope scheme {scheme!r} does not match expected {expect!r}")
    if min_generation is not None and generation < min_generation:
        raise ValueError(
            f"checkpoint generation {generation} is below the minimum {min_generation}"
        )
    return scheme, generation, bytes(payload)


def auth_state_unwrap(
    data: Any, *, key: Any, expect: Any = None, min_generation: Any = None
) -> tuple[str, int, bytes]:
    """Verify a v2 envelope and return ``(scheme, generation, checkpoint)``.

    ``data`` must be ``bytes`` or ``bytearray`` produced by
    :func:`auth_state_wrap` and ``key`` a non-empty ``bytes``/``bytearray``
    shared secret. ``expect`` may name a scheme the envelope must match.
    ``min_generation`` is ``None`` (the default: no floor) or a non-boolean
    integer from ``0`` to ``2**64 - 1``; when given, an envelope whose
    generation is below the floor is rejected. The floor is *not* carried in
    the envelope — persist it in trusted storage, or an attacker who can
    roll the checkpoint back and rewind the floor defeats the check.

    Wrong parameter types raise ``TypeError`` (a non-bytes ``data``/``key``,
    a non-string ``expect``, a non-integer or boolean ``min_generation``);
    an empty key, an unknown ``expect``/floor value out of the uint64 range,
    a bad envelope magic, a version other than 2 (including a v1 envelope),
    an unknown scheme identifier, a mismatched length field, truncation,
    trailing data, a bad HMAC tag, a payload magic that does not match its
    scheme identifier, an identifier different from ``expect`` or a
    generation below ``min_generation`` raises ``ValueError``.

    Once at least the 32 tag bytes are present, the last 32 bytes are taken
    as the tag and everything before them as the authenticated body; the tag
    is verified with :func:`hmac.compare_digest` before any field is
    trusted. Only afterwards are the v2 fields and the payload parsed, the
    payload magic and the scheme (including ``expect``) checked, and the
    generation floor applied last. The returned checkpoint is the exact
    payload passed to :func:`auth_state_wrap` (as ``bytes``), ready for the
    matching ``from_checkpoint``. The envelope authenticates but does not
    encrypt; a same-generation replay or a rollback accompanied by a floor
    rewind remains undetectable.
    """
    blob = _coerce_bytes(data, "data")
    key_bytes = _validate_key(key)
    _validate_expect(expect)
    if min_generation is not None:
        _validate_generation(min_generation, "min_generation")

    # Authenticate first: no field (including the generation) is trusted
    # until the tag over the whole body checks out.
    body = _auth_state_verify(blob, key_bytes)
    return _auth_state_parse(body, expect=expect, min_generation=min_generation)


def _validate_claim(claim: Any) -> Callable[..., Any]:
    if not callable(claim):
        raise TypeError("claim must be callable")
    return claim


def _restore_auth_state(scheme: str, data: Any, *, key: Any, min_generation: Any,
                        claim: Any, restore: Callable[[bytes], Any],
                        floor_label: str = "min_generation") -> tuple[Any, int]:
    """Validate, authenticate and restore one v2 envelope, then claim it once.

    Shared implementation behind the one-time signers' ``from_auth_state``
    and the top-level ``restore_merkle_claimed``. Argument types are checked
    first, the v2 HMAC tag is verified with :func:`hmac.compare_digest`, the
    envelope is fixed to ``scheme`` and the generation floor applied, and
    only then is the untouched payload handed to ``restore``; the ``claim``
    callback is invoked exactly once, after the restore has fully succeeded,
    and its return value is accepted only when it ``is True``. Any exception
    raised by ``claim`` propagates untouched. ``floor_label`` names the floor
    in validation error messages.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    key_bytes = _validate_key(key)
    if min_generation is not None:
        _validate_generation(min_generation, floor_label)
    claim_callable = _validate_claim(claim)
    _, generation_value, checkpoint = auth_state_unwrap(
        data,
        key=key_bytes,
        expect=scheme,
        min_generation=min_generation,
    )
    signer = restore(checkpoint)
    result = claim_callable((scheme, generation_value))
    if result is not True:
        raise ValueError("claim callback did not return True")
    return signer, generation_value


def _restore_auth_state_pair(data_a: Any, data_b: Any, *, key: Any, floor: Any,
                             claim: Any,
                             restore_a: Callable[[bytes], Any],
                             restore_b: Callable[[bytes], Any]
                             ) -> tuple[tuple[Any, Any], int]:
    """Authenticate and restore two same-generation envelopes, then claim both.

    Both blobs must verify under ``key``, the first must be a ``"lamport"``
    envelope and the second a ``"wots"`` envelope, their generations must be
    equal and — when ``floor`` is given — at least that high. Both v2 HMAC
    tags are verified with :func:`hmac.compare_digest` before any field of
    either envelope is parsed, and both checkpoints are restored before the
    single paired claim, so a caller can never successfully claim only one
    side. ``claim`` is invoked exactly once with ``(("lamport", g), ("wots",
    g))`` after every restore has succeeded, and its return value is accepted
    only when it ``is True``; any exception it raises propagates untouched.
    """
    if not isinstance(data_a, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    if not isinstance(data_b, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    key_bytes = _validate_key(key)
    if floor is not None:
        _validate_generation(floor, "floor")
    claim_callable = _validate_claim(claim)
    # Authenticate both sides first: no field of either envelope is parsed,
    # no checkpoint restored and no claim made until both tags check out.
    body_a = _auth_state_verify(data_a, key_bytes)
    body_b = _auth_state_verify(data_b, key_bytes)
    _, generation_a, checkpoint_a = _auth_state_parse(
        body_a, expect="lamport", min_generation=floor
    )
    _, generation_b, checkpoint_b = _auth_state_parse(
        body_b, expect="wots", min_generation=floor
    )
    if generation_a != generation_b:
        raise ValueError(
            f"lamport generation {generation_a} does not match wots generation {generation_b}"
        )
    signer_a = restore_a(checkpoint_a)
    signer_b = restore_b(checkpoint_b)
    result = claim_callable((("lamport", generation_a), ("wots", generation_b)))
    if result is not True:
        raise ValueError("claim callback did not return True")
    return (signer_a, signer_b), generation_a

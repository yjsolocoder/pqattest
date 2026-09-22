"""Winternitz one-time signature (W-OTS) for pqattest.

Like the Lamport construction this is a **one-time** signature: a key pair
must sign at most one message. Each signing key is a set of hash chains; a
signature for a base-``B`` digit ``d`` reveals the value at chain step ``d``
and the public key holds the step ``B - 1`` endpoint. Only the standard
library is used. Keys and signatures have a deterministic, versioned v1
binary codec: :meth:`WOTSPrivateKey.to_bytes` /
:meth:`WOTSPrivateKey.from_bytes`, :meth:`WOTSPublicKey.to_bytes` /
:meth:`WOTSPublicKey.from_bytes`, and the stateless
:func:`wots_signature_to_bytes` / :func:`wots_signature_from_bytes`. The
private-key encoding contains the secret in the clear, so callers must store
it securely. :class:`WOTSOneTimeSigner` state can be persisted with a
versioned binary checkpoint (``checkpoint`` / ``from_checkpoint``); the blob
holds the private key in the clear and is integrity-protected only by a
SHA-256 checksum, so callers must store it securely. A keyed v2
``auth_state_wrap`` envelope can be restored in one authenticated step with
:meth:`WOTSOneTimeSigner.from_auth_state`, which also drives an external
monotonic claim; :func:`pqattest.restore_ots_pair` restores a same-generation
Lamport/W-OTS pair with a single paired claim.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

from ._errors import KeyExhaustedError
from .auth import (
    _run_claim,
    _validate_claim,
    _validate_generation,
    _validate_key,
    auth_state_unwrap,
    auth_state_wrap,
)

__all__ = [
    "ELEMENT_BYTES",
    "WOTSOneTimeSigner",
    "WOTSPrivateKey",
    "WOTSPublicKey",
    "wots_keygen",
    "wots_sign",
    "wots_signature_from_bytes",
    "wots_signature_to_bytes",
    "wots_verify",
]

ELEMENT_BYTES = 32
_DOMAIN = b"pqattest/wots/v1"
_ALLOWED_W = (4, 8)

_CHECKPOINT_MAGIC = b"PQAWCP\0\0"
_CHECKPOINT_VERSION = 1
_CHECKPOINT_HEADER_BYTES = 8 + 1 + 1 + 1 + 2
_CHECKPOINT_CHECKSUM_BYTES = 32

_PRIVATE_KEY_MAGIC = b"PQAWPRV\0"
_PUBLIC_KEY_MAGIC = b"PQAWPUB\0"
_SIGNATURE_MAGIC = b"PQAWSIG\0"
_CODEC_VERSION = 1
_CODEC_HEADER_BYTES = 8 + 1 + 1 + 2


def _as_bytes(message: Any) -> bytes:
    if isinstance(message, bytes):
        return message
    if isinstance(message, bytearray):
        return bytes(message)
    if isinstance(message, str):
        return message.encode("utf-8")
    raise TypeError("message must be bytes, bytearray or str")


def _validate_w(w: Any) -> int:
    if isinstance(w, bool) or not isinstance(w, int) or w not in _ALLOWED_W:
        raise ValueError("w must be 4 or 8")
    return w


def _params(w: int) -> tuple[int, int, int]:
    """Return ``(B, l1, l2)``: base, message digit count, checksum digit count."""
    b = 1 << w
    l1 = 256 // w
    l2 = 1
    limit = l1 * (b - 1)
    while b ** l2 <= limit:
        l2 += 1
    return b, l1, l2


def _validate_elements(w: int, elements: Any) -> None:
    if not isinstance(elements, tuple):
        raise TypeError("elements must be a tuple of 32-byte values")
    _, l1, l2 = _params(w)
    if len(elements) != l1 + l2:
        raise ValueError(f"elements must contain exactly {l1 + l2} values for w={w}")
    for element in elements:
        if not isinstance(element, bytes) or len(element) != ELEMENT_BYTES:
            raise ValueError(f"every element must be exactly {ELEMENT_BYTES} bytes")


def _chain_count(w: int) -> int:
    _, l1, l2 = _params(w)
    return l1 + l2


def _encode_v1(magic: bytes, w: int, elements: tuple[bytes, ...]) -> bytes:
    """Shared v1 layout: magic, version, ``w``, element count, elements."""
    return (
        magic
        + bytes((_CODEC_VERSION, w))
        + len(elements).to_bytes(2, "big")
        + b"".join(elements)
    )


def _decode_v1(data: Any, magic: bytes, name: str) -> tuple[int, tuple[bytes, ...]]:
    """Parse a v1 blob into ``(w, elements)``; ``name`` labels error messages."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{name} data must be bytes or bytearray")
    data = bytes(data)
    if len(data) < _CODEC_HEADER_BYTES:
        raise ValueError(f"{name} encoding is truncated")
    if data[:8] != magic:
        raise ValueError(f"bad {name} magic")
    if data[8] != _CODEC_VERSION:
        raise ValueError(f"unsupported {name} version: {data[8]}")
    w = _validate_w(data[9])
    element_count = int.from_bytes(data[10:12], "big")
    chains = _chain_count(w)
    if element_count != chains:
        raise ValueError("element count does not match the chain count for w")
    expected = _CODEC_HEADER_BYTES + element_count * ELEMENT_BYTES
    if len(data) < expected:
        raise ValueError(f"{name} encoding is truncated")
    if len(data) > expected:
        raise ValueError(f"trailing data after the {name} encoding")
    elements = tuple(
        data[_CODEC_HEADER_BYTES + i * ELEMENT_BYTES : _CODEC_HEADER_BYTES + (i + 1) * ELEMENT_BYTES]
        for i in range(element_count)
    )
    return w, elements


def _key_to_bytes(key: Any, key_type: type, magic: bytes, name: str) -> bytes:
    if not isinstance(key, key_type):
        raise TypeError(f"to_bytes must be called on a {key_type.__name__}")
    try:
        w = _validate_w(key.w)
        _validate_elements(w, key.elements)
    except TypeError as exc:
        raise ValueError(f"corrupted {name}: {exc}") from exc
    return _encode_v1(magic, w, key.elements)


@dataclass(frozen=True)
class WOTSPrivateKey:
    """Frozen W-OTS private key.

    ``elements`` holds the random step-0 start value of every chain: the
    ``l1`` message chains followed by the ``l2`` checksum chains.
    """

    w: int
    elements: tuple[bytes, ...]

    def __post_init__(self) -> None:
        w = _validate_w(self.w)
        _validate_elements(w, self.elements)

    @property
    def length(self) -> int:
        """Number of chains (and signature elements): ``l1 + l2``."""
        return len(self.elements)

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQAWPRV\\0"``; one byte each for
        the version (1) and ``w``; the element count as 2 big-endian bytes
        (67 for ``w=4``, 34 for ``w=8``); then every private element in chain
        order, 32 bytes each. Encoding is deterministic: the same key always
        produces the same bytes. Fields corrupted by bypassing the frozen
        constructor raise ``ValueError`` instead of producing a malformed
        encoding. The blob contains the private key in the clear — store it
        as a secret.
        """
        return _key_to_bytes(self, WOTSPrivateKey, _PRIVATE_KEY_MAGIC, "private key")

    @classmethod
    def from_bytes(cls, data: Any) -> "WOTSPrivateKey":
        """Parse ``to_bytes()`` output back into a :class:`WOTSPrivateKey`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, an invalid ``w``, an
        element count that does not match the chain count for ``w``,
        truncation or trailing data raises ``ValueError`` and no instance is
        returned. The restored key is equal by value to the original.
        """
        w, elements = _decode_v1(data, _PRIVATE_KEY_MAGIC, "private key")
        return cls(w=w, elements=elements)


@dataclass(frozen=True)
class WOTSPublicKey:
    """Frozen W-OTS public key: the step ``B - 1`` endpoint of every chain."""

    w: int
    elements: tuple[bytes, ...]

    def __post_init__(self) -> None:
        w = _validate_w(self.w)
        _validate_elements(w, self.elements)

    @property
    def length(self) -> int:
        """Number of chains (and signature elements): ``l1 + l2``."""
        return len(self.elements)

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQAWPUB\\0"``; one byte each for
        the version (1) and ``w``; the element count as 2 big-endian bytes
        (67 for ``w=4``, 34 for ``w=8``); then every public element in chain
        order, 32 bytes each. Encoding is deterministic: the same key always
        produces the same bytes. Fields corrupted by bypassing the frozen
        constructor raise ``ValueError`` instead of producing a malformed
        encoding.
        """
        return _key_to_bytes(self, WOTSPublicKey, _PUBLIC_KEY_MAGIC, "public key")

    @classmethod
    def from_bytes(cls, data: Any) -> "WOTSPublicKey":
        """Parse ``to_bytes()`` output back into a :class:`WOTSPublicKey`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, an invalid ``w``, an
        element count that does not match the chain count for ``w``,
        truncation or trailing data raises ``ValueError`` and no instance is
        returned. The restored key is equal by value to the original.
        """
        w, elements = _decode_v1(data, _PUBLIC_KEY_MAGIC, "public key")
        return cls(w=w, elements=elements)


def _chain_step(value: bytes) -> bytes:
    return hashlib.sha256(_DOMAIN + value).digest()


def _chain_walk(value: bytes, steps: int) -> bytes:
    for _ in range(steps):
        value = _chain_step(value)
    return value


def _message_digits(digest: bytes, w: int, b: int, l1: int) -> tuple[int, ...]:
    """Split a 256-bit digest into ``l1`` base-``B`` digits, big endian."""
    value = int.from_bytes(digest, "big")
    return tuple((value >> (256 - w * (i + 1))) & (b - 1) for i in range(l1))


def _checksum_digits(
    message_digits: Iterable[int], w: int, b: int, l2: int
) -> tuple[int, ...]:
    """``sum(B - 1 - d)`` as exactly ``l2`` base-``B`` digits, leading zeros kept."""
    checksum = sum(b - 1 - digit for digit in message_digits)
    return tuple((checksum >> (w * (l2 - 1 - i))) & (b - 1) for i in range(l2))


def _signing_digits(message: Any, w: int) -> tuple[int, ...]:
    b, l1, l2 = _params(w)
    digest = hashlib.sha256(_as_bytes(message)).digest()
    message_part = _message_digits(digest, w, b, l1)
    return message_part + _checksum_digits(message_part, w, b, l2)


class WOTSOneTimeSigner:
    """Thread-safe, single-use wrapper around a :class:`WOTSPrivateKey`.

    The first :meth:`sign` call returns the ordinary :func:`wots_sign`
    signature and marks the key as used; every later call raises
    :class:`~pqattest.KeyExhaustedError`. The guard is per instance and per
    process — copying the private key, calling the stateless :func:`wots_sign`
    directly or reusing the key in another process is the caller's
    responsibility. State can be persisted with :meth:`checkpoint` and
    restored in another process with :meth:`from_checkpoint`; the checkpoint
    contains the private key in the clear and is protected only by a SHA-256
    checksum against accidental corruption, so callers must store it
    securely. :meth:`from_auth_state` restores from a keyed v2
    :func:`auth_state_wrap` envelope instead, applying the generation floor
    and driving the caller's external monotonic claim in one call.
    """

    __slots__ = ("_lock", "_private_key", "_public_key", "_used")

    def __init__(self, private_key: WOTSPrivateKey) -> None:
        if not isinstance(private_key, WOTSPrivateKey):
            raise TypeError("private_key must be a WOTSPrivateKey")
        self._restore_state(private_key, self._public_key_from(private_key), False)

    @staticmethod
    def _public_key_from(private_key: WOTSPrivateKey) -> WOTSPublicKey:
        b = 1 << private_key.w
        return WOTSPublicKey(
            w=private_key.w,
            elements=tuple(
                _chain_walk(start, b - 1) for start in private_key.elements
            ),
        )

    def _restore_state(
        self,
        private_key: WOTSPrivateKey,
        public_key: WOTSPublicKey,
        used: bool,
    ) -> None:
        self._lock = threading.Lock()
        self._private_key = private_key
        self._public_key = public_key
        self._used = used

    @property
    def public_key(self) -> WOTSPublicKey:
        """Public key derived from the wrapped private key (read-only)."""
        return self._public_key

    @property
    def used(self) -> bool:
        """``True`` once a signature has been produced (read-only)."""
        return self._used

    def sign(self, message: Any) -> tuple[bytes, ...]:
        """Sign once.

        Behaves exactly like :func:`wots_sign` on the first successful call,
        accepting ``bytes``/``bytearray``/``str``; an unsupported message type
        raises the same ``TypeError`` that :func:`wots_sign` raises without
        consuming the key. Any later call raises
        :class:`~pqattest.KeyExhaustedError`. Concurrent calls are serialised
        on one lock so that at most one succeeds and every loser raises
        :class:`~pqattest.KeyExhaustedError`.
        """
        with self._lock:
            if self._used:
                raise KeyExhaustedError("this one-time signing key has already been used")
            signature = wots_sign(message, self._private_key)
            self._used = True
            return signature

    def _checkpoint_bytes(self) -> bytes:
        """Serialise the signer state; the caller holds the lock."""
        body = (
            _CHECKPOINT_MAGIC
            + bytes((_CHECKPOINT_VERSION, self._private_key.w, int(self._used)))
            + len(self._private_key.elements).to_bytes(2, "big")
            + b"".join(self._private_key.elements)
        )
        return body + hashlib.sha256(body).digest()

    def checkpoint(self) -> bytes:
        """Serialise the signer state (private key plus ``used``) to ``bytes``.

        The v1 layout is: the 8-byte magic ``b"PQAWCP\\0\\0"``; one byte each
        for the version (1), ``w`` and ``used`` (0 or 1); the element count as
        2 big-endian bytes (67 for ``w=4``, 34 for ``w=8``); every private key
        element in chain order (32 bytes each); and finally the SHA-256 of all
        preceding content. Encoding is deterministic: the same state always
        produces the same bytes.

        The checkpoint shares the signing lock, so a concurrent snapshot
        reflects the state either immediately before or immediately after an
        in-flight :meth:`sign`, never part-way through one. The blob contains
        the private key in the clear and the trailing hash only detects
        accidental corruption — store it as a secret.
        """
        with self._lock:
            return self._checkpoint_bytes()

    def sign_with_auth_state(
        self, message: Any, *, key: Any, generation: Any
    ) -> tuple[tuple[bytes, ...], bytes]:
        """Sign once and return the advanced state as a v2 auth envelope.

        Behaves like :meth:`sign` — same ``bytes``/``bytearray``/``str``
        message rules, same one-time signature and the same post-sign
        ``used=True`` state, all under the signing lock — but instead of the
        signature alone it returns ``(signature, envelope)``: the first half
        is the ordinary immutable W-OTS signature tuple that :meth:`sign`
        returns, and the second is the :func:`auth_state_wrap` v2 envelope
        (``bytes``) over the v1 :meth:`checkpoint` bytes of the used state
        with ``scheme="wots"`` and the given ``key`` and ``generation``. The
        wrapped checkpoint is byte-for-byte identical to the one
        :meth:`checkpoint` returns immediately after signing, so the envelope
        is byte-for-byte identical to signing and then wrapping an explicit
        checkpoint. Pairing the two halves in one call keeps the signature
        and the state it advanced to together, so a caller can never match a
        signature against a checkpoint taken at the wrong point under
        concurrency.

        Every argument is validated before the key is spent: ``key`` is
        keyword-only and must be a non-empty ``bytes``/``bytearray`` shared
        secret; ``generation`` is keyword-only and must be a non-boolean
        integer in ``0 .. 2**64 - 1``. A wrong message or key type raises
        ``TypeError``; an empty key or an out-of-range generation raises
        ``ValueError``; an already used instance raises
        :class:`~pqattest.KeyExhaustedError`. Every failure leaves ``used``
        untouched and returns no partial result. The whole call — signature,
        ``used`` flip, snapshot and wrapping — linearises with :meth:`sign`
        and :meth:`checkpoint` under the same lock, and no randomness is
        drawn. The envelope is plaintext and authenticated only; it provides
        neither encryption nor protection against replay or rollback on its
        own.
        """
        message = _as_bytes(message)
        key_bytes = _validate_key(key)
        generation_value = _validate_generation(generation, "generation")
        with self._lock:
            if self._used:
                raise KeyExhaustedError("this one-time signing key has already been used")
            signature = wots_sign(message, self._private_key)
            self._used = True
            checkpoint = self._checkpoint_bytes()
            envelope = auth_state_wrap(
                checkpoint,
                scheme="wots",
                key=key_bytes,
                generation=generation_value,
            )
            return signature, envelope

    @classmethod
    def from_checkpoint(cls, data: Any) -> "WOTSOneTimeSigner":
        """Restore a signer from ``checkpoint()`` output without randomness.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, version, ``w``, ``used`` flag, element
        count, length, truncation, trailing data or checksum mismatch raises
        ``ValueError`` and no instance is returned. The private key and the
        public key rebuilt from it are identical to the original's, so a
        restored unused signer still allows exactly one signature and a
        checkpoint taken after signing restores a signer whose every call
        raises :class:`~pqattest.KeyExhaustedError`.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("checkpoint data must be bytes or bytearray")
        data = bytes(data)
        header = _CHECKPOINT_HEADER_BYTES
        if len(data) < header + _CHECKPOINT_CHECKSUM_BYTES:
            raise ValueError("checkpoint is too short")
        body, checksum = data[:-_CHECKPOINT_CHECKSUM_BYTES], data[-_CHECKPOINT_CHECKSUM_BYTES:]
        if body[:8] != _CHECKPOINT_MAGIC:
            raise ValueError("bad checkpoint magic")
        if body[8] != _CHECKPOINT_VERSION:
            raise ValueError(f"unsupported checkpoint version: {body[8]}")
        w = _validate_w(body[9])
        used_byte = body[10]
        if used_byte not in (0, 1):
            raise ValueError("used flag must be 0 or 1")
        element_count = int.from_bytes(body[11:13], "big")
        _, l1, l2 = _params(w)
        chains = l1 + l2
        if element_count != chains:
            raise ValueError("element count does not match the chain count for w")
        if len(body) != header + element_count * ELEMENT_BYTES:
            raise ValueError("checkpoint length does not match the element count")
        if hashlib.sha256(body).digest() != checksum:
            raise ValueError("checkpoint checksum mismatch")
        elements = tuple(
            body[header + i * ELEMENT_BYTES : header + (i + 1) * ELEMENT_BYTES]
            for i in range(element_count)
        )
        private_key = WOTSPrivateKey(w=w, elements=elements)
        signer = cls.__new__(cls)
        signer._restore_state(
            private_key, cls._public_key_from(private_key), bool(used_byte)
        )
        return signer

    @classmethod
    def from_auth_state(
        cls, data: Any, *, key: Any, min_generation: Any = None, claim: Any
    ) -> tuple["WOTSOneTimeSigner", int]:
        """Restore a signer from a v2 :func:`auth_state_wrap` envelope and claim it.

        Combines v2 verification, the generation floor, the v1 checkpoint
        restore and an external monotonic claim in one call without drawing
        randomness and without any new wire format: only an envelope produced
        by :func:`auth_state_wrap` with ``scheme="wots"`` is accepted.
        ``key``, ``min_generation`` and ``claim`` are keyword-only. Returns
        ``(signer, generation)``: the restored :class:`WOTSOneTimeSigner` and
        the non-negative uint64 generation carried in the envelope; the
        restored signer has the same public key and ``used`` semantics as
        :meth:`from_checkpoint` would give for the embedded checkpoint.

        ``data`` must be ``bytes`` or ``bytearray``; ``key`` must be a
        non-empty ``bytes``/``bytearray`` shared secret; ``min_generation``
        must be ``None`` or a non-boolean integer in ``0 .. 2**64 - 1``;
        ``claim`` must be callable. A wrong type (including a boolean floor or
        a non-callable claim) raises ``TypeError``. The v2 HMAC tag is
        verified first with :func:`hmac.compare_digest`; the envelope scheme
        is then fixed to ``"wots"`` and the generation floor applied; only
        afterwards is the untouched payload handed to
        :meth:`from_checkpoint`. Only once every check has passed and the
        signer is restored is ``claim`` called exactly once with the single
        token ``("wots", generation)``; the restore succeeds only when that
        call returns exactly ``True`` (a truthy non-bool such as ``1`` is
        rejected), and anything it raises propagates unchanged. An empty key,
        a bad tag or envelope, a non-wots scheme (including a v1 envelope), a
        generation below the floor, an invalid checkpoint or a claim that is
        not exactly ``True`` raises ``ValueError`` and leaves no instance
        behind; on every such failure ``claim`` is never called.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes or bytearray")
        key_bytes = _validate_key(key)
        if min_generation is not None:
            _validate_generation(min_generation, "min_generation")
        _validate_claim(claim)
        _, generation_value, checkpoint = auth_state_unwrap(
            data, key=key_bytes, expect="wots",
            min_generation=min_generation,
        )
        signer = cls.from_checkpoint(checkpoint)
        _run_claim(claim, ("wots", generation_value))
        return signer, generation_value


def wots_keygen(
    *,
    w: int = 4,
    token_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> tuple[WOTSPrivateKey, WOTSPublicKey]:
    """Generate a fresh W-OTS key pair.

    ``w`` selects the Winternitz parameter and must be 4 or 8. Every chain
    starts at a random 32-byte value from ``token_bytes``; the public key
    stores each chain's step ``B - 1`` endpoint.
    """
    w = _validate_w(w)
    b, l1, l2 = _params(w)
    starts = tuple(bytes(token_bytes(ELEMENT_BYTES)) for _ in range(l1 + l2))
    for start in starts:
        if len(start) != ELEMENT_BYTES:
            raise ValueError(f"token_bytes must return {ELEMENT_BYTES} bytes")
    private_key = WOTSPrivateKey(w=w, elements=starts)
    endpoints = tuple(_chain_walk(start, b - 1) for start in starts)
    return private_key, WOTSPublicKey(w=w, elements=endpoints)


def wots_sign(message: Any, private_key: WOTSPrivateKey) -> tuple[bytes, ...]:
    """Sign ``message``: for each digit ``d`` reveal chain value at step ``d``.

    Message digits come first, followed by the fixed-width checksum digits.
    """
    if not isinstance(private_key, WOTSPrivateKey):
        raise TypeError("private_key must be a WOTSPrivateKey")
    digits = _signing_digits(message, private_key.w)
    return tuple(
        _chain_walk(private_key.elements[i], digit)
        for i, digit in enumerate(digits)
    )


def wots_verify(
    message: Any, signature: Sequence[Any], public_key: WOTSPublicKey
) -> bool:
    """Complete the remaining chain steps and compare every public endpoint.

    Returns ``False`` for any structural, parameter or content mismatch; only
    a wrong key *type* raises ``TypeError``.
    """
    if not isinstance(public_key, WOTSPublicKey):
        raise TypeError("public_key must be a WOTSPublicKey")
    w = public_key.w
    b, l1, l2 = _params(w)
    length = l1 + l2

    try:
        parts = tuple(bytes(part) for part in signature)
    except (TypeError, ValueError):
        return False
    if len(parts) != length or len(public_key.elements) != length:
        return False
    if any(len(part) != ELEMENT_BYTES for part in parts):
        return False

    try:
        digits = _signing_digits(message, w)
    except TypeError:
        return False
    for i, digit in enumerate(digits):
        endpoint = _chain_walk(parts[i], b - 1 - digit)
        if endpoint != public_key.elements[i]:
            return False
    return True


def wots_signature_to_bytes(signature: Any, *, w: int) -> bytes:
    """Serialise a stateless W-OTS signature to the versioned v1 wire format.

    ``signature`` must be a ``tuple`` whose members are all ``bytes`` — the
    shape :func:`wots_sign` returns; anything else raises ``TypeError``.
    ``w`` is keyword-only and must be 4 or 8 (``ValueError`` otherwise); the
    signature must contain exactly the chain count for ``w`` (67 or 34
    elements) and every element must be exactly 32 bytes, else ``ValueError``.

    The layout is the 8-byte magic ``b"PQAWSIG\\0"``; one byte each for the
    version (1) and ``w``; the element count as 2 big-endian bytes; then every
    signature element in chain order, 32 bytes each. Encoding is
    deterministic: the same signature and ``w`` always produce the same
    bytes.
    """
    if not isinstance(signature, tuple):
        raise TypeError("signature must be a tuple of 32-byte values")
    for element in signature:
        if not isinstance(element, bytes):
            raise TypeError("every signature element must be bytes")
    w = _validate_w(w)
    chains = _chain_count(w)
    if len(signature) != chains:
        raise ValueError(f"signature must contain exactly {chains} elements for w={w}")
    for element in signature:
        if len(element) != ELEMENT_BYTES:
            raise ValueError(f"every signature element must be exactly {ELEMENT_BYTES} bytes")
    return _encode_v1(_SIGNATURE_MAGIC, w, signature)


def wots_signature_from_bytes(data: Any) -> tuple[int, tuple[bytes, ...]]:
    """Parse ``wots_signature_to_bytes()`` output back into ``(w, elements)``.

    ``data`` must be ``bytes`` or ``bytearray``; anything else raises
    ``TypeError``. A bad magic, an unknown version, an invalid ``w``, an
    element count that does not match the chain count for ``w``, truncation
    or trailing data raises ``ValueError``. The returned ``elements`` are an
    immutable ``tuple`` of 32-byte ``bytes`` in the original chain order,
    ready for :func:`wots_verify`.
    """
    return _decode_v1(data, _SIGNATURE_MAGIC, "signature")

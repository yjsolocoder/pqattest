"""Winternitz one-time signature (W-OTS) for pqattest.

Like the Lamport construction this is a **one-time** signature: a key pair
must sign at most one message. Each signing key is a set of hash chains; a
signature for a base-``B`` digit ``d`` reveals the value at chain step ``d``
and the public key holds the step ``B - 1`` endpoint. Only the standard
library is used. Keys and stateless signatures have a deterministic,
versioned v1 binary wire format (``to_bytes`` / ``from_bytes`` on the key
classes, :func:`wots_signature_to_bytes` / :func:`wots_signature_from_bytes`
for signatures); the private-key encoding holds the secret elements in the
clear, so callers must store it securely. :class:`WOTSOneTimeSigner` state
can be persisted with a versioned binary checkpoint (``checkpoint`` /
``from_checkpoint``); the blob holds the private key in the clear and is
integrity-protected only by a SHA-256 checksum, so callers must store it
securely.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

from ._errors import KeyExhaustedError

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

_PRIVATE_KEY_MAGIC = b"PQAWPRV\0"
_PUBLIC_KEY_MAGIC = b"PQAWPUB\0"
_SIGNATURE_MAGIC = b"PQAWSIG\0"
_ENCODING_VERSION = 1
_ENCODING_HEADER_BYTES = 8 + 1 + 1 + 2

_CHECKPOINT_MAGIC = b"PQAWCP\0\0"
_CHECKPOINT_VERSION = 1
_CHECKPOINT_HEADER_BYTES = 8 + 1 + 1 + 1 + 2
_CHECKPOINT_CHECKSUM_BYTES = 32


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


def _encode_elements(magic: bytes, w: int, elements: tuple[bytes, ...]) -> bytes:
    """Shared v1 wire format: magic, version, ``w``, count, then the elements."""
    return (
        magic
        + bytes((_ENCODING_VERSION, w))
        + len(elements).to_bytes(2, "big")
        + b"".join(elements)
    )


def _decode_elements(data: Any, magic: bytes, description: str) -> tuple[int, tuple[bytes, ...]]:
    """Parse the shared v1 wire format; return ``(w, elements)``.

    The element count is not trusted: it must equal the chain count implied
    by ``w`` (67 for ``w=4``, 34 for ``w=8``), which also fixes the total
    length, so truncation and trailing data are both detected.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{description} data must be bytes or bytearray")
    data = bytes(data)
    if len(data) < _ENCODING_HEADER_BYTES:
        raise ValueError(f"{description} encoding is truncated")
    if data[:8] != magic:
        raise ValueError(f"bad {description} magic")
    if data[8] != _ENCODING_VERSION:
        raise ValueError(f"unsupported {description} version: {data[8]}")
    w = _validate_w(data[9])
    element_count = int.from_bytes(data[10:12], "big")
    _, l1, l2 = _params(w)
    chains = l1 + l2
    if element_count != chains:
        raise ValueError("element count does not match the chain count for w")
    expected = _ENCODING_HEADER_BYTES + chains * ELEMENT_BYTES
    if len(data) < expected:
        raise ValueError(f"{description} encoding is truncated")
    if len(data) > expected:
        raise ValueError(f"trailing data after the {description} encoding")
    offset = _ENCODING_HEADER_BYTES
    elements = tuple(
        data[offset + i * ELEMENT_BYTES : offset + (i + 1) * ELEMENT_BYTES]
        for i in range(chains)
    )
    return w, elements


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

        The layout is the 8-byte magic ``b"PQAWPRV\\0"``, one byte each for
        the version (1) and ``w``, the element count as 2 big-endian bytes
        (67 for ``w=4``, 34 for ``w=8``), then every private element in chain
        order, 32 bytes each. Encoding is deterministic: the same key always
        produces the same bytes. The encoding holds the secret elements in
        the clear — store it as a secret. Fields corrupted by bypassing the
        frozen constructor raise ``TypeError``/``ValueError`` instead of
        producing a malformed encoding.
        """
        if not isinstance(self, WOTSPrivateKey):
            raise TypeError("to_bytes must be called on a WOTSPrivateKey")
        w = _validate_w(self.w)
        _validate_elements(w, self.elements)
        return _encode_elements(_PRIVATE_KEY_MAGIC, w, self.elements)

    @classmethod
    def from_bytes(cls, data: Any) -> "WOTSPrivateKey":
        """Parse ``to_bytes()`` output back into a :class:`WOTSPrivateKey`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, an invalid ``w``, an
        element count that disagrees with ``w``, truncation or trailing data
        raises ``ValueError`` and no instance is returned. The restored key
        is equal by value to the one that was encoded.
        """
        w, elements = _decode_elements(data, _PRIVATE_KEY_MAGIC, "private key")
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

        The layout is the 8-byte magic ``b"PQAWPUB\\0"``, one byte each for
        the version (1) and ``w``, the element count as 2 big-endian bytes
        (67 for ``w=4``, 34 for ``w=8``), then every public element in chain
        order, 32 bytes each. Encoding is deterministic: the same key always
        produces the same bytes. Fields corrupted by bypassing the frozen
        constructor raise ``TypeError``/``ValueError`` instead of producing a
        malformed encoding.
        """
        if not isinstance(self, WOTSPublicKey):
            raise TypeError("to_bytes must be called on a WOTSPublicKey")
        w = _validate_w(self.w)
        _validate_elements(w, self.elements)
        return _encode_elements(_PUBLIC_KEY_MAGIC, w, self.elements)

    @classmethod
    def from_bytes(cls, data: Any) -> "WOTSPublicKey":
        """Parse ``to_bytes()`` output back into a :class:`WOTSPublicKey`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, an invalid ``w``, an
        element count that disagrees with ``w``, truncation or trailing data
        raises ``ValueError`` and no instance is returned. The restored key
        is equal by value to the one that was encoded.
        """
        w, elements = _decode_elements(data, _PUBLIC_KEY_MAGIC, "public key")
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
    checksum against accidental corruption, so callers must store it securely.
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
            body = (
                _CHECKPOINT_MAGIC
                + bytes((_CHECKPOINT_VERSION, self._private_key.w, int(self._used)))
                + len(self._private_key.elements).to_bytes(2, "big")
                + b"".join(self._private_key.elements)
            )
            return body + hashlib.sha256(body).digest()

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


def wots_signature_to_bytes(signature: Any, *, w: int) -> bytes:
    """Serialise a stateless W-OTS signature to the v1 wire format as ``bytes``.

    ``signature`` must be a tuple of 32-byte ``bytes`` elements in chain
    order — anything else (a list, a non-``bytes`` member) raises
    ``TypeError``. ``w`` is keyword-only and must be 4 or 8; the signature
    must hold exactly the chain count for ``w`` (67 or 34 elements). An
    invalid ``w``, a wrong element count or a member that is not exactly 32
    bytes raises ``ValueError``. The layout is the 8-byte magic
    ``b"PQAWSIG\\0"``, one byte each for the version (1) and ``w``, the
    element count as 2 big-endian bytes, then every element in order.
    Encoding is deterministic: the same signature always produces the same
    bytes.
    """
    w = _validate_w(w)
    if not isinstance(signature, tuple):
        raise TypeError("signature must be a tuple of 32-byte values")
    for element in signature:
        if not isinstance(element, bytes):
            raise TypeError("every signature element must be bytes")
        if len(element) != ELEMENT_BYTES:
            raise ValueError(f"every element must be exactly {ELEMENT_BYTES} bytes")
    _, l1, l2 = _params(w)
    if len(signature) != l1 + l2:
        raise ValueError(f"signature must contain exactly {l1 + l2} elements for w={w}")
    return _encode_elements(_SIGNATURE_MAGIC, w, signature)


def wots_signature_from_bytes(data: Any) -> tuple[int, tuple[bytes, ...]]:
    """Parse ``wots_signature_to_bytes()`` output back into ``(w, elements)``.

    ``data`` must be ``bytes`` or ``bytearray``; anything else raises
    ``TypeError``. A bad magic, an unknown version, an invalid ``w``, an
    element count that disagrees with ``w``, truncation or trailing data
    raises ``ValueError``. The returned ``elements`` are an immutable tuple
    of 32-byte ``bytes`` in their original chain order, so the decoded
    signature verifies exactly like the one that was encoded.
    """
    return _decode_elements(data, _SIGNATURE_MAGIC, "signature")


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

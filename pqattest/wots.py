"""Winternitz one-time signature (W-OTS) for pqattest.

Like the Lamport construction this is a **one-time** signature: a key pair
must sign at most one message. Each signing key is a set of hash chains; a
signature for a base-``B`` digit ``d`` reveals the value at chain step ``d``
and the public key holds the step ``B - 1`` endpoint. Only the standard
library is used.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

__all__ = [
    "ELEMENT_BYTES",
    "WOTSPrivateKey",
    "WOTSPublicKey",
    "wots_keygen",
    "wots_sign",
    "wots_verify",
]

ELEMENT_BYTES = 32
_DOMAIN = b"pqattest/wots/v1"
_ALLOWED_W = (4, 8)


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

"""pqattest - hash-based one-time signatures (Lamport and Winternitz).

Public API: keygen / public_key_from / sign / verify / message_bits /
OneTimeSigner / KeyExhaustedError, plus the Winternitz construction:
wots_keygen / wots_sign / wots_verify / WOTSPrivateKey / WOTSPublicKey.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from .wots import (
    ELEMENT_BYTES,
    WOTSPrivateKey,
    WOTSPublicKey,
    wots_keygen,
    wots_sign,
    wots_verify,
)

__all__ = [
    "BITS",
    "ELEMENT_BYTES",
    "HASH_BYTES",
    "KeyExhaustedError",
    "OneTimeSigner",
    "PrivateKey",
    "PublicKey",
    "WOTSPrivateKey",
    "WOTSPublicKey",
    "keygen",
    "message_bits",
    "message_digest",
    "public_key_from",
    "sign",
    "verify",
    "wots_keygen",
    "wots_sign",
    "wots_verify",
]

BITS = 256
HASH_BYTES = 32
_DOMAIN = b"pqattest/lamport/v1"


def _as_bytes(message: Any) -> bytes:
    if isinstance(message, bytes):
        return message
    if isinstance(message, bytearray):
        return bytes(message)
    if isinstance(message, str):
        return message.encode("utf-8")
    raise TypeError("message must be bytes, bytearray or str")


def message_digest(message: Any) -> bytes:
    """SHA-256 digest of the message."""
    return hashlib.sha256(_as_bytes(message)).digest()


def message_bits(message: Any, *, bits: int = BITS) -> tuple[int, ...]:
    """Expand the digest into ``bits`` bits, most significant bit first."""
    if not isinstance(bits, int) or not 1 <= bits <= BITS:
        raise ValueError(f"bits must be an integer between 1 and {BITS}")
    digest = message_digest(message)
    return tuple((digest[index >> 3] >> (7 - (index & 7))) & 1 for index in range(bits))


def _secret_digest(secret: bytes) -> bytes:
    return hashlib.sha256(_DOMAIN + secret).digest()


@dataclass(frozen=True)
class PrivateKey:
    """``2 * bits`` secret values: index ``2 * i + b`` belongs to bit ``i``, branch ``b``."""

    secrets: tuple[bytes, ...]

    @property
    def bits(self) -> int:
        return len(self.secrets) // 2


@dataclass(frozen=True)
class PublicKey:
    """One-way images of the private secrets, in the same order."""

    digests: tuple[bytes, ...]

    @property
    def bits(self) -> int:
        return len(self.digests) // 2


def keygen(*, bits: int = BITS, token_bytes: Callable[[int], bytes] = secrets.token_bytes) -> tuple[PrivateKey, PublicKey]:
    """Generate a fresh one-time key pair."""
    if not isinstance(bits, int) or not 1 <= bits <= BITS:
        raise ValueError(f"bits must be an integer between 1 and {BITS}")
    secrets_tuple = tuple(bytes(token_bytes(HASH_BYTES)) for _ in range(2 * bits))
    for secret in secrets_tuple:
        if len(secret) != HASH_BYTES:
            raise ValueError(f"token_bytes must return {HASH_BYTES} bytes")
    private_key = PrivateKey(secrets_tuple)
    return private_key, public_key_from(private_key)


def public_key_from(private_key: PrivateKey) -> PublicKey:
    """Recompute the public key from a private key."""
    if not isinstance(private_key, PrivateKey):
        raise TypeError("private_key must be a PrivateKey")
    return PublicKey(tuple(_secret_digest(secret) for secret in private_key.secrets))


def sign(message: Any, private_key: PrivateKey) -> tuple[bytes, ...]:
    """Produce a one-time signature: reveal one secret per digest bit."""
    if not isinstance(private_key, PrivateKey):
        raise TypeError("private_key must be a PrivateKey")
    bits = message_bits(message, bits=private_key.bits)
    return tuple(private_key.secrets[2 * index + bit] for index, bit in enumerate(bits))


def verify(message: Any, signature: Sequence[bytes], public_key: PublicKey) -> bool:
    """Check a signature against the digest bits of ``message``."""
    if not isinstance(public_key, PublicKey):
        raise TypeError("public_key must be a PublicKey")
    materialised = tuple(bytes(part) for part in signature)
    if len(materialised) != public_key.bits:
        return False
    bits = message_bits(message, bits=public_key.bits)
    for index, bit in enumerate(bits):
        if _secret_digest(materialised[index]) != public_key.digests[2 * index + bit]:
            return False
    return True


class KeyExhaustedError(RuntimeError):
    """A :class:`OneTimeSigner` was asked to sign after its key was already used."""


class OneTimeSigner:
    """Thread-safe, single-use wrapper around a :class:`PrivateKey`.

    The first :meth:`sign` call returns the ordinary Lamport signature and
    marks the key as used; every later call raises :class:`KeyExhaustedError`.
    The guard is per instance — calling the stateless :func:`sign` directly is
    unaffected.
    """

    __slots__ = ("_lock", "_private_key", "_public_key", "_used")

    def __init__(self, private_key: PrivateKey) -> None:
        if not isinstance(private_key, PrivateKey):
            raise TypeError("private_key must be a PrivateKey")
        self._lock = threading.Lock()
        self._private_key = private_key
        self._public_key = public_key_from(private_key)
        self._used = False

    @property
    def public_key(self) -> PublicKey:
        """Public key derived from the wrapped private key (read-only)."""
        return self._public_key

    @property
    def used(self) -> bool:
        """``True`` once a signature has been produced (read-only)."""
        return self._used

    def sign(self, message: Any) -> tuple[bytes, ...]:
        """Sign once.

        Behaves exactly like :func:`sign` on the first call, accepting
        ``bytes``/``bytearray``/``str``; an unsupported message type raises
        ``TypeError`` without consuming the key. Any later call raises
        :class:`KeyExhaustedError`. Concurrent calls are serialised so that at
        most one of them can succeed.
        """
        with self._lock:
            if self._used:
                raise KeyExhaustedError("this one-time signing key has already been used")
            signature = sign(message, self._private_key)
            self._used = True
            return signature

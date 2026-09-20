"""Toy lattice-style key encapsulation mechanism (KEM) for teaching.

This is a deliberately tiny ring/lattice-flavoured KEM used to show how
encapsulation/decapsulation fit together. Coefficients live in a fixed
dimension-8 vector space reduced modulo 257; the encoding ``E`` serialises a
vector as eight 2-byte big-endian coefficients (each in ``0..256``). The
shared secret derives from a dot product modulo 257 and a SHA-256 key
confirmation tag.

.. warning::

    Unaudited and insecure by design: keygen reuses the same vector for the
    public and private keys, there is no noise or trapdoor, and the whole
    "lattice" fits in 16 bytes. **Teaching only — never use in production.**

Only the standard library is used.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Any, Callable, Iterable

__all__ = [
    "ToyLatticeCiphertext",
    "ToyLatticePrivateKey",
    "ToyLatticePublicKey",
    "toy_lattice_decapsulate",
    "toy_lattice_encapsulate",
    "toy_lattice_keygen",
]

_DIMENSION = 8
_COEFF_BYTES = 2
_ELEMENT_BYTES = _DIMENSION * _COEFF_BYTES
_MODULUS = 257
_MAX_COEFF = 256
_TOKEN_BYTES = _DIMENSION
_TAG_BYTES = 32
_KEY_DOMAIN = b"K"


def _encode_e(coeffs: Iterable[int]) -> bytes:
    """Encode ``coeffs`` as 2-byte big-endian values (the encoding ``E``)."""
    return b"".join(int(coeff).to_bytes(_COEFF_BYTES, "big") for coeff in coeffs)


def _decode_e(value: bytes) -> tuple[int, ...]:
    """Decode an ``E`` value back into its coefficient vector."""
    return tuple(
        int.from_bytes(value[offset : offset + _COEFF_BYTES], "big")
        for offset in range(0, _ELEMENT_BYTES, _COEFF_BYTES)
    )


def _validate_e(value: Any, name: str) -> None:
    """Check that ``value`` is an encoding ``E`` of eight ``0..256`` coefficients."""
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != _ELEMENT_BYTES:
        raise ValueError(f"{name} must be exactly {_ELEMENT_BYTES} bytes")
    for offset in range(0, _ELEMENT_BYTES, _COEFF_BYTES):
        coeff = int.from_bytes(value[offset : offset + _COEFF_BYTES], "big")
        if coeff > _MAX_COEFF:
            raise ValueError(
                f"{name} coefficients must be between 0 and {_MAX_COEFF}"
            )


def _dot_mod(left: Iterable[int], right: Iterable[int]) -> int:
    return sum(a * b for a, b in zip(left, right)) % _MODULUS


def _derive_shared(v: int) -> bytes:
    """K = SHA256(b"K" + v2) with ``v`` encoded as 2-byte big endian."""
    return hashlib.sha256(_KEY_DOMAIN + v.to_bytes(_COEFF_BYTES, "big")).digest()


@dataclass(frozen=True)
class ToyLatticePrivateKey:
    """Frozen toy private key: the ``E``-encoded secret vector ``s``."""

    s: bytes

    def __post_init__(self) -> None:
        _validate_e(self.s, "s")


@dataclass(frozen=True)
class ToyLatticePublicKey:
    """Frozen toy public key: the ``E``-encoded vector ``t``."""

    t: bytes

    def __post_init__(self) -> None:
        _validate_e(self.t, "t")


@dataclass(frozen=True)
class ToyLatticeCiphertext:
    """Frozen toy ciphertext: the ``E``-encoded ephemeral vector ``u`` and tag."""

    u: bytes
    tag: bytes

    def __post_init__(self) -> None:
        _validate_e(self.u, "u")
        if not isinstance(self.tag, bytes):
            raise TypeError("tag must be bytes")


def toy_lattice_keygen(
    *,
    token_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> tuple[ToyLatticePrivateKey, ToyLatticePublicKey]:
    """Generate a fresh toy key pair and return ``(private_key, public_key)``.

    Eight random bytes ``x`` are drawn with ``token_bytes`` and both keys are
    the same encoding ``s = t = E(x)``. A token source that does not return
    exactly eight bytes raises ``ValueError``.
    """
    raw = bytes(token_bytes(_TOKEN_BYTES))
    if len(raw) != _TOKEN_BYTES:
        raise ValueError(f"token_bytes must return {_TOKEN_BYTES} bytes")
    encoded = _encode_e(raw)
    return ToyLatticePrivateKey(encoded), ToyLatticePublicKey(encoded)


def toy_lattice_encapsulate(
    public_key: ToyLatticePublicKey,
    *,
    token_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> tuple[ToyLatticeCiphertext, bytes]:
    """Encapsulate against ``public_key`` and return ``(ciphertext, shared_key)``.

    Draws eight random bytes ``r``, sets ``u = E(r)`` and computes
    ``v = t . r mod 257`` from the *decoded* vectors. The shared key is
    ``K = SHA256(b"K" + v2)`` with ``v`` as a 2-byte big-endian value, and the
    ciphertext tag is a copy of ``K``.
    """
    if not isinstance(public_key, ToyLatticePublicKey):
        raise TypeError("public_key must be a ToyLatticePublicKey")
    raw = bytes(token_bytes(_TOKEN_BYTES))
    if len(raw) != _TOKEN_BYTES:
        raise ValueError(f"token_bytes must return {_TOKEN_BYTES} bytes")
    r = tuple(raw)
    v = _dot_mod(_decode_e(public_key.t), r)
    shared_key = _derive_shared(v)
    return ToyLatticeCiphertext(u=_encode_e(raw), tag=shared_key), shared_key


def toy_lattice_decapsulate(
    ciphertext: ToyLatticeCiphertext,
    private_key: ToyLatticePrivateKey,
) -> bytes:
    """Recover the shared key from ``ciphertext`` with ``private_key``.

    Computes ``v = s . u mod 257`` from the decoded vectors, derives the key
    exactly as encapsulation does, and checks the tag in constant time. A
    mismatched (including wrong-length) tag raises ``ValueError``; a wrong
    argument type raises ``TypeError``.
    """
    if not isinstance(ciphertext, ToyLatticeCiphertext):
        raise TypeError("ciphertext must be a ToyLatticeCiphertext")
    if not isinstance(private_key, ToyLatticePrivateKey):
        raise TypeError("private_key must be a ToyLatticePrivateKey")
    v = _dot_mod(_decode_e(private_key.s), _decode_e(ciphertext.u))
    candidate = _derive_shared(v)
    if not hmac.compare_digest(candidate, ciphertext.tag):
        raise ValueError("ciphertext tag does not match")
    return candidate

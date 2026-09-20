"""Toy lattice-style key encapsulation mechanism (KEM) for teaching.

This is a deliberately tiny ring/lattice-flavoured KEM used to show how
encapsulation/decapsulation fit together. Coefficients live in a fixed
dimension-8 vector space reduced modulo 257; the encoding ``E`` serialises a
vector as eight 2-byte big-endian coefficients (each in ``0..256``). The
shared secret derives from a dot product modulo 257 and a SHA-256 key
confirmation tag. Keys and ciphertexts each have a versioned binary wire
format via ``to_bytes`` / ``from_bytes`` (8-byte magics ``b"PQALPK\\0\\0"``,
``b"PQALSK\\0\\0"`` and ``b"PQALCT\\0\\0"``).

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

_WIRE_VERSION = 1
_PUBLIC_KEY_MAGIC = b"PQALPK\0\0"
_PRIVATE_KEY_MAGIC = b"PQALSK\0\0"
_CIPHERTEXT_MAGIC = b"PQALCT\0\0"
_KEY_BYTES = 8 + 1 + _ELEMENT_BYTES
_CIPHERTEXT_HEADER_BYTES = 8 + 1 + _ELEMENT_BYTES + 4
_TAG_LEN_BYTES = 4
_MAX_TAG_LEN = 2 ** 32 - 1


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

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQALSK\\0\\0"``, one version byte
        (1) and the 16-byte ``E``-encoded ``s`` — 25 bytes in total.
        Encoding is deterministic: the same key always produces the same
        bytes. A field corrupted by bypassing the frozen constructor raises
        ``ValueError`` instead of producing a malformed encoding.
        """
        if not isinstance(self, ToyLatticePrivateKey):
            raise TypeError("to_bytes must be called on a ToyLatticePrivateKey")
        _validate_e(self.s, "s")
        return _PRIVATE_KEY_MAGIC + bytes((_WIRE_VERSION,)) + self.s

    @classmethod
    def from_bytes(cls, data: Any) -> "ToyLatticePrivateKey":
        """Parse ``to_bytes()`` output back into a :class:`ToyLatticePrivateKey`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, a truncated or
        over-long encoding, or an out-of-range ``E`` coefficient raises
        ``ValueError`` and no instance is returned.
        """
        data = _wire_data(data, "private key")
        if len(data) < _KEY_BYTES:
            raise ValueError("private key encoding is truncated")
        if len(data) > _KEY_BYTES:
            raise ValueError("trailing data after the private key encoding")
        if data[:8] != _PRIVATE_KEY_MAGIC:
            raise ValueError("bad private key magic")
        if data[8] != _WIRE_VERSION:
            raise ValueError(f"unsupported private key version: {data[8]}")
        return cls(data[9:_KEY_BYTES])


@dataclass(frozen=True)
class ToyLatticePublicKey:
    """Frozen toy public key: the ``E``-encoded vector ``t``."""

    t: bytes

    def __post_init__(self) -> None:
        _validate_e(self.t, "t")

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQALPK\\0\\0"``, one version byte
        (1) and the 16-byte ``E``-encoded ``t`` — 25 bytes in total.
        Encoding is deterministic: the same key always produces the same
        bytes. A field corrupted by bypassing the frozen constructor raises
        ``ValueError`` instead of producing a malformed encoding.
        """
        if not isinstance(self, ToyLatticePublicKey):
            raise TypeError("to_bytes must be called on a ToyLatticePublicKey")
        _validate_e(self.t, "t")
        return _PUBLIC_KEY_MAGIC + bytes((_WIRE_VERSION,)) + self.t

    @classmethod
    def from_bytes(cls, data: Any) -> "ToyLatticePublicKey":
        """Parse ``to_bytes()`` output back into a :class:`ToyLatticePublicKey`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, a truncated or
        over-long encoding, or an out-of-range ``E`` coefficient raises
        ``ValueError`` and no instance is returned.
        """
        data = _wire_data(data, "public key")
        if len(data) < _KEY_BYTES:
            raise ValueError("public key encoding is truncated")
        if len(data) > _KEY_BYTES:
            raise ValueError("trailing data after the public key encoding")
        if data[:8] != _PUBLIC_KEY_MAGIC:
            raise ValueError("bad public key magic")
        if data[8] != _WIRE_VERSION:
            raise ValueError(f"unsupported public key version: {data[8]}")
        return cls(data[9:_KEY_BYTES])


@dataclass(frozen=True)
class ToyLatticeCiphertext:
    """Frozen toy ciphertext: the ``E``-encoded ephemeral vector ``u`` and tag."""

    u: bytes
    tag: bytes

    def __post_init__(self) -> None:
        _validate_e(self.u, "u")
        if not isinstance(self.tag, bytes):
            raise TypeError("tag must be bytes")

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQALCT\\0\\0"``; one version byte
        (1); the 16-byte ``E``-encoded ``u``; the tag length as four
        big-endian unsigned bytes; and the tag verbatim, which may be any
        ``bytes`` value from empty up to ``2 ** 32 - 1`` bytes. Encoding is
        deterministic: the same ciphertext always produces the same bytes.
        A field corrupted by bypassing the frozen constructor raises
        ``ValueError`` (or ``TypeError`` for a non-``bytes`` tag) instead of
        producing a malformed encoding.
        """
        if not isinstance(self, ToyLatticeCiphertext):
            raise TypeError("to_bytes must be called on a ToyLatticeCiphertext")
        _validate_e(self.u, "u")
        if not isinstance(self.tag, bytes):
            raise TypeError("tag must be bytes")
        if len(self.tag) > _MAX_TAG_LEN:
            raise ValueError(f"tag must be at most {_MAX_TAG_LEN} bytes")
        return (
            _CIPHERTEXT_MAGIC
            + bytes((_WIRE_VERSION,))
            + self.u
            + len(self.tag).to_bytes(_TAG_LEN_BYTES, "big")
            + self.tag
        )

    @classmethod
    def from_bytes(cls, data: Any) -> "ToyLatticeCiphertext":
        """Parse ``to_bytes()`` output back into a :class:`ToyLatticeCiphertext`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, an out-of-range ``E``
        coefficient, a tag length that runs past the end of the encoding,
        truncation or trailing data raises ``ValueError`` and no instance is
        returned.
        """
        data = _wire_data(data, "ciphertext")
        if len(data) < _CIPHERTEXT_HEADER_BYTES:
            raise ValueError("ciphertext encoding is truncated")
        if data[:8] != _CIPHERTEXT_MAGIC:
            raise ValueError("bad ciphertext magic")
        if data[8] != _WIRE_VERSION:
            raise ValueError(f"unsupported ciphertext version: {data[8]}")
        u = data[9 : 9 + _ELEMENT_BYTES]
        tag_length = int.from_bytes(
            data[9 + _ELEMENT_BYTES : _CIPHERTEXT_HEADER_BYTES], "big"
        )
        end = _CIPHERTEXT_HEADER_BYTES + tag_length
        if len(data) < end:
            raise ValueError("ciphertext encoding is truncated")
        if len(data) > end:
            raise ValueError("trailing data after the ciphertext encoding")
        return cls(u, data[_CIPHERTEXT_HEADER_BYTES:end])


def _wire_data(data: Any, name: str) -> bytes:
    """Coerce a ``bytes``/``bytearray`` wire blob to ``bytes`` or reject it."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{name} data must be bytes or bytearray")
    return bytes(data)


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

"""Toy lattice-style key encapsulation mechanism (KEM) for teaching.

This is a deliberately tiny ring/lattice-flavoured KEM used to show how
encapsulation/decapsulation fit together. Coefficients live in a fixed
dimension-8 vector space reduced modulo 257; the encoding ``E`` serialises a
vector as eight 2-byte big-endian coefficients (each in ``0..256``). The
shared secret derives from a dot product modulo 257 and a SHA-256 key
confirmation tag.

The same vectors also back a tiny one-message toy signature: signing draws a
fresh random vector, derives a 32-byte chain key from it and the message, and
keys a 32-byte HMAC-SHA-256 tag with the private vector; verification
re-derives the chain key and checks the tag against the public vector. As in
the Merkle signature, signing and verifying accept an optional keyword-only
``context`` (``None`` or an empty value means no context; a non-empty
``bytes``/``bytearray``/``str``, with ``str`` encoded as UTF-8) that is bound
into the chain key together with the message without changing the v1 wire
format or any no-context result.

.. warning::

    Unaudited and insecure by design: keygen reuses the same vector for the
    public and private keys, there is no noise or trapdoor, and the whole
    "lattice" fits in 16 bytes. The toy signature is a stateless MAC tag and
    is not a real lattice signature. **Teaching only — never use in
    production.**

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
    "ToyLatticeProof",
    "ToyLatticePublicKey",
    "ToyLatticeSignature",
    "toy_lattice_decapsulate",
    "toy_lattice_encapsulate",
    "toy_lattice_keygen",
    "toy_lattice_sign",
    "toy_lattice_verify",
]

_DIMENSION = 8
_COEFF_BYTES = 2
_ELEMENT_BYTES = _DIMENSION * _COEFF_BYTES
_MODULUS = 257
_MAX_COEFF = 256
_TOKEN_BYTES = _DIMENSION
_TAG_BYTES = 32
_KEY_DOMAIN = b"K"
_SIGNATURE_DOMAIN = b"S"
_CONTEXT_DOMAIN = b"pqattest/lattice/context/v1"

_PUBLIC_KEY_MAGIC = b"PQALPK\0\0"
_PRIVATE_KEY_MAGIC = b"PQALSK\0\0"
_CIPHERTEXT_MAGIC = b"PQALCT\0\0"
_SIGNATURE_MAGIC = b"PQALSG\0\0"
_PROOF_MAGIC = b"PQALPF\0\0"
_LATTICE_VERSION = 1
_KEY_BYTES = 8 + 1 + _ELEMENT_BYTES
_TAG_LENGTH_BYTES = 4
_CIPHERTEXT_HEADER_BYTES = 8 + 1 + _ELEMENT_BYTES + _TAG_LENGTH_BYTES
_SIGNATURE_HEADER_BYTES = 8 + 1 + _ELEMENT_BYTES + _TAG_LENGTH_BYTES
_PROOF_HEADER_BYTES = 8 + 1 + _TAG_LENGTH_BYTES + _TAG_LENGTH_BYTES
_MAX_TAG_LENGTH = 2**32 - 1


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


def _serializable_e(value: Any, name: str) -> None:
    """Validate an ``E`` field for ``to_bytes``; any corrupt field is ``ValueError``."""
    try:
        _validate_e(value, name)
    except TypeError as exc:
        raise ValueError(f"{name} is not a valid E encoding") from exc


def _dot_mod(left: Iterable[int], right: Iterable[int]) -> int:
    return sum(a * b for a, b in zip(left, right)) % _MODULUS


def _derive_shared(v: int) -> bytes:
    """K = SHA256(b"K" + v2) with ``v`` encoded as 2-byte big endian."""
    return hashlib.sha256(_KEY_DOMAIN + v.to_bytes(_COEFF_BYTES, "big")).digest()


def _as_bytes(message: Any) -> bytes:
    if isinstance(message, bytes):
        return message
    if isinstance(message, bytearray):
        return bytes(message)
    if isinstance(message, str):
        return message.encode("utf-8")
    raise TypeError("message must be bytes, bytearray or str")


def _validate_context(context: Any) -> bytes:
    """Normalise the optional signing context to canonical ``bytes``.

    ``None`` and an empty ``bytes``/``bytearray``/``str`` both mean
    "no context" and normalise to ``b""``. Any other type raises
    ``TypeError``; a ``str`` is encoded as UTF-8.
    """
    if context is None:
        return b""
    if isinstance(context, (bytes, bytearray)):
        return bytes(context)
    if isinstance(context, str):
        return context.encode("utf-8")
    raise TypeError("context must be bytes, bytearray, str or None")


def _context_message(context: bytes, message: Any) -> Any:
    """Bind ``message`` to ``context`` for the signature chain key.

    ``context`` must already be normalised by :func:`_validate_context`.
    The empty context passes ``message`` through untouched, so the
    no-context path hashes exactly as the unbound baseline and existing
    signatures stay byte-for-byte identical. With a non-empty context the
    domain separator and both length-prefixed fields are hashed as one
    unambiguous byte string, so the same message under two contexts (or the
    same context for two messages) produces two incompatible signatures.
    """
    if not context:
        return message
    message_bytes = _as_bytes(message)
    return (
        _CONTEXT_DOMAIN
        + len(context).to_bytes(4, "big")
        + context
        + len(message_bytes).to_bytes(4, "big")
        + message_bytes
    )


def _chain_key(random_vector: bytes, message: bytes) -> bytes:
    """Signature chain key: SHA256(b"S" + random vector + message)."""
    return hashlib.sha256(_SIGNATURE_DOMAIN + random_vector + message).digest()


def _signature_tag(chain: bytes, vector: bytes) -> bytes:
    """Keyed tag over the key vector, keyed by the chain key."""
    return hmac.new(chain, _SIGNATURE_DOMAIN + vector, hashlib.sha256).digest()


@dataclass(frozen=True)
class ToyLatticePrivateKey:
    """Frozen toy private key: the ``E``-encoded secret vector ``s``."""

    s: bytes

    def __post_init__(self) -> None:
        _validate_e(self.s, "s")

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQALSK\\0\\0"``, one version byte
        (1), and the 16-byte ``E``-encoded ``s`` — 25 bytes in total.
        Encoding is deterministic: the same key always produces the same
        bytes. A field corrupted by bypassing the frozen constructor raises
        ``ValueError`` instead of producing a malformed encoding.
        """
        if not isinstance(self, ToyLatticePrivateKey):
            raise TypeError("to_bytes must be called on a ToyLatticePrivateKey")
        _serializable_e(self.s, "s")
        return _PRIVATE_KEY_MAGIC + bytes((_LATTICE_VERSION,)) + self.s

    @classmethod
    def from_bytes(cls, data: Any) -> "ToyLatticePrivateKey":
        """Parse ``to_bytes()`` output back into a :class:`ToyLatticePrivateKey`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, a truncated or
        over-long encoding, or an ``s`` that is not a valid ``E`` encoding
        (eight coefficients in ``0..256``) raises ``ValueError``.
        """
        return cls(s=_decode_key_field(data, _PRIVATE_KEY_MAGIC, "private key"))


@dataclass(frozen=True)
class ToyLatticePublicKey:
    """Frozen toy public key: the ``E``-encoded vector ``t``."""

    t: bytes

    def __post_init__(self) -> None:
        _validate_e(self.t, "t")

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQALPK\\0\\0"``, one version byte
        (1), and the 16-byte ``E``-encoded ``t`` — 25 bytes in total.
        Encoding is deterministic: the same key always produces the same
        bytes. A field corrupted by bypassing the frozen constructor raises
        ``ValueError`` instead of producing a malformed encoding.
        """
        if not isinstance(self, ToyLatticePublicKey):
            raise TypeError("to_bytes must be called on a ToyLatticePublicKey")
        _serializable_e(self.t, "t")
        return _PUBLIC_KEY_MAGIC + bytes((_LATTICE_VERSION,)) + self.t

    @classmethod
    def from_bytes(cls, data: Any) -> "ToyLatticePublicKey":
        """Parse ``to_bytes()`` output back into a :class:`ToyLatticePublicKey`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, a truncated or
        over-long encoding, or a ``t`` that is not a valid ``E`` encoding
        (eight coefficients in ``0..256``) raises ``ValueError``.
        """
        return cls(t=_decode_key_field(data, _PUBLIC_KEY_MAGIC, "public key"))


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
        (1); the 16-byte ``E``-encoded ``u``; the tag length as four big-endian
        unsigned bytes; and the tag bytes verbatim. The tag may be any
        ``bytes`` from empty up to ``2 ** 32 - 1`` bytes. Encoding is
        deterministic. A field corrupted by bypassing the frozen constructor
        raises ``ValueError`` instead of producing a malformed encoding.
        """
        if not isinstance(self, ToyLatticeCiphertext):
            raise TypeError("to_bytes must be called on a ToyLatticeCiphertext")
        _serializable_e(self.u, "u")
        if not isinstance(self.tag, bytes):
            raise ValueError("tag is not a valid bytes field")
        if len(self.tag) > _MAX_TAG_LENGTH:
            raise ValueError("tag is too long to encode")
        return (
            _CIPHERTEXT_MAGIC
            + bytes((_LATTICE_VERSION,))
            + self.u
            + len(self.tag).to_bytes(_TAG_LENGTH_BYTES, "big")
            + self.tag
        )

    @classmethod
    def from_bytes(cls, data: Any) -> "ToyLatticeCiphertext":
        """Parse ``to_bytes()`` output back into a :class:`ToyLatticeCiphertext`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, a truncated or
        over-long encoding, a tag length that disagrees with the remaining
        bytes, or a ``u`` that is not a valid ``E`` encoding (eight
        coefficients in ``0..256``) raises ``ValueError``.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("ciphertext data must be bytes or bytearray")
        data = bytes(data)
        if len(data) < _CIPHERTEXT_HEADER_BYTES:
            raise ValueError("ciphertext encoding is truncated")
        if data[:8] != _CIPHERTEXT_MAGIC:
            raise ValueError("bad ciphertext magic")
        if data[8] != _LATTICE_VERSION:
            raise ValueError(f"unsupported ciphertext version: {data[8]}")
        u = data[9 : 9 + _ELEMENT_BYTES]
        _validate_e(u, "u")
        tag_length = int.from_bytes(
            data[9 + _ELEMENT_BYTES : _CIPHERTEXT_HEADER_BYTES], "big"
        )
        expected = _CIPHERTEXT_HEADER_BYTES + tag_length
        if len(data) < expected:
            raise ValueError("ciphertext encoding is truncated")
        if len(data) > expected:
            raise ValueError("trailing data after the ciphertext encoding")
        return cls(u=u, tag=data[_CIPHERTEXT_HEADER_BYTES:expected])


@dataclass(frozen=True)
class ToyLatticeSignature:
    """Frozen toy signature: the ``E``-encoded random vector ``u`` and a tag.

    ``u`` must be a valid encoding ``E`` (16 bytes, eight coefficients in
    ``0..256``) and ``tag`` must be exactly 32 bytes. A non-``bytes`` field
    raises ``TypeError``; a wrong ``u`` length, an out-of-range coefficient or
    a tag that is not exactly 32 bytes raises ``ValueError`` at construction
    time.
    """

    u: bytes
    tag: bytes

    def __post_init__(self) -> None:
        _validate_e(self.u, "u")
        if not isinstance(self.tag, bytes):
            raise TypeError("tag must be bytes")
        if len(self.tag) != _TAG_BYTES:
            raise ValueError(f"tag must be exactly {_TAG_BYTES} bytes")

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQALSG\\0\\0"``; one version byte
        (1); the 16-byte ``E``-encoded random vector ``u``; the tag length as
        four big-endian unsigned bytes (always 32); and the 32-byte tag
        verbatim — 61 bytes in total. Neither the message nor the key is
        carried. Encoding is deterministic: the same signature always produces
        the same bytes. A field corrupted by bypassing the frozen constructor
        raises ``ValueError`` instead of producing a malformed encoding.
        """
        if not isinstance(self, ToyLatticeSignature):
            raise TypeError("to_bytes must be called on a ToyLatticeSignature")
        _serializable_e(self.u, "u")
        if not isinstance(self.tag, bytes) or len(self.tag) != _TAG_BYTES:
            raise ValueError("tag is not a valid 32-byte bytes field")
        return (
            _SIGNATURE_MAGIC
            + bytes((_LATTICE_VERSION,))
            + self.u
            + len(self.tag).to_bytes(_TAG_LENGTH_BYTES, "big")
            + self.tag
        )

    @classmethod
    def from_bytes(cls, data: Any) -> "ToyLatticeSignature":
        """Parse ``to_bytes()`` output back into a :class:`ToyLatticeSignature`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, truncation, trailing
        data, a ``u`` that is not a valid ``E`` encoding (eight coefficients
        in ``0..256``), or a tag length other than 32 raises ``ValueError``.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("signature data must be bytes or bytearray")
        data = bytes(data)
        if len(data) < _SIGNATURE_HEADER_BYTES:
            raise ValueError("signature encoding is truncated")
        if data[:8] != _SIGNATURE_MAGIC:
            raise ValueError("bad signature magic")
        if data[8] != _LATTICE_VERSION:
            raise ValueError(f"unsupported signature version: {data[8]}")
        u = data[9 : 9 + _ELEMENT_BYTES]
        _validate_e(u, "u")
        tag_length = int.from_bytes(
            data[9 + _ELEMENT_BYTES : _SIGNATURE_HEADER_BYTES], "big"
        )
        if tag_length != _TAG_BYTES:
            raise ValueError(f"signature tag length must be {_TAG_BYTES}")
        expected = _SIGNATURE_HEADER_BYTES + tag_length
        if len(data) < expected:
            raise ValueError("signature encoding is truncated")
        if len(data) > expected:
            raise ValueError("trailing data after the signature encoding")
        return cls(u=u, tag=data[_SIGNATURE_HEADER_BYTES:expected])


@dataclass(frozen=True)
class ToyLatticeProof:
    """Frozen, self-contained bundle of one toy public key and one signature.

    Unlike a bare :class:`ToyLatticeSignature` (whose tag cannot be checked
    without the matching :class:`ToyLatticePublicKey` supplied separately), a
    proof carries the public key that constrains its signature, so it can be
    transported on its own as a single byte block and verified with
    :meth:`verify`. The proof stores no message, private key, randomness or
    state and is a pure serialisation container: it offers neither
    authentication nor encryption of the wrapper itself, draws no randomness,
    generates no keys and keeps no state.

    .. warning::

        Teaching only, like everything in this module: the embedded toy
        signature is a stateless MAC tag, not a real lattice signature.
    """

    public_key: ToyLatticePublicKey
    signature: ToyLatticeSignature

    def __post_init__(self) -> None:
        if not isinstance(self.public_key, ToyLatticePublicKey):
            raise TypeError("public_key must be a ToyLatticePublicKey")
        if not isinstance(self.signature, ToyLatticeSignature):
            raise TypeError("signature must be a ToyLatticeSignature")

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 proof wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQALPF\\0\\0"``; one version byte
        (1); the public-key and signature lengths as 4 big-endian bytes each;
        then the existing v1 encodings of the public key and of the
        signature, in that order (the inner encodings are reused unchanged).
        Encoding is deterministic: the same proof always produces the same
        bytes. Neither the message, the private key, any randomness nor any
        state is carried. A field corrupted by bypassing the frozen
        constructor raises ``ValueError`` instead of producing malformed
        bytes.
        """
        if not isinstance(self, ToyLatticeProof):
            raise TypeError("to_bytes must be called on a ToyLatticeProof")
        try:
            key_bytes = self.public_key.to_bytes()
            signature_bytes = self.signature.to_bytes()
        except (TypeError, AttributeError) as exc:
            raise ValueError(f"corrupted proof field: {exc}") from exc
        return (
            _PROOF_MAGIC
            + bytes((_LATTICE_VERSION,))
            + len(key_bytes).to_bytes(_TAG_LENGTH_BYTES, "big")
            + len(signature_bytes).to_bytes(_TAG_LENGTH_BYTES, "big")
            + key_bytes
            + signature_bytes
        )

    @classmethod
    def from_bytes(cls, data: Any) -> "ToyLatticeProof":
        """Parse ``to_bytes()`` output back into a :class:`ToyLatticeProof`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. The embedded public key and signature are each
        recovered through their own existing v1 parsers, public key first.
        A bad magic, an unknown version, a length field that is out of bounds
        or disagrees with the actual content, truncation, trailing data, or
        an invalid nested public-key or signature encoding raises
        ``ValueError`` and no half-valid object is returned.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("proof data must be bytes or bytearray")
        data = bytes(data)
        if len(data) < _PROOF_HEADER_BYTES:
            raise ValueError("proof encoding is truncated")
        if data[:8] != _PROOF_MAGIC:
            raise ValueError("bad proof magic")
        if data[8] != _LATTICE_VERSION:
            raise ValueError(f"unsupported proof version: {data[8]}")
        key_length = int.from_bytes(data[9:13], "big")
        signature_length = int.from_bytes(data[13:17], "big")
        key_end = _PROOF_HEADER_BYTES + key_length
        signature_end = key_end + signature_length
        if key_length == 0 or signature_length == 0:
            raise ValueError("a length field must not be zero")
        if key_end > len(data) or signature_end > len(data):
            raise ValueError("proof encoding is truncated")
        if signature_end < len(data):
            raise ValueError("trailing data after the proof encoding")
        try:
            public_key = ToyLatticePublicKey.from_bytes(
                data[_PROOF_HEADER_BYTES:key_end]
            )
            signature = ToyLatticeSignature.from_bytes(data[key_end:signature_end])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid nested proof field encoding: {exc}") from exc
        return cls(public_key=public_key, signature=signature)

    def verify(self, message: Any, *, context: Any = None) -> bool:
        """Verify the embedded signature against the embedded public key.

        Accepts ``bytes``/``bytearray``/``str`` exactly like
        :func:`toy_lattice_verify`, to which this call delegates; it returns
        ``True`` only for the message that was actually signed with the key
        matching the embedded public key. Any change to the message, public
        key or signature, an illegal message type, or fields corrupted by
        bypassing the frozen constructor returns ``False`` instead of
        raising. The proof itself carries no message and cannot authenticate
        its own origin.

        ``context`` is keyword-only and optional: ``None`` (the default) and
        an empty value both mean "no context" and verify legacy unbound
        signatures; any other ``bytes``/``bytearray``/``str`` (``str`` encoded
        as UTF-8) must match the signing context exactly, else the signature
        fails to verify. A context of any other type raises ``TypeError``.
        """
        context_bytes = _validate_context(context)
        try:
            return toy_lattice_verify(
                message,
                self.signature,
                self.public_key,
                context=context_bytes,
            )
        except Exception:
            return False

    def verify_bound(
        self, message: Any, *, public_key: Any, context: Any = None
    ) -> bool:
        """Verify the signature and bind the proof to an expected public key.

        First requires ``public_key`` to equal the public key embedded in
        the proof, compared by value, then runs the exact verification of
        :meth:`verify` — ``message`` is checked against the embedded
        signature with :func:`toy_lattice_verify`, accepting
        ``bytes``/``bytearray``/``str`` (a ``str`` is encoded as UTF-8). No
        wire format changes, no new objects, no randomness and no state are
        involved.

        ``context`` is keyword-only and optional and follows the same rules
        as :meth:`verify`: ``None``/empty means no context, while a non-empty
        context must be the one used at signing; the wrong context makes the
        bound check return ``False``, and a context of a wrong type raises
        ``TypeError``.

        ``public_key`` must be a :class:`ToyLatticePublicKey`; any other
        type raises ``TypeError``. Missing or mistyped embedded fields
        (including values corrupted by bypassing the frozen constructor),
        any public-key value mismatch, and any message, context or signature
        mismatch return ``False`` without leaking any other exception.
        """
        if not isinstance(public_key, ToyLatticePublicKey):
            raise TypeError("public_key must be a ToyLatticePublicKey")
        context_bytes = _validate_context(context)
        try:
            embedded_key = self.public_key
            signature = self.signature
            if not isinstance(embedded_key, ToyLatticePublicKey):
                return False
            if embedded_key != public_key:
                return False
            return toy_lattice_verify(
                message, signature, embedded_key, context=context_bytes
            )
        except Exception:
            # A bypass-constructed proof may carry arbitrary field objects
            # whose access or comparison raises anything; the bound check
            # reports every such malformed structure as ``False``. External
            # argument type errors were raised before this block.
            return False


def _decode_key_field(data: Any, magic: bytes, label: str) -> bytes:
    """Validate a fixed-length public/private key blob and return its ``E`` field."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{label} data must be bytes or bytearray")
    data = bytes(data)
    if len(data) < _KEY_BYTES:
        raise ValueError(f"{label} encoding is truncated")
    if len(data) > _KEY_BYTES:
        raise ValueError(f"trailing data after the {label} encoding")
    if data[:8] != magic:
        raise ValueError(f"bad {label} magic")
    if data[8] != _LATTICE_VERSION:
        raise ValueError(f"unsupported {label} version: {data[8]}")
    field = data[9:_KEY_BYTES]
    _validate_e(field, label)
    return field


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


def toy_lattice_sign(
    message: Any,
    private_key: ToyLatticePrivateKey,
    *,
    token_bytes: Callable[[int], bytes] = secrets.token_bytes,
    context: Any = None,
) -> ToyLatticeSignature:
    """Sign ``message`` with ``private_key`` and return a :class:`ToyLatticeSignature`.

    The message may be ``bytes``, ``bytearray`` or ``str`` (UTF-8); any other
    type raises ``TypeError``, as does a ``private_key`` that is not a
    :class:`ToyLatticePrivateKey`. Eight random bytes ``r`` are drawn with
    ``token_bytes`` and used verbatim as the eight coefficients of the
    ``E``-encoded random vector ``u``; a source that returns anything other
    than ``bytes`` (including ``bytearray``) or not exactly eight bytes raises
    ``ValueError``. The chain key is
    ``K = SHA256(b"S" + u + message)`` and the 32-byte tag is
    ``HMAC-SHA256(K, b"S" + s)`` over the private vector. The key is never
    modified; different random sources may produce different signatures even
    for the same message and key.

    ``context`` is keyword-only and optional: ``None`` (the default) and an
    empty ``bytes``/``bytearray``/``str`` all mean "no context" and produce a
    signature byte-for-byte identical to the legacy unbound signature for the
    same private key, message and ``token_bytes`` output. A non-empty context
    (``str`` encoded as UTF-8) is bound into the chain key together with the
    message, so the signature verifies only when verifier and signer share
    both the message and the context; signing stays deterministic for the
    same key, message, context and randomness. A context of any other type
    raises ``TypeError``. The v1 wire format is unchanged — the context is
    not carried in the signature.
    """
    if not isinstance(private_key, ToyLatticePrivateKey):
        raise TypeError("private_key must be a ToyLatticePrivateKey")
    context_bytes = _validate_context(context)
    message = _as_bytes(message)
    raw = token_bytes(_TOKEN_BYTES)
    if not isinstance(raw, bytes):
        raise ValueError("token_bytes must return bytes")
    if len(raw) != _TOKEN_BYTES:
        raise ValueError(f"token_bytes must return {_TOKEN_BYTES} bytes")
    u = _encode_e(raw)
    chain = _chain_key(u, _context_message(context_bytes, message))
    tag = _signature_tag(chain, private_key.s)
    return ToyLatticeSignature(u=u, tag=tag)


def toy_lattice_verify(
    message: Any,
    signature: ToyLatticeSignature,
    public_key: ToyLatticePublicKey,
    *,
    context: Any = None,
) -> bool:
    """Check ``signature`` on ``message`` against ``public_key``.

    Re-derives the chain key ``K = SHA256(b"S" + u + message)`` from the
    signature's random vector and the message, recomputes the keyed tag over
    the public vector ``t`` and compares it in constant time with the carried
    tag. Only the original message together with the matching public key
    returns ``True``. A ``public_key`` that is not a :class:`ToyLatticePublicKey`
    raises ``TypeError``; every other problem — an unsupported message type, a
    ``signature`` that is not a :class:`ToyLatticeSignature`, malformed
    signature fields, or any content mismatch — returns ``False``.

    ``context`` is keyword-only and optional: ``None`` (the default) and an
    empty value both mean "no context" and accept only legacy unbound
    signatures; a non-empty ``bytes``/``bytearray``/``str`` (``str`` encoded as
    UTF-8) must be the very context the message was signed under, so a
    signature made under one context fails under any other context, and an
    unbound signature fails whenever a non-empty context is supplied. A
    context of any other type raises ``TypeError``; a context mismatch returns
    ``False`` like any other mismatch.
    """
    if not isinstance(public_key, ToyLatticePublicKey):
        raise TypeError("public_key must be a ToyLatticePublicKey")
    context_bytes = _validate_context(context)
    try:
        message = _as_bytes(message)
        if not isinstance(signature, ToyLatticeSignature):
            return False
        _validate_e(signature.u, "u")
        if not isinstance(signature.tag, bytes) or len(signature.tag) != _TAG_BYTES:
            return False
        chain = _chain_key(signature.u, _context_message(context_bytes, message))
        candidate = _signature_tag(chain, public_key.t)
        return hmac.compare_digest(candidate, signature.tag)
    except Exception:
        # A bypass-constructed signature may carry arbitrary field objects
        # whose access raises anything; every malformed structure verifies
        # False. External public-key and context type errors were raised
        # before this block.
        return False

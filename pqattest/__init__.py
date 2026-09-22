"""pqattest - hash-based one-time and few-times signatures, plus a toy KEM.

Public API: keygen / public_key_from / sign / verify / message_bits /
OneTimeSigner / KeyExhaustedError, with a deterministic, versioned v1 binary
codec for the Lamport keys and stateless signatures:
PrivateKey.to_bytes / PrivateKey.from_bytes,
PublicKey.to_bytes / PublicKey.from_bytes,
lamport_signature_to_bytes / lamport_signature_from_bytes, and a versioned
state checkpoint for the signer: OneTimeSigner.checkpoint /
OneTimeSigner.from_checkpoint; the Winternitz
construction: wots_keygen / wots_sign / wots_verify / WOTSPrivateKey /
WOTSPublicKey / WOTSOneTimeSigner / wots_signature_to_bytes /
wots_signature_from_bytes, Merkle-aggregated W-OTS: MerkleSigner /
MerklePublicKey / MerkleSignature / MerkleProof / MerkleBatchProof /
merkle_verify / multiproof_encode / multiproof_verify, static
parameter analysis: Params / profile / recommend / recommend_merkle_deployment /
merkle_deployment_frontier /
MerkleStorageProfile / merkle_storage_profile / merkle_transport_profile /
recommend_merkle_transport_deployment / MerkleTransportDeploymentProfile /
merkle_transport_deployment_frontier /
recommend_merkle_transport_workload / MerkleTransportWorkloadProfile /
merkle_transport_workload_frontier / merkle_mode_frontier /
recommend_merkle_mode_deployment, and
the teaching-only toy lattice KEM: toy_lattice_keygen / toy_lattice_encapsulate /
toy_lattice_decapsulate / ToyLatticePublicKey / ToyLatticePrivateKey /
ToyLatticeCiphertext. The three plaintext signer checkpoints can be sealed
in a keyed HMAC-SHA-256 envelope with auth_wrap / auth_unwrap; a v2
envelope with auth_state_wrap / auth_state_unwrap additionally binds a
uint64 generation so an externally tracked floor can detect rollback.
Both envelopes authenticate but do not encrypt and give no replay
protection on their own.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from ._errors import KeyExhaustedError
from .auth import (
    _validate_generation,
    _validate_key,
    auth_state_unwrap,
    auth_state_wrap,
    auth_unwrap,
    auth_wrap,
)
from .merkle import (
    MerkleBatchProof,
    MerkleProof,
    MerklePublicKey,
    MerkleSignature,
    MerkleSigner,
    merkle_verify,
    multiproof_encode,
    multiproof_verify,
)
from .params import (
    MerkleStorageProfile,
    MerkleTransportDeploymentProfile,
    MerkleTransportWorkloadProfile,
    Params,
    merkle_storage_profile,
    merkle_transport_profile,
    merkle_transport_deployment_frontier,
    merkle_transport_workload_frontier,
    merkle_mode_frontier,
    profile,
    recommend,
    recommend_merkle_deployment,
    merkle_deployment_frontier,
    recommend_merkle_mode_deployment,
    recommend_merkle_transport_deployment,
    recommend_merkle_transport_workload,
)
from .toy_lattice import (
    ToyLatticeCiphertext,
    ToyLatticePrivateKey,
    ToyLatticePublicKey,
    toy_lattice_decapsulate,
    toy_lattice_encapsulate,
    toy_lattice_keygen,
)
from .wots import (
    ELEMENT_BYTES,
    WOTSOneTimeSigner,
    WOTSPrivateKey,
    WOTSPublicKey,
    wots_keygen,
    wots_sign,
    wots_signature_from_bytes,
    wots_signature_to_bytes,
    wots_verify,
)

__all__ = [
    "BITS",
    "ELEMENT_BYTES",
    "HASH_BYTES",
    "KeyExhaustedError",
    "MerkleBatchProof",
    "MerkleProof",
    "MerklePublicKey",
    "MerkleSignature",
    "MerkleSigner",
    "MerkleStorageProfile",
    "MerkleTransportDeploymentProfile",
    "MerkleTransportWorkloadProfile",
    "OneTimeSigner",
    "Params",
    "PrivateKey",
    "PublicKey",
    "ToyLatticeCiphertext",
    "ToyLatticePrivateKey",
    "ToyLatticePublicKey",
    "WOTSOneTimeSigner",
    "WOTSPrivateKey",
    "WOTSPublicKey",
    "auth_state_unwrap",
    "auth_state_wrap",
    "auth_unwrap",
    "auth_wrap",
    "keygen",
    "lamport_signature_from_bytes",
    "lamport_signature_to_bytes",
    "merkle_verify",
    "merkle_deployment_frontier",
    "merkle_storage_profile",
    "merkle_transport_profile",
    "merkle_transport_deployment_frontier",
    "merkle_transport_workload_frontier",
    "merkle_mode_frontier",
    "message_bits",
    "message_digest",
    "multiproof_encode",
    "multiproof_verify",
    "profile",
    "public_key_from",
    "recommend",
    "recommend_merkle_deployment",
    "recommend_merkle_transport_deployment",
    "recommend_merkle_transport_workload",
    "recommend_merkle_mode_deployment",
    "sign",
    "toy_lattice_decapsulate",
    "toy_lattice_encapsulate",
    "toy_lattice_keygen",
    "verify",
    "wots_keygen",
    "wots_sign",
    "wots_signature_from_bytes",
    "wots_signature_to_bytes",
    "wots_verify",
]

BITS = 256
HASH_BYTES = 32
_DOMAIN = b"pqattest/lamport/v1"

_PRIVATE_KEY_MAGIC = b"PQALPRV\0"
_PUBLIC_KEY_MAGIC = b"PQALPUB\0"
_SIGNATURE_MAGIC = b"PQALSIG\0"
_CODEC_VERSION = 1
_CODEC_HEADER_BYTES = 8 + 1 + 2 + 2

_CHECKPOINT_MAGIC = b"PQALCP\0\0"
_CHECKPOINT_VERSION = 1
_CHECKPOINT_HEADER_BYTES = 8 + 1 + 1 + 4
_CHECKPOINT_CHECKSUM_BYTES = 32


def _validate_bits(bits: Any) -> int:
    if isinstance(bits, bool) or not isinstance(bits, int) or not 1 <= bits <= BITS:
        raise ValueError(f"bits must be a non-boolean integer between 1 and {BITS}")
    return bits


def _validate_container(elements: Any, label: str) -> None:
    if not isinstance(elements, tuple):
        raise TypeError(f"{label} collection must be a tuple of {HASH_BYTES}-byte values")
    for element in elements:
        if not isinstance(element, bytes):
            raise TypeError(f"every {label} must be bytes")
        if len(element) != HASH_BYTES:
            raise ValueError(f"every {label} must be exactly {HASH_BYTES} bytes")


def _encode_v1(magic: bytes, bits: int, elements: tuple[bytes, ...]) -> bytes:
    """Shared v1 layout: magic, version, ``bits``, element count, elements."""
    return (
        magic
        + bytes((_CODEC_VERSION,))
        + bits.to_bytes(2, "big")
        + len(elements).to_bytes(2, "big")
        + b"".join(elements)
    )


def _decode_v1(data: Any, magic: bytes, name: str, *, is_key: bool) -> tuple[int, tuple[bytes, ...]]:
    """Parse a v1 blob into ``(bits, elements)``; ``name`` labels errors.

    Keys carry ``2 * bits`` elements, signatures carry ``bits``.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{name} data must be bytes or bytearray")
    data = bytes(data)
    if len(data) < _CODEC_HEADER_BYTES:
        raise ValueError(f"{name} encoding is truncated")
    if data[:8] != magic:
        raise ValueError(f"bad {name} magic")
    if data[8] != _CODEC_VERSION:
        raise ValueError(f"unsupported {name} version: {data[8]}")
    bits = int.from_bytes(data[9:11], "big")
    _validate_bits(bits)
    element_count = int.from_bytes(data[11:13], "big")
    expected_count = 2 * bits if is_key else bits
    if element_count != expected_count:
        raise ValueError("element count does not match bits")
    expected_length = _CODEC_HEADER_BYTES + element_count * HASH_BYTES
    if len(data) < expected_length:
        raise ValueError(f"{name} encoding is truncated")
    if len(data) > expected_length:
        raise ValueError(f"trailing data after the {name} encoding")
    elements = tuple(
        data[_CODEC_HEADER_BYTES + i * HASH_BYTES : _CODEC_HEADER_BYTES + (i + 1) * HASH_BYTES]
        for i in range(element_count)
    )
    return bits, elements


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


def _key_to_bytes(key: Any, key_type: type, field_name: str, magic: bytes, label: str) -> bytes:
    if not isinstance(key, key_type):
        raise TypeError(f"to_bytes must be called on a {key_type.__name__}")
    elements = getattr(key, field_name, None)
    _validate_container(elements, label)
    bits = len(elements) // 2
    _validate_bits(bits)
    if len(elements) != 2 * bits:
        raise ValueError("key must contain exactly 2 * bits elements")
    return _encode_v1(magic, bits, elements)


@dataclass(frozen=True)
class PrivateKey:
    """``2 * bits`` secret values: index ``2 * i + b`` belongs to bit ``i``, branch ``b``."""

    secrets: tuple[bytes, ...]

    @property
    def bits(self) -> int:
        return len(self.secrets) // 2

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQALPRV\\0"``; the version byte
        (1); ``bits`` and the element count (``2 * bits``) as 2 big-endian
        bytes each; then every secret in its original position, 32 bytes
        each. Encoding is deterministic: the same key always produces the
        same bytes. A field corrupted by bypassing the frozen value shape —
        a non-tuple container or non-``bytes`` members — raises ``TypeError``;
        an out-of-range ``bits``, a wrong element count or a member that is
        not exactly 32 bytes raises ``ValueError``. The blob contains the
        private secrets in the clear — store it as a secret.
        """
        return _key_to_bytes(self, PrivateKey, "secrets", _PRIVATE_KEY_MAGIC, "private secret")

    @classmethod
    def from_bytes(cls, data: Any) -> "PrivateKey":
        """Parse ``to_bytes()`` output back into a :class:`PrivateKey`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, an out-of-range
        ``bits`` value, an element count that is not ``2 * bits``,
        truncation or trailing data raises ``ValueError`` and no instance is
        returned. The restored key is equal by value to the original.
        """
        _bits, secrets = _decode_v1(data, _PRIVATE_KEY_MAGIC, "private key", is_key=True)
        return cls(secrets)


@dataclass(frozen=True)
class PublicKey:
    """One-way images of the private secrets, in the same order."""

    digests: tuple[bytes, ...]

    @property
    def bits(self) -> int:
        return len(self.digests) // 2

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQALPUB\\0"``; the version byte
        (1); ``bits`` and the element count (``2 * bits``) as 2 big-endian
        bytes each; then every digest in its original position, 32 bytes
        each. Encoding is deterministic: the same key always produces the
        same bytes. A field corrupted by bypassing the frozen value shape —
        a non-tuple container or non-``bytes`` members — raises ``TypeError``;
        an out-of-range ``bits`` value, a wrong element count or a member
        that is not exactly 32 bytes raises ``ValueError``.
        """
        return _key_to_bytes(self, PublicKey, "digests", _PUBLIC_KEY_MAGIC, "public digest")

    @classmethod
    def from_bytes(cls, data: Any) -> "PublicKey":
        """Parse ``to_bytes()`` output back into a :class:`PublicKey`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, an out-of-range
        ``bits`` value, an element count that is not ``2 * bits``,
        truncation or trailing data raises ``ValueError`` and no instance is
        returned. The restored key is equal by value to the original.
        """
        _bits, digests = _decode_v1(data, _PUBLIC_KEY_MAGIC, "public key", is_key=True)
        return cls(digests)


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


class OneTimeSigner:
    """Thread-safe, single-use wrapper around a :class:`PrivateKey`.

    The first :meth:`sign` call returns the ordinary Lamport signature and
    marks the key as used; every later call raises :class:`KeyExhaustedError`.
    The guard is per instance and per process — copying the private key,
    calling the stateless :func:`sign` directly or reusing the key in another
    process is the caller's responsibility. State can be persisted with
    :meth:`checkpoint` and restored in another process with
    :meth:`from_checkpoint`; the checkpoint contains the private key in the
    clear and is protected only by a SHA-256 checksum against accidental
    corruption, so callers must store it securely.
    """

    __slots__ = ("_lock", "_private_key", "_public_key", "_used")

    def __init__(self, private_key: PrivateKey) -> None:
        if not isinstance(private_key, PrivateKey):
            raise TypeError("private_key must be a PrivateKey")
        self._restore_state(private_key, public_key_from(private_key), False)

    def _restore_state(
        self,
        private_key: PrivateKey,
        public_key: PublicKey,
        used: bool,
    ) -> None:
        self._lock = threading.Lock()
        self._private_key = private_key
        self._public_key = public_key
        self._used = used

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

    def _checkpoint_bytes(self) -> bytes:
        """Serialise the signer state; the caller holds the lock."""
        key_blob = self._private_key.to_bytes()
        body = (
            _CHECKPOINT_MAGIC
            + bytes((_CHECKPOINT_VERSION, int(self._used)))
            + len(key_blob).to_bytes(4, "big")
            + key_blob
        )
        return body + hashlib.sha256(body).digest()

    def checkpoint(self) -> bytes:
        """Serialise the signer state (private key plus ``used``) to ``bytes``.

        The v1 layout is: the 8-byte magic ``b"PQALCP\\0\\0"``; one byte each
        for the version (1) and ``used`` (0 or 1); the length of the nested
        private key encoding as 4 big-endian bytes; the complete
        :meth:`PrivateKey.to_bytes` output; and finally the SHA-256 of all
        preceding content. Encoding is deterministic: the same state always
        produces the same bytes.

        The checkpoint shares the signing lock, so a concurrent snapshot
        reflects the state either immediately before or immediately after an
        in-flight :meth:`sign`, never part-way through one. The blob contains
        the private key in the clear and the trailing hash only detects
        accidental corruption — it provides neither authentication nor
        encryption, so store it as a secret.
        """
        with self._lock:
            return self._checkpoint_bytes()

    def sign_with_auth_state(
        self, message: Any, *, key: Any, generation: Any
    ) -> tuple[tuple[bytes, ...], bytes]:
        """Sign once and return the advanced state as a v2 auth envelope.

        Behaves like :meth:`sign` — same ``bytes``/``bytearray``/``str``
        message rules, same one-time Lamport signature and the same post-sign
        ``used=True`` state, all under the signing lock — but instead of the
        signature alone it returns ``(signature, envelope)``: the first half
        is the ordinary immutable signature tuple that :meth:`sign` returns,
        and the second is the :func:`auth_state_wrap` v2 envelope (``bytes``)
        over the v1 :meth:`checkpoint` bytes of the used state with
        ``scheme="lamport"`` and the given ``key`` and ``generation``. The
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
        :class:`KeyExhaustedError`. Every failure leaves ``used`` untouched
        and returns no partial result. The whole call — signature, ``used``
        flip, snapshot and wrapping — linearises with :meth:`sign` and
        :meth:`checkpoint` under the same lock, at most one concurrent caller
        succeeds, and no randomness is drawn. The envelope is plaintext and
        authenticated only; it provides neither encryption nor protection
        against replay or rollback on its own.
        """
        message = _as_bytes(message)
        key_bytes = _validate_key(key)
        generation_value = _validate_generation(generation, "generation")
        with self._lock:
            if self._used:
                raise KeyExhaustedError("this one-time signing key has already been used")
            signature = sign(message, self._private_key)
            self._used = True
            checkpoint = self._checkpoint_bytes()
            envelope = auth_state_wrap(
                checkpoint,
                scheme="lamport",
                key=key_bytes,
                generation=generation_value,
            )
            return signature, envelope

    @classmethod
    def from_checkpoint(cls, data: Any) -> "OneTimeSigner":
        """Restore a signer from ``checkpoint()`` output without randomness.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, a ``used`` flag that
        is not 0 or 1, a private key length field that does not match the
        content, an invalid nested private key encoding, truncation, trailing
        data or a checksum mismatch raises ``ValueError`` and no instance is
        returned. The private key and the public key rebuilt from it are
        identical to the original's, so a restored unused signer still allows
        exactly one signature and a checkpoint taken after signing restores a
        signer whose every call raises :class:`KeyExhaustedError`.
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
        used_byte = body[9]
        if used_byte not in (0, 1):
            raise ValueError("used flag must be 0 or 1")
        key_length = int.from_bytes(body[10:14], "big")
        if len(body) != header + key_length:
            raise ValueError("private key length field does not match the checkpoint length")
        if hashlib.sha256(body).digest() != checksum:
            raise ValueError("checkpoint checksum mismatch")
        try:
            private_key = PrivateKey.from_bytes(body[header:])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid nested private key encoding: {exc}") from exc
        signer = cls.__new__(cls)
        signer._restore_state(private_key, public_key_from(private_key), bool(used_byte))
        return signer


def lamport_signature_to_bytes(signature: Any, *, bits: int) -> bytes:
    """Serialise a stateless Lamport signature to the versioned v1 wire format.

    ``signature`` must be a ``tuple`` whose members are all ``bytes`` — the
    shape :func:`sign` returns; a non-tuple container or a non-``bytes``
    member raises ``TypeError``. ``bits`` is keyword-only and must be a
    non-boolean integer between 1 and 256; the signature must contain
    exactly ``bits`` elements and every element must be exactly 32 bytes,
    else ``ValueError``.

    The layout is the 8-byte magic ``b"PQALSIG\\0"``; the version byte (1);
    ``bits`` and the element count (equal to ``bits``) as 2 big-endian
    bytes each; then every signature element in its original order, 32
    bytes each. Encoding is deterministic: the same signature and ``bits``
    always produce the same bytes.
    """
    if not isinstance(signature, tuple):
        raise TypeError("signature must be a tuple of 32-byte values")
    for element in signature:
        if not isinstance(element, bytes):
            raise TypeError("every signature element must be bytes")
    bits = _validate_bits(bits)
    if len(signature) != bits:
        raise ValueError(f"signature must contain exactly {bits} elements")
    for element in signature:
        if len(element) != HASH_BYTES:
            raise ValueError(f"every signature element must be exactly {HASH_BYTES} bytes")
    return _encode_v1(_SIGNATURE_MAGIC, bits, signature)


def lamport_signature_from_bytes(data: Any) -> tuple[int, tuple[bytes, ...]]:
    """Parse :func:`lamport_signature_to_bytes` output back into ``(bits, elements)``.

    ``data`` must be ``bytes`` or ``bytearray``; anything else raises
    ``TypeError``. A bad magic, an unknown version, an out-of-range
    ``bits`` value, an element count that is not ``bits``, truncation or
    trailing data raises ``ValueError``. The returned ``bits`` is an
    ``int`` and ``elements`` is an immutable ``tuple`` of 32-byte
    ``bytes`` in their original order, ready for :func:`verify`.
    """
    return _decode_v1(data, _SIGNATURE_MAGIC, "signature", is_key=False)

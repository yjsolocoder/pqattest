"""Merkle-tree aggregation of W-OTS keys: a few-times signature scheme.

A :class:`MerkleSigner` generates ``2 ** height`` W-OTS key pairs up front and
commits to every public key in a Merkle tree. The tree root is the single
long-term public key; each signature spends one leaf (one W-OTS key pair) and
carries the authentication path from that leaf to the root. Only the standard
library is used. Public keys and signatures have a versioned binary wire
format via ``to_bytes`` / ``from_bytes`` (the signature codec is constrained
by the corresponding :class:`MerklePublicKey`). A :class:`MerkleProof`
bundles one public key and one signature for independent transport, and a
:class:`MerkleBatchProof` does the same for several signatures of the same
public key. The top-level :func:`multiproof_encode` /
:func:`multiproof_verify` pair compresses several signatures of the same
public key further into one deterministic proof whose shared authentication
nodes are deduplicated into a canonical node set. Signer
state can be persisted explicitly with
:meth:`MerkleSigner.checkpoint` /
:meth:`MerkleSigner.from_checkpoint`; the checkpoint contains every private
key and is protected only by a SHA-256 checksum against accidental
corruption, so callers must store it securely.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Callable

from ._errors import KeyExhaustedError
from .auth import _validate_generation, _validate_key, auth_state_wrap
from .wots import (
    ELEMENT_BYTES,
    WOTSPrivateKey,
    _as_bytes,
    _chain_walk,
    _params,
    _signing_digits,
    _validate_w,
    wots_keygen,
    wots_sign,
)

__all__ = [
    "MerkleBatchProof",
    "MerkleProof",
    "MerklePublicKey",
    "MerkleSignature",
    "MerkleSigner",
    "merkle_verify",
    "multiproof_encode",
    "multiproof_verify",
]

_LEAF_DOMAIN = b"pqattest/leaf"
_NODE_DOMAIN = b"pqattest/node"
_MIN_HEIGHT = 1
_MAX_HEIGHT = 8

_PROOF_MAGIC = b"PQAMPRF\0"
_PROOF_VERSION = 1
_PROOF_HEADER_BYTES = 8 + 1 + 4 + 4

_BATCH_PROOF_MAGIC = b"PQAMBAT\0"
_BATCH_PROOF_VERSION = 1
_BATCH_PROOF_HEADER_BYTES = 8 + 1 + 4 + 2
_MAX_BATCH_SIGNATURES = 0xFFFF

_MULTIPROOF_MAGIC = b"PQAMMUL\0"
_MULTIPROOF_VERSION = 1
_MULTIPROOF_HEADER_BYTES = 8 + 1 + 4 + 2 + 2
_MULTIPROOF_NODE_BYTES = 1 + 2 + ELEMENT_BYTES
_MAX_MULTIPROOF_LEAVES = 0xFFFF
_MAX_MULTIPROOF_NODES = 0xFFFF
_MAX_MULTIPROOF_LEVEL = 0xFF

_CHECKPOINT_MAGIC = b"PQAMSCP\0"
_CHECKPOINT_VERSION = 1
_CHECKPOINT_HEADER_BYTES = 8 + 1 + 1 + 1 + 2 + 4 + ELEMENT_BYTES
_CHECKPOINT_CHECKSUM_BYTES = 32

_PUBLIC_KEY_MAGIC = b"PQAMPK\0\0"
_PUBLIC_KEY_VERSION = 1
_PUBLIC_KEY_BYTES = 8 + 1 + 1 + 1 + ELEMENT_BYTES

_SIGNATURE_MAGIC = b"PQAMSIG\0"
_SIGNATURE_VERSION = 1
_SIGNATURE_HEADER_BYTES = 8 + 1 + 1 + 1 + 2 + 2 + 1


def _validate_height(height: Any) -> int:
    if (
        isinstance(height, bool)
        or not isinstance(height, int)
        or not _MIN_HEIGHT <= height <= _MAX_HEIGHT
    ):
        raise ValueError(
            f"height must be an integer between {_MIN_HEIGHT} and {_MAX_HEIGHT}"
        )
    return height


def _validate_nodes(name: str, nodes: Any) -> None:
    if not isinstance(nodes, tuple):
        raise TypeError(f"{name} must be a tuple of {ELEMENT_BYTES}-byte values")
    for node in nodes:
        if not isinstance(node, bytes) or len(node) != ELEMENT_BYTES:
            raise ValueError(f"every {name} node must be exactly {ELEMENT_BYTES} bytes")


def _nodes_well_formed(nodes: Any) -> bool:
    """Non-raising counterpart of :func:`_validate_nodes` for verification."""
    return isinstance(nodes, tuple) and all(
        isinstance(node, bytes) and len(node) == ELEMENT_BYTES for node in nodes
    )


def _leaf_hash(w: int, elements: tuple[bytes, ...]) -> bytes:
    return hashlib.sha256(_LEAF_DOMAIN + bytes([w]) + b"".join(elements)).digest()


def _signature_params(public_key: MerklePublicKey) -> tuple[int, int, int]:
    """Return ``(w, height, chains)`` constraining a signature encoding."""
    w = _validate_w(public_key.w)
    height = _validate_height(public_key.height)
    _, l1, l2 = _params(w)
    return w, height, l1 + l2



def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_DOMAIN + left + right).digest()


@dataclass(frozen=True)
class MerklePublicKey:
    """Frozen Merkle public key: Winternitz parameter, tree height and root."""

    w: int
    height: int
    root: bytes

    def __post_init__(self) -> None:
        _validate_w(self.w)
        _validate_height(self.height)
        if not isinstance(self.root, bytes) or len(self.root) != ELEMENT_BYTES:
            raise ValueError(f"root must be exactly {ELEMENT_BYTES} bytes")

    @property
    def leaf_count(self) -> int:
        """Number of W-OTS leaves (signatures) this key commits to."""
        return 1 << self.height

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQAMPK\\0\\0"``, one byte each for
        the version (1), ``w`` and ``height``, and the 32-byte root — 43 bytes
        in total. Encoding is deterministic: the same key always produces the
        same bytes. Fields corrupted by bypassing the frozen constructor
        raise ``ValueError`` instead of producing a malformed encoding.
        """
        if not isinstance(self, MerklePublicKey):
            raise TypeError("to_bytes must be called on a MerklePublicKey")
        _validate_w(self.w)
        _validate_height(self.height)
        if not isinstance(self.root, bytes) or len(self.root) != ELEMENT_BYTES:
            raise ValueError(f"root must be exactly {ELEMENT_BYTES} bytes")
        return (
            _PUBLIC_KEY_MAGIC
            + bytes((_PUBLIC_KEY_VERSION, self.w, self.height))
            + self.root
        )

    @classmethod
    def from_bytes(cls, data: Any) -> "MerklePublicKey":
        """Parse ``to_bytes()`` output back into a :class:`MerklePublicKey`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, a truncated or
        over-long encoding, or invalid ``w``/``height``/root fields raises
        ``ValueError`` and no instance is returned.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("public key data must be bytes or bytearray")
        data = bytes(data)
        if len(data) < _PUBLIC_KEY_BYTES:
            raise ValueError("public key encoding is truncated")
        if len(data) > _PUBLIC_KEY_BYTES:
            raise ValueError("trailing data after the public key encoding")
        if data[:8] != _PUBLIC_KEY_MAGIC:
            raise ValueError("bad public key magic")
        if data[8] != _PUBLIC_KEY_VERSION:
            raise ValueError(f"unsupported public key version: {data[8]}")
        return cls(w=data[9], height=data[10], root=data[11:_PUBLIC_KEY_BYTES])


@dataclass(frozen=True)
class MerkleSignature:
    """Frozen Merkle signature: leaf index, W-OTS signature, auth path.

    ``auth_path`` lists the sibling nodes from the leaf level up to the level
    just below the root; every node is 32 bytes.
    """

    index: int
    wots_signature: tuple[bytes, ...]
    auth_path: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if (
            isinstance(self.index, bool)
            or not isinstance(self.index, int)
            or self.index < 0
        ):
            raise ValueError("index must be a non-negative integer")
        _validate_nodes("wots_signature", self.wots_signature)
        _validate_nodes("auth_path", self.auth_path)

    def to_bytes(self, public_key: MerklePublicKey) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The signature carries no parameters of its own, so ``public_key``
        supplies — and constrains — them: the encoding stores the key's ``w``
        and ``height``, and the signature must match them (index below
        ``2 ** height``, as many W-OTS elements as ``w`` has chains, and an
        authentication path exactly ``height`` nodes long). The layout is the
        8-byte magic ``b"PQAMSIG\\0"``; one byte each for the version (1),
        ``w`` and ``height``; the index and the W-OTS element count as 2
        big-endian bytes each; the path count as 1 byte; then every signature
        element followed by the authentication path from the leaf level
        upwards, 32 bytes each. Encoding is deterministic. A wrong
        ``public_key`` type raises ``TypeError``; a signature inconsistent
        with the key (or corrupted by bypassing the frozen constructor)
        raises ``ValueError``.
        """
        if not isinstance(self, MerkleSignature):
            raise TypeError("to_bytes must be called on a MerkleSignature")
        if not isinstance(public_key, MerklePublicKey):
            raise TypeError("public_key must be a MerklePublicKey")
        w, height, chains = _signature_params(public_key)
        index = self.index
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise ValueError("index must be a non-negative integer")
        if index >= (1 << height):
            raise ValueError("index is out of range for the public key's tree height")
        _validate_nodes("wots_signature", self.wots_signature)
        _validate_nodes("auth_path", self.auth_path)
        if len(self.wots_signature) != chains:
            raise ValueError("wots_signature length does not match the chain count")
        if len(self.auth_path) != height:
            raise ValueError("auth_path length does not match the tree height")
        return (
            _SIGNATURE_MAGIC
            + bytes((_SIGNATURE_VERSION, w, height))
            + index.to_bytes(2, "big")
            + chains.to_bytes(2, "big")
            + bytes((height,))
            + b"".join(self.wots_signature)
            + b"".join(self.auth_path)
        )

    @classmethod
    def from_bytes(cls, data: Any, public_key: MerklePublicKey) -> "MerkleSignature":
        """Parse ``to_bytes()`` output back into a :class:`MerkleSignature`.

        ``public_key`` constrains the expected parameters: the encoded ``w``
        and ``height`` must equal the key's, the index must be below
        ``2 ** height``, the element count must equal the chain count for
        ``w`` and the path count must equal ``height``. ``data`` must be
        ``bytes`` or ``bytearray`` and ``public_key`` a
        :class:`MerklePublicKey`; other types raise ``TypeError``. A bad
        magic, an unknown version, a parameter mismatch, a wrong count, an
        out-of-range index, truncation or trailing data raises ``ValueError``
        and no instance is returned.
        """
        if not isinstance(public_key, MerklePublicKey):
            raise TypeError("public_key must be a MerklePublicKey")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("signature data must be bytes or bytearray")
        data = bytes(data)
        w, height, chains = _signature_params(public_key)
        if len(data) < _SIGNATURE_HEADER_BYTES:
            raise ValueError("signature encoding is truncated")
        if data[:8] != _SIGNATURE_MAGIC:
            raise ValueError("bad signature magic")
        if data[8] != _SIGNATURE_VERSION:
            raise ValueError(f"unsupported signature version: {data[8]}")
        if data[9] != w:
            raise ValueError("encoded w does not match the public key")
        if data[10] != height:
            raise ValueError("encoded height does not match the public key")
        index = int.from_bytes(data[11:13], "big")
        element_count = int.from_bytes(data[13:15], "big")
        path_count = data[15]
        if index >= (1 << height):
            raise ValueError("index is out of range for the public key's tree height")
        if element_count != chains:
            raise ValueError("element count does not match the chain count")
        if path_count != height:
            raise ValueError("path count does not match the tree height")
        expected = _SIGNATURE_HEADER_BYTES + (element_count + path_count) * ELEMENT_BYTES
        if len(data) < expected:
            raise ValueError("signature encoding is truncated")
        if len(data) > expected:
            raise ValueError("trailing data after the signature encoding")
        offset = _SIGNATURE_HEADER_BYTES
        wots_signature = tuple(
            data[offset + i * ELEMENT_BYTES : offset + (i + 1) * ELEMENT_BYTES]
            for i in range(element_count)
        )
        offset += element_count * ELEMENT_BYTES
        auth_path = tuple(
            data[offset + i * ELEMENT_BYTES : offset + (i + 1) * ELEMENT_BYTES]
            for i in range(path_count)
        )
        return cls(index=index, wots_signature=wots_signature, auth_path=auth_path)


@dataclass(frozen=True)
class MerkleProof:
    """Frozen, self-contained bundle of one Merkle public key and one signature.

    Unlike :class:`MerkleSignature` (whose wire format needs the
    corresponding key separately), a proof carries the
    :class:`MerklePublicKey` that constrains its :class:`MerkleSignature`, so
    it can be transported on its own and verified with :meth:`verify`. The
    proof stores no message and is a pure serialisation container: it offers
    neither authentication nor encryption of the wrapper itself.
    """

    public_key: MerklePublicKey
    signature: MerkleSignature

    def __post_init__(self) -> None:
        if not isinstance(self.public_key, MerklePublicKey):
            raise TypeError("public_key must be a MerklePublicKey")
        if not isinstance(self.signature, MerkleSignature):
            raise TypeError("signature must be a MerkleSignature")
        if not _signature_matches_key(self.signature, self.public_key):
            raise ValueError("signature is not consistent with the public key")

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 proof wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQAMPRF\\0"``; one version byte
        (1); the public-key and signature lengths as 4 big-endian bytes each;
        then the existing v1 encodings of the public key and of the signature
        constrained by that key, in that order. Encoding is deterministic: the
        same proof always produces the same bytes.
        """
        if not isinstance(self, MerkleProof):
            raise TypeError("to_bytes must be called on a MerkleProof")
        key_bytes = self.public_key.to_bytes()
        signature_bytes = self.signature.to_bytes(self.public_key)
        return (
            _PROOF_MAGIC
            + bytes((_PROOF_VERSION,))
            + len(key_bytes).to_bytes(4, "big")
            + len(signature_bytes).to_bytes(4, "big")
            + key_bytes
            + signature_bytes
        )

    @classmethod
    def from_bytes(cls, data: Any) -> "MerkleProof":
        """Parse ``to_bytes()`` output back into a :class:`MerkleProof`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. The embedded public key is recovered first and then
        constrains the signature. A bad magic, an unknown version, a length
        field that is out of bounds or disagrees with the actual content,
        truncation, trailing data, an invalid nested encoding, or a signature
        inconsistent with the key (wrong parameters or counts) raises
        ``ValueError`` and no half-valid object is returned.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("proof data must be bytes or bytearray")
        data = bytes(data)
        if len(data) < _PROOF_HEADER_BYTES:
            raise ValueError("proof encoding is truncated")
        if data[:8] != _PROOF_MAGIC:
            raise ValueError("bad proof magic")
        if data[8] != _PROOF_VERSION:
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
        public_key = MerklePublicKey.from_bytes(data[_PROOF_HEADER_BYTES:key_end])
        signature = MerkleSignature.from_bytes(
            data[key_end:signature_end], public_key
        )
        return cls(public_key=public_key, signature=signature)

    def verify(self, message: Any) -> bool:
        """Verify the embedded signature against the embedded public key.

        Accepts ``bytes``/``bytearray``/``str`` exactly like
        :func:`merkle_verify`, to which this call delegates; it returns
        ``True`` only for the message that was actually signed. The proof
        itself carries no message and cannot authenticate its own origin.
        """
        return merkle_verify(message, self.signature, self.public_key)


def _signature_matches_key(signature: MerkleSignature, public_key: MerklePublicKey) -> bool:
    """Non-raising check mirroring the constraints enforced by ``to_bytes``."""
    try:
        w, height, chains = _signature_params(public_key)
        index = signature.index
        wots_signature = signature.wots_signature
        auth_path = signature.auth_path
    except (ValueError, AttributeError):
        return False
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        return False
    if index >= (1 << height):
        return False
    if not _nodes_well_formed(wots_signature):
        return False
    if not _nodes_well_formed(auth_path):
        return False
    if len(wots_signature) != chains:
        return False
    if len(auth_path) != height:
        return False
    return True


def _validate_batch_fields(public_key: Any, signatures: Any) -> None:
    """Enforce the :class:`MerkleBatchProof` field types and structure."""
    if not isinstance(public_key, MerklePublicKey):
        raise TypeError("public_key must be a MerklePublicKey")
    if not isinstance(signatures, tuple):
        raise TypeError("signatures must be a tuple of MerkleSignature")
    for signature in signatures:
        if not isinstance(signature, MerkleSignature):
            raise TypeError("every signature must be a MerkleSignature")
    if not signatures:
        raise ValueError("signatures must not be empty")
    for signature in signatures:
        if not _signature_matches_key(signature, public_key):
            raise ValueError("signature is not consistent with the public key")
    indices = [signature.index for signature in signatures]
    if any(former >= latter for former, latter in zip(indices, indices[1:])):
        raise ValueError("signature indices must be strictly increasing and unique")


@dataclass(frozen=True)
class MerkleBatchProof:
    """Frozen bundle of one Merkle public key and several of its signatures.

    The batch generalises :class:`MerkleProof`: every
    :class:`MerkleSignature` in ``signatures`` is constrained by the same
    :class:`MerklePublicKey`, so the whole batch travels as one
    self-contained object and verifies with :meth:`verify`. ``signatures``
    must be a non-empty tuple whose leaf indices are strictly increasing
    (hence unique). The batch stores no messages and is a pure
    serialisation container: it offers neither authentication nor
    encryption of the wrapper itself.
    """

    public_key: MerklePublicKey
    signatures: tuple[MerkleSignature, ...]

    def __post_init__(self) -> None:
        _validate_batch_fields(self.public_key, self.signatures)

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 batch wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQAMBAT\\0"``; one version byte
        (1); the public-key length as 4 big-endian bytes; the signature
        count as 2 big-endian bytes; the complete v1 encoding of the
        public key; then, in tuple order, each signature's length as 4
        big-endian bytes followed by its existing v1 encoding constrained
        by that key. Encoding is deterministic: the same batch always
        produces the same bytes. Fields corrupted by bypassing the frozen
        constructor raise ``TypeError``/``ValueError`` instead of
        producing a malformed encoding.
        """
        if not isinstance(self, MerkleBatchProof):
            raise TypeError("to_bytes must be called on a MerkleBatchProof")
        _validate_batch_fields(self.public_key, self.signatures)
        if len(self.signatures) > _MAX_BATCH_SIGNATURES:
            raise ValueError("the signature count does not fit in 2 bytes")
        key_bytes = self.public_key.to_bytes()
        parts = [
            _BATCH_PROOF_MAGIC,
            bytes((_BATCH_PROOF_VERSION,)),
            len(key_bytes).to_bytes(4, "big"),
            len(self.signatures).to_bytes(2, "big"),
            key_bytes,
        ]
        for signature in self.signatures:
            signature_bytes = signature.to_bytes(self.public_key)
            parts.append(len(signature_bytes).to_bytes(4, "big"))
            parts.append(signature_bytes)
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: Any) -> "MerkleBatchProof":
        """Parse ``to_bytes()`` output back into a :class:`MerkleBatchProof`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. The embedded public key is recovered first and then
        constrains every signature. A bad magic, an unknown version, a
        zero public-key length or signature count, a length field that is
        out of bounds, truncation, trailing data, an invalid nested
        encoding, a signature inconsistent with the key, or indices that
        are not strictly increasing raises ``ValueError`` and no
        half-valid object is returned.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("batch proof data must be bytes or bytearray")
        data = bytes(data)
        if len(data) < _BATCH_PROOF_HEADER_BYTES:
            raise ValueError("batch proof encoding is truncated")
        if data[:8] != _BATCH_PROOF_MAGIC:
            raise ValueError("bad batch proof magic")
        if data[8] != _BATCH_PROOF_VERSION:
            raise ValueError(f"unsupported batch proof version: {data[8]}")
        key_length = int.from_bytes(data[9:13], "big")
        signature_count = int.from_bytes(data[13:15], "big")
        if key_length == 0:
            raise ValueError("the public key length must not be zero")
        if signature_count == 0:
            raise ValueError("the signature count must not be zero")
        key_end = _BATCH_PROOF_HEADER_BYTES + key_length
        if key_end > len(data):
            raise ValueError("batch proof encoding is truncated")
        public_key = MerklePublicKey.from_bytes(data[_BATCH_PROOF_HEADER_BYTES:key_end])
        offset = key_end
        signatures = []
        for _ in range(signature_count):
            if offset + 4 > len(data):
                raise ValueError("batch proof encoding is truncated")
            signature_length = int.from_bytes(data[offset : offset + 4], "big")
            if signature_length == 0:
                raise ValueError("a signature length must not be zero")
            signature_end = offset + 4 + signature_length
            if signature_end > len(data):
                raise ValueError("batch proof encoding is truncated")
            signatures.append(
                MerkleSignature.from_bytes(data[offset + 4 : signature_end], public_key)
            )
            offset = signature_end
        if offset < len(data):
            raise ValueError("trailing data after the batch proof encoding")
        return cls(public_key=public_key, signatures=tuple(signatures))

    def verify(self, messages: Any) -> bool:
        """Verify every embedded signature against the embedded public key.

        ``messages`` must be a ``tuple`` of the same length as
        ``signatures``; each member accepts
        ``bytes``/``bytearray``/``str`` exactly like :func:`merkle_verify`,
        to which every item delegates in tuple order. Returns ``True``
        only when every signature verifies against its message; a
        non-tuple argument, a count mismatch, an illegal message member or
        any verification failure returns ``False``.
        """
        if not isinstance(messages, tuple):
            return False
        if len(messages) != len(self.signatures):
            return False
        return all(
            merkle_verify(message, signature, self.public_key)
            for message, signature in zip(messages, self.signatures)
        )


class MerkleSigner:
    """Thread-safe, in-process few-times signer over a Merkle tree of W-OTS keys.

    Leaves are allocated in increasing order starting at 0; a leaf is consumed
    only by a successful :meth:`sign`, :meth:`sign_batch`,
    :meth:`sign_with_checkpoint`, :meth:`sign_batch_with_checkpoint`,
    :meth:`sign_multiproof_with_checkpoint`,
    :meth:`sign_with_auth_state`, :meth:`sign_batch_with_auth_state` or
    :meth:`sign_multiproof_with_auth_state`. Once
    every leaf is spent, further calls raise :class:`KeyExhaustedError`.

    Leaves can also be proactively voided with :meth:`advance_to` (or
    atomically recorded with :meth:`advance_to_with_auth_state`): after a
    crash or whenever state is uncertain, a caller skips leaves that may
    already have been exposed so they can never be signed again. Voiding only
    moves ``next_index`` forward — it never changes the keys, and there is no
    public way to move it backwards.
    """

    def __init__(
        self,
        *,
        height: int = 4,
        w: int = 4,
        token_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        w = _validate_w(w)
        height = _validate_height(height)
        private_keys = []
        leaves = []
        for _ in range(1 << height):
            wots_private, wots_public = wots_keygen(w=w, token_bytes=token_bytes)
            private_keys.append(wots_private)
            leaves.append(_leaf_hash(w, wots_public.elements))
        self._init_state(w, height, tuple(private_keys), leaves, 0)

    def _init_state(
        self,
        w: int,
        height: int,
        private_keys: tuple[Any, ...],
        leaves: list[bytes],
        next_index: int,
    ) -> None:
        layers = [leaves]
        while len(layers[-1]) > 1:
            level = layers[-1]
            layers.append(
                [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
            )
        self._w = w
        self._height = height
        self._private_keys = private_keys
        self._layers = tuple(tuple(layer) for layer in layers)
        self._next_index = next_index
        self._lock = threading.Lock()
        self._public_key = MerklePublicKey(w=w, height=height, root=layers[-1][0])

    @property
    def public_key(self) -> MerklePublicKey:
        """The Merkle public key committing to every leaf (read-only)."""
        return self._public_key

    @property
    def next_index(self) -> int:
        """Index of the next leaf that has not been spent or voided (read-only).

        Shares the signing lock, so the value is linearised with every
        :meth:`sign`, :meth:`sign_batch`, :meth:`advance_to` and
        :meth:`checkpoint`.
        """
        with self._lock:
            return self._next_index

    @property
    def remaining(self) -> int:
        """Leaves still available for signing: ``public_key.leaf_count - next_index``.

        Reads through the same lock as :attr:`next_index`; it is ``0`` once
        every leaf has been spent or voided.
        """
        with self._lock:
            return len(self._private_keys) - self._next_index

    def _checkpoint_bytes(self, next_index: int | None = None) -> bytes:
        """Serialise the full signer state; the caller holds the lock.

        ``next_index`` renders the checkpoint at a candidate index without
        touching ``self._next_index``; it defaults to the current index.
        """
        if next_index is None:
            next_index = self._next_index
        body = (
            _CHECKPOINT_MAGIC
            + bytes((_CHECKPOINT_VERSION, self._w, self._height))
            + next_index.to_bytes(2, "big")
            + (len(self._private_keys) * self._private_keys[0].length).to_bytes(
                4, "big"
            )
            + self._public_key.root
            + b"".join(
                element
                for private_key in self._private_keys
                for element in private_key.elements
            )
        )
        return body + hashlib.sha256(body).digest()

    def checkpoint(self) -> bytes:
        """Serialise the full signer state (all private keys) to ``bytes``.

        The v1 layout is: the 8-byte magic ``b"PQAMSCP\\0"``; one byte each
        for the version (1), ``w`` and ``height``; ``next_index`` as 2
        big-endian bytes; the total element count as 4 big-endian bytes
        (always ``2 ** height`` times the chain count for ``w``); the 32-byte
        Merkle root; every W-OTS private element in leaf-then-chain order
        (32 bytes each); and finally the SHA-256 of all preceding content.

        The checkpoint shares the signing lock, so a concurrent snapshot
        reflects the state either immediately before or immediately after an
        in-flight :meth:`sign`, never part-way through one. The blob contains
        every private key in the clear and the trailing hash only detects
        accidental corruption — store it as a secret.
        """
        with self._lock:
            return self._checkpoint_bytes()

    @classmethod
    def from_checkpoint(cls, data: Any) -> "MerkleSigner":
        """Restore a signer from ``checkpoint()`` output without randomness.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, version, length, ``w``, ``height``,
        ``next_index`` outside ``0 .. 2 ** height``, element count, checksum,
        or a Merkle root that does not match the one rebuilt from the private
        keys raises ``ValueError`` and no instance is returned. The restored
        signer has the same public key and resumes signing at the saved
        ``next_index``; a checkpoint taken after the last leaf was spent
        restores an exhausted signer.
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
        height = _validate_height(body[10])
        next_index = int.from_bytes(body[11:13], "big")
        element_count = int.from_bytes(body[13:17], "big")
        root = body[17:header]
        if next_index > (1 << height):
            raise ValueError("next_index exceeds the leaf count")
        b, l1, l2 = _params(w)
        chains = l1 + l2
        if element_count != (1 << height) * chains:
            raise ValueError("element count does not match 2 ** height * chains")
        if len(body) != header + element_count * ELEMENT_BYTES:
            raise ValueError("checkpoint length does not match the element count")
        if hashlib.sha256(body).digest() != checksum:
            raise ValueError("checkpoint checksum mismatch")
        private_keys = []
        leaves = []
        offset = header
        for _ in range(1 << height):
            elements = tuple(
                body[offset + i * ELEMENT_BYTES : offset + (i + 1) * ELEMENT_BYTES]
                for i in range(chains)
            )
            offset += chains * ELEMENT_BYTES
            private_keys.append(WOTSPrivateKey(w=w, elements=elements))
            endpoints = tuple(_chain_walk(element, b - 1) for element in elements)
            leaves.append(_leaf_hash(w, endpoints))
        signer = cls.__new__(cls)
        signer._init_state(w, height, tuple(private_keys), leaves, next_index)
        if signer._public_key.root != root:
            raise ValueError("Merkle root rebuilt from the private keys does not match")
        return signer

    def advance_to(self, next_index: Any) -> tuple[int, int]:
        """Void leaves by advancing ``next_index`` to ``next_index``.

        Use this after a crash or whenever signing state is uncertain to skip
        leaves that may already have been exposed: every leaf below the target
        can never be signed again, and the next :meth:`sign` uses the target
        leaf. Only the index moves — keys, public key and tree are unchanged,
        and there is deliberately no way to move the index backwards.

        ``next_index`` must be a non-boolean integer in the closed interval
        ``[self.next_index, public_key.leaf_count]``; a boolean or any other
        type raises ``TypeError``, and a target below the current index or
        above the leaf count raises ``ValueError``. Returns
        ``(before, after)``: the next-leaf index before and after the call. An
        equal target succeeds, returns the same value twice and neither
        changes the state nor draws randomness. The call shares the signing
        lock with :meth:`sign`, :meth:`sign_batch` and :meth:`checkpoint`, so
        it linearises as one atomic jump. Advancing to the leaf count
        exhausts the signer: :attr:`remaining` is ``0`` and :meth:`sign` or a
        non-empty :meth:`sign_batch` then raises :class:`KeyExhaustedError`.
        The advanced state is saved and restored by the existing v1
        checkpoint format.
        """
        if isinstance(next_index, bool) or not isinstance(next_index, int):
            raise TypeError("next_index must be a non-boolean integer")
        with self._lock:
            before = self._next_index
            leaf_count = len(self._private_keys)
            if next_index < before or next_index > leaf_count:
                raise ValueError(
                    "next_index must be between the current index and the leaf count"
                )
            self._next_index = next_index
            return before, next_index

    def advance_to_with_auth_state(
        self, next_index: Any, *, key: Any, generation: Any
    ) -> tuple[tuple[int, int], bytes]:
        """Void leaves and return the advanced state as a v2 auth envelope.

        Combines :meth:`advance_to` and :func:`auth_state_wrap` in one atomic
        call. Returns ``((before, after), envelope)``: the inner tuple is the
        next-leaf index before and after the jump, exactly what
        :meth:`advance_to` returns for the same target, and ``envelope`` is
        the ``bytes`` :func:`auth_state_wrap` v2 envelope over the
        post-advance v1 :meth:`checkpoint` bytes — byte-for-byte identical to
        advancing and then wrapping an explicit checkpoint — fixed to
        ``scheme="merkle"`` with the given ``key`` and ``generation`` and the
        existing v2 field order and HMAC-SHA-256 tag. An equal target succeeds
        and, even though the state is unchanged, still returns an envelope
        authenticating that state.

        Every argument is validated before the index moves: ``next_index``
        must be a non-boolean integer in the closed interval
        ``[self.next_index, public_key.leaf_count]``; ``key`` is keyword-only
        and must be a non-empty ``bytes``/``bytearray`` shared secret;
        ``generation`` is keyword-only and must be a non-boolean integer in
        ``0 .. 2**64 - 1``. A boolean or any other wrong type raises
        ``TypeError``; an empty key, an out-of-range generation, a target
        below the current index or above the leaf count raises
        ``ValueError``. A failed call neither changes the state nor returns a
        partial result.

        The whole call — index advance, checkpoint snapshot and wrapping —
        runs under the same lock as :meth:`sign`, :meth:`sign_batch`,
        :meth:`advance_to`, :meth:`sign_with_checkpoint`,
        :meth:`sign_batch_with_checkpoint`, :meth:`sign_with_auth_state`,
        :meth:`sign_batch_with_auth_state`, :meth:`sign_multiproof_with_auth_state`,
        the
        index properties and :meth:`checkpoint`, so it linearises as one
        atomic jump. The keys and public key are unchanged, no randomness is
        drawn, and the advanced state is saved and restored by the existing
        v1 checkpoint format. The envelope is plaintext and authenticated
        only; it provides neither encryption nor protection against replay or
        rollback on its own.
        """
        if isinstance(next_index, bool) or not isinstance(next_index, int):
            raise TypeError("next_index must be a non-boolean integer")
        key_bytes = _validate_key(key)
        generation_value = _validate_generation(generation, "generation")
        with self._lock:
            before = self._next_index
            leaf_count = len(self._private_keys)
            if next_index < before or next_index > leaf_count:
                raise ValueError(
                    "next_index must be between the current index and the leaf count"
                )
            self._next_index = next_index
            checkpoint = self._checkpoint_bytes()
            envelope = auth_state_wrap(
                checkpoint,
                scheme="merkle",
                key=key_bytes,
                generation=generation_value,
            )
            return (before, next_index), envelope

    def _signature_at(self, index: int, message: Any) -> MerkleSignature:
        """Build the signature for ``message`` at leaf ``index``.

        Does not touch signer state: the caller holds the lock and decides
        whether and when to advance ``_next_index``.
        """
        wots_signature = wots_sign(message, self._private_keys[index])
        auth_path = tuple(
            self._layers[level][(index >> level) ^ 1]
            for level in range(self._height)
        )
        return MerkleSignature(
            index=index, wots_signature=wots_signature, auth_path=auth_path
        )

    def sign(self, message: Any) -> MerkleSignature:
        """Sign ``message`` with the next unused leaf.

        Accepts ``bytes``/``bytearray``/``str`` like the W-OTS API. A leaf is
        consumed only when signing succeeds: a rejected message type raises
        ``TypeError`` without spending anything, and once all leaves are used
        every call raises :class:`KeyExhaustedError`. Concurrent callers never
        receive the same leaf index.
        """
        with self._lock:
            if self._next_index >= len(self._private_keys):
                raise KeyExhaustedError("all Merkle leaves have been used")
            index = self._next_index
            signature = self._signature_at(index, message)
            self._next_index += 1
            return signature

    def sign_batch(self, messages: Any) -> tuple[MerkleSignature, ...]:
        """Sign every message in ``messages`` atomically, one leaf each, in order.

        ``messages`` must be a ``tuple`` whose members each follow the usual
        message rules (``bytes``/``bytearray``/``str``); a non-tuple argument
        or an illegal member raises ``TypeError``. The whole batch runs under
        the same lock as :meth:`sign` and :meth:`checkpoint`: leaves are
        allocated consecutively from the current ``next_index`` and the state
        advances exactly once, after every signature has been generated, so a
        concurrent caller never observes a half-consumed batch. The returned
        tuple carries one :class:`MerkleSignature` per message, in the same
        order, with strictly increasing indices — value-for-value identical
        to calling :meth:`sign` on each message in sequence from the same
        state, and encoded by the existing ``to_bytes`` codec unchanged.

        The call is all-or-nothing: a batch larger than the number of
        remaining leaves raises :class:`KeyExhaustedError`, and any
        ``TypeError`` from an illegal message leaves the signer untouched —
        no leaf is consumed and no partial result is returned either way.
        An empty tuple returns an empty tuple and does not change the state.
        """
        with self._lock:
            if not isinstance(messages, tuple):
                raise TypeError("messages must be a tuple of messages")
            base = self._next_index
            leaf_count = len(self._private_keys)
            signatures = []
            for offset, message in enumerate(messages):
                index = base + offset
                if index >= leaf_count:
                    raise KeyExhaustedError(
                        "not enough Merkle leaves remain for the batch"
                    )
                signatures.append(self._signature_at(index, message))
            self._next_index = base + len(signatures)
            return tuple(signatures)

    def sign_with_checkpoint(self, message: Any) -> tuple[MerkleSignature, bytes]:
        """Sign ``message`` and snapshot the advanced state in one atomic step.

        Accepts ``bytes``/``bytearray``/``str`` exactly like :meth:`sign`.
        Returns ``(signature, checkpoint)``: the
        :class:`MerkleSignature` produced by the existing signing path —
        value-for-value identical to calling :meth:`sign` on the same message
        from the same starting state, drawing no extra randomness — and the
        ``bytes`` that :meth:`checkpoint` returns for the advanced state,
        byte-for-byte the same v1 encoding holding the new ``next_index`` and
        every private key. Both halves are produced under the same lock as
        :meth:`sign`, :meth:`sign_batch`, :meth:`advance_to`, the index
        properties and :meth:`checkpoint`, so a concurrent observer sees the
        state either before the whole call or after both the signature and
        the snapshot are complete — never part-way through.

        A rejected message type raises ``TypeError`` without spending a leaf,
        and an exhausted signer raises :class:`KeyExhaustedError`; a failed
        call returns no partial result. The returned checkpoint still carries
        every private key in the clear and offers no authentication,
        encryption or atomic persistence — confidentiality, durable storage
        and rollback protection remain the caller's responsibility.
        """
        with self._lock:
            if self._next_index >= len(self._private_keys):
                raise KeyExhaustedError("all Merkle leaves have been used")
            index = self._next_index
            signature = self._signature_at(index, message)
            self._next_index += 1
            return signature, self._checkpoint_bytes()

    def sign_batch_with_checkpoint(
        self, messages: Any
    ) -> tuple[tuple[MerkleSignature, ...], bytes]:
        """Sign a whole batch and snapshot the advanced state atomically.

        Combines :meth:`sign_batch` and :meth:`checkpoint` in one atomic
        call. Returns ``(signatures, checkpoint)``: ``signatures`` is a
        tuple with one :class:`MerkleSignature` per message, in the same
        order — value-for-value identical to calling :meth:`sign_batch` on
        the same messages from the same starting state, drawing no extra
        randomness, with strictly increasing leaf indices and the existing
        ``to_bytes`` codec unchanged — and ``checkpoint`` is the ``bytes``
        that :meth:`checkpoint` returns for the advanced state,
        byte-for-byte the same v1 encoding holding the new ``next_index``
        and every private key. Pairing the two halves in one call keeps the
        batch and the state it advanced to together, so a caller can never
        match signatures against a checkpoint taken at the wrong point
        under concurrency.

        ``messages`` must be a ``tuple`` whose members each follow the
        usual message rules (``bytes``/``bytearray``/``str``); every member
        is validated before the capacity check, so a non-tuple argument or
        an illegal member raises ``TypeError`` even on an exhausted signer.
        The whole batch then runs under the same lock as :meth:`sign`,
        :meth:`sign_batch`, :meth:`advance_to`, the index properties and
        :meth:`checkpoint`: leaves are allocated consecutively from the
        current ``next_index`` and the state advances exactly once, after
        every signature has been generated, so a concurrent observer never
        sees a half-consumed batch. A batch larger than the number of
        remaining leaves raises :class:`KeyExhaustedError`; every failure
        happens without spending a leaf and returns no partial result. An
        empty tuple is legal: it returns ``((), checkpoint)`` where the
        checkpoint snapshots the unchanged state. The returned checkpoint
        still carries every private key in the clear and offers no
        authentication, encryption or atomic persistence — confidentiality,
        durable storage and rollback protection remain the caller's
        responsibility.
        """
        if not isinstance(messages, tuple):
            raise TypeError("messages must be a tuple of messages")
        for message in messages:
            _as_bytes(message)
        with self._lock:
            base = self._next_index
            leaf_count = len(self._private_keys)
            if len(messages) > leaf_count - base:
                raise KeyExhaustedError(
                    "not enough Merkle leaves remain for the batch"
                )
            signatures = tuple(
                self._signature_at(base + offset, message)
                for offset, message in enumerate(messages)
            )
            self._next_index = base + len(signatures)
            return signatures, self._checkpoint_bytes()

    def sign_multiproof_with_checkpoint(self, messages: Any) -> tuple[bytes, bytes]:
        """Sign a tuple of messages and return the multiproof plus a checkpoint.

        Combines :meth:`sign_batch`, :func:`multiproof_encode` and
        :meth:`checkpoint` in one atomic call. Returns ``(proof, blob)``:
        ``proof`` is byte-for-byte identical to calling
        :func:`multiproof_encode` on this signer's :attr:`public_key` and the
        tuple of consecutive signatures produced for ``messages`` from the
        current ``next_index`` — the same bytes
        :func:`multiproof_verify` accepts together with ``messages`` — and
        ``blob`` is the ``bytes`` :meth:`checkpoint` returns for the advanced
        state, byte-for-byte the same v1 encoding holding the new
        ``next_index`` and every private key. Pairing the two halves in one
        call keeps the proof and the state it advanced to together, so a
        caller can never match a proof against a checkpoint taken at the
        wrong point under concurrency.

        ``messages`` must be a non-empty ``tuple`` whose members each follow
        the usual message rules (``bytes``/``bytearray``/``str``); every
        member is validated before the remaining-leaf-capacity check, so a
        non-tuple argument or an illegal member raises ``TypeError`` even on
        an exhausted signer, and an empty tuple raises ``ValueError``. The
        whole call then runs under the same lock as :meth:`sign`,
        :meth:`sign_batch`, :meth:`advance_to`, the index properties and
        :meth:`checkpoint`: leaves are allocated consecutively from the
        current ``next_index`` and the proof, the state advance and the
        snapshot form one linearised operation, so a concurrent observer
        never sees a half-consumed batch or a proof built on an advanced but
        unsnapshotted state.

        A tuple larger than the number of remaining leaves raises
        :class:`KeyExhaustedError`; a proof structure the v1 format cannot
        express raises ``ValueError``. Every failure happens without spending
        a leaf and returns no partial result; the state is advanced only once
        the proof bytes have been built, so a failed encode cannot leave the
        signer half-way. No randomness is drawn anywhere in the call. The
        returned checkpoint still carries every private key in the clear and
        offers no authentication, encryption or atomic persistence —
        confidentiality, durable storage and rollback protection remain the
        caller's responsibility.
        """
        if not isinstance(messages, tuple):
            raise TypeError("messages must be a tuple of messages")
        for message in messages:
            _as_bytes(message)
        if not messages:
            raise ValueError("messages must not be empty")
        with self._lock:
            base = self._next_index
            leaf_count = len(self._private_keys)
            if len(messages) > leaf_count - base:
                raise KeyExhaustedError(
                    "not enough Merkle leaves remain for the multiproof"
                )
            signatures = tuple(
                self._signature_at(base + offset, message)
                for offset, message in enumerate(messages)
            )
            # Encode before advancing: a structural failure must consume no
            # leaf, and no observer must ever see the advanced state without
            # the finished proof.
            proof = multiproof_encode(self._public_key, signatures)
            self._next_index = base + len(signatures)
            return proof, self._checkpoint_bytes()

    def sign_with_auth_state(
        self, message: Any, *, key: Any, generation: Any
    ) -> tuple[MerkleSignature, bytes]:
        """Sign ``message`` and return the advanced state as a v2 auth envelope.

        Behaves like :meth:`sign_with_checkpoint` — the same leaf allocation,
        the same :class:`MerkleSignature` and the same post-advance v1
        :meth:`checkpoint` bytes, all under the signing lock — but instead of
        the plaintext checkpoint the second half of the returned
        ``(signature, envelope)`` tuple is the
        :func:`auth_state_wrap` v2 envelope over that checkpoint with
        ``scheme="merkle"`` and the given ``key`` and ``generation``. Pairing
        the two halves in one call keeps the signature and the state it
        advanced to together, so a caller can never match a signature against
        a checkpoint taken at the wrong point under concurrency.

        ``message`` accepts ``bytes``/``bytearray``/``str`` exactly like
        :meth:`sign`; ``key`` is keyword-only and must be a non-empty
        ``bytes``/``bytearray`` shared secret; ``generation`` is keyword-only
        and must be a non-boolean integer in ``0 .. 2**64 - 1``. A rejected
        message or key type raises ``TypeError``, an empty key or an
        out-of-range generation raises ``ValueError``, and an exhausted
        signer raises :class:`KeyExhaustedError`; every failure happens
        without spending a leaf and returns no partial result. The whole call
        — signature, leaf advance, snapshot and wrapping — linearises with
        :meth:`sign`, :meth:`sign_batch`, :meth:`advance_to`, the index
        properties and :meth:`checkpoint` under the same lock, so a concurrent
        observer sees the state either before the call or after all four
        steps are complete. The envelope is plaintext and authenticated only;
        it provides neither encryption nor protection against replay or
        rollback on its own.
        """
        key_bytes = _validate_key(key)
        generation_value = _validate_generation(generation, "generation")
        with self._lock:
            if self._next_index >= len(self._private_keys):
                raise KeyExhaustedError("all Merkle leaves have been used")
            index = self._next_index
            signature = self._signature_at(index, message)
            self._next_index += 1
            checkpoint = self._checkpoint_bytes()
            envelope = auth_state_wrap(
                checkpoint,
                scheme="merkle",
                key=key_bytes,
                generation=generation_value,
            )
            return signature, envelope

    def sign_batch_with_auth_state(
        self, messages: Any, *, key: Any, generation: Any
    ) -> tuple[tuple[MerkleSignature, ...], bytes]:
        """Sign a whole batch and return the advanced state as a v2 envelope.

        Combines :meth:`sign_batch` and :meth:`sign_with_auth_state` in one
        atomic call. Returns ``(signatures, envelope)``: ``signatures`` is a
        tuple with one :class:`MerkleSignature` per message, in the same
        order — value-for-value identical to calling :meth:`sign_batch` on
        the same messages from the same starting state, drawing no extra
        randomness — and ``envelope`` is the :func:`auth_state_wrap` v2
        envelope (``bytes``) over the post-advance v1 :meth:`checkpoint`
        bytes with ``scheme="merkle"`` and the given ``key`` and
        ``generation``, byte-for-byte the same as signing the batch and then
        wrapping an explicit checkpoint.

        Every input is validated before any capacity check: ``messages``
        must be a ``tuple`` whose members each follow the usual message
        rules (``bytes``/``bytearray``/``str``); ``key`` is keyword-only and
        must be a non-empty ``bytes``/``bytearray`` shared secret;
        ``generation`` is keyword-only and must be a non-boolean integer in
        ``0 .. 2**64 - 1``. A non-tuple ``messages``, an illegal message
        member or a wrong key/generation type raises ``TypeError``; an empty
        key or an out-of-range generation raises ``ValueError``.

        The whole batch then runs under the same lock as :meth:`sign`,
        :meth:`sign_batch`, :meth:`advance_to`, the index properties and
        :meth:`checkpoint`: leaves are allocated consecutively from the
        current ``next_index`` and the state advances exactly once, after
        every signature has been generated, so a concurrent observer never
        sees a half-consumed batch. A batch larger than the number of
        remaining leaves raises :class:`KeyExhaustedError`; every failure
        happens without spending a leaf and returns no partial result. An
        empty tuple is legal: it returns ``((), envelope)`` where the
        envelope wraps the unchanged state. The envelope is plaintext and
        authenticated only; it provides neither encryption nor protection
        against replay or rollback on its own.
        """
        if not isinstance(messages, tuple):
            raise TypeError("messages must be a tuple of messages")
        for message in messages:
            _as_bytes(message)
        key_bytes = _validate_key(key)
        generation_value = _validate_generation(generation, "generation")
        with self._lock:
            base = self._next_index
            leaf_count = len(self._private_keys)
            if len(messages) > leaf_count - base:
                raise KeyExhaustedError(
                    "not enough Merkle leaves remain for the batch"
                )
            signatures = tuple(
                self._signature_at(base + offset, message)
                for offset, message in enumerate(messages)
            )
            self._next_index = base + len(signatures)
            checkpoint = self._checkpoint_bytes()
            envelope = auth_state_wrap(
                checkpoint,
                scheme="merkle",
                key=key_bytes,
                generation=generation_value,
            )
            return signatures, envelope

    def sign_multiproof_with_auth_state(
        self, messages: Any, *, key: Any, generation: Any
    ) -> tuple[bytes, bytes]:
        """Sign a tuple of messages and return the multiproof plus a v2 envelope.

        Combines :meth:`sign_batch`, :func:`multiproof_encode` and
        :func:`auth_state_wrap` in one atomic call. Returns ``(proof,
        envelope)``: ``proof`` is byte-for-byte identical to calling
        :func:`multiproof_encode` on this signer's :attr:`public_key` and the
        tuple of consecutive signatures produced for ``messages`` from the
        current ``next_index`` — the same bytes
        :func:`multiproof_verify` accepts together with ``messages`` — and
        ``envelope`` is the :func:`auth_state_wrap` v2 envelope (``bytes``)
        over the post-advance v1 :meth:`checkpoint` bytes with
        ``scheme="merkle"`` and the given ``key`` and ``generation``,
        byte-for-byte the same as building the multiproof and then wrapping an
        explicit checkpoint; the existing v2 field order and HMAC-SHA-256 tag
        are unchanged. Pairing the two halves in one call keeps the proof and
        the state it advanced to together, so a caller can never match a proof
        against an envelope taken at the wrong point under concurrency.

        Every input is validated before the remaining-leaf-capacity check and
        before any state change: ``messages`` must be a **non-empty**
        ``tuple`` whose members each follow the usual message rules
        (``bytes``/``bytearray``/``str``); ``key`` is keyword-only and must be
        a non-empty ``bytes``/``bytearray`` shared secret; ``generation`` is
        keyword-only and must be a non-boolean integer in
        ``0 .. 2**64 - 1``. A non-tuple ``messages``, an illegal message
        member or a wrong key/generation type raises ``TypeError``; an empty
        tuple or key or an out-of-range generation raises ``ValueError``.

        The whole call then runs under the same lock as :meth:`sign`,
        :meth:`sign_batch`, :meth:`advance_to`, the index properties and
        :meth:`checkpoint`: leaves are allocated consecutively from the
        current ``next_index`` and the proof, the candidate checkpoint, the
        envelope and the index advance form one linearised operation, so a
        concurrent observer never sees a half-consumed batch or an advanced
        state without the finished proof and envelope. A tuple larger than the
        number of remaining leaves raises :class:`KeyExhaustedError`; a proof
        structure the v1 format cannot express raises ``ValueError``. Proof
        and envelope are both built before ``next_index`` is committed, so
        every failure happens without spending a leaf and returns no partial
        result. No randomness is drawn anywhere in the call. The envelope is
        plaintext and authenticated only; it provides neither encryption nor
        protection against replay or rollback on its own.
        """
        if not isinstance(messages, tuple):
            raise TypeError("messages must be a tuple of messages")
        for message in messages:
            _as_bytes(message)
        if not messages:
            raise ValueError("messages must not be empty")
        key_bytes = _validate_key(key)
        generation_value = _validate_generation(generation, "generation")
        with self._lock:
            base = self._next_index
            leaf_count = len(self._private_keys)
            if len(messages) > leaf_count - base:
                raise KeyExhaustedError(
                    "not enough Merkle leaves remain for the multiproof"
                )
            signatures = tuple(
                self._signature_at(base + offset, message)
                for offset, message in enumerate(messages)
            )
            # Build both outputs before advancing: any failure must consume
            # no leaf, and no observer must ever see the advanced state
            # without the finished proof and envelope.
            proof = multiproof_encode(self._public_key, signatures)
            checkpoint = self._checkpoint_bytes(base + len(signatures))
            envelope = auth_state_wrap(
                checkpoint,
                scheme="merkle",
                key=key_bytes,
                generation=generation_value,
            )
            self._next_index = base + len(signatures)
            return proof, envelope


def merkle_verify(message: Any, signature: Any, public_key: MerklePublicKey) -> bool:
    """Recover the W-OTS public key from ``signature`` and climb to the root.

    The leaf hash is rebuilt from the recovered key, the authentication path
    is folded in according to the bits of ``signature.index`` (leaf level
    first), and the result is compared against ``public_key.root``. A wrong
    public key *type* raises ``TypeError``; every other structural, range or
    content mismatch returns ``False`` — including keys or signatures whose
    fields were corrupted by bypassing the frozen-dataclass constructors.
    """
    if not isinstance(public_key, MerklePublicKey):
        raise TypeError("public_key must be a MerklePublicKey")
    if not isinstance(signature, MerkleSignature):
        return False
    try:
        w = public_key.w
        height = public_key.height
        root = public_key.root
        index = signature.index
        wots_signature = signature.wots_signature
        auth_path = signature.auth_path
    except AttributeError:
        return False
    try:
        _validate_w(w)
        _validate_height(height)
    except ValueError:
        return False
    if not isinstance(root, bytes) or len(root) != ELEMENT_BYTES:
        return False
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        return False
    if not _nodes_well_formed(wots_signature) or not _nodes_well_formed(auth_path):
        return False
    if len(auth_path) != height:
        return False
    if index >= (1 << height):
        return False
    b, l1, l2 = _params(w)
    if len(wots_signature) != l1 + l2:
        return False
    try:
        digits = _signing_digits(message, w)
    except TypeError:
        return False
    recovered = tuple(
        _chain_walk(element, b - 1 - digit)
        for element, digit in zip(wots_signature, digits)
    )
    node = _leaf_hash(w, recovered)
    for level, sibling in enumerate(auth_path):
        if (index >> level) & 1:
            node = _node_hash(sibling, node)
        else:
            node = _node_hash(node, sibling)
    return node == root


def _canonical_multiproof_nodes(
    indices: tuple[int, ...], height: int
) -> list[tuple[int, int]]:
    """Canonical sibling coordinates for a multiproof over ``indices``.

    Starting from the leaf indices at level 0, each level records the sibling
    of every current-set index whose sibling is not itself in the current set,
    then the set is shifted right and deduplicated for the next level. The
    returned coordinates are sorted by level then index — exactly the order the
    v1 wire format uses.
    """
    current = set(indices)
    nodes: list[tuple[int, int]] = []
    for level in range(height):
        siblings = {index ^ 1 for index in current if (index ^ 1) not in current}
        nodes.extend(sorted((level, sibling) for sibling in siblings))
        current = {index >> 1 for index in current}
    return nodes


def multiproof_encode(public_key: Any, signatures: Any) -> bytes:
    """Compress several signatures of one Merkle public key into one proof.

    Unlike :class:`MerkleBatchProof`, each signature's full authentication
    path is not stored: siblings shared by the selected leaves are deduplicated
    into one canonical node set, so every sibling the verifier cannot itself
    derive is carried exactly once.

    Both arguments must have the expected types — ``public_key`` a
    :class:`MerklePublicKey` and ``signatures`` a non-empty tuple of
    :class:`MerkleSignature` — or ``TypeError`` is raised. ``ValueError`` is
    raised for an empty set, leaf indices that are not strictly increasing, a
    signature that the key does not constrain (wrong ``w``/height, an index out
    of range, a wrong W-OTS element or auth-path count, a malformed element),
    an auth-path node that disagrees with another signature at the same
    coordinate, or a tree whose shape cannot be expressed in the v1 format
    (more than 65535 leaves or sibling nodes, or a level above 255).

    The v1 layout is the 8-byte magic ``b"PQAMMUL\\0"``; the version byte (1);
    the public-key length as 4 big-endian bytes; the leaf and sibling-node
    counts as 2 big-endian bytes each; the complete v1 encoding of the public
    key; then, in increasing index order, one block per leaf holding the
    2-byte big-endian index, the 2-byte big-endian W-OTS element count and the
    original-order 32-byte elements; then the canonical sibling nodes sorted by
    level and index, each encoded as a 1-byte level, a 2-byte big-endian index
    and a 32-byte hash. Encoding is deterministic: the same inputs always
    produce the same bytes.
    """
    if not isinstance(public_key, MerklePublicKey):
        raise TypeError("public_key must be a MerklePublicKey")
    if not isinstance(signatures, tuple):
        raise TypeError("signatures must be a tuple of MerkleSignature")
    for signature in signatures:
        if not isinstance(signature, MerkleSignature):
            raise TypeError("every signature must be a MerkleSignature")
    if not signatures:
        raise ValueError("signatures must not be empty")
    w, height, chains = _signature_params(public_key)
    if isinstance(height, bool) or height > _MAX_MULTIPROOF_LEVEL:
        raise ValueError("the public key's tree height does not fit in one byte")
    if len(signatures) > _MAX_MULTIPROOF_LEAVES:
        raise ValueError("the leaf count does not fit in 2 bytes")
    indices = [signature.index for signature in signatures]
    if any(isinstance(index, bool) or not isinstance(index, int) for index in indices):
        raise ValueError("every signature index must be an integer")
    if any(former >= latter for former, latter in zip(indices, indices[1:])):
        raise ValueError("signature indices must be strictly increasing and unique")
    if any(index < 0 or index >= (1 << height) for index in indices):
        raise ValueError("a signature index is out of range for the public key's tree")
    for signature in signatures:
        if not _nodes_well_formed(signature.wots_signature):
            raise ValueError("a W-OTS signature element is malformed")
        if not _nodes_well_formed(signature.auth_path):
            raise ValueError("an authentication path node is malformed")
        if len(signature.wots_signature) != chains:
            raise ValueError("a W-OTS signature length does not match the chain count")
        if len(signature.auth_path) != height:
            raise ValueError("an authentication path length does not match the tree height")

    coordinates = _canonical_multiproof_nodes(tuple(indices), height)
    if len(coordinates) > _MAX_MULTIPROOF_NODES:
        raise ValueError("the node count does not fit in 2 bytes")
    node_values: dict[tuple[int, int], bytes] = {}
    for signature in signatures:
        for level in range(height):
            key = (level, (signature.index >> level) ^ 1)
            node = signature.auth_path[level]
            previous = node_values.get(key)
            if previous is not None and previous != node:
                raise ValueError("conflicting authentication nodes at the same coordinate")
            node_values[key] = node

    key_bytes = public_key.to_bytes()
    parts = [
        _MULTIPROOF_MAGIC,
        bytes((_MULTIPROOF_VERSION,)),
        len(key_bytes).to_bytes(4, "big"),
        len(signatures).to_bytes(2, "big"),
        len(coordinates).to_bytes(2, "big"),
        key_bytes,
    ]
    for signature in signatures:
        parts.append(signature.index.to_bytes(2, "big"))
        parts.append(len(signature.wots_signature).to_bytes(2, "big"))
        parts.append(b"".join(signature.wots_signature))
    for level, index in coordinates:
        parts.append(bytes((level,)))
        parts.append(index.to_bytes(2, "big"))
        parts.append(node_values[(level, index)])
    return b"".join(parts)


def multiproof_verify(messages: Any, data: Any) -> bool:
    """Verify a :func:`multiproof_encode` proof against one message per leaf.

    ``data`` must be ``bytes`` or ``bytearray`` and ``messages`` a tuple with
    exactly as many members as the proof has leaves; each member follows the
    usual message rules (``bytes``/``bytearray``/``str``). Every W-OTS public
    key is recovered from its message, hashed with the existing leaf rule and
    merged level by level with the existing internal-node rule, consuming each
    proof node exactly once. Verification returns ``True`` only when the merge
    reaches the public-key root and every carried node was used; any other
    outcome — a wrong argument type or count, an illegal message member, a bad
    magic/version/length/count field, truncation, trailing data, a
    non-canonical node coordinate, a missing, extra, duplicated or unordered
    node, or a mismatched message — returns ``False``.
    """
    if not isinstance(data, (bytes, bytearray)):
        return False
    if not isinstance(messages, tuple):
        return False
    data = bytes(data)
    if len(data) < _MULTIPROOF_HEADER_BYTES:
        return False
    if data[:8] != _MULTIPROOF_MAGIC:
        return False
    if data[8] != _MULTIPROOF_VERSION:
        return False
    key_length = int.from_bytes(data[9:13], "big")
    leaf_count = int.from_bytes(data[13:15], "big")
    node_count = int.from_bytes(data[15:17], "big")
    if key_length == 0 or leaf_count == 0:
        return False
    if len(messages) != leaf_count:
        return False
    offset = _MULTIPROOF_HEADER_BYTES
    key_end = offset + key_length
    if key_end > len(data):
        return False
    try:
        public_key = MerklePublicKey.from_bytes(data[offset:key_end])
    except (TypeError, ValueError):
        return False
    w = public_key.w
    height = public_key.height
    root = public_key.root
    b, l1, l2 = _params(w)
    chains = l1 + l2

    leaves: dict[int, bytes] = {}
    offset = key_end
    previous_index = -1
    for _ in range(leaf_count):
        if offset + 4 > len(data):
            return False
        index = int.from_bytes(data[offset : offset + 2], "big")
        element_count = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += 4
        if index >= (1 << height) or index <= previous_index:
            return False
        previous_index = index
        if element_count != chains:
            return False
        end = offset + element_count * ELEMENT_BYTES
        if end > len(data):
            return False
        wots_signature = tuple(
            data[offset + i * ELEMENT_BYTES : offset + (i + 1) * ELEMENT_BYTES]
            for i in range(element_count)
        )
        offset = end
        try:
            digits = _signing_digits(messages[len(leaves)], w)
        except TypeError:
            return False
        recovered = tuple(
            _chain_walk(element, b - 1 - digit)
            for element, digit in zip(wots_signature, digits)
        )
        leaves[index] = _leaf_hash(w, recovered)

    proof_nodes: dict[tuple[int, int], bytes] = {}
    previous_coordinate: tuple[int, int] | None = None
    for _ in range(node_count):
        end = offset + _MULTIPROOF_NODE_BYTES
        if end > len(data):
            return False
        level = data[offset]
        index = int.from_bytes(data[offset + 1 : offset + 3], "big")
        node = data[offset + 3 : end]
        offset = end
        if level >= height:
            return False
        coordinate = (level, index)
        if previous_coordinate is not None and coordinate <= previous_coordinate:
            return False
        previous_coordinate = coordinate
        proof_nodes[coordinate] = node
    if offset < len(data):
        return False
    indices = tuple(sorted(leaves))
    if set(proof_nodes) != set(_canonical_multiproof_nodes(indices, height)):
        return False

    current = dict(leaves)
    for level in range(height):
        parents: dict[int, bytes] = {}
        positions = sorted(current)
        i = 0
        while i < len(positions):
            index = positions[i]
            node = current[index]
            if i + 1 < len(positions) and positions[i + 1] == index ^ 1:
                parents[index >> 1] = _node_hash(node, current[index ^ 1])
                i += 2
                continue
            proof_node = proof_nodes.pop((level, index ^ 1), None)
            if proof_node is None:
                return False
            if index & 1:
                parents[index >> 1] = _node_hash(proof_node, node)
            else:
                parents[index >> 1] = _node_hash(node, proof_node)
            i += 1
        current = parents
    return len(current) == 1 and current.get(0) == root and not proof_nodes

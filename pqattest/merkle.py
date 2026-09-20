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
public key. Signer
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
from .wots import (
    ELEMENT_BYTES,
    WOTSPrivateKey,
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
_MAX_MULTIPROOF_LEAVES = 0xFFFF
_MAX_MULTIPROOF_NODES = 0xFFFF
_NODE_RECORD_BYTES = 1 + 2 + ELEMENT_BYTES
_LEAF_RECORD_BYTES = 2 + 2

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
    only by a successful :meth:`sign` or :meth:`sign_batch`. Once every leaf
    is spent, further calls raise :class:`KeyExhaustedError`.
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
            body = (
                _CHECKPOINT_MAGIC
                + bytes((_CHECKPOINT_VERSION, self._w, self._height))
                + self._next_index.to_bytes(2, "big")
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


def _canonical_proof_nodes(
    height: int, indices: tuple[int, ...]
) -> tuple[tuple[int, int], ...]:
    """Coordinates ``(level, index)`` of the deduplicated authentication nodes.

    Starting from the signed leaf indices on level 0, each level keeps every
    sibling that is not itself part of the current index set and then folds the
    set in half (index right shift). The result is sorted by level and then by
    index, so the encoding is canonical and deterministic.
    """
    current = set(indices)
    nodes: list[tuple[int, int]] = []
    for level in range(height):
        siblings = {
            (level, index ^ 1) for index in current if (index ^ 1) not in current
        }
        nodes.extend(sorted(siblings))
        current = {index >> 1 for index in current}
    return tuple(nodes)


def multiproof_encode(public_key: Any, signatures: Any) -> bytes:
    """Pack several signatures of one Merkle key into a deduplicated multiproof.

    Unlike :class:`MerkleBatchProof` (which embeds each signature's full
    authentication path), the multiproof keeps only the W-OTS signature of
    every signed leaf plus the *canonical* set of Merkle nodes shared by their
    authentication paths: each node appears exactly once.

    The v1 layout is the 8-byte magic ``b"PQAMMUL\\0"``; the version byte (1);
    the public-key length as 4 big-endian bytes; the leaf count and the node
    count as 2 big-endian bytes each; the complete v1 encoding of
    ``public_key``; one record per leaf in strictly increasing index order —
    the index and the W-OTS element count as 2 big-endian bytes each followed
    by that many 32-byte elements in chain order; and one record per canonical
    node in ``(level, index)`` order — one level byte, the node index as 2
    big-endian bytes and the 32-byte node hash. Encoding is deterministic: the
    same inputs always produce the same bytes.

    A wrong argument type (a non-:class:`MerklePublicKey` key, a non-tuple
    container or a non-:class:`MerkleSignature` member) raises ``TypeError``.
    An empty set, non-strictly-increasing or out-of-range leaf indices, a
    signature inconsistent with the key, or an encoding whose node set exceeds
    the 2-byte count field raises ``ValueError``.
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
    for signature in signatures:
        if not _signature_matches_key(signature, public_key):
            raise ValueError("signature is not consistent with the public key")
    indices = tuple(signature.index for signature in signatures)
    if any(former >= latter for former, latter in zip(indices, indices[1:])):
        raise ValueError("signature indices must be strictly increasing and unique")
    if len(indices) > _MAX_MULTIPROOF_LEAVES:
        raise ValueError("the leaf count does not fit in 2 bytes")

    w, height, chains = _signature_params(public_key)
    nodes = _canonical_proof_nodes(height, indices)
    if len(nodes) > _MAX_MULTIPROOF_NODES:
        raise ValueError("the node count does not fit in 2 bytes")

    # Every embedded signature carries the complete authentication path, so
    # every canonical node is available without the signer's tree; paths
    # belonging to different signatures must agree wherever they overlap.
    node_values: dict[tuple[int, int], bytes] = {}
    for signature in signatures:
        for level, node in enumerate(signature.auth_path):
            coordinate = (level, (signature.index >> level) ^ 1)
            previous = node_values.get(coordinate)
            if previous is not None and previous != node:
                raise ValueError("conflicting proof nodes across signatures")
            node_values[coordinate] = node

    key_bytes = public_key.to_bytes()
    parts = [
        _MULTIPROOF_MAGIC,
        bytes((_MULTIPROOF_VERSION,)),
        len(key_bytes).to_bytes(4, "big"),
        len(indices).to_bytes(2, "big"),
        len(nodes).to_bytes(2, "big"),
        key_bytes,
    ]
    for signature in signatures:
        parts.append(signature.index.to_bytes(2, "big"))
        parts.append(chains.to_bytes(2, "big"))
        parts.append(b"".join(signature.wots_signature))
    for level, node_index in nodes:
        parts.append(bytes((level,)))
        parts.append(node_index.to_bytes(2, "big"))
        parts.append(node_values[(level, node_index)])
    return b"".join(parts)


def multiproof_verify(messages: Any, data: Any) -> bool:
    """Verify a deterministic multiproof produced by :func:`multiproof_encode`.

    ``messages`` must be a tuple with one entry per embedded leaf; each member
    follows the usual message rules (``bytes``/``bytearray``/``str``). The
    leaves are verified by index: the W-OTS public key recovered from each
    leaf's signature is leaf-hashed, the canonical nodes are folded in level by
    level using the existing leaf and internal-node byte rules, and the result
    must equal the root committed by the embedded public key. Every proof node
    must be used exactly once.

    ``data`` must be ``bytes`` or ``bytearray``; any other type, a bad magic or
    version, mismatched lengths or counts, truncation, trailing bytes, a
    non-canonical (missing, extra, duplicated or out-of-order) node set, a
    wrong number or type of messages, or any signature that does not recover to
    the committed root makes the function return ``False``.
    """
    if not isinstance(data, (bytes, bytearray)):
        return False
    if not isinstance(messages, tuple):
        return False
    data = bytes(data)

    parsed = _multiproof_parse(data)
    if parsed is None:
        return False
    public_key, leaves, nodes = parsed
    if len(messages) != len(leaves):
        return False

    w = public_key.w
    height = public_key.height
    b, _, _ = _params(w)

    # Recover one W-OTS public key (hence one leaf hash) per signed message.
    current: dict[int, bytes] = {}
    for message, (index, wots_signature) in zip(messages, leaves):
        try:
            digits = _signing_digits(message, w)
        except TypeError:
            return False
        recovered = tuple(
            _chain_walk(element, b - 1 - digit)
            for element, digit in zip(wots_signature, digits)
        )
        current[index] = _leaf_hash(w, recovered)

    node_map: dict[tuple[int, int], bytes] = {}
    for level, node_index, node_value in nodes:
        coordinate = (level, node_index)
        if coordinate in node_map:
            return False
        node_map[coordinate] = node_value

    used: set[tuple[int, int]] = set()
    for level in range(height):
        parents: dict[int, bytes] = {}
        for position in sorted(current):
            parent = position >> 1
            if parent in parents:
                continue
            sibling = position ^ 1
            if sibling in current:
                left, right = current[position], current[sibling]
                if position & 1:
                    left, right = right, left
            else:
                coordinate = (level, sibling)
                if coordinate in used or coordinate not in node_map:
                    return False
                used.add(coordinate)
                sibling_value = node_map[coordinate]
                if position & 1:
                    left, right = sibling_value, current[position]
                else:
                    left, right = current[position], sibling_value
            parents[parent] = _node_hash(left, right)
        current = parents

    if used != set(node_map):
        return False
    return current.get(0) == public_key.root


def _multiproof_parse(
    data: bytes,
) -> Any:
    """Strict parser for the multiproof v1 wire format.

    Returns ``(public_key, leaves, nodes)`` with
    ``leaves = ((index, wots_elements), ...)`` and
    ``nodes = ((level, index, value), ...)`` in wire order, or ``None`` for any
    malformed, truncated, trailing or non-canonical encoding.
    """
    if len(data) < _MULTIPROOF_HEADER_BYTES:
        return None
    if data[:8] != _MULTIPROOF_MAGIC:
        return None
    if data[8] != _MULTIPROOF_VERSION:
        return None
    key_length = int.from_bytes(data[9:13], "big")
    leaf_count = int.from_bytes(data[13:15], "big")
    node_count = int.from_bytes(data[15:17], "big")
    if key_length == 0 or leaf_count == 0:
        return None
    offset = _MULTIPROOF_HEADER_BYTES
    key_end = offset + key_length
    if key_end > len(data):
        return None
    try:
        public_key = MerklePublicKey.from_bytes(data[offset:key_end])
    except (TypeError, ValueError):
        return None
    w, height, chains = _signature_params(public_key)
    leaf_limit = 1 << height

    offset = key_end
    leaves = []
    last_index = -1
    for _ in range(leaf_count):
        if offset + _LEAF_RECORD_BYTES > len(data):
            return None
        index = int.from_bytes(data[offset : offset + 2], "big")
        element_count = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += _LEAF_RECORD_BYTES
        if index >= leaf_limit or index <= last_index:
            return None
        last_index = index
        if element_count != chains:
            return None
        elements_end = offset + element_count * ELEMENT_BYTES
        if elements_end > len(data):
            return None
        elements = tuple(
            data[offset + i * ELEMENT_BYTES : offset + (i + 1) * ELEMENT_BYTES]
            for i in range(element_count)
        )
        offset = elements_end
        leaves.append((index, elements))

    nodes = []
    last_coordinate = (-1, -1)
    for _ in range(node_count):
        record_end = offset + _NODE_RECORD_BYTES
        if record_end > len(data):
            return None
        level = data[offset]
        node_index = int.from_bytes(data[offset + 1 : offset + 3], "big")
        node_value = data[offset + 3 : record_end]
        offset = record_end
        if not 0 <= level < height:
            return None
        if node_index >= (1 << (height - level)):
            return None
        coordinate = (level, node_index)
        if coordinate <= last_coordinate:
            return None
        last_coordinate = coordinate
        nodes.append((level, node_index, node_value))

    if offset != len(data):
        return None

    # The node set must be exactly the canonical set implied by the leaves:
    # nothing missing, nothing extra, nothing reordered.
    indices = tuple(index for index, _ in leaves)
    canonical = _canonical_proof_nodes(height, indices)
    if tuple((level, node_index) for level, node_index, _ in nodes) != canonical:
        return None
    return public_key, tuple(leaves), tuple(nodes)

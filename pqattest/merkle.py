"""Merkle-tree aggregation of W-OTS keys: a few-times signature scheme.

A :class:`MerkleSigner` generates ``2 ** height`` W-OTS key pairs up front and
commits to every public key in a Merkle tree. The tree root is the single
long-term public key; each signature spends one leaf (one W-OTS key pair) and
carries the authentication path from that leaf to the root. Only the standard
library is used. Public keys and signatures have a versioned binary wire
format via ``to_bytes`` / ``from_bytes`` (the signature codec is constrained
by the corresponding :class:`MerklePublicKey`). A :class:`MerkleProof`
bundles one public key and one signature for independent transport. Signer
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
    "MerkleProof",
    "MerklePublicKey",
    "MerkleSignature",
    "MerkleSigner",
    "merkle_verify",
]

_LEAF_DOMAIN = b"pqattest/leaf"
_NODE_DOMAIN = b"pqattest/node"
_MIN_HEIGHT = 1
_MAX_HEIGHT = 8

_PROOF_MAGIC = b"PQAMPRF\0"
_PROOF_VERSION = 1
_PROOF_HEADER_BYTES = 8 + 1 + 4 + 4

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

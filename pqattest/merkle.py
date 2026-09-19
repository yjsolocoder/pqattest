"""Merkle-tree aggregation of W-OTS keys: a few-times signature scheme.

A :class:`MerkleSigner` generates ``2 ** height`` W-OTS key pairs up front and
commits to every public key in a Merkle tree. The tree root is the single
long-term public key; each signature spends one leaf (one W-OTS key pair) and
carries the authentication path from that leaf to the root. Only the standard
library is used. State is in-process by default; :meth:`MerkleSigner.checkpoint`
optionally exports the full private state (including every W-OTS private key)
so the caller can persist it, and :meth:`MerkleSigner.from_checkpoint` restores
a signer that continues leaf allocation exactly where the snapshot was taken.
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
    "MerklePublicKey",
    "MerkleSignature",
    "MerkleSigner",
    "merkle_verify",
]

_LEAF_DOMAIN = b"pqattest/leaf"
_NODE_DOMAIN = b"pqattest/node"
_MIN_HEIGHT = 1
_MAX_HEIGHT = 8

_CHECKPOINT_MAGIC = b"PQAMSCP\0"
_CHECKPOINT_VERSION = 1
# magic(8) + version(1) + w(1) + height(1) + next_index(2) + count(4) + root(32)
_CHECKPOINT_HEADER_BYTES = 49
_CHECKPOINT_CHECKSUM_BYTES = 32


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


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_DOMAIN + left + right).digest()


def _tree_layers(leaves: list[bytes]) -> list[list[bytes]]:
    """Stack Merkle layers above ``leaves`` up to and including the root."""
    layers = [leaves]
    while len(layers[-1]) > 1:
        level = layers[-1]
        layers.append(
            [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        )
    return layers


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


class MerkleSigner:
    """Thread-safe, in-process few-times signer over a Merkle tree of W-OTS keys.

    Leaves are allocated in increasing order starting at 0; a leaf is consumed
    only by a successful :meth:`sign`. Once every leaf is spent, further calls
    raise :class:`KeyExhaustedError`.
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
        _, l1, l2 = _params(w)
        private_keys = []
        leaves = []
        for _ in range(1 << height):
            wots_private, wots_public = wots_keygen(w=w, token_bytes=token_bytes)
            private_keys.append(wots_private)
            leaves.append(_leaf_hash(w, wots_public.elements))
        layers = _tree_layers(leaves)
        self._w = w
        self._height = height
        self._chains = l1 + l2
        self._private_keys = tuple(private_keys)
        self._layers = tuple(tuple(layer) for layer in layers)
        self._next_index = 0
        self._lock = threading.Lock()
        self._public_key = MerklePublicKey(w=w, height=height, root=layers[-1][0])

    @property
    def public_key(self) -> MerklePublicKey:
        """The Merkle public key committing to every leaf (read-only)."""
        return self._public_key

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
            wots_signature = wots_sign(message, self._private_keys[index])
            self._next_index += 1
            auth_path = tuple(
                self._layers[level][(index >> level) ^ 1]
                for level in range(self._height)
            )
            return MerkleSignature(
                index=index, wots_signature=wots_signature, auth_path=auth_path
            )

    def checkpoint(self) -> bytes:
        """Serialise the full private state into an opaque byte string.

        The snapshot contains every W-OTS private key and the current leaf
        cursor; :meth:`from_checkpoint` restores a signer with the identical
        public key that continues allocating leaves at the saved
        ``next_index``. The snapshot is taken under the same lock as
        :meth:`sign`, so a concurrent checkpoint always falls either before
        or after a complete signature — never in the middle of one.

        The v1 binary layout is: the 8-byte magic ``b"PQAMSCP\\0"``, one byte
        each of version (1), ``w`` and ``height``, a 2-byte big-endian
        ``next_index``, a 4-byte big-endian element count (always
        ``2 ** height`` times the chain count for ``w``), the 32-byte Merkle
        root, then every 32-byte W-OTS private element in leaf-then-chain
        order, and finally the SHA-256 of all preceding bytes.

        .. warning::
           The bytes are plaintext key material: the trailing SHA-256 only
           detects accidental corruption, it neither authenticates nor
           encrypts. Store checkpoints securely and persist them atomically
           after every successful signature — restoring an older checkpoint
           re-issues spent leaves and destroys unforgeability.
        """
        with self._lock:
            parts = [
                _CHECKPOINT_MAGIC,
                bytes((_CHECKPOINT_VERSION, self._w, self._height)),
                self._next_index.to_bytes(2, "big"),
                (len(self._private_keys) * self._chains).to_bytes(4, "big"),
                self._public_key.root,
            ]
            parts.extend(
                element for key in self._private_keys for element in key.elements
            )
            body = b"".join(parts)
            return body + hashlib.sha256(body).digest()

    @classmethod
    def from_checkpoint(cls, data: Any) -> "MerkleSigner":
        """Restore a signer from :meth:`checkpoint` bytes; no randomness is drawn.

        The restored signer has the identical public key and continues leaf
        allocation at the saved ``next_index``; if the snapshot was taken with
        every leaf spent, signing raises :class:`KeyExhaustedError` as before.
        Only ``bytes``/``bytearray`` are accepted — anything else raises
        ``TypeError``. A bad magic, version, length, ``w``, height,
        ``next_index`` outside ``0 .. 2 ** height``, element count, checksum,
        or a Merkle root that does not match the tree rebuilt from the
        private keys raises ``ValueError`` and no instance is returned.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("checkpoint data must be bytes or bytearray")
        data = bytes(data)
        if len(data) < _CHECKPOINT_HEADER_BYTES + _CHECKPOINT_CHECKSUM_BYTES:
            raise ValueError("checkpoint is too short")
        if data[:8] != _CHECKPOINT_MAGIC:
            raise ValueError("bad checkpoint magic")
        if data[8] != _CHECKPOINT_VERSION:
            raise ValueError(f"unsupported checkpoint version: {data[8]}")
        w = _validate_w(data[9])
        height = _validate_height(data[10])
        next_index = int.from_bytes(data[11:13], "big")
        element_count = int.from_bytes(data[13:17], "big")
        root = data[17:_CHECKPOINT_HEADER_BYTES]
        leaf_count = 1 << height
        if next_index > leaf_count:
            raise ValueError(
                f"next_index must satisfy 0 <= next_index <= {leaf_count}"
            )
        _, l1, l2 = _params(w)
        chains = l1 + l2
        if element_count != leaf_count * chains:
            raise ValueError(
                "element count must equal 2 ** height times the chain count"
            )
        expected = (
            _CHECKPOINT_HEADER_BYTES
            + element_count * ELEMENT_BYTES
            + _CHECKPOINT_CHECKSUM_BYTES
        )
        if len(data) != expected:
            raise ValueError("checkpoint length mismatch")
        body = data[:-_CHECKPOINT_CHECKSUM_BYTES]
        if hashlib.sha256(body).digest() != data[-_CHECKPOINT_CHECKSUM_BYTES:]:
            raise ValueError("checkpoint checksum mismatch")
        elements = data[_CHECKPOINT_HEADER_BYTES:-_CHECKPOINT_CHECKSUM_BYTES]
        key_bytes = chains * ELEMENT_BYTES
        private_keys = tuple(
            WOTSPrivateKey(
                w=w,
                elements=tuple(
                    elements[offset : offset + ELEMENT_BYTES]
                    for offset in range(
                        leaf * key_bytes, (leaf + 1) * key_bytes, ELEMENT_BYTES
                    )
                ),
            )
            for leaf in range(leaf_count)
        )
        b = 1 << w
        leaves = [
            _leaf_hash(
                w, tuple(_chain_walk(element, b - 1) for element in key.elements)
            )
            for key in private_keys
        ]
        layers = _tree_layers(leaves)
        if layers[-1][0] != root:
            raise ValueError("checkpoint root does not match the private keys")
        signer = cls.__new__(cls)
        signer._w = w
        signer._height = height
        signer._chains = chains
        signer._private_keys = private_keys
        signer._layers = tuple(tuple(layer) for layer in layers)
        signer._next_index = next_index
        signer._lock = threading.Lock()
        signer._public_key = MerklePublicKey(w=w, height=height, root=root)
        return signer


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

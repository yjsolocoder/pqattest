"""Merkle-tree aggregation of W-OTS keys: a few-times signature scheme.

A :class:`MerkleSigner` holds ``2 ** height`` W-OTS key pairs. Their public
keys are hashed into a binary Merkle tree whose root is the single public
key; each signature spends one leaf (one W-OTS key pair) and carries the
authentication path proving that leaf belongs to the tree. One tree can
therefore sign up to ``2 ** height`` messages, each leaf at most once.

Leaf hashes are ``SHA-256(b"pqattest/leaf" || w_byte || public elements)``
and inner nodes are ``SHA-256(b"pqattest/node" || left || right)``. Only the
standard library is used and all state lives in memory — nothing persists
across processes.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from . import KeyExhaustedError
from .wots import (
    ELEMENT_BYTES,
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
_MAX_HEIGHT = 8


def _validate_height(height: Any) -> int:
    if isinstance(height, bool) or not isinstance(height, int) or not 1 <= height <= _MAX_HEIGHT:
        raise ValueError(f"height must be an integer between 1 and {_MAX_HEIGHT}")
    return height


def _leaf_hash(w: int, elements: Sequence[bytes]) -> bytes:
    return hashlib.sha256(_LEAF_DOMAIN + bytes([w]) + b"".join(elements)).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_DOMAIN + left + right).digest()


def _validate_path(index: int, auth_path: Any) -> None:
    if not isinstance(auth_path, tuple):
        raise TypeError("auth_path must be a tuple of 32-byte nodes")
    if not 1 <= len(auth_path) <= _MAX_HEIGHT:
        raise ValueError(f"auth_path must contain between 1 and {_MAX_HEIGHT} nodes")
    for node in auth_path:
        if not isinstance(node, bytes) or len(node) != ELEMENT_BYTES:
            raise ValueError(f"every auth_path node must be exactly {ELEMENT_BYTES} bytes")
    if index >= 1 << len(auth_path):
        raise ValueError("index is out of range for the auth_path depth")


@dataclass(frozen=True)
class MerklePublicKey:
    """Frozen Merkle public key: the tree root plus the parameters needed to
    recompute it — the Winternitz parameter ``w`` and the tree ``height``."""

    w: int
    height: int
    root: bytes

    def __post_init__(self) -> None:
        _validate_w(self.w)
        _validate_height(self.height)
        if not isinstance(self.root, bytes):
            raise TypeError("root must be bytes")
        if len(self.root) != ELEMENT_BYTES:
            raise ValueError(f"root must be exactly {ELEMENT_BYTES} bytes")


@dataclass(frozen=True)
class MerkleSignature:
    """Frozen Merkle signature: the leaf ``index``, the W-OTS signature
    produced with that leaf's key, and the authentication path from the leaf
    layer up to (but excluding) the root."""

    index: int
    wots_signature: tuple[bytes, ...]
    auth_path: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int):
            raise ValueError("index must be an integer")
        if self.index < 0:
            raise ValueError("index must be non-negative")
        if not isinstance(self.wots_signature, tuple):
            raise TypeError("wots_signature must be a tuple of 32-byte values")
        valid_lengths = {_params(w)[1] + _params(w)[2] for w in (4, 8)}
        if len(self.wots_signature) not in valid_lengths:
            raise ValueError("wots_signature has the wrong number of elements")
        for element in self.wots_signature:
            if not isinstance(element, bytes) or len(element) != ELEMENT_BYTES:
                raise ValueError(f"every element must be exactly {ELEMENT_BYTES} bytes")
        _validate_path(self.index, self.auth_path)


class MerkleSigner:
    """Thread-safe few-times signer: one Merkle tree over W-OTS key pairs.

    Leaves are allocated sequentially starting at index 0. A leaf is consumed
    only by a successful :meth:`sign`; an unsupported message type raises
    ``TypeError`` and leaves the allocation untouched. Once every leaf is
    spent, :meth:`sign` raises :class:`KeyExhaustedError`. Concurrent calls
    are serialised so no index is ever handed out twice.
    """

    __slots__ = ("_lock", "_height", "_w", "_private_keys", "_layers", "_public_key", "_next_index")

    def __init__(
        self,
        *,
        height: int = 4,
        w: int = 4,
        token_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        height = _validate_height(height)
        w = _validate_w(w)
        self._lock = threading.Lock()
        self._height = height
        self._w = w
        pairs = [wots_keygen(w=w, token_bytes=token_bytes) for _ in range(1 << height)]
        self._private_keys = tuple(private for private, _ in pairs)
        layers = [[_leaf_hash(w, public.elements) for _, public in pairs]]
        while len(layers[-1]) > 1:
            layer = layers[-1]
            layers.append([_node_hash(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)])
        self._layers = tuple(tuple(layer) for layer in layers)
        self._public_key = MerklePublicKey(w=w, height=height, root=self._layers[-1][0])
        self._next_index = 0

    @property
    def public_key(self) -> MerklePublicKey:
        """The tree's public key (read-only)."""
        return self._public_key

    @property
    def remaining(self) -> int:
        """Number of leaves still available for signing (read-only)."""
        return len(self._private_keys) - self._next_index

    def sign(self, message: Any) -> MerkleSignature:
        """Sign ``message`` with the next unused leaf.

        Accepts ``bytes``/``bytearray``/``str`` like the underlying W-OTS
        signer. Only a successful call consumes a leaf.
        """
        with self._lock:
            if self._next_index >= len(self._private_keys):
                raise KeyExhaustedError("all leaves of this Merkle tree have been used")
            index = self._next_index
            # wots_sign raises TypeError for a bad message before any state changes.
            wots_signature = wots_sign(message, self._private_keys[index])
            auth_path = tuple(
                self._layers[level][(index >> level) ^ 1]
                for level in range(self._height)
            )
            self._next_index += 1
            return MerkleSignature(
                index=index,
                wots_signature=wots_signature,
                auth_path=auth_path,
            )


def merkle_verify(message: Any, signature: Any, public_key: Any) -> bool:
    """Recompute the root from the signature and compare it to ``public_key``.

    The W-OTS public endpoints are recovered from the signature, hashed into
    the leaf, and folded with the authentication path — at each level the
    corresponding bit of ``index`` decides whether the running node is the
    left or the right child. Returns ``False`` for any structural, parameter
    or content mismatch; only a wrong public key *type* raises ``TypeError``.
    """
    if not isinstance(public_key, MerklePublicKey):
        raise TypeError("public_key must be a MerklePublicKey")
    if not isinstance(signature, MerkleSignature):
        return False
    w = public_key.w
    if len(signature.auth_path) != public_key.height:
        return False
    if signature.index >= 1 << public_key.height:
        return False
    b, l1, l2 = _params(w)
    if len(signature.wots_signature) != l1 + l2:
        return False

    try:
        digits = _signing_digits(message, w)
    except TypeError:
        return False
    endpoints = tuple(
        _chain_walk(element, b - 1 - digit)
        for element, digit in zip(signature.wots_signature, digits)
    )
    node = _leaf_hash(w, endpoints)
    for level, sibling in enumerate(signature.auth_path):
        if (signature.index >> level) & 1:
            node = _node_hash(sibling, node)
        else:
            node = _node_hash(node, sibling)
    return secrets.compare_digest(node, public_key.root)

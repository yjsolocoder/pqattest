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
public key; :meth:`MerkleProof.verify_bound` and
:meth:`MerkleBatchProof.verify_bound` additionally bind such proofs to the
receiver's expected public key and, optionally, an explicit leaf-index
selection. The top-level :func:`multiproof_encode` /
:func:`multiproof_verify` pair compresses several signatures of the same
public key further into one deterministic proof whose shared authentication
nodes are deduplicated into a canonical node set;
:func:`multiproof_verify_bound` additionally binds such a proof to the
receiver's expected public key and, optionally, an explicit leaf-index
selection. :func:`multiproof_select` re-emits a chosen subset of a verified
multiproof's leaves as a fresh standalone v1 multiproof — using only the
source proof, its messages and the expected public key, with no access to
the original signatures or any private key. :func:`multiproof_merge` is
the union counterpart: it combines the leaf sets of several verified
multiproofs into one fresh v1 multiproof from the source proofs, their
messages and the expected public key alone. :func:`multiproof_expand` is
the inverse of :func:`multiproof_encode`: it restores a verified
multiproof to an ordinary :class:`MerkleBatchProof` of standalone
:class:`MerkleSignature` values, again from the source proof, its
messages and the expected public key alone. Signer
state can be persisted explicitly with
:meth:`MerkleSigner.checkpoint` /
:meth:`MerkleSigner.from_checkpoint`; the checkpoint contains every private
key and is protected only by a SHA-256 checksum against accidental
corruption, so callers must store it securely. Alternatively,
:meth:`MerkleSigner.from_seed` derives the whole leaf tree deterministically
from a 32-byte secret seed, and such a signer can be persisted compactly
with :meth:`MerkleSigner.seed_checkpoint` /
:meth:`MerkleSigner.from_seed_checkpoint` — a separate versioned 109-byte
format that stores the seed instead of every private key and is likewise
plaintext secret material.

Every signing and verification entry optionally accepts a keyword-only
``context``: when omitted (or given as an empty value) the message is
hashed exactly as the unbound baseline and existing v1 serialised bytes
verify unchanged; when given, the same ``bytes``/``bytearray``/``str``
(UTF-8 encoded) context must be supplied to both sides or verification
fails.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Callable

from ._errors import KeyExhaustedError
from .auth import (
    _validate_generation,
    _validate_key,
    auth_state_unwrap,
    auth_state_wrap,
)
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
    "multiproof_expand",
    "multiproof_merge",
    "multiproof_select",
    "multiproof_verify",
    "multiproof_verify_bound",
]

_LEAF_DOMAIN = b"pqattest/leaf"
_NODE_DOMAIN = b"pqattest/node"
_CONTEXT_DOMAIN = b"pqattest/merkle/context/v1"
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

_SEED_CHECKPOINT_MAGIC = b"PQAMSED\0"
_SEED_CHECKPOINT_VERSION = 1
_SEED_CHECKPOINT_HEADER_BYTES = 8 + 1 + 1 + 1 + 2 + ELEMENT_BYTES + ELEMENT_BYTES
_SEED_CHECKPOINT_BYTES = _SEED_CHECKPOINT_HEADER_BYTES + _CHECKPOINT_CHECKSUM_BYTES

_SEED_ELEMENT_DOMAIN = b"pqattest/merkle/seed/v1"

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
    """Bind ``message`` to ``context`` for the W-OTS message digest.

    ``context`` must already be normalised by :func:`_validate_context`.
    The empty context passes ``message`` through untouched, so the
    no-context path hashes exactly as the unbound baseline and existing
    signatures stay byte-for-byte identical. With a non-empty context the
    domain separator, both length-prefixed fields and the message are hashed
    by :func:`wots._signing_digits` as one unambiguous byte string, so the
    same message under two contexts produces two incompatible signatures.
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


def _merkle_signing_digits(
    message: Any, w: int, context: bytes = b""
) -> tuple[int, ...]:
    """W-OTS signing digits for ``message`` bound to ``context``."""
    return _signing_digits(_context_message(context, message), w)


def _leaf_hash(w: int, elements: tuple[bytes, ...]) -> bytes:
    return hashlib.sha256(_LEAF_DOMAIN + bytes([w]) + b"".join(elements)).digest()


def _seed_element(
    seed: bytes, w: int, height: int, leaf_index: int, chain_index: int
) -> bytes:
    """Derive one W-OTS private element deterministically from ``seed``.

    The leaf index, the chain position and the ``(w, height)`` parameter
    combination are all bound into the derivation, so every element of every
    leaf of every parameter set is an independent domain-separated hash.
    """
    return hashlib.sha256(
        _SEED_ELEMENT_DOMAIN
        + bytes((w, height))
        + leaf_index.to_bytes(4, "big")
        + chain_index.to_bytes(4, "big")
        + seed
    ).digest()


def _derive_seed_keys(
    seed: bytes, w: int, height: int
) -> tuple[tuple[WOTSPrivateKey, ...], list[bytes]]:
    """Re-derive every private key and leaf hash for a seed-derived signer."""
    b, l1, l2 = _params(w)
    chains = l1 + l2
    private_keys = []
    leaves = []
    for leaf_index in range(1 << height):
        elements = tuple(
            _seed_element(seed, w, height, leaf_index, chain_index)
            for chain_index in range(chains)
        )
        private_keys.append(WOTSPrivateKey(w=w, elements=elements))
        endpoints = tuple(_chain_walk(element, b - 1) for element in elements)
        leaves.append(_leaf_hash(w, endpoints))
    return tuple(private_keys), leaves


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
    it can be transported on its own and verified with :meth:`verify`.
    :meth:`verify_bound` additionally binds the proof to the receiver's
    expected public key and, optionally, an explicit leaf-index selection.
    The proof stores no message and is a pure serialisation container: it
    offers neither authentication nor encryption of the wrapper itself.
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

    def verify(self, message: Any, *, context: Any = None) -> bool:
        """Verify the embedded signature against the embedded public key.

        Accepts ``bytes``/``bytearray``/``str`` exactly like
        :func:`merkle_verify`, to which this call delegates; it returns
        ``True`` only for the message that was actually signed. The proof
        itself carries no message and cannot authenticate its own origin.

        ``context`` is keyword-only and optional: ``None`` (the default) and
        an empty value both mean "no context" and verify legacy unbound
        signatures; any other ``bytes``/``bytearray``/``str`` (``str`` encoded
        as UTF-8) must match the signing context exactly, else the signature
        fails to verify. A context of any other type raises ``TypeError``.
        """
        return merkle_verify(
            message, self.signature, self.public_key, context=context
        )

    def verify_bound(
        self,
        message: Any,
        *,
        public_key: Any,
        index: Any = None,
        context: Any = None,
    ) -> bool:
        """Verify the signature and bind the proof to an expected key/leaf.

        First requires ``public_key`` to equal the public key embedded in the
        proof value by value (``w``, ``height`` and ``root``), then runs the
        exact verification of :meth:`verify` — ``message`` is checked with
        :func:`merkle_verify` against the embedded signature, accepting
        ``bytes``/``bytearray``/``str`` (a ``str`` is encoded as UTF-8). No
        wire format changes, no new objects, no randomness and no state are
        involved.

        ``context`` is keyword-only and optional and follows the same rules
        as :meth:`verify`: ``None``/empty means no context, while a non-empty
        context must be the one used at signing; the wrong context makes the
        bound check return ``False``, and a context of a wrong type raises
        ``TypeError``.

        ``public_key`` must be a :class:`MerklePublicKey`; any other type
        raises ``TypeError``. ``index=None`` imposes no constraint on the
        leaf selection. An explicit ``index`` must be a non-boolean integer
        equal to the signature's leaf ``index``: a value that is not an
        integer at all raises ``TypeError``, while a boolean, a negative or
        out-of-range value, or one unequal to the signature index returns
        ``False``. Missing or mistyped embedded fields (including values
        corrupted by bypassing the frozen constructor), and any message,
        signature or public-key mismatch return ``False`` without leaking
        any other exception.
        """
        if not isinstance(public_key, MerklePublicKey):
            raise TypeError("public_key must be a MerklePublicKey")
        context_bytes = _validate_context(context)
        if index is not None:
            # ``bool`` is a subtype of ``int``, but a boolean is not an
            # acceptable leaf selection: it falls through to the structural
            # checks below and returns ``False``.
            if not isinstance(index, int):
                raise TypeError("index must be an integer")
        try:
            embedded_key = self.public_key
            signature = self.signature
            if not isinstance(embedded_key, MerklePublicKey):
                return False
            if not isinstance(signature, MerkleSignature):
                return False
            if (
                public_key.w != embedded_key.w
                or public_key.height != embedded_key.height
                or public_key.root != embedded_key.root
            ):
                return False
            if not merkle_verify(
                message, signature, embedded_key, context=context_bytes
            ):
                return False
            if index is None:
                return True
            signature_index = signature.index
            if (
                isinstance(index, bool)
                or isinstance(signature_index, bool)
                or not isinstance(signature_index, int)
                or index < 0
                or index >= (1 << embedded_key.height)
                or index != signature_index
            ):
                return False
            return True
        except Exception:
            # A bypass-constructed proof may carry arbitrary field objects
            # whose access or comparison raises anything; the bound check
            # reports every such malformed structure as ``False``. External
            # argument type errors were raised before this block.
            return False


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
    self-contained object and verifies with :meth:`verify`.
    :meth:`verify_bound` additionally binds the batch to the receiver's
    expected public key and, optionally, an explicit leaf-index selection.
    ``signatures`` must be a non-empty tuple whose leaf indices are strictly
    increasing (hence unique). The batch stores no messages and is a pure
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

    def verify(self, messages: Any, *, context: Any = None) -> bool:
        """Verify every embedded signature against the embedded public key.

        ``messages`` must be a ``tuple`` of the same length as
        ``signatures``; each member accepts
        ``bytes``/``bytearray``/``str`` exactly like :func:`merkle_verify`,
        to which every item delegates in tuple order. Returns ``True``
        only when every signature verifies against its message; a
        non-tuple argument, a count mismatch, an illegal message member or
        any verification failure returns ``False``.

        ``context`` is keyword-only and optional: ``None`` (the default) and
        an empty value both mean "no context" and verify legacy unbound
        signatures; any other ``bytes``/``bytearray``/``str`` (``str`` encoded
        as UTF-8) must be the one shared by every signed message in the
        batch, in the same order. A context of any other type raises
        ``TypeError``.
        """
        context_bytes = _validate_context(context)
        if not isinstance(messages, tuple):
            return False
        if len(messages) != len(self.signatures):
            return False
        return all(
            merkle_verify(
                message, signature, self.public_key, context=context_bytes
            )
            for message, signature in zip(messages, self.signatures)
        )

    def verify_bound(
        self,
        messages: Any,
        *,
        public_key: Any,
        indices: Any = None,
        context: Any = None,
    ) -> bool:
        """Verify every signature and bind the batch to an expected key/leaves.

        Runs the exact per-item verification of :meth:`verify` — each member
        of ``messages`` is checked with :func:`merkle_verify` against the
        signature at the same tuple position, accepting
        ``bytes``/``bytearray``/``str`` (a ``str`` is encoded as UTF-8) — and
        additionally requires ``public_key`` to equal the public key embedded
        in the batch value by value (``w``, ``height`` and ``root``). No wire
        format changes, no new objects, no randomness and no state are
        involved.

        ``context`` is keyword-only and optional and follows the same rules
        as :meth:`verify`: ``None``/empty means no context, while a non-empty
        context must be the one shared by every signed message; the wrong
        context makes the bound check return ``False``, and a context of a
        wrong type raises ``TypeError``.

        ``public_key`` must be a :class:`MerklePublicKey`; any other type
        raises ``TypeError``. ``indices=None`` imposes no constraint on the
        leaf selection. An explicit ``indices`` must be a tuple — any other
        container type raises ``TypeError``, as does any member that is not an
        integer — with exactly as many members as ``messages``; every member
        must be a non-boolean integer, the values must be strictly increasing
        and identical, position by position, to the ``index`` of the
        signature in the same slot. A boolean member, a duplicate, an
        out-of-order or out-of-range value, a wrong count, a non-tuple or
        ill-sized ``messages``, an illegal message member, a missing or
        mistyped embedded public key or signature field (an empty or
        non-tuple ``signatures`` included, including values corrupted by
        bypassing the frozen constructor), and any cryptographic, structural
        or public-key-value mismatch all return ``False``.
        """
        if not isinstance(public_key, MerklePublicKey):
            raise TypeError("public_key must be a MerklePublicKey")
        context_bytes = _validate_context(context)
        if indices is not None:
            if not isinstance(indices, tuple):
                raise TypeError("indices must be a tuple of integers")
            for index in indices:
                if not isinstance(index, int):
                    raise TypeError("every index must be an integer")
        try:
            embedded_key = self.public_key
            signatures = self.signatures
            if not isinstance(embedded_key, MerklePublicKey):
                return False
            if not isinstance(signatures, tuple) or not signatures:
                return False
            if not all(
                isinstance(signature, MerkleSignature) for signature in signatures
            ):
                return False
            if not isinstance(messages, tuple) or len(messages) != len(signatures):
                return False
            if not all(
                merkle_verify(
                    message, signature, embedded_key, context=context_bytes
                )
                for message, signature in zip(messages, signatures)
            ):
                return False
            if (
                public_key.w != embedded_key.w
                or public_key.height != embedded_key.height
                or public_key.root != embedded_key.root
            ):
                return False
            if indices is None:
                return True
            if len(indices) != len(messages):
                return False
            if any(isinstance(index, bool) for index in indices):
                return False
            if any(former >= latter for former, latter in zip(indices, indices[1:])):
                return False
            leaf_count = 1 << embedded_key.height
            if any(index < 0 or index >= leaf_count for index in indices):
                return False
            return indices == tuple(signature.index for signature in signatures)
        except Exception:
            # A bypass-constructed batch may carry arbitrary field objects
            # whose access or comparison raises anything; the bound check
            # reports every such malformed structure as ``False``. External
            # argument type errors were raised before this block.
            return False


class MerkleSigner:
    """Thread-safe, in-process few-times signer over a Merkle tree of W-OTS keys.

    Leaves are allocated in increasing order starting at 0; a leaf is consumed
    only by a successful :meth:`sign`, :meth:`sign_batch`,
    :meth:`sign_selected`, :meth:`sign_selected_with_checkpoint`,
    :meth:`sign_selected_with_auth_state`,
    :meth:`sign_with_checkpoint`, :meth:`sign_batch_with_checkpoint`,
    :meth:`sign_multiproof_with_checkpoint`,
    :meth:`sign_proof_with_checkpoint`,
    :meth:`sign_batch_proof_with_checkpoint`,
    :meth:`sign_with_auth_state`, :meth:`sign_batch_with_auth_state`,
    :meth:`sign_multiproof_with_auth_state`,
    :meth:`sign_proof_with_auth_state` or
    :meth:`sign_batch_proof_with_auth_state`. Once
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
        self._seed: bytes | None = None

    @classmethod
    def from_seed(cls, seed: Any, *, height: int = 4, w: int = 4) -> "MerkleSigner":
        """Derive a signer deterministically from a 32-byte secret seed.

        Every W-OTS private element of every leaf is derived from ``seed``
        with a domain-separated SHA-256 that binds the leaf index, the chain
        position and the ``(w, height)`` parameter combination, so the same
        ``seed``, ``w`` and ``height`` always produce the same public key and
        the same per-leaf signatures, while a different seed produces a
        different public key. ``w`` and ``height`` follow the same rules as
        the random constructor. No randomness is drawn.

        ``seed`` must be exactly 32 bytes of ``bytes`` or ``bytearray``; any
        other type raises ``TypeError`` and any other length raises
        ``ValueError``. The seed is a secret: anyone holding it can re-derive
        every private key, so protect it like a private key. A seed-derived
        signer behaves exactly like a randomly generated one through every
        public entry point, and additionally supports the compact
        :meth:`seed_checkpoint` snapshot.
        """
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError("seed must be bytes or bytearray")
        seed = bytes(seed)
        if len(seed) != ELEMENT_BYTES:
            raise ValueError(f"seed must be exactly {ELEMENT_BYTES} bytes")
        w = _validate_w(w)
        height = _validate_height(height)
        private_keys, leaves = _derive_seed_keys(seed, w, height)
        signer = cls.__new__(cls)
        signer._init_state(w, height, private_keys, leaves, 0)
        signer._seed = seed
        return signer

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

    def seed_checkpoint(self) -> bytes:
        """Serialise a seed-derived signer's state to a compact 109-byte blob.

        Only available on a signer created by :meth:`from_seed` (or restored
        by :meth:`from_seed_checkpoint`): instead of every private key, the
        snapshot stores the 32-byte seed from which they are re-derived. The
        v1 layout is: the 8-byte magic ``b"PQAMSED\\0"``; one byte each for
        the version (1), ``w`` and ``height``; ``next_index`` as 2 big-endian
        bytes; the 32-byte seed; the 32-byte Merkle root; and finally the
        SHA-256 of all preceding content — 109 bytes in total. Encoding is
        deterministic: the same state always produces the same bytes, so
        repeated calls on an unchanged state return identical bytes, and a
        snapshot taken after signing, advancing or exhausting reflects the
        index at that moment.

        The snapshot shares the signing lock, so a concurrent snapshot
        reflects the state either immediately before or immediately after an
        in-flight :meth:`sign`, never part-way through one. A signer that was
        not seed-derived raises ``ValueError``. The blob contains the seed —
        and therefore every private key — in the clear and the trailing hash
        only detects accidental corruption — store it as a secret. This is a
        separate versioned format from :meth:`checkpoint`;
        :meth:`from_checkpoint` does not accept it and
        :meth:`from_seed_checkpoint` does not accept the full format.
        """
        with self._lock:
            if self._seed is None:
                raise ValueError(
                    "seed_checkpoint is only available on a seed-derived signer"
                )
            body = (
                _SEED_CHECKPOINT_MAGIC
                + bytes((_SEED_CHECKPOINT_VERSION, self._w, self._height))
                + self._next_index.to_bytes(2, "big")
                + self._seed
                + self._public_key.root
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

    @classmethod
    def from_seed_checkpoint(cls, data: Any) -> "MerkleSigner":
        """Restore a seed-derived signer from ``seed_checkpoint()`` output.

        Re-derives every private key from the embedded seed and resumes at
        the saved ``next_index`` — no randomness is drawn. The restored
        signer has the same public key, ``next_index`` and ``remaining`` as
        the snapshot, keeps the exhaustion semantics (a snapshot taken after
        the last leaf was spent restores an exhausted signer, and the index
        never moves backwards), supports every existing public entry point,
        and is itself seed-derived, so :meth:`seed_checkpoint` works on it.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, a length other than
        exactly 109 bytes (truncated or with trailing data), an invalid
        ``w`` or ``height``, a ``next_index`` outside ``0 .. 2 ** height``, a
        checksum mismatch, or a Merkle root that does not match the one
        rebuilt from the seed raises ``ValueError`` and no partial instance
        is returned. The full :meth:`checkpoint` format is a separate
        versioned format and is not accepted here.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("seed checkpoint data must be bytes or bytearray")
        data = bytes(data)
        if len(data) < _SEED_CHECKPOINT_BYTES:
            raise ValueError("seed checkpoint is truncated")
        if len(data) > _SEED_CHECKPOINT_BYTES:
            raise ValueError("trailing data after the seed checkpoint encoding")
        body, checksum = (
            data[:-_CHECKPOINT_CHECKSUM_BYTES],
            data[-_CHECKPOINT_CHECKSUM_BYTES:],
        )
        if body[:8] != _SEED_CHECKPOINT_MAGIC:
            raise ValueError("bad seed checkpoint magic")
        if body[8] != _SEED_CHECKPOINT_VERSION:
            raise ValueError(f"unsupported seed checkpoint version: {body[8]}")
        w = _validate_w(body[9])
        height = _validate_height(body[10])
        next_index = int.from_bytes(body[11:13], "big")
        seed = body[13 : 13 + ELEMENT_BYTES]
        root = body[13 + ELEMENT_BYTES : _SEED_CHECKPOINT_HEADER_BYTES]
        if next_index > (1 << height):
            raise ValueError("next_index exceeds the leaf count")
        if hashlib.sha256(body).digest() != checksum:
            raise ValueError("seed checkpoint checksum mismatch")
        private_keys, leaves = _derive_seed_keys(seed, w, height)
        signer = cls.__new__(cls)
        signer._init_state(w, height, private_keys, leaves, next_index)
        if signer._public_key.root != root:
            raise ValueError("Merkle root rebuilt from the seed does not match")
        signer._seed = seed
        return signer

    @classmethod
    def from_auth_state(
        cls, data: Any, *, key: Any, min_generation: Any = None
    ) -> tuple["MerkleSigner", int]:
        """Restore a signer from a v2 :func:`auth_state_wrap` envelope.

        Combines v2 verification, the generation floor and the v1 checkpoint
        restore in one call without drawing randomness. Only an envelope
        produced by :func:`auth_state_wrap` is accepted — no new format is
        introduced — and ``key``/``min_generation`` are keyword-only. Returns
        ``(signer, generation)``: the restored :class:`MerkleSigner` and the
        non-negative uint64 generation carried in the envelope. The restored
        signer has the same public key, ``next_index`` and exhaustion
        semantics as :meth:`from_checkpoint` would give for the embedded
        checkpoint; the floor is not stored in the envelope and remains the
        caller's responsibility in trusted storage.

        ``data`` must be ``bytes`` or ``bytearray``; ``key`` must be a
        non-empty ``bytes``/``bytearray`` shared secret; ``min_generation``
        must be ``None`` or a non-boolean integer in ``0 .. 2**64 - 1``. A
        wrong type (including a boolean floor) raises ``TypeError``. The v2
        HMAC tag is verified first with :func:`hmac.compare_digest`, the
        envelope scheme is then fixed to ``"merkle"`` and the generation
        floor applied, and only afterwards is the untouched payload handed to
        :meth:`from_checkpoint`; an empty key, a bad tag or envelope, a
        non-merkle scheme (including a v1 envelope), a generation below the
        floor, or an invalid checkpoint raises ``ValueError`` and no instance
        is returned.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes or bytearray")
        key_bytes = _validate_key(key)
        if min_generation is not None:
            _validate_generation(min_generation, "min_generation")
        _, generation_value, checkpoint = auth_state_unwrap(
            data, key=key_bytes, expect="merkle",
            min_generation=min_generation,
        )
        signer = cls.from_checkpoint(checkpoint)
        return signer, generation_value

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

    def _signature_at(
        self, index: int, message: Any, context: bytes = b""
    ) -> MerkleSignature:
        """Build the signature for ``message`` at leaf ``index``.

        Does not touch signer state: the caller holds the lock and decides
        whether and when to advance ``_next_index``. ``context`` must already
        be normalised by :func:`_validate_context`; the empty context hashes
        ``message`` exactly like the unbound baseline.
        """
        wots_signature = wots_sign(
            _context_message(context, message), self._private_keys[index]
        )
        auth_path = tuple(
            self._layers[level][(index >> level) ^ 1]
            for level in range(self._height)
        )
        return MerkleSignature(
            index=index, wots_signature=wots_signature, auth_path=auth_path
        )

    def sign(self, message: Any, *, context: Any = None) -> MerkleSignature:
        """Sign ``message`` with the next unused leaf.

        Accepts ``bytes``/``bytearray``/``str`` like the W-OTS API. A leaf is
        consumed only when signing succeeds: a rejected message or context
        type raises ``TypeError`` without spending anything, and once all
        leaves are used every call raises :class:`KeyExhaustedError`.
        Concurrent callers never receive the same leaf index.

        ``context`` is keyword-only and optional: ``None`` (the default) and
        an empty ``bytes``/``bytearray``/``str`` both mean "no context" and
        produce the exact unbound signature, while any other ``str`` is
        encoded as UTF-8 and the message digest is bound to it, so a
        signature made under one context verifies only under that same
        context. Signing stays deterministic: the same key, message and
        context always produce the same signature.
        """
        context_bytes = _validate_context(context)
        with self._lock:
            if self._next_index >= len(self._private_keys):
                raise KeyExhaustedError("all Merkle leaves have been used")
            index = self._next_index
            signature = self._signature_at(index, message, context_bytes)
            self._next_index += 1
            return signature

    def sign_batch(
        self, messages: Any, *, context: Any = None
    ) -> tuple[MerkleSignature, ...]:
        """Sign every message in ``messages`` atomically, one leaf each, in order.

        ``messages`` must be a ``tuple`` whose members each follow the usual
        message rules (``bytes``/``bytearray``/``str``); a non-tuple argument
        or an illegal member raises ``TypeError``. ``context`` is
        keyword-only and optional, follows the usual context rules
        (``None``/empty means no context, ``str`` encoded as UTF-8) and is
        bound into every message digest with the same rule as :meth:`sign`;
        the verifier must pass the very same context, in the same message
        order. The whole batch runs under
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
        ``TypeError`` from an illegal message or context leaves the signer
        untouched —
        no leaf is consumed and no partial result is returned either way.
        An empty tuple returns an empty tuple and does not change the state.
        """
        context_bytes = _validate_context(context)
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
                signatures.append(self._signature_at(index, message, context_bytes))
            self._next_index = base + len(signatures)
            return tuple(signatures)

    @staticmethod
    def _validate_selected(indices: Any, messages: Any, context: Any) -> bytes:
        """Validate an explicit leaf selection before the signing lock.

        Shared by :meth:`sign_selected`,
        :meth:`sign_selected_with_checkpoint` and
        :meth:`sign_selected_with_auth_state` so the one-time-key usage
        constraints (what may be signed, in which order errors are raised,
        and that nothing is consumed before every check passes) live in
        exactly one place. Runs entirely outside the lock and never touches
        state: it first normalises ``context`` (raising ``TypeError`` for an
        unsupported context type), then enforces the selection's types and
        structure in the fixed order containers, member types, emptiness,
        equal length, non-boolean indices, strictly increasing indices —
        returning the normalised context bytes on success. Exhaustion and
        the index range are checked afterwards, inside the lock, by
        :meth:`_sign_selected_locked`.
        """
        context_bytes = _validate_context(context)
        if not isinstance(indices, tuple):
            raise TypeError("indices must be a tuple of integers")
        if not isinstance(messages, tuple):
            raise TypeError("messages must be a tuple of messages")
        for index in indices:
            if not isinstance(index, int):
                raise TypeError("every index must be an integer")
        for message in messages:
            _as_bytes(message)
        if not indices:
            raise ValueError("indices must not be empty")
        if len(indices) != len(messages):
            raise ValueError("indices and messages must have the same length")
        if any(isinstance(index, bool) for index in indices):
            raise ValueError("every index must be a non-boolean integer")
        if any(
            former >= latter for former, latter in zip(indices, indices[1:])
        ):
            raise ValueError("indices must be strictly increasing and unique")
        return context_bytes

    def _sign_selected_locked(
        self,
        indices: tuple[int, ...],
        messages: tuple[Any, ...],
        context_bytes: bytes,
        pack: Callable[[int], Any] | None = None,
    ) -> tuple[tuple[MerkleSignature, ...], Any]:
        """Validate the range, sign the selection and advance exactly once.

        Shared state-advancement core of the three explicit-selection
        entries; the caller holds the signing lock and has already passed
        :meth:`_validate_selected` (plus any envelope key/generation
        checks). Exhaustion is reported before the index range, so a
        structurally valid request on an exhausted signer raises
        :class:`KeyExhaustedError` while a not-yet-exhausted signer raises
        ``ValueError`` for an index below ``next_index`` or past the last
        leaf. Every signature is produced first; when ``pack`` is given it
        builds the state artifact (a candidate checkpoint, or an envelope
        over one) at the candidate next index, and any exception it raises
        propagates untouched with nothing committed — only once it returns
        does ``next_index`` move to the last chosen index plus one, so a
        failure consumes no leaf and no observer ever sees a half-signed
        selection or an advanced state without the finished artifact.
        Returns ``(signatures, artifact)`` where ``artifact`` is ``None``
        when ``pack`` is omitted.
        """
        if self._next_index >= len(self._private_keys):
            raise KeyExhaustedError("all Merkle leaves have been used")
        base = self._next_index
        leaf_count = len(self._private_keys)
        if indices[0] < base or indices[-1] >= leaf_count:
            raise ValueError(
                "every index must be between the current next leaf and "
                "the last leaf"
            )
        signatures = tuple(
            self._signature_at(index, message, context_bytes)
            for index, message in zip(indices, messages)
        )
        new_next_index = indices[-1] + 1
        # Build the state output before advancing: any failure must consume
        # no leaf, and no observer must ever see the advanced state without
        # the finished artifact.
        artifact = pack(new_next_index) if pack is not None else None
        self._next_index = new_next_index
        return signatures, artifact

    def sign_selected(
        self, indices: Any, messages: Any, *, context: Any = None
    ) -> tuple[MerkleSignature, ...]:
        """Sign one message per explicitly chosen leaf, voiding the gaps.

        Unlike :meth:`sign_batch`, which allocates consecutive leaves from the
        current ``next_index``, this entry spends exactly the leaves named in
        ``indices``: each message is signed with the leaf at the same tuple
        position, and every skipped leaf below the last chosen one is voided
        just like :meth:`advance_to` — it can never be signed again. On
        success the next usable leaf is the index right after the last chosen
        leaf, so a signer restored from a checkpoint taken afterwards resumes
        there.

        ``indices`` and ``messages`` must both be tuples of equal, non-zero
        length. Validation happens in a fixed order — first the types and
        structure, then exhaustion, then the index range:

        * a non-tuple ``indices`` or ``messages``, an index member that is not
          an integer, or an unsupported message member type raises
          ``TypeError`` (a ``bool`` is an ``int`` subclass, so it survives this
          bullet and is rejected by the structural one below);
        * an empty tuple on either side, a length mismatch, a boolean index,
          a duplicate or non-increasing index raises ``ValueError``;
        * on an exhausted signer (no leaf left to spend) the call raises
          :class:`KeyExhaustedError`;
        * an index below the current ``next_index`` or past the last leaf
          raises ``ValueError``.

        ``context`` is keyword-only and optional and follows the usual
        context rules (``None``/empty means no context, ``str`` encoded as
        UTF-8); the same context is bound into every selected message digest
        and the verifier must pass it unchanged. Only once every check
        passes does the method enter the signing lock
        and produce, in tuple order, one signature per chosen leaf, committing
        the advance exactly once. The whole call shares the same lock as
        :meth:`sign`, :meth:`sign_batch`, :meth:`advance_to` and
        :meth:`checkpoint`, so under concurrency a leaf is allocated at most
        once and no thread ever observes a half-signed selection. A failed
        call consumes no leaf and returns no partial result. When the chosen
        indices are exactly consecutive from ``next_index``, the result is
        value-for-value identical to :meth:`sign_batch` on the same messages
        from the same state; every signature verifies under the long-term
        public key, and ``multiproof_encode``/``multiproof_verify`` bind a
        deduplicated proof for the batch to exactly these leaves. No
        randomness is drawn.
        """
        context_bytes = self._validate_selected(indices, messages, context)
        with self._lock:
            signatures, _ = self._sign_selected_locked(
                indices, messages, context_bytes
            )
            return signatures

    def sign_selected_with_checkpoint(
        self, indices: Any, messages: Any, *, context: Any = None
    ) -> tuple[tuple[MerkleSignature, ...], bytes]:
        """Sign an explicit leaf set and snapshot the advanced state atomically.

        ``context`` is keyword-only and optional: ``None`` and an empty value
        both mean no context and give byte-identical unbound output; any other
        ``bytes``/``bytearray``/``str`` (``str`` encoded as UTF-8) is bound
        into every selected message digest, and the same context must be
        passed unchanged to the matching verification entry.

        Combines :meth:`sign_selected` and :meth:`checkpoint` in one atomic
        call. Returns ``(signatures, checkpoint)``: ``signatures`` is a tuple
        with one :class:`MerkleSignature` per chosen leaf, in the same tuple
        order and each bound to its selected leaf — value-for-value identical
        to calling :meth:`sign_selected` with the same ``indices`` and
        ``messages`` from the same starting state, drawing no extra randomness
        — and ``checkpoint`` is the ``bytes`` that :meth:`checkpoint` returns
        once the selection has been committed, byte-for-byte the same v1
        encoding holding ``next_index`` equal to the last chosen index plus one
        and every private key. A signer restored from it keeps the same public
        key and resumes signing right after the last selected leaf; the
        signatures still go straight into :func:`multiproof_encode` for a
        deduplicated multi-proof.

        ``indices`` and ``messages`` follow exactly the rules of
        :meth:`sign_selected`, validated in the same fixed order — first the
        types and structure, then exhaustion, then the index range:

        * a non-tuple ``indices`` or ``messages``, an index member that is not
          an integer, or an unsupported message member type raises
          ``TypeError``;
        * an empty tuple on either side, a length mismatch, a boolean index,
          a duplicate or non-increasing index raises ``ValueError``;
        * on an exhausted signer (no leaf left to spend) the call raises
          :class:`KeyExhaustedError`;
        * an index below the current ``next_index`` or past the last leaf
          raises ``ValueError``.

        The signatures and the candidate checkpoint are both built under the
        same lock as :meth:`sign`, :meth:`sign_batch`, :meth:`sign_selected`,
        :meth:`advance_to` and :meth:`checkpoint`, and the advance is committed
        exactly once only after both halves exist, so the whole call linearises
        as one operation: under concurrency a leaf is allocated at most once
        and no thread ever observes a half-signed selection or an advanced
        state without the finished checkpoint. Every failure happens without
        spending a leaf and returns no partial result. The returned checkpoint
        still carries every private key in the clear and offers no
        authentication, encryption or atomic persistence — confidentiality,
        durable storage and rollback protection remain the caller's
        responsibility.
        """
        context_bytes = self._validate_selected(indices, messages, context)
        with self._lock:
            signatures, checkpoint = self._sign_selected_locked(
                indices,
                messages,
                context_bytes,
                pack=lambda new_next_index: self._checkpoint_bytes(
                    new_next_index
                ),
            )
            return signatures, checkpoint

    def sign_selected_with_auth_state(
        self,
        indices: Any,
        messages: Any,
        *,
        key: Any,
        generation: Any,
        context: Any = None,
    ) -> tuple[tuple[MerkleSignature, ...], bytes]:
        """Sign an explicit leaf set and return the advanced state as an envelope.

        ``context`` is keyword-only and optional: ``None`` and an empty value
        both mean no context and give byte-identical unbound output; any other
        ``bytes``/``bytearray``/``str`` (``str`` encoded as UTF-8) is bound
        into every selected message digest, and the same context must be
        passed unchanged to the matching verification entry.

        Behaves like :meth:`sign_selected_with_checkpoint` — the same explicit
        leaf allocation, the same tuple of :class:`MerkleSignature` values and
        the same post-selection v1 :meth:`checkpoint` bytes, all under the
        signing lock — but instead of the plaintext checkpoint the second half
        of the returned ``(signatures, envelope)`` tuple is the
        :func:`auth_state_wrap` v2 envelope over that checkpoint with
        ``scheme="merkle"`` and the given keyword-only ``key`` and
        ``generation``, byte-for-byte the same as signing the selection and
        then wrapping an explicit checkpoint; the existing v2 field order and
        HMAC-SHA-256 tag are unchanged. Pairing the two halves in one call keeps
        the signatures and the state they advanced to together, so a caller can
        never match a selection against an envelope taken at the wrong point
        under concurrency.

        ``indices`` and ``messages`` follow exactly the rules of
        :meth:`sign_selected`; ``key`` must be a non-empty
        ``bytes``/``bytearray`` shared secret and ``generation`` must be a
        non-boolean integer in ``0 .. 2**64 - 1``. Every input is validated
        before any state change, in the fixed order types and structure, then
        ``key``/``generation``, then exhaustion, then the index range:

        * a non-tuple ``indices`` or ``messages``, an index member that is not
          an integer, an unsupported message member type, or a wrong
          key/generation type raises ``TypeError``;
        * an empty tuple on either side, a length mismatch, a boolean index,
          a duplicate or non-increasing index, an empty key or an
          out-of-range generation raises ``ValueError``;
        * on an exhausted signer (no leaf left to spend) the call raises
          :class:`KeyExhaustedError`;
        * an index below the current ``next_index`` or past the last leaf
          raises ``ValueError``.

        The signatures, the candidate checkpoint and the envelope are all
        built under the same lock as :meth:`sign`, :meth:`sign_batch`,
        :meth:`sign_selected`, :meth:`advance_to` and :meth:`checkpoint`; the
        advance is committed exactly once — to the last chosen index plus one —
        only after both outputs exist, so the whole call linearises as one
        operation: under concurrency a leaf is allocated at most once and no
        thread ever observes a half-signed selection. Every failure happens
        without spending a leaf and returns no partial result. No randomness is
        drawn anywhere in the call. The envelope is plaintext and authenticated
        only; it provides neither encryption nor protection against replay or
        rollback on its own.
        """
        context_bytes = self._validate_selected(indices, messages, context)
        # The envelope inputs are checked only after the selection's types
        # and structure, matching the fixed order of the other auth-state
        # entries; exhaustion and the index range follow inside the lock.
        key_bytes = _validate_key(key)
        generation_value = _validate_generation(generation, "generation")

        def pack(new_next_index: int) -> bytes:
            checkpoint = self._checkpoint_bytes(new_next_index)
            return auth_state_wrap(
                checkpoint,
                scheme="merkle",
                key=key_bytes,
                generation=generation_value,
            )

        with self._lock:
            signatures, envelope = self._sign_selected_locked(
                indices, messages, context_bytes, pack=pack
            )
            return signatures, envelope

    def sign_with_checkpoint(
        self, message: Any, *, context: Any = None
    ) -> tuple[MerkleSignature, bytes]:
        """Sign ``message`` and snapshot the advanced state in one atomic step.

        ``context`` is keyword-only and optional: ``None`` and an empty value
        both mean no context and give byte-identical unbound output; any other
        ``bytes``/``bytearray``/``str`` (``str`` encoded as UTF-8) is bound
        into the message digest, and the same context must be passed unchanged
        to the matching verification entry.

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
        context_bytes = _validate_context(context)
        with self._lock:
            if self._next_index >= len(self._private_keys):
                raise KeyExhaustedError("all Merkle leaves have been used")
            index = self._next_index
            signature = self._signature_at(index, message, context_bytes)
            self._next_index += 1
            return signature, self._checkpoint_bytes()

    def sign_batch_with_checkpoint(
        self, messages: Any, *, context: Any = None
    ) -> tuple[tuple[MerkleSignature, ...], bytes]:
        """Sign a whole batch and snapshot the advanced state atomically.

        ``context`` is keyword-only and optional: ``None`` and an empty value
        both mean no context and give byte-identical unbound output; any other
        ``bytes``/``bytearray``/``str`` (``str`` encoded as UTF-8) is bound
        into every message digest, and the same context must be passed
        unchanged (with the same message order) to the matching verification
        entry.

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
        context_bytes = _validate_context(context)
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
                self._signature_at(base + offset, message, context_bytes)
                for offset, message in enumerate(messages)
            )
            self._next_index = base + len(signatures)
            return signatures, self._checkpoint_bytes()

    def sign_multiproof_with_checkpoint(
        self, messages: Any, *, context: Any = None
    ) -> tuple[bytes, bytes]:
        """Sign a tuple of messages and return the multiproof plus a checkpoint.

        ``context`` is keyword-only and optional: ``None`` and an empty value
        both mean no context and give byte-identical unbound output; any other
        ``bytes``/``bytearray``/``str`` (``str`` encoded as UTF-8) is bound
        into every message digest, and the same context must be passed
        unchanged (with the same message order) to
        :func:`multiproof_verify`.

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
        context_bytes = _validate_context(context)
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
                self._signature_at(base + offset, message, context_bytes)
                for offset, message in enumerate(messages)
            )
            # Encode before advancing: a structural failure must consume no
            # leaf, and no observer must ever see the advanced state without
            # the finished proof.
            proof = multiproof_encode(self._public_key, signatures)
            self._next_index = base + len(signatures)
            return proof, self._checkpoint_bytes()

    def sign_with_auth_state(
        self, message: Any, *, key: Any, generation: Any, context: Any = None
    ) -> tuple[MerkleSignature, bytes]:
        """Sign ``message`` and return the advanced state as a v2 auth envelope.

        ``context`` is keyword-only and optional: ``None`` and an empty value
        both mean no context and give byte-identical unbound output; any other
        ``bytes``/``bytearray``/``str`` (``str`` encoded as UTF-8) is bound
        into the message digest, and the same context must be passed unchanged
        to the matching verification entry.

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
        context_bytes = _validate_context(context)
        key_bytes = _validate_key(key)
        generation_value = _validate_generation(generation, "generation")
        with self._lock:
            if self._next_index >= len(self._private_keys):
                raise KeyExhaustedError("all Merkle leaves have been used")
            index = self._next_index
            signature = self._signature_at(index, message, context_bytes)
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
        self, messages: Any, *, key: Any, generation: Any, context: Any = None
    ) -> tuple[tuple[MerkleSignature, ...], bytes]:
        """Sign a whole batch and return the advanced state as a v2 envelope.

        ``context`` is keyword-only and optional: ``None`` and an empty value
        both mean no context and give byte-identical unbound output; any other
        ``bytes``/``bytearray``/``str`` (``str`` encoded as UTF-8) is bound
        into every message digest, and the same context must be passed
        unchanged (with the same message order) to the matching verification
        entry.

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
        context_bytes = _validate_context(context)
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
                self._signature_at(base + offset, message, context_bytes)
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
        self,
        messages: Any,
        *,
        key: Any,
        generation: Any,
        context: Any = None,
    ) -> tuple[bytes, bytes]:
        """Sign a tuple of messages and return the multiproof plus a v2 envelope.

        ``context`` is keyword-only and optional: ``None`` and an empty value
        both mean no context and give byte-identical unbound output; any other
        ``bytes``/``bytearray``/``str`` (``str`` encoded as UTF-8) is bound
        into every message digest, and the same context must be passed
        unchanged (with the same message order) to
        :func:`multiproof_verify`.

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
        context_bytes = _validate_context(context)
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
                self._signature_at(base + offset, message, context_bytes)
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

    def sign_proof_with_auth_state(
        self, message: Any, *, key: Any, generation: Any, context: Any = None
    ) -> tuple[bytes, bytes]:
        """Sign ``message`` and return the self-contained proof plus an envelope.

        ``context`` is keyword-only and optional: ``None`` and an empty value
        both mean no context and give byte-identical unbound output; any other
        ``bytes``/``bytearray``/``str`` (``str`` encoded as UTF-8) is bound
        into the message digest, and the same context must be passed unchanged
        to :meth:`MerkleProof.verify`.

        Combines :meth:`sign`, :class:`MerkleProof` serialisation and
        :func:`auth_state_wrap` in one atomic call. Returns ``(proof,
        envelope)``, both ``bytes``: ``proof`` is byte-for-byte identical to
        ``MerkleProof(public_key=self.public_key, signature=signature).to_bytes()``
        for the :class:`MerkleSignature` this call produces — the same bytes
        :meth:`MerkleProof.from_bytes` parses back into a proof whose
        :meth:`MerkleProof.verify` accepts exactly the signed message — and
        ``envelope`` is the :func:`auth_state_wrap` v2 envelope over the
        post-advance v1 :meth:`checkpoint` bytes with ``scheme="merkle"`` and
        the given ``key`` and ``generation``, byte-for-byte the same as
        signing and then wrapping an explicit checkpoint. Pairing the two
        halves in one call keeps the proof and the state it advanced to
        together, so a caller can never match a proof against a checkpoint
        taken at the wrong point under concurrency.

        ``message`` accepts ``bytes``/``bytearray``/``str`` exactly like
        :meth:`sign` (a ``str`` is encoded as UTF-8); ``key`` is
        keyword-only and must be a non-empty ``bytes``/``bytearray`` shared
        secret; ``generation`` is keyword-only and must be a non-boolean
        integer in ``0 .. 2**64 - 1``. Every argument is validated before
        the remaining-leaf capacity check: a wrong message, key or
        generation type raises ``TypeError``, and an empty key or an
        out-of-range generation raises ``ValueError``.

        The signature spends the current lowest unused leaf. The proof, the
        candidate checkpoint and the envelope are all built under the same
        lock as :meth:`sign`, :meth:`sign_batch`, :meth:`advance_to`, the
        index properties and :meth:`checkpoint`, and no randomness is drawn;
        the state is committed — advancing ``next_index`` by exactly one —
        only after both outputs have been built successfully, so the whole
        call linearises as one operation and a concurrent observer never
        sees a half-consumed leaf. An exhausted signer raises
        :class:`KeyExhaustedError`; every failure happens without spending a
        leaf and returns no partial result. The envelope is plaintext and
        authenticated only; it provides neither encryption nor protection
        against replay or rollback on its own.
        """
        _as_bytes(message)
        context_bytes = _validate_context(context)
        key_bytes = _validate_key(key)
        generation_value = _validate_generation(generation, "generation")
        with self._lock:
            if self._next_index >= len(self._private_keys):
                raise KeyExhaustedError("all Merkle leaves have been used")
            index = self._next_index
            signature = self._signature_at(index, message, context_bytes)
            # Build both outputs before advancing: any failure must consume
            # no leaf, and no observer must ever see the advanced state
            # without the finished proof and envelope.
            proof = MerkleProof(
                public_key=self._public_key, signature=signature
            ).to_bytes()
            checkpoint = self._checkpoint_bytes(index + 1)
            envelope = auth_state_wrap(
                checkpoint,
                scheme="merkle",
                key=key_bytes,
                generation=generation_value,
            )
            self._next_index = index + 1
            return proof, envelope

    def sign_proof_with_checkpoint(
        self, message: Any, *, context: Any = None
    ) -> tuple[bytes, bytes]:
        """Sign ``message`` and return the self-contained proof plus a checkpoint.

        ``context`` is keyword-only and optional: ``None`` and an empty value
        both mean no context and give byte-identical unbound output; any other
        ``bytes``/``bytearray``/``str`` (``str`` encoded as UTF-8) is bound
        into the message digest, and the same context must be passed unchanged
        to :meth:`MerkleProof.verify`.

        Combines :meth:`sign`, :class:`MerkleProof` serialisation and
        :meth:`checkpoint` in one atomic call. Returns ``(proof,
        checkpoint)``, both ``bytes``, in that fixed order: ``proof`` is
        byte-for-byte identical to
        ``MerkleProof(self.public_key, signature).to_bytes()`` for the
        :class:`MerkleSignature` this call produces — the same bytes
        :meth:`MerkleProof.from_bytes` parses back into a proof whose
        :meth:`MerkleProof.verify` accepts exactly the signed message — and
        ``checkpoint`` is the ``bytes`` that :meth:`checkpoint` returns once
        the leaf has been consumed, byte-for-byte the same v1 encoding
        holding the new ``next_index`` and every private key; a signer
        restored from it keeps the same public key and resumes signing at
        the first unconsumed index. Pairing the two halves in one call keeps
        the proof and the state it advanced to together, so a caller can
        never match a proof against a checkpoint taken at the wrong point
        under concurrency.

        ``message`` accepts ``bytes``/``bytearray``/``str`` exactly like
        :meth:`sign` (a ``str`` is encoded as UTF-8); any other type raises
        ``TypeError`` without spending a leaf, and the message is validated
        before the remaining-leaf capacity check, so an illegal message
        raises ``TypeError`` even on an exhausted signer.

        The signature spends the current lowest unused leaf. The signature,
        the proof and the candidate checkpoint are all built under the same
        lock as :meth:`sign`, :meth:`sign_batch`, :meth:`advance_to`, the
        index properties and :meth:`checkpoint`, and no randomness is drawn;
        ``next_index`` is committed — advanced by exactly one — only after
        both outputs have been built successfully, so the whole call
        linearises as one operation and a concurrent observer never sees a
        half-consumed leaf or an advanced state without the finished proof
        and checkpoint. An exhausted signer raises
        :class:`KeyExhaustedError`; a proof encoding or checkpoint failure
        likewise leaves the state unchanged, and every failure happens
        without spending a leaf and returns no partial result. The returned
        checkpoint still carries every private key in the clear and offers
        no authentication, encryption or atomic persistence —
        confidentiality, durable storage and rollback protection remain the
        caller's responsibility.
        """
        _as_bytes(message)
        context_bytes = _validate_context(context)
        with self._lock:
            if self._next_index >= len(self._private_keys):
                raise KeyExhaustedError("all Merkle leaves have been used")
            index = self._next_index
            signature = self._signature_at(index, message, context_bytes)
            # Build both outputs before advancing: any failure must consume
            # no leaf, and no observer must ever see the advanced state
            # without the finished proof and checkpoint.
            proof = MerkleProof(
                public_key=self._public_key, signature=signature
            ).to_bytes()
            checkpoint = self._checkpoint_bytes(index + 1)
            self._next_index = index + 1
            return proof, checkpoint

    def sign_batch_proof_with_auth_state(
        self, messages: Any, *, key: Any, generation: Any, context: Any = None
    ) -> tuple[bytes, bytes]:
        """Sign a non-empty tuple and return a batch proof plus a v2 envelope.

        ``context`` is keyword-only and optional: ``None`` and an empty value
        both mean no context and give byte-identical unbound output; any other
        ``bytes``/``bytearray``/``str`` (``str`` encoded as UTF-8) is bound
        into every message digest, and the same context must be passed
        unchanged (with the same message order) to
        :meth:`MerkleBatchProof.verify`.

        Combines :meth:`sign_batch`, :class:`MerkleBatchProof` serialisation
        and :func:`auth_state_wrap` in one atomic call. Returns ``(proof,
        envelope)``, both ``bytes``: ``proof`` is byte-for-byte identical to
        ``MerkleBatchProof(public_key=self.public_key, signatures=signatures).to_bytes()``
        for the tuple of consecutive :class:`MerkleSignature` values produced
        for ``messages`` from the current ``next_index`` — the same bytes
        :meth:`MerkleBatchProof.from_bytes` parses back into a batch whose
        :meth:`MerkleBatchProof.verify` accepts exactly the signed messages —
        and ``envelope`` is the :func:`auth_state_wrap` v2 envelope over the
        post-advance v1 :meth:`checkpoint` bytes with ``scheme="merkle"`` and
        the given ``key`` and ``generation``, byte-for-byte the same as
        building the batch proof and then wrapping an explicit checkpoint; a
        signer restored from that checkpoint resumes at the first index after
        the batch. Pairing the two halves in one call keeps the proof and the
        state it advanced to together, so a caller can never match a proof
        against an envelope taken at the wrong point under concurrency.

        ``messages`` must be a **non-empty** ``tuple`` whose members each
        follow the usual message rules (``bytes``/``bytearray``/``str``; a
        ``str`` is encoded as UTF-8); ``key`` is keyword-only and must be a
        non-empty ``bytes``/``bytearray`` shared secret; ``generation`` is
        keyword-only and must be a non-boolean integer in
        ``0 .. 2**64 - 1``. Every member of ``messages`` plus ``key`` and
        ``generation`` are validated before the remaining-leaf capacity
        check: a non-tuple ``messages``, an illegal message member or a wrong
        key/generation type raises ``TypeError``, and an empty tuple or key
        or an out-of-range generation raises ``ValueError`` — even on an
        exhausted signer.

        The signatures spend consecutive leaves starting at the current
        ``next_index``. The signatures, batch proof, candidate checkpoint and
        envelope are all built under the same lock as :meth:`sign`,
        :meth:`sign_batch`, :meth:`advance_to`, the index properties and
        :meth:`checkpoint`, and no randomness is drawn; the leaf indices are
        committed in one step — advancing ``next_index`` by exactly the batch
        length — only after both outputs have been built successfully, so the
        whole call linearises as one operation and a concurrent observer
        never sees a half-consumed batch. A tuple larger than the number of
        remaining leaves raises :class:`KeyExhaustedError`; every failure
        happens without spending a leaf and returns no partial result. The
        envelope is plaintext and authenticated only; it provides neither
        encryption nor protection against replay or rollback on its own.
        """
        context_bytes = _validate_context(context)
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
                    "not enough Merkle leaves remain for the batch"
                )
            signatures = tuple(
                self._signature_at(base + offset, message, context_bytes)
                for offset, message in enumerate(messages)
            )
            # Build both outputs before advancing: any failure must consume
            # no leaf, and no observer must ever see the advanced state
            # without the finished proof and envelope.
            proof = MerkleBatchProof(
                public_key=self._public_key, signatures=signatures
            ).to_bytes()
            checkpoint = self._checkpoint_bytes(base + len(signatures))
            envelope = auth_state_wrap(
                checkpoint,
                scheme="merkle",
                key=key_bytes,
                generation=generation_value,
            )
            self._next_index = base + len(signatures)
            return proof, envelope

    def sign_batch_proof_with_checkpoint(
        self, messages: Any, *, context: Any = None
    ) -> tuple[bytes, bytes]:
        """Sign a non-empty tuple and return a batch proof plus a checkpoint.

        ``context`` is keyword-only and optional: ``None`` and an empty value
        both mean no context and give byte-identical unbound output; any other
        ``bytes``/``bytearray``/``str`` (``str`` encoded as UTF-8) is bound
        into every message digest, and the same context must be passed
        unchanged (with the same message order) to
        :meth:`MerkleBatchProof.verify`.

        Combines :meth:`sign_batch`, :class:`MerkleBatchProof` serialisation
        and :meth:`checkpoint` in one atomic call. Returns ``(proof,
        checkpoint)``, both ``bytes``: ``proof`` is byte-for-byte identical to
        ``MerkleBatchProof(self.public_key, signatures).to_bytes()`` for the
        tuple of consecutive :class:`MerkleSignature` values produced for
        ``messages``, in message order, from the current ``next_index`` — the
        same bytes :meth:`MerkleBatchProof.from_bytes` parses back into a
        batch whose :meth:`MerkleBatchProof.verify` accepts exactly the
        signed messages — and ``checkpoint`` is the ``bytes`` that
        :meth:`checkpoint` returns once the whole batch has been consumed,
        byte-for-byte the same v1 encoding holding the new ``next_index`` and
        every private key; a signer restored from it keeps the same public
        key and resumes signing at the first index after the batch. Pairing
        the two halves in one call keeps the proof and the state it advanced
        to together, so a caller can never match a proof against a checkpoint
        taken at the wrong point under concurrency.

        ``messages`` must be a **non-empty** ``tuple`` whose members each
        follow the usual message rules (``bytes``/``bytearray``/``str``; a
        ``str`` is encoded as UTF-8). Every member is validated before the
        remaining-leaf capacity check, so a non-tuple argument or an illegal
        member raises ``TypeError`` and an empty tuple raises ``ValueError``
        even on an exhausted signer.

        The signatures spend consecutive leaves starting at the current
        ``next_index``. The signatures, the batch proof and the candidate
        checkpoint are all built under the same lock as :meth:`sign`,
        :meth:`sign_batch`, :meth:`advance_to`, the index properties and
        :meth:`checkpoint`, and no randomness is drawn; the leaf indices are
        committed in one step — advancing ``next_index`` by exactly the batch
        length — only after both outputs have been built successfully, so the
        whole call linearises as one operation and a concurrent observer
        never sees a half-consumed batch or an advanced state without the
        finished proof. A tuple larger than the number of remaining leaves
        raises :class:`KeyExhaustedError`; a proof encoding or checkpoint
        failure likewise leaves the state unchanged, and every failure
        happens without spending a leaf and returns no partial result. The
        returned checkpoint still carries every private key in the clear and
        offers no authentication, encryption or atomic persistence —
        confidentiality, durable storage and rollback protection remain the
        caller's responsibility.
        """
        context_bytes = _validate_context(context)
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
                    "not enough Merkle leaves remain for the batch"
                )
            signatures = tuple(
                self._signature_at(base + offset, message, context_bytes)
                for offset, message in enumerate(messages)
            )
            # Build both outputs before advancing: any failure must consume
            # no leaf, and no observer must ever see the advanced state
            # without the finished proof and checkpoint.
            proof = MerkleBatchProof(
                public_key=self._public_key, signatures=signatures
            ).to_bytes()
            checkpoint = self._checkpoint_bytes(base + len(signatures))
            self._next_index = base + len(signatures)
            return proof, checkpoint


def merkle_verify(
    message: Any, signature: Any, public_key: MerklePublicKey, *, context: Any = None
) -> bool:
    """Recover the W-OTS public key from ``signature`` and climb to the root.

    The leaf hash is rebuilt from the recovered key, the authentication path
    is folded in according to the bits of ``signature.index`` (leaf level
    first), and the result is compared against ``public_key.root``. A wrong
    public key *type* raises ``TypeError``; every other structural, range or
    content mismatch returns ``False`` — including keys or signatures whose
    fields were corrupted by bypassing the frozen-dataclass constructors.

    ``context`` is keyword-only and optional: ``None`` (the default) and an
    empty ``bytes``/``bytearray``/``str`` both mean "no context" and verify
    the legacy unbound signatures, while any other context must be exactly
    the one used at signing (a ``str`` is encoded as UTF-8); a signature made
    under one context returns ``False`` under another. A context of any other
    type raises ``TypeError``.
    """
    context_bytes = _validate_context(context)
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
        digits = _merkle_signing_digits(message, w, context_bytes)
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


def _multiproof_parse(
    data: Any,
) -> tuple[MerklePublicKey, tuple[tuple[int, tuple[bytes, ...]], ...], dict[tuple[int, int], bytes]] | None:
    """Parse a v1 multiproof into its key, leaf blocks and proof nodes.

    Runs the exact structural rule of :func:`multiproof_verify` — magic,
    version, field widths, key encoding, strictly increasing in-range leaf
    indices, per-leaf element counts, canonical node coordinates and order,
    no truncation and no trailing data, and a node set equal to the canonical
    sibling set of the leaf indices. On success returns ``(public_key,
    leaves, proof_nodes)`` where ``leaves`` is a tuple of ``(index,
    wots_signature)`` pairs in proof order and ``proof_nodes`` maps
    ``(level, index)`` coordinates to their 32-byte hashes; on any structural
    failure returns ``None``. No message is bound and no hash is checked
    here — that is :func:`_multiproof_fold`'s part.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
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
    w = public_key.w
    height = public_key.height
    b, l1, l2 = _params(w)
    chains = l1 + l2

    leaves: list[tuple[int, tuple[bytes, ...]]] = []
    offset = key_end
    previous_index = -1
    for _ in range(leaf_count):
        if offset + 4 > len(data):
            return None
        index = int.from_bytes(data[offset : offset + 2], "big")
        element_count = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += 4
        if index >= (1 << height) or index <= previous_index:
            return None
        previous_index = index
        if element_count != chains:
            return None
        end = offset + element_count * ELEMENT_BYTES
        if end > len(data):
            return None
        wots_signature = tuple(
            data[offset + i * ELEMENT_BYTES : offset + (i + 1) * ELEMENT_BYTES]
            for i in range(element_count)
        )
        offset = end
        leaves.append((index, wots_signature))

    proof_nodes: dict[tuple[int, int], bytes] = {}
    previous_coordinate: tuple[int, int] | None = None
    for _ in range(node_count):
        end = offset + _MULTIPROOF_NODE_BYTES
        if end > len(data):
            return None
        level = data[offset]
        index = int.from_bytes(data[offset + 1 : offset + 3], "big")
        node = data[offset + 3 : end]
        offset = end
        if level >= height:
            return None
        coordinate = (level, index)
        if previous_coordinate is not None and coordinate <= previous_coordinate:
            return None
        previous_coordinate = coordinate
        proof_nodes[coordinate] = node
    if offset < len(data):
        return None
    indices = tuple(index for index, _ in leaves)
    if set(proof_nodes) != set(_canonical_multiproof_nodes(indices, height)):
        return None
    return public_key, tuple(leaves), proof_nodes


def _multiproof_fold(
    leaf_hashes: dict[int, bytes],
    proof_nodes: dict[tuple[int, int], bytes],
    height: int,
    root: bytes,
) -> bool:
    """Fold recovered leaf hashes and proof nodes up to the root.

    Merges level by level with the existing internal-node rule, consuming
    each proof node exactly once, and returns ``True`` only when the merge
    reaches ``root`` and every carried node was used.
    """
    current = dict(leaf_hashes)
    proof_nodes = dict(proof_nodes)
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


def _multiproof_verify(
    messages: Any, data: Any, *, context: bytes = b""
) -> tuple[MerklePublicKey, tuple[int, ...]] | None:
    """Verify a v1 multiproof, returning the proven key and leaf indices.

    Runs the exact parse-and-verify rule of :func:`multiproof_verify`; on
    success the embedded public key and the leaf indices (in proof order,
    strictly increasing) are returned, on any failure ``None``.
    ``context`` must already be normalised by :func:`_validate_context` and
    is bound into every per-leaf message digest exactly like
    :func:`merkle_verify`.
    """
    if not isinstance(messages, tuple):
        return None
    parsed = _multiproof_parse(data)
    if parsed is None:
        return None
    public_key, leaves, proof_nodes = parsed
    if len(messages) != len(leaves):
        return None
    w = public_key.w
    height = public_key.height
    root = public_key.root
    b, l1, l2 = _params(w)
    leaf_hashes: dict[int, bytes] = {}
    for position, (index, wots_signature) in enumerate(leaves):
        try:
            digits = _merkle_signing_digits(messages[position], w, context)
        except TypeError:
            return None
        recovered = tuple(
            _chain_walk(element, b - 1 - digit)
            for element, digit in zip(wots_signature, digits)
        )
        leaf_hashes[index] = _leaf_hash(w, recovered)
    if not _multiproof_fold(leaf_hashes, proof_nodes, height, root):
        return None
    return public_key, tuple(index for index, _ in leaves)


def multiproof_verify(
    messages: Any, data: Any, *, context: Any = None
) -> bool:
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

    ``context`` is keyword-only and optional: ``None`` (the default) and an
    empty ``bytes``/``bytearray``/``str`` both mean "no context" and verify
    legacy unbound multiproofs; any other ``bytes``/``bytearray``/``str``
    (``str`` encoded as UTF-8) must be exactly the signing context and is
    bound into every message digest in the given tuple order — a proof made
    under one context returns ``False`` under another. A context of any other
    type raises ``TypeError``.
    """
    context_bytes = _validate_context(context)
    return _multiproof_verify(messages, data, context=context_bytes) is not None


def multiproof_verify_bound(
    messages: Any,
    data: Any,
    *,
    public_key: Any,
    indices: Any = None,
    context: Any = None,
) -> bool:
    """Verify a multiproof and bind it to an expected key and leaf selection.

    Runs the exact verification of :func:`multiproof_verify` on ``messages``
    and ``data`` — the same v1 magic, field order, big-endian widths,
    canonical node order, W-OTS recovery, leaf and internal-node hashing and
    use-each-node-once rule — and additionally requires the public key
    embedded in the proof to equal ``public_key`` value by value (``w``,
    ``height`` and ``root``). No new wire format is introduced, no randomness
    is drawn and no state is kept.

    ``context`` is keyword-only and optional and follows the same rules as
    :func:`multiproof_verify`: ``None``/empty means no context, while a
    non-empty context must match the signing context for every message; the
    wrong context returns ``False`` and a context of a wrong type raises
    ``TypeError``.

    ``public_key`` must be a :class:`MerklePublicKey`; any other type raises
    ``TypeError``. ``indices=None`` imposes no extra constraint on the leaf
    selection. An explicit ``indices`` must be a tuple — any other container
    type raises ``TypeError``, as does any member that is not an integer —
    with exactly as many members as ``messages``; every member must be a
    non-boolean integer, the values must be strictly increasing, in range for
    the proof's tree and identical to the proof's leaf indices item by item.
    A boolean member, a duplicate, an out-of-order or out-of-range value, a
    wrong count, a wrong ``data`` or ``messages`` type, and any structural,
    message, root or public-key-value mismatch all return ``False``.
    """
    if not isinstance(public_key, MerklePublicKey):
        raise TypeError("public_key must be a MerklePublicKey")
    context_bytes = _validate_context(context)
    if indices is not None:
        if not isinstance(indices, tuple):
            raise TypeError("indices must be a tuple of integers")
        for index in indices:
            if not isinstance(index, int):
                raise TypeError("every index must be an integer")
    result = _multiproof_verify(messages, data, context=context_bytes)
    if result is None:
        return False
    proof_key, proof_indices = result
    try:
        if (
            public_key.w != proof_key.w
            or public_key.height != proof_key.height
            or public_key.root != proof_key.root
        ):
            return False
    except AttributeError:
        return False
    if indices is None:
        return True
    if len(indices) != len(messages):
        return False
    if any(isinstance(index, bool) for index in indices):
        return False
    if any(former >= latter for former, latter in zip(indices, indices[1:])):
        return False
    if any(index < 0 or index >= (1 << proof_key.height) for index in indices):
        return False
    return indices == proof_indices


def multiproof_select(
    messages: Any,
    data: Any,
    *,
    public_key: Any,
    indices: Any,
    context: Any = None,
) -> bytes:
    """Extract an independent multiproof for a chosen leaf subset.

    Given only a source :func:`multiproof_encode` proof (``data``), every
    message it proves (``messages``, in the source proof's leaf order) and
    the expected ``public_key``, re-emit the leaves named by ``indices`` as
    a fresh v1 multiproof — without access to the original signatures or
    any private key. ``indices`` names actual tree leaf indices, not
    positions in ``messages``. The caller verifies the result with the
    selected leaves' messages, the same public key and the same context via
    :func:`multiproof_verify` / :func:`multiproof_verify_bound`.

    The whole source proof is authenticated before anything is returned:
    the proof must parse under the exact structural rule of
    :func:`multiproof_verify`, every leaf — including the ones being
    dropped — must verify against its message under ``context``, and the
    embedded public key must equal ``public_key`` value by value (``w``,
    ``height`` and ``root``). A corrupted dropped leaf's message or
    signature therefore fails the call instead of being silently discarded.

    ``data`` must be ``bytes`` or ``bytearray`` and ``messages`` a tuple
    whose members each follow the usual message rules
    (``bytes``/``bytearray``/``str``); ``public_key`` must be a
    :class:`MerklePublicKey`; ``indices`` must be a tuple of integers.
    ``context`` is keyword-only and optional and follows the usual context
    rules (``None``/empty means no context, ``str`` encoded as UTF-8); it
    must be the context the source proof was made under. Any of these type
    violations raises ``TypeError``. A boolean index, an empty selection,
    duplicate or out-of-order indices, an index not present in the source
    proof, a message count that differs from the proof's leaf count, a
    structurally malformed source proof, a verification failure, and a
    public-key or context mismatch all raise ``ValueError`` and no partial
    result is returned.

    The result uses the existing v1 format unchanged: it keeps the original
    public key, leaf indices and W-OTS elements, and its authentication
    nodes follow the existing canonical ordering and deduplication rule, so
    the bytes are identical to feeding the selected original signatures to
    :func:`multiproof_encode`. Selecting every leaf reproduces the source
    bytes exactly; selecting from a proof that itself covers every leaf, or
    selecting twice in a row, behaves like selecting the final leaf set
    directly. Duplicate messages are treated as distinct leaf positions and
    are never merged. No randomness is drawn and no input or signer state
    is modified.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("multiproof data must be bytes or bytearray")
    if not isinstance(messages, tuple):
        raise TypeError("messages must be a tuple of messages")
    for message in messages:
        _as_bytes(message)
    if not isinstance(public_key, MerklePublicKey):
        raise TypeError("public_key must be a MerklePublicKey")
    if not isinstance(indices, tuple):
        raise TypeError("indices must be a tuple of integers")
    for index in indices:
        if not isinstance(index, int):
            raise TypeError("every index must be an integer")
    context_bytes = _validate_context(context)
    if not indices:
        raise ValueError("indices must not be empty")
    if any(isinstance(index, bool) for index in indices):
        raise ValueError("every index must be a non-boolean integer")
    if any(former >= latter for former, latter in zip(indices, indices[1:])):
        raise ValueError("indices must be strictly increasing and unique")
    parsed = _multiproof_parse(data)
    if parsed is None:
        raise ValueError("the source multiproof is malformed")
    proof_key, leaves, proof_nodes = parsed
    if len(messages) != len(leaves):
        raise ValueError("messages and proof leaves must have the same length")
    if (
        public_key.w != proof_key.w
        or public_key.height != proof_key.height
        or public_key.root != proof_key.root
    ):
        raise ValueError("public_key does not match the proof's embedded public key")
    w = proof_key.w
    height = proof_key.height
    b, l1, l2 = _params(w)
    leaf_hashes: dict[int, bytes] = {}
    for position, (index, wots_signature) in enumerate(leaves):
        digits = _merkle_signing_digits(messages[position], w, context_bytes)
        recovered = tuple(
            _chain_walk(element, b - 1 - digit)
            for element, digit in zip(wots_signature, digits)
        )
        leaf_hashes[index] = _leaf_hash(w, recovered)
    if not _multiproof_fold(leaf_hashes, proof_nodes, height, proof_key.root):
        raise ValueError("the source multiproof does not verify")
    leaf_indices = {index for index, _ in leaves}
    if any(index not in leaf_indices for index in indices):
        raise ValueError("every selected index must be present in the source proof")

    # Recover every tree node the proof determines: the verified leaf
    # hashes, the carried proof nodes, and every internal node whose two
    # children are both known. A selected leaf's ancestor at each level is
    # computed by exactly the fold above, and its sibling is either another
    # known node or a carried proof node, so the lookup below always hits.
    known: dict[tuple[int, int], bytes] = dict(proof_nodes)
    for index, leaf_hash in leaf_hashes.items():
        known[(0, index)] = leaf_hash
    for level in range(height):
        for (node_level, index), node in list(known.items()):
            if node_level != level:
                continue
            sibling = known.get((level, index ^ 1))
            if sibling is None:
                continue
            if index & 1:
                known[(level + 1, index >> 1)] = _node_hash(sibling, node)
            else:
                known[(level + 1, index >> 1)] = _node_hash(node, sibling)

    elements_by_index = {index: elements for index, elements in leaves}
    selected = tuple(
        MerkleSignature(
            index=index,
            wots_signature=elements_by_index[index],
            auth_path=tuple(
                known[(level, (index >> level) ^ 1)] for level in range(height)
            ),
        )
        for index in indices
    )
    return multiproof_encode(public_key, selected)


def multiproof_merge(
    message_groups: Any,
    proofs: Any,
    *,
    public_key: Any,
    context: Any = None,
) -> bytes:
    """Merge the leaf sets of several verified multiproofs into one proof.

    Given only source :func:`multiproof_encode` proofs (``proofs``) and, for
    each proof, every message it proves in that proof's leaf order
    (``message_groups``), re-emit the union of their leaves as a fresh v1
    multiproof — without access to the original single signatures or any
    private key. The two positional arguments are non-empty tuples of equal
    length and correspond item by item; each member of ``message_groups`` is
    itself a tuple of ``bytes``/``bytearray``/``str`` messages (``str``
    encoded as UTF-8), ordered exactly as the matching source proof's leaves.
    The caller verifies the result with the union leaf order's messages, the
    same public key and the same context via :func:`multiproof_verify` /
    :func:`multiproof_verify_bound`, and can select subsets of it or feed it
    into another merge.

    Every source proof is fully authenticated before anything is returned,
    including duplicate submissions of the same source: each proof must parse
    under the exact structural rule of :func:`multiproof_verify`, every leaf
    it carries must verify against its group's message under ``context``, and
    the embedded public key must equal ``public_key`` value by value (``w``,
    ``height`` and ``root``); a leaf shared with an earlier proof is never
    skipped. The result keeps the original public key and W-OTS elements,
    orders its leaves by their actual tree indices, and deduplicates shared
    authentication nodes under the existing canonical rule. When the same
    leaf occurs in more than one source proof, one copy is kept only when the
    UTF-8 message bytes and every W-OTS element are equal across the
    occurrences; otherwise ``ValueError`` is raised. Equal messages at
    different leaves stay distinct. The bytes are identical to sorting the
    union's original single signatures by index and feeding them to
    :func:`multiproof_encode`; a single legal source is returned byte for
    byte, and reordering sources, resubmitting a source or splitting the
    merge into batches does not change the result.

    ``public_key`` must be a :class:`MerklePublicKey`; ``context`` is
    keyword-only and optional and follows the usual context rules
    (``None``/empty means no context, ``str`` encoded as UTF-8). Any type
    violation — a non-tuple container, a non-tuple message group, a proof
    member that is not ``bytes``/``bytearray``, a message of another type, a
    wrong ``public_key`` or ``context`` type — raises ``TypeError``, and type
    checks precede all content checks. Empty input, unequal group counts, a
    group whose message count differs from its proof's leaf count, a
    malformed or non-canonical source encoding, a verification failure, a
    public-key or context mismatch, an overlapping-leaf conflict, a
    conflicting authentication node at the same coordinate, or a union that
    exceeds the existing v1 format limits all raise ``ValueError`` and no
    partial result is returned. No randomness is drawn, no input or signer
    state is modified, and no wire-format version is added.
    """
    if not isinstance(message_groups, tuple):
        raise TypeError("message_groups must be a tuple of message tuples")
    if not isinstance(proofs, tuple):
        raise TypeError("proofs must be a tuple of multiproof bytes")
    for messages in message_groups:
        if not isinstance(messages, tuple):
            raise TypeError("every message group must be a tuple of messages")
        for message in messages:
            _as_bytes(message)
    for data in proofs:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("every proof must be bytes or bytearray")
    if not isinstance(public_key, MerklePublicKey):
        raise TypeError("public_key must be a MerklePublicKey")
    context_bytes = _validate_context(context)
    if not message_groups or not proofs:
        raise ValueError("message_groups and proofs must not be empty")
    if len(message_groups) != len(proofs):
        raise ValueError("message_groups and proofs must have the same length")

    # index -> (message bytes, W-OTS elements, verified leaf hash);
    # coordinates -> carried canonical nodes from the source proofs
    leaves: dict[int, tuple[bytes, tuple[bytes, ...], bytes]] = {}
    nodes: dict[tuple[int, int], bytes] = {}
    for position, data in enumerate(proofs):
        messages = message_groups[position]
        parsed = _multiproof_parse(data)
        if parsed is None:
            raise ValueError("a source multiproof is malformed")
        proof_key, proof_leaves, proof_nodes = parsed
        if len(messages) != len(proof_leaves):
            raise ValueError(
                "every message group must match its proof's leaf count"
            )
        if (
            public_key.w != proof_key.w
            or public_key.height != proof_key.height
            or public_key.root != proof_key.root
        ):
            raise ValueError(
                "public_key does not match a proof's embedded public key"
            )
        w = proof_key.w
        height = proof_key.height
        b, l1, l2 = _params(w)
        leaf_hashes: dict[int, bytes] = {}
        for leaf_position, (index, elements) in enumerate(proof_leaves):
            message_bytes = _as_bytes(messages[leaf_position])
            digits = _merkle_signing_digits(message_bytes, w, context_bytes)
            recovered = tuple(
                _chain_walk(element, b - 1 - digit)
                for element, digit in zip(elements, digits)
            )
            leaf_hash = _leaf_hash(w, recovered)
            leaf_hashes[index] = leaf_hash
            previous = leaves.get(index)
            if previous is not None:
                previous_message, previous_elements, _ = previous
                if previous_message != message_bytes:
                    raise ValueError("conflicting messages at an overlapping leaf")
                if previous_elements != elements:
                    raise ValueError(
                        "conflicting W-OTS signatures at an overlapping leaf"
                    )
            else:
                leaves[index] = (message_bytes, elements, leaf_hash)
        if not _multiproof_fold(leaf_hashes, proof_nodes, height, proof_key.root):
            raise ValueError("a source multiproof does not verify")
        for coordinate, node in proof_nodes.items():
            previous = nodes.get(coordinate)
            if previous is not None and previous != node:
                raise ValueError(
                    "conflicting authentication nodes at the same coordinate"
                )
            nodes[coordinate] = node

    # Recover every tree node the union determines: the verified leaf hashes,
    # the carried proof nodes, and every internal node whose two children are
    # both known, using the same level-by-level derivation as
    # multiproof_select. A carried node at a coordinate another source proves
    # or derives a different value for is a same-coordinate conflict. Each
    # source folded to the root, so every sibling of a union leaf is
    # determinable and the auth-path lookups below always hit consistently.
    height = public_key.height
    known: dict[tuple[int, int], bytes] = {}
    for index, (_, _, leaf_hash) in leaves.items():
        coordinate = (0, index)
        carried = nodes.get(coordinate)
        if carried is not None and carried != leaf_hash:
            raise ValueError(
                "conflicting authentication nodes at the same coordinate"
            )
        known[coordinate] = leaf_hash
    for coordinate, node in nodes.items():
        # A carried level-0 node whose coordinate is a union leaf was already
        # checked against that leaf's hash above; every other carried node is
        # an unknown sibling the merged auth paths must take as given.
        if coordinate not in known:
            known[coordinate] = node
    for level in range(height):
        for (node_level, index), node in list(known.items()):
            if node_level != level:
                continue
            sibling = known.get((level, index ^ 1))
            if sibling is None:
                continue
            if index & 1:
                parent = _node_hash(sibling, node)
            else:
                parent = _node_hash(node, sibling)
            coordinate = (level + 1, index >> 1)
            previous = known.get(coordinate)
            if previous is not None and previous != parent:
                raise ValueError(
                    "conflicting authentication nodes at the same coordinate"
                )
            known[coordinate] = parent

    indices = sorted(leaves)
    merged = tuple(
        MerkleSignature(
            index=index,
            wots_signature=leaves[index][1],
            auth_path=tuple(
                known[(level, (index >> level) ^ 1)] for level in range(height)
            ),
        )
        for index in indices
    )
    return multiproof_encode(public_key, merged)


def multiproof_expand(
    messages: Any,
    data: Any,
    *,
    public_key: Any,
    context: Any = None,
) -> MerkleBatchProof:
    """Restore a verified multiproof to an ordinary :class:`MerkleBatchProof`.

    Given only a source :func:`multiproof_encode` proof (``data``), every
    message it proves (``messages``, in the source proof's leaf order) and
    the expected ``public_key``, rebuild the pre-compression standalone
    :class:`MerkleSignature` values — one per leaf, each with its complete
    authentication path — and return them as a :class:`MerkleBatchProof`,
    without access to the original signatures, any private key or the
    signer. The result keeps the source public key, the strictly increasing
    actual leaf indices and each leaf's original W-OTS elements, so every
    rebuilt signature is value-for-value equal to the signature that was
    compressed and the batch serialisation is byte-for-byte the same as
    directly wrapping those original signatures. Feeding the result's
    public key and signatures back to :func:`multiproof_encode` reproduces
    the source bytes exactly. Each rebuilt signature can also be verified
    on its own with :func:`merkle_verify` or wrapped in a
    :class:`MerkleProof`, and the whole batch passes
    :meth:`MerkleBatchProof.verify`.

    The whole source proof is authenticated before anything is returned:
    it must parse under the exact structural rule of
    :func:`multiproof_verify` (magic, version, lengths, counts, indices
    and canonical authentication nodes, no truncation or trailing data),
    every leaf must verify against its message under ``context`` with the
    root recomputed through the existing fold rule, and the embedded
    public key must equal ``public_key`` value by value (``w``, ``height``
    and ``root``). A failure on any leaf — including an authentication
    node that only the root check can expose — raises ``ValueError`` and
    no partial result is returned.

    ``data`` must be ``bytes`` or ``bytearray``; ``messages`` must be a
    tuple whose members each follow the usual message rules
    (``bytes``/``bytearray``/``str``); ``public_key`` must be a
    :class:`MerklePublicKey`; ``context`` is keyword-only and must be
    ``None`` or one of the usual message types (``None``/empty means no
    context, a ``str`` is encoded as UTF-8), exactly like
    :func:`multiproof_verify`. Any of these type violations raises
    ``TypeError`` and type checks precede all content checks. An empty
    message tuple, a message count that differs from the proof's leaf
    count, a wrong or unbound message or context, a public-key mismatch,
    a malformed or non-canonical source encoding, or a proof that does not
    reach the expected root all raise ``ValueError``. The returned object
    never references the caller's mutable byte buffers, no input is
    modified, no randomness is drawn, no signing state is touched and no
    wire format or version is added.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("multiproof data must be bytes or bytearray")
    if not isinstance(messages, tuple):
        raise TypeError("messages must be a tuple of messages")
    for message in messages:
        _as_bytes(message)
    if not isinstance(public_key, MerklePublicKey):
        raise TypeError("public_key must be a MerklePublicKey")
    context_bytes = _validate_context(context)
    if not messages:
        raise ValueError("messages must not be empty")
    parsed = _multiproof_parse(data)
    if parsed is None:
        raise ValueError("the source multiproof is malformed")
    proof_key, leaves, proof_nodes = parsed
    if len(messages) != len(leaves):
        raise ValueError("messages and proof leaves must have the same length")
    if (
        public_key.w != proof_key.w
        or public_key.height != proof_key.height
        or public_key.root != proof_key.root
    ):
        raise ValueError("public_key does not match the proof's embedded public key")
    w = proof_key.w
    height = proof_key.height
    b, l1, l2 = _params(w)
    leaf_hashes: dict[int, bytes] = {}
    for position, (index, wots_signature) in enumerate(leaves):
        digits = _merkle_signing_digits(messages[position], w, context_bytes)
        recovered = tuple(
            _chain_walk(element, b - 1 - digit)
            for element, digit in zip(wots_signature, digits)
        )
        leaf_hashes[index] = _leaf_hash(w, recovered)
    if not _multiproof_fold(leaf_hashes, proof_nodes, height, proof_key.root):
        raise ValueError("the source multiproof does not verify")

    # Recover every tree node the proof determines: the verified leaf
    # hashes, the carried proof nodes, and every internal node whose two
    # children are both known. Each leaf folded to the root above, so the
    # sibling of every leaf at each level is either another known node or
    # a carried proof node, and the auth-path lookups below always hit.
    known: dict[tuple[int, int], bytes] = dict(proof_nodes)
    for index, leaf_hash in leaf_hashes.items():
        known[(0, index)] = leaf_hash
    for level in range(height):
        for (node_level, index), node in list(known.items()):
            if node_level != level:
                continue
            sibling = known.get((level, index ^ 1))
            if sibling is None:
                continue
            if index & 1:
                known[(level + 1, index >> 1)] = _node_hash(sibling, node)
            else:
                known[(level + 1, index >> 1)] = _node_hash(node, sibling)

    signatures = tuple(
        MerkleSignature(
            index=index,
            wots_signature=elements,
            auth_path=tuple(
                known[(level, (index >> level) ^ 1)] for level in range(height)
            ),
        )
        for index, elements in leaves
    )
    return MerkleBatchProof(public_key=proof_key, signatures=signatures)


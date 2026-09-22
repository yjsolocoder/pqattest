"""Static parameter analysis for pqattest schemes.

:func:`profile` reports the size and cost metrics of a scheme/parameter
combination without generating any keys, and :func:`recommend` picks a Merkle
configuration for a desired signature capacity, :func:`recommend_merkle_deployment`
picks one that additionally fits deployment budgets. :func:`merkle_storage_profile`
breaks the Merkle wire sizes down per serialised object and
:func:`merkle_transport_profile` sizes a batch or multi-proof over a chosen
leaf-index set. :func:`recommend_merkle_transport_deployment` chooses both the
tree parameters and the transport encoding together under checkpoint, batch,
multi-proof and verifier-step budgets, and
:func:`merkle_transport_deployment_frontier` returns every feasible,
non-dominated choice of the same joint deployment as a tuple instead of
ranking one. :func:`recommend_merkle_transport_workload`
extends that joint choice to several independent leaf-index groups, each carried
in its own transport, under checkpoint, per-group, aggregate and verifier-step
budgets. :func:`merkle_transport_workload_frontier` returns every feasible,
non-dominated choice of the same workload as a tuple instead of ranking one.
:func:`merkle_mode_frontier` goes further and enumerates every per-group
``batch``/``multiproof`` mode combination of the workload under checkpoint,
per-group, aggregate, verifier-step and carried-node budgets, returning the
feasible, non-dominated mode choices as a tuple.
:func:`recommend_merkle_mode_deployment` ranks that mode frontier by a
business preference — ``"compact"``, ``"nodes"`` or ``"speed"`` — and
returns one profile.
:func:`merkle_deployment_frontier` likewise returns the whole Pareto frontier
of ordinary Merkle deployments under checkpoint, signature, proof and
verifier-step budgets. :func:`merkle_verify_profile` compares the
verifier-side SHA-256 hash cost of a batch proof against a multi-proof over
the same leaf set, returning a :class:`MerkleVerifyProfile`.
:func:`merkle_verify_workload_profile` extends that comparison to several
independent leaf-index groups, each carried in its own ``"batch"`` or
``"multiproof"`` transport, and totals the per-group SHA-256 work in a
:class:`MerkleVerifyWorkloadProfile`. :func:`merkle_verify_mode_frontier`
joins the two: it enumerates every per-group mode combination of every
candidate config under checkpoint, per-group peak, aggregate transport,
verifier-step, carried-node and verifier-hash budgets, returning the
feasible, non-dominated choices as frozen :class:`MerkleModeCost` tuples.
All fifteen
are pure functions: no randomness, no
state, no I/O, no keys are generated.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Any

from .merkle import _canonical_multiproof_nodes, _validate_height
from .wots import ELEMENT_BYTES, _params, _validate_w

__all__ = [
    "Params",
    "MerkleStorageProfile",
    "MerkleTransportDeploymentProfile",
    "MerkleTransportWorkloadProfile",
    "MerkleModeCost",
    "MerkleVerifyProfile",
    "MerkleVerifyWorkloadProfile",
    "profile",
    "recommend",
    "recommend_merkle_deployment",
    "merkle_deployment_frontier",
    "recommend_merkle_transport_deployment",
    "merkle_transport_deployment_frontier",
    "recommend_merkle_transport_workload",
    "merkle_transport_workload_frontier",
    "merkle_mode_frontier",
    "merkle_verify_mode_frontier",
    "recommend_merkle_mode_deployment",
    "merkle_storage_profile",
    "merkle_transport_profile",
    "merkle_verify_profile",
    "merkle_verify_workload_profile",
]

_SCHEMES = ("lamport", "wots", "merkle")
_MAX_CAPACITY = 256


@dataclass(frozen=True)
class Params:
    """Frozen metrics for one scheme/parameter combination.

    ``capacity`` is the number of messages one key pair can sign; ``elements``
    the number of 32-byte chain elements per (one-time) signature;
    ``sig_bytes`` and ``path_bytes`` the serialised signature and
    authentication-path sizes in bytes, excluding any leaf index and Python
    object overhead; ``steps`` the upper bound on hash-chain steps a verifier
    performs per (one-time) signature. ``w``/``height`` are ``None`` when the
    scheme does not use them.
    """

    scheme: str
    w: int | None
    height: int | None
    capacity: int
    elements: int
    sig_bytes: int
    path_bytes: int
    steps: int


def _wots_metrics(w: int) -> tuple[int, int]:
    """Return ``(n, steps)``: chain count and chain-step upper bound."""
    b, l1, l2 = _params(w)
    n = l1 + l2
    return n, n * (b - 1)


def profile(scheme: str, w: Any = None, height: Any = None) -> Params:
    """Return the :class:`Params` metrics for a scheme configuration.

    ``lamport`` takes neither ``w`` nor ``height``; ``wots`` takes ``w`` (4 or
    8) only; ``merkle`` takes both (``height`` an integer from 1 to 8). An
    unknown scheme, a missing parameter or an unexpected one raises
    ``ValueError``.
    """
    if scheme == "lamport":
        if w is not None or height is not None:
            raise ValueError("lamport takes neither w nor height")
        return Params(
            scheme="lamport",
            w=None,
            height=None,
            capacity=1,
            elements=0,
            sig_bytes=256 * 32,
            path_bytes=0,
            steps=0,
        )
    if scheme == "wots":
        if w is None:
            raise ValueError("wots requires w")
        if height is not None:
            raise ValueError("wots takes no height")
        w = _validate_w(w)
        n, steps = _wots_metrics(w)
        return Params(
            scheme="wots",
            w=w,
            height=None,
            capacity=1,
            elements=n,
            sig_bytes=n * ELEMENT_BYTES,
            path_bytes=0,
            steps=steps,
        )
    if scheme == "merkle":
        if w is None or height is None:
            raise ValueError("merkle requires both w and height")
        w = _validate_w(w)
        height = _validate_height(height)
        n, steps = _wots_metrics(w)
        return Params(
            scheme="merkle",
            w=w,
            height=height,
            capacity=1 << height,
            elements=n,
            sig_bytes=(n + height) * ELEMENT_BYTES,
            path_bytes=height * ELEMENT_BYTES,
            steps=steps,
        )
    raise ValueError(f"unknown scheme: {scheme!r}")


def recommend(capacity: Any, prefer: str = "size") -> Params:
    """Return the Merkle :class:`Params` covering ``capacity`` signatures.

    ``capacity`` must be an integer from 1 to 256 (non-bool); the height is
    the smallest one with ``2 ** height >= capacity`` and at least 1.
    ``prefer="size"`` picks ``w=8`` (shorter signatures), ``prefer="speed"``
    picks ``w=4`` (fewer chain steps). Anything else raises ``ValueError``.
    """
    if (
        isinstance(capacity, bool)
        or not isinstance(capacity, int)
        or not 1 <= capacity <= _MAX_CAPACITY
    ):
        raise ValueError(f"capacity must be an integer between 1 and {_MAX_CAPACITY}")
    if prefer == "size":
        w = 8
    elif prefer == "speed":
        w = 4
    else:
        raise ValueError('prefer must be "size" or "speed"')
    height = max(1, (capacity - 1).bit_length())
    return profile("merkle", w=w, height=height)


def recommend_merkle_deployment(
    capacity: Any, budgets: Any, prefer: Any = "size"
) -> MerkleStorageProfile:
    """Return the :class:`MerkleStorageProfile` fitting deployment budgets.

    Unlike :func:`recommend`, which only minimises the tree height, this
    enumerates every Merkle candidate — ``w`` in ``(4, 8)`` times ``height``
    from 1 to 8 — keeps those whose ``leaf_count`` covers ``capacity`` and
    that satisfy every set budget, and ranks the feasible set.

    ``capacity`` must be a non-boolean integer from 1 to 256. ``budgets``
    must be a four-tuple, in order: an upper bound on the checkpoint bytes
    (:attr:`MerkleStorageProfile.checkpoint_bytes`), on one signature wire
    length (:attr:`MerkleStorageProfile.signature_wire_bytes`), on one
    standalone proof wire length (:attr:`MerkleStorageProfile.proof_wire_bytes`)
    and on the verifier hash-chain step count (``profile("merkle", ...)``'s
    ``steps``). Each entry is either ``None`` (no bound) or a positive,
    non-boolean integer, and at least one entry must be set.

    ``prefer="size"`` ranks candidates lexicographically by signature wire
    length, proof wire length, checkpoint bytes, steps, leaf count, ``w`` and
    ``height``; ``prefer="speed"`` minimises steps first and then applies the
    same remaining order. The first candidate after sorting is returned as a
    :class:`MerkleStorageProfile`.

    A non-tuple ``budgets`` raises ``TypeError``; a tuple of the wrong length,
    an illegal member, an out-of-range ``capacity``, an unknown ``prefer``
    value or the absence of any feasible candidate raises ``ValueError``. The
    function is pure: it draws no randomness, generates no keys and changes
    no state.
    """
    if not isinstance(budgets, tuple):
        raise TypeError("budgets must be a 4-tuple of budget limits")
    if len(budgets) != 4:
        raise ValueError("budgets must contain exactly four entries")
    if (
        isinstance(capacity, bool)
        or not isinstance(capacity, int)
        or not 1 <= capacity <= _MAX_CAPACITY
    ):
        raise ValueError(f"capacity must be an integer between 1 and {_MAX_CAPACITY}")
    if prefer not in ("size", "speed"):
        raise ValueError('prefer must be "size" or "speed"')

    labels = ("checkpoint", "signature", "proof", "steps")
    limits = []
    for label, budget in zip(labels, budgets):
        if budget is None:
            limits.append(None)
        elif isinstance(budget, bool) or not isinstance(budget, int) or budget < 1:
            raise ValueError(f"{label} budget must be None or a positive integer")
        else:
            limits.append(budget)
    if all(limit is None for limit in limits):
        raise ValueError("at least one budget must be set")
    checkpoint_limit, signature_limit, proof_limit, steps_limit = limits

    feasible = []
    for w in (4, 8):
        for height in range(1, 9):
            storage = merkle_storage_profile(w, height)
            if storage.leaf_count < capacity:
                continue
            if checkpoint_limit is not None and storage.checkpoint_bytes > checkpoint_limit:
                continue
            if signature_limit is not None and storage.signature_wire_bytes > signature_limit:
                continue
            if proof_limit is not None and storage.proof_wire_bytes > proof_limit:
                continue
            steps = profile("merkle", w=w, height=height).steps
            if steps_limit is not None and steps > steps_limit:
                continue
            feasible.append((storage, steps))
    if not feasible:
        raise ValueError("no Merkle configuration fits the requested capacity and budgets")

    def ranking(candidate: tuple[MerkleStorageProfile, int]) -> tuple[int, ...]:
        storage, steps = candidate
        ordered = (
            storage.signature_wire_bytes,
            storage.proof_wire_bytes,
            storage.checkpoint_bytes,
            steps,
            storage.leaf_count,
            storage.w,
            storage.height,
        )
        if prefer == "speed":
            return (steps,) + ordered
        return ordered

    feasible.sort(key=ranking)
    return feasible[0][0]


def _validate_deployment_budgets(budgets: Any) -> tuple[int | None, ...]:
    """Validate the four-tuple of deployment budget limits."""
    if not isinstance(budgets, tuple):
        raise TypeError("budgets must be a 4-tuple of budget limits")
    if len(budgets) != 4:
        raise ValueError("budgets must contain exactly four entries")
    labels = ("checkpoint", "signature", "proof", "steps")
    limits = []
    for label, budget in zip(labels, budgets):
        if budget is None:
            limits.append(None)
        elif isinstance(budget, bool) or not isinstance(budget, int) or budget < 1:
            raise ValueError(f"{label} budget must be None or a positive integer")
        else:
            limits.append(budget)
    if all(limit is None for limit in limits):
        raise ValueError("at least one budget must be set")
    return tuple(limits)


def _validate_transport_budgets(budgets: Any) -> tuple[int | None, ...]:
    """Validate the four-tuple of checkpoint/batch/multi-proof/steps limits."""
    if not isinstance(budgets, tuple):
        raise TypeError("budgets must be a 4-tuple of budget limits")
    if len(budgets) != 4:
        raise ValueError("budgets must contain exactly four entries")
    labels = ("checkpoint", "batch", "multiproof", "steps")
    limits = []
    for label, budget in zip(labels, budgets):
        if budget is None:
            limits.append(None)
        elif isinstance(budget, bool) or not isinstance(budget, int) or budget < 1:
            raise ValueError(f"{label} budget must be None or a positive integer")
        else:
            limits.append(budget)
    if all(limit is None for limit in limits):
        raise ValueError("at least one budget must be set")
    return tuple(limits)


def merkle_deployment_frontier(
    capacity: Any, budgets: Any
) -> tuple[MerkleStorageProfile, ...]:
    """Return every feasible, non-dominated ordinary Merkle deployment as a tuple.

    Where :func:`recommend_merkle_deployment` ranks the feasible configs and
    returns one, this function keeps the whole Pareto frontier so a caller can
    inspect the trade-off between storage, signature, proof and verification
    costs: it enumerates every Merkle candidate — ``w`` in ``(4, 8)`` times
    ``height`` from 1 to 8 — whose ``leaf_count`` covers ``capacity``, keeps
    those satisfying every set budget, reusing
    :func:`merkle_storage_profile` for the wire sizes and
    :func:`profile` for the per-signature verifier hash-chain step count, and
    drops every dominated candidate.

    ``capacity`` must be a non-boolean integer from 1 to 256. ``budgets``
    must be a four-tuple, in order: an upper bound on the checkpoint bytes
    (:attr:`MerkleStorageProfile.checkpoint_bytes`), on one signature wire
    length (:attr:`MerkleStorageProfile.signature_wire_bytes`), on one
    standalone proof wire length
    (:attr:`MerkleStorageProfile.proof_wire_bytes`) and on the per-signature
    verifier hash-chain step count (``profile("merkle", ...)``'s ``steps``).
    Each entry is either ``None`` (no bound) or a positive, non-boolean
    integer, and at least one entry must be set; every bound is inclusive.

    A feasible profile *A* dominates another feasible profile *B* when
    ``A`` is no greater than ``B`` on all four metrics — checkpoint bytes,
    signature wire bytes, proof wire bytes and verifier steps — and strictly
    smaller on at least one; every dominated candidate is dropped and the
    survivors are deduplicated by value. No preference is applied, so a
    configuration trading speed for size (or the reverse) is never discarded
    ahead of the dominance test. The returned tuple is sorted stably and
    ascending by verifier steps, signature wire bytes, proof wire bytes,
    checkpoint bytes, leaf count, ``w`` and ``height``.

    A non-tuple ``budgets`` raises ``TypeError``; a wrong-length or otherwise
    illegal ``budgets`` tuple, an out-of-range ``capacity`` or the absence of
    any feasible candidate raises ``ValueError``. The function is pure: it
    draws no randomness, generates no keys and changes no state.
    """
    limits = _validate_deployment_budgets(budgets)
    if (
        isinstance(capacity, bool)
        or not isinstance(capacity, int)
        or not 1 <= capacity <= _MAX_CAPACITY
    ):
        raise ValueError(f"capacity must be an integer between 1 and {_MAX_CAPACITY}")
    checkpoint_limit, signature_limit, proof_limit, steps_limit = limits

    candidates: list[tuple[MerkleStorageProfile, int]] = []
    for w in (4, 8):
        for height in range(1, 9):
            storage = merkle_storage_profile(w, height)
            if storage.leaf_count < capacity:
                continue
            if checkpoint_limit is not None and storage.checkpoint_bytes > checkpoint_limit:
                continue
            if signature_limit is not None and storage.signature_wire_bytes > signature_limit:
                continue
            if proof_limit is not None and storage.proof_wire_bytes > proof_limit:
                continue
            steps = profile("merkle", w=w, height=height).steps
            if steps_limit is not None and steps > steps_limit:
                continue
            candidates.append((storage, steps))
    if not candidates:
        raise ValueError("no Merkle configuration fits the requested capacity and budgets")

    def dominates(
        a: tuple[MerkleStorageProfile, int],
        b: tuple[MerkleStorageProfile, int],
    ) -> bool:
        a_storage, a_steps = a
        b_storage, b_steps = b
        no_worse = (
            a_storage.checkpoint_bytes <= b_storage.checkpoint_bytes
            and a_storage.signature_wire_bytes <= b_storage.signature_wire_bytes
            and a_storage.proof_wire_bytes <= b_storage.proof_wire_bytes
            and a_steps <= b_steps
        )
        strictly_better = (
            a_storage.checkpoint_bytes < b_storage.checkpoint_bytes
            or a_storage.signature_wire_bytes < b_storage.signature_wire_bytes
            or a_storage.proof_wire_bytes < b_storage.proof_wire_bytes
            or a_steps < b_steps
        )
        return no_worse and strictly_better

    non_dominated = [
        candidate
        for candidate in candidates
        if not any(dominates(other, candidate) for other in candidates)
    ]

    unique: list[MerkleStorageProfile] = []
    seen: set[MerkleStorageProfile] = set()
    for storage, _steps in non_dominated:
        if storage not in seen:
            seen.add(storage)
            unique.append(storage)

    unique.sort(
        key=lambda storage: (
            profile("merkle", w=storage.w, height=storage.height).steps,
            storage.signature_wire_bytes,
            storage.proof_wire_bytes,
            storage.checkpoint_bytes,
            storage.leaf_count,
            storage.w,
            storage.height,
        )
    )
    return tuple(unique)


@dataclass(frozen=True)
class MerkleStorageProfile:
    """Frozen on-the-wire byte sizes for one Merkle ``(w, height)`` choice.

    Every value is a size in bytes of the matching serialised object,
    excluding Python object overhead:

    - ``w`` / ``height`` echo the validated parameters;
    - ``leaf_count`` is ``L = 2 ** height`` W-OTS leaves;
    - ``signature_wire_bytes`` (``S``) is one ``MerkleSignature.to_bytes``
      blob: a 16-byte v1 header followed by ``n + height`` 32-byte elements
      (``n`` W-OTS chains plus ``height`` auth-path nodes);
    - ``proof_wire_bytes`` is one ``MerkleProof.to_bytes`` blob — an
      ``S``-byte signature plus its 60-byte frame (17-byte proof header,
      43-byte public key);
    - ``checkpoint_bytes`` (``C``) is one ``MerkleSigner.checkpoint`` blob:
      the 49-byte v1 header, ``L * n`` 32-byte private elements and the
      32-byte checksum;
    - ``auth_v1_bytes`` / ``auth_v2_bytes`` are the matching checkpoint
      sealed in a :func:`auth_wrap` (v1, 14-byte header) or
      :func:`auth_state_wrap` (v2, 22-byte header) envelope, each adding a
      32-byte HMAC tag.

    Instances are frozen, support keyword construction and compare (and
    hash) by value; no key material or randomness is involved.
    """

    w: int
    height: int
    leaf_count: int
    signature_wire_bytes: int
    proof_wire_bytes: int
    checkpoint_bytes: int
    auth_v1_bytes: int
    auth_v2_bytes: int


def merkle_storage_profile(w: Any, height: Any) -> MerkleStorageProfile:
    """Return the frozen :class:`MerkleStorageProfile` wire sizes.

    ``w`` must be 4 or 8 and ``height`` a non-boolean integer from 1 to 8;
    anything else raises ``ValueError``. The profile is a pure static
    estimate: no keys are generated and no randomness is drawn.

    With ``n`` the W-OTS chain count (67 for ``w=4``, 34 for ``w=8``),
    ``L = 2 ** height``, ``S = 16 + 32 * (n + height)`` and
    ``C = 81 + 32 * L * n``, the sizes are ``S``, ``S + 60``, ``C``,
    ``C + 46`` and ``C + 54`` for the signature, proof, plain checkpoint,
    v1 envelope and v2 envelope respectively.
    """
    w = _validate_w(w)
    height = _validate_height(height)
    b, l1, l2 = _params(w)
    n = l1 + l2
    leaf_count = 1 << height
    signature_wire_bytes = 16 + ELEMENT_BYTES * (n + height)
    checkpoint_bytes = 81 + ELEMENT_BYTES * leaf_count * n
    return MerkleStorageProfile(
        w=w,
        height=height,
        leaf_count=leaf_count,
        signature_wire_bytes=signature_wire_bytes,
        proof_wire_bytes=signature_wire_bytes + 60,
        checkpoint_bytes=checkpoint_bytes,
        auth_v1_bytes=checkpoint_bytes + 46,
        auth_v2_bytes=checkpoint_bytes + 54,
    )


def merkle_transport_profile(
    w: Any, height: Any, indices: Any
) -> tuple[int, int, int]:
    """Return ``(node_count, batch_bytes, multiproof_bytes)`` for leaf indices.

    Sizes a batch proof and a multi-proof over the same leaf set. ``w`` must
    be 4 or 8 and ``height`` a non-boolean integer from 1 to 8; ``indices``
    must be a non-empty tuple of strictly increasing, non-boolean integers,
    each in ``0 .. 2 ** height - 1``. A non-tuple ``indices`` or a member
    that is not an ``int`` raises ``TypeError``; an empty set, a boolean
    member, an out-of-range index or a non-strictly-increasing (duplicate or
    descending) sequence raises ``ValueError``.

    With ``k = len(indices)``, ``S`` the single-signature wire size
    (``16 + 32 * (n + height)``) and ``m`` the canonical multi-proof node
    count — siblings outside the current index set at each level, with the
    set shifted right and deduplicated between levels — the result is
    ``(m, 58 + k * (4 + S), 60 + k * (4 + 32 * n) + 35 * m)``: the carried
    node count, the length of a ``MerkleBatchProof.to_bytes`` blob, and the
    length of a :func:`multiproof_encode` blob. The estimate is pure: no
    signatures are produced and no randomness is drawn.
    """
    w = _validate_w(w)
    height = _validate_height(height)
    if not isinstance(indices, tuple):
        raise TypeError("indices must be a tuple of leaf indices")
    if not indices:
        raise ValueError("indices must not be empty")
    if any(isinstance(index, bool) for index in indices):
        raise ValueError("index members must not be booleans")
    if any(not isinstance(index, int) for index in indices):
        raise TypeError("every index must be an integer")
    leaf_count = 1 << height
    if any(index < 0 or index >= leaf_count for index in indices):
        raise ValueError("every index must be within the tree's leaf range")
    if any(former >= latter for former, latter in zip(indices, indices[1:])):
        raise ValueError("indices must be strictly increasing and unique")

    b, l1, l2 = _params(w)
    n = l1 + l2
    k = len(indices)
    node_count = len(_canonical_multiproof_nodes(indices, height))
    signature_wire_bytes = 16 + ELEMENT_BYTES * (n + height)
    batch_bytes = 58 + k * (4 + signature_wire_bytes)
    multiproof_bytes = 60 + k * (4 + ELEMENT_BYTES * n) + 35 * node_count
    return node_count, batch_bytes, multiproof_bytes


@dataclass(frozen=True)
class MerkleVerifyProfile:
    """Frozen SHA-256 verification-hash counts for one leaf-index set.

    Compares the verifier-side hash cost of a :class:`MerkleBatchProof`
    against a :func:`multiproof_encode` proof over the same ``k`` leaves.
    Fields, in positional order:

    - ``w`` / ``height`` echo the validated parameters;
    - ``k`` is the number of selected leaf indices;
    - ``wots`` is the upper bound on W-OTS hash-chain steps for all ``k``
      signatures: ``k * 67 * 15`` for ``w=4`` or ``k * 34 * 255`` for
      ``w=8``;
    - ``leaf`` is the number of leaf hashes, one per recovered W-OTS public
      key: ``k`` (authentication-path deduplication never reduces it);
    - ``batch`` is the internal-node hash count when each signature carries a
      full authentication path: ``k * height``, every path repeated in full;
    - ``multi`` is the internal-node hash count of the deduplicated
      multi-proof merge: ``sum(len({i >> l for i in indices}) for l in
      range(1, height + 1))`` — at each level every distinct parent node is
      hashed exactly once.

    Instances are frozen, support positional construction and compare (and
    hash) by value; no key material or randomness is involved.
    """

    w: int
    height: int
    k: int
    wots: int
    leaf: int
    batch: int
    multi: int


def merkle_verify_profile(w: Any, height: Any, indices: Any) -> MerkleVerifyProfile:
    """Return the frozen :class:`MerkleVerifyProfile` verification-hash counts.

    Counts the SHA-256 work a verifier spends on a batch proof versus a
    multi-proof over the same leaf set ``indices``. ``w`` must be 4 or 8 and
    ``height`` a non-boolean integer from 1 to 8; ``indices`` must be a
    non-empty tuple of strictly increasing, non-boolean integers, each in
    ``0 .. 2 ** height - 1``. A non-tuple ``indices`` or a member that is not
    an ``int`` raises ``TypeError``; an empty set, a boolean member, an
    out-of-range, duplicate or out-of-order index, or an illegal ``w`` /
    ``height`` raises ``ValueError``.

    With ``k = len(indices)``, the fields are: ``wots`` the W-OTS chain-step
    upper bound (``k * 67 * 15`` for ``w=4``, ``k * 34 * 255`` for ``w=8``);
    ``leaf = k`` (one leaf hash per selected leaf, never reduced by path
    deduplication); ``batch = k * height`` (each signature repeats its full
    authentication path); and ``multi`` the deduplicated internal-node count,
    ``sum(len({i >> l for i in indices}) for l in range(1, height + 1))`` —
    at each level each distinct parent is hashed once. The estimate is pure:
    no keys are generated, no randomness is drawn and no state is changed.
    """
    w = _validate_w(w)
    height = _validate_height(height)
    if not isinstance(indices, tuple):
        raise TypeError("indices must be a tuple of leaf indices")
    if not indices:
        raise ValueError("indices must not be empty")
    if any(isinstance(index, bool) for index in indices):
        raise ValueError("index members must not be booleans")
    if any(not isinstance(index, int) for index in indices):
        raise TypeError("every index must be an integer")
    leaf_count = 1 << height
    if any(index < 0 or index >= leaf_count for index in indices):
        raise ValueError("every index must be within the tree's leaf range")
    if any(former >= latter for former, latter in zip(indices, indices[1:])):
        raise ValueError("indices must be strictly increasing and unique")

    b, l1, l2 = _params(w)
    k = len(indices)
    wots = k * (l1 + l2) * (b - 1)
    leaf = k
    batch = k * height
    multi = sum(
        len({index >> level for index in indices})
        for level in range(1, height + 1)
    )
    return MerkleVerifyProfile(
        w=w, height=height, k=k, wots=wots, leaf=leaf, batch=batch, multi=multi
    )


@dataclass(frozen=True)
class MerkleVerifyWorkloadProfile:
    """Frozen SHA-256 verification-hash counts for several leaf-index groups.

    Generalises :class:`MerkleVerifyProfile` to a workload of independent
    groups, each carried in its own batch proof or multi-proof. Fields, in
    positional order:

    - ``w`` / ``height`` echo the validated parameters shared by every group;
    - ``costs`` is one five-tuple per input group, in group order; each entry
      is ``(mode, wots, leaf, internal, total)`` where ``mode`` is the chosen
      transport name, ``wots`` is the group's W-OTS hash-chain-step upper
      bound, ``leaf`` its leaf-hash count, ``internal`` its internal-node hash
      count (``batch`` of :class:`MerkleVerifyProfile` for a ``"batch"``
      group, ``multi`` for a ``"multiproof"`` group) and ``total`` the sum of
      those three hash counts for the group — repeated groups are billed
      separately;
    - ``total`` is the grand total: the sum of every group's ``total``.

    Instances are frozen, support positional construction and compare (and
    hash) by value; no key material or randomness is involved.
    """

    w: int
    height: int
    costs: tuple[tuple[str, int, int, int, int], ...]
    total: int


def merkle_verify_workload_profile(
    w: Any, height: Any, groups: Any, modes: Any
) -> MerkleVerifyWorkloadProfile:
    """Return the frozen :class:`MerkleVerifyWorkloadProfile` hash counts.

    Totals the SHA-256 work a verifier spends on a workload of several
    independent leaf-index groups, each carried in its own batch proof or
    multi-proof over the same Merkle tree. ``w`` must be 4 or 8 and
    ``height`` a non-boolean integer from 1 to 8. ``groups`` must be a
    non-empty tuple; each member must itself be a non-empty tuple of strictly
    increasing, non-boolean integers, each in ``0 .. 2 ** height - 1`` (the
    single-group rules of :func:`merkle_verify_profile`, applied per group).
    ``modes`` must be a tuple of the same length as ``groups``; each entry is
    ``"batch"`` or ``"multiproof"``.

    Each group reuses :func:`merkle_verify_profile`: a ``"batch"`` mode takes
    that profile's ``batch`` internal-node count (each signature repeats its
    full authentication path) and a ``"multiproof"`` mode takes its
    ``multi`` count (deduplicated merge). The per-group five-tuple is
    ``(mode, wots, leaf, internal, wots + leaf + internal)`` in group order;
    repeated groups are billed separately. ``total`` is the sum of every
    group's three hash counts. The estimate is pure: no keys are generated,
    no randomness is drawn and no state is changed.

    A non-tuple ``groups`` or ``modes`` (a group that is not itself a tuple
    included), or a mode entry that is not a string, raises ``TypeError``;
    an empty ``groups``, a group-level mismatch with the single-group rules,
    a wrong-length ``modes`` tuple or an unknown mode name raises
    ``ValueError`` (as do illegal ``w`` / ``height``).
    """
    w = _validate_w(w)
    height = _validate_height(height)
    if not isinstance(groups, tuple):
        raise TypeError("groups must be a tuple of leaf-index groups")
    if not groups:
        raise ValueError("groups must not be empty")
    if not isinstance(modes, tuple):
        raise TypeError("modes must be a tuple of transport mode names")
    if len(modes) != len(groups):
        raise ValueError("modes must have exactly one entry per group")
    if any(not isinstance(mode, str) for mode in modes):
        raise TypeError("every mode must be a string")
    if any(mode not in ("batch", "multiproof") for mode in modes):
        raise ValueError('every mode must be "batch" or "multiproof"')

    costs = []
    grand_total = 0
    for group, mode in zip(groups, modes):
        single = merkle_verify_profile(w, height, group)
        internal = single.batch if mode == "batch" else single.multi
        group_total = single.wots + single.leaf + internal
        costs.append((mode, single.wots, single.leaf, internal, group_total))
        grand_total += group_total
    return MerkleVerifyWorkloadProfile(
        w=w, height=height, costs=tuple(costs), total=grand_total
    )


@dataclass(frozen=True)
class MerkleTransportDeploymentProfile:
    """Frozen joint choice of Merkle tree parameters and transport encoding.

    Fields, in positional order:

    - ``config``: the chosen :class:`MerkleStorageProfile` (``w``, ``height``
      and its leaf/wire sizes);
    - ``nodes``: the canonical multi-proof node count ``m`` for the chosen
      leaf-index set;
    - ``batch``: the ``MerkleBatchProof`` wire size in bytes;
    - ``multi``: the :func:`multiproof_encode` wire size in bytes.

    Instances are frozen, support positional construction and compare (and
    hash) by value; no key material or randomness is involved.
    """

    config: MerkleStorageProfile
    nodes: int
    batch: int
    multi: int


def recommend_merkle_transport_deployment(
    capacity: Any,
    indices: Any,
    budgets: Any,
    prefer: str = "multiproof",
) -> MerkleTransportDeploymentProfile:
    """Jointly choose Merkle tree parameters and a transport encoding.

    Enumerates every Merkle candidate — ``w`` in ``(4, 8)`` times ``height``
    from 1 to 8 — keeps those whose ``leaf_count`` covers both ``capacity``
    and the requested leaf ``indices`` and that satisfy every set budget, and
    ranks the feasible set, reusing :func:`merkle_storage_profile`,
    :func:`merkle_transport_profile` and :func:`profile` for every size and
    step count.

    ``capacity`` must be a non-boolean integer from 1 to 256. ``indices``
    must be a non-empty tuple of strictly increasing, non-boolean integers
    whose largest member is below the candidate tree's leaf count; the same
    index set is sized for every candidate. ``budgets`` must be a four-tuple,
    in order: an upper bound on the checkpoint bytes
    (:attr:`MerkleStorageProfile.checkpoint_bytes`), on the batch-proof wire
    length (:attr:`MerkleTransportDeploymentProfile.batch`), on the
    multi-proof wire length (:attr:`MerkleTransportDeploymentProfile.multi`)
    and on the verifier hash-chain step count (``profile("merkle", ...)``'s
    ``steps``). Each entry is either ``None`` (no bound) or a positive,
    non-boolean integer, and at least one entry must be set.

    ``prefer`` selects the ranking: ``"multiproof"`` minimises ``multi``
    first and then ``batch``, ``"batch"`` minimises ``batch`` first and then
    ``multi``, and ``"speed"`` minimises steps first and then ``multi`` and
    ``batch``. All three finish with the same tie-break in ascending order —
    checkpoint bytes, leaf count, ``w`` and ``height`` — and the first
    candidate after sorting is returned as a
    :class:`MerkleTransportDeploymentProfile`.

    A non-tuple ``indices`` or ``budgets`` raises ``TypeError``; an
    out-of-range ``capacity``, an empty, non-integer, boolean,
    out-of-range or non-strictly-increasing ``indices``, a wrong-length or
    otherwise illegal ``budgets`` tuple, an unknown ``prefer`` value, or
    the absence of any feasible candidate raises ``ValueError``. The
    function is pure: it draws no randomness, generates no keys and
    changes no state.
    """
    if not isinstance(indices, tuple):
        raise TypeError("indices must be a tuple of leaf indices")
    if not isinstance(budgets, tuple):
        raise TypeError("budgets must be a 4-tuple of budget limits")
    if len(budgets) != 4:
        raise ValueError("budgets must contain exactly four entries")
    if (
        isinstance(capacity, bool)
        or not isinstance(capacity, int)
        or not 1 <= capacity <= _MAX_CAPACITY
    ):
        raise ValueError(f"capacity must be an integer between 1 and {_MAX_CAPACITY}")
    if not indices:
        raise ValueError("indices must not be empty")
    if any(isinstance(index, bool) or not isinstance(index, int) for index in indices):
        raise ValueError("every index must be a non-boolean integer")
    if any(former >= latter for former, latter in zip(indices, indices[1:])):
        raise ValueError("indices must be strictly increasing and unique")
    if indices[0] < 0:
        raise ValueError("every index must be within the tree's leaf range")
    if prefer not in ("multiproof", "batch", "speed"):
        raise ValueError('prefer must be "multiproof", "batch" or "speed"')

    labels = ("checkpoint", "batch", "multiproof", "steps")
    limits = []
    for label, budget in zip(labels, budgets):
        if budget is None:
            limits.append(None)
        elif isinstance(budget, bool) or not isinstance(budget, int) or budget < 1:
            raise ValueError(f"{label} budget must be None or a positive integer")
        else:
            limits.append(budget)
    if all(limit is None for limit in limits):
        raise ValueError("at least one budget must be set")
    checkpoint_limit, batch_limit, multi_limit, steps_limit = limits

    required_leaves = max(capacity, indices[-1] + 1)
    feasible = []
    for w in (4, 8):
        for height in range(1, 9):
            storage = merkle_storage_profile(w, height)
            if storage.leaf_count < required_leaves:
                continue
            if checkpoint_limit is not None and storage.checkpoint_bytes > checkpoint_limit:
                continue
            node_count, batch_bytes, multi_bytes = merkle_transport_profile(
                w, height, indices
            )
            if batch_limit is not None and batch_bytes > batch_limit:
                continue
            if multi_limit is not None and multi_bytes > multi_limit:
                continue
            steps = profile("merkle", w=w, height=height).steps
            if steps_limit is not None and steps > steps_limit:
                continue
            feasible.append((storage, node_count, batch_bytes, multi_bytes, steps))
    if not feasible:
        raise ValueError("no Merkle configuration fits the requested capacity, indices and budgets")

    def ranking(candidate: tuple) -> tuple[int, ...]:
        storage, _node_count, batch_bytes, multi_bytes, steps = candidate
        tail = (
            storage.checkpoint_bytes,
            storage.leaf_count,
            storage.w,
            storage.height,
        )
        if prefer == "multiproof":
            return (multi_bytes, batch_bytes) + tail
        if prefer == "batch":
            return (batch_bytes, multi_bytes) + tail
        return (steps, multi_bytes, batch_bytes) + tail

    feasible.sort(key=ranking)
    storage, node_count, batch_bytes, multi_bytes, _steps = feasible[0]
    return MerkleTransportDeploymentProfile(
        config=storage, nodes=node_count, batch=batch_bytes, multi=multi_bytes
    )


def merkle_transport_deployment_frontier(
    capacity: Any,
    indices: Any,
    budgets: Any,
) -> tuple[MerkleTransportDeploymentProfile, ...]:
    """Return every feasible, non-dominated joint deployment as a tuple.

    Where :func:`recommend_merkle_transport_deployment` ranks the feasible
    configs and returns one, this function keeps the whole Pareto frontier so
    a caller can inspect the trade-off between checkpoint, batch-proof,
    multi-proof and verification costs: it enumerates every Merkle candidate
    — ``w`` in ``(4, 8)`` times ``height`` from 1 to 8 — whose leaf count
    covers both ``capacity`` and the requested leaf ``indices``, keeps those
    satisfying every set budget, reusing :func:`merkle_storage_profile` for
    the tree wire sizes, :func:`merkle_transport_profile` for the carried
    multi-proof node count and the batch/multi-proof wire sizes and
    :func:`profile` for the per-signature verifier hash-chain step count, and
    drops every dominated candidate.

    ``capacity`` must be a non-boolean integer from 1 to 256. ``indices``
    must be a non-empty tuple of strictly increasing, non-negative,
    non-boolean integers; the same index set is sized for every candidate and
    the chosen tree's leaf count must cover both ``capacity`` and the largest
    index plus one. ``budgets`` must be a four-tuple, in order: an upper bound
    on the checkpoint bytes
    (:attr:`MerkleStorageProfile.checkpoint_bytes`), on the batch-proof wire
    length (:attr:`MerkleTransportDeploymentProfile.batch`), on the
    multi-proof wire length (:attr:`MerkleTransportDeploymentProfile.multi`)
    and on the per-signature verifier hash-chain step count
    (``profile("merkle", ...)``'s ``steps``). Each entry is either ``None``
    (no bound) or a positive, non-boolean integer, and at least one entry
    must be set; every bound is inclusive.

    A feasible profile *A* dominates another feasible profile *B* when
    ``A`` is no greater than ``B`` on all four metrics — checkpoint bytes,
    batch-proof wire bytes, multi-proof wire bytes and verifier steps — and
    strictly smaller on at least one; every dominated candidate is dropped
    and the survivors are deduplicated by value. The carried node count is
    an output of :func:`merkle_transport_profile` rather than a budgeted
    metric, so it never participates in dominance or ordering on its own. No
    preference is applied, so a configuration trading speed for transport
    size (or the reverse) is never discarded ahead of the dominance test.
    The returned tuple is sorted stably and ascending by verifier steps,
    multi-proof wire bytes, batch-proof wire bytes, checkpoint bytes, leaf
    count, ``w`` and ``height``.

    A non-tuple ``indices`` or ``budgets`` raises ``TypeError``; an
    out-of-range ``capacity``, an empty, non-integer, boolean, negative or
    non-strictly-increasing ``indices``, a wrong-length or otherwise illegal
    ``budgets`` tuple, or the absence of any feasible candidate raises
    ``ValueError``. The function is pure: it draws no randomness, generates
    no keys and changes no state.
    """
    if not isinstance(indices, tuple):
        raise TypeError("indices must be a tuple of leaf indices")
    limits = _validate_transport_budgets(budgets)
    if (
        isinstance(capacity, bool)
        or not isinstance(capacity, int)
        or not 1 <= capacity <= _MAX_CAPACITY
    ):
        raise ValueError(f"capacity must be an integer between 1 and {_MAX_CAPACITY}")
    if not indices:
        raise ValueError("indices must not be empty")
    if any(isinstance(index, bool) or not isinstance(index, int) for index in indices):
        raise ValueError("every index must be a non-boolean integer")
    if any(former >= latter for former, latter in zip(indices, indices[1:])):
        raise ValueError("indices must be strictly increasing and unique")
    if indices[0] < 0:
        raise ValueError("every index must be non-negative")
    checkpoint_limit, batch_limit, multi_limit, steps_limit = limits

    required_leaves = max(capacity, indices[-1] + 1)
    candidates: list[tuple[MerkleStorageProfile, int, int, int, int]] = []
    for w in (4, 8):
        for height in range(1, 9):
            storage = merkle_storage_profile(w, height)
            if storage.leaf_count < required_leaves:
                continue
            if checkpoint_limit is not None and storage.checkpoint_bytes > checkpoint_limit:
                continue
            node_count, batch_bytes, multi_bytes = merkle_transport_profile(
                w, height, indices
            )
            if batch_limit is not None and batch_bytes > batch_limit:
                continue
            if multi_limit is not None and multi_bytes > multi_limit:
                continue
            steps = profile("merkle", w=w, height=height).steps
            if steps_limit is not None and steps > steps_limit:
                continue
            candidates.append((storage, node_count, batch_bytes, multi_bytes, steps))
    if not candidates:
        raise ValueError(
            "no Merkle configuration fits the requested capacity, indices and budgets"
        )

    def dominates(
        a: tuple[MerkleStorageProfile, int, int, int, int],
        b: tuple[MerkleStorageProfile, int, int, int, int],
    ) -> bool:
        a_storage, _a_nodes, a_batch, a_multi, a_steps = a
        b_storage, _b_nodes, b_batch, b_multi, b_steps = b
        no_worse = (
            a_storage.checkpoint_bytes <= b_storage.checkpoint_bytes
            and a_batch <= b_batch
            and a_multi <= b_multi
            and a_steps <= b_steps
        )
        strictly_better = (
            a_storage.checkpoint_bytes < b_storage.checkpoint_bytes
            or a_batch < b_batch
            or a_multi < b_multi
            or a_steps < b_steps
        )
        return no_worse and strictly_better

    non_dominated = [
        candidate
        for candidate in candidates
        if not any(dominates(other, candidate) for other in candidates)
    ]

    profiles = [
        MerkleTransportDeploymentProfile(
            config=storage, nodes=node_count, batch=batch_bytes, multi=multi_bytes
        )
        for storage, node_count, batch_bytes, multi_bytes, _steps in non_dominated
    ]

    unique: list[MerkleTransportDeploymentProfile] = []
    seen: set[MerkleTransportDeploymentProfile] = set()
    for deployment in profiles:
        if deployment not in seen:
            seen.add(deployment)
            unique.append(deployment)

    unique.sort(
        key=lambda deployment: (
            profile(
                "merkle",
                w=deployment.config.w,
                height=deployment.config.height,
            ).steps,
            deployment.multi,
            deployment.batch,
            deployment.config.checkpoint_bytes,
            deployment.config.leaf_count,
            deployment.config.w,
            deployment.config.height,
        )
    )
    return tuple(unique)


@dataclass(frozen=True)
class MerkleTransportWorkloadProfile:
    """Frozen choice of tree parameters and one transport encoding per group.

    Fields, in positional order:

    - ``config``: the chosen :class:`MerkleStorageProfile` (``w``, ``height``
      and its leaf/wire sizes);
    - ``modes``: one transport name per input group, in group order, each
      ``"batch"`` (a :class:`MerkleBatchProof` blob) or ``"multiproof"``
      (a :func:`multiproof_encode` blob);
    - ``sizes``: the wire length in bytes of each group's chosen transport,
      aligned position-for-position with ``modes``;
    - ``total``: the aggregate transport bytes, the sum of ``sizes``.

    Instances are frozen, support positional construction and compare (and
    hash) by value; no key material or randomness is involved.
    """

    config: MerkleStorageProfile
    modes: tuple[str, ...]
    sizes: tuple[int, ...]
    total: int


def _validate_workload_groups(capacity: Any, groups: Any) -> int:
    """Validate ``capacity`` and the leaf-index ``groups``; return required leaves."""
    if not isinstance(groups, tuple):
        raise TypeError("groups must be a tuple of leaf-index groups")
    if (
        isinstance(capacity, bool)
        or not isinstance(capacity, int)
        or not 1 <= capacity <= _MAX_CAPACITY
    ):
        raise ValueError(f"capacity must be an integer between 1 and {_MAX_CAPACITY}")
    if not groups:
        raise ValueError("groups must not be empty")
    for group in groups:
        if not isinstance(group, tuple):
            raise TypeError("every group must be a tuple of leaf indices")
        if not group:
            raise ValueError("groups must not contain an empty tuple")
        if any(isinstance(index, bool) or not isinstance(index, int) for index in group):
            raise ValueError("every index must be a non-boolean integer")
        if group[0] < 0:
            raise ValueError("every index must be non-negative")
        if any(former >= latter for former, latter in zip(group, group[1:])):
            raise ValueError("every group's indices must be strictly increasing and unique")
    return max([capacity, *(group[-1] + 1 for group in groups)])


def _validate_workload_budgets(budgets: Any) -> tuple[int | None, ...]:
    """Validate the four-tuple of workload budget limits."""
    if not isinstance(budgets, tuple):
        raise TypeError("budgets must be a 4-tuple of budget limits")
    if len(budgets) != 4:
        raise ValueError("budgets must contain exactly four entries")
    labels = ("checkpoint", "group", "total", "steps")
    limits = []
    for label, budget in zip(labels, budgets):
        if budget is None:
            limits.append(None)
        elif isinstance(budget, bool) or not isinstance(budget, int) or budget < 1:
            raise ValueError(f"{label} budget must be None or a positive integer")
        else:
            limits.append(budget)
    if all(limit is None for limit in limits):
        raise ValueError("at least one budget must be set")
    return tuple(limits)


def recommend_merkle_transport_workload(
    capacity: Any,
    groups: Any,
    budgets: Any,
    prefer: str = "compact",
) -> MerkleTransportWorkloadProfile:
    """Choose one Merkle config and one transport per group under budgets.

    Generalises :func:`recommend_merkle_transport_deployment` to a workload
    of several independent leaf-index groups: every group is carried in its
    own batch proof or multi-proof over the same Merkle tree, and one config
    — ``w`` in ``(4, 8)`` times ``height`` from 1 to 8 — must cover every
    group. All sizes and step counts reuse
    :func:`merkle_storage_profile`, :func:`merkle_transport_profile` and
    :func:`profile`.

    ``capacity`` must be a non-boolean integer from 1 to 256. ``groups``
    must be a non-empty tuple; each member must itself be a non-empty tuple
    of strictly increasing, non-negative, non-boolean integers (a leaf-index
    set). The chosen tree's leaf count must cover both ``capacity`` and every
    group's largest index.

    ``budgets`` must be a four-tuple, in order: an upper bound on the
    checkpoint bytes
    (:attr:`MerkleStorageProfile.checkpoint_bytes`), on the wire length of
    any single group's chosen transport (every entry of
    :attr:`MerkleTransportWorkloadProfile.sizes`), on the aggregate
    transport bytes (:attr:`MerkleTransportWorkloadProfile.total`) and on
    the per-signature verifier hash-chain step count
    (``profile("merkle", ...)``'s ``steps``). Each entry is either ``None``
    (no bound) or a positive, non-boolean integer, and at least one entry
    must be set.

    ``prefer`` selects both the per-group format and the config ranking:

    - ``"compact"`` (the default): each group takes the shorter of the batch
      and multi-proof wire lengths, breaking a tie towards ``"multiproof"``;
      feasible configs rank by aggregate bytes first.
    - ``"speed"``: the same per-group shortest-wire choice, but configs rank
      by verifier steps first and then aggregate bytes.
    - ``"batch"``: every group uses the batch format; configs rank by
      aggregate bytes first.
    - ``"multiproof"``: every group uses the multi-proof format; configs
      rank by aggregate bytes first.

    All rankings finish with the same tie-break in ascending order —
    checkpoint bytes, leaf count, ``w`` and ``height`` — and the first
    config after sorting is returned as a
    :class:`MerkleTransportWorkloadProfile`.

    A non-tuple ``groups`` or ``budgets`` (a group that is not itself a
    tuple included) raises ``TypeError``; an out-of-range ``capacity``, an
    empty group tuple or group, a non-integer, boolean, negative or
    non-strictly-increasing group member, a wrong-length or otherwise
    illegal ``budgets`` tuple, an unknown ``prefer`` value, or the absence
    of any feasible candidate raises ``ValueError``. The function is pure:
    it draws no randomness, generates no keys and changes no state.
    """
    if not isinstance(groups, tuple):
        raise TypeError("groups must be a tuple of leaf-index groups")
    if not isinstance(budgets, tuple):
        raise TypeError("budgets must be a 4-tuple of budget limits")
    if len(budgets) != 4:
        raise ValueError("budgets must contain exactly four entries")
    if (
        isinstance(capacity, bool)
        or not isinstance(capacity, int)
        or not 1 <= capacity <= _MAX_CAPACITY
    ):
        raise ValueError(f"capacity must be an integer between 1 and {_MAX_CAPACITY}")
    if not groups:
        raise ValueError("groups must not be empty")
    for group in groups:
        if not isinstance(group, tuple):
            raise TypeError("every group must be a tuple of leaf indices")
        if not group:
            raise ValueError("groups must not contain an empty tuple")
        if any(isinstance(index, bool) or not isinstance(index, int) for index in group):
            raise ValueError("every index must be a non-boolean integer")
        if group[0] < 0:
            raise ValueError("every index must be non-negative")
        if any(former >= latter for former, latter in zip(group, group[1:])):
            raise ValueError("every group's indices must be strictly increasing and unique")
    if prefer not in ("compact", "speed", "batch", "multiproof"):
        raise ValueError('prefer must be "compact", "speed", "batch" or "multiproof"')

    labels = ("checkpoint", "group", "total", "steps")
    limits = []
    for label, budget in zip(labels, budgets):
        if budget is None:
            limits.append(None)
        elif isinstance(budget, bool) or not isinstance(budget, int) or budget < 1:
            raise ValueError(f"{label} budget must be None or a positive integer")
        else:
            limits.append(budget)
    if all(limit is None for limit in limits):
        raise ValueError("at least one budget must be set")
    checkpoint_limit, group_limit, total_limit, steps_limit = limits

    required_leaves = max([capacity, *(group[-1] + 1 for group in groups)])
    feasible = []
    for w in (4, 8):
        for height in range(1, 9):
            storage = merkle_storage_profile(w, height)
            if storage.leaf_count < required_leaves:
                continue
            if checkpoint_limit is not None and storage.checkpoint_bytes > checkpoint_limit:
                continue
            modes = []
            sizes = []
            for group in groups:
                _node_count, batch_bytes, multi_bytes = merkle_transport_profile(
                    w, height, group
                )
                if prefer in ("compact", "speed"):
                    if multi_bytes <= batch_bytes:
                        mode, size = "multiproof", multi_bytes
                    else:
                        mode, size = "batch", batch_bytes
                elif prefer == "batch":
                    mode, size = "batch", batch_bytes
                else:
                    mode, size = "multiproof", multi_bytes
                modes.append(mode)
                sizes.append(size)
            if group_limit is not None and any(size > group_limit for size in sizes):
                continue
            total = sum(sizes)
            if total_limit is not None and total > total_limit:
                continue
            steps = profile("merkle", w=w, height=height).steps
            if steps_limit is not None and steps > steps_limit:
                continue
            feasible.append((storage, tuple(modes), tuple(sizes), total, steps))
    if not feasible:
        raise ValueError("no Merkle configuration fits the requested capacity, groups and budgets")

    def ranking(candidate: tuple) -> tuple[int, ...]:
        storage, _modes, _sizes, total, steps = candidate
        tail = (
            storage.checkpoint_bytes,
            storage.leaf_count,
            storage.w,
            storage.height,
        )
        if prefer == "speed":
            return (steps, total) + tail
        return (total,) + tail

    feasible.sort(key=ranking)
    storage, modes, sizes, total, _steps = feasible[0]
    return MerkleTransportWorkloadProfile(
        config=storage, modes=modes, sizes=sizes, total=total
    )


def merkle_transport_workload_frontier(
    capacity: Any,
    groups: Any,
    budgets: Any,
) -> tuple[MerkleTransportWorkloadProfile, ...]:
    """Return every feasible, non-dominated workload deployment as a tuple.

    Where :func:`recommend_merkle_transport_workload` ranks the feasible
    configs and returns one, this function keeps the whole Pareto frontier:
    it enumerates every Merkle candidate — ``w`` in ``(4, 8)`` times
    ``height`` from 1 to 8 — whose leaf count covers ``capacity`` and every
    group's largest index, sizes each group's transport with
    :func:`merkle_transport_profile` and takes the shorter of the batch and
    multi-proof wire lengths per group (an equal length breaks towards
    ``"multiproof"``, exactly like ``prefer="compact"``), and applies the
    same checkpoint, per-group, aggregate and verifier-step budgets. Sizes
    and step counts reuse :func:`merkle_storage_profile`,
    :func:`merkle_transport_profile` and :func:`profile`.

    ``capacity`` must be a non-boolean integer from 1 to 256. ``groups``
    must be a non-empty tuple; each member must itself be a non-empty tuple
    of strictly increasing, non-negative, non-boolean integers. ``budgets``
    must be a four-tuple, in order: an upper bound on the checkpoint bytes
    (:attr:`MerkleStorageProfile.checkpoint_bytes`), on any single group's
    chosen transport, on the aggregate transport bytes (the sum across
    groups) and on the per-signature verifier hash-chain step count
    (``profile("merkle", ...)``'s ``steps``). Each entry is either ``None``
    (no bound) or a positive, non-boolean integer, and at least one entry
    must be set.

    A feasible profile *A* dominates another feasible profile *B* when
    ``A.config.checkpoint_bytes <= B.config.checkpoint_bytes``,
    ``A.total <= B.total`` and ``A``'s ``steps`` are no greater than
    ``B``'s, with at least one of the three strictly smaller; every
    dominated profile is dropped and the survivors are deduplicated by
    value. The returned tuple is sorted stably and ascending by
    verifier steps, aggregate transport bytes, checkpoint bytes, leaf
    count, ``w`` and ``height``.

    A non-tuple ``groups`` or ``budgets`` (a group that is not itself a
    tuple included) raises ``TypeError``; an out-of-range ``capacity``, an
    empty group tuple or group, a non-integer, boolean, negative or
    non-strictly-increasing group member, a wrong-length or otherwise
    illegal ``budgets`` tuple, or the absence of any feasible candidate
    raises ``ValueError``. The function is pure: it draws no randomness,
    generates no keys and changes no state.
    """
    required_leaves = _validate_workload_groups(capacity, groups)
    limits = _validate_workload_budgets(budgets)
    checkpoint_limit, group_limit, total_limit, steps_limit = limits

    candidates: list[tuple[MerkleStorageProfile, tuple[str, ...], tuple[int, ...], int, int]] = []
    for w in (4, 8):
        for height in range(1, 9):
            storage = merkle_storage_profile(w, height)
            if storage.leaf_count < required_leaves:
                continue
            if checkpoint_limit is not None and storage.checkpoint_bytes > checkpoint_limit:
                continue
            modes = []
            sizes = []
            for group in groups:
                _node_count, batch_bytes, multi_bytes = merkle_transport_profile(
                    w, height, group
                )
                if multi_bytes <= batch_bytes:
                    mode, size = "multiproof", multi_bytes
                else:
                    mode, size = "batch", batch_bytes
                modes.append(mode)
                sizes.append(size)
            if group_limit is not None and any(size > group_limit for size in sizes):
                continue
            total = sum(sizes)
            if total_limit is not None and total > total_limit:
                continue
            steps = profile("merkle", w=w, height=height).steps
            if steps_limit is not None and steps > steps_limit:
                continue
            candidates.append((storage, tuple(modes), tuple(sizes), total, steps))
    if not candidates:
        raise ValueError(
            "no Merkle configuration fits the requested capacity, groups and budgets"
        )

    def dominates(
        a: tuple[MerkleStorageProfile, tuple[str, ...], tuple[int, ...], int, int],
        b: tuple[MerkleStorageProfile, tuple[str, ...], tuple[int, ...], int, int],
    ) -> bool:
        a_storage, _a_modes, _a_sizes, a_total, a_steps = a
        b_storage, _b_modes, _b_sizes, b_total, b_steps = b
        no_worse = (
            a_storage.checkpoint_bytes <= b_storage.checkpoint_bytes
            and a_total <= b_total
            and a_steps <= b_steps
        )
        strictly_better = (
            a_storage.checkpoint_bytes < b_storage.checkpoint_bytes
            or a_total < b_total
            or a_steps < b_steps
        )
        return no_worse and strictly_better

    non_dominated = [
        candidate
        for candidate in candidates
        if not any(dominates(other, candidate) for other in candidates)
    ]

    profiles = [
        MerkleTransportWorkloadProfile(
            config=storage, modes=modes, sizes=sizes, total=total
        )
        for storage, modes, sizes, total, _steps in non_dominated
    ]

    unique: list[MerkleTransportWorkloadProfile] = []
    seen: set[MerkleTransportWorkloadProfile] = set()
    for profile_value in profiles:
        if profile_value not in seen:
            seen.add(profile_value)
            unique.append(profile_value)

    unique.sort(
        key=lambda workload: (
            profile("merkle", w=workload.config.w, height=workload.config.height).steps,
            workload.total,
            workload.config.checkpoint_bytes,
            workload.config.leaf_count,
            workload.config.w,
            workload.config.height,
        )
    )
    return tuple(unique)


def _validate_mode_budgets(budgets: Any) -> tuple[int | None, ...]:
    """Validate the five-tuple of mode-frontier budget limits."""
    if not isinstance(budgets, tuple):
        raise TypeError("budgets must be a 5-tuple of budget limits")
    if len(budgets) != 5:
        raise ValueError("budgets must contain exactly five entries")
    labels = ("checkpoint", "group", "total", "steps", "nodes")
    limits = []
    for label, budget in zip(labels, budgets):
        if budget is None:
            limits.append(None)
        elif isinstance(budget, bool) or not isinstance(budget, int) or budget < 1:
            raise ValueError(f"{label} budget must be None or a positive integer")
        else:
            limits.append(budget)
    if all(limit is None for limit in limits):
        raise ValueError("at least one budget must be set")
    return tuple(limits)


def merkle_mode_frontier(
    capacity: Any,
    groups: Any,
    budgets: Any,
) -> tuple[MerkleTransportWorkloadProfile, ...]:
    """Return every feasible, non-dominated per-group mode choice as a tuple.

    Where :func:`merkle_transport_workload_frontier` fixes each group's
    transport to the shorter of the batch and multi-proof wire lengths, this
    function enumerates **every** combination of ``"batch"``/``"multiproof"``
    assignments across the groups — all ``2 ** len(groups)`` mode
    combinations of every candidate config participate in the budget
    screening — and keeps the whole Pareto frontier of the feasible choices
    so a caller can inspect the trade-off between checkpoint size, per-group
    peak, aggregate transport, verification cost and carried multi-proof
    nodes. It enumerates every Merkle candidate — ``w`` in ``(4, 8)`` times
    ``height`` from 1 to 8 — whose leaf count covers ``capacity`` and every
    group's largest index, reusing :func:`merkle_storage_profile`,
    :func:`merkle_transport_profile` and :func:`profile` for every size, node
    count and step count.

    ``capacity`` must be a non-boolean integer from 1 to 256. ``groups``
    must be a non-empty tuple; each member must itself be a non-empty tuple
    of strictly increasing, non-negative, non-boolean integers. ``budgets``
    must be a five-tuple, in order: an upper bound on the checkpoint bytes
    (:attr:`MerkleStorageProfile.checkpoint_bytes`), on any single group's
    chosen transport (the peak of
    :attr:`MerkleTransportWorkloadProfile.sizes`), on the aggregate transport
    bytes (:attr:`MerkleTransportWorkloadProfile.total`), on the
    per-signature verifier hash-chain step count (``profile("merkle", ...)``'s
    ``steps``) and on the total carried multi-proof node count — which
    accumulates the canonical node count of every group carried as a
    multi-proof and counts ``0`` for every group carried as a batch proof.
    Each entry is either ``None`` (no bound) or a positive, non-boolean
    integer, and at least one entry must be set; every bound is inclusive.

    A feasible profile *A* dominates another feasible profile *B* when
    ``A`` is no greater than ``B`` on all five costs — checkpoint bytes,
    per-group peak, aggregate transport bytes, verifier steps and carried
    node total — and strictly smaller on at least one; every dominated
    profile is dropped and the survivors are deduplicated by value. No
    preference is applied, so a mode combination trading transport size for
    fewer carried nodes (or the reverse) is never discarded ahead of the
    dominance test. The returned tuple is sorted stably and ascending by
    verifier steps, aggregate transport bytes, per-group peak, carried node
    total, checkpoint bytes, leaf count, ``w``, ``height`` and the ``modes``
    tuple in lexicographic order.

    A non-tuple ``groups`` or ``budgets`` (a group that is not itself a
    tuple included) raises ``TypeError``; an out-of-range ``capacity``, an
    empty group tuple or group, a non-integer, boolean, negative or
    non-strictly-increasing group member, a wrong-length or otherwise
    illegal ``budgets`` tuple, or the absence of any feasible candidate
    raises ``ValueError``. The function is pure: it draws no randomness,
    generates no keys and changes no state.
    """
    required_leaves = _validate_workload_groups(capacity, groups)
    limits = _validate_mode_budgets(budgets)
    checkpoint_limit, group_limit, total_limit, steps_limit, nodes_limit = limits

    candidates: list[
        tuple[MerkleStorageProfile, tuple[str, ...], tuple[int, ...], int, int, int, int]
    ] = []
    for w in (4, 8):
        for height in range(1, 9):
            storage = merkle_storage_profile(w, height)
            if storage.leaf_count < required_leaves:
                continue
            if checkpoint_limit is not None and storage.checkpoint_bytes > checkpoint_limit:
                continue
            steps = profile("merkle", w=w, height=height).steps
            if steps_limit is not None and steps > steps_limit:
                continue
            transports = [
                merkle_transport_profile(w, height, group) for group in groups
            ]
            for choices in product((0, 1), repeat=len(groups)):
                modes = []
                sizes = []
                nodes = 0
                for choice, (node_count, batch_bytes, multi_bytes) in zip(
                    choices, transports
                ):
                    if choice:
                        modes.append("multiproof")
                        sizes.append(multi_bytes)
                        nodes += node_count
                    else:
                        modes.append("batch")
                        sizes.append(batch_bytes)
                peak = max(sizes)
                if group_limit is not None and peak > group_limit:
                    continue
                total = sum(sizes)
                if total_limit is not None and total > total_limit:
                    continue
                if nodes_limit is not None and nodes > nodes_limit:
                    continue
                candidates.append(
                    (storage, tuple(modes), tuple(sizes), total, steps, peak, nodes)
                )
    if not candidates:
        raise ValueError(
            "no Merkle configuration fits the requested capacity, groups and budgets"
        )

    def costs(
        candidate: tuple[
            MerkleStorageProfile, tuple[str, ...], tuple[int, ...], int, int, int, int
        ],
    ) -> tuple[int, int, int, int, int]:
        storage, _modes, _sizes, total, steps, peak, nodes = candidate
        return (storage.checkpoint_bytes, peak, total, steps, nodes)

    def dominates(
        a: tuple[MerkleStorageProfile, tuple[str, ...], tuple[int, ...], int, int, int, int],
        b: tuple[MerkleStorageProfile, tuple[str, ...], tuple[int, ...], int, int, int, int],
    ) -> bool:
        a_costs = costs(a)
        b_costs = costs(b)
        return all(a_cost <= b_cost for a_cost, b_cost in zip(a_costs, b_costs)) and any(
            a_cost < b_cost for a_cost, b_cost in zip(a_costs, b_costs)
        )

    non_dominated = [
        candidate
        for candidate in candidates
        if not any(dominates(other, candidate) for other in candidates)
    ]

    unique: list[
        tuple[MerkleStorageProfile, tuple[str, ...], tuple[int, ...], int, int, int, int]
    ] = []
    seen: set[MerkleTransportWorkloadProfile] = set()
    for candidate in non_dominated:
        storage, modes, sizes, total, _steps, _peak, _nodes = candidate
        profile_value = MerkleTransportWorkloadProfile(
            config=storage, modes=modes, sizes=sizes, total=total
        )
        if profile_value not in seen:
            seen.add(profile_value)
            unique.append(candidate)

    unique.sort(
        key=lambda candidate: (
            candidate[4],
            candidate[3],
            candidate[5],
            candidate[6],
            candidate[0].checkpoint_bytes,
            candidate[0].leaf_count,
            candidate[0].w,
            candidate[0].height,
            candidate[1],
        )
    )
    return tuple(
        MerkleTransportWorkloadProfile(
            config=storage, modes=modes, sizes=sizes, total=total
        )
        for storage, modes, sizes, total, _steps, _peak, _nodes in unique
    )


def recommend_merkle_mode_deployment(
    capacity: Any,
    groups: Any,
    budgets: Any,
    prefer: str = "compact",
) -> MerkleTransportWorkloadProfile:
    """Pick one non-dominated per-group mode choice from :func:`merkle_mode_frontier`.

    Computes the full feasible, non-dominated mode frontier exactly like
    :func:`merkle_mode_frontier` — every ``w`` in ``(4, 8)`` times
    ``height`` from 1 to 8, every ``2 ** len(groups)`` per-group
    ``"batch"``/``"multiproof"`` combination, screened by the same
    checkpoint, per-group peak, aggregate, verifier-step and carried-node
    budgets with the same Pareto pruning — and ranks the survivors by a
    business preference instead of returning them all:

    - ``"compact"`` (the default): aggregate transport bytes
      (:attr:`MerkleTransportWorkloadProfile.total`), then per-group peak
      (the maximum of :attr:`MerkleTransportWorkloadProfile.sizes`), then
      carried node total, then verifier steps;
    - ``"nodes"``: carried node total first, then aggregate bytes, peak and
      steps. The node total uses the mode frontier's definition: it
      accumulates the canonical multi-proof node count of every group
      carried as a multi-proof and counts ``0`` for batch groups;
    - ``"speed"``: per-signature verifier hash-chain steps
      (``profile("merkle", ...)``'s ``steps``) first, then aggregate bytes,
      then per-group peak, then carried node total.

    All three rankings finish with the same ascending tie-break —
    checkpoint bytes, leaf count, ``w``, ``height`` and the ``modes`` tuple
    in lexicographic order — and the first profile after sorting is
    returned as a :class:`MerkleTransportWorkloadProfile`.

    ``capacity``, ``groups`` and the five-tuple ``budgets`` follow
    :func:`merkle_mode_frontier`'s types, ranges, budget rules and
    exceptions exactly; an unknown ``prefer`` value (anything other than
    ``"compact"``, ``"nodes"`` or ``"speed"``) or the absence of any
    feasible candidate raises ``ValueError``. The function is pure: it
    draws no randomness, generates no keys and changes no state.
    """
    _validate_workload_groups(capacity, groups)
    _validate_mode_budgets(budgets)
    if prefer not in ("compact", "nodes", "speed"):
        raise ValueError('prefer must be "compact", "nodes" or "speed"')
    frontier = merkle_mode_frontier(capacity, groups, budgets)

    def ranking(workload: MerkleTransportWorkloadProfile) -> tuple[int, ...]:
        peak = max(workload.sizes)
        steps = profile(
            "merkle", w=workload.config.w, height=workload.config.height
        ).steps
        nodes = sum(
            merkle_transport_profile(
                workload.config.w, workload.config.height, group
            )[0]
            for mode, group in zip(workload.modes, groups)
            if mode == "multiproof"
        )
        tail = (
            workload.config.checkpoint_bytes,
            workload.config.leaf_count,
            workload.config.w,
            workload.config.height,
            workload.modes,
        )
        if prefer == "compact":
            return (workload.total, peak, nodes, steps) + tail
        if prefer == "nodes":
            return (nodes, workload.total, peak, steps) + tail
        return (steps, workload.total, peak, nodes) + tail

    return min(frontier, key=ranking)


def _validate_verify_mode_budgets(budgets: Any) -> tuple[int | None, ...]:
    """Validate the six-tuple of verify-mode-frontier budget limits."""
    if not isinstance(budgets, tuple):
        raise TypeError("budgets must be a 6-tuple of budget limits")
    if len(budgets) != 6:
        raise ValueError("budgets must contain exactly six entries")
    labels = ("checkpoint", "group", "total", "steps", "nodes", "hashes")
    limits = []
    for label, budget in zip(labels, budgets):
        if budget is None:
            limits.append(None)
        elif isinstance(budget, bool) or not isinstance(budget, int) or budget < 1:
            raise ValueError(f"{label} budget must be None or a positive integer")
        else:
            limits.append(budget)
    if all(limit is None for limit in limits):
        raise ValueError("at least one budget must be set")
    return tuple(limits)


@dataclass(frozen=True)
class MerkleModeCost:
    """Frozen per-group mode choice together with its verify hash costs.

    Pairs the transport plan of :func:`merkle_mode_frontier` with the
    verifier-side SHA-256 work of :func:`merkle_verify_workload_profile` for
    the same config and per-group mode assignment. Fields, in positional
    order:

    - ``plan``: the chosen :class:`MerkleTransportWorkloadProfile` — its
      ``config``, per-group ``modes``, per-group transport wire ``sizes`` and
      aggregate ``total``;
    - ``cost``: the :class:`MerkleVerifyWorkloadProfile` for the same
      ``w``/``height``, groups and ``modes``;
    - ``nodes``: the total carried multi-proof node count, accumulating the
      canonical node count of every group carried as a multi-proof and
      counting ``0`` for every group carried as a batch proof.

    Instances are frozen, support positional construction and compare (and
    hash) by value; no key material or randomness is involved.
    """

    plan: MerkleTransportWorkloadProfile
    cost: MerkleVerifyWorkloadProfile
    nodes: int


def merkle_verify_mode_frontier(
    capacity: Any,
    groups: Any,
    budgets: Any,
) -> tuple[MerkleModeCost, ...]:
    """Return every feasible, non-dominated mode/verify-cost choice as a tuple.

    Joins :func:`merkle_mode_frontier` with
    :func:`merkle_verify_workload_profile`: it enumerates every Merkle
    candidate — ``w`` in ``(4, 8)`` times ``height`` from 1 to 8 — whose leaf
    count covers ``capacity`` and every group's largest index, and every
    ``2 ** len(groups)`` combination of per-group ``"batch"``/
    ``"multiproof"`` assignments, reusing :func:`merkle_storage_profile`,
    :func:`merkle_transport_profile`, :func:`profile` and
    :func:`merkle_verify_workload_profile` for every size, node count, step
    count and verifier hash count, and keeps the whole Pareto frontier of
    the feasible choices so a caller can inspect the trade-off between
    checkpoint size, per-group peak, aggregate transport, verifier steps,
    carried multi-proof nodes and verifier SHA-256 hashes.

    ``capacity`` must be a non-boolean integer from 1 to 256. ``groups``
    must be a non-empty tuple; each member must itself be a non-empty tuple
    of strictly increasing, non-negative, non-boolean integers (the same
    group rules as :func:`merkle_mode_frontier`). ``budgets`` must be a
    six-tuple, in order: an upper bound on the checkpoint bytes
    (:attr:`MerkleStorageProfile.checkpoint_bytes`), on any single group's
    chosen transport (the peak of
    :attr:`MerkleTransportWorkloadProfile.sizes`), on the aggregate
    transport bytes (:attr:`MerkleTransportWorkloadProfile.total`), on the
    per-signature verifier hash-chain step count
    (``profile("merkle", ...)``'s ``steps``), on the total carried
    multi-proof node count (the canonical node count of every multi-proof
    group, ``0`` for every batch group) and on the total verifier SHA-256
    hash count (:attr:`MerkleVerifyWorkloadProfile.total`). Each entry is
    either ``None`` (no bound) or a positive, non-boolean integer, and at
    least one entry must be set; every bound is inclusive.

    Each survivor is returned as a :class:`MerkleModeCost`: ``plan`` saves
    the config, modes, per-group sizes and aggregate total exactly as
    :func:`merkle_mode_frontier` does, ``cost`` is the
    :func:`merkle_verify_workload_profile` for the same parameters and
    ``nodes`` accumulates the canonical node count of the multi-proof
    groups only.

    A feasible choice *A* dominates another feasible choice *B* when ``A``
    is no greater than ``B`` on all six costs — checkpoint bytes,
    per-group peak, aggregate transport bytes, verifier steps, carried node
    total and verifier hash total — and strictly smaller on at least one;
    every dominated choice is dropped and the survivors are deduplicated by
    value. No preference is applied, so a mode combination trading one
    cost for another is never discarded ahead of the dominance test. The
    returned tuple is sorted stably and ascending by verifier steps,
    verifier hash total, aggregate transport bytes, per-group peak, carried
    node total, checkpoint bytes, leaf count, ``w``, ``height`` and the
    ``modes`` tuple in lexicographic order.

    A non-tuple ``groups`` or ``budgets`` (a group that is not itself a
    tuple included) raises ``TypeError``; an out-of-range ``capacity``, an
    empty group tuple or group, a non-integer, boolean, negative or
    non-strictly-increasing group member, a wrong-length or otherwise
    illegal ``budgets`` tuple, or the absence of any feasible candidate
    raises ``ValueError``. The function is pure: it draws no randomness,
    generates no keys and changes no state.
    """
    required_leaves = _validate_workload_groups(capacity, groups)
    limits = _validate_verify_mode_budgets(budgets)
    (
        checkpoint_limit,
        group_limit,
        total_limit,
        steps_limit,
        nodes_limit,
        hashes_limit,
    ) = limits

    candidates: list[
        tuple[
            MerkleStorageProfile,
            tuple[str, ...],
            tuple[int, ...],
            int,
            int,
            int,
            int,
            int,
            MerkleVerifyWorkloadProfile,
        ]
    ] = []
    for w in (4, 8):
        for height in range(1, 9):
            storage = merkle_storage_profile(w, height)
            if storage.leaf_count < required_leaves:
                continue
            if checkpoint_limit is not None and storage.checkpoint_bytes > checkpoint_limit:
                continue
            steps = profile("merkle", w=w, height=height).steps
            if steps_limit is not None and steps > steps_limit:
                continue
            transports = [
                merkle_transport_profile(w, height, group) for group in groups
            ]
            for choices in product((0, 1), repeat=len(groups)):
                modes = []
                sizes = []
                nodes = 0
                for choice, (node_count, batch_bytes, multi_bytes) in zip(
                    choices, transports
                ):
                    if choice:
                        modes.append("multiproof")
                        sizes.append(multi_bytes)
                        nodes += node_count
                    else:
                        modes.append("batch")
                        sizes.append(batch_bytes)
                modes_tuple = tuple(modes)
                peak = max(sizes)
                if group_limit is not None and peak > group_limit:
                    continue
                total = sum(sizes)
                if total_limit is not None and total > total_limit:
                    continue
                if nodes_limit is not None and nodes > nodes_limit:
                    continue
                verify = merkle_verify_workload_profile(
                    w, height, groups, modes_tuple
                )
                if hashes_limit is not None and verify.total > hashes_limit:
                    continue
                candidates.append(
                    (
                        storage,
                        modes_tuple,
                        tuple(sizes),
                        total,
                        steps,
                        peak,
                        nodes,
                        verify.total,
                        verify,
                    )
                )
    if not candidates:
        raise ValueError(
            "no Merkle configuration fits the requested capacity, groups and budgets"
        )

    def costs(
        candidate: tuple[
            MerkleStorageProfile,
            tuple[str, ...],
            tuple[int, ...],
            int,
            int,
            int,
            int,
            int,
            MerkleVerifyWorkloadProfile,
        ],
    ) -> tuple[int, int, int, int, int, int]:
        (
            storage,
            _modes,
            _sizes,
            total,
            steps,
            peak,
            nodes,
            hashes,
            _verify,
        ) = candidate
        return (storage.checkpoint_bytes, peak, total, steps, nodes, hashes)

    def dominates(a: tuple, b: tuple) -> bool:
        a_costs = costs(a)
        b_costs = costs(b)
        return all(a_cost <= b_cost for a_cost, b_cost in zip(a_costs, b_costs)) and any(
            a_cost < b_cost for a_cost, b_cost in zip(a_costs, b_costs)
        )

    non_dominated = [
        candidate
        for candidate in candidates
        if not any(dominates(other, candidate) for other in candidates)
    ]

    unique: list[tuple] = []
    seen: set[MerkleModeCost] = set()
    for candidate in non_dominated:
        storage, modes, sizes, total, _steps, _peak, nodes, _hashes, verify = candidate
        mode_cost = MerkleModeCost(
            plan=MerkleTransportWorkloadProfile(
                config=storage, modes=modes, sizes=sizes, total=total
            ),
            cost=verify,
            nodes=nodes,
        )
        if mode_cost not in seen:
            seen.add(mode_cost)
            unique.append(candidate)

    unique.sort(
        key=lambda candidate: (
            candidate[4],
            candidate[7],
            candidate[3],
            candidate[5],
            candidate[6],
            candidate[0].checkpoint_bytes,
            candidate[0].leaf_count,
            candidate[0].w,
            candidate[0].height,
            candidate[1],
        )
    )
    return tuple(
        MerkleModeCost(
            plan=MerkleTransportWorkloadProfile(
                config=storage, modes=modes, sizes=sizes, total=total
            ),
            cost=verify,
            nodes=nodes,
        )
        for storage, modes, sizes, total, _steps, _peak, nodes, _hashes, verify in unique
    )

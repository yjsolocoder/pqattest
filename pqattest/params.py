"""Static parameter analysis for pqattest schemes.

:func:`profile` reports the size and cost metrics of a scheme/parameter
combination without generating any keys, and :func:`recommend` picks a Merkle
configuration for a desired signature capacity, :func:`recommend_merkle_deployment`
picks one that additionally fits deployment budgets. :func:`merkle_storage_profile`
breaks the Merkle wire sizes down per serialised object and
:func:`merkle_transport_profile` sizes a batch or multi-proof over a chosen
leaf-index set. :func:`recommend_merkle_transport_deployment` chooses both the
tree parameters and the transport encoding together under checkpoint, batch,
multi-proof and verifier-step budgets.
:func:`recommend_merkle_transport_workload` does the same for a workload of
several leaf-index groups, picking a transport mode per group under
checkpoint, per-group, total-transport and verifier-step budgets. All seven
are pure functions: no randomness, no state, no I/O, no keys are generated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .merkle import _canonical_multiproof_nodes, _validate_height
from .wots import ELEMENT_BYTES, _params, _validate_w

__all__ = [
    "Params",
    "MerkleStorageProfile",
    "MerkleTransportDeploymentProfile",
    "MerkleTransportWorkloadProfile",
    "profile",
    "recommend",
    "recommend_merkle_deployment",
    "recommend_merkle_transport_deployment",
    "recommend_merkle_transport_workload",
    "merkle_storage_profile",
    "merkle_transport_profile",
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


@dataclass(frozen=True)
class MerkleTransportWorkloadProfile:
    """Frozen joint choice of tree parameters and per-group transport modes.

    Fields, in positional order:

    - ``config``: the chosen :class:`MerkleStorageProfile` (``w``, ``height``
      and its leaf/wire sizes);
    - ``modes``: one transport mode per leaf-index group, each ``"batch"``
      or ``"multiproof"``;
    - ``sizes``: the matching wire size in bytes per group — the
      ``MerkleBatchProof`` length for a ``"batch"`` group, the
      :func:`multiproof_encode` length for a ``"multiproof"`` group;
    - ``total``: the sum of ``sizes``.

    Instances are frozen, support positional construction and compare (and
    hash) by value; no key material or randomness is involved.
    """

    config: MerkleStorageProfile
    modes: tuple[str, ...]
    sizes: tuple[int, ...]
    total: int


def recommend_merkle_transport_workload(
    capacity: Any,
    groups: Any,
    budgets: Any,
    prefer: str = "compact",
) -> MerkleTransportWorkloadProfile:
    """Choose tree parameters and a per-group transport mode for a workload.

    Enumerates every Merkle candidate — ``w`` in ``(4, 8)`` times ``height``
    from 1 to 8 — keeps those whose ``leaf_count`` covers both ``capacity``
    and every leaf index in ``groups`` and that satisfy every set budget,
    and ranks the feasible set, reusing :func:`merkle_storage_profile`,
    :func:`merkle_transport_profile` and :func:`profile` for every size and
    step count.

    ``capacity`` must be a non-boolean integer from 1 to 256. ``groups``
    must be a non-empty tuple whose members are themselves non-empty tuples
    of strictly increasing, non-boolean, non-negative integers — each member
    is one leaf-index group transported together, and every group is sized
    for every candidate. ``budgets`` must be a four-tuple, in order: an
    upper bound on the checkpoint bytes
    (:attr:`MerkleStorageProfile.checkpoint_bytes`), on any single group's
    transport wire length, on the total transport wire length
    (:attr:`MerkleTransportWorkloadProfile.total`) and on the verifier
    hash-chain step count (``profile("merkle", ...)``'s ``steps``). Each
    entry is either ``None`` (no bound) or a positive, non-boolean integer,
    and at least one entry must be set.

    ``prefer`` selects both the per-group modes and the ranking:
    ``"compact"`` and ``"speed"`` pick the shorter of the batch and
    multi-proof wire lengths for each group independently (a tie resolves
    to ``"multiproof"``), while ``"batch"`` and ``"multiproof"`` fix that
    same-named format for every group. ``"compact"``, ``"batch"`` and
    ``"multiproof"`` rank by total transport bytes first; ``"speed"``
    ranks by steps first and then total. All four finish with the same
    tie-break in ascending order — checkpoint bytes, leaf count, ``w`` and
    ``height`` — and the first candidate after sorting is returned as a
    :class:`MerkleTransportWorkloadProfile`.

    A non-tuple ``groups`` or ``budgets``, or a group that is not itself a
    tuple, raises ``TypeError``; an out-of-range ``capacity``, an empty,
    non-integer, boolean, negative or non-strictly-increasing group, a
    wrong-length or otherwise illegal ``budgets`` tuple, an unknown
    ``prefer`` value, or the absence of any feasible candidate raises
    ``ValueError``. The function is pure: it draws no randomness, generates
    no keys and changes no state.
    """
    if not isinstance(groups, tuple):
        raise TypeError("groups must be a tuple of leaf-index tuples")
    if not isinstance(budgets, tuple):
        raise TypeError("budgets must be a 4-tuple of budget limits")
    if any(not isinstance(group, tuple) for group in groups):
        raise TypeError("every group must be a tuple of leaf indices")
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
        if not group:
            raise ValueError("every group must not be empty")
        if any(isinstance(index, bool) or not isinstance(index, int) for index in group):
            raise ValueError("every index must be a non-boolean integer")
        if any(former >= latter for former, latter in zip(group, group[1:])):
            raise ValueError("indices must be strictly increasing and unique")
        if group[0] < 0:
            raise ValueError("every index must be within the tree's leaf range")
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

    required_leaves = max(
        [capacity] + [group[-1] + 1 for group in groups]
    )
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
                _nodes, batch_bytes, multi_bytes = merkle_transport_profile(
                    w, height, group
                )
                if prefer == "batch":
                    mode, size = "batch", batch_bytes
                elif prefer == "multiproof":
                    mode, size = "multiproof", multi_bytes
                elif batch_bytes < multi_bytes:
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

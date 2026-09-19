"""Parameter analysis for pqattest schemes.

:func:`profile` turns a scheme configuration into a frozen :class:`Params`
summary (capacity, signature size, chain-step bound), and :func:`recommend`
picks the cheapest Merkle configuration covering a requested capacity. Both
are pure functions: no randomness, no I/O, no state.
"""

from __future__ import annotations

from dataclasses import dataclass

from .merkle import _validate_height
from .wots import _params as _wots_params
from .wots import _validate_w

__all__ = ["Params", "profile", "recommend"]

_ELEMENT_BYTES = 32
_LAMPORT_SIG_BYTES = 256 * _ELEMENT_BYTES
_MAX_CAPACITY = 256


@dataclass(frozen=True)
class Params:
    """Frozen metric summary for one scheme configuration.

    ``scheme`` is ``"lamport"``, ``"wots"`` or ``"merkle"``; ``w`` and
    ``height`` are ``None`` where the scheme has no such parameter. The
    metrics:

    - ``capacity`` — messages signable per key pair (1 for the one-time
      schemes, ``2 ** height`` for Merkle).
    - ``elements`` — 32-byte chain elements in one signature (0 for Lamport,
      which reveals raw secrets rather than chain values).
    - ``sig_bytes`` — total signature size in bytes, excluding the Merkle
      leaf index and any Python object overhead.
    - ``path_bytes`` — Merkle authentication-path bytes (already included in
      ``sig_bytes``; 0 for the other schemes).
    - ``steps`` — upper bound on hash-chain steps to verify one signature
      (0 for Lamport, which hashes every revealed secret exactly once).
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
    """Return ``(n, steps)``: chain count and the chain-step upper bound."""
    b, l1, l2 = _wots_params(w)
    n = l1 + l2
    return n, n * (b - 1)


def profile(scheme: str, w: int | None = None, height: int | None = None) -> Params:
    """Return the :class:`Params` summary for one scheme configuration.

    ``"lamport"`` takes neither ``w`` nor ``height``; ``"wots"`` takes
    ``w`` (4 or 8) only; ``"merkle"`` takes both, with ``height`` an integer
    from 1 to 8 (not ``bool``). An unknown scheme, a missing parameter or an
    unexpected one raises ``ValueError``.
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
            sig_bytes=_LAMPORT_SIG_BYTES,
            path_bytes=0,
            steps=0,
        )
    if scheme == "wots":
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
            sig_bytes=n * _ELEMENT_BYTES,
            path_bytes=0,
            steps=steps,
        )
    if scheme == "merkle":
        w = _validate_w(w)
        height = _validate_height(height)
        n, steps = _wots_metrics(w)
        return Params(
            scheme="merkle",
            w=w,
            height=height,
            capacity=1 << height,
            elements=n,
            sig_bytes=(n + height) * _ELEMENT_BYTES,
            path_bytes=height * _ELEMENT_BYTES,
            steps=steps,
        )
    raise ValueError(f"unknown scheme: {scheme!r}")


def recommend(capacity: int, prefer: str = "size") -> Params:
    """Return the Merkle :class:`Params` covering ``capacity`` signatures.

    ``capacity`` must be an integer from 1 to 256 (not ``bool``); the height
    is the smallest one with ``2 ** height >= capacity`` and at least 1.
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

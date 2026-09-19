"""Static parameter analysis for pqattest schemes.

:func:`profile` reports the size and cost metrics of a scheme/parameter
combination without generating any keys, and :func:`recommend` picks a Merkle
configuration for a desired signature capacity. Both are pure functions: no
randomness, no state, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .merkle import _validate_height
from .wots import ELEMENT_BYTES, _params, _validate_w

__all__ = ["Params", "profile", "recommend"]

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

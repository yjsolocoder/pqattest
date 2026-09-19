"""Shared exceptions for pqattest."""

from __future__ import annotations

__all__ = ["KeyExhaustedError"]


class KeyExhaustedError(RuntimeError):
    """A bounded-use signer was asked to sign after its keys were exhausted."""

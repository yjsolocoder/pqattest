"""Toy lattice KEM for pqattest — **教学演示，未经审计，严禁用于生产**。

一个刻意缩到最小的“格风格”密钥封装机制：密钥与密文都是 8 个
``0..256`` 系数的编码向量，共享值是双方各自算出的点积（模 257），
会话密钥由该点积派生。它只用于演示 KEM 的 keygen/encapsulate/
decapsulate 流程与类型/值校验形状，**不提供任何真实安全性**。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Callable

__all__ = [
    "ToyLatticeCiphertext",
    "ToyLatticePrivateKey",
    "ToyLatticePublicKey",
    "toy_lattice_decapsulate",
    "toy_lattice_encapsulate",
    "toy_lattice_keygen",
]

DIMENSION = 8
MODULUS = 257
SEED_BYTES = 8
COEFFICIENT_BYTES = 2
ENCODED_BYTES = DIMENSION * COEFFICIENT_BYTES
KEY_BYTES = 32
_KEY_DOMAIN = b"K"

D = secrets.token_bytes


def _encode(seed: bytes) -> bytes:
    """``E``:把 8 个种子字节编码为 8 个 ``0..256`` 系数的 2 字节大端串。"""
    return b"".join(byte.to_bytes(COEFFICIENT_BYTES, "big") for byte in seed)


def _decode(data: bytes) -> tuple[int, ...]:
    """``E`` 的逆:把 16 字节串解码回 8 个 ``0..256`` 系数。"""
    if len(data) != ENCODED_BYTES:
        raise ValueError(f"encoded vector must be exactly {ENCODED_BYTES} bytes")
    coefficients = tuple(
        int.from_bytes(data[i : i + COEFFICIENT_BYTES], "big")
        for i in range(0, ENCODED_BYTES, COEFFICIENT_BYTES)
    )
    for coefficient in coefficients:
        if coefficient >= MODULUS:
            raise ValueError(f"every coefficient must be between 0 and {MODULUS - 1}")
    return coefficients


def _validate_vector(name: str, value: object) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    _decode(value)


def _validate_tag(value: object) -> None:
    if not isinstance(value, bytes):
        raise TypeError("tag must be bytes")
    if len(value) != KEY_BYTES:
        raise ValueError(f"tag must be exactly {KEY_BYTES} bytes")


@dataclass(frozen=True)
class ToyLatticePublicKey:
    """冻结的教学公钥(P):``t`` 为 ``E`` 编码的 8 系数向量。"""

    t: bytes

    def __post_init__(self) -> None:
        _validate_vector("t", self.t)


@dataclass(frozen=True)
class ToyLatticePrivateKey:
    """冻结的教学私钥(S):``s`` 为 ``E`` 编码的 8 系数向量。"""

    s: bytes

    def __post_init__(self) -> None:
        _validate_vector("s", self.s)


@dataclass(frozen=True)
class ToyLatticeCiphertext:
    """冻结的教学密文(C):``u`` 为 ``E`` 编码的 8 系数向量,``tag`` 为会话密钥。"""

    u: bytes
    tag: bytes

    def __post_init__(self) -> None:
        _validate_vector("u", self.u)
        _validate_tag(self.tag)


def _draw_seed(token_bytes: Callable[[int], bytes]) -> bytes:
    seed = bytes(token_bytes(SEED_BYTES))
    if len(seed) != SEED_BYTES:
        raise ValueError(f"token_bytes must return {SEED_BYTES} bytes")
    return seed


def _dot(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    return sum(x * y for x, y in zip(a, b)) % MODULUS


def _derive_key(v: int) -> bytes:
    return hashlib.sha256(_KEY_DOMAIN + v.to_bytes(2, "big")).digest()


def toy_lattice_keygen(
    *, token_bytes: Callable[[int], bytes] = D
) -> tuple[ToyLatticePrivateKey, ToyLatticePublicKey]:
    """生成教学密钥对,返回 ``(private_key, public_key)``。

    取 ``x = token_bytes(8)``,令 ``s = t = E(x)``——私钥与公钥持有同一
    编码向量,这正是本构造只是玩具的原因之一。
    """
    x = _draw_seed(token_bytes)
    s = _encode(x)
    return ToyLatticePrivateKey(s=s), ToyLatticePublicKey(t=s)


def toy_lattice_encapsulate(
    public_key: ToyLatticePublicKey, *, token_bytes: Callable[[int], bytes] = D
) -> tuple[ToyLatticeCiphertext, bytes]:
    """封装:返回 ``(ciphertext, K)``。

    取 ``r = token_bytes(8)``、``u = E(r)``,共享值 ``v = t·r mod 257``
    (点积用解码向量),``K = SHA256(b"K" + v 的 2 字节大端)``,``tag = K``。
    """
    if not isinstance(public_key, ToyLatticePublicKey):
        raise TypeError("public_key must be a ToyLatticePublicKey")
    r = _draw_seed(token_bytes)
    u = _encode(r)
    v = _dot(_decode(public_key.t), _decode(u))
    key = _derive_key(v)
    return ToyLatticeCiphertext(u=u, tag=key), key


def toy_lattice_decapsulate(
    ciphertext: ToyLatticeCiphertext, private_key: ToyLatticePrivateKey
) -> bytes:
    """解封:重算 ``v = s·u mod 257`` 与 ``K``,常量时间校验 ``tag`` 后返回 ``K``。

    ``tag`` 不匹配抛 ``ValueError``。
    """
    if not isinstance(ciphertext, ToyLatticeCiphertext):
        raise TypeError("ciphertext must be a ToyLatticeCiphertext")
    if not isinstance(private_key, ToyLatticePrivateKey):
        raise TypeError("private_key must be a ToyLatticePrivateKey")
    v = _dot(_decode(private_key.s), _decode(ciphertext.u))
    key = _derive_key(v)
    if not hmac.compare_digest(key, ciphertext.tag):
        raise ValueError("ciphertext tag mismatch")
    return key

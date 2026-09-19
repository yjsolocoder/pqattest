# pqattest

基于哈希的**一次性**签名（Lamport 构造与 Winternitz 构造）。安全性只依赖哈希函数的单向性，不依赖大整数分解或离散对数，因此不惧量子攻击；代价是密钥对只能签一条消息。

## 环境

Python 3.10+，只依赖标准库（`hashlib`、`secrets`）。

## 使用

```python
from pqattest import keygen, sign, verify

private_key, public_key = keygen()
signature = sign(b"position claim", private_key)
assert verify(b"position claim", signature, public_key)
assert not verify(b"other claim", signature, public_key)
```

Winternitz（W-OTS）用法相同，但签名更短：

```python
from pqattest import wots_keygen, wots_sign, wots_verify

private_key, public_key = wots_keygen(w=4)  # w 仅支持 4 或 8
signature = wots_sign(b"position claim", private_key)
assert wots_verify(b"position claim", signature, public_key)
```

消息统一接受 `bytes`、`bytearray`、`str`（str 按 UTF-8 编码）。

## 命令行演示

```bash
python3 -m pqattest
```

## 公开接口

Lamport：

- `BITS` / `HASH_BYTES` — 默认 256 位摘要与 32 字节哈希
- `PrivateKey(secrets)` / `PublicKey(digests)` — 不可变密钥；各含 `2 * bits` 个 32 字节元素
- `message_digest(message)` — 对 `bytes`/`bytearray`/`str` 取 SHA-256
- `message_bits(message, *, bits=BITS)` — 摘要展开为比特序列
- `keygen(*, bits=BITS, token_bytes=secrets.token_bytes)` — 返回 `(private_key, public_key)`
- `public_key_from(private_key)` — 由私钥重算公钥
- `sign(message, private_key)` — 返回长度等于 `bits` 的签名（比特 `i` 揭示第 `i` 位对应的那个秘密）
- `verify(message, signature, public_key)` — 逐位比对
- `OneTimeSigner(private_key)` — 线程安全的进程内一次性签名器；首次 `sign(message)` 与 `sign(message, private_key)` 相同，此后抛出 `KeyExhaustedError`；只读属性 `public_key`、`used`
- `KeyExhaustedError` — 已用签名器再次签名时抛出（继承 `RuntimeError`）

```python
from pqattest import keygen, OneTimeSigner, KeyExhaustedError

private_key, public_key = keygen()
signer = OneTimeSigner(private_key)
signature = signer.sign(b"position claim")   # 成功
assert signer.used and signer.public_key == public_key
try:
    signer.sign(b"another claim")            # KeyExhaustedError
except KeyExhaustedError:
    pass
```

Winternitz（W-OTS）：

- `ELEMENT_BYTES` — 链元素固定 32 字节
- `WOTSPrivateKey(w, elements)` / `WOTSPublicKey(w, elements)` — 含 `w` 与元素元组的冻结值对象
- `wots_keygen(*, w=4, token_bytes=secrets.token_bytes)` — 返回 `(private_key, public_key)`；`w` 仅允许 `4` 或 `8`
- `wots_sign(message, private_key)` — 返回不可变元组签名
- `wots_verify(message, signature, public_key)` — 结构/参数/内容不匹配一律返回 `False`；密钥类型错误抛 `TypeError`

构造细节（域串 `b"pqattest/wots/v1"`）：令 `B = 2**w`，SHA-256 摘要按大端拆成 `256/w` 个基 `B` 数字；校验和为 `sum(B-1-d)`，取满足 `B**l2 > (256/w)*(B-1)` 的最小 `l2`（w=4 时 l2=3，w=8 时 l2=2），并编码为固定 `l2` 位的大端基 `B` 数字（保留前导零）。每条链始于一个随机值，链步为 `H(x) = SHA256(b"pqattest/wots/v1" + x)`；签名依次给出消息数字与校验和数字对应的第 `d` 步值（w=4 共 67 个元素、2144 字节；w=8 共 34 个元素、1088 字节），公钥保存第 `B-1` 步端点；验证时补足剩余步数并逐条比对端点。无效 `w`、令牌长度错误或元素数量/长度错误抛 `ValueError`。

## 限制

两种构造都是纯一次性签名：**同一密钥对签第二条消息就会同时暴露多个链位置的哈希原像（Lamport 为两个分支的秘密），签名即可被伪造**。无状态的 `sign`/`wots_sign` 不阻止也不检测重复使用（Lamport 可用 `OneTimeSigner` 在进程内防护；W-OTS 没有等价包装器）。没有 Merkle 多一次性签名结构，因此一把长期公钥无法对应多次签名，也没有任何持久化状态——一次性密钥的生成、保管与废弃完全由调用方负责。参数固定为 SHA-256 安全级：Lamport 为 256 位（签名 256 × 32 = 8 KB）；W-OTS 仅提供 `w ∈ {4, 8}` 两档尺寸/速度权衡，链元素固定 32 字节，不含针对多消息或可变安全裕度的参数。

## 测试

```bash
python3 -m unittest discover -s tests
```

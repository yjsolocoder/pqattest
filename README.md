# pqattest

基于哈希的**一次性**签名，提供两种构造：Lamport 与 Winternitz（W-OTS）。安全性只依赖哈希函数的单向性，不依赖大整数分解或离散对数，因此不惧量子攻击；代价是密钥对只能签一条消息。

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

## 命令行演示

```bash
python3 -m pqattest
```

## 公开接口

- `BITS` / `HASH_BYTES` — 默认 256 位摘要与 32 字节哈希
- `PrivateKey(secrets)` / `PublicKey(digests)` — 不可变密钥；各含 `2 * bits` 个 32 字节元素
- `message_digest(message)` — 对 `bytes`/`str` 取 SHA-256
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

## Winternitz 一次性签名（W-OTS）

Winternitz 构造用哈希链压缩签名体积，消息同样取 SHA-256 后按大端拆成基 `B = 2**w` 数字，并附加一个同样以基 B 编码的校验和（保留前导零）。每条链始于一个随机值，链步为 `H(x) = SHA256(b"pqattest/wots/v1" + x)`；签名暴露每条链的第 `d` 步值，公钥保存第 `B-1` 步端点，验证时补足剩余步数并逐条比对。

- `WOTSPrivateKey(w, elements)` / `WOTSPublicKey(w, elements)` — 冻结的值对象；`elements` 为不可变元组，每个元素固定 32 字节
- `wots_keygen(*, w=4, token_bytes=secrets.token_bytes)` — 返回 `(private_key, public_key)`；`w` 仅允许 `4` 或 `8`
- `wots_sign(message, private_key)` — 返回不可变元组签名；消息接受 `bytes`/`bytearray`/`str`
- `wots_verify(message, signature, public_key)` — 结构、参数或内容不匹配一律返回 `False`；密钥类型错误抛出 `TypeError`

参数尺寸（`l1 = 256/w`，`l2` 为满足 `B**l2 > l1*(B-1)` 的最小值）：

| `w` | `B` | 消息数字 `l1` | 校验和数字 `l2` | 链总数 | 签名大小 |
| --- | --- | ------------- | --------------- | ------ | -------- |
| 4   | 16  | 64            | 3               | 67     | 67 × 32 B ≈ 2.1 KB |
| 8   | 256 | 32            | 2               | 34     | 34 × 32 B ≈ 1.1 KB |

```python
from pqattest import wots_keygen, wots_sign, wots_verify

private_key, public_key = wots_keygen(w=8)
signature = wots_sign("position claim", private_key)
assert wots_verify(b"position claim", signature, public_key)
assert not wots_verify("other claim", signature, public_key)
```

## 限制

两种构造都仍是**纯一次性签名**：同一密钥对签第二条消息就会泄露哈希链上的中间值（Lamport 下则同时泄露两个分支的秘密），签名即可被伪造。无状态的 `sign` / `wots_sign` 不阻止也不检测重复使用；需要防护时使用 `OneTimeSigner`（仅约束同一签名器实例，且为进程内管理）。Lamport 签名尺寸等于摘要位数乘以哈希长度（256 × 32 = 8 KB）；W-OTS 通过 Winternitz 链把签名压缩到约 2.1 KB（w=4）或 1.1 KB（w=8），但代价是签名/验证需要更多次哈希运算。本包**没有 Merkle 多一次性签名结构，也没有任何持久状态**，因此一把长期公钥无法对应多次签名；每条消息都需要独立的一次性密钥对（或由包外的 Merkle 层聚合）。安全参数固定为 SHA-256、元素 32 字节，W-OTS 的 `w` 仅可取 4 或 8，没有其他可配置的安全裕度或尺寸权衡。

## 测试

```bash
python3 -m unittest discover -s tests
```

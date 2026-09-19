# pqattest

基于哈希的**一次性**签名（Lamport 构造）。安全性只依赖哈希函数的单向性，不依赖大整数分解或离散对数，因此不惧量子攻击；代价是密钥对只能签一条消息。

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

## 限制

这是纯一次性签名：**同一密钥对签第二条消息就会同时泄露两个分支的秘密，签名即可被伪造**，库本身不阻止也不检测重复使用。没有任何状态记录，也没有密钥用尽管理。签名尺寸等于摘要位数乘以哈希长度（256 × 32 = 8 KB），签名本身比消息大得多，没有 Winternitz 链压缩。没有 Merkle 多一次性签名结构，因此一把长期公钥无法对应多次签名。参数固定为 256 位，没有可配置的安全裕度或尺寸权衡。

## 测试

```bash
python3 -m unittest discover -s tests
```

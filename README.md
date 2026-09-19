# pqattest

基于哈希的签名：Lamport 与 Winternitz **一次性**构造，以及把多把 W-OTS 密钥聚合进一棵 Merkle 树的**有限次**构造。安全性只依赖哈希函数的单向性，不依赖大整数分解或离散对数，因此不惧量子攻击；代价是一次性密钥对只能签一条消息（Merkle 构造则限 `2**height` 条）。

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

需要一把长期公钥对应多条消息时，用 Merkle 聚合的 W-OTS（有限次签名）：

```python
from pqattest import MerkleSigner, merkle_verify

signer = MerkleSigner(height=4, w=4)        # 16 片叶子 = 可签 16 条
public_key = signer.public_key              # 唯一的长期公钥（含 Merkle 根）
sig0 = signer.sign(b"position claim")       # 自动占用叶子 0
sig1 = signer.sign(b"another claim")        # 叶子 1，依此类推
assert merkle_verify(b"position claim", sig0, public_key)
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

Merkle 聚合（有限次签名）：

- `MerklePublicKey(w, height, root)` — 冻结的长期公钥；`leaf_count` 给出叶子数 `2**height`
- `MerkleSignature(index, wots_signature, auth_path)` — 冻结签名：叶索引、该叶的 W-OTS 签名、自叶层至根层的认证路径（每级一个 32 字节兄弟节点）
- `MerkleSigner(*, height=4, w=4, token_bytes=secrets.token_bytes)` — 生成 `2**height` 把 W-OTS 密钥并建成 Merkle 树；`height` 为 1 至 8 的整数（非布尔），`w` 为 4 或 8。只读属性 `public_key`；`sign(message)` 线程安全地按 0 起递增分配叶子，仅成功后消耗叶子（非法消息抛 `TypeError` 且不消耗），叶子用尽抛 `KeyExhaustedError`，并发调用不会分配到重复索引
- `merkle_verify(message, signature, public_key)` — 由签名恢复 W-OTS 公钥、算出叶哈希，再按 `index` 的各位把认证路径逐层折回根并比对；公钥类型错误抛 `TypeError`，其余畸形、越界或不匹配一律返回 `False`（包括绕过冻结构造器造成的字段缺失、类型/范围错误或元素、路径畸形）

构造细节：叶哈希为 `SHA256(b"pqattest/leaf" + bytes([w]) + 公钥元素串)`；内部节点为 `SHA256(b"pqattest/node" + 左 + 右)`；所有节点 32 字节。状态只在进程内，不持久化。

参数分析（纯函数，不生成密钥、不取随机数）：

- `Params` — 冻结的指标值对象，字段为 `scheme, w, height, capacity, elements, sig_bytes, path_bytes, steps`；`w`/`height` 对该方案无意义时为 `None`
- `profile(scheme, w=None, height=None)` — 返回某方案参数组合的 `Params`。`"lamport"` 不收 `w`/`height`；`"wots"` 只收 `w ∈ {4, 8}`；`"merkle"` 收 `w` 与 `height`（1 至 8 非布尔整数）。未知方案、参数缺失或多余一律抛 `ValueError`
- `recommend(capacity, prefer="size")` — 为期望的签名条数选 Merkle 配置并返回其 `Params`。`capacity` 限 1 至 256 的非布尔整数；`height` 取满足 `2**height >= capacity` 的最小值且至少为 1；`prefer="size"` 选 `w=8`（签名更短），`prefer="speed"` 选 `w=4`（链步更少、验签更快）。非法输入抛 `ValueError`

指标含义：`capacity` 为一把密钥可签的消息条数；`elements` 为单条（一次性）签名的 32 字节链元素个数；`sig_bytes` 为签名序列化字节数（Merkle 含认证路径，**不含**叶索引与 Python 对象开销）；`path_bytes` 为其中认证路径部分的字节数；`steps` 为验证一条（一次性）签名所需哈希链步数的上界。

```python
from pqattest import profile, recommend

profile("wots", w=4)          # Params(..., elements=67, sig_bytes=2144, steps=1005)
params = recommend(100)       # 最小覆盖 100 条的 Merkle 配置：w=8, height=7
signer = MerkleSigner(height=params.height, w=params.w)
```

推荐策略：先按要签的消息条数定 `capacity`，`recommend` 给出能覆盖它的最小树高；签名体积敏感（默认）用 `w=8`，验证/签名速度敏感用 `prefer="speed"` 换 `w=4`——后者签名约大一倍，但链步上界从 `34×255=8670` 降到 `67×15=1005`。

## 限制

Lamport 与 W-OTS 构造都是纯一次性签名：**同一密钥对签第二条消息就会同时暴露多个链位置的哈希原像（Lamport 为两个分支的秘密），签名即可被伪造**。无状态的 `sign`/`wots_sign` 不阻止也不检测重复使用（Lamport 可用 `OneTimeSigner` 在进程内防护；W-OTS 没有等价包装器）。Merkle 构造把上限提高到 `2**height` 条消息，但每签一条就永久消耗一片叶子，`MerkleSigner` 只在进程内跟踪已用叶子、没有任何持久化状态——进程重启后叶子分配从零开始，因此长期防重用仍由调用方负责。参数固定为 SHA-256 安全级：Lamport 为 256 位（签名 256 × 32 = 8 KB）；W-OTS 仅提供 `w ∈ {4, 8}` 两档尺寸/速度权衡，链元素固定 32 字节，不含针对多消息或可变安全裕度的参数。

## 测试

```bash
python3 -m unittest discover -s tests
```

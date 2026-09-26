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

需要把一份签名连同公钥**独立**传给没有旁带公钥的接收方时，用 `MerkleProof` 打包：

```python
from pqattest import MerkleProof

proof = MerkleProof(public_key=public_key, signature=sig0)
blob = proof.to_bytes()                     # 单块字节即可传输
assert MerkleProof.from_bytes(blob).verify(b"position claim")
```

同一公钥的多份签名可用 `MerkleBatchProof` 打成一个批次整体传输（签名索引须严格递增，与 `sign`/`sign_batch` 的产出顺序天然一致）：

```python
from pqattest import MerkleBatchProof

messages = (b"claim 0", b"claim 1", b"claim 2")
batch = MerkleBatchProof(public_key=public_key, signatures=signer.sign_batch(messages))
blob = batch.to_bytes()
assert MerkleBatchProof.from_bytes(blob).verify(messages)
```

消息统一接受 `bytes`、`bytearray`、`str`（str 按 UTF-8 编码）。

教学用格基玩具 KEM（仅演示封装/解封装流程）：

```python
from pqattest import toy_lattice_keygen, toy_lattice_encapsulate, toy_lattice_decapsulate

private_key, public_key = toy_lattice_keygen()
ciphertext, enc_key = toy_lattice_encapsulate(public_key)
dec_key = toy_lattice_decapsulate(ciphertext, private_key)
assert enc_key == dec_key == ciphertext.tag
```

**未审计、不具安全性，仅供教学，严禁生产使用。**

## 命令行演示

```bash
python3 -m pqattest
```

## 公开接口

Lamport：

- `BITS` / `HASH_BYTES` — 默认 256 位摘要与 32 字节哈希
- `PrivateKey(secrets)` / `PublicKey(digests)` — 不可变密钥；各含 `2 * bits` 个 32 字节元素
- `PrivateKey.to_bytes()` / `PrivateKey.from_bytes(data)`、`PublicKey.to_bytes()` / `PublicKey.from_bytes(data)` — 密钥的确定性 v1 二进制编解码；编码方法不接参数，`from_bytes` 只接受 `bytes`/`bytearray`（其他类型抛 `TypeError`），魔数、版本、`bits`（1..256 非布尔整数）、元素计数（须为 `2 * bits`）、截断或尾随数据非法抛 `ValueError`；往返后密钥仍可位置构造、冻结、按值相等，且可照常签名/验证。**私钥编码含明文秘密**，须按私钥保护
- `message_digest(message)` — 对 `bytes`/`bytearray`/`str` 取 SHA-256
- `message_bits(message, *, bits=BITS)` — 摘要展开为比特序列
- `keygen(*, bits=BITS, token_bytes=secrets.token_bytes)` — 返回 `(private_key, public_key)`
- `public_key_from(private_key)` — 由私钥重算公钥
- `sign(message, private_key)` — 返回长度等于 `bits` 的签名（比特 `i` 揭示第 `i` 位对应的那个秘密）
- `verify(message, signature, public_key)` — 逐位比对
- `lamport_signature_to_bytes(signature, *, bits)` / `lamport_signature_from_bytes(data)` — 无状态签名的确定性 v1 二进制编解码；前者要求 `signature` 为成员全为 `bytes` 的元组（容器或成员类型错抛 `TypeError`）并返回 `bytes`，`bits` 仅限关键字且须为 1..256 的非布尔整数、等于元素数（否则抛 `ValueError`）；后者返回 `(bits, elements)`，`bits` 为 `int`，`elements` 为保持原序的不可变 `bytes` 元组、每项 32 字节，可直接交给 `verify`。计数或成员长度不符、坏魔数、未知版本、截断或尾随数据均抛 `ValueError`；解码入口只接受 `bytes`/`bytearray`（其他类型抛 `TypeError`）
- `OneTimeSigner(private_key)` — 线程安全的进程内一次性签名器；首次 `sign(message)` 与 `sign(message, private_key)` 相同，此后抛出 `KeyExhaustedError`；只读属性 `public_key`、`used`
- `OneTimeSigner.checkpoint()` — 把签名器状态（**含私钥**与 `used`）序列化为 `bytes`；与 `sign` 共用同一把锁，并发快照只会落在某次签名之前或之后，不会落在签名中途；同一状态编码逐字节相同
- `OneTimeSigner.from_checkpoint(data)` — 从检查点恢复签名器，不取随机数；按既有 Lamport 规则原序重建私钥及公钥，公钥与原实例相等，`used` 状态也一致（未用恢复后仍只允许一签，已用恢复后任何 `sign` 都抛 `KeyExhaustedError`）。`data` 只接受 `bytes`/`bytearray`，其他类型抛 `TypeError`；坏魔数、未知版本、`used` 非 0/1、私钥长度字段不符、嵌套私钥编码非法、截断、尾随数据或校验值不符，均抛 `ValueError` 且不返回实例
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

```python
from pqattest import lamport_signature_to_bytes, lamport_signature_from_bytes

blob = private_key.to_bytes()                 # 含明文秘密，须按私钥保护
restored_private = PrivateKey.from_bytes(blob)
assert restored_private == private_key

sig_blob = lamport_signature_to_bytes(signature, bits=private_key.bits)
bits, elements = lamport_signature_from_bytes(sig_blob)
assert verify(b"position claim", elements, public_key)
```

Winternitz（W-OTS）：

- `ELEMENT_BYTES` — 链元素固定 32 字节
- `WOTSPrivateKey(w, elements)` / `WOTSPublicKey(w, elements)` — 含 `w` 与元素元组的冻结值对象
- `WOTSPrivateKey.to_bytes()` / `WOTSPrivateKey.from_bytes(data)`、`WOTSPublicKey.to_bytes()` / `WOTSPublicKey.from_bytes(data)` — 密钥的确定性 v1 二进制编解码；编码方法不接参数，`from_bytes` 只接受 `bytes`/`bytearray`（其他类型抛 `TypeError`），魔数、版本、`w`、元素计数、截断或尾随数据非法抛 `ValueError`；往返后密钥按值相等。**私钥编码含明文秘密**，须妥善保管
- `wots_keygen(*, w=4, token_bytes=secrets.token_bytes)` — 返回 `(private_key, public_key)`；`w` 仅允许 `4` 或 `8`
- `wots_sign(message, private_key)` — 返回不可变元组签名
- `wots_verify(message, signature, public_key)` — 结构/参数/内容不匹配一律返回 `False`；密钥类型错误抛 `TypeError`
- `wots_signature_to_bytes(signature, *, w)` / `wots_signature_from_bytes(data)` — 无状态签名的确定性 v1 二进制编解码；前者要求 `signature` 为成员全为 `bytes` 的元组（否则抛 `TypeError`）并返回 `bytes`，后者返回 `(w, elements)`，`elements` 为保持原序的不可变 `bytes` 元组，可直接交给 `wots_verify`。非法 `w`、计数不符、成员长度非 32 字节、坏魔数、未知版本、截断或尾随数据均抛 `ValueError`；解码入口只接受 `bytes`/`bytearray`（其他类型抛 `TypeError`）
- `WOTSOneTimeSigner(private_key)` — 线程安全的进程内一次性签名器；首次 `sign(message)` 与 `wots_sign` 相同，此后抛出 `KeyExhaustedError`；只读属性 `public_key`、`used`
- `WOTSOneTimeSigner.checkpoint()` — 把签名器状态（**含私钥**与 `used`）序列化为 `bytes`；与 `sign` 共用同一把锁，并发快照只会落在某次签名之前或之后，不会落在签名中途；同一状态编码逐字节相同
- `WOTSOneTimeSigner.from_checkpoint(data)` — 从检查点恢复签名器，不取随机数；按既有 W-OTS 规则原序重建私钥及公钥，公钥与原实例相等，`used` 状态也一致（未用恢复后仍只允许一签，已用恢复后任何 `sign` 都抛 `KeyExhaustedError`）。`data` 只接受 `bytes`/`bytearray`，其他类型抛 `TypeError`；魔数、版本、`w`、`used`（仅 0/1）、元素计数（须严格等于 `w` 对应的链数）、长度、截断、尾随数据或校验值非法，均抛 `ValueError` 且不返回实例

构造细节（域串 `b"pqattest/wots/v1"`）：令 `B = 2**w`，SHA-256 摘要按大端拆成 `256/w` 个基 `B` 数字；校验和为 `sum(B-1-d)`，取满足 `B**l2 > (256/w)*(B-1)` 的最小 `l2`（w=4 时 l2=3，w=8 时 l2=2），并编码为固定 `l2` 位的大端基 `B` 数字（保留前导零）。每条链始于一个随机值，链步为 `H(x) = SHA256(b"pqattest/wots/v1" + x)`；签名依次给出消息数字与校验和数字对应的第 `d` 步值（w=4 共 67 个元素、2144 字节；w=8 共 34 个元素、1088 字节），公钥保存第 `B-1` 步端点；验证时补足剩余步数并逐条比对端点。无效 `w`、令牌长度错误或元素数量/长度错误抛 `ValueError`。

Merkle 聚合（有限次签名）：

- `MerklePublicKey(w, height, root)` — 冻结的长期公钥；`leaf_count` 给出叶子数 `2**height`
- `MerklePublicKey.to_bytes()` / `MerklePublicKey.from_bytes(data)` — 版本化的公钥二进制编解码；编码确定一致，`from_bytes` 只接受 `bytes`/`bytearray`（其他类型抛 `TypeError`），魔数、版本、长度或字段非法抛 `ValueError`
- `MerkleSignature(index, wots_signature, auth_path)` — 冻结签名：叶索引、该叶的 W-OTS 签名、自叶层至根层的认证路径（每级一个 32 字节兄弟节点）
- `MerkleSignature.to_bytes(public_key)` / `MerkleSignature.from_bytes(data, public_key)` — 版本化的签名二进制编解码。签名对象自身不带参数，两个接口都以 `public_key` 约束：`w` 与树高须与之一致、索引小于 `2**height`、元素数等于 `w` 对应的链数、路径数等于树高；不满足抛 `ValueError`，`public_key` 类型错误抛 `TypeError`
- `MerkleSigner(*, height=4, w=4, token_bytes=secrets.token_bytes)` — 生成 `2**height` 把 W-OTS 密钥并建成 Merkle 树；`height` 为 1 至 8 的整数（非布尔），`w` 为 4 或 8。只读属性 `public_key`；`sign(message)` 线程安全地按 0 起递增分配叶子，仅成功后消耗叶子（非法消息抛 `TypeError` 且不消耗），叶子用尽抛 `KeyExhaustedError`，并发调用不会分配到重复索引
- `MerkleSigner.next_index` / `MerkleSigner.remaining` — 只读整数属性：下一可用叶索引，以及 `public_key.leaf_count - next_index`（剩余可签叶子数）。两者均与 `sign`/`sign_batch`/`checkpoint` 共用同一把锁并线性化；到达叶总数后 `remaining` 为 0。**不存在公开的回退入口**
- `MerkleSigner.advance_to(next_index) -> (int, int)` — 主动作废叶子：把下一可用叶索引推进到 `next_index`，返回推进前后的索引二元组。供调用方在崩溃恢复或状态不确定时跳过可能已暴露的 W-OTS 叶子，使其永不再用于签名。推进只移动索引，不改变公私钥；目标必须是非布尔整数且落在闭区间 `[当前 next_index, public_key.leaf_count]`，类型错（含布尔）抛 `TypeError`，倒退或越界抛 `ValueError`。等值目标成功返回相同二元组且不改状态、不取随机数；推到叶总数后签名器用尽，`sign` 与非空 `sign_batch` 抛 `KeyExhaustedError`（空批次仍返回空元组）。与 `sign`、`sign_batch`、`checkpoint` 共用锁并线性化；推进状态由现有 v1 检查点格式原样保存与恢复
- `MerkleSigner.advance_to_with_auth_state(next_index, *, key, generation) -> ((int, int), bytes)` — 在一次原子调用内完成作废与认证封装：返回 `((before, after), envelope)`，内层二元组与同目标下 `advance_to` 的返回相同，`envelope` 为对推进后 v1 `checkpoint()` 逐字节相同的检查点调用 `auth_state_wrap(scheme="merkle", key=key, generation=generation)` 得到的 v2 封装（既有字段顺序与 HMAC-SHA-256 标签）。等值目标成功且状态不变时仍返回认证该状态的封装。`next_index` 须为非布尔整数且在 `[当前 next_index, public_key.leaf_count]` 闭区间；`key` 须为非空 `bytes`/`bytearray`，`generation` 须为 `0..2**64-1` 的非布尔整数（均仅限关键字）。全部参数在推进前验证：类型错抛 `TypeError`，空 key、代次越界、倒退或超出叶总数抛 `ValueError`，失败不改状态且无部分返回。推进、快照与封装在与所有其他状态操作共用的锁内一次线性化完成，全程不取随机数、不改变公私钥；封装仅认证不加密，本身不防重放/回滚
- `MerkleSigner.checkpoint()` — 把完整签名状态（含**全部私钥**）序列化为 `bytes`；与 `sign`/`advance_to` 共用同一把锁，并发快照只会落在某次操作之前或之后，不会落在操作中途
- `MerkleSigner.from_checkpoint(data)` — 从检查点恢复签名器，不取随机数；公钥与原签名器相同，下一次 `sign` 从保存的 `next_index` 继续，用尽状态恢复后仍抛 `KeyExhaustedError`。`data` 只接受 `bytes`/`bytearray`，其他类型抛 `TypeError`；魔数、版本、长度、`w`、树高、`next_index` 越界（允许 `0 <= next_index <= 2**height`）、元素数量、校验值非法，或由私钥重建的 Merkle 根不符，均抛 `ValueError` 且不返回实例
- `MerkleSigner.from_auth_state(data, *, key, min_generation=None) -> (signer, generation)` — 认证恢复入口：把 v2 验签、代次下限与 v1 检查点恢复合并为一次调用，全程不取随机数、不新增格式，仅接受既定 `auth_state_wrap` v2 封装。`key` 与 `min_generation` 仅限关键字；`data` 为封装字节，`key` 为非空 `bytes`/`bytearray`，`min_generation` 为 `None` 或 `0..2**64-1` 的非布尔整数（下限仍由外部可信存储维护，封装不携带）。返回的 `signer` 公钥、索引及用尽语义与把封装载荷交给 `from_checkpoint` 完全一致，`generation` 为封装内的非负整数。字段顺序、HMAC-SHA-256 标签与 v2 封装格式逐字节不变；恢复时**先按现有 v2 规则用 `hmac.compare_digest` 验证 HMAC**，再固定要求方案为 `merkle` 并检查代次下限，**最后**才把原样载荷交给 `from_checkpoint`，仅全部成功后构造实例。`data`/`key` 非 `bytes`/`bytearray`、下限非整数或为布尔抛 `TypeError`；空密钥、越界参数、HMAC/魔数/版本/方案非法（v1 或其他方案封装同样拒绝）、代次低于下限或检查点非法一律抛 `ValueError` 且不返回实例
- `merkle_verify(message, signature, public_key)` — 由签名恢复 W-OTS 公钥、算出叶哈希，再按 `index` 的各位把认证路径逐层折回根并比对；公钥类型错误抛 `TypeError`，其余畸形、越界或不匹配一律返回 `False`（包括绕过冻结构造器造成的字段缺失、类型/范围错误或元素、路径畸形）
- `MerkleProof(public_key, signature)` — 冻结的证明值对象，字段须分别为 `MerklePublicKey` 与 `MerkleSignature`（字段类型错误抛 `TypeError`，签名参数/计数与公钥不一致抛 `ValueError`）；把一把公钥和一份签名打包成一份可**独立传输**的证明。证明包不存消息，本身不提供认证或加密
- `MerkleProof.to_bytes()` / `MerkleProof.from_bytes(data)` — 证明包的版本化二进制编解码；编码确定、同值同字节。`from_bytes` 只接受 `bytes`/`bytearray`（其他类型抛 `TypeError`），解析时先恢复包内公钥、再以它约束签名；魔数、版本、长度越界或与内容不符、截断、尾随数据、嵌套编码非法或公钥与签名交叉不一致均抛 `ValueError`，不返回半有效对象
- `MerkleProof.verify(message)` — 接受 `bytes`/`bytearray`/`str`，等价于 `merkle_verify(message, proof.signature, proof.public_key)`；只对被签署的消息返回 `True`，消息、公钥或签名被改动后返回 `False`（非法消息类型返回 `False`）
- `MerkleProof.verify_bound(message, *, public_key, index=None)` — 在 `verify(message)` 的验证之外，把证明绑定到接收方预期公钥与可选叶选择；参数与默认值固定，不新增对象、不改动证明 v1 线格式及任何旧入口行为，不生成密钥、不取随机数、不保存状态。`public_key` 须为 `MerklePublicKey`（错型抛 `TypeError`）；先按 `w`、`height`、`root` 把预期公钥与包内公钥逐值比较，再沿用 `merkle_verify` 验证消息与签名，全部匹配才返回 `True`。`index=None` 不限制叶选择；显式值须为非布尔整数并等于签名索引——完全不是整数（`bool` 除外）抛 `TypeError`，布尔、负数、越界或不相等返回 `False`。包内公钥或签名字段缺失、错型（含绕过冻结构造器形成的畸形结构），以及消息、签名或公钥不匹配均返回 `False` 而不泄漏其他异常
- `MerkleBatchProof(public_key, signatures)` — 冻结的批次证明值对象：`public_key` 须为 `MerklePublicKey`，`signatures` 须为**非空**的 `MerkleSignature` 元组，索引严格递增（故唯一）且每份签名都与该公钥参数/计数一致（字段类型错误抛 `TypeError`，结构约束违反抛 `ValueError`）；把同一公钥的多份签名打包成一份可**独立传输**的批次证明。批次包不存消息，本身不提供认证或加密
- `MerkleBatchProof.to_bytes()` / `MerkleBatchProof.from_bytes(data)` — 批次证明的版本化二进制编解码；编码确定、同值同字节。`from_bytes` 只接受 `bytes`/`bytearray`（其他类型抛 `TypeError`），解析时先恢复包内公钥、再以它约束每份签名；魔数、版本、长度/计数越界或为零、截断、尾随数据、嵌套编码非法、签名与公钥交叉不一致或索引非严格递增均抛 `ValueError`，不返回半有效对象
- `MerkleBatchProof.verify(messages)` — `messages` 须为与签名等长的元组，成员接受 `bytes`/`bytearray`/`str`；逐项等价于 `merkle_verify(message, signature, public_key)`，全部成功才返回 `True`；非元组、数量不符、非法消息成员或任一验签失败均返回 `False`
- `MerkleBatchProof.verify_bound(messages, *, public_key, indices=None)` — 在 `verify(messages)` 的逐项验证之外，把批次绑定到接收方预期公钥与可选叶选择；不新增对象、不改动批次证明 v1 线格式，不生成密钥、不取随机数、不保存状态。`public_key` 须为 `MerklePublicKey`（错型抛 `TypeError`），并与包内公钥的 `w`、`height`、`root` 逐值相等；`indices=None` 不限制叶选择；显式 `indices` 须为元组（非元组或含非整数成员抛 `TypeError`），与消息等长、成员为非布尔整数、严格递增，并与各签名的 `index` 按位置完全相同；布尔成员、重复、乱序、越界、数量不符，包内公钥非 `MerklePublicKey`、签名为空或非 `MerkleSignature` 元组（字段缺失、错型、空或非元组，含绕过冻结构造器形成的畸形结构），以及消息、签名、公钥值不匹配均返回 `False` 而不抛异常；仅外部参数 `public_key` 错型或 `indices` 非元组/含非整数成员按旧约抛 `TypeError`
- `multiproof_encode(public_key, signatures)` — 顶层函数，把同一 `MerklePublicKey` 的多份 `MerkleSignature` 压成一份去重认证路径的确定性证明 `bytes`；不引入新对象、不改动任何旧接口与格式。`public_key` 须为 `MerklePublicKey`，`signatures` 须为非空的 `MerkleSignature` 元组（类型错抛 `TypeError`）；空集合、索引非严格递增、签名不被公钥约束（`w`/树高/索引越界/W-OTS 元素数或路径数不符、元素畸形）或同一坐标节点冲突抛 `ValueError`
- `multiproof_verify(messages, data)` — 顶层验证；`data` 只接受 `bytes`/`bytearray`，`messages` 须为与叶数等长的元组，成员沿用现有消息规则（`bytes`/`bytearray`/`str`）。按各消息恢复 W-OTS 公钥，沿用现有叶哈希与内部节点字节规则逐层合并，必须得到包内公钥根、且每个证明节点恰好使用一次；消息不符，或 `data`/`messages` 类型或数量错、魔数/版本/长度/计数错、截断、尾随、叶块乱序或重复、节点缺失/多余/重复/乱序/坐标非规范，一律返回 `False`

构造细节：叶哈希为 `SHA256(b"pqattest/leaf" + bytes([w]) + 公钥元素串)`；内部节点为 `SHA256(b"pqattest/node" + 左 + 右)`；所有节点 32 字节。

检查点 v1 二进制格式：8 字节魔数 `b"PQAMSCP\0"`；各 1 字节的版本（1）、`w`、`height`；2 字节大端 `next_index`；4 字节大端元素总数（必须等于 `2**height` 乘 `w` 对应的链数）；32 字节 Merkle 根；随后按叶、链顺序排列的全部 W-OTS 私钥元素（每个 32 字节）；最后为此前全部内容的 SHA-256。

W-OTS 一次性签名器检查点 v1 二进制格式（`WOTSOneTimeSigner.checkpoint`）：8 字节魔数 `b"PQAWCP\0\0"`；各 1 字节的版本（1）、`w`、`used`（仅 0 或 1）；2 字节大端私钥元素数（由 `w` 严格限定：`w=4` 为 67、`w=8` 为 34）；随后按原链序排列的全部 32 字节私钥元素；最后为此前全部内容的 SHA-256。总长度为 `13 + 元素数 × 32 + 32` 字节（w=4 时 2189 字节，w=8 时 1133 字节）。

Lamport 密钥与签名 v1 线格式（`PrivateKey.to_bytes` / `PublicKey.to_bytes` / `lamport_signature_to_bytes`）：三种格式结构相同——8 字节魔数（私钥 `b"PQALPRV\0"`、公钥 `b"PQALPUB\0"`、签名 `b"PQALSIG\0"`）；1 字节版本（1）；两个 2 字节大端无符号整数依次为 `bits`（1..256）与元素计数（密钥严格等于 `2 * bits`，签名严格等于 `bits`）；随后按原序拼接全部 32 字节元素。总长度为 `13 + 元素计数 × 32` 字节（默认 bits=256 时：密钥 16397 字节，签名 8205 字节）。编码确定、同值同字节；私钥编码含明文秘密。

Lamport 一次性签名器检查点 v1 二进制格式（`OneTimeSigner.checkpoint`）：8 字节魔数 `b"PQALCP\0\0"`；各 1 字节的版本（1）与 `used`（仅 0 或 1）；4 字节大端无符号嵌套私钥编码长度；随后是完整的 `PrivateKey.to_bytes()` 输出（即上面的 Lamport 私钥 v1 编码原样嵌入）；最后为此前全部内容的 SHA-256。总长度为 `14 + 私钥编码长度 + 32` 字节（默认 bits=256 时 16443 字节）。编码确定、同状态同字节；检查点含明文秘密，末尾校验值只发现意外损坏，不提供认证或加密。

W-OTS 密钥与签名 v1 线格式（`WOTSPrivateKey.to_bytes` / `WOTSPublicKey.to_bytes` / `wots_signature_to_bytes`）：三种格式结构相同——8 字节魔数（私钥 `b"PQAWPRV\0"`、公钥 `b"PQAWPUB\0"`、签名 `b"PQAWSIG\0"`）；各 1 字节的版本（1）与 `w`；2 字节大端元素数（由 `w` 严格限定：`w=4` 为 67、`w=8` 为 34）；随后按原序拼接全部 32 字节元素。总长度为 `12 + 元素数 × 32` 字节（w=4 时 2156 字节，w=8 时 1100 字节）。编码确定、同值同字节；私钥编码含明文秘密。

公钥 v1 线格式（`MerklePublicKey.to_bytes`，固定 43 字节）：8 字节魔数 `b"PQAMPK\0\0"`；各 1 字节的版本（1）、`w`、`height`；32 字节 Merkle 根。

签名 v1 线格式（`MerkleSignature.to_bytes(public_key)`）：8 字节魔数 `b"PQAMSIG\0"`；各 1 字节的版本（1）、`w`、`height`；2 字节大端叶索引；2 字节大端 W-OTS 元素数（等于 `w` 对应的链数）；1 字节路径数（等于树高）；随后依次是全部 W-OTS 签名元素和**自叶层向根层**排列的认证路径节点，每项 32 字节。总长度为 `16 + (元素数 + 树高) × 32` 字节。

证明包 v1 线格式（`MerkleProof.to_bytes`）：8 字节魔数 `b"PQAMPRF\0"`；1 字节版本（1）；4 字节大端公钥长度；4 字节大端签名长度；随后先拼接完整的公钥 v1 编码，再拼接以该公钥约束的签名 v1 编码（即上面两种既有编码原样串联，证明包不另造单体编码）。长度字段必须与各自编码的实际内容一致；解析顺序固定为先公钥、后签名，签名始终由同包内刚恢复的公钥约束。总长度为 `17 + 公钥编码长度 + 签名编码长度` 字节。

批次证明 v1 线格式（`MerkleBatchProof.to_bytes`）：8 字节魔数 `b"PQAMBAT\0"`；1 字节版本（1）；4 字节大端公钥长度；2 字节大端签名数（至少 1）；完整的公钥 v1 编码；随后按元组顺序，每份签名先写 4 字节大端长度、再写以该公钥约束的既有签名 v1 编码。总长度为 `15 + 公钥编码长度 + Σ(4 + 各签名编码长度)` 字节。

多签名证明 v1 线格式（`multiproof_encode`）：8 字节魔数 `b"PQAMMUL\0"`；1 字节版本（1）；4 字节大端公钥长度；各 2 字节大端的叶数与（去重后）兄弟节点数；完整的公钥 v1 编码；随后每叶按索引升序依次写 2 字节大端叶索引、2 字节大端 W-OTS 元素数（等于该公钥 `w` 对应的链数）与保持原序的 32 字节元素（不含旧签名里的认证路径）；最后是规范兄弟节点，各编码为 1 字节层号、2 字节大端层内索引与 32 字节哈希。规范节点集的构造从第 0 层的叶索引集合开始：每层收录当前集合中「兄弟不在当前集合」的索引之兄弟坐标 `(level, index^1)`，再把全部索引右移一位并去重进入下一层；节点按层、层内索引递增排列。总长度为 `17 + 公钥编码长度 + 叶数 × (4 + 元素数 × 32) + 节点数 × 35` 字节。与批次证明相比，被多片叶子共享的兄弟节点只出现一次。

```python
from pqattest import MerkleProof, MerklePublicKey, MerkleSignature, MerkleSigner

signer = MerkleSigner(height=4, w=4)
signature = signer.sign(b"position claim")
proof = MerkleProof(public_key=signer.public_key, signature=signature)
blob = proof.to_bytes()                       # 可独立传输的单块字节
received = MerkleProof.from_bytes(blob)       # 接收方无需任何旁带参数
assert received == proof
assert received.verify(b"position claim")
assert not received.verify(b"other claim")
```

```python
signer = MerkleSigner(height=4, w=8)
signature = signer.sign(b"position claim")
key_blob = signer.public_key.to_bytes()
sig_blob = signature.to_bytes(signer.public_key)
key = MerklePublicKey.from_bytes(key_blob)
restored = MerkleSignature.from_bytes(sig_blob, key)
assert restored == signature
assert merkle_verify(b"position claim", restored, key)
```

```python
from pqattest import multiproof_encode, multiproof_verify

signer = MerkleSigner(height=4, w=4)
messages = (b"claim 0", b"claim 1", b"claim 2")
signatures = tuple(signer.sign(message) for message in messages)
blob = multiproof_encode(signer.public_key, signatures)   # 共享兄弟节点只存一次
assert multiproof_verify(messages, blob)
assert not multiproof_verify((b"claim 0", b"claim 1", b"other"), blob)
```

**编解码须知**：三种编码（公钥、签名、证明包）都是纯序列化——只含结构校验（魔数、版本、计数、长度），**不提供认证或加密**，任何人都能改写字节；需要完整性或来源保证时须由调用方在传输/存储层自行解决（公钥与签名本身公开，通常只需防篡改）。证明包只做参数与计数层面的交叉约束：参数一致的异源公钥/签名组合在结构上合法，必须靠 `verify(message)` 才能识别——证明包不存消息，无从自行判断签名是否出自该公钥。未来格式变更会启用新的版本号（证明包与内层两种编码各自独立版本化），解析器对未知版本一律抛 `ValueError`，不会静默按 v1 解释；新版本若改变内层编码，须在证明包新的版本号下整体规定其组合方式，v1 解析器永远只接受 v1 内层编码。

```python
signer = MerkleSigner(height=4, w=4)
blob = signer.checkpoint()                 # 含全部私钥，须当秘密保管
restored = MerkleSigner.from_checkpoint(blob)
assert restored.public_key == signer.public_key
```

```python
from pqattest import WOTSOneTimeSigner, wots_keygen

one_time = WOTSOneTimeSigner(wots_keygen()[0])
blob = one_time.checkpoint()               # 未用时 used=0，仍可签一次
restored = WOTSOneTimeSigner.from_checkpoint(blob)
assert restored.public_key == one_time.public_key
restored.sign(b"position claim")           # 成功
assert WOTSOneTimeSigner.from_checkpoint(
    restored.checkpoint()
).used                                      # 已用状态恢复后 used=True
```

`OneTimeSigner`（Lamport）用法相同：

```python
from pqattest import OneTimeSigner, keygen

one_time = OneTimeSigner(keygen()[0])
blob = one_time.checkpoint()               # 含明文私钥，须当秘密保管
restored = OneTimeSigner.from_checkpoint(blob)
assert restored.public_key == one_time.public_key
restored.sign(b"position claim")           # 成功；此后任何 sign 都抛 KeyExhaustedError
```

**检查点安全须知**：检查点明文包含私钥（Merkle 为整棵树的全部 W-OTS 私钥），末尾的 SHA-256 校验值只能发现意外损坏，**不提供认证或加密**——任何拿到检查点的人都能伪造签名。调用方必须把它当私钥一样安全存储，并在每次成功签名后**原子地**持久化新检查点（如写临时文件再 rename）；复制检查点或在不同进程间共享会让同一把一次性私钥被多次使用，风险由调用方承担。回滚到旧检查点会让状态倒退：对 `OneTimeSigner`/`WOTSOneTimeSigner` 是已用标志复位、对 `MerkleSigner` 是 `next_index` 倒退、已消耗的叶子被再次分配，二者都造成一次性密钥重用，签名即可被伪造。

### 带密钥的认证封装 `auth_wrap` / `auth_unwrap`

三类现有明文检查点（Lamport、W-OTS、Merkle）可再套一层**带密钥的认证封装**，用来发现没有共享密钥者的篡改：

- `auth_wrap(checkpoint, *, scheme, key)` — 关键字参数 `scheme` 仅取 `"lamport"`/`"wots"`/`"merkle"`（依次编码为 1/2/3），`checkpoint` 与 `key` 只接受非空的 `bytes`/`bytearray`（`key` 不得为空字节串）；返回确定编码的 `bytes`。封装前按既有检查点魔数核对方案（Lamport `b"PQALCP\0\0"`、W-OTS `b"PQAWCP\0\0"`、Merkle `b"PQAMSCP\0"`），不符抛 `ValueError`
- `auth_unwrap(data, *, key, expect=None)` — 验证封装并返回 `(scheme, payload)`：方案名字符串与传入 `auth_wrap` 的原检查点字节（`bytes`，可直接交给对应的 `from_checkpoint`）。`expect` 给出时必须与封装中的方案一致，否则抛 `ValueError`
- 参数类型错误抛 `TypeError`；空 `key`、未知或与 `expect` 不符的方案、坏封装魔数/版本/方案标识/长度字段、截断、尾随数据、载荷魔数与标识不符或 HMAC 标签错误，一律抛 `ValueError`。标签用 `hmac.compare_digest` 常量时间比较，**先验标签、后核对载荷魔数**，任何字段都不会在标签验证通过前被信任

v1 封装格式依次为：8 字节魔数 `b"PQAAUTH\0"`；1 字节版本（1）；1 字节方案标识（lamport=1、wots=2、merkle=3）；4 字节大端载荷长度；原样嵌入的检查点载荷；末尾 32 字节 `HMAC-SHA-256(key, 此前全部字节)`。总长度为 `14 + 载荷长度 + 32` 字节。编码确定、同输入同字节。

```python
from pqattest import MerkleSigner, auth_wrap, auth_unwrap

signer = MerkleSigner(height=4, w=4)
blob = auth_wrap(signer.checkpoint(), scheme="merkle", key=b"shared-secret")
scheme, checkpoint = auth_unwrap(blob, key=b"shared-secret", expect="merkle")
assert scheme == "merkle"
restored = MerkleSigner.from_checkpoint(checkpoint)
```

**封装安全边界**：HMAC 只提供**来源/完整性认证**，**不加密**——载荷依旧是明文，任何拿到封装的人都能读到检查点内容；它也**不防复制、重放或回滚**：旧的合法封装随时可以重新提交，`auth_unwrap` 无法判断新旧。需要防回滚/重放时，调用方仍须自行加入单调序号或受信存储，并把封装连同明文检查点一起当秘密保管。旧的明文 `checkpoint()`/`from_checkpoint()` 接口保持不变，封装是可选的外层。

### 带代次的认证封装 `auth_state_wrap` / `auth_state_unwrap`

v1 封装没有任何新旧概念；v2 封装在共享同一魔数、同一套 v1 参数约束与认证方式之外，额外绑定一个 64 位无符号**代次（generation）**，解封时可按调用方提供的下限拒绝旧封装：

- `auth_state_wrap(checkpoint, *, scheme, key, generation)` — 参数与 `auth_wrap` 完全一致（`checkpoint`/`key` 为非空 `bytes`/`bytearray`，`scheme` 仅取 `"lamport"`/`"wots"`/`"merkle"`，封装前按检查点魔数核对方案），额外的关键字参数 `generation` 必须是 `0..2**64-1` 的**非布尔整数**；类型错抛 `TypeError`，越界抛 `ValueError`。返回确定编码的 `bytes`
- `auth_state_unwrap(data, *, key, expect=None, min_generation=None)` — 验证 v2 封装并返回 `(scheme, generation, payload)`：`generation` 为封装中的非负 `int`，`payload` 为传入 `auth_state_wrap` 的原检查点字节（`bytes`，可直接交给对应的 `from_checkpoint`）。`expect` 语义与 `auth_unwrap` 相同；`min_generation` 为 `None`（缺省，不检查）或 `0..2**64-1` 的非布尔整数，低于下限的代次一律拒绝
- 参数类型错误抛 `TypeError`（非字节的 `data`/`key`、非字符串 `expect`、非整数或布尔的 `generation`/`min_generation`）；空 `key`、未知 `expect`、代次参数超出 uint64、坏封装魔数、版本不为 2（v1 封装也算版本不符）、未知方案标识、长度字段不符、截断、尾随数据、载荷魔数与标识不符、与 `expect` 不符、HMAC 标签错误或代次低于 `min_generation`，一律抛 `ValueError`

v2 封装格式依次为：8 字节魔数 `b"PQAAUTH\0"`；1 字节版本（2）；1 字节方案标识（lamport=1、wots=2、merkle=3）；**8 字节大端 `generation`**；4 字节大端载荷长度；原样嵌入的检查点载荷；末尾 32 字节 `HMAC-SHA-256(key, 此前全部字节)`。总长度为 `22 + 载荷长度 + 32` 字节。编码确定、同输入同字节。解封**先用 `hmac.compare_digest` 验证标签**，此后才信任任何字段；标签通过后再核对载荷魔数与方案（含 `expect`），**最后**应用代次下限。v1 与 v2 仅以版本字节区分：`auth_unwrap` 只接受版本 1、`auth_state_unwrap` 只接受版本 2，互不解析对方的封装；旧的 v1 封装与三类检查点的字节格式保持逐字节不变。

```python
from pqattest import MerkleSigner, auth_state_wrap, auth_state_unwrap

signer = MerkleSigner(height=4, w=4)
blob = auth_state_wrap(
    signer.checkpoint(), scheme="merkle", key=b"shared-secret", generation=7
)
scheme, generation, checkpoint = auth_state_unwrap(
    blob, key=b"shared-secret", expect="merkle", min_generation=7
)
assert scheme == "merkle" and generation == 7
restored = MerkleSigner.from_checkpoint(checkpoint)

# 等价的一步认证恢复：v2 验签 + merkle 方案 + 代次下限 + v1 检查点恢复
restored, generation = MerkleSigner.from_auth_state(
    blob, key=b"shared-secret", min_generation=7
)

auth_state_unwrap(blob, key=b"shared-secret", min_generation=8)  # ValueError：回滚
MerkleSigner.from_auth_state(blob, key=b"shared-secret", min_generation=8)  # 同上
```

**代次安全边界**：下限 `min_generation` **不由封装携带**，必须保存在调用方的外部可信存储中（随每次接受的新一代次原子推进），并与封装/检查点分开保管。代次只对「检查点回滚、但可信下限没有一并回退」的情形有效：攻击者若能把检查点和可信下限**一起**回滚，或者在**同一代次内**重放一份合法封装，HMAC 依然有效、无从检测。与 v1 相同，v2 封装**不加密**，载荷是明文，也不防复制；须把封装连同明文检查点一起当秘密保管。

### 带外部单调认领的认证恢复

可信高水位（代次下限）通常由外部单调计数器/认领存储负责推进；为了让「恢复签名器」与「认领代次」不可分割，Lamport 与 W-OTS 两类一次性签名器各自提供带认领的一步恢复，成对同代恢复则用 `restore_ots_pair`——认证与检查点恢复全部成功后才**恰好调用一次**认领回调，失败路径绝不调用，因而不会只认领一侧：

- `OneTimeSigner.from_auth_state(data, *, key, min_generation=None, claim)` / `WOTSOneTimeSigner.from_auth_state(data, *, key, min_generation=None, claim)` — 参数规则与 `MerkleSigner.from_auth_state` 相同（`data`/`key` 仅收非空 `bytes`/`bytearray`，`min_generation` 为 `None` 或非布尔 uint64），额外的必给关键字参数 `claim` **必须可调用**（否则 `TypeError`）。封装方案分别固定为 `"lamport"`/`"wots"`。返回 `(signer, generation)`：恢复出的签名器与封装代次。全部校验通过、检查点恢复完成后，`claim` 被**恰好调用一次**，入参单项分别为 `("lamport", g)` 与 `("wots", g)`；仅当回调返回值**按身份 `is True`** 时成功（`1`、非空串等真值不算，抛 `ValueError`）；回调自身抛出的任何异常原样透传
- `restore_ots_pair(a, b, *, key, floor=None, claim)` — 成对恢复。`a` 必须是 `"lamport"` 封装、`b` 必须是 `"wots"` 封装（位置固定，互换即方案不符），两者**必须同代**，`floor` 给定时两侧代次都不得低于它。返回 `((l, w), g)`：`l` 为 Lamport `OneTimeSigner`、`w` 为 `WOTSOneTimeSigner`、`g` 为共同代次。两侧 HMAC、方案、载荷魔数、同代与下限检查、两个检查点恢复**全部成功后**，`claim` 才被恰好调用一次，入参为成对令牌 `(("lamport", g), ("wots", g))`；成功条件与异常语义同单项
- `sign_merkle_auth_state(data, message, *, key, min_generation=None, claim) -> (signature, envelope, generation)` — **无隐藏状态**的「认证恢复 + 单条签名 + 下一代封装」转换：`data` 为 `"merkle"` 的 v2 封装（`bytes`/`bytearray`），先按既有 v2 规则用 `hmac.compare_digest` 验 HMAC、固定方案、应用代次下限并恢复原样 v1 载荷，再用恢复签名器的**当前最小叶**对 `message`（沿用 `bytes`/`bytearray`/`str` 规则）签一条，最后把推进后（`next_index` 加一）的 v1 检查点以 `scheme="merkle"`、原 `key` 与 **g+1** 代次封装。返回的 `signature` 与同状态下 `MerkleSigner.sign` 逐值相同；`envelope` 与对推进后检查点直接调用 `auth_state_wrap` **逐字节相同**；`generation` 为 `g+1`。不修改任何对象、不保留库内状态、不取随机数、不新增线格式，同一封装重复调用得到逐字节相同的结果（叶子是否真正作废由调用方在认领后只保存新封装来保证）。入参 `g` 必须小于 `2**64-1`，否则抛 `ValueError`；恢复出的签名器无叶可用时抛 `KeyExhaustedError`。**全部输出生成后**才以唯一入参 `(("merkle", g), ("merkle", g+1))` 恰好调用一次 `claim`，仅返回值 `is True` 时成功（否则抛 `ValueError`），回调异常原样透传；封装失败、认证失败、代次低于下限、代次触顶、叶子用尽或认领拒绝等任何先前失败都**不调用** `claim` 且无部分返回。错型（`data`/`key` 非 `bytes`/`bytearray`、`min_generation` 为布尔或非整数、`claim` 不可调用）抛 `TypeError`，空 key 等抛 `ValueError`
- `sign_merkle_auth_state_batch(data, messages, *, key, min_generation=None, claim) -> (signatures, envelope, generation)` — **无隐藏状态**的「认证恢复 + 连续批量签名 + 下一代封装」转换，合并 v2 恢复与 `sign_batch` 语义：`data` 为 `"merkle"` 的 v2 封装（`bytes`/`bytearray`），先按既有 v2 规则用 `hmac.compare_digest` 验 HMAC、固定方案、应用代次下限并恢复原样 v1 载荷，再按 `MerkleSigner.sign_batch` 的既有规则从恢复签名器的**当前最小叶**起对 `messages` **连续**签名（一次临界区、叶索引严格递增），最后把推进后（`next_index` 加批长）的 v1 检查点以 `scheme="merkle"`、原 `key` 与 **g+1** 代次封装。`messages` 必须是**非空元组**，成员沿用 `bytes`/`bytearray`/`str`（UTF-8）规则；`data`/`key` 仅收 `bytes`/`bytearray` 且 `key` 非空；`min_generation` 为 `None` 或非布尔 uint64；`claim` 须可调用。返回 `(signatures, envelope, generation)`：`signatures` 为每消息一份 `MerkleSignature` 的元组（同序、索引连续，与同状态下 `sign_batch` 逐值相同），`envelope` 与对批签后检查点直接调用 `auth_state_wrap` **逐字节相同**，`generation` 为 `g+1`。不修改任何对象、不保留库内状态、不取随机数、不新增线格式，同一输入重复调用逐字节相同。整批容量不足时抛 `KeyExhaustedError`；入参 `g` 必须小于 `2**64-1`（否则 `ValueError`）。**全部输出生成后**才以唯一入参 `(("merkle", g), ("merkle", g+1))` 恰好调用一次 `claim`，仅返回值 `is True` 时成功（否则抛 `ValueError`），回调异常原样透传；任何先前失败（含空批、空 key、认证失败、代次低于下限、代次触顶、容量不足、认领拒绝）都**不调用** `claim`、不推进且无部分返回。错型抛 `TypeError`，空批、空 key 或其他库内拒绝抛 `ValueError`
- `sign_multiproof_merkle_auth_state(data, messages, *, indices=None, key, min_generation=None, claim) -> (proof, envelope, generation)` — **无隐藏状态**的「认证恢复 + 批量签名 + 去重多证明 + 下一代封装」转换，是 `sign_merkle_auth_state_batch` 的多证明对应物：`data` 为 `"merkle"` 的 v2 封装（`bytes`/`bytearray`），先按既有 v2 规则用 `hmac.compare_digest` 验 HMAC、固定方案、应用代次下限并恢复原样 v1 载荷，再对 `messages` 逐条签名并把恢复公钥与签名交给 `multiproof_encode` 压成一份去重认证路径的证明，最后把签后的 v1 检查点以 `scheme="merkle"`、原 `key` 与 **g+1** 代次封装。`indices`/`key`/`min_generation`/`claim` 均为仅关键字参数，仅 `indices` 与 `min_generation` 有默认值（`None`）。`indices=None` 时叶子从恢复签名器的**当前最小叶**起**连续**分配（与 `sign_merkle_auth_state_batch` 相同）；显式 `indices` 必须为与 `messages` **等长**、**严格递增**的元组，成员为闭区间 `[恢复状态的当前 next_index, 末叶]` 内的**非布尔整数**，所选叶之间的间隙一并作废，签后 `next_index` 为末项加一。返回 `(proof, envelope, generation)`：`proof` 为 `bytes`，与「同状态签名后以恢复公钥调用 `multiproof_encode`」**逐字节相同**，且 `multiproof_verify(messages, proof)` 返回 `True`（沿用 v1 叶块与规范节点顺序）；`envelope` 与对签后检查点直接调用 `auth_state_wrap` **逐字节相同**；`generation` 为 `g+1`，状态只推进一代（与批长无关）。除 `indices` 外的输入、异常及认领规则与 `sign_merkle_auth_state_batch` 完全相同：`messages` 必须是**非空元组**，成员沿用 `bytes`/`bytearray`/`str`（UTF-8）规则；入参 `g` 必须小于 `2**64-1`（否则 `ValueError`）；`indices=None` 且剩余叶数装不下整批时抛 `KeyExhaustedError`。不修改任何对象、不保留库内状态、不取随机数、不新增线格式，同一输入重复调用逐字节相同。**全部输出生成后**才以唯一入参 `(("merkle", g), ("merkle", g+1))` 恰好调用一次 `claim`，仅返回值 `is True` 时成功（否则抛 `ValueError`），回调异常原样透传；任何先前失败都**不调用** `claim`、不推进且无部分返回。错型（`data`/`key` 非 `bytes`/`bytearray`、`messages` 非元组或成员类型非法、`indices` 非元组或成员非整数、下限为布尔/非整数、`claim` 不可调用）抛 `TypeError`，空批、空 key、`indices` 长度不符、布尔成员、非严格递增或越界等非法值抛 `ValueError`
- `advance_merkle_auth_state(data, next_index, *, key, min_generation=None, claim) -> ((before, after), envelope, generation)` — **无隐藏状态**的「认证恢复 + 作废叶子 + 下一代封装」转换，是 `MerkleSigner.advance_to_with_auth_state` 的无状态对应物：`data` 为 `"merkle"` 的 v2 封装（`bytes`/`bytearray`），先按既有 v2 规则用 `hmac.compare_digest` 验 HMAC、固定方案、应用代次下限并恢复原样 v1 载荷，再按 `MerkleSigner.advance_to` 的既有语义把恢复签名器的下一可用叶索引推进到 `next_index`（低于目标的叶子此后再不能签名），最后把推进后的 v1 检查点以 `scheme="merkle"`、原 `key` 与 **g+1** 代次封装。返回 `((before, after), envelope, generation)`：内层二元组为推进前后的原索引与目标，与同目标下 `advance_to` 的返回相同；`envelope` 与对推进后检查点直接调用 `auth_state_wrap` **逐字节相同**；`generation` 为 `g+1`。**等值推进合法**（`(x, x)`），即便封装的状态不变，仍产出下一代封装。`next_index` 须为闭区间 `[恢复状态的当前 next_index, 叶总数]` 内的非布尔整数；`data`/`key` 仅收 `bytes`/`bytearray` 且 `key` 非空；`min_generation` 为 `None` 或非布尔 uint64；`claim` 须可调用。不修改任何对象、不保留库内状态、不取随机数、不新增线格式，同一输入重复调用逐字节相同。倒退或超出叶总数抛 `ValueError`，入参 `g` 必须小于 `2**64-1`（否则 `ValueError`）。**全部输出生成后**才以唯一入参 `(("merkle", g), ("merkle", g+1))` 恰好调用一次 `claim`，仅返回值 `is True` 时成功（否则抛 `ValueError`），回调异常原样透传；任何先前失败（认证失败、代次低于下限、代次触顶、目标越界、检查点非法、认领拒绝）都**不调用** `claim`、不推进且无部分返回。错型（`data`/`key` 非 `bytes`/`bytearray`、目标或下限为布尔/非整数、`claim` 不可调用）抛 `TypeError`，空 key 等抛 `ValueError`
- `advance_and_sign_merkle_auth_state(data, next_index, message, *, key, min_generation=None, claim) -> ((before, target), signature, envelope, generation)` — **无隐藏状态**的「认证恢复 + 跳叶作废 + 目标叶单签 + 下一代封装」转换，合并 `advance_merkle_auth_state` 的跳叶与 `sign_merkle_auth_state` 的单签：`data` 为 `"merkle"` 的 v2 封装（`bytes`/`bytearray`），先按既有 v2 规则用 `hmac.compare_digest` 验 HMAC、固定方案、应用代次下限并恢复原样 v1 载荷，再把恢复签名器的下一可用叶索引推进到 `next_index`（低于目标的叶子此后再不能签名），用**目标叶**对 `message`（沿用 `bytes`/`bytearray`/`str` 规则）签一条，最后把 `next_index == target + 1` 的 v1 检查点以 `scheme="merkle"`、原 `key` 与 **g+1** 代次封装。返回 `((before, target), signature, envelope, generation)`：内层二元组与同目标下 `advance_to` 的返回相同（等值目标合法，返回 `(x, x)`）；`signature` 为目标叶上的 `MerkleSignature`，与「同状态先 `advance_to(target)` 再 `sign(message)`」逐值相同；`envelope` 与对签后检查点直接调用 `auth_state_wrap` **逐字节相同**；`generation` 为 `g+1`。`next_index` 须为闭区间 `[恢复状态的当前 next_index, 叶总数 - 1]` 内的非布尔整数——与 `advance_merkle_auth_state` 不同，叶总数本身**不是**合法目标（目标叶必须仍可签）；其余参数规则与 `sign_merkle_auth_state` 相同。不修改任何对象、不保留库内状态、不取随机数、不新增线格式，同一输入重复调用逐字节相同。倒退或越过最后一片叶抛 `ValueError`，恢复状态叶已用尽抛 `KeyExhaustedError`，入参 `g` 必须小于 `2**64-1`（否则 `ValueError`）。**全部输出生成后**才以唯一入参 `(("merkle", g), ("merkle", g+1))` 恰好调用一次 `claim`，仅返回值 `is True` 时成功（否则抛 `ValueError`），回调异常原样透传；任何先前失败（认证失败、代次低于下限、代次触顶、目标越界、叶子用尽、检查点非法、认领拒绝）都**不调用** `claim`、不推进且无部分返回。错型（`data`/`key` 非 `bytes`/`bytearray`、目标或下限为布尔/非整数、`message` 类型非法、`claim` 不可调用）抛 `TypeError`，空 key 等抛 `ValueError`
- `advance_and_sign_merkle_auth_state_batch(data, next_index, messages, *, key, min_generation=None, claim) -> ((before, target), signatures, envelope, generation)` — **无隐藏状态**的「认证恢复 + 跳叶作废 + 自目标叶起连续批量签名 + 下一代封装」转换，是 `advance_and_sign_merkle_auth_state` 的批量对应物：`data` 为 `"merkle"` 的 v2 封装（`bytes`/`bytearray`），先按既有 v2 规则用 `hmac.compare_digest` 验 HMAC、固定方案、应用代次下限并恢复原样 v1 载荷，再按 `MerkleSigner.advance_to` 的既有语义把恢复签名器的下一可用叶索引推进到 `next_index`，随后按 `MerkleSigner.sign_batch` 的既有规则从**目标叶**起对 `messages` **连续**签名（一次临界区、叶索引自 `target` 起严格递增），最后把 `next_index == target + len(messages)` 的 v1 检查点以 `scheme="merkle"`、原 `key` 与 **g+1** 代次封装。`messages` 必须是**非空元组**，成员沿用 `bytes`/`bytearray`/`str`（UTF-8）规则。返回 `((before, target), signatures, envelope, generation)`：内层二元组与同目标下 `advance_to` 的返回相同（等值目标合法，返回 `(x, x)`）；`signatures` 为每消息一份 `MerkleSignature` 的元组（同序、索引自 `target` 连续），与「同状态先 `advance_to(target)` 再 `sign_batch(messages)`」**逐值相同**；`envelope` 与对批签后检查点直接调用 `auth_state_wrap` **逐字节相同**；`generation` 为 `g+1`，状态只推进一代（与批长无关）。`next_index` 须为闭区间 `[恢复状态的当前 next_index, 叶总数 - 1]` 内的非布尔整数（叶总数本身**不是**合法目标，目标叶必须仍可签）；其余参数规则与 `sign_merkle_auth_state_batch` 相同。不修改任何对象、不保留库内状态、不取随机数、不新增线格式，同一输入重复调用逐字节相同。倒退或越过最后一片叶、空批、入参 `g` 触顶（须小于 `2**64-1`）抛 `ValueError`；目标叶可签但整批超出剩余叶数时抛 `KeyExhaustedError`。**全部输出生成后**才以唯一入参 `(("merkle", g), ("merkle", g+1))` 恰好调用一次 `claim`，仅返回值 `is True` 时成功（否则抛 `ValueError`），回调异常原样透传；任何先前失败（含错型、空批、空 key、认证失败、代次低于下限、代次触顶、目标越界、容量不足、检查点非法、认领拒绝）都**不调用** `claim`、不推进且无部分返回。错型（`data`/`key` 非 `bytes`/`bytearray`、目标或下限为布尔/非整数、`messages` 非元组或成员类型非法、`claim` 不可调用）抛 `TypeError`，空批、空 key 或其他库内拒绝抛 `ValueError`
- `advance_and_multiproof_merkle_auth_state(data, next_index, messages, *, key, min_generation=None, claim) -> ((before, target), proof, envelope, generation)` — **无隐藏状态**的「认证恢复 + 跳叶作废 + 自目标叶起连续批量签名 + 去重多证明 + 下一代封装」转换，是 `advance_and_sign_merkle_auth_state_batch` 的多证明对应物：`data` 为 `"merkle"` 的 v2 封装（`bytes`/`bytearray`），先按既有 v2 规则用 `hmac.compare_digest` 验 HMAC、固定方案、应用代次下限并恢复原样 v1 载荷，再按 `MerkleSigner.advance_to` 的既有语义把恢复签名器的下一可用叶索引推进到 `next_index`，随后按 `MerkleSigner.sign_batch` 的既有规则从**目标叶**起对 `messages` **连续**签名（一次临界区、叶索引自 `target` 起严格递增），把恢复公钥与本批签名交给 `multiproof_encode` 压成一份去重认证路径的证明，最后把 `next_index == target + len(messages)` 的 v1 检查点以 `scheme="merkle"`、原 `key` 与 **g+1** 代次封装。`messages` 必须是**非空元组**，成员沿用 `bytes`/`bytearray`/`str`（UTF-8）规则；`next_index` 须为闭区间 `[恢复状态的当前 next_index, 叶总数 - 1]` 内的非布尔整数（叶总数本身**不是**合法目标，目标叶必须仍可签）；其余参数规则与 `advance_and_sign_merkle_auth_state_batch` 相同。返回 `((before, target), proof, envelope, generation)`：内层二元组与同目标下 `advance_to` 的返回相同（等值目标合法，返回 `(x, x)`）；`proof` 为 `bytes`，与「同状态先 `advance_to(target)` 再 `sign_batch(messages)`、再以恢复公钥调用 `multiproof_encode`」**逐字节相同**，且 `multiproof_verify(messages, proof)` 返回 `True`；`envelope` 与对批签后检查点直接调用 `auth_state_wrap` **逐字节相同**；`generation` 为 `g+1`，状态只推进一代（与批长无关）。不修改任何对象、不保留库内状态、不取随机数、不新增线格式，同一输入重复调用逐字节相同。倒退或越过最后一片叶、空批、入参 `g` 触顶（须小于 `2**64-1`）抛 `ValueError`；目标叶可签但整批超出剩余叶数时抛 `KeyExhaustedError`。**全部输出生成后**才以唯一入参 `(("merkle", g), ("merkle", g+1))` 恰好调用一次 `claim`，仅返回值 `is True` 时成功（否则抛 `ValueError`），回调异常原样透传；任何先前失败（含错型、空批、空 key、认证失败、代次低于下限、代次触顶、目标越界、容量不足、检查点非法、认领拒绝）都**不调用** `claim`、不推进且无部分返回。错型（`data`/`key` 非 `bytes`/`bytearray`、目标或下限为布尔/非整数、`messages` 非元组或成员类型非法、`claim` 不可调用）抛 `TypeError`，空批、空 key 或其他库内拒绝抛 `ValueError`

处理顺序固定：先以 `hmac.compare_digest` 验两侧 HMAC，再核对固定方案标识、载荷魔数与（成对的）同代/代次下限，最后恢复 v1 检查点；只有这一切都成功才调用一次 `claim` 并返回。因此任何 `ValueError`（空 `key`、坏标签/坏封装、v1 封装、方案不符、载荷魔数不符、代次低于下限、成对代次不一致、检查点非法，或认领未返回 `True`）发生时，回调**从未被调用**，调用方不可能认领一个没有成功恢复的状态（也不可能只认领成对中的一侧）。错型（非字节数据/密钥、非可调用 `claim`、布尔或非整数下限）抛 `TypeError`；不新增线格式、不使用随机数、不引入任何库内状态。

```python
from pqattest import (
    OneTimeSigner, WOTSOneTimeSigner, restore_ots_pair,
    keygen, wots_keygen, auth_state_wrap,
)

key = b"shared-secret"
state = {"high_water": 6}  # 由外部可信单调存储维护

def claim_single(token):
    scheme, generation = token           # 如 ("lamport", 7)
    if generation < state["high_water"]:
        return False                     # 过期代次：拒绝，恢复抛 ValueError
    state["high_water"] = generation + 1  # 仅在此时原子推进
    return True

lamport = OneTimeSigner(keygen()[0])
blob = auth_state_wrap(lamport.checkpoint(), scheme="lamport",
                       key=key, generation=7)
restored, generation = OneTimeSigner.from_auth_state(
    blob, key=key, min_generation=state["high_water"], claim=claim_single
)

# 两类一次性密钥同代成对恢复：claim 只会被调用一次，且只在两侧都恢复成功后
l = OneTimeSigner(keygen()[0])
w = WOTSOneTimeSigner(wots_keygen()[0])
blob_a = auth_state_wrap(l.checkpoint(), scheme="lamport", key=key, generation=7)
blob_b = auth_state_wrap(w.checkpoint(), scheme="wots", key=key, generation=7)

def claim_pair(token):
    (lamport_claim, wots_claim) = token     # (("lamport", 7), ("wots", 7))
    if lamport_claim[1] != wots_claim[1]:   # 同代（恢复时已强制，此处再确认）
        return False
    if lamport_claim[1] < state["high_water"]:
        return False                        # 回滚：拒绝，恢复抛 ValueError
    state["high_water"] = lamport_claim[1] + 1  # 仅在此时原子推进一次
    return True

(lamport_signer, wots_signer), generation = restore_ots_pair(
    blob_a, blob_b, key=key, floor=state["high_water"], claim=claim_pair,
)
```

无状态 Merkle 转换 `sign_merkle_auth_state` 则把「恢复」换成「恢复并签一条」：输入当前封装，输出签名、推进一代的新封装与 `g+1`，认领令牌同时携带新旧两个代次，调用方可在一次原子认领里核对 `g+1 == g + 1` 并把高水位推进到 `g+1`；认领失败时调用方绝不保存新封装，下一次仍可用旧封装重试，得到逐字节相同的结果：

```python
from pqattest import MerkleSigner, sign_merkle_auth_state

signer = MerkleSigner(height=4, w=4)
blob = auth_state_wrap(signer.checkpoint(), scheme="merkle",
                       key=key, generation=7)

def claim_transition(token):
    (old, new) = token                    # (("merkle", 7), ("merkle", 8))
    if new[1] != old[1] + 1:
        return False                      # 代次必须恰好推进一格
    if old[1] < state["high_water"]:
        return False                      # 回滚：拒绝，调用抛 ValueError
    state["high_water"] = new[1]          # 仅在此时原子推进
    return True

signature, next_blob, generation = sign_merkle_auth_state(
    blob, b"position claim", key=key,
    min_generation=state["high_water"], claim=claim_transition,
)
assert generation == 8                    # 新封装绑定的代次
assert merkle_verify(b"position claim", signature, signer.public_key)
```

一次转换整批消息则用 `sign_merkle_auth_state_batch`：叶子从当前最小叶起**连续**分配，状态只推进一代（`g -> g+1`，与批长无关），认领令牌同样是一对 `(g, g+1)`，整批容量不足时不签名、不认领：

```python
from pqattest import sign_merkle_auth_state_batch

signatures, next_blob, generation = sign_merkle_auth_state_batch(
    blob, (b"claim 0", b"claim 1", b"claim 2"), key=key,
    min_generation=state["high_water"], claim=claim_transition,
)
assert tuple(sig.index for sig in signatures) == (0, 1, 2)
assert generation == 8
for message, signature in zip(("claim 0", "claim 1", "claim 2"), signatures):
    assert merkle_verify(message, signature, signer.public_key)
```

需要「跳过可能已暴露的叶子、并立刻用目标叶签一条」时，用 `advance_and_sign_merkle_auth_state` 把跳叶与单签合并进同一次无状态转换（目标必须仍可签，即 `next_index <= 叶总数 - 1`）：

```python
from pqattest import advance_and_sign_merkle_auth_state

(before, target), signature, next_blob, generation = (
    advance_and_sign_merkle_auth_state(
        blob, 5, b"position claim", key=key,
        min_generation=state["high_water"], claim=claim_transition,
    )
)
assert (before, target) == (0, 5)     # 叶子 0..4 已作废，签名用的是叶子 5
assert signature.index == 5
assert generation == 8
assert merkle_verify(b"position claim", signature, signer.public_key)
```

跳叶后还要一次转换整批消息时，用 `advance_and_sign_merkle_auth_state_batch`：签名自目标叶起**连续**分配，状态只推进一代（`g -> g+1`，与批长无关），叶子 0..4 同样先作废，剩余叶数装不下整批时不签名、不认领：

```python
from pqattest import advance_and_sign_merkle_auth_state_batch

(before, target), signatures, next_blob, generation = (
    advance_and_sign_merkle_auth_state_batch(
        blob, 5, (b"claim 5", b"claim 6", b"claim 7"), key=key,
        min_generation=state["high_water"], claim=claim_transition,
    )
)
assert (before, target) == (0, 5)     # 叶子 0..4 已作废
assert tuple(sig.index for sig in signatures) == (5, 6, 7)
assert generation == 8
for message, signature in zip(
    (b"claim 5", b"claim 6", b"claim 7"), signatures
):
    assert merkle_verify(message, signature, signer.public_key)
```

同样的跳叶批签，若接收方只要一份可独立传输的去重证明，用 `advance_and_multiproof_merkle_auth_state`：返回值里签名元组换成 `multiproof_encode` 的证明字节，共享兄弟节点只存一次，`multiproof_verify` 直接可验：

```python
from pqattest import advance_and_multiproof_merkle_auth_state, multiproof_verify

(before, target), proof, next_blob, generation = (
    advance_and_multiproof_merkle_auth_state(
        blob, 5, (b"claim 5", b"claim 6", b"claim 7"), key=key,
        min_generation=state["high_water"], claim=claim_transition,
    )
)
assert (before, target) == (0, 5)     # 叶子 0..4 已作废
assert generation == 8
assert multiproof_verify((b"claim 5", b"claim 6", b"claim 7"), proof)
```

玩具格基 KEM（教学用，**未审计，禁止生产**）：

- `ToyLatticePrivateKey(s)` / `ToyLatticePublicKey(t)` / `ToyLatticeCiphertext(u, tag)` — 三个冻结值对象，可位置构造、按值相等（含可哈希）。字段均为 `bytes`：`s`/`t`/`u` 必须是编码 `E` 值（恰好 16 字节、8 个 2 字节大端系数、每项在 `0..256`），`tag` 为任意 `bytes`。字段类型错误抛 `TypeError`，长度或系数越界抛 `ValueError`
- `ToyLatticePrivateKey.to_bytes()` / `ToyLatticePrivateKey.from_bytes(data)`、`ToyLatticePublicKey.to_bytes()` / `ToyLatticePublicKey.from_bytes(data)`、`ToyLatticeCiphertext.to_bytes()` / `ToyLatticeCiphertext.from_bytes(data)` — 三类对象的版本化二进制编解码；编码确定、同值同字节，往返后仍是可位置构造、按值相等的冻结对象。`from_bytes` 只接受 `bytes`/`bytearray`（其他类型抛 `TypeError`），魔数、版本、长度、截断、尾随数据或非法 `E` 系数抛 `ValueError`
- `toy_lattice_keygen(*, token_bytes=secrets.token_bytes)` — 返回 `(private_key, public_key)`；取 `x = token_bytes(8)`，令 `s = t = E(x)`（即私钥与公钥是同一个向量，毫无难度可求逆——这正是它只能教学的原因之一）。令牌源未返回恰好 8 字节抛 `ValueError`
- `toy_lattice_encapsulate(public_key, *, token_bytes=secrets.token_bytes)` — 返回 `(ciphertext, shared_key)`；取 `r = token_bytes(8)`、`u = E(r)`，用**解码后的向量**计算 `v = t·r mod 257`，共享密钥 `K = SHA256(b"K" + v₂)`，其中 `v₂` 为 `v` 的 2 字节大端编码；`tag = K`。`public_key` 类型错误抛 `TypeError`，令牌长度错误抛 `ValueError`
- `toy_lattice_decapsulate(ciphertext, private_key)` — 用解码向量计算 `v = s·u mod 257`，以相同方式推出 `K`，并以常量时间比较校验 `tag`；一致则返回 `K`，`tag` 不符（含长度不同）抛 `ValueError`。参数类型错误抛 `TypeError`

构造细节：向量维度固定为 8，系数环为模 257 整数；编码 `E` 把 8 个系数各编为 2 字节大端（系数允许 256，故 2 字节刚好容纳），共 16 字节。封装与解封装都先把 `E` 值解码回向量再做点积。密钥生成与封装的随机字节经注入的 `token_bytes` 取得（默认 `secrets.token_bytes`），仅被原样当作系数使用，因此系数实际落在 `0..255`；接收到的 `t`/`s`/`u` 则允许完整的 `0..256`。

线格式（v1）：公钥固定 25 字节——8 字节魔数 `b"PQALPK\0\0"`、1 字节版本（1）、16 字节 `t`；私钥同序，魔数为 `b"PQALSK\0\0"`，随后 16 字节 `s`，同样固定 25 字节。密文依次为 8 字节魔数 `b"PQALCT\0\0"`、1 字节版本（1）、16 字节 `u`、4 字节大端无符号 `tag` 长度、原样拼接的 `tag`；`tag` 可为任意 `bytes`，长度范围 `0..2**32-1`，故密文总长为 `29 + tag 长度` 字节。

```python
from pqattest import toy_lattice_keygen, toy_lattice_encapsulate, toy_lattice_decapsulate

private_key, public_key = toy_lattice_keygen()
ciphertext, enc_key = toy_lattice_encapsulate(public_key)
assert toy_lattice_decapsulate(ciphertext, private_key) == enc_key

# tag 是密钥确认：任何字节被改动都会在解封装时抛 ValueError
tampered = ToyLatticeCiphertext(ciphertext.u, b"\x00" * 32)
toy_lattice_decapsulate(tampered, private_key)   # ValueError
```

参数分析（纯函数，不生成密钥、不取随机数）：

- `Params` — 冻结的指标值对象，字段为 `scheme, w, height, capacity, elements, sig_bytes, path_bytes, steps`；`w`/`height` 对该方案无意义时为 `None`
- `profile(scheme, w=None, height=None)` — 返回某方案参数组合的 `Params`。`"lamport"` 不收 `w`/`height`；`"wots"` 只收 `w ∈ {4, 8}`；`"merkle"` 收 `w` 与 `height`（1 至 8 非布尔整数）。未知方案、参数缺失或多余一律抛 `ValueError`
- `recommend(capacity, prefer="size")` — 为期望的签名条数选 Merkle 配置并返回其 `Params`。`capacity` 限 1 至 256 的非布尔整数；`height` 取满足 `2**height >= capacity` 的最小值且至少为 1；`prefer="size"` 选 `w=8`（签名更短），`prefer="speed"` 选 `w=4`（链步更少、验签更快）。非法输入抛 `ValueError`
- `recommend_scheme(capacity, budgets, prefer="size")` — **跨 Lamport、W-OTS 与 Merkle 三方案的统一推荐入口**，返回所选配置的 `Params`。候选覆盖 `profile` 接受的全部方案与参数组合：容量为 1 时含 Lamport 与 W-OTS（`w=4/8`）两个一次性方案，以及 `w=4/8` × `height=1..8` 的全部 Merkle 配置；请求条数大于 1 时一次性方案只签一条，候选只剩 Merkle 配置。纯函数：不取随机数、不生成密钥、不改状态。前两参数无默认值；`capacity` 限 1 至 256 的非布尔整数；`budgets` 必须为**二元组**，依次为单签序列化尺寸（`Params.sig_bytes`）与验签链步上界（`Params.steps`）的含边界上限，口径与 `profile` 指标完全一致，每项为 `None`（不限）或正的非布尔整数，且至少一项非空；叶数不覆盖 `capacity` 或超出预算的候选一律排除。`prefer` 仅取 `"size"`（默认）或 `"speed"`：前者先最小化 `sig_bytes` 再看 `steps`，后者次序相反；两者决胜尾序相同，依次为容量余量（候选容量减请求条数）、方案名字典序、`w` 升序、`height` 升序，无该参数者（`None`）排在最前，取排序首项。校验次序固定为容量、预算、偏好：`budgets` 非元组抛 `TypeError`；容量为布尔、非整数或越界抛 `ValueError`；预算长度不符、成员为布尔/非正/非整数或两项全空同样抛 `ValueError`；偏好取值之外或无任何可行候选也抛 `ValueError` 且不返回结果。同一输入重复调用结果逐项相同
- `recommend_merkle_deployment(capacity, budgets, prefer="size")` — 在部署预算内选可行 Merkle 参数，返回 `MerkleStorageProfile`。纯函数：不取随机数、不生成密钥、不改状态。`capacity` 限 1 至 256 的非布尔整数；`budgets` 必须为四元组，按顺序分别为检查点字节（对应 `checkpoint_bytes`）、单签线长（`signature_wire_bytes`）、独立证明线长（`proof_wire_bytes`）、验签链步数（`profile("merkle", ...).steps`）的上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 全部候选：叶数须覆盖 `capacity`，字节上限按 `merkle_storage_profile` 字段比较，步数上限按 `profile` 返回的 `steps` 比较。`size` 依次最小化签名线长、证明线长、检查点、步数、叶数、`w`、`height`；`speed` 先最小化步数，再沿用前述其余顺序；取排序首项。`budgets` 非元组抛 `TypeError`；其长度或成员非法、`capacity`/`prefer` 非法、无可行候选均抛 `ValueError`
- `merkle_deployment_frontier(capacity, budgets)` — 与 `recommend_merkle_deployment` 同一组候选与预算，但**不排序取首项**，而是返回全部可行且非支配的普通 Merkle 部署，类型为 `tuple[MerkleStorageProfile, ...]`，不新增值类型。纯函数：不取随机数、不生成密钥、不改状态，且无默认参数。`capacity` 限 1 至 256 的非布尔整数；`budgets` 必须为四元组，按顺序分别为检查点字节（`checkpoint_bytes`）、单签线长（`signature_wire_bytes`）、独立证明线长（`proof_wire_bytes`）及单签验签步数（`profile("merkle", ...).steps`）的含边界上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 中叶数覆盖 `capacity` 的全部候选，配置取 `merkle_storage_profile`、步数取 `profile` 的 Merkle 结果。支配判定固定为：A 在检查点字节、签名线长、证明线长、单签步数四项上均不大于 B 且至少一项严格更小，则 A 支配 B；删除全部被支配候选并按值去重，不因偏好预先舍弃速度与尺寸形成取舍的配置。结果按单签步数、签名线长、证明线长、检查点字节、叶数、`w`、`height` 稳定升序排列。`budgets` 非元组抛 `TypeError`；其余非法输入或无可行候选抛 `ValueError`
- `recommend_merkle_deployment_weighted(capacity, budgets, weights)` — 在 `merkle_deployment_frontier` 的非支配结果上**按四元组权重的归一化加权评分选出一个普通 Merkle 部署方案**，返回该前沿成员（现有的 `MerkleStorageProfile`），不新增值类型、不复制候选枚举与 Pareto 筛选、不改变既有前沿与按偏好取一项的推荐入口。纯函数：不取随机数、不生成密钥、不改状态，同一输入重复调用结果逐项确定；前沿在函数内恰好调用一次。三参数均无默认值；`capacity` 与四元组 `budgets` 先按 `merkle_deployment_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `weights` 筛查）。`weights` 必须为四元组，依次对应检查点字节（`checkpoint_bytes`）、单签线长（`signature_wire_bytes`）、独立证明线长（`proof_wire_bytes`）与单签验签链步数（`profile("merkle", ...).steps`），每个成员只能是非布尔非负整数且四项中至少一项为正。四项成本各自按全前沿最小值与最大值作 `(x-min)/(max-min)` 归一化（零跨度一律记 0），四项归一化成本乘对应权重求和后除以权重总和，全程精确有理数（`fractions.Fraction`，禁止浮点）；取评分最小的前沿成员，评分完全相同时按检查点字节、叶数、`w`、`height` 升序取首项。`weights` 非元组或权重成员非整数抛 `TypeError`；权重长度错误、含布尔或负数、整组全零抛 `ValueError`；无可行方案同样抛 `ValueError`
- `recommend_merkle_deployment_weighted_scenarios(capacity, budgets, scenarios)` — 为普通 Merkle 存储部署前沿 `merkle_deployment_frontier` 补上**抗偏好漂移的多情景版本**（基线已有按偏好取一项的 `recommend_merkle_deployment` 与单一固定权重的 `recommend_merkle_deployment_weighted`）：同时评估多组权重情景，从同一次前沿中选择最坏后悔值最小的方案，返回该前沿成员（现有的 `MerkleStorageProfile`），不新增值类型、不重复枚举或筛选候选、不改变既有前沿与两个既有推荐入口。纯函数：不取随机数、不生成密钥、不改状态，同一输入重复调用结果逐项相同；前沿在函数内恰好调用一次。三参数均无默认值；`capacity` 与四元组 `budgets` 先按 `merkle_deployment_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `scenarios` 筛查）。`scenarios` 必须为**非空元组**，每项是覆盖检查点字节（`checkpoint_bytes`）、单签线长（`signature_wire_bytes`）、独立证明线长（`proof_wire_bytes`）与单签验签链步数（`profile("merkle", ...).steps`）的四元权重；权重只能是非布尔非负整数，每个情景至少一项为正，重复情景分别计入（权重总和参与归一化）。四项成本按全前沿各自的最小值与最大值归一化（零跨度记 0），全程为精确有理数（`fractions.Fraction`，禁止浮点）；每个情景的加权和除以该情景自身的权重总和作为该情景下的得分。先求每个情景在全前沿上的最优得分，候选得分减去它即为该情景下的后悔值；按各情景最大后悔值（最坏后悔）升序、再按后悔值总和、再按各情景得分元组排序，完全平局时按检查点字节、叶数、`w`、`height` 升序取首项。`scenarios` 或其成员非元组、权重成员非整数抛 `TypeError`；空元组、权重组长度不符、含布尔或负数权重、或整项全零抛 `ValueError`；无可行方案也抛 `ValueError`
- `explain_merkle_deployment_weighted(capacity, budgets, weights)` — 为普通 Merkle 存储部署的加权推荐 `recommend_merkle_deployment_weighted` 补上**决策成本明细的导出入口**（基线无此类明细入口）：在同一次 `merkle_deployment_frontier` 前沿上逐项给出每个候选的归一化成本与最终评分，返回冻结的 `MerkleDeploymentScore` 行元组，行序与该前沿成员顺序完全一致，不重复枚举或筛选候选、不改变既有前沿与任何既有推荐入口。纯函数：不取随机数、不生成密钥、不改状态，同一输入结果逐项确定。三参数均无默认值；`capacity` 与四元组 `budgets` 先按 `merkle_deployment_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `weights` 筛查），`weights` 规则与 `recommend_merkle_deployment_weighted` 完全一致。每行依次携带该候选的配置（`MerkleStorageProfile`）、与权重逐位对应的四项归一化成本（检查点字节、单签线长、独立证明线长、单签链步，各按全前沿最小值与最大值作 `(x-min)/(max-min)` 归一化、零跨度记 0）、最终评分（归一化成本乘各自权重求和再除以权重总和）与选中标志，各数值均为 `fractions.Fraction` 精确有理数、禁止浮点。恰好一行被选中，其配置与同参数调用 `recommend_merkle_deployment_weighted` 的结果逐字段相同；评分完全相同时沿用既有决胜尾序（检查点字节、叶数、`w`、`height` 升序取首）。全前沿零跨度时各行评分都是零，选中项由决胜尾序决定，明细如实反映。`budgets`/`weights` 非元组或权重成员非整数抛 `TypeError`；容量越界或为布尔、预算长度不符或成员非法或全空、权重长度不符、含布尔或负数、整组全零均抛 `ValueError`；预算下无可行方案同样抛 `ValueError`，不返回任何明细行
- `MerkleDeploymentScore` — 冻结的决策成本明细行值对象，七个字段按位置依次为 `config, checkpoint_cost, signature_cost, proof_cost, steps_cost, score, selected`：候选配置（`MerkleStorageProfile`）、与权重逐位对应的四项归一化成本（`Fraction`）、最终评分（`Fraction`）与选中标志（`bool`）；冻结、可位置构造、按值相等（可哈希）
- `explain_merkle_deployment_weighted_scenarios(capacity, budgets, scenarios)` — 为普通 Merkle 存储部署的多情景加权推荐 `recommend_merkle_deployment_weighted_scenarios` 补上**决策成本明细的导出入口**（基线已有该前沿与三类推荐入口及单权重明细，缺多情景版明细，本次从零新增）：在同一次 `merkle_deployment_frontier` 前沿上逐项给出每个候选的归一化成本、各情景得分与后悔值，返回冻结的 `MerkleDeploymentScenarioScore` 行元组，行序与该前沿成员顺序完全一致，不重复枚举或筛选候选、不改变既有前沿、各族既有推荐入口、单权重明细及任何旧接口与线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入结果逐项确定；前沿在函数内恰好调用一次。三参数均无默认值；`capacity` 与四元组 `budgets` 先按 `merkle_deployment_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `scenarios` 筛查），`scenarios` 规则与 `recommend_merkle_deployment_weighted_scenarios` 完全一致：非空元组，每项是覆盖检查点字节（`checkpoint_bytes`）、单签线长（`signature_wire_bytes`）、独立证明线长（`proof_wire_bytes`）与单签链步（`profile("merkle", ...).steps`）的四元权重，权重只能是非布尔非负整数、每项至少一个正数，重复情景分别计入。每行依次携带该候选的配置（`MerkleStorageProfile`）、与权重逐位对应的四项归一化成本（各按全前沿最小值与最大值作 `(x-min)/(max-min)` 归一化、零跨度一律记 0）、与情景同序的得分元组（归一化成本乘该情景权重求和再除以该情景权重总和）、与情景同序的后悔值元组（该行得分减去该情景在全前沿上的最优得分）与选中标志，各数值均为 `fractions.Fraction` 精确有理数、禁止浮点。选中标志恰好落在一行，其配置与同参数调用 `recommend_merkle_deployment_weighted_scenarios` 的结果逐字段相同：沿用最坏后悔最小、后悔值总和与各情景得分元组依次决胜，平局再按既有尾键（检查点字节、叶数、`w`、`height` 升序）取首项。`scenarios` 或其成员非元组、权重成员非整数抛 `TypeError`；情景集为空、权重组长度不符、含布尔或负数权重、或整项全零抛 `ValueError`；容量为布尔或越界、预算长度或成员非法或全空同样抛 `ValueError`；预算下无可行方案也抛 `ValueError`，不返回任何明细行
- `MerkleDeploymentScenarioScore` — 冻结的多情景决策成本明细行值对象，八个字段按位置依次为 `config, checkpoint_cost, signature_cost, proof_cost, steps_cost, scores, regrets, selected`：候选配置（`MerkleStorageProfile`）、与权重逐位对应的四项归一化成本（`Fraction`）、与情景同序的得分元组与后悔值元组（各 `Fraction` 元组）及选中标志（`bool`）；冻结、可位置构造、按值相等（可哈希）
- `MerkleStorageProfile` — 冻结的 Merkle 线长估算值对象，八个字段均为 `int` 且按位置依次为 `w, height, leaf_count, signature_wire_bytes, proof_wire_bytes, checkpoint_bytes, auth_v1_bytes, auth_v2_bytes`；冻结、可位置构造、按值相等（可哈希）
- `merkle_storage_profile(w, height)` — 纯函数：返回 `(w, height)` 对应的 `MerkleStorageProfile`，不生成密钥、不取随机数。`w` 限 4/8，`height` 限 1 至 8 非布尔整数，非法抛 `ValueError`。令 `n = 67/34`（对应 `w = 4/8`）、`L = 2**height`、`S = 16 + 32*(n+height)`、`C = 81 + 32*L*n`：前四字段为 `w, height, L, S`，后四字段 `proof_wire_bytes, checkpoint_bytes, auth_v1_bytes, auth_v2_bytes` 依次为 `S+60, C, C+46, C+54`，分别对应 `MerkleProof` 线长、明文检查点、v1 封装、v2 封装
- `merkle_transport_profile(w, height, indices)` — 纯函数：为同一叶集合估算批量证明与多证明线长，返回三元组 `(m, 58+k*(4+S), 60+k*(4+32*n)+35*m)`，分别为多证明携带的节点数 `m`、批量证明线长、多证明线长，其中 `k = len(indices)`，`m` 按既有多证明规范计入集合外兄弟并逐级右移去重。`indices` 必须为非空、严格递增的整数元组，成员均在 `0 .. 2**height-1`；容器或成员类型错抛 `TypeError`，空元组、布尔成员、越界或非严格递增抛 `ValueError`；`w`/`height` 非法同样抛 `ValueError`
- `recommend_merkle_transport_deployment(capacity, indices, budgets, prefer="multiproof")` — 在预算内**联合**选择树参数与传输方案，返回 `MerkleTransportDeploymentProfile`。纯函数：不取随机数、不生成密钥、不改状态。`capacity` 限 1 至 256 的非布尔整数；`indices` 必须为非空、严格递增的非布尔整数元组，最大成员须小于候选树叶数；`budgets` 必须为四元组，按顺序分别为检查点字节、批次证明字节、多证明字节及单签验签步数（`profile("merkle", ...).steps`）的上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 全部候选：叶数须同时覆盖 `capacity` 与 `indices`，尺寸与步数均复用 `merkle_storage_profile`、`merkle_transport_profile` 与 `profile`。`prefer` 取 `"multiproof"`/`"batch"`/`"speed"`：主排序键分别为多证明字节、批次字节、步数；前两者次键取另一传输线长（multiproof 先多证明后批次，batch 反之），speed 依次再多证明字节、批次字节；三种偏好末段均按检查点字节、叶数、`w`、`height` 升序取首项。`indices`/`budgets` 容器类型错抛 `TypeError`，其余非法输入（含非整数或布尔索引成员）或无可行候选抛 `ValueError`
- `MerkleTransportDeploymentProfile` — 冻结的联合部署选择值对象，四个字段按位置依次为 `config, nodes, batch, multi`，类型依次为 `MerkleStorageProfile, int, int, int`：所选配置、多证明节点数、批次证明字节数、多证明字节数；冻结、可位置构造、按值相等（可哈希）
- `merkle_transport_deployment_frontier(capacity, indices, budgets)` — 与 `recommend_merkle_transport_deployment` 同一组候选与预算，但**不排序取首项**，而是返回全部可行且非支配的联合部署，类型为 `tuple[MerkleTransportDeploymentProfile, ...]`，不新增值类型。纯函数：不取随机数、不生成密钥、不改状态，且无默认参数。`capacity` 限 1 至 256 的非布尔整数；`indices` 必须为非空、严格递增的非负非布尔整数元组，候选树叶数须同时覆盖 `capacity` 与最大索引加一；`budgets` 必须为四元组，按顺序分别为检查点字节、批次证明字节、多证明字节及单签验签步数（`profile("merkle", ...).steps`）的含边界上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 全部候选，配置取 `merkle_storage_profile`、批次/多证明与节点数取 `merkle_transport_profile`、步数取 `profile`。支配判定固定为：A 在检查点字节、批次证明字节、多证明字节、单签步数四项上均不大于 B 且至少一项严格更小，则 A 支配 B（节点数仅作输出，不参与支配）；删除全部被支配候选并按值去重，不因偏好预先舍弃速度与传输尺寸形成取舍的配置。结果按单签步数、多证明字节、批次证明字节、检查点字节、叶数、`w`、`height` 稳定升序排列。`indices`/`budgets` 非元组抛 `TypeError`；其余非法输入或无可行候选抛 `ValueError`
- `recommend_merkle_transport_deployment_weighted(capacity, indices, budgets, weights)` — 在 `merkle_transport_deployment_frontier` 的非支配结果上**按五元组权重的归一化加权评分选出一个联合部署方案**，返回该前沿成员（现有的 `MerkleTransportDeploymentProfile`），不新增值类型、不复制候选枚举与 Pareto 筛选、不改变任何线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入结果逐项确定；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`indices` 与四元组 `budgets` 完全沿用 `merkle_transport_deployment_frontier` 的类型、范围、含边界预算、异常与无可行项规则，且先于 `weights` 筛查。`weights` 必须为五元组，依次对应批次证明字节（`batch`）、多证明字节（`multi`）、携带节点数（`nodes`）、检查点字节（`config.checkpoint_bytes`）与单签验签链步数（`profile("merkle", ...).steps`），每个成员只能是非布尔非负整数且至少一项为正。对前沿五项成本分别按 `(x-min)/(max-min)` 归一化（零跨度记 0），五项归一化成本乘对应权重后求和，以精确有理数（`fractions.Fraction`，无浮点）取评分最小者；评分相同时按检查点字节、叶数、`w`、`height` 升序取首项。`indices`/`budgets`/`weights` 非元组抛 `TypeError`；权重长度错误、含布尔、负数、非整数成员或全零抛 `ValueError`
- `recommend_merkle_transport_deployment_weighted_scenarios(capacity, indices, budgets, scenarios)` — 为单叶集合的 `merkle_transport_deployment_frontier` 联合部署前沿补上**抗偏好漂移的多情景版本**（基线已有 `recommend_merkle_transport_deployment_weighted` 的单一固定权重选择）：同时评估多组权重情景，从同一次联合部署前沿中选择最坏后悔值最小的方案，返回该前沿成员（现有的 `MerkleTransportDeploymentProfile`），不新增值类型、不重复枚举或筛选候选、不改变既有前沿、既有推荐入口及任何旧接口与线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入重复调用结果逐项相同；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`indices` 与四元组 `budgets` 先按 `merkle_transport_deployment_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `scenarios` 筛查）。`scenarios` 必须为**非空元组**，每项是覆盖批次证明字节（`batch`）、多证明字节（`multi`）、携带节点数（`nodes`）、检查点字节（`config.checkpoint_bytes`）与单签链步（`profile("merkle", ...).steps`）的五元权重；权重只能是非布尔非负整数，每个情景至少一项为正，重复情景分别计入（权重总和参与归一化）。五项成本按全前沿各自的最小值与最大值归一化（零跨度记 0），全程为精确有理数（`fractions.Fraction`，禁止浮点）；每个情景的加权和除以该情景自身的权重总和作为该情景下的得分。先求每个情景的最优得分，候选得分减去它即为该情景下的后悔值；按各情景最大后悔值（最坏后悔）升序、再按后悔值总和、再按各情景得分元组排序，完全平局时按检查点字节、叶数、`w`、`height` 升序取首项。`scenarios` 或其成员非元组、权重成员非整数抛 `TypeError`；空元组、权重组长度不符、含布尔或负数权重、或整项全零抛 `ValueError`；无可行方案也抛 `ValueError`
- `explain_merkle_transport_deployment_weighted(capacity, indices, budgets, weights)` — 为单叶集合联合部署前沿的单一权重推荐 `recommend_merkle_transport_deployment_weighted` 补上**决策成本明细的导出入口**（基线已有该前沿与按权重选出单一方案的推荐入口，但没有明细入口，本次从零新增）：在同一次 `merkle_transport_deployment_frontier` 前沿上逐项给出每个候选的归一化成本与最终评分，返回冻结的 `MerkleTransportDeploymentScore` 行元组，行序与同参数联合部署前沿一次调用的成员顺序完全一致，不重复枚举或筛选候选、不改变既有前沿、各族推荐入口、已有明细入口及任何旧接口与线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入结果逐项确定；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`indices` 与四元组 `budgets` 先按 `merkle_transport_deployment_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `weights` 筛查）。`weights` 必须为五元组，依次对应批次证明字节（`batch`）、多证明字节（`multi`）、携带节点数（`nodes`）、检查点字节（`config.checkpoint_bytes`）与单签链步（`profile("merkle", ...).steps`），每个成员只能是非布尔非负整数且至少一项为正。每行依次携带该候选的部署方案对象（`MerkleTransportDeploymentProfile`）、与权重逐位对应的五项归一化成本（各按全前沿最小值与最大值作 `(x-min)/(max-min)` 归一化、零跨度一律记 0）、最终评分（归一化成本乘各自权重求和再除以权重总和）与选中标志，各数值均为 `fractions.Fraction` 精确有理数、禁止浮点。选中标志恰好落在一行，其方案与同参数调用 `recommend_merkle_transport_deployment_weighted` 的结果逐字段相同；评分完全相同时沿用其决胜尾序（检查点字节、叶数、`w`、`height` 升序取首）。全前沿零跨度时各行评分都是零，选中项由决胜尾序决定，明细如实反映。`indices`/`budgets`/`weights` 非元组抛 `TypeError`；权重长度不符、含布尔、负数或非整数成员、整组全零抛 `ValueError`；预算下无可行方案同样抛 `ValueError`，不返回任何明细行
- `MerkleTransportDeploymentScore` — 冻结的决策成本明细行值对象，八个字段按位置依次为 `deployment, batch_cost, multi_cost, nodes_cost, checkpoint_cost, steps_cost, score, selected`：候选的部署方案对象（`MerkleTransportDeploymentProfile`）、与权重逐位对应的五项归一化成本（`Fraction`）、最终评分（`Fraction`）与选中标志（`bool`）；冻结、可位置构造、按值相等（可哈希）
- `recommend_merkle_transport_workload(capacity, groups, budgets, prefer="compact")` — 把联合选择推广到**多个独立叶索引组**：每组各自携带一份批次证明或多证明，但共用同一棵 Merkle 树与同一 `(w, height)` 配置；返回 `MerkleTransportWorkloadProfile`。纯函数：不取随机数、不生成密钥、不改状态。`capacity` 限 1 至 256 的非布尔整数；`groups` 必须为非空元组，每个成员本身也是非空、严格递增的非负非布尔整数元组（一组叶索引），所选树的叶数须同时覆盖 `capacity` 与每组的最大索引加一。`budgets` 必须为四元组，按顺序分别为检查点字节、**单组**传输字节（每组所选格式线长均不得超过）、**总传输字节**（各组线长之和）及单签验签步数（`profile("merkle", ...).steps`）的上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 全部候选，尺寸与步数均复用 `merkle_storage_profile`、`merkle_transport_profile` 与 `profile`。`prefer="compact"`（默认）与 `"speed"` 均逐组取批次/多证明中**更短**者、等长取 `"multiproof"`；`"batch"` 与 `"multiproof"` 各组固定使用同名格式。配置排序：`"speed"` 先按验签步数、再按总传输字节，其余三种偏好先按总传输字节；四种偏好末段均按检查点字节、叶数、`w`、`height` 升序取首项。`groups`/`budgets`（含成员组本身）容器类型错抛 `TypeError`，其余非法输入或无可行候选抛 `ValueError`
- `MerkleTransportWorkloadProfile` — 冻结的多组工作负载选择值对象，四个字段按位置依次为 `config, modes, sizes, total`，类型依次为 `MerkleStorageProfile`、`str` 元组、`int` 元组、`int`：所选配置、每组的传输格式名（`"batch"` 或 `"multiproof"`，与输入组同序）、各组所选格式的线长（与 `modes` 逐位对齐）及各组长之和；冻结、可位置构造、按值相等（可哈希）
- `merkle_transport_workload_frontier(capacity, groups, budgets)` — 与 `recommend_merkle_transport_workload` 同一工作负载，但**不排序取首项**，而是返回全部可行且非支配的部署，类型为 `tuple[MerkleTransportWorkloadProfile, ...]`，不新增值类型。纯函数：不取随机数、不生成密钥、不改状态，且无默认参数。`capacity` 限 1 至 256 的非布尔整数；`groups` 必须为非空元组，每个成员本身也是非空、严格递增的非负非布尔整数元组；`budgets` 必须为四元组，按顺序分别为检查点字节、单组传输字节、总传输字节及单签验签步数（`profile("merkle", ...).steps`）的上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 全部候选，配置与步数取 `merkle_storage_profile` 与 `profile`，逐组以 `merkle_transport_profile` 取批次/多证明中更短的线长、等长取 `"multiproof"`，四项预算均须满足。支配判定：A 的 `config.checkpoint_bytes`、`total`、单签 `steps` 均不大于 B 且至少一项严格更小，则 A 支配 B；删除全部被支配项并按值去重。结果按步数、总量、检查点、叶数、`w`、`height` 稳定升序排列。`groups`/`budgets`（含成员组本身）容器类型错抛 `TypeError`，其余非法输入或无可行候选抛 `ValueError`
- `recommend_merkle_transport_workload_weighted(capacity, groups, budgets, weights)` — 在 `merkle_transport_workload_frontier` 的非支配结果上**按四元组权重的归一化加权评分选出一个多组工作负载方案**，返回该前沿成员（现有的 `MerkleTransportWorkloadProfile`），不新增值类型、不复制候选枚举与 Pareto 筛选、不改变任何线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入结果逐项确定；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`groups` 与四元组 `budgets` 完全沿用 `merkle_transport_workload_frontier` 的类型、范围、含边界预算、异常与无可行项规则，且先于 `weights` 筛查。`weights` 必须为四元组，依次对应检查点字节（`config.checkpoint_bytes`）、单组峰值（`max(sizes)`）、总传输字节（`total`）与单签验签链步数（`profile("merkle", ...).steps`）；每个成员只能是非布尔非负整数且至少一项为正。对前沿四项成本分别按 `(x-min)/(max-min)` 归一化（零跨度记 0），四项归一化成本乘对应权重后求和再除以权重总和，以精确有理数（`fractions.Fraction`，无浮点）取评分最小者；评分相同时按检查点字节、叶数、`w`、`height`、逐组模式（`modes`）字典序升序取首项。`groups`/`budgets`/`weights` 非元组或权重含非整数成员抛 `TypeError`；权重长度错误、含布尔、负数或全零抛 `ValueError`；无可行方案也抛 `ValueError`
- `recommend_merkle_transport_workload_weighted_scenarios(capacity, groups, budgets, scenarios)` — 为多组工作负载前沿 `merkle_transport_workload_frontier` 补上**抗偏好漂移的多情景版本**（基线已有按偏好取一项的 `recommend_merkle_transport_workload` 与单一固定权重的 `recommend_merkle_transport_workload_weighted`）：同时评估多组权重情景，从同一次工作负载前沿中选择最坏后悔值最小的方案，返回该前沿成员（现有的 `MerkleTransportWorkloadProfile`），不新增值类型、不重复枚举或筛选候选、不改变既有前沿、两个现有推荐入口及任何旧接口与线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入重复调用结果逐项相同；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`groups` 与四元组 `budgets` 先按 `merkle_transport_workload_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `scenarios` 筛查）。`scenarios` 必须为**非空元组**，每项是覆盖检查点字节（`config.checkpoint_bytes`）、单组峰值（`max(sizes)`）、总传输字节（`total`）与单签链步（`profile("merkle", ...).steps`）的四元权重；权重只能是非布尔非负整数，每个情景至少一项为正，重复情景分别计入（权重总和参与归一化）。四项成本按全前沿各自的最小值与最大值归一化（零跨度记 0），全程为精确有理数（`fractions.Fraction`，禁止浮点）；每个情景的加权和除以该情景自身的权重总和作为该情景下的得分。先求每个情景在全前沿上的最优得分，候选得分减去它即为该情景下的后悔值；按各情景最大后悔值（最坏后悔）升序、再按后悔值总和、再按各情景得分元组排序，完全平局时按检查点字节、叶数、`w`、`height` 与逐组模式（`modes`）的字典序取首项。`scenarios` 或其成员非元组、权重成员非整数抛 `TypeError`；空元组、权重组长度不符、含布尔或负数权重、或整项全零抛 `ValueError`；无可行方案也抛 `ValueError`
- `merkle_mode_frontier(capacity, groups, budgets)` — 与 `merkle_transport_workload_frontier` 同一工作负载，但**逐组枚举全部 `batch`/`multiproof` 模式组合**（每组两种，共 `2**len(groups)` 种，均参与预算筛选），返回全部可行且非支配的模式选择，类型为 `tuple[MerkleTransportWorkloadProfile, ...]`，各项沿用 `config, modes, sizes, total` 字段，`modes` 与 `sizes` 按组对齐，`total` 为各组线长之和，不新增值类型。纯函数：不取随机数、不生成密钥、不改状态，且无默认参数。`capacity` 限 1 至 256 的非布尔整数；`groups` 必须为非空元组，每个成员本身也是非空、严格递增的非负非布尔整数元组；`budgets` 必须为**五元组**，按顺序分别为检查点字节、单组峰值（`sizes` 中的最大值）、总传输字节、单签验签步数（`profile("merkle", ...).steps`）及**节点总数**（仅累加 multiproof 组的规范节点数，batch 组计 0）的含边界上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 中叶数覆盖 `capacity` 与各组最大索引的全部候选，尺寸、节点数与步数均复用 `merkle_storage_profile`、`merkle_transport_profile` 与 `profile`。支配判定：A 在检查点字节、单组峰值、总量、单签步数、节点总数五项成本上均不大于 B 且至少一项严格更小，则 A 支配 B；删除全部被支配项并按值去重，不因偏好预先舍弃尺寸与节点数形成取舍的组合。结果按单签步数、总量、单组峰值、节点总数、检查点字节、叶数、`w`、`height`、`modes` 字典序稳定升序排列。`groups`/`budgets`（含成员组本身）容器类型错抛 `TypeError`，其余非法输入或无可行候选抛 `ValueError`
- `recommend_merkle_mode_deployment(capacity, groups, budgets, prefer="compact")` — 在 `merkle_mode_frontier` 的非支配结果上**按业务偏好选出一个模式组合**，返回现有的 `MerkleTransportWorkloadProfile`，不新增值类型、不改变任何线格式。纯函数：不取随机数、不生成密钥、不改状态。前三参数无默认值；`capacity`、`groups` 与五元组 `budgets` 完全沿用 `merkle_mode_frontier` 的类型、范围、预算及异常规则，无可行项抛 `ValueError`。`prefer` 仅取 `"compact"`（默认）、`"nodes"` 或 `"speed"`，其他值抛 `ValueError`。排序键：`"compact"` 依次按 `total`、单组峰值（`max(sizes)`）、节点总数、单签步数升序；`"nodes"` 依次按节点总数、`total`、单组峰值、单签步数升序；节点总数沿用模式前沿定义，仅累加 multiproof 组的规范节点数；`"speed"` 依次按单签步数、`total`、单组峰值、节点总数升序。三种策略末段统一按检查点字节、叶数、`w`、`height`、`modes` 字典序升序取首项。`groups`/`budgets`（含成员组本身）容器类型错抛 `TypeError`，其余非法输入抛 `ValueError`
- `recommend_merkle_mode_weighted(capacity, groups, budgets, weights)` — 在 `merkle_mode_frontier` 的非支配结果上**按五元组权重的归一化加权评分选出一个模式组合**，返回该前沿成员（现有的 `MerkleTransportWorkloadProfile`），不新增值类型、不复制候选枚举与 Pareto 筛选、不改变任何线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入结果逐项确定；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`groups` 与五元组 `budgets` 完全沿用 `merkle_mode_frontier` 的类型、范围、含边界预算、异常与无可行项规则，且先于 `weights` 筛查。`weights` 必须为五元组，依次对应检查点字节（`config.checkpoint_bytes`）、单组峰值（`max(sizes)`）、总传输字节（`total`）、单签验签链步数（`profile("merkle", ...).steps`）与节点总数，节点总数沿用模式前沿口径，只累计 multiproof 组的规范节点、batch 组计零；每个成员只能是非布尔非负整数且至少一项为正。对前沿五项成本分别按 `(x-min)/(max-min)` 归一化（零跨度记 0），五项归一化成本乘对应权重后求和再除以权重总和，以精确有理数（`fractions.Fraction`，无浮点）取评分最小者；评分相同时按检查点字节、叶数、`w`、`height`、`modes` 字典序升序取首项。`groups`/`budgets`/`weights` 非元组或权重含非整数成员抛 `TypeError`；权重长度错误、含布尔、负数或全零抛 `ValueError`；无可行方案也抛 `ValueError`
- `recommend_merkle_mode_weighted_scenarios(capacity, groups, budgets, scenarios)` — 同一 `merkle_mode_frontier` 模式前沿的**抗偏好漂移多情景版本**（基线已有按偏好取一项的 `recommend_merkle_mode_deployment`）：同时评估多组权重情景，从同一次模式前沿中选择最坏后悔值最小的方案，返回该前沿成员（现有的 `MerkleTransportWorkloadProfile`），不新增值类型、不重复枚举或筛选候选、不改变既有前沿、既有推荐入口及任何旧接口与线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入重复调用结果逐项相同；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`groups` 与五元组 `budgets` 先按 `merkle_mode_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `scenarios` 筛查）。`scenarios` 必须为**非空元组**，每项是覆盖检查点字节（`config.checkpoint_bytes`）、单组峰值（`max(sizes)`）、总传输字节（`total`）、单签链步（`profile("merkle", ...).steps`）与节点总数（只累计 multiproof 组的规范节点、batch 组计零）的五元权重；权重只能是非布尔非负整数，每个情景至少一项为正，重复情景分别计入（权重总和参与归一化）。五项成本按全前沿各自的最小值与最大值归一化（零跨度记 0），全程为精确有理数（`fractions.Fraction`，禁止浮点）；每个情景的加权和除以该情景自身的权重总和作为该情景下的得分。先求每个情景的最优得分，候选得分减去它即为该情景下的后悔值；按各情景最大后悔值（最坏后悔）升序、再按后悔值总和、再按各情景得分元组排序，完全平局时按检查点字节、叶数、`w`、`height` 与逐组模式（`modes`）的字典序取首项。`groups`/`budgets`/`scenarios` 非元组（含成员组或情景本身非元组）或权重成员非整数抛 `TypeError`；空组/空情景、权重组长度不符、含布尔或负数权重、或整组全零抛 `ValueError`；无可行方案也抛 `ValueError`
- `explain_merkle_mode_weighted(capacity, groups, budgets, weights)` — 为多组 Merkle 模式前沿的单一权重推荐 `recommend_merkle_mode_weighted` 补上**决策成本明细的导出入口**（基线已有该模式前沿与按偏好取一项、单权重、多情景三类推荐，但没有明细入口）：在同一次 `merkle_mode_frontier` 前沿上逐项给出每个候选的归一化成本与最终评分，返回冻结的 `MerkleModeScore` 行元组，行序与该前沿成员顺序完全一致，不重复枚举或筛选候选、不改变既有前沿、该族既有推荐入口及任何旧接口与线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入结果逐项确定；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`groups` 与五元组 `budgets` 先按 `merkle_mode_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `weights` 筛查）。`weights` 必须为五元组，依次对应检查点字节（`config.checkpoint_bytes`）、单组峰值（`max(sizes)`）、总传输字节（`total`）、单签链步（`profile("merkle", ...).steps`）与节点总数，节点总数沿用模式前沿口径，只累计 multiproof 组的规范节点、batch 组计零；每个成员只能是非布尔非负整数且至少一项为正。每行依次携带该候选的工作负载方案对象（`MerkleTransportWorkloadProfile`）、与权重逐位对应的五项归一化成本（各按全前沿最小值与最大值作 `(x-min)/(max-min)` 归一化、零跨度一律记 0）、最终评分（归一化成本乘各自权重求和再除以权重总和）与选中标志，各数值均为 `fractions.Fraction` 精确有理数、禁止浮点；行对象可位置构造、按值相等且可哈希。选中标志恰好落在一行，其方案与同参数调用 `recommend_merkle_mode_weighted` 的结果逐字段相同；评分完全相同时沿用其决胜尾序（检查点字节、叶数、`w`、`height`、`modes` 字典序升序取首）。全前沿零跨度时各行评分都是零，选中项由决胜尾序决定，明细如实反映。`groups`/`budgets`/`weights` 非元组或权重成员非整数抛 `TypeError`；容量为布尔或越界、组为空或组内索引非法、预算长度不符或成员非法或全空、权重长度不符、含布尔或负数、整组全零均抛 `ValueError`；预算下无可行方案同样抛 `ValueError`，不返回任何明细行
- `MerkleModeScenarioScore` — 冻结的多情景决策成本明细行值对象，九个字段按位置依次为 `workload, checkpoint_cost, peak_cost, transport_cost, steps_cost, nodes_cost, scores, regrets, selected`：候选的工作负载方案对象（`MerkleTransportWorkloadProfile`）、与权重逐位对应的五项归一化成本（`Fraction`）、与情景同序的得分元组与后悔值元组（各 `Fraction` 元组）及选中标志（`bool`）；冻结、可位置构造、按值相等（可哈希）
- `explain_merkle_mode_weighted_scenarios(capacity, groups, budgets, scenarios)` — 为多组 Merkle 模式前沿的多情景加权推荐 `recommend_merkle_mode_weighted_scenarios` 补上**决策成本明细的导出入口**（基线已有该模式前沿、三类推荐与单权重明细，缺多情景版明细，本次从零新增）：在同一次 `merkle_mode_frontier` 前沿上逐项给出每个候选的归一化成本、各情景得分与后悔值，返回冻结的 `MerkleModeScenarioScore` 行元组，行序与同参数模式前沿一次调用的成员顺序完全一致，不重复枚举或筛选候选、不改变既有模式前沿、三类推荐、已有明细入口及任何旧接口与线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入结果逐项确定；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`groups` 与五元组 `budgets` 先按 `merkle_mode_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `scenarios` 筛查），`scenarios` 规则与 `recommend_merkle_mode_weighted_scenarios` 完全一致：非空元组，每项是覆盖检查点字节（`config.checkpoint_bytes`）、单组峰值（`max(sizes)`）、总传输字节（`total`）、单签链步（`profile("merkle", ...).steps`）与节点总数（只累计 multiproof 组的规范节点、batch 组计零）的五元权重，权重只能是非布尔非负整数、每项至少一个正数，重复情景分别计入。每行依次携带该候选的工作负载方案对象（`MerkleTransportWorkloadProfile`）、与权重逐位对应的五项归一化成本（各按全前沿最小值与最大值作 `(x-min)/(max-min)` 归一化、零跨度一律记 0）、与情景同序的得分元组（归一化成本乘该情景权重求和再除以该情景权重总和）、与情景同序的后悔值元组（该行得分减去该情景在全前沿上的最优得分）与选中标志，各数值均为 `fractions.Fraction` 精确有理数、禁止浮点；行对象可位置构造、按值相等且可哈希。选中标志恰好落在一行，其方案与同参数调用 `recommend_merkle_mode_weighted_scenarios` 的结果逐字段相同：沿用最坏后悔最小、后悔值总和与各情景得分元组依次决胜，平局再按既有尾键（检查点字节、叶数、`w`、`height`、`modes` 字典序升序）取首项。`scenarios` 或其成员非元组、权重成员非整数抛 `TypeError`；情景集为空、权重组长度不符、含布尔或负数权重、或整项全零抛 `ValueError`；前沿规则之外的非法输入沿用模式前沿的异常口径，预算下无可行方案同样抛 `ValueError`，不返回任何明细行
- `MerkleVerifyProfile` — 冻结的验签哈希成本值对象，七个字段均为 `int` 且按位置依次为 `w, height, k, wots, leaf, batch, multi`；冻结、可位置构造、按值相等（可哈希）。`k` 为叶索引数；`wots` 为全部 `k` 条 W-OTS 链步上界；`leaf` 为叶哈希数；`batch`/`multi` 分别为批次证明与多证明的内部节点 SHA-256 次数
- `merkle_verify_profile(w, height, indices)` — 纯函数：比较同一叶集合的批次证明与多证明**验签哈希成本**，返回 `MerkleVerifyProfile`，不生成密钥、不取随机数、不修改状态。`w` 仅为 4 或 8，`height` 仅为 1..8 的非布尔整数；`indices` 须为非空、严格递增且落在 `0 .. 2**height-1` 内的非布尔整数元组。令 `k = len(indices)`：`wots` 链步上界为 `k*67*15`（`w=4`）或 `k*34*255`（`w=8`），`leaf = k`，这些 SHA-256 次数均按每叶计算，不因认证路径去重而减少；`batch = k*height`（每份证明重复完整路径），`multi = Σ(l=1..height)|{i>>l : i∈indices}|`（每层每个不同父节点仅执行一次内部节点 SHA-256）。`indices` 容器或非整数成员错型抛 `TypeError`；空元组、布尔成员、越界、重复或乱序，以及非法 `w` 或 `height` 均抛 `ValueError`
- `MerkleVerifyWorkloadProfile` — 冻结的多组验签哈希成本汇总值对象，四个字段按位置依次为 `w, height, costs, total`，类型依次为 `int`、`int`、五元组元组 `tuple[tuple[str,int,int,int,int], ...]`、`int`；冻结、可位置构造、按值相等（可哈希）。`costs` 与输入各组同序，每项依次为模式名（`"batch"` 或 `"multiproof"`）、该组 W-OTS 链步、叶哈希数、内部节点哈希数及该组三项哈希总数；`total` 为各组总数之和，重复组分别计费
- `merkle_verify_workload_profile(w, height, groups, modes)` — 纯函数：把 `merkle_verify_profile` 的成本比较推广到**多个独立叶索引组**，每组各自携带一份批次证明或多证明但共用同一棵 Merkle 树，按组比较 batch 与 multiproof 混合方案的 SHA-256 工作量并给出全局合计，返回 `MerkleVerifyWorkloadProfile`，不生成密钥、不取随机数、不修改状态，旧接口与线格式不变。`w` 仅为 4 或 8，`height` 仅为 1..8 的非布尔整数；`groups` 必须为非空元组，每个成员本身也是非空、严格递增且落在 `0 .. 2**height-1` 内的非布尔整数元组（各组沿用 `merkle_verify_profile` 的单组规则）；`modes` 为与 `groups` 等长的元组，每项仅为 `"batch"` 或 `"multiproof"`。每组复用 `merkle_verify_profile(w, height, group)`：模式 `batch` 取其 `batch`、`multiproof` 取其 `multi` 作为内部节点哈希数；五元组依次为模式名、W-OTS 链步、叶哈希、内部节点哈希、该组三项哈希总数，`total` 为各组总数之和，重复组也分别计费。`groups`/`modes`（含成员组本身）容器错型或模式成员非字符串抛 `TypeError`；`groups` 为空、单组违反单组规则（空元组、布尔或非整数成员、越界、重复或乱序）、`modes` 长度与 `groups` 不符、出现未知模式，以及非法 `w` 或 `height` 均抛 `ValueError`
- `MerkleModeCost` — 冻结的模式选择与验签哈希成本配对值对象，三个字段按位置依次为 `plan, cost, nodes`，类型依次为 `MerkleTransportWorkloadProfile`、`MerkleVerifyWorkloadProfile`、`int`：传输方案（配置、逐组模式、逐组尺寸、总量）、同参数的验签 SHA-256 工作量及仅累计 multiproof 组的规范节点总数（batch 组计 0）；冻结、可位置构造、按值相等（可哈希）
- `merkle_verify_mode_frontier(capacity, groups, budgets)` — 与 `merkle_mode_frontier` 同一工作负载与逐组模式枚举，但在五项传输/链步预算之外**再加一项验签 SHA-256 总量预算**，返回全部可行且非支配的选择，类型为 `tuple[MerkleModeCost, ...]`，不改变旧接口与任何线格式。纯函数：不取随机数、不生成密钥、不改状态，且无默认参数。`capacity`、`groups` 完全沿用 `merkle_mode_frontier` 的类型、范围与异常规则；`budgets` 必须为**六元组**，预算成员规则（各项为 `None` 或正的非布尔整数、至少一项非空、含边界、非元组抛 `TypeError`、长度或成员非法抛 `ValueError`）也沿用之，按顺序分别限制检查点字节、单组峰值、总传输字节、单签验签步数、multiproof 节点总数及**验签 SHA-256 总数**（`MerkleVerifyWorkloadProfile.total`）。枚举 `w=4/8` × `height=1..8` 中叶数覆盖 `capacity` 与各组最大索引的全部候选，以及每组两种模式的全部 `2**len(groups)` 组合；`plan` 按现有公式保存配置、模式、逐组尺寸与总量，`cost` 取同参数 `merkle_verify_workload_profile(w, height, groups, modes)` 的结果，`nodes` 仅累计 multiproof 组的规范节点。支配判定：A 在六项成本（检查点、单组峰值、总量、单签步数、节点总数、验签哈希总数）上均不大于 B 且至少一项严格更小，则 A 支配 B；删除全部被支配项并按值去重。结果按单签步数、验签哈希总量、总传输字节、单组峰值、节点总数、检查点字节、叶数、`w`、`height`、`modes` 字典序稳定升序排列；无可行项抛 `ValueError`
- `merkle_cardinality_frontier(capacity, group_sizes, budgets)` — `merkle_verify_mode_frontier` 的**叶位置未定**版本：每组只给叶数 `group_sizes`（非空正整数元组，每项是一个独立索引组的叶数，重复项分别计费，且不得大于候选叶数），对每个 multiproof 组在该树**全部同规模严格递增索引子集中取传输字节、规范节点数与内部哈希数的最大值**（同一最大化铺开布局同时达到三者），batch 组沿用与位置无关的固定公式，返回全部可行且非支配的方案，类型仍为 `tuple[MerkleModeCost, ...]`，不新增值类型、不改变旧接口。纯函数：不取随机数、不生成密钥、不改状态，且无默认参数。`capacity` 限 1 至 256 的非布尔整数；`budgets` 沿用联合前沿的**六元含边界上限**（检查点字节、单组峰值、总传输字节、单签验签步数、multiproof 节点总数、验签 SHA-256 总数，各项 `None` 或正的非布尔整数、至少一项非空）。枚举 `w=4/8` × `height=1..8` 中叶数同时覆盖 `capacity` 与每组叶数的全部候选，以及每组两种模式的全部 `2**len(group_sizes)` 组合。以 `n` 为 W-OTS 链数、`S = 16 + 32*(n+height)`：`k` 叶的 batch 组为 `58 + k*(4+S)` 字节、0 节点、内部哈希 `k*height`；multiproof 组最坏为 `60 + k*(4+32*n) + 35*m_max` 字节、`m_max` 节点，其中 `internal_max = Σ_{j=0..height-1} min(k, 2**j)`、`m_max = internal_max - (k-1)`（逐层祖先数上界且可由尽量均匀铺开的布局达到），W-OTS 链步 `k*n*(b-1)` 与叶哈希 `k` 两种模式相同、与位置无关。`plan.sizes`、`plan.total`、`cost.costs`、`cost.total` 与 `nodes` 均记录上述逐组最坏值或其和。六项成本 Pareto 支配、去重及排序完全沿用 `merkle_verify_mode_frontier`。`group_sizes`/`budgets` 非元组、或 `group_sizes` 含非整数成员抛 `TypeError`；空、布尔、非正成员、`capacity` 越界、预算非法或无可行方案抛 `ValueError`
- `recommend_merkle_cardinality_deployment(capacity, group_sizes, budgets, prefer="compact")` — 在 `merkle_cardinality_frontier` 的非支配结果上**按业务偏好选出一个最坏位置基数方案**，返回该前沿成员（`MerkleModeCost`），不新增值类型、不复制候选枚举与 Pareto 筛选、不改变任何线格式。纯函数：不取随机数、不生成密钥、不改状态；前沿在函数内恰好调用一次。前三参数无默认值；`capacity`、`group_sizes` 与六元组 `budgets` 完全沿用 `merkle_cardinality_frontier` 的类型、范围、含边界预算、异常与无可行项规则。`prefer` 仅取 `"compact"`（默认）、`"verify"`、`"nodes"`、`"speed"`、`"robust"`，其他值抛 `ValueError`。排序的五项成本为总传输（`plan.total`）、单组峰值（`max(plan.sizes)`）、验签哈希总量（`cost.total`）、节点数（`nodes`）与单签链步（`profile("merkle", ...).steps`）：`"compact"` 依次最小化总传输、单组峰值、验签哈希总量、节点数、单签链步；`"verify"` 依次最小化验签哈希总量、单签链步、总传输、单组峰值、节点数；`"nodes"` 依次最小化节点数、总传输、验签哈希总量、单组峰值、单签链步；`"speed"` 依次最小化单签链步、验签哈希总量、总传输、单组峰值、节点数。`"robust"` 在前沿五项成本上各取 `(x-min)/(max-min)`（零跨度记 0），以精确有理数（`fractions.Fraction`，无浮点）先最小化最大归一化成本、再最小化其和。全部策略末段统一按检查点字节、叶数、`w`、`height`、`modes` 字典序升序取首项
- `recommend_merkle_verify_mode_deployment(capacity, groups, budgets, prefer="compact")` — `recommend_merkle_cardinality_deployment` 的**固定叶位置**版本：在 `merkle_verify_mode_frontier` 的非支配结果上按业务偏好选出一个方案，返回该前沿成员（`MerkleModeCost`），不新增值类型、不复制候选枚举与 Pareto 筛选、不改变任何线格式。纯函数：不取随机数、不生成密钥、不改状态；前沿在函数内恰好调用一次。前三参数无默认值；`capacity`、`groups` 与六元组 `budgets` 完全沿用 `merkle_verify_mode_frontier` 的类型、范围、含边界预算、异常与无可行项规则，且先于 `prefer` 筛查。`prefer` 仅取 `"compact"`（默认）、`"verify"`、`"nodes"`、`"speed"`、`"robust"`，其他值抛 `ValueError`。排序的五项成本为总传输（`plan.total`）、单组峰值（`max(plan.sizes)`）、验签哈希总量（`cost.total`）、节点数（`nodes`）与单签链步（`profile("merkle", ...).steps`）：`"compact"` 依次最小化总传输、单组峰值、验签哈希总量、节点数、单签链步；`"verify"` 依次最小化验签哈希总量、单签链步、总传输、单组峰值、节点数；`"nodes"` 依次最小化节点数、总传输、验签哈希总量、单组峰值、单签链步；`"speed"` 依次最小化单签链步、验签哈希总量、总传输、单组峰值、节点数。`"robust"` 在前沿五项成本上各取 `(x-min)/(max-min)`（零跨度记 0），以精确有理数（`fractions.Fraction`，无浮点）先最小化最大归一化成本、再最小化其和。全部策略末段统一按检查点字节、叶数、`w`、`height`、`modes` 字典序升序取首项
- `recommend_merkle_verify_mode_deployment_weighted(capacity, groups, budgets, weights)` — 为**固定叶位置**的 `merkle_verify_mode_frontier` 工作负载补上**单一五元组权重的归一化加权评分推荐**（基线已有该前沿、按偏好取一项的 `recommend_merkle_verify_mode_deployment` 与多情景加权的 `recommend_merkle_verify_mode_weighted`，本次只新增单权重版本）：从同一次前沿调用得到的非支配结果中选评分最小的一个方案，返回该前沿成员（现有的 `MerkleModeCost`），不新增值类型、不重复枚举或自行筛选候选、不改变既有前沿与任何旧接口及线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入重复调用结果逐项相同；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`groups` 与六元组 `budgets` 先按 `merkle_verify_mode_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `weights` 筛查）。`weights` 必须为五元组，依次对应总传输（`plan.total`）、单组峰值（`max(plan.sizes)`）、验签 SHA-256 总量（`cost.total`）、multiproof 节点数（`nodes`，口径与前沿一致：仅累计 multiproof 组的规范节点，batch 组计零）与单签链步（`profile("merkle", ...).steps`）；每项权重只能是非布尔非负整数，五项中至少一项为正。五项成本分别按整个前沿的最小值与最大值作 `(x-min)/(max-min)` 归一化（零跨度记 0），归一化成本乘各自权重求和后除以权重总和，全程为精确有理数（`fractions.Fraction`，禁止浮点）；取评分最小者，只点亮其中一维时返回的即该维成本最小的前沿成员。评分完全相同时按检查点字节、叶数、`w`、`height` 与逐组模式（`modes`）字典序升序取首项。`weights` 容器或成员不是元组、不是整数抛 `TypeError`；长度不符、含布尔或负数、或五项全零抛 `ValueError`；预算下无可行方案同样抛 `ValueError`
- `recommend_merkle_cardinality_weighted(capacity, group_sizes, budgets, weights)` — 在 `merkle_cardinality_frontier` 的非支配结果上**按五元组权重的归一化加权评分选出一个最坏位置基数方案**，返回该前沿成员（现有的 `MerkleModeCost`），不新增值类型、不复制候选枚举与 Pareto 筛选、不改变任何线格式。纯函数：不取随机数、不生成密钥、不改状态；前沿在函数内恰好调用一次。前三参数无默认值；`capacity`、`group_sizes` 与六元组 `budgets` 完全沿用 `merkle_cardinality_frontier` 的类型、范围、含边界预算、异常与无可行项规则。`weights` 必须为五元组，依次对应总传输（`plan.total`）、单组峰值（`max(plan.sizes)`）、验签 SHA-256 总量（`cost.total`）、multiproof 节点数（`nodes`）与单签链步（`profile("merkle", ...).steps`），每个成员只能是非布尔非负整数且至少一项为正。对前沿五项成本分别按 `(x-min)/(max-min)` 归一化（零跨度记 0），五项归一化成本乘对应权重后求和，以精确有理数（`fractions.Fraction`，无浮点）取评分最小者；评分相同时按检查点字节、叶数、`w`、`height`、`modes` 字典序升序取首项。`weights` 非元组抛 `TypeError`；长度错误、含布尔、负数、非整数成员或全零抛 `ValueError`
- `recommend_merkle_verify_mode_weighted(capacity, groups, budgets, scenarios)` — 为**固定叶位置**的 `merkle_verify_mode_frontier` 工作负载新增**抗偏好漂移的加权推荐**：同时评估多组权重情景，从同一次联合验签前沿中选择最坏后悔值最小的方案，返回该前沿成员（现有的 `MerkleModeCost`），不新增值类型、不复制候选枚举与 Pareto 筛选、不改变旧接口与任何线格式。纯函数：不取随机数、不生成密钥、不改状态；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`groups` 与六元组 `budgets` 先按前沿原规则校验（异常与无可行项规则完全沿用 `merkle_verify_mode_frontier`，且先于 `scenarios` 筛查）。`scenarios` 必须为非空元组，每项是五元组权重，依次对应总传输（`plan.total`）、单组峰值（`max(plan.sizes)`）、验签 SHA-256 总量（`cost.total`）、multiproof 节点数（`nodes`）与单签链步（`profile("merkle", ...).steps`）；权重只能是非布尔非负整数，每项至少一个正数，重复情景分别计入。五项成本按全前沿各自的最小值与最大值归一化为 `Fraction`（零跨度记 0）；每个情景的加权和除以该情景的权重总和，禁止浮点。对每个情景先求其在全前沿上的最小归一化得分，再以候选得分减去该最小值得到该情景下的后悔值；按各情景最大后悔值（最坏后悔）升序、再按后悔值总和、再按各情景得分元组排序，末段仍按检查点字节、叶数、`w`、`height`、`modes` 字典序升序取首项。`scenarios` 或其成员非元组、权重非整数抛 `TypeError`；空元组、错长、布尔或负数权重、全零项抛 `ValueError`
- `explain_merkle_verify_mode_weighted(capacity, groups, budgets, scenarios)` — 为**固定叶位置**联合验签前沿的多情景加权推荐 `recommend_merkle_verify_mode_weighted` 补上**决策成本明细的导出入口**（基线已有该前沿与按多情景最坏后悔选出单一方案的推荐入口，但没有明细入口）：在同一次 `merkle_verify_mode_frontier` 前沿上逐项给出每个候选的归一化成本、各情景得分与后悔值，返回冻结的 `MerkleVerifyModeScore` 行元组，行序与该前沿成员顺序完全一致，不重复枚举或筛选候选、不改变既有前沿与任何旧接口及线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入结果逐项确定；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`groups` 与六元组 `budgets` 先按 `merkle_verify_mode_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `scenarios` 筛查），`scenarios` 规则与 `recommend_merkle_verify_mode_weighted` 完全一致：非空元组，每项是覆盖总传输（`plan.total`）、单组峰值（`max(plan.sizes)`）、验签 SHA-256 总量（`cost.total`）、multiproof 节点数（`nodes`）与单签链步（`profile("merkle", ...).steps`）的五元权重，权重只能是非布尔非负整数、每项至少一个正数，重复情景分别计入。每行依次携带该候选的方案成本配对对象（`MerkleModeCost`）、与权重逐位对应的五项归一化成本（各按全前沿最小值与最大值作 `(x-min)/(max-min)` 归一化、零跨度一律记 0）、与情景同序的得分元组（归一化成本乘该情景权重求和再除以该情景权重总和）、与情景同序的后悔值元组（该行得分减去该情景在全前沿上的最优得分）与选中标志，各数值均为 `fractions.Fraction` 精确有理数、禁止浮点。选中标志恰好落在一行，其方案与同参数调用 `recommend_merkle_verify_mode_weighted` 的结果逐字段相同：沿用最坏后悔最小、后悔值总和与各情景得分元组依次决胜，平局再按既有尾键（检查点字节、叶数、`w`、`height`、`modes` 字典序升序）取首项。`scenarios` 或其成员非元组、权重成员非整数抛 `TypeError`；情景集为空、权重组长度不符、含布尔或负数权重、或整项全零抛 `ValueError`；前沿规则之外的非法输入与预算下无可行方案同样抛 `ValueError`，不返回任何明细行
- `MerkleVerifyModeScore` — 冻结的决策成本明细行值对象，九个字段按位置依次为 `mode_cost, transport_cost, peak_cost, hashes_cost, nodes_cost, steps_cost, scores, regrets, selected`：候选的方案成本配对对象（`MerkleModeCost`）、与权重逐位对应的五项归一化成本（`Fraction`）、与情景同序的得分元组与后悔值元组（各 `Fraction` 元组）及选中标志（`bool`）；冻结、可位置构造、按值相等（可哈希）
- `explain_merkle_verify_mode_deployment_weighted(capacity, groups, budgets, weights)` — 为**固定叶位置**联合验签前沿的单一权重推荐 `recommend_merkle_verify_mode_deployment_weighted` 补上**决策成本明细的导出入口**（基线已有该前沿、按偏好取一项与多情景两类推荐，单权重推荐也已具备，但没有该单权重推荐的明细入口，本次从零新增）：在同一次 `merkle_verify_mode_frontier` 前沿上逐项给出每个候选的归一化成本与最终评分，返回冻结的 `MerkleVerifyModeDeploymentScore` 行元组，行序与同参数联合验签前沿一次调用的成员顺序完全一致，不重复枚举或筛选候选、不改变既有前沿、各族推荐入口、已有明细入口及任何旧接口与线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入结果逐项确定；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`groups` 与六元组 `budgets` 先按 `merkle_verify_mode_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `weights` 筛查）。`weights` 必须为五元组，依次对应总传输（`plan.total`）、单组峰值（`max(plan.sizes)`）、验签哈希总量（`cost.total`）、multiproof 节点数（`nodes`）与单签链步（`profile("merkle", ...).steps`），每个成员只能是非布尔非负整数且至少一项为正。每行依次携带该候选的方案成本配对对象（`MerkleModeCost`）、与权重逐位对应的五项归一化成本（各按全前沿最小值与最大值作 `(x-min)/(max-min)` 归一化、零跨度一律记 0）、最终评分（归一化成本乘各自权重求和再除以权重总和）与选中标志，各数值均为 `fractions.Fraction` 精确有理数、禁止浮点。选中标志恰好落在一行，其方案与同参数调用 `recommend_merkle_verify_mode_deployment_weighted` 的结果逐字段相同；评分完全相同时沿用其决胜尾序（检查点字节、叶数、`w`、`height`、`modes` 字典序升序取首）。全前沿零跨度时各行评分都是零，选中项由决胜尾序决定，明细如实反映。`weights` 不是元组或权重成员不是整数抛 `TypeError`；权重长度不符、含布尔或负数、或整项全零抛 `ValueError`；前沿规则之外的非法输入沿用其异常口径，预算下无可行方案同样抛 `ValueError`，不返回任何明细行
- `MerkleVerifyModeDeploymentScore` — 冻结的决策成本明细行值对象，八个字段按位置依次为 `mode_cost, transport_cost, peak_cost, hashes_cost, nodes_cost, steps_cost, score, selected`：候选的方案成本配对对象（`MerkleModeCost`）、与权重逐位对应的五项归一化成本（`Fraction`）、最终评分（`Fraction`）与选中标志（`bool`）；冻结、可位置构造、按值相等（可哈希）
- `recommend_merkle_cardinality_weighted_scenarios(capacity, group_sizes, budgets, scenarios)` — 为**叶位置未定**的 `merkle_cardinality_frontier` 工作负载补上与 `recommend_merkle_verify_mode_weighted` 对应的**抗偏好漂移多情景版本**（基线已有 `recommend_merkle_cardinality_weighted` 的单一固定权重选择）：同时评估多组权重情景，从同一次基数前沿中选择最坏后悔值最小的方案，返回该前沿成员（现有的 `MerkleModeCost` 方案/成本配对对象），不新增值类型、不重复枚举或筛选候选、不改变既有前沿、单一权重推荐及任何旧接口与线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入重复调用结果逐项相同；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`group_sizes` 与六元组 `budgets` 先按 `merkle_cardinality_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `scenarios` 筛查）。`scenarios` 必须为**非空元组**，每项是覆盖总传输（`plan.total`）、单组峰值（`max(plan.sizes)`）、验签哈希总量（`cost.total`）、multiproof 节点数（`nodes`）与单签链步（`profile("merkle", ...).steps`）的五元权重；权重只能是非布尔非负整数，每个情景至少一项为正，重复情景分别计入（权重总和参与归一化）。五项成本按全前沿各自的最小值与最大值归一化（零跨度记 0），全程为精确有理数（`fractions.Fraction`，禁止浮点）；每个情景的加权和除以该情景自身的权重总和作为该情景下的得分。先求每个情景的最优得分，候选得分减去它即为该情景下的后悔值；按各情景最大后悔值（最坏后悔）升序、再按后悔值总和、再按各情景得分元组排序，完全平局时按检查点字节、叶数、`w`、`height` 与逐组模式（`modes`）的字典序取首项。`scenarios` 或其成员非元组、权重成员非整数抛 `TypeError`；空元组、权重组长度不符、含布尔或负数权重、或整项全零抛 `ValueError`；无可行方案也抛 `ValueError`
- `explain_merkle_cardinality_weighted(capacity, group_sizes, budgets, weights)` — 为**叶位置未定**基数工作负载的单一权重推荐 `recommend_merkle_cardinality_weighted` 补上**决策成本明细的导出入口**（基线已有该基数前沿与单一权重推荐入口，但没有明细入口）：在同一次 `merkle_cardinality_frontier` 前沿上逐项给出每个候选的归一化成本与最终评分，返回冻结的 `MerkleCardinalityScore` 行元组，行序与该前沿成员顺序完全一致，不重复枚举或筛选候选、不改变既有前沿、该族既有推荐入口及任何旧接口与线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入结果逐项确定；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`group_sizes` 与六元组 `budgets` 先按 `merkle_cardinality_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `weights` 筛查）。`weights` 必须为五元组，依次对应总传输（`plan.total`）、单组峰值（`max(plan.sizes)`）、验签哈希总量（`cost.total`）、multiproof 节点数（`nodes`）与单签链步（`profile("merkle", ...).steps`），每个成员只能是非布尔非负整数且至少一项为正。每行依次携带该候选的方案成本配对对象（`MerkleModeCost`）、与权重逐位对应的五项归一化成本（各按全前沿最小值与最大值作 `(x-min)/(max-min)` 归一化、零跨度一律记 0）、最终评分（归一化成本乘各自权重求和再除以权重总和）与选中标志，各数值均为 `fractions.Fraction` 精确有理数、禁止浮点。选中标志恰好落在一行，其方案与同参数调用 `recommend_merkle_cardinality_weighted` 的结果逐字段相同；评分完全相同时沿用其决胜尾序（检查点字节、叶数、`w`、`height`、`modes` 字典序升序取首）。全前沿零跨度时各行评分都是零，选中项由决胜尾序决定，明细如实反映。`budgets`/`weights` 非元组或权重成员非整数抛 `TypeError`；容量越界或为布尔、叶数组为空或成员非法、预算长度不符或成员非法或全空、权重长度不符、含布尔或负数、整组全零均抛 `ValueError`；预算下无可行方案同样抛 `ValueError`，不返回任何明细行
- `MerkleCardinalityScore` — 冻结的决策成本明细行值对象，八个字段按位置依次为 `mode_cost, transport_cost, peak_cost, hashes_cost, nodes_cost, steps_cost, score, selected`：候选的方案成本配对对象（`MerkleModeCost`）、与权重逐位对应的五项归一化成本（`Fraction`）、最终评分（`Fraction`）与选中标志（`bool`）；冻结、可位置构造、按值相等（可哈希）
- `explain_merkle_cardinality_weighted_scenarios(capacity, group_sizes, budgets, scenarios)` — 为**叶位置未定**基数工作负载的多情景加权推荐 `recommend_merkle_cardinality_weighted_scenarios` 补上**决策成本明细的导出入口**（基线已有该基数前沿与两类推荐入口，缺多情景版明细，本次从零新增）：在同一次 `merkle_cardinality_frontier` 前沿上逐项给出每个候选的归一化成本、各情景得分与后悔值，返回冻结的 `MerkleCardinalityScenarioScore` 行元组，行序与该前沿成员顺序完全一致，不重复枚举或筛选候选、不改变既有前沿、该族既有推荐入口及任何旧接口与线格式。纯函数：不取随机数、不生成密钥、不改状态，同一输入结果逐项确定；前沿在函数内恰好调用一次。四参数均无默认值；`capacity`、`group_sizes` 与六元组 `budgets` 先按 `merkle_cardinality_frontier` 原规则校验（类型、范围与含边界预算规则、异常与无可行项规则完全沿用，且先于 `scenarios` 筛查），`scenarios` 规则与 `recommend_merkle_cardinality_weighted_scenarios` 完全一致：非空元组，每项是覆盖总传输（`plan.total`）、单组峰值（`max(plan.sizes)`）、验签哈希总量（`cost.total`）、multiproof 节点数（`nodes`）与单签链步（`profile("merkle", ...).steps`）的五元权重，权重只能是非布尔非负整数、每项至少一个正数，重复情景分别计入。每行依次携带该候选的方案成本配对对象（`MerkleModeCost`）、与权重逐位对应的五项归一化成本（各按全前沿最小值与最大值作 `(x-min)/(max-min)` 归一化、零跨度一律记 0）、与情景同序的得分元组（归一化成本乘该情景权重求和再除以该情景权重总和）、与情景同序的后悔值元组（该行得分减去该情景在全前沿上的最优得分）与选中标志，各数值均为 `fractions.Fraction` 精确有理数、禁止浮点。选中标志恰好落在一行，其方案与同参数调用 `recommend_merkle_cardinality_weighted_scenarios` 的结果逐字段相同：沿用最坏后悔最小、后悔值总和与各情景得分元组依次决胜，平局再按既有尾键（检查点字节、叶数、`w`、`height`、`modes` 字典序升序）取首项。`scenarios` 或其成员非元组、权重成员非整数抛 `TypeError`；情景集为空、权重组长度不符、含布尔或负数权重、或整项全零抛 `ValueError`；前沿规则之外的非法输入与预算下无可行方案同样抛 `ValueError`，不返回任何明细行
- `MerkleCardinalityScenarioScore` — 冻结的多情景决策成本明细行值对象，九个字段按位置依次为 `mode_cost, transport_cost, peak_cost, hashes_cost, nodes_cost, steps_cost, scores, regrets, selected`：候选的方案成本配对对象（`MerkleModeCost`）、与权重逐位对应的五项归一化成本（`Fraction`）、与情景同序的得分元组与后悔值元组（各 `Fraction` 元组）及选中标志（`bool`）；冻结、可位置构造、按值相等（可哈希）

指标含义：`capacity` 为一把密钥可签的消息条数；`elements` 为单条（一次性）签名的 32 字节链元素个数；`sig_bytes` 为签名序列化字节数（Merkle 含认证路径，**不含**叶索引与 Python 对象开销）；`path_bytes` 为其中认证路径部分的字节数；`steps` 为验证一条（一次性）签名所需哈希链步数的上界。

```python
from pqattest import (
    profile,
    recommend,
    recommend_scheme,
    recommend_merkle_deployment,
    merkle_deployment_frontier,
    recommend_merkle_deployment_weighted,
    recommend_merkle_deployment_weighted_scenarios,
    MerkleDeploymentScore,
    explain_merkle_deployment_weighted,
    MerkleDeploymentScenarioScore,
    explain_merkle_deployment_weighted_scenarios,
    merkle_storage_profile,
    merkle_transport_profile,
    recommend_merkle_transport_deployment,
    merkle_transport_deployment_frontier,
    recommend_merkle_transport_deployment_weighted,
    recommend_merkle_transport_deployment_weighted_scenarios,
    MerkleTransportDeploymentScore,
    explain_merkle_transport_deployment_weighted,
    recommend_merkle_transport_workload,
    merkle_transport_workload_frontier,
    recommend_merkle_transport_workload_weighted,
    recommend_merkle_transport_workload_weighted_scenarios,
    merkle_mode_frontier,
    recommend_merkle_mode_deployment,
    recommend_merkle_mode_weighted,
    recommend_merkle_mode_weighted_scenarios,
    MerkleModeScore,
    explain_merkle_mode_weighted,
    MerkleModeScenarioScore,
    explain_merkle_mode_weighted_scenarios,
    merkle_verify_profile,
    merkle_verify_workload_profile,
    MerkleModeCost,
    merkle_verify_mode_frontier,
    merkle_cardinality_frontier,
    recommend_merkle_cardinality_deployment,
    recommend_merkle_cardinality_weighted,
    recommend_merkle_cardinality_weighted_scenarios,
    MerkleCardinalityScore,
    explain_merkle_cardinality_weighted,
    MerkleCardinalityScenarioScore,
    explain_merkle_cardinality_weighted_scenarios,
    recommend_merkle_verify_mode_deployment,
    recommend_merkle_verify_mode_deployment_weighted,
    recommend_merkle_verify_mode_weighted,
    MerkleVerifyModeScore,
    explain_merkle_verify_mode_weighted,
    MerkleVerifyModeDeploymentScore,
    explain_merkle_verify_mode_deployment_weighted,
)

profile("wots", w=4)          # Params(..., elements=67, sig_bytes=2144, steps=1005)
params = recommend(100)       # 最小覆盖 100 条的 Merkle 配置：w=8, height=7
signer = MerkleSigner(height=params.height, w=params.w)

# 跨方案统一入口：在 Lamport、W-OTS 与 Merkle 全部候选中按容量与预算选型；
# 预算二元组顺序为 (单签序列化字节, 验签链步上界)，不限的项传 None，至少给一项
recommend_scheme(1, (None, 10**9))
# Params(scheme='wots', w=8, height=None, capacity=1, sig_bytes=1088, steps=8670, ...)
recommend_scheme(1, (None, 10**9), prefer="speed")
# Params(scheme='lamport', ..., sig_bytes=8192, steps=0)；只签一条时速度选 Lamport
recommend_scheme(100, (None, 10**9))
# Params(scheme='merkle', w=8, height=7, capacity=128, ...)；多于一条只剩 Merkle
# 预算过紧无候选（如单签 <= 100 字节）或偏好非法时抛 ValueError；
# budgets 非元组抛 TypeError；capacity/budgets 先于 prefer 校验

merkle_storage_profile(8, 7)
# MerkleStorageProfile(w=8, height=7, leaf_count=128, signature_wire_bytes=1328,
#                      proof_wire_bytes=1388, checkpoint_bytes=139345,
#                      auth_v1_bytes=139391, auth_v2_bytes=139399)
merkle_transport_profile(8, 7, (3, 11, 70))   # (节点数, 批量线长, 多证明线长)

# 覆盖 16 条且单签线长 <= 1.3 KB；顺序为 (检查点, 签名, 证明, 步数)，不限的项传 None
recommend_merkle_deployment(16, (None, 1300, None, None))
# MerkleStorageProfile(w=8, height=4, leaf_count=16, signature_wire_bytes=1232, ...)

# 覆盖 4 条、只限验签步数 <= 9000：speed 先压步数，选 w=4；size 则选签名更短的 w=8
recommend_merkle_deployment(4, (None, None, None, 9000), prefer="speed")
# MerkleStorageProfile(w=4, height=2, ...)；预算过紧、无可行候选时抛 ValueError

# 前沿：同一预算下全部可行且非支配的部署，同时呈现存储、签名、证明与验签
# 成本的取舍，按步数、签名线长、证明线长、检查点、叶数、w、height 升序；
# 无偏好参数，w=4（快）与 w=8（短）的取舍配置都会保留；无可行候选时抛 ValueError
merkle_deployment_frontier(4, (None, None, None, 9000))
# (MerkleStorageProfile(w=4, height=2, ...), MerkleStorageProfile(w=8, height=2, ...))

# 也可给四元组权重（检查点、单签线长、独立证明线长、链步），对同一前沿
# 四项成本 min-max 归一化后加权求和并除以权重总和，Fraction 精确取最小，
# 平局按检查点、叶数、w、height 决胜；权重须为四元组非布尔非负整数且至少一项为正
recommend_merkle_deployment_weighted(
    4, (None, None, None, 9000), (1, 1, 1, 1)
)
# MerkleStorageProfile(w=8, height=2, ...)；只给链步权重 (0, 0, 0, 1) 时选 w=4

# 普通部署前沿的抗偏好漂移版本：同时给多组权重情景（检查点、单签线长、
# 独立证明线长、链步），每情景加权和除以自身权重总和，选最坏后悔值最小者；
# Fraction 精确，无浮点
recommend_merkle_deployment_weighted_scenarios(
    4, (None, None, None, 9000), ((1, 0, 0, 0), (0, 0, 0, 1))
)
# MerkleStorageProfile(w=8, height=2, ...)；重复情景分别计入

# 同一加权推荐的决策成本明细：每个前沿候选一行，行序与前沿一致，依次为
# 配置、四项归一化成本、最终评分与选中标志；恰好一行 selected=True，
# 其配置与 recommend_merkle_deployment_weighted 同参数的结果逐字段相同
explain_merkle_deployment_weighted(
    4, (None, None, None, 9000), (1, 1, 1, 1)
)
# (MerkleDeploymentScore(config=MerkleStorageProfile(w=4, height=2, ...),
#   checkpoint_cost=Fraction(1, 1), signature_cost=Fraction(1, 1),
#   proof_cost=Fraction(1, 1), steps_cost=Fraction(0, 1),
#   score=Fraction(3, 4), selected=False),
#  MerkleDeploymentScore(config=MerkleStorageProfile(w=8, height=2, ...),
#   checkpoint_cost=Fraction(0, 1), signature_cost=Fraction(0, 1),
#   proof_cost=Fraction(0, 1), steps_cost=Fraction(1, 1),
#   score=Fraction(1, 4), selected=True))

# 多情景加权推荐的决策成本明细：每个前沿候选一行，行序与前沿一致，依次为
# 配置、四项归一化成本、与情景同序的得分元组、与情景同序的后悔值元组与
# 选中标志；恰好一行 selected=True，其配置与
# recommend_merkle_deployment_weighted_scenarios 同参数的结果逐字段相同
explain_merkle_deployment_weighted_scenarios(
    4, (None, None, None, 9000), ((1, 0, 0, 0), (0, 0, 0, 1))
)
# (MerkleDeploymentScenarioScore(config=MerkleStorageProfile(w=4, height=2, ...),
#   checkpoint_cost=Fraction(1, 1), signature_cost=Fraction(1, 1),
#   proof_cost=Fraction(1, 1), steps_cost=Fraction(0, 1),
#   scores=(Fraction(1, 1), Fraction(0, 1)),
#   regrets=(Fraction(1, 1), Fraction(0, 1)), selected=False),
#  MerkleDeploymentScenarioScore(config=MerkleStorageProfile(w=8, height=2, ...),
#   checkpoint_cost=Fraction(0, 1), signature_cost=Fraction(0, 1),
#   proof_cost=Fraction(0, 1), steps_cost=Fraction(1, 1),
#   scores=(Fraction(0, 1), Fraction(1, 1)),
#   regrets=(Fraction(0, 1), Fraction(1, 1)), selected=True))

# 联合选择树参数与传输方案：对叶集合 (3, 5) 要求多证明不超过 8 KB，顺序为
# (检查点, 批次证明, 多证明, 步数)，不限的项传 None
recommend_merkle_transport_deployment(16, (3, 5), (None, None, 8000, None))
# MerkleTransportDeploymentProfile(config=MerkleStorageProfile(...), nodes=...,
#                                  batch=..., multi=...)
# prefer="batch" 先压批次线长，prefer="speed" 先压验签步数

# 前沿：同一叶索引组下全部可行且非支配的联合部署，按步数、多证明线长、
# 批次线长、检查点、叶数、w、height 升序；无偏好参数；无可行候选时抛 ValueError
merkle_transport_deployment_frontier(4, (0, 1), (None, None, None, 9000))
# (MerkleTransportDeploymentProfile(config=MerkleStorageProfile(w=4, height=2, ...), ...),
#  MerkleTransportDeploymentProfile(config=MerkleStorageProfile(w=8, height=2, ...), ...))

# 也可给五元组权重（批次证明、多证明、节点数、检查点、链步），对同一前沿
# 五项成本 min-max 归一化后加权求和，Fraction 精确取最小，平局按检查点、
# 叶数、w、height 决胜
recommend_merkle_transport_deployment_weighted(
    16, (3, 5), (None, None, 8000, None), (1, 1, 1, 1, 1)
)
# MerkleTransportDeploymentProfile(config=MerkleStorageProfile(...), nodes=...,
#                                  batch=..., multi=...)

# 单叶集合联合部署的抗偏好漂移版本：同时给多组权重情景（批次证明、多证明、
# 节点数、检查点、链步），每情景加权和除以自身权重总和，选最坏后悔值最小者；
# Fraction 精确，无浮点
recommend_merkle_transport_deployment_weighted_scenarios(
    16, (3, 5), (None, None, 8000, None), ((1, 0, 0, 0, 0), (0, 0, 1, 1, 1))
)
# MerkleTransportDeploymentProfile(config=MerkleStorageProfile(...), nodes=...,
#                                  batch=..., multi=...)

# 单叶集合联合部署单一权重推荐的决策成本明细：每个前沿候选一行，行序与联合
# 部署前沿一致，依次为部署方案、五项归一化成本（批次证明、多证明、节点数、
# 检查点、链步）、最终评分与选中标志；恰好一行 selected=True，其方案与
# recommend_merkle_transport_deployment_weighted 同参数的结果逐字段相同
explain_merkle_transport_deployment_weighted(
    16, (3, 5), (None, None, 8000, None), (1, 1, 1, 1, 1)
)
# (MerkleTransportDeploymentScore(deployment=MerkleTransportDeploymentProfile(...),
#   batch_cost=Fraction(...), multi_cost=Fraction(...),
#   nodes_cost=Fraction(...), checkpoint_cost=Fraction(...),
#   steps_cost=Fraction(...), score=Fraction(...), selected=False),
#  ...,
#  MerkleTransportDeploymentScore(deployment=MerkleTransportDeploymentProfile(...),
#   ..., score=Fraction(...), selected=True))

# 多组工作负载：三个独立叶组共用一棵树，每组各带一份证明；预算顺序为
# (检查点, 单组传输, 总传输, 步数)，不限的项传 None。compact 逐组择短，
# batch/multiproof 固定格式，speed 先压步数
recommend_merkle_transport_workload(
    16, ((0, 1), (3, 5), (8, 9, 10)), (None, 5000, 12000, None)
)
# MerkleTransportWorkloadProfile(config=MerkleStorageProfile(...),
#                                modes=(...), sizes=(...), total=...)

# 前沿：同一工作负载下全部可行且非支配的部署，按步数、总量、检查点、
# 叶数、w、height 升序；无可行候选时抛 ValueError
merkle_transport_workload_frontier(
    16, ((0, 1), (3, 5), (8, 9, 10)), (None, 5000, 12000, None)
)
# (MerkleTransportWorkloadProfile(...), ...)

# 也可给四元组权重（检查点、单组峰值、总传输、单签链步），对同一工作负载
# 前沿四项成本 min-max 归一化后加权求和并除以权重总和，Fraction 精确取
# 最小，平局按检查点、叶数、w、height、modes 决胜
recommend_merkle_transport_workload_weighted(
    16, ((0, 1), (3, 5), (8, 9, 10)), (None, 5000, 12000, None), (1, 1, 1, 1)
)
# MerkleTransportWorkloadProfile(..., modes=(...), sizes=(...), total=...)

# 多组工作负载前沿的抗偏好漂移版本：同时给多组权重情景（检查点、单组峰值、
# 总传输、单签链步），每情景加权和除以自身权重总和，选最坏后悔值最小者；
# Fraction 精确，无浮点
recommend_merkle_transport_workload_weighted_scenarios(
    16,
    ((0, 1), (3, 5), (8, 9, 10)),
    (None, 5000, 12000, None),
    ((1, 0, 0, 0), (0, 0, 0, 1)),
)
# MerkleTransportWorkloadProfile(..., modes=(...), sizes=(...), total=...)

# 模式前沿：逐组枚举全部 batch/multiproof 组合，预算顺序为
# (检查点, 单组峰值, 总传输, 步数, 节点总数)，节点总数只累加 multiproof 组；
# 按步数、总量、峰值、节点、检查点、叶数、w、height、modes 字典序升序
merkle_mode_frontier(
    16, ((0, 1), (3, 5)), (None, 5000, 12000, None, 8)
)
# (MerkleTransportWorkloadProfile(..., modes=("batch", "multiproof"), ...), ...)

# 在模式前沿上按业务偏好取一项：compact 先压总量，nodes 先压多证明节点数，
# speed 先压单签验签步数；末段统一按检查点、叶数、w、height、modes 决胜
recommend_merkle_mode_deployment(
    16, ((0, 1), (3, 5)), (None, 5000, 12000, None, 8), prefer="compact"
)
# MerkleTransportWorkloadProfile(..., modes=("batch", "multiproof"), ...)

# 也可给五元组权重（检查点、单组峰值、总传输、单签链步、节点总数），对同一
# 模式前沿五项成本 min-max 归一化后加权求和并除以权重总和，Fraction 精确取
# 最小，平局按检查点、叶数、w、height、modes 决胜
recommend_merkle_mode_weighted(
    16, ((0, 1), (3, 5)), (None, 5000, 12000, None, 8), (1, 1, 1, 1, 1)
)
# MerkleTransportWorkloadProfile(..., modes=("batch", "multiproof"), ...)

# 模式前沿的抗偏好漂移版本：同时给多组权重情景（检查点、单组峰值、总传输、
# 单签链步、节点总数），每情景加权和除以自身权重总和，选最坏后悔值最小者；
# Fraction 精确，无浮点
recommend_merkle_mode_weighted_scenarios(
    16,
    ((0, 1), (3, 5)),
    (None, 5000, 12000, None, 8),
    ((1, 0, 0, 0, 0), (0, 0, 0, 0, 1)),
)
# MerkleTransportWorkloadProfile(..., modes=("batch", "multiproof"), ...)

# 模式前沿单一权重推荐的决策成本明细：每个前沿候选一行，行序与模式前沿
# 一致，依次为工作负载方案、五项归一化成本（检查点、单组峰值、总传输、
# 单签链步、节点总数）、最终评分与选中标志；恰好一行 selected=True，
# 其方案与 recommend_merkle_mode_weighted 同参数的结果逐字段相同
explain_merkle_mode_weighted(
    16, ((0, 1), (3, 5)), (None, 5000, 12000, None, 8), (1, 1, 1, 1, 1)
)
# (MerkleModeScore(workload=MerkleTransportWorkloadProfile(...),
#   checkpoint_cost=Fraction(...), ..., nodes_cost=Fraction(...),
#   score=Fraction(...), selected=False),
#  ...,
#  MerkleModeScore(workload=MerkleTransportWorkloadProfile(...), ...,
#   score=Fraction(...), selected=True))

# 模式前沿多情景推荐的决策成本明细：每个前沿候选一行，行序与模式前沿
# 一致，依次为工作负载方案、五项归一化成本（检查点、单组峰值、总传输、
# 单签链步、节点总数）、各情景得分元组、各情景后悔值元组与选中标志；
# 恰好一行 selected=True，其方案与 recommend_merkle_mode_weighted_scenarios
# 同参数的结果逐字段相同
explain_merkle_mode_weighted_scenarios(
    16,
    ((0, 1), (3, 5)),
    (None, 5000, 12000, None, 8),
    ((1, 0, 0, 0, 0), (0, 0, 0, 0, 1)),
)
# (MerkleModeScenarioScore(workload=MerkleTransportWorkloadProfile(...),
#   checkpoint_cost=Fraction(...), ..., nodes_cost=Fraction(...),
#   scores=(Fraction(...), Fraction(...)),
#   regrets=(Fraction(...), Fraction(...)), selected=False),
#  ...,
#  MerkleModeScenarioScore(workload=MerkleTransportWorkloadProfile(...), ...,
#   selected=True))

# 验签哈希成本：同一叶集合上批次证明（每份重复完整路径）与多证明（每层
# 每个不同父节点仅哈希一次）的 SHA-256 次数对比；纯估算，不接触任何证明
merkle_verify_profile(8, 3, (0, 1, 6))
# MerkleVerifyProfile(w=8, height=3, k=3, wots=3*34*255, leaf=3,
#                     batch=3*3, multi=|{(0,1,6)>>1}| + |{(0,1,6)>>2}|
#                              + |{(0,1,6)>>3}| = |{0,3}| + |{0,1}| + |{0}|
#                              = 2 + 2 + 1 = 5)

# 多组纯成本汇总：每组各选 batch 或 multiproof，逐组给出 (模式, W-OTS 链步,
# 叶哈希, 内部节点哈希, 本组合计) 并汇总全局 total；重复组分别计费
merkle_verify_workload_profile(
    4, 3, ((0, 1, 6), (0, 1, 6), (5,)), ("batch", "multiproof", "multiproof")
)
# MerkleVerifyWorkloadProfile(w=4, height=3,
#     costs=(("batch", 3*67*15, 3, 9, 3*67*15 + 3 + 9),
#            ("multiproof", 3*67*15, 3, 5, 3*67*15 + 3 + 5),
#            ("multiproof", 67*15, 1, 3, 67*15 + 1 + 3)),
#     total=各组三项哈希总数之和)

# 模式 + 验签哈希联合前沿：逐组枚举全部 batch/multiproof 组合，预算顺序为
# (检查点, 单组峰值, 总传输, 单签步数, multiproof 节点总数, 验签 SHA-256 总数)；
# 每项为 MerkleModeCost(plan, cost, nodes)，按步数、验签总量、传输总量、峰值、
# 节点、检查点、叶数、w、height、modes 字典序升序；无可行项时抛 ValueError
merkle_verify_mode_frontier(
    16, ((0, 1), (3, 5)), (None, 5000, 12000, None, 8, None)
)
# (MerkleModeCost(plan=MerkleTransportWorkloadProfile(..., modes=("batch", "multiproof"), ...),
#                 cost=MerkleVerifyWorkloadProfile(...), nodes=...), ...)

# 叶位置未定时只给每组叶数；六元组预算顺序同上（检查点、单组峰值、总量、链步、节点、验签哈希）
merkle_cardinality_frontier(4, (1, 2), (None, None, None, 9000, None, None))
# 在该前沿上按偏好取一个成员；prefer ∈ compact/verify/nodes/speed/robust
recommend_merkle_cardinality_deployment(
    4, (1, 2), (None, None, None, 9000, None, None), prefer="compact"
)
# 也可给五元组权重（总传输、单组峰值、验签哈希、节点、链步），
# 对前沿五项成本 min-max 归一化后加权求和，Fraction 精确取最小
recommend_merkle_cardinality_weighted(
    4, (1, 2), (None, None, None, 9000, None, None), (1, 1, 1, 1, 1)
)
# 叶位置未定工作负载的抗偏好漂移版本：同时给多组权重情景（总传输、单组峰值、
# 验签哈希、节点、链步），每情景加权和除以自身权重总和，选最坏后悔值最小者；
# Fraction 精确，无浮点
recommend_merkle_cardinality_weighted_scenarios(
    4,
    (1, 2),
    (None, None, None, 9000, None, None),
    ((1, 0, 0, 0, 0), (0, 0, 1, 1, 1)),
)
# 叶位置未定工作负载单一权重推荐的决策成本明细：每个前沿候选一行，行序与
# 基数前沿一致，依次为方案成本配对、五项归一化成本、最终评分与选中标志；
# 恰好一行 selected=True，其方案与 recommend_merkle_cardinality_weighted
# 同参数的结果逐字段相同
explain_merkle_cardinality_weighted(
    4, (1, 2), (None, None, None, 9000, None, None), (1, 1, 1, 1, 1)
)
# (MerkleCardinalityScore(mode_cost=MerkleModeCost(...),
#   transport_cost=Fraction(...), ..., steps_cost=Fraction(...),
#   score=Fraction(...), selected=False),
#  ...,
#  MerkleCardinalityScore(mode_cost=MerkleModeCost(...), ..., selected=True))
# 叶位置未定工作负载多情景推荐的决策成本明细：每个前沿候选一行，行序与
# 基数前沿一致，依次为方案成本配对、五项归一化成本、各情景得分元组、
# 各情景后悔值元组与选中标志；恰好一行 selected=True，其方案与
# recommend_merkle_cardinality_weighted_scenarios 同参数的结果逐字段相同
explain_merkle_cardinality_weighted_scenarios(
    4,
    (1, 2),
    (None, None, None, 9000, None, None),
    ((1, 0, 0, 0, 0), (0, 0, 1, 1, 1)),
)
# (MerkleCardinalityScenarioScore(mode_cost=MerkleModeCost(...),
#   transport_cost=Fraction(...), ..., steps_cost=Fraction(...),
#   scores=(Fraction(...), Fraction(...)),
#   regrets=(Fraction(...), Fraction(...)), selected=False),
#  ...,
#  MerkleCardinalityScenarioScore(mode_cost=MerkleModeCost(...), ..., selected=True))
# 固定叶位置工作负载按偏好取一个成员；prefer ∈ compact/verify/nodes/speed/robust
recommend_merkle_verify_mode_deployment(
    16, ((0, 1), (3, 5)), (None, 5000, 12000, None, 8, None), prefer="compact"
)
# 固定叶位置工作负载的单一权重版本：给五元组权重（总传输、单组峰值、验签哈希、
# 节点、链步），对前沿五项成本 min-max 归一化后加权求和再除以权重总和，
# Fraction 精确取最小；只点亮一维即取该维成本最小者
recommend_merkle_verify_mode_deployment_weighted(
    16,
    ((0, 1), (3, 5)),
    (None, 5000, 12000, None, 8, None),
    (1, 1, 1, 1, 1),
)
# MerkleModeCost(plan=MerkleTransportWorkloadProfile(...), cost=MerkleVerifyWorkloadProfile(...), nodes=...)
# 固定叶位置工作负载的抗偏好漂移版本：同时给多组权重情景（总传输、单组峰值、
# 验签哈希、节点、链步），选各情景下最坏后悔值最小者；Fraction 精确，无浮点
recommend_merkle_verify_mode_weighted(
    16,
    ((0, 1), (3, 5)),
    (None, 5000, 12000, None, 8, None),
    ((1, 0, 0, 0, 0), (0, 0, 1, 1, 1)),
)
# MerkleModeCost(plan=MerkleTransportWorkloadProfile(...), cost=MerkleVerifyWorkloadProfile(...), nodes=...)
# 同一多情景推荐的决策成本明细：每个前沿候选一行，行序与前沿一致，依次为
# 方案成本配对、五项归一化成本、各情景得分元组、各情景后悔值元组与选中标志；
# 恰好一行 selected=True，其方案与 recommend_merkle_verify_mode_weighted
# 同参数的结果逐字段相同
explain_merkle_verify_mode_weighted(
    16,
    ((0, 1), (3, 5)),
    (None, 5000, 12000, None, 8, None),
    ((1, 0, 0, 0, 0), (0, 0, 1, 1, 1)),
)
# (MerkleVerifyModeScore(mode_cost=MerkleModeCost(...),
#   transport_cost=Fraction(...), ..., steps_cost=Fraction(...),
#   scores=(Fraction(...), Fraction(...)),
#   regrets=(Fraction(...), Fraction(...)), selected=False),
#  ...,
#  MerkleVerifyModeScore(mode_cost=MerkleModeCost(...), ..., selected=True))
# 固定叶位置工作负载单一权重推荐的决策成本明细：每个前沿候选一行，
# 行序与前沿一致，依次为方案成本配对、五项归一化成本、最终评分与选中
# 标志；恰好一行 selected=True，其方案与
# recommend_merkle_verify_mode_deployment_weighted 同参数的结果逐字段相同
explain_merkle_verify_mode_deployment_weighted(
    16,
    ((0, 1), (3, 5)),
    (None, 5000, 12000, None, 8, None),
    (1, 1, 1, 1, 1),
)
# (MerkleVerifyModeDeploymentScore(mode_cost=MerkleModeCost(...),
#   transport_cost=Fraction(...), ..., steps_cost=Fraction(...),
#   score=Fraction(...), selected=False),
#  ...,
#  MerkleVerifyModeDeploymentScore(mode_cost=MerkleModeCost(...), ...,
#   score=Fraction(...), selected=True))
```

推荐策略：先按要签的消息条数定 `capacity`，`recommend` 给出能覆盖它的最小树高；签名体积敏感（默认）用 `w=8`，验证/签名速度敏感用 `prefer="speed"` 换 `w=4`——后者签名约大一倍，但链步上界从 `34×255=8670` 降到 `67×15=1005`。

## 限制

玩具格基 KEM 是为讲解 KEM 外形（keygen/encapsulate/decapsulate、密钥确认 tag）而写的极简模型，**未经过安全审计且结构性地不安全**：私钥与公钥是同一个向量（无单向函数、无噪声、无陷门），任何人都能从公钥直接还原私钥；16 字节、模 257 的参数也无任何安全裕度。**仅供教学，严禁用于任何真实系统。**

Lamport 与 W-OTS 构造都是纯一次性签名：**同一密钥对签第二条消息就会同时暴露多个链位置的哈希原像（Lamport 为两个分支的秘密），签名即可被伪造**。无状态的 `sign`/`wots_sign` 不阻止也不检测重复使用；Lamport 可用 `OneTimeSigner`、W-OTS 可用 `WOTSOneTimeSigner` 在进程内防护，两者都可经 `checkpoint()`/`from_checkpoint()` 跨进程恢复同一私钥及 `used` 状态。Merkle 构造把上限提高到 `2**height` 条消息，但每签一条就永久消耗一片叶子；`MerkleSigner` 在进程内跟踪已用叶子，跨进程持久化同样由调用方通过 `checkpoint()`/`from_checkpoint()` 完成——检查点明文包含私钥且校验值不提供认证，安全存储、每次签名后原子更新、绝不回滚旧检查点的责任都在调用方，回滚即造成一次性密钥重用。参数固定为 SHA-256 安全级：Lamport 为 256 位（签名 256 × 32 = 8 KB）；W-OTS 仅提供 `w ∈ {4, 8}` 两档尺寸/速度权衡，链元素固定 32 字节，不含针对多消息或可变安全裕度的参数。

## 测试

```bash
python3 -m unittest discover -s tests
```

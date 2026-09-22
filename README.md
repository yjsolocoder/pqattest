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
- `MerkleSigner.from_auth_state(data, *, key, min_generation=None)` — 类方法：一步完成 v2 验签、代次下限检查与 v1 检查点恢复的认证恢复入口，不取随机数。`data` 只接受 README 既定 `auth_state_wrap` v2 封装（魔数 `PQAAUTH\0`、版本 2、方案标识 3、8 字节大端代次、4 字节大端载荷长度、原 v1 检查点、末尾 32 字节 `HMAC-SHA-256` 标签），`key` 与 `min_generation` 仅限关键字。返回 `(signer, generation)`：恢复的 `MerkleSigner`（公钥、`next_index` 与用尽语义同 `from_checkpoint`）和封装内的非负整数代次；下限仍由调用方外部可信存储维护。检查顺序固定：先按现有 v2 规则验证 HMAC，再固定要求方案为 `merkle` 并检查代次下限，最后把原样载荷交给 `from_checkpoint`，仅全部成功后构造实例。`data`、`key` 非 `bytes`/`bytearray`，或 `min_generation` 非 `None` 且非 uint64 非布尔整数时抛 `TypeError`；空密钥、下限越界、认证/方案/下限或检查点非法抛 `ValueError`，且不返回实例
- `merkle_verify(message, signature, public_key)` — 由签名恢复 W-OTS 公钥、算出叶哈希，再按 `index` 的各位把认证路径逐层折回根并比对；公钥类型错误抛 `TypeError`，其余畸形、越界或不匹配一律返回 `False`（包括绕过冻结构造器造成的字段缺失、类型/范围错误或元素、路径畸形）
- `MerkleProof(public_key, signature)` — 冻结的证明值对象，字段须分别为 `MerklePublicKey` 与 `MerkleSignature`（字段类型错误抛 `TypeError`，签名参数/计数与公钥不一致抛 `ValueError`）；把一把公钥和一份签名打包成一份可**独立传输**的证明。证明包不存消息，本身不提供认证或加密
- `MerkleProof.to_bytes()` / `MerkleProof.from_bytes(data)` — 证明包的版本化二进制编解码；编码确定、同值同字节。`from_bytes` 只接受 `bytes`/`bytearray`（其他类型抛 `TypeError`），解析时先恢复包内公钥、再以它约束签名；魔数、版本、长度越界或与内容不符、截断、尾随数据、嵌套编码非法或公钥与签名交叉不一致均抛 `ValueError`，不返回半有效对象
- `MerkleProof.verify(message)` — 接受 `bytes`/`bytearray`/`str`，等价于 `merkle_verify(message, proof.signature, proof.public_key)`；只对被签署的消息返回 `True`，消息、公钥或签名被改动后返回 `False`（非法消息类型返回 `False`）
- `MerkleBatchProof(public_key, signatures)` — 冻结的批次证明值对象：`public_key` 须为 `MerklePublicKey`，`signatures` 须为**非空**的 `MerkleSignature` 元组，索引严格递增（故唯一）且每份签名都与该公钥参数/计数一致（字段类型错误抛 `TypeError`，结构约束违反抛 `ValueError`）；把同一公钥的多份签名打包成一份可**独立传输**的批次证明。批次包不存消息，本身不提供认证或加密
- `MerkleBatchProof.to_bytes()` / `MerkleBatchProof.from_bytes(data)` — 批次证明的版本化二进制编解码；编码确定、同值同字节。`from_bytes` 只接受 `bytes`/`bytearray`（其他类型抛 `TypeError`），解析时先恢复包内公钥、再以它约束每份签名；魔数、版本、长度/计数越界或为零、截断、尾随数据、嵌套编码非法、签名与公钥交叉不一致或索引非严格递增均抛 `ValueError`，不返回半有效对象
- `MerkleBatchProof.verify(messages)` — `messages` 须为与签名等长的元组，成员接受 `bytes`/`bytearray`/`str`；逐项等价于 `merkle_verify(message, signature, public_key)`，全部成功才返回 `True`；非元组、数量不符、非法消息成员或任一验签失败均返回 `False`
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

auth_state_unwrap(blob, key=b"shared-secret", min_generation=8)  # ValueError：回滚
```

Merkle 检查点也可以用 `MerkleSigner.from_auth_state` 一步完成验签、下限检查与恢复：

```python
restored, generation = MerkleSigner.from_auth_state(
    blob, key=b"shared-secret", min_generation=7
)
assert generation == 7 and restored.public_key == signer.public_key
```

**代次安全边界**：下限 `min_generation` **不由封装携带**，必须保存在调用方的外部可信存储中（随每次接受的新一代次原子推进），并与封装/检查点分开保管。代次只对「检查点回滚、但可信下限没有一并回退」的情形有效：攻击者若能把检查点和可信下限**一起**回滚，或者在**同一代次内**重放一份合法封装，HMAC 依然有效、无从检测。与 v1 相同，v2 封装**不加密**，载荷是明文，也不防复制；须把封装连同明文检查点一起当秘密保管。



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
- `recommend_merkle_deployment(capacity, budgets, prefer="size")` — 在部署预算内选可行 Merkle 参数，返回 `MerkleStorageProfile`。纯函数：不取随机数、不生成密钥、不改状态。`capacity` 限 1 至 256 的非布尔整数；`budgets` 必须为四元组，按顺序分别为检查点字节（对应 `checkpoint_bytes`）、单签线长（`signature_wire_bytes`）、独立证明线长（`proof_wire_bytes`）、验签链步数（`profile("merkle", ...).steps`）的上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 全部候选：叶数须覆盖 `capacity`，字节上限按 `merkle_storage_profile` 字段比较，步数上限按 `profile` 返回的 `steps` 比较。`size` 依次最小化签名线长、证明线长、检查点、步数、叶数、`w`、`height`；`speed` 先最小化步数，再沿用前述其余顺序；取排序首项。`budgets` 非元组抛 `TypeError`；其长度或成员非法、`capacity`/`prefer` 非法、无可行候选均抛 `ValueError`
- `merkle_deployment_frontier(capacity, budgets)` — 与 `recommend_merkle_deployment` 同一组候选与预算，但**不排序取首项**，而是返回全部可行且非支配的普通 Merkle 部署，类型为 `tuple[MerkleStorageProfile, ...]`，不新增值类型。纯函数：不取随机数、不生成密钥、不改状态，且无默认参数。`capacity` 限 1 至 256 的非布尔整数；`budgets` 必须为四元组，按顺序分别为检查点字节（`checkpoint_bytes`）、单签线长（`signature_wire_bytes`）、独立证明线长（`proof_wire_bytes`）及单签验签步数（`profile("merkle", ...).steps`）的含边界上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 中叶数覆盖 `capacity` 的全部候选，配置取 `merkle_storage_profile`、步数取 `profile` 的 Merkle 结果。支配判定固定为：A 在检查点字节、签名线长、证明线长、单签步数四项上均不大于 B 且至少一项严格更小，则 A 支配 B；删除全部被支配候选并按值去重，不因偏好预先舍弃速度与尺寸形成取舍的配置。结果按单签步数、签名线长、证明线长、检查点字节、叶数、`w`、`height` 稳定升序排列。`budgets` 非元组抛 `TypeError`；其余非法输入或无可行候选抛 `ValueError`
- `MerkleStorageProfile` — 冻结的 Merkle 线长估算值对象，八个字段均为 `int` 且按位置依次为 `w, height, leaf_count, signature_wire_bytes, proof_wire_bytes, checkpoint_bytes, auth_v1_bytes, auth_v2_bytes`；冻结、可位置构造、按值相等（可哈希）
- `merkle_storage_profile(w, height)` — 纯函数：返回 `(w, height)` 对应的 `MerkleStorageProfile`，不生成密钥、不取随机数。`w` 限 4/8，`height` 限 1 至 8 非布尔整数，非法抛 `ValueError`。令 `n = 67/34`（对应 `w = 4/8`）、`L = 2**height`、`S = 16 + 32*(n+height)`、`C = 81 + 32*L*n`：前四字段为 `w, height, L, S`，后四字段 `proof_wire_bytes, checkpoint_bytes, auth_v1_bytes, auth_v2_bytes` 依次为 `S+60, C, C+46, C+54`，分别对应 `MerkleProof` 线长、明文检查点、v1 封装、v2 封装
- `merkle_transport_profile(w, height, indices)` — 纯函数：为同一叶集合估算批量证明与多证明线长，返回三元组 `(m, 58+k*(4+S), 60+k*(4+32*n)+35*m)`，分别为多证明携带的节点数 `m`、批量证明线长、多证明线长，其中 `k = len(indices)`，`m` 按既有多证明规范计入集合外兄弟并逐级右移去重。`indices` 必须为非空、严格递增的整数元组，成员均在 `0 .. 2**height-1`；容器或成员类型错抛 `TypeError`，空元组、布尔成员、越界或非严格递增抛 `ValueError`；`w`/`height` 非法同样抛 `ValueError`
- `recommend_merkle_transport_deployment(capacity, indices, budgets, prefer="multiproof")` — 在预算内**联合**选择树参数与传输方案，返回 `MerkleTransportDeploymentProfile`。纯函数：不取随机数、不生成密钥、不改状态。`capacity` 限 1 至 256 的非布尔整数；`indices` 必须为非空、严格递增的非布尔整数元组，最大成员须小于候选树叶数；`budgets` 必须为四元组，按顺序分别为检查点字节、批次证明字节、多证明字节及单签验签步数（`profile("merkle", ...).steps`）的上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 全部候选：叶数须同时覆盖 `capacity` 与 `indices`，尺寸与步数均复用 `merkle_storage_profile`、`merkle_transport_profile` 与 `profile`。`prefer` 取 `"multiproof"`/`"batch"`/`"speed"`：主排序键分别为多证明字节、批次字节、步数；前两者次键取另一传输线长（multiproof 先多证明后批次，batch 反之），speed 依次再多证明字节、批次字节；三种偏好末段均按检查点字节、叶数、`w`、`height` 升序取首项。`indices`/`budgets` 容器类型错抛 `TypeError`，其余非法输入（含非整数或布尔索引成员）或无可行候选抛 `ValueError`
- `MerkleTransportDeploymentProfile` — 冻结的联合部署选择值对象，四个字段按位置依次为 `config, nodes, batch, multi`，类型依次为 `MerkleStorageProfile, int, int, int`：所选配置、多证明节点数、批次证明字节数、多证明字节数；冻结、可位置构造、按值相等（可哈希）
- `merkle_transport_deployment_frontier(capacity, indices, budgets)` — 与 `recommend_merkle_transport_deployment` 同一组候选与预算，但**不排序取首项**，而是返回全部可行且非支配的联合部署，类型为 `tuple[MerkleTransportDeploymentProfile, ...]`，不新增值类型。纯函数：不取随机数、不生成密钥、不改状态，且无默认参数。`capacity` 限 1 至 256 的非布尔整数；`indices` 必须为非空、严格递增的非负非布尔整数元组，候选树叶数须同时覆盖 `capacity` 与最大索引加一；`budgets` 必须为四元组，按顺序分别为检查点字节、批次证明字节、多证明字节及单签验签步数（`profile("merkle", ...).steps`）的含边界上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 全部候选，配置取 `merkle_storage_profile`、批次/多证明与节点数取 `merkle_transport_profile`、步数取 `profile`。支配判定固定为：A 在检查点字节、批次证明字节、多证明字节、单签步数四项上均不大于 B 且至少一项严格更小，则 A 支配 B（节点数仅作输出，不参与支配）；删除全部被支配候选并按值去重，不因偏好预先舍弃速度与传输尺寸形成取舍的配置。结果按单签步数、多证明字节、批次证明字节、检查点字节、叶数、`w`、`height` 稳定升序排列。`indices`/`budgets` 非元组抛 `TypeError`；其余非法输入或无可行候选抛 `ValueError`
- `recommend_merkle_transport_workload(capacity, groups, budgets, prefer="compact")` — 把联合选择推广到**多个独立叶索引组**：每组各自携带一份批次证明或多证明，但共用同一棵 Merkle 树与同一 `(w, height)` 配置；返回 `MerkleTransportWorkloadProfile`。纯函数：不取随机数、不生成密钥、不改状态。`capacity` 限 1 至 256 的非布尔整数；`groups` 必须为非空元组，每个成员本身也是非空、严格递增的非负非布尔整数元组（一组叶索引），所选树的叶数须同时覆盖 `capacity` 与每组的最大索引加一。`budgets` 必须为四元组，按顺序分别为检查点字节、**单组**传输字节（每组所选格式线长均不得超过）、**总传输字节**（各组线长之和）及单签验签步数（`profile("merkle", ...).steps`）的上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 全部候选，尺寸与步数均复用 `merkle_storage_profile`、`merkle_transport_profile` 与 `profile`。`prefer="compact"`（默认）与 `"speed"` 均逐组取批次/多证明中**更短**者、等长取 `"multiproof"`；`"batch"` 与 `"multiproof"` 各组固定使用同名格式。配置排序：`"speed"` 先按验签步数、再按总传输字节，其余三种偏好先按总传输字节；四种偏好末段均按检查点字节、叶数、`w`、`height` 升序取首项。`groups`/`budgets`（含成员组本身）容器类型错抛 `TypeError`，其余非法输入或无可行候选抛 `ValueError`
- `MerkleTransportWorkloadProfile` — 冻结的多组工作负载选择值对象，四个字段按位置依次为 `config, modes, sizes, total`，类型依次为 `MerkleStorageProfile`、`str` 元组、`int` 元组、`int`：所选配置、每组的传输格式名（`"batch"` 或 `"multiproof"`，与输入组同序）、各组所选格式的线长（与 `modes` 逐位对齐）及各组长之和；冻结、可位置构造、按值相等（可哈希）
- `merkle_transport_workload_frontier(capacity, groups, budgets)` — 与 `recommend_merkle_transport_workload` 同一工作负载，但**不排序取首项**，而是返回全部可行且非支配的部署，类型为 `tuple[MerkleTransportWorkloadProfile, ...]`，不新增值类型。纯函数：不取随机数、不生成密钥、不改状态，且无默认参数。`capacity` 限 1 至 256 的非布尔整数；`groups` 必须为非空元组，每个成员本身也是非空、严格递增的非负非布尔整数元组；`budgets` 必须为四元组，按顺序分别为检查点字节、单组传输字节、总传输字节及单签验签步数（`profile("merkle", ...).steps`）的上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 全部候选，配置与步数取 `merkle_storage_profile` 与 `profile`，逐组以 `merkle_transport_profile` 取批次/多证明中更短的线长、等长取 `"multiproof"`，四项预算均须满足。支配判定：A 的 `config.checkpoint_bytes`、`total`、单签 `steps` 均不大于 B 且至少一项严格更小，则 A 支配 B；删除全部被支配项并按值去重。结果按步数、总量、检查点、叶数、`w`、`height` 稳定升序排列。`groups`/`budgets`（含成员组本身）容器类型错抛 `TypeError`，其余非法输入或无可行候选抛 `ValueError`
- `merkle_mode_frontier(capacity, groups, budgets)` — 与 `merkle_transport_workload_frontier` 同一工作负载，但**逐组枚举全部 `batch`/`multiproof` 模式组合**（每组两种，共 `2**len(groups)` 种，均参与预算筛选），返回全部可行且非支配的模式选择，类型为 `tuple[MerkleTransportWorkloadProfile, ...]`，各项沿用 `config, modes, sizes, total` 字段，`modes` 与 `sizes` 按组对齐，`total` 为各组线长之和，不新增值类型。纯函数：不取随机数、不生成密钥、不改状态，且无默认参数。`capacity` 限 1 至 256 的非布尔整数；`groups` 必须为非空元组，每个成员本身也是非空、严格递增的非负非布尔整数元组；`budgets` 必须为**五元组**，按顺序分别为检查点字节、单组峰值（`sizes` 中的最大值）、总传输字节、单签验签步数（`profile("merkle", ...).steps`）及**节点总数**（仅累加 multiproof 组的规范节点数，batch 组计 0）的含边界上限，各项为 `None`（不限）或正的非布尔整数，且至少一项非空。枚举 `w=4/8` × `height=1..8` 中叶数覆盖 `capacity` 与各组最大索引的全部候选，尺寸、节点数与步数均复用 `merkle_storage_profile`、`merkle_transport_profile` 与 `profile`。支配判定：A 在检查点字节、单组峰值、总量、单签步数、节点总数五项成本上均不大于 B 且至少一项严格更小，则 A 支配 B；删除全部被支配项并按值去重，不因偏好预先舍弃尺寸与节点数形成取舍的组合。结果按单签步数、总量、单组峰值、节点总数、检查点字节、叶数、`w`、`height`、`modes` 字典序稳定升序排列。`groups`/`budgets`（含成员组本身）容器类型错抛 `TypeError`，其余非法输入或无可行候选抛 `ValueError`
- `recommend_merkle_mode_deployment(capacity, groups, budgets, prefer="compact")` — 在 `merkle_mode_frontier` 的非支配结果上**按业务偏好选出一个模式组合**，返回现有的 `MerkleTransportWorkloadProfile`，不新增值类型、不改变任何线格式。纯函数：不取随机数、不生成密钥、不改状态。前三参数无默认值；`capacity`、`groups` 与五元组 `budgets` 完全沿用 `merkle_mode_frontier` 的类型、范围、预算及异常规则，无可行项抛 `ValueError`。`prefer` 仅取 `"compact"`（默认）、`"nodes"` 或 `"speed"`，其他值抛 `ValueError`。排序键：`"compact"` 依次按 `total`、单组峰值（`max(sizes)`）、节点总数、单签步数升序；`"nodes"` 依次按节点总数、`total`、单组峰值、单签步数升序；节点总数沿用模式前沿定义，仅累加 multiproof 组的规范节点数；`"speed"` 依次按单签步数、`total`、单组峰值、节点总数升序。三种策略末段统一按检查点字节、叶数、`w`、`height`、`modes` 字典序升序取首项。`groups`/`budgets`（含成员组本身）容器类型错抛 `TypeError`，其余非法输入抛 `ValueError`

指标含义：`capacity` 为一把密钥可签的消息条数；`elements` 为单条（一次性）签名的 32 字节链元素个数；`sig_bytes` 为签名序列化字节数（Merkle 含认证路径，**不含**叶索引与 Python 对象开销）；`path_bytes` 为其中认证路径部分的字节数；`steps` 为验证一条（一次性）签名所需哈希链步数的上界。

```python
from pqattest import (
    profile,
    recommend,
    merkle_deployment_frontier,
    merkle_storage_profile,
    merkle_transport_profile,
    recommend_merkle_transport_deployment,
    merkle_transport_deployment_frontier,
    recommend_merkle_transport_workload,
    merkle_transport_workload_frontier,
    merkle_mode_frontier,
    recommend_merkle_mode_deployment,
)

profile("wots", w=4)          # Params(..., elements=67, sig_bytes=2144, steps=1005)
params = recommend(100)       # 最小覆盖 100 条的 Merkle 配置：w=8, height=7
signer = MerkleSigner(height=params.height, w=params.w)

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
```

推荐策略：先按要签的消息条数定 `capacity`，`recommend` 给出能覆盖它的最小树高；签名体积敏感（默认）用 `w=8`，验证/签名速度敏感用 `prefer="speed"` 换 `w=4`——后者签名约大一倍，但链步上界从 `34×255=8670` 降到 `67×15=1005`。

## 限制

玩具格基 KEM 是为讲解 KEM 外形（keygen/encapsulate/decapsulate、密钥确认 tag）而写的极简模型，**未经过安全审计且结构性地不安全**：私钥与公钥是同一个向量（无单向函数、无噪声、无陷门），任何人都能从公钥直接还原私钥；16 字节、模 257 的参数也无任何安全裕度。**仅供教学，严禁用于任何真实系统。**

Lamport 与 W-OTS 构造都是纯一次性签名：**同一密钥对签第二条消息就会同时暴露多个链位置的哈希原像（Lamport 为两个分支的秘密），签名即可被伪造**。无状态的 `sign`/`wots_sign` 不阻止也不检测重复使用；Lamport 可用 `OneTimeSigner`、W-OTS 可用 `WOTSOneTimeSigner` 在进程内防护，两者都可经 `checkpoint()`/`from_checkpoint()` 跨进程恢复同一私钥及 `used` 状态。Merkle 构造把上限提高到 `2**height` 条消息，但每签一条就永久消耗一片叶子；`MerkleSigner` 在进程内跟踪已用叶子，跨进程持久化同样由调用方通过 `checkpoint()`/`from_checkpoint()` 完成——检查点明文包含私钥且校验值不提供认证，安全存储、每次签名后原子更新、绝不回滚旧检查点的责任都在调用方，回滚即造成一次性密钥重用。参数固定为 SHA-256 安全级：Lamport 为 256 位（签名 256 × 32 = 8 KB）；W-OTS 仅提供 `w ∈ {4, 8}` 两档尺寸/速度权衡，链元素固定 32 字节，不含针对多消息或可变安全裕度的参数。

## 测试

```bash
python3 -m unittest discover -s tests
```

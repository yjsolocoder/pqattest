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
- `MerkleSigner.checkpoint()` — 把完整签名状态（含**全部私钥**）序列化为 `bytes`；与 `sign` 共用同一把锁，并发快照只会落在某次签名之前或之后，不会落在签名中途
- `MerkleSigner.from_checkpoint(data)` — 从检查点恢复签名器，不取随机数；公钥与原签名器相同，下一次 `sign` 从保存的 `next_index` 继续，用尽状态恢复后仍抛 `KeyExhaustedError`。`data` 只接受 `bytes`/`bytearray`，其他类型抛 `TypeError`；魔数、版本、长度、`w`、树高、`next_index` 越界（允许 `0 <= next_index <= 2**height`）、元素数量、校验值非法，或由私钥重建的 Merkle 根不符，均抛 `ValueError` 且不返回实例
- `merkle_verify(message, signature, public_key)` — 由签名恢复 W-OTS 公钥、算出叶哈希，再按 `index` 的各位把认证路径逐层折回根并比对；公钥类型错误抛 `TypeError`，其余畸形、越界或不匹配一律返回 `False`（包括绕过冻结构造器造成的字段缺失、类型/范围错误或元素、路径畸形）
- `MerkleProof(public_key, signature)` — 冻结的证明值对象，字段须分别为 `MerklePublicKey` 与 `MerkleSignature`（字段类型错误抛 `TypeError`，签名参数/计数与公钥不一致抛 `ValueError`）；把一把公钥和一份签名打包成一份可**独立传输**的证明。证明包不存消息，本身不提供认证或加密
- `MerkleProof.to_bytes()` / `MerkleProof.from_bytes(data)` — 证明包的版本化二进制编解码；编码确定、同值同字节。`from_bytes` 只接受 `bytes`/`bytearray`（其他类型抛 `TypeError`），解析时先恢复包内公钥、再以它约束签名；魔数、版本、长度越界或与内容不符、截断、尾随数据、嵌套编码非法或公钥与签名交叉不一致均抛 `ValueError`，不返回半有效对象
- `MerkleProof.verify(message)` — 接受 `bytes`/`bytearray`/`str`，等价于 `merkle_verify(message, proof.signature, proof.public_key)`；只对被签署的消息返回 `True`，消息、公钥或签名被改动后返回 `False`（非法消息类型返回 `False`）

构造细节：叶哈希为 `SHA256(b"pqattest/leaf" + bytes([w]) + 公钥元素串)`；内部节点为 `SHA256(b"pqattest/node" + 左 + 右)`；所有节点 32 字节。

检查点 v1 二进制格式：8 字节魔数 `b"PQAMSCP\0"`；各 1 字节的版本（1）、`w`、`height`；2 字节大端 `next_index`；4 字节大端元素总数（必须等于 `2**height` 乘 `w` 对应的链数）；32 字节 Merkle 根；随后按叶、链顺序排列的全部 W-OTS 私钥元素（每个 32 字节）；最后为此前全部内容的 SHA-256。

W-OTS 一次性签名器检查点 v1 二进制格式（`WOTSOneTimeSigner.checkpoint`）：8 字节魔数 `b"PQAWCP\0\0"`；各 1 字节的版本（1）、`w`、`used`（仅 0 或 1）；2 字节大端私钥元素数（由 `w` 严格限定：`w=4` 为 67、`w=8` 为 34）；随后按原链序排列的全部 32 字节私钥元素；最后为此前全部内容的 SHA-256。总长度为 `13 + 元素数 × 32 + 32` 字节（w=4 时 2189 字节，w=8 时 1133 字节）。

W-OTS 密钥与签名 v1 线格式（`WOTSPrivateKey.to_bytes` / `WOTSPublicKey.to_bytes` / `wots_signature_to_bytes`）：三种格式结构相同——8 字节魔数（私钥 `b"PQAWPRV\0"`、公钥 `b"PQAWPUB\0"`、签名 `b"PQAWSIG\0"`）；各 1 字节的版本（1）与 `w`；2 字节大端元素数（由 `w` 严格限定：`w=4` 为 67、`w=8` 为 34）；随后按原序拼接全部 32 字节元素。总长度为 `12 + 元素数 × 32` 字节（w=4 时 2156 字节，w=8 时 1100 字节）。编码确定、同值同字节；私钥编码含明文秘密。

公钥 v1 线格式（`MerklePublicKey.to_bytes`，固定 43 字节）：8 字节魔数 `b"PQAMPK\0\0"`；各 1 字节的版本（1）、`w`、`height`；32 字节 Merkle 根。

签名 v1 线格式（`MerkleSignature.to_bytes(public_key)`）：8 字节魔数 `b"PQAMSIG\0"`；各 1 字节的版本（1）、`w`、`height`；2 字节大端叶索引；2 字节大端 W-OTS 元素数（等于 `w` 对应的链数）；1 字节路径数（等于树高）；随后依次是全部 W-OTS 签名元素和**自叶层向根层**排列的认证路径节点，每项 32 字节。总长度为 `16 + (元素数 + 树高) × 32` 字节。

证明包 v1 线格式（`MerkleProof.to_bytes`）：8 字节魔数 `b"PQAMPRF\0"`；1 字节版本（1）；4 字节大端公钥长度；4 字节大端签名长度；随后先拼接完整的公钥 v1 编码，再拼接以该公钥约束的签名 v1 编码（即上面两种既有编码原样串联，证明包不另造单体编码）。长度字段必须与各自编码的实际内容一致；解析顺序固定为先公钥、后签名，签名始终由同包内刚恢复的公钥约束。总长度为 `17 + 公钥编码长度 + 签名编码长度` 字节。

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

**检查点安全须知**：检查点明文包含私钥（Merkle 为整棵树的全部 W-OTS 私钥），末尾的 SHA-256 校验值只能发现意外损坏，**不提供认证或加密**——任何拿到检查点的人都能伪造签名。调用方必须把它当私钥一样安全存储，并在每次成功签名后**原子地**持久化新检查点（如写临时文件再 rename）；复制检查点或在不同进程间共享会让同一把一次性私钥被多次使用，风险由调用方承担。回滚到旧检查点会让状态倒退：对 `WOTSOneTimeSigner` 是已用标志复位、对 `MerkleSigner` 是 `next_index` 倒退、已消耗的叶子被再次分配，二者都造成一次性密钥重用，签名即可被伪造。

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

指标含义：`capacity` 为一把密钥可签的消息条数；`elements` 为单条（一次性）签名的 32 字节链元素个数；`sig_bytes` 为签名序列化字节数（Merkle 含认证路径，**不含**叶索引与 Python 对象开销）；`path_bytes` 为其中认证路径部分的字节数；`steps` 为验证一条（一次性）签名所需哈希链步数的上界。

```python
from pqattest import profile, recommend

profile("wots", w=4)          # Params(..., elements=67, sig_bytes=2144, steps=1005)
params = recommend(100)       # 最小覆盖 100 条的 Merkle 配置：w=8, height=7
signer = MerkleSigner(height=params.height, w=params.w)
```

推荐策略：先按要签的消息条数定 `capacity`，`recommend` 给出能覆盖它的最小树高；签名体积敏感（默认）用 `w=8`，验证/签名速度敏感用 `prefer="speed"` 换 `w=4`——后者签名约大一倍，但链步上界从 `34×255=8670` 降到 `67×15=1005`。

## 限制

玩具格基 KEM 是为讲解 KEM 外形（keygen/encapsulate/decapsulate、密钥确认 tag）而写的极简模型，**未经过安全审计且结构性地不安全**：私钥与公钥是同一个向量（无单向函数、无噪声、无陷门），任何人都能从公钥直接还原私钥；16 字节、模 257 的参数也无任何安全裕度。**仅供教学，严禁用于任何真实系统。**

Lamport 与 W-OTS 构造都是纯一次性签名：**同一密钥对签第二条消息就会同时暴露多个链位置的哈希原像（Lamport 为两个分支的秘密），签名即可被伪造**。无状态的 `sign`/`wots_sign` 不阻止也不检测重复使用；Lamport 可用 `OneTimeSigner`、W-OTS 可用 `WOTSOneTimeSigner` 在进程内防护，后者还可经 `checkpoint()`/`from_checkpoint()` 跨进程恢复同一私钥及 `used` 状态。Merkle 构造把上限提高到 `2**height` 条消息，但每签一条就永久消耗一片叶子；`MerkleSigner` 在进程内跟踪已用叶子，跨进程持久化同样由调用方通过 `checkpoint()`/`from_checkpoint()` 完成——检查点明文包含私钥且校验值不提供认证，安全存储、每次签名后原子更新、绝不回滚旧检查点的责任都在调用方，回滚即造成一次性密钥重用。参数固定为 SHA-256 安全级：Lamport 为 256 位（签名 256 × 32 = 8 KB）；W-OTS 仅提供 `w ∈ {4, 8}` 两档尺寸/速度权衡，链元素固定 32 字节，不含针对多消息或可变安全裕度的参数。

## 测试

```bash
python3 -m unittest discover -s tests
```

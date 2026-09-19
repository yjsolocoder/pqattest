"""Self-contained demo: python3 -m pqattest"""

from __future__ import annotations

from . import (
    BITS,
    ELEMENT_BYTES,
    HASH_BYTES,
    MerkleSigner,
    keygen,
    merkle_verify,
    message_bits,
    public_key_from,
    sign,
    verify,
    wots_keygen,
    wots_sign,
    wots_verify,
)

MESSAGE = "position claim: -73.9857,40.7484"


def main() -> int:
    private_key, public_key = keygen()
    print("Lamport one-time signature")
    print(f"parameters: bits={BITS} hash_bytes={HASH_BYTES}")
    print(f"  private key: {len(private_key.secrets)} secrets x {HASH_BYTES} B = {len(private_key.secrets) * HASH_BYTES} B")
    print(f"  public key : {len(public_key.digests)} digests x {HASH_BYTES} B = {len(public_key.digests) * HASH_BYTES} B")
    print(f"  public key recomputes from private: {public_key_from(private_key) == public_key}")

    signature = sign(MESSAGE, private_key)
    print()
    print(f"message: {MESSAGE!r}")
    print(f"  digest bits (first 32): {''.join(str(bit) for bit in message_bits(MESSAGE)[:32])}")
    print(f"  signature: {len(signature)} parts x {HASH_BYTES} B = {len(signature) * HASH_BYTES} B")
    print(f"  verify: {verify(MESSAGE, signature, public_key)}")

    print()
    print("rejection cases:")
    print(f"  different message          -> {verify(MESSAGE + '!', signature, public_key)}")
    print(f"  truncated signature        -> {verify(MESSAGE, signature[:-1], public_key)}")
    tampered = list(signature)
    tampered[0] = bytes(HASH_BYTES)
    print(f"  substituted signature part -> {verify(MESSAGE, tampered, public_key)}")

    print()
    print("Winternitz one-time signature (W-OTS)")
    for w in (4, 8):
        wots_private, wots_public = wots_keygen(w=w)
        wots_signature = wots_sign(MESSAGE, wots_private)
        b = 1 << w
        print(
            f"  w={w}: {len(wots_signature)} chains of {b} steps, "
            f"signature {len(wots_signature) * ELEMENT_BYTES} B, "
            f"verify: {wots_verify(MESSAGE, wots_signature, wots_public)}"
        )

    print()
    print("Merkle aggregation over W-OTS")
    merkle_signer = MerkleSigner(height=4, w=4)
    merkle_key = merkle_signer.public_key
    print(f"  height={merkle_key.height} ({merkle_signer.remaining} leaves), root: {merkle_key.root.hex()[:32]}...")
    merkle_signature = merkle_signer.sign(MESSAGE)
    print(
        f"  leaf {merkle_signature.index}: signature "
        f"{len(merkle_signature.wots_signature)} elements + "
        f"{len(merkle_signature.auth_path)} path nodes, "
        f"verify: {merkle_verify(MESSAGE, merkle_signature, merkle_key)}"
    )
    print(f"  different message -> {merkle_verify(MESSAGE + '!', merkle_signature, merkle_key)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

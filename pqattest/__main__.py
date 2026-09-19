"""Self-contained demo: python3 -m pqattest"""

from __future__ import annotations

from . import BITS, HASH_BYTES, keygen, message_bits, public_key_from, sign, verify

MESSAGE = "position claim: -73.9857,40.7484"


def main() -> int:
    private_key, public_key = keygen()
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

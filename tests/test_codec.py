import unittest
from dataclasses import replace

from pqattest import (
    MerklePublicKey,
    MerkleSignature,
    MerkleSigner,
    WOTSPublicKey,
    merkle_verify,
)
from pqattest.merkle import (
    _PUBLIC_KEY_BYTES,
    _SIGNATURE_HEADER_BYTES,
)
from pqattest.wots import ELEMENT_BYTES


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def chains_for(w):
    return 67 if w == 4 else 34


class PublicKeyCodecTest(unittest.TestCase):
    def test_round_trip_both_w_and_heights(self):
        for w in (4, 8):
            for height in (1, 2, 4, 8):
                with self.subTest(w=w, height=height):
                    public_key = make_signer(height=height, w=w).public_key
                    blob = public_key.to_bytes()
                    restored = MerklePublicKey.from_bytes(blob)
                    self.assertEqual(restored, public_key)

    def test_encoding_is_deterministic(self):
        public_key = make_signer().public_key
        self.assertEqual(public_key.to_bytes(), public_key.to_bytes())

    def test_to_bytes_returns_bytes(self):
        self.assertIs(type(make_signer().public_key.to_bytes()), bytes)

    def test_wire_layout(self):
        public_key = make_signer(height=3, w=8).public_key
        blob = public_key.to_bytes()
        self.assertEqual(len(blob), _PUBLIC_KEY_BYTES)
        self.assertEqual(len(blob), 43)
        self.assertEqual(blob[:8], b"PQAMPK\0\0")
        self.assertEqual(blob[8], 1)
        self.assertEqual(blob[9], 8)
        self.assertEqual(blob[10], 3)
        self.assertEqual(blob[11:], public_key.root)

    def test_bytearray_accepted(self):
        public_key = make_signer().public_key
        restored = MerklePublicKey.from_bytes(bytearray(public_key.to_bytes()))
        self.assertEqual(restored, public_key)

    def test_type_errors(self):
        blob = make_signer().public_key.to_bytes()
        for bad in (None, 42, "bytes", memoryview(blob), [blob]):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerklePublicKey.from_bytes(bad)

    def test_bad_magic(self):
        blob = bytearray(make_signer().public_key.to_bytes())
        blob[0] ^= 0x01
        with self.assertRaises(ValueError):
            MerklePublicKey.from_bytes(bytes(blob))

    def test_bad_version(self):
        for version in (0, 2, 255):
            with self.subTest(version=version):
                blob = bytearray(make_signer().public_key.to_bytes())
                blob[8] = version
                with self.assertRaises(ValueError):
                    MerklePublicKey.from_bytes(bytes(blob))

    def test_illegal_w_and_height(self):
        for offset, value in ((9, 2), (9, 16), (10, 0), (10, 9), (10, 255)):
            with self.subTest(offset=offset, value=value):
                blob = bytearray(make_signer().public_key.to_bytes())
                blob[offset] = value
                with self.assertRaises(ValueError):
                    MerklePublicKey.from_bytes(bytes(blob))

    def test_truncated_and_trailing(self):
        blob = make_signer().public_key.to_bytes()
        with self.assertRaises(ValueError):
            MerklePublicKey.from_bytes(blob[:-1])
        with self.assertRaises(ValueError):
            MerklePublicKey.from_bytes(blob + b"\x00")
        with self.assertRaises(ValueError):
            MerklePublicKey.from_bytes(b"")

    def test_signature_blob_rejected_as_public_key(self):
        signer = make_signer()
        sig_blob = signer.sign("m").to_bytes(signer.public_key)
        with self.assertRaises(ValueError):
            MerklePublicKey.from_bytes(sig_blob)


class SignatureCodecTest(unittest.TestCase):
    def test_round_trip_both_w_and_heights(self):
        for w in (4, 8):
            for height in (1, 2, 8):
                with self.subTest(w=w, height=height):
                    signer = make_signer(height=height, w=w)
                    signature = signer.sign("position claim")
                    blob = signature.to_bytes(signer.public_key)
                    restored = MerkleSignature.from_bytes(blob, signer.public_key)
                    self.assertEqual(restored, signature)
                    self.assertTrue(
                        merkle_verify("position claim", restored, signer.public_key)
                    )

    def test_round_trip_every_leaf_including_last(self):
        for height in (1, 3):
            with self.subTest(height=height):
                signer = make_signer(height=height)
                for i in range(1 << height):
                    message = f"leaf-{i}"
                    signature = signer.sign(message)
                    restored = MerkleSignature.from_bytes(
                        signature.to_bytes(signer.public_key), signer.public_key
                    )
                    self.assertEqual(restored.index, i)
                    self.assertTrue(merkle_verify(message, restored, signer.public_key))

    def test_encoding_is_deterministic(self):
        signer = make_signer()
        signature = signer.sign("m")
        self.assertEqual(
            signature.to_bytes(signer.public_key),
            signature.to_bytes(signer.public_key),
        )

    def test_to_bytes_returns_bytes(self):
        signer = make_signer()
        self.assertIs(type(signer.sign("m").to_bytes(signer.public_key)), bytes)

    def test_wire_layout_and_member_order(self):
        w, height = 4, 3
        signer = make_signer(height=height, w=w)
        signature = signer.sign("m")
        blob = signature.to_bytes(signer.public_key)
        chains = chains_for(w)
        expected_length = _SIGNATURE_HEADER_BYTES + (chains + height) * ELEMENT_BYTES
        self.assertEqual(len(blob), expected_length)
        self.assertEqual(blob[:8], b"PQAMSIG\0")
        self.assertEqual(blob[8], 1)
        self.assertEqual(blob[9], w)
        self.assertEqual(blob[10], height)
        self.assertEqual(blob[11:13], signature.index.to_bytes(2, "big"))
        self.assertEqual(blob[13:15], chains.to_bytes(2, "big"))
        self.assertEqual(blob[15], height)
        # Elements first (message chains then checksum chains), path afterwards.
        elements_end = _SIGNATURE_HEADER_BYTES + chains * ELEMENT_BYTES
        self.assertEqual(
            blob[_SIGNATURE_HEADER_BYTES:elements_end],
            b"".join(signature.wots_signature),
        )
        self.assertEqual(blob[elements_end:], b"".join(signature.auth_path))

    def test_w8_layout_counts(self):
        signer = make_signer(height=2, w=8)
        signature = signer.sign("m")
        blob = signature.to_bytes(signer.public_key)
        self.assertEqual(blob[9], 8)
        self.assertEqual(int.from_bytes(blob[13:15], "big"), 34)
        self.assertEqual(len(blob), _SIGNATURE_HEADER_BYTES + (34 + 2) * 32)

    def test_bytearray_accepted(self):
        signer = make_signer()
        signature = signer.sign("m")
        restored = MerkleSignature.from_bytes(
            bytearray(signature.to_bytes(signer.public_key)), signer.public_key
        )
        self.assertEqual(restored, signature)

    def test_last_index_encodes_in_two_bytes(self):
        signer = make_signer(height=8)
        for _ in range(255):
            signer.sign("x")
        last = signer.sign("last")
        self.assertEqual(last.index, 255)
        blob = last.to_bytes(signer.public_key)
        self.assertEqual(blob[11:13], b"\x00\xff")
        restored = MerkleSignature.from_bytes(blob, signer.public_key)
        self.assertTrue(merkle_verify("last", restored, signer.public_key))

    def test_type_errors(self):
        signer = make_signer()
        signature = signer.sign("m")
        blob = signature.to_bytes(signer.public_key)
        for bad_data in (None, 42, "bytes", memoryview(blob), [blob]):
            with self.subTest(bad_data=type(bad_data).__name__):
                with self.assertRaises(TypeError):
                    MerkleSignature.from_bytes(bad_data, signer.public_key)
        # to_bytes / from_bytes require a MerklePublicKey specifically.
        wots_public = WOTSPublicKey(w=4, elements=signature.wots_signature)
        for bad_key in (None, "key", object(), wots_public):
            with self.subTest(bad_key=type(bad_key).__name__):
                with self.assertRaises(TypeError):
                    signature.to_bytes(bad_key)
                with self.assertRaises(TypeError):
                    MerkleSignature.from_bytes(blob, bad_key)

    def test_bad_magic_and_version(self):
        signer = make_signer()
        blob = bytearray(signer.sign("m").to_bytes(signer.public_key))
        tampered = bytearray(blob)
        tampered[0] ^= 0x01
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(bytes(tampered), signer.public_key)
        for version in (0, 2, 255):
            with self.subTest(version=version):
                tampered = bytearray(blob)
                tampered[8] = version
                with self.assertRaises(ValueError):
                    MerkleSignature.from_bytes(bytes(tampered), signer.public_key)

    def test_w_mismatch_rejected(self):
        signer4 = make_signer(w=4, start=0)
        signer8 = make_signer(w=8, start=1000)
        blob = signer4.sign("m").to_bytes(signer4.public_key)
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(blob, signer8.public_key)

    def test_height_mismatch_rejected(self):
        short = make_signer(height=2, start=0)
        tall = make_signer(height=4, start=1000)
        blob = short.sign("m").to_bytes(short.public_key)
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(blob, tall.public_key)

    def test_index_out_of_range_rejected(self):
        signer = make_signer(height=2)
        blob = bytearray(signer.sign("m").to_bytes(signer.public_key))
        blob[11:13] = (1 << 2).to_bytes(2, "big")
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(bytes(blob), signer.public_key)
        blob[11:13] = b"\xff\xff"
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(bytes(blob), signer.public_key)

    def test_wrong_element_count_rejected(self):
        signer = make_signer()
        blob = bytearray(signer.sign("m").to_bytes(signer.public_key))
        blob[13:15] = (66).to_bytes(2, "big")
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(bytes(blob), signer.public_key)

    def test_wrong_path_count_rejected(self):
        signer = make_signer(height=2)
        blob = bytearray(signer.sign("m").to_bytes(signer.public_key))
        blob[15] = 3
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(bytes(blob), signer.public_key)

    def test_truncated_and_trailing(self):
        signer = make_signer()
        blob = signer.sign("m").to_bytes(signer.public_key)
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(blob[:-1], signer.public_key)
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(blob[: _SIGNATURE_HEADER_BYTES - 1], signer.public_key)
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(blob + b"\x00", signer.public_key)
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(b"", signer.public_key)
        # Truncation exactly one 32-byte member short.
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(blob[: -ELEMENT_BYTES], signer.public_key)

    def test_illegal_embedded_params_rejected(self):
        signer = make_signer()
        blob = bytearray(signer.sign("m").to_bytes(signer.public_key))
        blob[9] = 16
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(bytes(blob), signer.public_key)
        blob = bytearray(signer.sign("m").to_bytes(signer.public_key))
        blob[10] = 9
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(bytes(blob), signer.public_key)

    def test_public_key_blob_rejected_as_signature(self):
        signer = make_signer()
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(
                signer.public_key.to_bytes(), signer.public_key
            )

    def test_to_bytes_rejects_incompatible_fields(self):
        signer = make_signer(height=2)
        signature = signer.sign("m")
        other = make_signer(height=3, start=1000)
        # Same w, but the height-2 signature carries only 2 path nodes for a
        # height-3 key; encoding must be bound by the supplied key.
        with self.assertRaises(ValueError):
            signature.to_bytes(other.public_key)
        out_of_range = replace(signature, index=4)
        with self.assertRaises(ValueError):
            out_of_range.to_bytes(signer.public_key)
        wrong_count = replace(signature, wots_signature=signature.wots_signature[:-1])
        with self.assertRaises(ValueError):
            wrong_count.to_bytes(signer.public_key)

    def test_tampered_member_fails_after_round_trip(self):
        signer = make_signer()
        signature = signer.sign("m")
        blob = bytearray(signature.to_bytes(signer.public_key))
        blob[_SIGNATURE_HEADER_BYTES] ^= 0x01
        restored = MerkleSignature.from_bytes(bytes(blob), signer.public_key)
        self.assertFalse(merkle_verify("m", restored, signer.public_key))


if __name__ == "__main__":
    unittest.main()

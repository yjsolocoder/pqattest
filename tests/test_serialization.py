import unittest

from pqattest import MerklePublicKey, MerkleSignature, MerkleSigner, merkle_verify
from pqattest.merkle import (
    _PUBLIC_KEY_MAGIC,
    _SIGNATURE_MAGIC,
    _SIGNATURE_HEADER_BYTES,
)
from pqattest.wots import _params


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def chains_for(w):
    _, l1, l2 = _params(w)
    return l1 + l2


class PublicKeyFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for w in (4, 8):
            with self.subTest(w=w):
                signer = make_signer(height=3, w=w)
                blob = signer.public_key.to_bytes()
                self.assertEqual(len(blob), 8 + 1 + 1 + 1 + 32)
                self.assertEqual(blob[:8], _PUBLIC_KEY_MAGIC)
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(blob[9], w)
                self.assertEqual(blob[10], 3)  # height
                self.assertEqual(blob[11:], signer.public_key.root)

    def test_to_bytes_returns_bytes(self):
        self.assertIsInstance(make_signer().public_key.to_bytes(), bytes)

    def test_encoding_is_deterministic(self):
        key = make_signer().public_key
        self.assertEqual(key.to_bytes(), key.to_bytes())


class PublicKeyRoundTripTest(unittest.TestCase):
    def test_round_trip_all_w_and_heights(self):
        for w in (4, 8):
            for height in (1, 2, 5, 8):
                with self.subTest(w=w, height=height):
                    key = make_signer(height=height, w=w).public_key
                    restored = MerklePublicKey.from_bytes(key.to_bytes())
                    self.assertEqual(restored, key)
                    self.assertEqual(restored.to_bytes(), key.to_bytes())

    def test_accepts_bytearray(self):
        key = make_signer().public_key
        restored = MerklePublicKey.from_bytes(bytearray(key.to_bytes()))
        self.assertEqual(restored, key)


class PublicKeyValidationTest(unittest.TestCase):
    def setUp(self):
        self.blob = make_signer(height=2).public_key.to_bytes()

    def test_non_bytes_types_raise_type_error(self):
        for bad in (None, 42, 4.5, "key", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerklePublicKey.from_bytes(bad)

    def test_truncated_and_empty_rejected(self):
        for cut in (0, 7, 20, len(self.blob) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    MerklePublicKey.from_bytes(self.blob[:cut])

    def test_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            MerklePublicKey.from_bytes(self.blob + b"\x00")

    def test_bad_magic_rejected(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        with self.assertRaises(ValueError):
            MerklePublicKey.from_bytes(bytes(bad))

    def test_bad_version_rejected(self):
        for version in (0, 2, 255):
            with self.subTest(version=version):
                bad = bytearray(self.blob)
                bad[8] = version
                with self.assertRaises(ValueError):
                    MerklePublicKey.from_bytes(bytes(bad))

    def test_bad_w_rejected(self):
        for bad_w in (0, 2, 16, 255):
            with self.subTest(bad_w=bad_w):
                bad = bytearray(self.blob)
                bad[9] = bad_w
                with self.assertRaises(ValueError):
                    MerklePublicKey.from_bytes(bytes(bad))

    def test_bad_height_rejected(self):
        for bad_height in (0, 9, 255):
            with self.subTest(bad_height=bad_height):
                bad = bytearray(self.blob)
                bad[10] = bad_height
                with self.assertRaises(ValueError):
                    MerklePublicKey.from_bytes(bytes(bad))

    def test_to_bytes_on_foreign_object_raises_type_error(self):
        for bad in (None, 42, "key", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerklePublicKey.to_bytes(bad)


class SignatureFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for w in (4, 8):
            with self.subTest(w=w):
                signer = make_signer(height=3, w=w)
                signer.sign("spent")
                signature = signer.sign("message")
                blob = signature.to_bytes(signer.public_key)
                chains = chains_for(w)
                self.assertEqual(
                    len(blob), _SIGNATURE_HEADER_BYTES + (chains + 3) * 32
                )
                self.assertEqual(blob[:8], _SIGNATURE_MAGIC)
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(blob[9], w)
                self.assertEqual(blob[10], 3)  # height
                self.assertEqual(int.from_bytes(blob[11:13], "big"), 1)  # index
                self.assertEqual(int.from_bytes(blob[13:15], "big"), chains)
                self.assertEqual(blob[15], 3)  # path count
                offset = _SIGNATURE_HEADER_BYTES
                self.assertEqual(
                    blob[offset : offset + chains * 32],
                    b"".join(signature.wots_signature),
                )
                self.assertEqual(
                    blob[offset + chains * 32 :],
                    b"".join(signature.auth_path),
                )

    def test_to_bytes_returns_bytes(self):
        signer = make_signer()
        signature = signer.sign("m")
        self.assertIsInstance(signature.to_bytes(signer.public_key), bytes)

    def test_encoding_is_deterministic(self):
        signer = make_signer()
        signature = signer.sign("m")
        self.assertEqual(
            signature.to_bytes(signer.public_key),
            signature.to_bytes(signer.public_key),
        )


class SignatureRoundTripTest(unittest.TestCase):
    def test_round_trip_all_w_and_heights(self):
        for w in (4, 8):
            for height in (1, 2, 5, 8):
                with self.subTest(w=w, height=height):
                    signer = make_signer(height=height, w=w)
                    for message in ("one", "two"):
                        signature = signer.sign(message)
                        blob = signature.to_bytes(signer.public_key)
                        restored = MerkleSignature.from_bytes(
                            blob, signer.public_key
                        )
                        self.assertEqual(restored, signature)
                        self.assertTrue(
                            merkle_verify(message, restored, signer.public_key)
                        )

    def test_accepts_bytearray(self):
        signer = make_signer()
        signature = signer.sign("m")
        blob = signature.to_bytes(signer.public_key)
        restored = MerkleSignature.from_bytes(bytearray(blob), signer.public_key)
        self.assertEqual(restored, signature)

    def test_public_key_round_trips_with_signature(self):
        signer = make_signer(height=3, w=8)
        signature = signer.sign("m")
        key = MerklePublicKey.from_bytes(signer.public_key.to_bytes())
        restored = MerkleSignature.from_bytes(signature.to_bytes(key), key)
        self.assertTrue(merkle_verify("m", restored, key))


class SignatureValidationTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=2)
        self.signer.sign("spent")
        self.signature = self.signer.sign("message")
        self.public_key = self.signer.public_key
        self.blob = self.signature.to_bytes(self.public_key)

    def assert_rejected(self, data, public_key=None):
        with self.assertRaises(ValueError):
            MerkleSignature.from_bytes(
                data, self.public_key if public_key is None else public_key
            )

    def test_non_bytes_data_raises_type_error(self):
        for bad in (None, 42, 4.5, "sig", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleSignature.from_bytes(bad, self.public_key)

    def test_non_public_key_raises_type_error(self):
        for bad in (None, 42, "key", self.blob, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleSignature.from_bytes(self.blob, bad)
                with self.assertRaises(TypeError):
                    self.signature.to_bytes(bad)

    def test_to_bytes_on_foreign_object_raises_type_error(self):
        for bad in (None, 42, "sig", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleSignature.to_bytes(bad, self.public_key)

    def test_truncated_and_empty_rejected(self):
        self.assert_rejected(b"")
        self.assert_rejected(self.blob[:10])
        self.assert_rejected(self.blob[: _SIGNATURE_HEADER_BYTES])
        self.assert_rejected(self.blob[:-1])

    def test_trailing_data_rejected(self):
        self.assert_rejected(self.blob + b"\x00")

    def test_bad_magic_rejected(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        self.assert_rejected(bytes(bad))

    def test_bad_version_rejected(self):
        bad = bytearray(self.blob)
        bad[8] = 2
        self.assert_rejected(bytes(bad))

    def test_w_mismatch_rejected(self):
        other = make_signer(height=2, w=8, start=1000)
        self.assert_rejected(self.blob, public_key=other.public_key)
        bad = bytearray(self.blob)
        bad[9] = 8
        self.assert_rejected(bytes(bad))

    def test_height_mismatch_rejected(self):
        other = make_signer(height=3, start=1000)
        self.assert_rejected(self.blob, public_key=other.public_key)
        bad = bytearray(self.blob)
        bad[10] = 3
        self.assert_rejected(bytes(bad))

    def test_out_of_range_index_rejected(self):
        bad = bytearray(self.blob)
        bad[11:13] = (4).to_bytes(2, "big")  # height 2 -> 4 leaves
        self.assert_rejected(bytes(bad))

    def test_bad_element_count_rejected(self):
        chains = chains_for(self.public_key.w)
        for count in (0, chains - 1, chains + 1):
            with self.subTest(count=count):
                bad = bytearray(self.blob)
                bad[13:15] = count.to_bytes(2, "big")
                self.assert_rejected(bytes(bad))

    def test_bad_path_count_rejected(self):
        for count in (0, 1, 3, 255):
            with self.subTest(count=count):
                bad = bytearray(self.blob)
                bad[15] = count
                self.assert_rejected(bytes(bad))

    def test_to_bytes_rejects_signature_inconsistent_with_key(self):
        other = make_signer(height=3, w=8, start=1000)
        with self.assertRaises(ValueError):
            self.signature.to_bytes(other.public_key)

    def test_valid_signature_still_accepted(self):
        # Guard against the corruption tests making the helper too strict.
        restored = MerkleSignature.from_bytes(self.blob, self.public_key)
        self.assertEqual(restored, self.signature)
        self.assertTrue(merkle_verify("message", restored, self.public_key))


if __name__ == "__main__":
    unittest.main()

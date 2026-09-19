import unittest

from pqattest import MerkleProof, MerklePublicKey, MerkleSignature, MerkleSigner, merkle_verify
from pqattest.merkle import (
    _PROOF_MAGIC,
    _PROOF_HEADER_BYTES,
    _PUBLIC_KEY_BYTES,
)
from pqattest.wots import _params


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_proof(height=2, w=4, start=0, message=b"message"):
    signer = MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))
    signature = signer.sign(message)
    return signer.public_key, signature, MerkleProof(signer.public_key, signature)


def chains_for(w):
    _, l1, l2 = _params(w)
    return l1 + l2


class ProofFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for w in (4, 8):
            with self.subTest(w=w):
                public_key, signature, proof = make_proof(height=3, w=w)
                key_blob = public_key.to_bytes()
                sig_blob = signature.to_bytes(public_key)
                blob = proof.to_bytes()
                self.assertEqual(len(blob), _PROOF_HEADER_BYTES + len(key_blob) + len(sig_blob))
                self.assertEqual(blob[:8], _PROOF_MAGIC)
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(int.from_bytes(blob[9:13], "big"), len(key_blob))
                self.assertEqual(int.from_bytes(blob[13:17], "big"), len(sig_blob))
                self.assertEqual(blob[17 : 17 + len(key_blob)], key_blob)
                self.assertEqual(blob[17 + len(key_blob) :], sig_blob)

    def test_to_bytes_returns_bytes(self):
        _, _, proof = make_proof()
        self.assertIsInstance(proof.to_bytes(), bytes)

    def test_encoding_is_deterministic(self):
        _, _, proof = make_proof()
        self.assertEqual(proof.to_bytes(), proof.to_bytes())

    def test_fields_named_as_specified(self):
        public_key, signature, proof = make_proof()
        self.assertIs(proof.MerklePublicKey, public_key)
        self.assertIs(proof.MerkleSignature, signature)

    def test_frozen(self):
        import dataclasses

        _, _, proof = make_proof()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            proof.MerklePublicKey = proof.MerklePublicKey


class ProofConstructionTest(unittest.TestCase):
    def test_field_type_errors(self):
        public_key, signature, _ = make_proof()
        for bad in (None, 42, b"x", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleProof(bad, signature)
                with self.assertRaises(TypeError):
                    MerkleProof(public_key, bad)

    def test_inconsistent_pair_raises_value_error(self):
        public_key, signature, _ = make_proof(w=4)
        other = MerkleSigner(height=2, w=8, token_bytes=counter_tokens(1000)).public_key
        with self.assertRaises(ValueError):
            MerkleProof(other, signature)
        other_signer = MerkleSigner(height=3, w=4, token_bytes=counter_tokens(1000))
        with self.assertRaises(ValueError):
            MerkleProof(other_signer.public_key, signature)

    def test_to_bytes_on_foreign_object_raises_type_error(self):
        for bad in (None, 42, "proof", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleProof.to_bytes(bad)


class ProofRoundTripTest(unittest.TestCase):
    def test_round_trip_all_w_and_heights(self):
        for w in (4, 8):
            for height in (1, 2, 5, 8):
                with self.subTest(w=w, height=height):
                    public_key, signature, proof = make_proof(height=height, w=w)
                    restored = MerkleProof.from_bytes(proof.to_bytes())
                    self.assertEqual(restored, proof)
                    self.assertEqual(restored.to_bytes(), proof.to_bytes())
                    self.assertEqual(restored.MerklePublicKey, public_key)
                    self.assertEqual(restored.MerkleSignature, signature)

    def test_accepts_bytearray(self):
        _, _, proof = make_proof()
        self.assertEqual(MerkleProof.from_bytes(bytearray(proof.to_bytes())), proof)


class ProofValidationTest(unittest.TestCase):
    def setUp(self):
        self.blob = make_proof()[2].to_bytes()

    def assert_rejected(self, data):
        with self.assertRaises(ValueError):
            MerkleProof.from_bytes(data)

    def test_non_bytes_types_raise_type_error(self):
        for bad in (None, 42, 4.5, "proof", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleProof.from_bytes(bad)

    def test_truncated_and_empty_rejected(self):
        for cut in (0, 8, _PROOF_HEADER_BYTES - 1, _PROOF_HEADER_BYTES, len(self.blob) - 1):
            with self.subTest(cut=cut):
                self.assert_rejected(self.blob[:cut])

    def test_trailing_data_rejected(self):
        self.assert_rejected(self.blob + b"\x00")

    def test_bad_magic_rejected(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        self.assert_rejected(bytes(bad))

    def test_bad_version_rejected(self):
        for version in (0, 2, 255):
            with self.subTest(version=version):
                bad = bytearray(self.blob)
                bad[8] = version
                self.assert_rejected(bytes(bad))

    def test_declared_lengths_must_match(self):
        for field in (slice(9, 13), slice(13, 17)):
            for delta in (-1, 1):
                bad = bytearray(self.blob)
                value = int.from_bytes(bad[field], "big") + delta
                bad[field] = value.to_bytes(4, "big")
                with self.subTest(field=field.start, delta=delta):
                    self.assert_rejected(bytes(bad))

    def test_declared_lengths_overflow_rejected(self):
        bad = bytearray(self.blob)
        bad[9:13] = (0xFFFFFFFF).to_bytes(4, "big")
        self.assert_rejected(bytes(bad))
        bad = bytearray(self.blob)
        bad[13:17] = (0xFFFFFFFF).to_bytes(4, "big")
        self.assert_rejected(bytes(bad))

    def test_zero_lengths_rejected(self):
        for key_length, sig_length in ((0, 0), (0, 10), (_PUBLIC_KEY_BYTES, 0)):
            with self.subTest(key_length=key_length, sig_length=sig_length):
                bad = bytearray(self.blob)
                bad[9:13] = key_length.to_bytes(4, "big")
                bad[13:17] = sig_length.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_nested_public_key_corruption_rejected(self):
        # Nested key starts right after the 17-byte proof header; corrupt its w.
        bad = bytearray(self.blob)
        bad[17 + 9] = 8
        self.assert_rejected(bytes(bad))

    def test_nested_signature_cross_inconsistency_rejected(self):
        # Flip w inside the nested signature blob (key blob ends at 17 + 43);
        # the recovered key (w=4) must reject a signature claiming w=8.
        bad = bytearray(self.blob)
        sig_start = 17 + _PUBLIC_KEY_BYTES
        bad[sig_start + 9] = 8
        self.assert_rejected(bytes(bad))

    def test_valid_proof_still_accepted(self):
        restored = MerkleProof.from_bytes(self.blob)
        self.assertTrue(restored.verify(b"message"))


class ProofVerifyTest(unittest.TestCase):
    def setUp(self):
        self.public_key, self.signature, self.proof = make_proof(message=b"position claim")

    def test_accepts_all_message_types(self):
        for message in (b"position claim", bytearray(b"position claim"), "position claim"):
            with self.subTest(kind=type(message).__name__):
                self.assertTrue(self.proof.verify(message))

    def test_matches_merkle_verify(self):
        for message, expected in ((b"position claim", True), (b"other", False), ("x", False)):
            with self.subTest(message=message):
                self.assertEqual(
                    self.proof.verify(message),
                    merkle_verify(message, self.signature, self.public_key),
                )

    def test_tampered_message_key_or_signature_fails(self):
        self.assertFalse(self.proof.verify(b"different message"))
        tampered_key = MerkleProof(
            MerklePublicKey(
                w=self.public_key.w,
                height=self.public_key.height,
                root=bytes(b ^ 1 for b in self.public_key.root),
            ),
            self.signature,
        )
        self.assertFalse(tampered_key.verify(b"position claim"))
        broken_elements = list(self.signature.wots_signature)
        broken_elements[0] = bytes(b ^ 1 for b in broken_elements[0])
        tampered_sig = MerkleSignature(
            index=self.signature.index,
            wots_signature=tuple(broken_elements),
            auth_path=self.signature.auth_path,
        )
        self.assertFalse(MerkleProof(self.public_key, tampered_sig).verify(b"position claim"))

    def test_bad_message_type_returns_false(self):
        # Mirrors merkle_verify: unsupported message types yield False.
        self.assertFalse(self.proof.verify(42))
        self.assertFalse(self.proof.verify(None))

    def test_verify_on_foreign_object_raises_type_error(self):
        with self.assertRaises(TypeError):
            MerkleProof.verify(object(), b"m")


if __name__ == "__main__":
    unittest.main()

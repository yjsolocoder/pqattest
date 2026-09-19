import unittest

from pqattest import (
    MerkleProof,
    MerklePublicKey,
    MerkleSignature,
    MerkleSigner,
    merkle_verify,
)
from pqattest.merkle import _PROOF_HEADER_BYTES


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def make_proof(height=2, w=4, start=0, message="position claim"):
    signer = make_signer(height=height, w=w, start=start)
    signature = signer.sign(message)
    return signer, MerkleProof(public_key=signer.public_key, signature=signature)


def proof_envelope(key_blob: bytes, sig_blob: bytes) -> bytes:
    return (
        b"PQAMPRF\0"
        + bytes((1,))
        + len(key_blob).to_bytes(4, "big")
        + len(sig_blob).to_bytes(4, "big")
        + key_blob
        + sig_blob
    )


class ProofConstructionTest(unittest.TestCase):
    def test_fields_and_equality(self):
        signer = make_signer()
        signature = signer.sign("m")
        proof = MerkleProof(public_key=signer.public_key, signature=signature)
        self.assertIs(proof.public_key, signer.public_key)
        self.assertIs(proof.signature, signature)
        self.assertEqual(
            proof, MerkleProof(public_key=signer.public_key, signature=signature)
        )
        self.assertEqual(hash(proof), hash(proof))

    def test_frozen(self):
        _, proof = make_proof()
        with self.assertRaises(Exception):
            proof.public_key = proof.public_key
        with self.assertRaises(Exception):
            proof.signature = proof.signature

    def test_wrong_field_types_raise_type_error(self):
        signer = make_signer()
        signature = signer.sign("m")
        for bad in (None, 42, "key", signature, b"raw", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleProof(public_key=bad, signature=signature)
        for bad in (None, 42, "sig", signer.public_key, b"raw", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleProof(public_key=signer.public_key, signature=bad)

    def test_same_shape_foreign_signature_builds_but_does_not_verify(self):
        # Construction checks parameter/count consistency only: without a
        # message the proof cannot cryptographically cross-check the pair, so
        # a same-shape signature from another key is accepted here and fails
        # at verify time (the proof stores no message).
        signer_a = make_signer(start=0)
        signer_b = make_signer(start=1000)
        foreign = signer_a.sign("m")
        proof = MerkleProof(public_key=signer_b.public_key, signature=foreign)
        self.assertFalse(proof.verify("m"))

    def test_parameter_mismatch_rejected(self):
        cases = (
            (make_signer(w=4), make_signer(w=8, start=1000)),
            (make_signer(height=2), make_signer(height=3, start=2000)),
        )
        for own, other in cases:
            with self.subTest(other=other.public_key):
                with self.assertRaises(ValueError):
                    MerkleProof(
                        public_key=other.public_key, signature=own.sign("m")
                    )


class ProofFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for w in (4, 8):
            for height in (1, 3):
                with self.subTest(w=w, height=height):
                    signer, proof = make_proof(w=w, height=height)
                    key_blob = signer.public_key.to_bytes()
                    sig_blob = proof.signature.to_bytes(signer.public_key)
                    blob = proof.to_bytes()
                    self.assertEqual(
                        len(blob),
                        _PROOF_HEADER_BYTES + len(key_blob) + len(sig_blob),
                    )
                    self.assertEqual(blob[:8], b"PQAMPRF\0")
                    self.assertEqual(blob[8], 1)  # version
                    self.assertEqual(int.from_bytes(blob[9:13], "big"), len(key_blob))
                    self.assertEqual(int.from_bytes(blob[13:17], "big"), len(sig_blob))
                    self.assertEqual(
                        blob[
                            _PROOF_HEADER_BYTES : _PROOF_HEADER_BYTES + len(key_blob)
                        ],
                        key_blob,
                    )
                    self.assertEqual(
                        blob[_PROOF_HEADER_BYTES + len(key_blob) :], sig_blob
                    )

    def test_to_bytes_returns_bytes(self):
        _, proof = make_proof()
        self.assertIsInstance(proof.to_bytes(), bytes)

    def test_encoding_is_deterministic(self):
        _, proof = make_proof()
        self.assertEqual(proof.to_bytes(), proof.to_bytes())

    def test_equal_values_have_equal_bytes(self):
        signer = make_signer()
        signature = signer.sign("m")
        proof_a = MerkleProof(signer.public_key, signature)
        proof_b = MerkleProof(signer.public_key, signature)
        self.assertEqual(proof_a, proof_b)
        self.assertEqual(proof_a.to_bytes(), proof_b.to_bytes())

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
                    signer, proof = make_proof(w=w, height=height, message="hi")
                    restored = MerkleProof.from_bytes(proof.to_bytes())
                    self.assertEqual(restored, proof)
                    self.assertEqual(restored.public_key, proof.public_key)
                    self.assertEqual(restored.signature, proof.signature)
                    self.assertEqual(restored.to_bytes(), proof.to_bytes())
                    self.assertTrue(restored.verify("hi"))

    def test_accepts_bytearray(self):
        _, proof = make_proof()
        restored = MerkleProof.from_bytes(bytearray(proof.to_bytes()))
        self.assertEqual(restored, proof)

    def test_standalone_transport(self):
        signer = make_signer(height=3, w=8)
        signature = signer.sign(b"position claim")
        blob = MerkleProof(signer.public_key, signature).to_bytes()
        # The receiver needs nothing but the blob.
        received = MerkleProof.from_bytes(blob)
        self.assertTrue(received.verify(b"position claim"))
        self.assertFalse(received.verify(b"other claim"))


class ProofFromBytesValidationTest(unittest.TestCase):
    def setUp(self):
        _, proof = make_proof()
        self.blob = proof.to_bytes()
        self.key_len = int.from_bytes(self.blob[9:13], "big")
        self.sig_len = int.from_bytes(self.blob[13:17], "big")

    def assert_rejected(self, data):
        with self.assertRaises(ValueError):
            MerkleProof.from_bytes(data)

    def test_non_bytes_types_raise_type_error(self):
        for bad in (None, 42, 4.5, "proof", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleProof.from_bytes(bad)

    def test_truncated_and_empty_rejected(self):
        for cut in (0, 8, 9, 16, _PROOF_HEADER_BYTES, len(self.blob) - 1):
            with self.subTest(cut=cut):
                self.assert_rejected(self.blob[:cut])

    def test_trailing_data_rejected(self):
        self.assert_rejected(self.blob + b"\x00")
        self.assert_rejected(self.blob + b"tail")

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

    def test_zero_lengths_rejected(self):
        for offset in (9, 13):
            with self.subTest(offset=offset):
                bad = bytearray(self.blob)
                bad[offset : offset + 4] = (0).to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_key_length_out_of_bounds_rejected(self):
        payload = len(self.blob) - _PROOF_HEADER_BYTES
        for length in (payload + 1, payload + 100, 1 << 31, 0xFFFFFFFF):
            with self.subTest(length=length):
                bad = bytearray(self.blob)
                bad[9:13] = length.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_signature_length_out_of_bounds_rejected(self):
        payload = len(self.blob) - _PROOF_HEADER_BYTES
        for length in (payload - self.key_len + 1, 1 << 31, 0xFFFFFFFF):
            with self.subTest(length=length):
                bad = bytearray(self.blob)
                bad[13:17] = length.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_key_length_shorter_than_key_encoding_rejected(self):
        for new_len in (1, self.key_len - 1):
            with self.subTest(new_len=new_len):
                bad = bytearray(self.blob)
                bad[9:13] = new_len.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_key_length_longer_misaligns_signature(self):
        bad = bytearray(self.blob)
        bad[9:13] = (self.key_len + 1).to_bytes(4, "big")
        self.assert_rejected(bytes(bad))

    def test_sig_length_shorter_truncates_signature(self):
        for new_len in (1, self.sig_len - 1):
            with self.subTest(new_len=new_len):
                bad = bytearray(self.blob)
                bad[13:17] = new_len.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_nested_public_key_encoding_corrupted(self):
        for name, delta in (("magic", 0), ("version", 8), ("w", 9), ("height", 10)):
            with self.subTest(field=name):
                bad = bytearray(self.blob)
                bad[_PROOF_HEADER_BYTES + delta] ^= 0x01
                self.assert_rejected(bytes(bad))

    def test_nested_signature_magic_corrupted(self):
        bad = bytearray(self.blob)
        bad[_PROOF_HEADER_BYTES + self.key_len] ^= 0x01
        self.assert_rejected(bytes(bad))

    def test_nested_signature_version_corrupted(self):
        bad = bytearray(self.blob)
        bad[_PROOF_HEADER_BYTES + self.key_len + 8] = 2
        self.assert_rejected(bytes(bad))

    def test_nested_signature_count_tampered_rejected(self):
        count_offset = _PROOF_HEADER_BYTES + self.key_len + 13
        chains = int.from_bytes(
            self.blob[count_offset : count_offset + 2], "big"
        )
        bad = bytearray(self.blob)
        bad[count_offset : count_offset + 2] = (chains + 1).to_bytes(2, "big")
        self.assert_rejected(bytes(bad))

    def test_cross_inconsistent_key_and_signature_rejected(self):
        signer_a = make_signer(height=2, w=4, start=0)
        sig_a = signer_a.sign("m")
        key_blob = signer_a.public_key.to_bytes()
        for other in (
            make_signer(height=2, w=8, start=1000),
            make_signer(height=3, w=4, start=2000),
        ):
            with self.subTest(other=other.public_key):
                foreign_blob = other.sign("m").to_bytes(other.public_key)
                self.assert_rejected(proof_envelope(key_blob, foreign_blob))
        # Sanity: the matching pair parses and verifies.
        restored = MerkleProof.from_bytes(self.blob)
        self.assertEqual(restored.to_bytes(), self.blob)
        self.assertTrue(restored.verify("position claim"))
        self.assertIsNotNone(sig_a)

    def test_repartitioned_lengths_rejected_by_nested_codecs(self):
        # Same total payload, shifted boundary: the nested key slice carries a
        # trailing byte and the nested codec must reject it.
        payload = self.blob[_PROOF_HEADER_BYTES:]
        bad = (
            b"PQAMPRF\0"
            + bytes((1,))
            + (self.key_len + 1).to_bytes(4, "big")
            + (self.sig_len - 1).to_bytes(4, "big")
            + payload
        )
        self.assert_rejected(bad)


class ProofVerifyTest(unittest.TestCase):
    def test_message_types_match_merkle_verify(self):
        message = "position claim"
        signer = make_signer()
        signature = signer.sign(message)
        proof = MerkleProof(signer.public_key, signature)
        for variant in (message, message.encode(), bytearray(message.encode())):
            with self.subTest(kind=type(variant).__name__):
                self.assertIs(
                    proof.verify(variant),
                    merkle_verify(variant, signature, signer.public_key),
                )
                self.assertTrue(proof.verify(variant))

    def test_wrong_message_fails(self):
        _, proof = make_proof(message=b"signed text")
        self.assertTrue(proof.verify(b"signed text"))
        self.assertFalse(proof.verify(b"signed text!"))
        self.assertFalse(proof.verify("other"))

    def test_unsupported_message_type_is_false_not_raise(self):
        _, proof = make_proof()
        for bad in (None, 42, 4.5, [1, 2], object()):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(proof.verify(bad))

    def test_tampered_signature_element_fails(self):
        signer = make_signer()
        signature = signer.sign("m")
        proof = MerkleProof(signer.public_key, signature)
        self.assertTrue(proof.verify("m"))
        tampered_elements = list(signature.wots_signature)
        tampered_elements[0] = bytes(32)
        tampered = MerkleSignature(
            index=signature.index,
            wots_signature=tuple(tampered_elements),
            auth_path=signature.auth_path,
        )
        # Still structurally consistent with the key, so the proof builds —
        # but cryptography rejects it.
        tampered_proof = MerkleProof(signer.public_key, tampered)
        self.assertFalse(tampered_proof.verify("m"))

    def test_tampered_blob_fails_after_parsing(self):
        signer = make_signer()
        signature = signer.sign("m")
        blob = MerkleProof(signer.public_key, signature).to_bytes()
        # Flip the last byte (inside the auth path).
        bad = bytearray(blob)
        bad[-1] ^= 0x01
        restored = MerkleProof.from_bytes(bytes(bad))
        self.assertFalse(restored.verify("m"))

    def test_proof_does_not_store_message(self):
        _, proof = make_proof(message="the message")
        self.assertFalse(hasattr(proof, "message"))
        self.assertEqual(sorted(vars(proof).keys()), ["public_key", "signature"])


if __name__ == "__main__":
    unittest.main()

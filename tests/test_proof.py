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


class ProofVerifyBoundTest(unittest.TestCase):
    def test_bound_verifies_signed_message(self):
        signer = make_signer()
        signature = signer.sign("m")
        proof = MerkleProof(signer.public_key, signature)
        self.assertTrue(
            proof.verify_bound("m", public_key=signer.public_key)
        )
        self.assertTrue(
            proof.verify_bound(
                "m", public_key=signer.public_key, index=signature.index
            )
        )

    def test_message_types_match_merkle_verify(self):
        message = "position claim"
        signer = make_signer()
        signature = signer.sign(message)
        proof = MerkleProof(signer.public_key, signature)
        for variant in (message, message.encode(), bytearray(message.encode())):
            with self.subTest(kind=type(variant).__name__):
                self.assertTrue(
                    proof.verify_bound(variant, public_key=signer.public_key)
                )

    def test_value_equal_distinct_key_accepted(self):
        signer = make_signer()
        signature = signer.sign("m")
        proof = MerkleProof(signer.public_key, signature)
        other = MerklePublicKey(
            w=signer.public_key.w,
            height=signer.public_key.height,
            root=signer.public_key.root,
        )
        self.assertIsNot(other, signer.public_key)
        self.assertTrue(proof.verify_bound("m", public_key=other))

    def test_public_key_must_be_keyword(self):
        _, proof = make_proof()
        with self.assertRaises(TypeError):
            proof.verify_bound("m", make_signer().public_key)

    def test_wrong_public_key_type_raises_type_error(self):
        _, proof = make_proof()
        for bad in (None, 42, 4.5, "key", b"key", object(), ()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    proof.verify_bound("m", public_key=bad)

    def test_public_key_value_mismatch_is_false(self):
        signer = make_signer()
        signature = signer.sign("m")
        proof = MerkleProof(signer.public_key, signature)
        own = proof.public_key
        foreign = make_signer(start=1000).public_key
        for bad_key in (
            foreign,
            MerklePublicKey(w=8, height=own.height, root=own.root),
            MerklePublicKey(w=own.w, height=1, root=own.root),
            MerklePublicKey(w=own.w, height=own.height, root=bytes(32)),
        ):
            with self.subTest(bad_key=bad_key):
                self.assertFalse(
                    proof.verify_bound("m", public_key=bad_key)
                )

    def test_verification_failure_is_false_even_with_matching_key(self):
        _, proof = make_proof(message=b"signed text")
        for bad in (b"other", "other", None, 42, object()):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(
                    proof.verify_bound(bad, public_key=proof.public_key)
                )

    def test_index_none_imposes_no_leaf_restriction(self):
        signer = make_signer(height=3)
        signer.sign("gap0")
        signer.sign("gap1")
        signature = signer.sign("a")
        proof = MerkleProof(signer.public_key, signature)
        self.assertEqual(signature.index, 2)
        self.assertTrue(proof.verify_bound("a", public_key=signer.public_key))
        self.assertTrue(
            proof.verify_bound(
                "a", public_key=signer.public_key, index=None
            )
        )

    def test_explicit_index_must_equal_signature_index(self):
        signer = make_signer(height=3)
        signer.sign("gap0")
        signature = signer.sign("a")
        proof = MerkleProof(signer.public_key, signature)
        self.assertEqual(signature.index, 1)
        self.assertTrue(
            proof.verify_bound("a", public_key=signer.public_key, index=1)
        )
        for bad in (0, 2, 7):
            with self.subTest(index=bad):
                self.assertFalse(
                    proof.verify_bound(
                        "a", public_key=signer.public_key, index=bad
                    )
                )

    def test_non_integer_index_raises_type_error(self):
        _, proof = make_proof()
        for bad in (1.0, "1", b"1", [1], (1,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    proof.verify_bound(
                        "m", public_key=proof.public_key, index=bad
                    )

    def test_boolean_index_is_false_not_raising(self):
        signer = make_signer()
        signature = signer.sign("m")
        proof = MerkleProof(signer.public_key, signature)
        # Leaf 0 really is the signed leaf, but a boolean must still fail.
        self.assertEqual(signature.index, 0)
        self.assertIs(
            proof.verify_bound("m", public_key=signer.public_key, index=False),
            False,
        )
        self.assertIs(
            proof.verify_bound("m", public_key=signer.public_key, index=True),
            False,
        )

    def test_negative_and_out_of_range_indices_are_false(self):
        signer = make_signer(height=2)
        signature = signer.sign("m")
        proof = MerkleProof(signer.public_key, signature)
        for bad in (-1, -100, 4, 5, 1 << 30):
            with self.subTest(index=bad):
                self.assertFalse(
                    proof.verify_bound(
                        "m", public_key=signer.public_key, index=bad
                    )
                )

    def test_type_errors_take_precedence_over_other_failures(self):
        _, proof = make_proof()
        with self.assertRaises(TypeError):
            proof.verify_bound("wrong", public_key="not-a-key")
        with self.assertRaises(TypeError):
            proof.verify_bound(
                "m", public_key=proof.public_key, index=1.0
            )
        # The external argument contract holds even on a malformed bundle.
        rogue = object.__new__(MerkleProof)
        object.__setattr__(rogue, "public_key", "not-a-key")
        object.__setattr__(rogue, "signature", "not-a-signature")
        with self.assertRaises(TypeError):
            rogue.verify_bound("m", public_key="not-a-key")

    def test_malformed_bypass_constructed_proof_is_false(self):
        signer = make_signer()
        signature = signer.sign("m")
        valid_key = signer.public_key

        rogue = object.__new__(MerkleProof)
        object.__setattr__(rogue, "public_key", "not-a-key")
        object.__setattr__(rogue, "signature", "not-a-signature")
        self.assertFalse(rogue.verify_bound("m", public_key=valid_key))
        self.assertFalse(
            rogue.verify_bound("m", public_key=valid_key, index=0)
        )

        missing = object.__new__(MerkleProof)
        self.assertFalse(missing.verify_bound("m", public_key=valid_key))

        rogue_key = object.__new__(MerkleProof)
        object.__setattr__(rogue_key, "public_key", None)
        object.__setattr__(rogue_key, "signature", signature)
        self.assertFalse(rogue_key.verify_bound("m", public_key=valid_key))

        rogue_sig = object.__new__(MerkleProof)
        object.__setattr__(rogue_sig, "public_key", valid_key)
        object.__setattr__(rogue_sig, "signature", "x")
        self.assertFalse(rogue_sig.verify_bound("m", public_key=valid_key))

        corrupted_key = object.__new__(MerklePublicKey)
        object.__setattr__(corrupted_key, "w", 999)
        object.__setattr__(corrupted_key, "height", valid_key.height)
        object.__setattr__(corrupted_key, "root", valid_key.root)
        rogue_fields = object.__new__(MerkleProof)
        object.__setattr__(rogue_fields, "public_key", corrupted_key)
        object.__setattr__(rogue_fields, "signature", signature)
        self.assertFalse(
            rogue_fields.verify_bound("m", public_key=valid_key)
        )

        corrupted_sig = object.__new__(MerkleSignature)
        object.__setattr__(corrupted_sig, "index", 99)
        object.__setattr__(
            corrupted_sig, "wots_signature", signature.wots_signature
        )
        object.__setattr__(corrupted_sig, "auth_path", signature.auth_path)
        rogue_index = MerkleProof.__new__(MerkleProof)
        object.__setattr__(rogue_index, "public_key", valid_key)
        object.__setattr__(rogue_index, "signature", corrupted_sig)
        self.assertFalse(
            rogue_index.verify_bound("m", public_key=valid_key)
        )
        self.assertFalse(
            rogue_index.verify_bound(
                "m", public_key=valid_key, index=99
            )
        )

    def test_round_tripped_proof_still_verifies_bound(self):
        signer = make_signer()
        signature = signer.sign("m")
        proof = MerkleProof(signer.public_key, signature)
        restored = MerkleProof.from_bytes(proof.to_bytes())
        self.assertEqual(restored, proof)
        self.assertTrue(
            restored.verify_bound(
                "m", public_key=signer.public_key, index=signature.index
            )
        )

    def test_bound_checks_key_and_index_before_accepting(self):
        signer = make_signer(height=2)
        signature = signer.sign("m")
        proof = MerkleProof(signer.public_key, signature)
        foreign = make_signer(start=1000).public_key
        # A matching index cannot rescue a wrong key or wrong message.
        self.assertFalse(
            proof.verify_bound(
                "m", public_key=foreign, index=signature.index
            )
        )
        self.assertFalse(
            proof.verify_bound(
                "other",
                public_key=signer.public_key,
                index=signature.index,
            )
        )

    def test_plain_verify_unchanged(self):
        _, proof = make_proof(message="m")
        self.assertTrue(proof.verify("m"))
        self.assertFalse(proof.verify("other"))
        self.assertEqual(sorted(vars(proof).keys()), ["public_key", "signature"])


if __name__ == "__main__":
    unittest.main()

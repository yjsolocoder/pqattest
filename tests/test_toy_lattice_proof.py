import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    ToyLatticeProof,
    ToyLatticePublicKey,
    ToyLatticeSignature,
    toy_lattice_keygen,
    toy_lattice_sign,
    toy_lattice_verify,
)

_PROOF_HEADER_BYTES = 8 + 1 + 4 + 4


def fixed_tokens(value: bytes):
    def token_bytes(size: int) -> bytes:
        assert size == len(value)
        return value

    return token_bytes


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        chunk = state["value"].to_bytes(8, "big").rjust(size, b"\x00")
        state["value"] += 1
        return chunk

    return token_bytes


def make_keypair(start=0):
    return toy_lattice_keygen(token_bytes=counter_tokens(start))


def make_proof(start=0, message=b"position claim"):
    private_key, public_key = make_keypair(start=start)
    signature = toy_lattice_sign(
        message, private_key, token_bytes=counter_tokens(start + 1000)
    )
    return public_key, ToyLatticeProof(public_key=public_key, signature=signature)


def proof_envelope(key_blob: bytes, sig_blob: bytes) -> bytes:
    return (
        b"PQALPF\0\0"
        + bytes((1,))
        + len(key_blob).to_bytes(4, "big")
        + len(sig_blob).to_bytes(4, "big")
        + key_blob
        + sig_blob
    )


class ToyLatticeProofConstructionTest(unittest.TestCase):
    def test_fields_and_equality(self):
        private_key, public_key = make_keypair()
        signature = toy_lattice_sign(b"m", private_key)
        proof = ToyLatticeProof(public_key, signature)
        self.assertIs(proof.public_key, public_key)
        self.assertIs(proof.signature, signature)
        self.assertEqual(proof, ToyLatticeProof(public_key, signature))
        self.assertEqual(hash(proof), hash(ToyLatticeProof(public_key, signature)))

    def test_positional_construction(self):
        private_key, public_key = make_keypair()
        signature = toy_lattice_sign(b"m", private_key)
        self.assertEqual(
            ToyLatticeProof(public_key, signature),
            ToyLatticeProof(public_key=public_key, signature=signature),
        )

    def test_frozen(self):
        _, proof = make_proof()
        with self.assertRaises(FrozenInstanceError):
            proof.public_key = proof.public_key
        with self.assertRaises(FrozenInstanceError):
            proof.signature = proof.signature

    def test_wrong_field_types_raise_type_error(self):
        private_key, public_key = make_keypair()
        signature = toy_lattice_sign(b"m", private_key)
        for bad in (None, 42, "key", signature, b"raw", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    ToyLatticeProof(public_key=bad, signature=signature)
        for bad in (None, 42, "sig", public_key, b"raw", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    ToyLatticeProof(public_key=public_key, signature=bad)

    def test_invalid_nested_values_raise_value_error(self):
        # The field value objects keep enforcing the existing E-vector and
        # 32-byte tag constraints at their own construction time.
        with self.assertRaises(ValueError):
            ToyLatticeSignature(u=b"\x01\x01" + b"\x00" * 14, tag=b"\x00" * 32)
        with self.assertRaises(ValueError):
            ToyLatticeSignature(u=b"\x00" * 16, tag=b"\x00" * 31)
        with self.assertRaises(ValueError):
            ToyLatticePublicKey(b"\x00" * 15)

    def test_foreign_signature_builds_but_does_not_verify(self):
        private_a, public_a = make_keypair(start=0)
        _, public_b = make_keypair(start=1000)
        foreign = toy_lattice_sign(
            b"m", private_a, token_bytes=fixed_tokens(b"zyxwvuts")
        )
        proof = ToyLatticeProof(public_key=public_b, signature=foreign)
        self.assertFalse(proof.verify(b"m"))


class ToyLatticeProofFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        public_key, proof = make_proof()
        key_blob = public_key.to_bytes()
        sig_blob = proof.signature.to_bytes()
        blob = proof.to_bytes()
        self.assertEqual(
            len(blob), _PROOF_HEADER_BYTES + len(key_blob) + len(sig_blob)
        )
        self.assertEqual(blob[:8], b"PQALPF\0\0")
        self.assertEqual(blob[8], 1)
        self.assertEqual(int.from_bytes(blob[9:13], "big"), len(key_blob))
        self.assertEqual(int.from_bytes(blob[13:17], "big"), len(sig_blob))
        self.assertEqual(
            blob[_PROOF_HEADER_BYTES : _PROOF_HEADER_BYTES + len(key_blob)],
            key_blob,
        )
        self.assertEqual(blob[_PROOF_HEADER_BYTES + len(key_blob) :], sig_blob)

    def test_deterministic_encoding(self):
        _, proof = make_proof()
        self.assertEqual(proof.to_bytes(), proof.to_bytes())
        _, same = make_proof()
        self.assertEqual(proof.to_bytes(), same.to_bytes())

    def test_round_trip(self):
        _, proof = make_proof()
        restored = ToyLatticeProof.from_bytes(proof.to_bytes())
        self.assertEqual(restored, proof)
        self.assertIsInstance(restored.public_key, ToyLatticePublicKey)
        self.assertIsInstance(restored.signature, ToyLatticeSignature)

    def test_from_bytes_accepts_bytearray(self):
        _, proof = make_proof()
        self.assertEqual(ToyLatticeProof.from_bytes(bytearray(proof.to_bytes())), proof)

    def test_from_bytes_rejects_other_types(self):
        _, proof = make_proof()
        for bad in (None, 42, "blob", proof.to_bytes().decode("latin1"), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    ToyLatticeProof.from_bytes(bad)

    def test_bad_magic_version_truncation_trailing(self):
        _, proof = make_proof()
        blob = proof.to_bytes()
        with self.assertRaises(ValueError):
            ToyLatticeProof.from_bytes(b"PQALPX\0\0" + blob[8:])
        with self.assertRaises(ValueError):
            ToyLatticeProof.from_bytes(blob[:8] + bytes((2,)) + blob[9:])
        with self.assertRaises(ValueError):
            ToyLatticeProof.from_bytes(blob[: _PROOF_HEADER_BYTES - 1])
        with self.assertRaises(ValueError):
            ToyLatticeProof.from_bytes(blob[:-1])
        with self.assertRaises(ValueError):
            ToyLatticeProof.from_bytes(blob + b"\x00")

    def test_length_field_mismatch(self):
        public_key, proof = make_proof()
        blob = proof.to_bytes()
        key_blob = public_key.to_bytes()
        sig_blob = blob[_PROOF_HEADER_BYTES + len(key_blob) :]
        bad = blob[:9] + (len(key_blob) + 1).to_bytes(4, "big") + blob[13:]
        with self.assertRaises(ValueError):
            ToyLatticeProof.from_bytes(bad)
        for key_len, sig_len in ((0, len(sig_blob)), (len(key_blob), 0)):
            with self.subTest(key_len=key_len, sig_len=sig_len):
                bad = (
                    blob[:9]
                    + key_len.to_bytes(4, "big")
                    + sig_len.to_bytes(4, "big")
                    + blob[17:]
                )
                with self.assertRaises(ValueError):
                    ToyLatticeProof.from_bytes(bad)

    def test_invalid_nested_encodings(self):
        public_key, proof = make_proof()
        blob = proof.to_bytes()
        key_blob = public_key.to_bytes()
        sig_blob = blob[_PROOF_HEADER_BYTES + len(key_blob) :]
        bad_key = b"PQALPX\0\0" + key_blob[8:]
        with self.assertRaises(ValueError):
            ToyLatticeProof.from_bytes(proof_envelope(bad_key, sig_blob))
        bad_sig = b"PQALSX\0\0" + sig_blob[8:]
        with self.assertRaises(ValueError):
            ToyLatticeProof.from_bytes(proof_envelope(key_blob, bad_sig))
        # Nested key with an out-of-range E coefficient.
        corrupt_key = key_blob[:9] + b"\x01\x01" + key_blob[11:]
        with self.assertRaises(ValueError):
            ToyLatticeProof.from_bytes(proof_envelope(corrupt_key, sig_blob))
        # Nested signature whose declared tag length is not 32.
        corrupt_sig = sig_blob[:25] + (33).to_bytes(4, "big") + sig_blob[29:]
        # Total byte count must be consistent with the declared length for the
        # truncation/trailing checks not to fire first; append one tag byte.
        corrupt_sig = corrupt_sig + b"\x00"
        with self.assertRaises(ValueError):
            ToyLatticeProof.from_bytes(proof_envelope(key_blob, corrupt_sig))

    def test_swapped_nested_order_rejected(self):
        public_key, proof = make_proof()
        blob = proof.to_bytes()
        key_blob = public_key.to_bytes()
        sig_blob = blob[_PROOF_HEADER_BYTES + len(key_blob) :]
        with self.assertRaises(ValueError):
            ToyLatticeProof.from_bytes(proof_envelope(sig_blob, key_blob))

    def test_corrupted_fields_encode_raises_value_error(self):
        _, proof = make_proof()
        object.__setattr__(proof, "signature", "not-a-signature")
        with self.assertRaises(ValueError):
            proof.to_bytes()
        _, proof2 = make_proof()
        object.__setattr__(proof2, "public_key", "not-a-key")
        with self.assertRaises(ValueError):
            proof2.to_bytes()


class ToyLatticeProofVerifyTest(unittest.TestCase):
    def test_verify_signed_message_only(self):
        _, proof = make_proof(message=b"position claim")
        self.assertTrue(proof.verify(b"position claim"))
        self.assertTrue(proof.verify(bytearray(b"position claim")))
        self.assertTrue(proof.verify("position claim"))
        self.assertFalse(proof.verify(b"other claim"))
        self.assertFalse(proof.verify(b""))

    def test_verify_matches_toy_lattice_verify(self):
        private_key, public_key = make_keypair()
        signature = toy_lattice_sign(b"m", private_key)
        proof = ToyLatticeProof(public_key, signature)
        self.assertEqual(
            proof.verify(b"m"), toy_lattice_verify(b"m", signature, public_key)
        )

    def test_tampered_signature_returns_false(self):
        public_key, proof = make_proof()
        forged_tag = bytes(proof.signature.tag[i] ^ 0xFF for i in range(32))
        tampered = ToyLatticeSignature(u=proof.signature.u, tag=forged_tag)
        forged = ToyLatticeProof(public_key=public_key, signature=tampered)
        self.assertFalse(forged.verify(b"position claim"))

    def test_illegal_message_type_returns_false(self):
        _, proof = make_proof()
        for bad in (None, 42, 3.5, object(), ["x"]):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(proof.verify(bad))

    def test_corrupted_fields_return_false(self):
        _, proof = make_proof()
        object.__setattr__(proof, "signature", "not-a-signature")
        self.assertFalse(proof.verify(b"position claim"))
        _, proof2 = make_proof()
        object.__setattr__(proof2, "public_key", object())
        self.assertFalse(proof2.verify(b"position claim"))

    def test_round_tripped_proof_still_verifies(self):
        _, proof = make_proof(message=b"m")
        restored = ToyLatticeProof.from_bytes(proof.to_bytes())
        self.assertEqual(restored, proof)
        self.assertTrue(restored.verify(b"m"))


class ToyLatticeProofVerifyBoundTest(unittest.TestCase):
    def test_bound_verifies_signed_message(self):
        public_key, proof = make_proof()
        self.assertTrue(proof.verify_bound(b"position claim", public_key=public_key))

    def test_message_types_match_plain_verify(self):
        for message in ("claim", b"bytes claim", bytearray(b"array claim")):
            with self.subTest(kind=type(message).__name__):
                public_key, proof = make_proof(message=message)
                self.assertTrue(proof.verify_bound(message, public_key=public_key))

    def test_value_equal_distinct_key_accepted(self):
        public_key, proof = make_proof()
        other = ToyLatticePublicKey(bytes(public_key.t))
        self.assertIsNot(other, public_key)
        self.assertTrue(proof.verify_bound(b"position claim", public_key=other))

    def test_key_must_be_keyword(self):
        public_key, proof = make_proof()
        with self.assertRaises(TypeError):
            proof.verify_bound(b"position claim", public_key)

    def test_wrong_key_type_raises_type_error(self):
        _, proof = make_proof()
        for bad in (None, 42, 4.5, "key", b"key", proof.signature, object(), ()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    proof.verify_bound(b"position claim", public_key=bad)

    def test_type_error_takes_precedence_over_other_failures(self):
        _, proof = make_proof()
        with self.assertRaises(TypeError):
            proof.verify_bound(b"wrong", public_key="not-a-key")

    def test_key_value_mismatch_is_false(self):
        public_key, proof = make_proof()
        _, foreign_key = make_keypair(start=6000)
        self.assertFalse(
            proof.verify_bound(b"position claim", public_key=foreign_key)
        )

    def test_wrong_message_is_false_even_with_matching_key(self):
        public_key, proof = make_proof()
        self.assertFalse(proof.verify_bound(b"other", public_key=public_key))
        self.assertFalse(proof.verify_bound(None, public_key=public_key))

    def test_illegal_message_type_is_false(self):
        public_key, proof = make_proof()
        for bad in (None, 42, 3.5, object(), ["x"]):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(proof.verify_bound(bad, public_key=public_key))

    def test_tampered_signature_is_false_even_with_matching_key(self):
        public_key, proof = make_proof()
        forged_tag = bytes(proof.signature.tag[i] ^ 0xFF for i in range(32))
        tampered = ToyLatticeSignature(u=proof.signature.u, tag=forged_tag)
        forged = ToyLatticeProof(public_key=public_key, signature=tampered)
        self.assertFalse(forged.verify_bound(b"position claim", public_key=public_key))

    def test_malformed_bypass_constructed_proof_is_false(self):
        public_key, proof = make_proof()
        rogue = object.__new__(ToyLatticeProof)
        object.__setattr__(rogue, "public_key", "not-a-key")
        object.__setattr__(rogue, "signature", proof.signature)
        self.assertFalse(rogue.verify_bound(b"position claim", public_key=public_key))
        rogue2 = object.__new__(ToyLatticeProof)
        object.__setattr__(rogue2, "public_key", public_key)
        object.__setattr__(rogue2, "signature", "not-a-signature")
        self.assertFalse(rogue2.verify_bound(b"position claim", public_key=public_key))
        rogue3 = object.__new__(ToyLatticeProof)
        self.assertFalse(rogue3.verify_bound(b"position claim", public_key=public_key))

    def test_hostile_field_objects_do_not_leak_exceptions(self):
        class Boom:
            def __eq__(self, other):
                raise RuntimeError("boom")

            def __ne__(self, other):
                raise RuntimeError("boom")

        _, proof = make_proof()
        rogue = object.__new__(ToyLatticeProof)
        object.__setattr__(rogue, "public_key", Boom())
        object.__setattr__(rogue, "signature", proof.signature)
        _, public_key = make_keypair(start=9000)
        self.assertFalse(rogue.verify_bound(b"position claim", public_key=public_key))

    def test_repeated_calls_are_stable(self):
        public_key, proof = make_proof()
        for _ in range(5):
            self.assertTrue(proof.verify_bound(b"position claim", public_key=public_key))
            self.assertFalse(proof.verify_bound(b"other", public_key=public_key))

    def test_round_tripped_proof_still_verifies_bound(self):
        public_key, proof = make_proof(message=b"m")
        restored = ToyLatticeProof.from_bytes(proof.to_bytes())
        self.assertEqual(restored, proof)
        self.assertTrue(restored.verify_bound(b"m", public_key=public_key))

    def test_plain_verify_unchanged(self):
        _, proof = make_proof(message=b"m")
        self.assertTrue(proof.verify(b"m"))
        self.assertFalse(proof.verify(b"other"))
        self.assertEqual(sorted(vars(proof).keys()), ["public_key", "signature"])


class ToyLatticeProofExportTest(unittest.TestCase):
    def test_toplevel_export(self):
        import pqattest

        self.assertIs(pqattest.ToyLatticeProof, ToyLatticeProof)
        self.assertIn("ToyLatticeProof", pqattest.__all__)


if __name__ == "__main__":
    unittest.main()

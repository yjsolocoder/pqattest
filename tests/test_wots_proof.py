import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    PublicKey,
    WOTSProof,
    WOTSPublicKey,
    keygen,
    wots_keygen,
    wots_sign,
    wots_signature_to_bytes,
)

_PROOF_HEADER_BYTES = 8 + 1 + 4 + 4


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_keypair(w=4, start=0):
    return wots_keygen(w=w, token_bytes=counter_tokens(start))


def make_proof(w=4, start=0, message=b"position claim"):
    private_key, public_key = make_keypair(w=w, start=start)
    signature = wots_sign(message, private_key)
    return public_key, WOTSProof(public_key=public_key, signature=signature)


def proof_envelope(key_blob: bytes, sig_blob: bytes) -> bytes:
    return (
        b"PQAWPRF\0"
        + bytes((1,))
        + len(key_blob).to_bytes(4, "big")
        + len(sig_blob).to_bytes(4, "big")
        + key_blob
        + sig_blob
    )


class WOTSProofConstructionTest(unittest.TestCase):
    def test_fields_and_equality(self):
        private_key, public_key = make_keypair()
        signature = wots_sign(b"m", private_key)
        proof = WOTSProof(public_key, signature)
        self.assertIs(proof.public_key, public_key)
        self.assertIs(proof.signature, signature)
        self.assertEqual(proof, WOTSProof(public_key, signature))
        self.assertEqual(hash(proof), hash(WOTSProof(public_key, signature)))

    def test_positional_construction(self):
        private_key, public_key = make_keypair()
        signature = wots_sign(b"m", private_key)
        self.assertEqual(
            WOTSProof(public_key, signature),
            WOTSProof(public_key=public_key, signature=signature),
        )

    def test_frozen(self):
        _, proof = make_proof()
        with self.assertRaises(FrozenInstanceError):
            proof.public_key = proof.public_key
        with self.assertRaises(FrozenInstanceError):
            proof.signature = proof.signature

    def test_wrong_field_types_raise_type_error(self):
        private_key, public_key = make_keypair()
        signature = wots_sign(b"m", private_key)
        for bad in (None, 42, "key", signature, b"raw", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    WOTSProof(public_key=bad, signature=signature)
        for bad in (None, 42, "sig", public_key, b"raw", list(signature), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    WOTSProof(public_key=public_key, signature=bad)
        bad_member = signature[:-1] + ("not-bytes",)
        with self.assertRaises(TypeError):
            WOTSProof(public_key=public_key, signature=bad_member)

    def test_chain_count_mismatch_raises_value_error(self):
        private_key, public_key = make_keypair()
        signature = wots_sign(b"m", private_key)
        for bad in (signature[:-1], signature + (b"\x00" * 32,), ()):
            with self.subTest(count=len(bad)):
                with self.assertRaises(ValueError):
                    WOTSProof(public_key=public_key, signature=bad)

    def test_element_length_mismatch_raises_value_error(self):
        private_key, public_key = make_keypair()
        signature = wots_sign(b"m", private_key)
        bad = signature[:-1] + (b"short",)
        with self.assertRaises(ValueError):
            WOTSProof(public_key=public_key, signature=bad)

    def test_w_mismatch_raises_value_error(self):
        private_4, public_4 = make_keypair(w=4)
        private_8, public_8 = make_keypair(w=8, start=1000)
        signature_8 = wots_sign(b"m", private_8)
        with self.assertRaises(ValueError):
            WOTSProof(public_key=public_4, signature=signature_8)
        signature_4 = wots_sign(b"m", private_4)
        with self.assertRaises(ValueError):
            WOTSProof(public_key=public_8, signature=signature_4)

    def test_same_shape_foreign_signature_builds_but_does_not_verify(self):
        private_a, public_a = make_keypair(start=0)
        _, public_b = make_keypair(start=1000)
        foreign = wots_sign(b"m", private_a)
        proof = WOTSProof(public_key=public_b, signature=foreign)
        self.assertFalse(proof.verify(b"m"))


class WOTSProofFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for w in (4, 8):
            with self.subTest(w=w):
                public_key, proof = make_proof(w=w)
                key_blob = public_key.to_bytes()
                sig_blob = wots_signature_to_bytes(proof.signature, w=w)
                blob = proof.to_bytes()
                self.assertEqual(
                    len(blob), _PROOF_HEADER_BYTES + len(key_blob) + len(sig_blob)
                )
                self.assertEqual(blob[:8], b"PQAWPRF\0")
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
        for w in (4, 8):
            with self.subTest(w=w):
                _, proof = make_proof(w=w)
                restored = WOTSProof.from_bytes(proof.to_bytes())
                self.assertEqual(restored, proof)
                self.assertIsInstance(restored.signature, tuple)

    def test_from_bytes_accepts_bytearray(self):
        _, proof = make_proof()
        self.assertEqual(WOTSProof.from_bytes(bytearray(proof.to_bytes())), proof)

    def test_from_bytes_rejects_other_types(self):
        _, proof = make_proof()
        for bad in (None, 42, "blob", proof.to_bytes().decode("latin1"), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    WOTSProof.from_bytes(bad)

    def test_bad_magic_version_truncation_trailing(self):
        _, proof = make_proof()
        blob = proof.to_bytes()
        with self.assertRaises(ValueError):
            WOTSProof.from_bytes(b"PQAWPRX\0" + blob[8:])
        with self.assertRaises(ValueError):
            WOTSProof.from_bytes(blob[:8] + bytes((2,)) + blob[9:])
        with self.assertRaises(ValueError):
            WOTSProof.from_bytes(blob[: _PROOF_HEADER_BYTES - 1])
        with self.assertRaises(ValueError):
            WOTSProof.from_bytes(blob[:-1])
        with self.assertRaises(ValueError):
            WOTSProof.from_bytes(blob + b"\x00")

    def test_length_field_mismatch(self):
        public_key, proof = make_proof()
        blob = proof.to_bytes()
        key_blob = public_key.to_bytes()
        sig_blob = blob[_PROOF_HEADER_BYTES + len(key_blob) :]
        bad = blob[:9] + (len(key_blob) + 1).to_bytes(4, "big") + blob[13:]
        with self.assertRaises(ValueError):
            WOTSProof.from_bytes(bad)
        for key_len, sig_len in ((0, len(sig_blob)), (len(key_blob), 0)):
            with self.subTest(key_len=key_len, sig_len=sig_len):
                bad = (
                    blob[:9]
                    + key_len.to_bytes(4, "big")
                    + sig_len.to_bytes(4, "big")
                    + blob[17:]
                )
                with self.assertRaises(ValueError):
                    WOTSProof.from_bytes(bad)

    def test_invalid_nested_encodings(self):
        public_key, proof = make_proof()
        blob = proof.to_bytes()
        key_blob = public_key.to_bytes()
        sig_blob = blob[_PROOF_HEADER_BYTES + len(key_blob) :]
        bad_key = b"PQAWPUX\0" + key_blob[8:]
        with self.assertRaises(ValueError):
            WOTSProof.from_bytes(proof_envelope(bad_key, sig_blob))
        bad_sig = b"PQAWSIX\0" + sig_blob[8:]
        with self.assertRaises(ValueError):
            WOTSProof.from_bytes(proof_envelope(key_blob, bad_sig))

    def test_cross_inconsistent_w_rejected(self):
        # A valid key encoding and a valid signature encoding whose w values
        # disagree must be rejected even though both parse on their own.
        public_key, _ = make_proof(w=4)
        other_private, _ = make_keypair(w=8, start=1000)
        other_sig = wots_signature_to_bytes(wots_sign(b"m", other_private), w=8)
        with self.assertRaises(ValueError):
            WOTSProof.from_bytes(proof_envelope(public_key.to_bytes(), other_sig))

    def test_corrupted_fields_encode_raises_value_error(self):
        _, proof = make_proof()
        object.__setattr__(proof, "signature", list(proof.signature))
        with self.assertRaises(ValueError):
            proof.to_bytes()
        _, proof2 = make_proof()
        object.__setattr__(proof2, "public_key", "not-a-key")
        with self.assertRaises(ValueError):
            proof2.to_bytes()


class WOTSProofVerifyTest(unittest.TestCase):
    def test_verify_signed_message_only(self):
        _, proof = make_proof(message=b"position claim")
        self.assertTrue(proof.verify(b"position claim"))
        self.assertTrue(proof.verify(bytearray(b"position claim")))
        self.assertTrue(proof.verify("position claim"))
        self.assertFalse(proof.verify(b"other claim"))
        self.assertFalse(proof.verify(b""))

    def test_tampered_fields_return_false(self):
        public_key, proof = make_proof()
        tampered = proof.signature[:-1] + (b"\x00" * 32,)
        forged = WOTSProof(public_key=public_key, signature=tampered)
        self.assertFalse(forged.verify(b"position claim"))

    def test_illegal_message_type_returns_false(self):
        _, proof = make_proof()
        for bad in (None, 42, 3.5, object(), ["x"]):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(proof.verify(bad))

    def test_corrupted_fields_return_false(self):
        _, proof = make_proof()
        object.__setattr__(proof, "signature", "not-a-tuple")
        self.assertFalse(proof.verify(b"position claim"))
        _, proof2 = make_proof()
        object.__setattr__(proof2, "public_key", object())
        self.assertFalse(proof2.verify(b"position claim"))


class WOTSProofVerifyBoundTest(unittest.TestCase):
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
        other = WOTSPublicKey(w=public_key.w, elements=tuple(public_key.elements))
        self.assertIsNot(other, public_key)
        self.assertTrue(proof.verify_bound(b"position claim", public_key=other))

    def test_key_must_be_keyword(self):
        public_key, proof = make_proof()
        with self.assertRaises(TypeError):
            proof.verify_bound(b"position claim", public_key)

    def test_no_extra_arguments(self):
        public_key, proof = make_proof()
        with self.assertRaises(TypeError):
            proof.verify_bound(b"position claim", public_key=public_key, extra=1)

    def test_wrong_key_type_raises_type_error(self):
        lamport_public = keygen()[1]
        _, proof = make_proof()
        for bad in (None, 42, 4.5, "key", b"key", lamport_public, object(), ()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    proof.verify_bound(b"position claim", public_key=bad)

    def test_other_w_value_key_is_value_mismatch_not_type_error(self):
        public_key, proof = make_proof(w=4)
        other_key, _ = make_proof(w=8, start=5000)
        self.assertIsInstance(other_key, WOTSPublicKey)
        self.assertFalse(proof.verify_bound(b"position claim", public_key=other_key))

    def test_type_error_takes_precedence_over_other_failures(self):
        _, proof = make_proof()
        with self.assertRaises(TypeError):
            proof.verify_bound(b"wrong", public_key="not-a-key")

    def test_key_value_mismatch_is_false(self):
        public_key, proof = make_proof()
        foreign_key, _ = make_proof(start=6000)
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
        tampered = proof.signature[:-1] + (b"\x00" * 32,)
        forged = WOTSProof(public_key=public_key, signature=tampered)
        self.assertFalse(forged.verify_bound(b"position claim", public_key=public_key))

    def test_malformed_bypass_constructed_proof_is_false(self):
        public_key, proof = make_proof()
        rogue = object.__new__(WOTSProof)
        object.__setattr__(rogue, "public_key", "not-a-key")
        object.__setattr__(rogue, "signature", proof.signature)
        self.assertFalse(rogue.verify_bound(b"position claim", public_key=public_key))
        rogue2 = object.__new__(WOTSProof)
        object.__setattr__(rogue2, "public_key", public_key)
        object.__setattr__(rogue2, "signature", "not-a-tuple")
        self.assertFalse(rogue2.verify_bound(b"position claim", public_key=public_key))
        # Fields missing entirely.
        rogue3 = object.__new__(WOTSProof)
        self.assertFalse(rogue3.verify_bound(b"position claim", public_key=public_key))

    def test_hostile_field_objects_do_not_leak_exceptions(self):
        class Boom:
            def __eq__(self, other):
                raise RuntimeError("boom")

            def __ne__(self, other):
                raise RuntimeError("boom")

        _, proof = make_proof()
        rogue = object.__new__(WOTSProof)
        object.__setattr__(rogue, "public_key", Boom())
        object.__setattr__(rogue, "signature", proof.signature)
        public_key, _ = make_proof(start=9000)
        self.assertFalse(rogue.verify_bound(b"position claim", public_key=public_key))

    def test_repeated_calls_are_stable(self):
        public_key, proof = make_proof()
        for _ in range(5):
            self.assertTrue(proof.verify_bound(b"position claim", public_key=public_key))
            self.assertFalse(proof.verify_bound(b"other", public_key=public_key))

    def test_round_tripped_proof_still_verifies_bound(self):
        public_key, proof = make_proof(message=b"m")
        restored = WOTSProof.from_bytes(proof.to_bytes())
        self.assertEqual(restored, proof)
        self.assertTrue(restored.verify_bound(b"m", public_key=public_key))

    def test_plain_verify_unchanged(self):
        _, proof = make_proof(message=b"m")
        self.assertTrue(proof.verify(b"m"))
        self.assertFalse(proof.verify(b"other"))
        self.assertEqual(sorted(vars(proof).keys()), ["public_key", "signature"])


if __name__ == "__main__":
    unittest.main()

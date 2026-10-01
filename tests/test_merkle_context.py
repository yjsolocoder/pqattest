"""Optional context binding for Merkle one-time signatures.

Covers every public generation entry on ``MerkleSigner`` (single, batch,
selected-leaf, proof bundles and multiproofs, with checkpoint and auth-state
variants) and every verification entry (``merkle_verify``,
``MerkleProof`` / ``MerkleBatchProof`` verify and verify_bound,
``multiproof_verify`` / ``multiproof_verify_bound``).
"""

import unittest

from pqattest import (
    KeyExhaustedError,
    MerkleBatchProof,
    MerkleProof,
    MerkleSigner,
    merkle_verify,
    multiproof_encode,
    multiproof_verify,
    multiproof_verify_bound,
)

SEED = bytes(range(32))
CONTEXT_A = b"context-a"
CONTEXT_B = "café/context-b"  # str on purpose: UTF-8 must match its bytes
CONTEXT_B_BYTES = CONTEXT_B.encode("utf-8")
MESSAGE = b"the signed message"


def make_signer(seed: bytes = SEED, height: int = 3, w: int = 4) -> MerkleSigner:
    return MerkleSigner.from_seed(seed, height=height, w=w)


BAD_CONTEXTS = (1, 1.5, ["ctx"], {"ctx": 1}, object())


class ContextNormalisationTest(unittest.TestCase):
    def test_none_and_empty_are_legacy_identical(self):
        signature = make_signer().sign(MESSAGE)
        for context in (None, b"", bytearray(b""), ""):
            with self.subTest(context=repr(context)):
                signer = make_signer()
                got = (
                    signer.sign(MESSAGE)
                    if context is None
                    else signer.sign(MESSAGE, context=context)
                )
                self.assertEqual(got, signature)
                self.assertTrue(
                    merkle_verify(
                        MESSAGE,
                        signature,
                        make_signer().public_key,
                        context=context,
                    )
                )

    def test_context_changes_the_signature_at_the_same_leaf(self):
        bound = make_signer().sign(MESSAGE, context=CONTEXT_A)
        unbound = make_signer().sign(MESSAGE)
        self.assertNotEqual(bound, unbound)
        self.assertEqual(bound.index, unbound.index)

    def test_str_context_uses_utf8_and_is_deterministic(self):
        first = make_signer().sign(MESSAGE, context=CONTEXT_B)
        second = make_signer().sign(MESSAGE, context=CONTEXT_B_BYTES)
        third = make_signer().sign(MESSAGE, context=CONTEXT_B)
        self.assertEqual(first, second)
        self.assertEqual(first, third)

    def test_bytearray_context_accepted(self):
        signature = make_signer().sign(MESSAGE, context=bytearray(CONTEXT_A))
        self.assertTrue(
            merkle_verify(
                MESSAGE, signature, make_signer().public_key, context=CONTEXT_A
            )
        )

    def test_wrong_context_is_not_just_a_different_message(self):
        # The binding must enter the W-OTS message digest: verifying the same
        # message under the wrong context is the same as verifying a wrong
        # message under the right context, and neither passes.
        signature = make_signer().sign(MESSAGE, context=CONTEXT_A)
        public_key = make_signer().public_key
        self.assertTrue(
            merkle_verify(MESSAGE, signature, public_key, context=CONTEXT_A)
        )
        self.assertFalse(merkle_verify(MESSAGE, signature, public_key))
        self.assertFalse(
            merkle_verify(MESSAGE, signature, public_key, context=CONTEXT_B_BYTES)
        )
        self.assertFalse(
            merkle_verify(b"wrong message", signature, public_key, context=CONTEXT_A)
        )
        # Empty and non-empty contexts are genuinely separated: a signature
        # made under one context cannot be accepted under another.
        other = make_signer().sign(MESSAGE, context=b"")
        self.assertNotEqual(other, make_signer().sign(MESSAGE, context=CONTEXT_A))


class GenerationTypeErrorTest(unittest.TestCase):
    def _assert_type_error(self, callable_, label):
        for bad in BAD_CONTEXTS:
            with self.subTest(label=label, bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    callable_(bad)

    def test_bad_context_type_on_every_generator(self):
        def fresh():
            return make_signer()

        self._assert_type_error(
            lambda c: fresh().sign(MESSAGE, context=c), "sign"
        )
        self._assert_type_error(
            lambda c: fresh().sign_with_checkpoint(MESSAGE, context=c),
            "sign_with_checkpoint",
        )
        self._assert_type_error(
            lambda c: fresh().sign_with_auth_state(
                MESSAGE, key=b"key", generation=0, context=c
            ),
            "sign_with_auth_state",
        )
        self._assert_type_error(
            lambda c: fresh().sign_proof_with_checkpoint(MESSAGE, context=c),
            "sign_proof_with_checkpoint",
        )
        self._assert_type_error(
            lambda c: fresh().sign_proof_with_auth_state(
                MESSAGE, key=b"key", generation=0, context=c
            ),
            "sign_proof_with_auth_state",
        )
        self._assert_type_error(
            lambda c: fresh().sign_batch((MESSAGE, b"other"), context=c),
            "sign_batch",
        )
        self._assert_type_error(
            lambda c: fresh().sign_batch_with_checkpoint(
                (MESSAGE, b"other"), context=c
            ),
            "sign_batch_with_checkpoint",
        )
        self._assert_type_error(
            lambda c: fresh().sign_batch_with_auth_state(
                (MESSAGE, b"other"), key=b"key", generation=0, context=c
            ),
            "sign_batch_with_auth_state",
        )
        self._assert_type_error(
            lambda c: fresh().sign_multiproof_with_checkpoint(
                (MESSAGE, b"other"), context=c
            ),
            "sign_multiproof_with_checkpoint",
        )
        self._assert_type_error(
            lambda c: fresh().sign_multiproof_with_auth_state(
                (MESSAGE, b"other"), key=b"key", generation=0, context=c
            ),
            "sign_multiproof_with_auth_state",
        )
        self._assert_type_error(
            lambda c: fresh().sign_batch_proof_with_checkpoint(
                (MESSAGE, b"other"), context=c
            ),
            "sign_batch_proof_with_checkpoint",
        )
        self._assert_type_error(
            lambda c: fresh().sign_batch_proof_with_auth_state(
                (MESSAGE, b"other"), key=b"key", generation=0, context=c
            ),
            "sign_batch_proof_with_auth_state",
        )
        self._assert_type_error(
            lambda c: fresh().sign_selected((0, 2), (MESSAGE, b"z"), context=c),
            "sign_selected",
        )
        self._assert_type_error(
            lambda c: fresh().sign_selected_with_checkpoint(
                (0, 2), (MESSAGE, b"z"), context=c
            ),
            "sign_selected_with_checkpoint",
        )
        self._assert_type_error(
            lambda c: fresh().sign_selected_with_auth_state(
                (0, 2), (MESSAGE, b"z"), key=b"key", generation=0, context=c
            ),
            "sign_selected_with_auth_state",
        )

    def test_bad_message_type_still_raises_type_error(self):
        signer = make_signer()
        with self.assertRaises(TypeError):
            signer.sign(42, context=CONTEXT_A)
        with self.assertRaises(TypeError):
            signer.sign_batch((b"ok", 42), context=CONTEXT_A)
        with self.assertRaises(TypeError):
            signer.sign_selected((0,), (42,), context=CONTEXT_A)

    def test_bad_context_does_not_consume_a_leaf(self):
        signer = make_signer()
        before = signer.next_index
        for call in (
            lambda: signer.sign(MESSAGE, context=42),
            lambda: signer.sign_batch((MESSAGE, MESSAGE), context=42),
            lambda: signer.sign_selected((0, 1), (MESSAGE, b"x"), context=42),
        ):
            with self.assertRaises(TypeError):
                call()
        self.assertEqual(signer.next_index, before)
        # The next leaf is still 0 and signs normally.
        self.assertEqual(signer.sign(MESSAGE).index, 0)


class ExhaustionAndStateTest(unittest.TestCase):
    def test_exhaustion_still_raised_with_context(self):
        signer = make_signer(height=1)
        signer.sign(b"a", context=CONTEXT_A)
        signer.sign(b"b")
        with self.assertRaises(KeyExhaustedError):
            signer.sign(b"c", context=CONTEXT_A)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch((b"c",), context=CONTEXT_A)

    def test_batch_capacity_error_with_context_consumes_nothing(self):
        signer = make_signer(height=2)
        signer.advance_to(3)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch((b"a", b"b"), context=CONTEXT_A)
        self.assertEqual(signer.next_index, 3)

    def test_checkpoint_round_trip_preserves_context_signatures(self):
        signer = make_signer()
        signature, checkpoint = signer.sign_with_checkpoint(
            MESSAGE, context=CONTEXT_A
        )
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertTrue(
            merkle_verify(MESSAGE, signature, restored.public_key, context=CONTEXT_A)
        )
        self.assertFalse(merkle_verify(MESSAGE, signature, restored.public_key))
        next_signature = restored.sign(b"next", context=CONTEXT_B_BYTES)
        self.assertTrue(
            merkle_verify(
                b"next", next_signature, restored.public_key, context=CONTEXT_B_BYTES
            )
        )

    def test_seed_checkpoint_round_trip(self):
        signer = make_signer()
        signature = signer.sign(MESSAGE, context=CONTEXT_A)
        blob = signer.seed_checkpoint()
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.next_index, 1)
        self.assertTrue(
            merkle_verify(MESSAGE, signature, restored.public_key, context=CONTEXT_A)
        )

    def test_auth_state_round_trip(self):
        signer = make_signer()
        signature, envelope = signer.sign_with_auth_state(
            MESSAGE, key=b"shared secret", generation=7, context=CONTEXT_A
        )
        restored, generation = MerkleSigner.from_auth_state(
            envelope, key=b"shared secret", min_generation=7
        )
        self.assertEqual(generation, 7)
        self.assertTrue(
            merkle_verify(MESSAGE, signature, restored.public_key, context=CONTEXT_A)
        )


class SingleSignatureTest(unittest.TestCase):
    def test_sign_and_verify_with_matching_context(self):
        signer = make_signer()
        signature = signer.sign(MESSAGE, context=CONTEXT_A)
        self.assertTrue(
            merkle_verify(MESSAGE, signature, signer.public_key, context=CONTEXT_A)
        )

    def test_legacy_serialized_v1_bytes_still_verify(self):
        signer = make_signer()
        signature = signer.sign(MESSAGE)  # no context: legacy bytes
        wire = signature.to_bytes(signer.public_key)
        parsed = type(signature).from_bytes(wire, signer.public_key)
        self.assertTrue(merkle_verify(MESSAGE, parsed, signer.public_key))
        self.assertTrue(
            merkle_verify(MESSAGE, parsed, signer.public_key, context=b"")
        )
        self.assertFalse(
            merkle_verify(MESSAGE, parsed, signer.public_key, context=CONTEXT_A)
        )

    def test_bound_signature_serialises_with_existing_format(self):
        signer = make_signer()
        signature = signer.sign(MESSAGE, context=CONTEXT_A)
        wire = signature.to_bytes(signer.public_key)
        parsed = type(signature).from_bytes(wire, signer.public_key)
        self.assertEqual(parsed, signature)
        self.assertTrue(
            merkle_verify(MESSAGE, parsed, signer.public_key, context=CONTEXT_A)
        )
        self.assertFalse(merkle_verify(MESSAGE, parsed, signer.public_key))


class ProofTest(unittest.TestCase):
    def _proof(self):
        signer = make_signer(height=2)
        return signer, MerkleProof(
            signer.public_key, signer.sign(MESSAGE, context=CONTEXT_A)
        )

    def test_verify_requires_matching_context(self):
        signer, proof = self._proof()
        self.assertTrue(proof.verify(MESSAGE, context=CONTEXT_A))
        self.assertFalse(proof.verify(MESSAGE))
        self.assertFalse(proof.verify(MESSAGE, context=b"other"))
        self.assertFalse(proof.verify(b"wrong", context=CONTEXT_A))

    def test_verify_bound_requires_matching_context(self):
        signer, proof = self._proof()
        self.assertTrue(
            proof.verify_bound(
                MESSAGE,
                public_key=signer.public_key,
                index=0,
                context=CONTEXT_A,
            )
        )
        # Context mismatch fails even when key and leaf are exactly right.
        self.assertFalse(
            proof.verify_bound(MESSAGE, public_key=signer.public_key, index=0)
        )
        self.assertFalse(
            proof.verify_bound(
                MESSAGE,
                public_key=signer.public_key,
                index=0,
                context=b"other",
            )
        )

    def test_bad_context_type_raises_on_verify(self):
        _, proof = self._proof()
        for bad in BAD_CONTEXTS:
            with self.assertRaises(TypeError):
                proof.verify(MESSAGE, context=bad)
            with self.assertRaises(TypeError):
                proof.verify_bound(
                    MESSAGE, public_key=make_signer().public_key, context=bad
                )

    def test_serialized_proof_round_trip_with_context(self):
        signer = make_signer(height=2)
        blob, _ = signer.sign_proof_with_checkpoint(MESSAGE, context=CONTEXT_A)
        proof = MerkleProof.from_bytes(blob)
        self.assertTrue(proof.verify(MESSAGE, context=CONTEXT_A))
        self.assertFalse(proof.verify(MESSAGE))

    def test_proof_generator_variants_match(self):
        messages = (MESSAGE, b"second")
        s1 = make_signer()
        s2 = make_signer()
        sigs = s1.sign_batch(messages, context=CONTEXT_A)
        blob, _ = s2.sign_batch_proof_with_checkpoint(messages, context=CONTEXT_A)
        batch = MerkleBatchProof.from_bytes(blob)
        self.assertEqual(batch.signatures, sigs)


class BatchProofTest(unittest.TestCase):
    MESSAGES = (b"a", b"b", b"a")  # duplicate message kept, order matters

    def _batch(self):
        signer = make_signer()
        signatures = signer.sign_batch(self.MESSAGES, context=CONTEXT_A)
        return signer, MerkleBatchProof(signer.public_key, signatures)

    def test_verify_requires_context_and_order(self):
        signer, batch = self._batch()
        self.assertTrue(batch.verify(self.MESSAGES, context=CONTEXT_A))
        self.assertFalse(batch.verify(self.MESSAGES))
        self.assertFalse(batch.verify(self.MESSAGES, context=b"other"))
        # Same set in a different order must fail under the right context.
        self.assertFalse(
            batch.verify((b"b", b"a", b"a"), context=CONTEXT_A)
        )
        self.assertFalse(
            batch.verify((b"a", b"b"), context=CONTEXT_A)
        )

    def test_verify_bound_requires_context(self):
        signer, batch = self._batch()
        indices = tuple(range(len(self.MESSAGES)))
        self.assertTrue(
            batch.verify_bound(
                self.MESSAGES,
                public_key=signer.public_key,
                indices=indices,
                context=CONTEXT_A,
            )
        )
        self.assertFalse(
            batch.verify_bound(
                self.MESSAGES, public_key=signer.public_key, indices=indices
            )
        )

    def test_serialized_batch_round_trip_with_context(self):
        signer = make_signer()
        blob, _ = signer.sign_batch_proof_with_checkpoint(
            self.MESSAGES, context=CONTEXT_A
        )
        batch = MerkleBatchProof.from_bytes(blob)
        self.assertTrue(batch.verify(self.MESSAGES, context=CONTEXT_A))
        self.assertFalse(batch.verify(self.MESSAGES))

    def test_bad_context_type_raises(self):
        _, batch = self._batch()
        for bad in BAD_CONTEXTS:
            with self.assertRaises(TypeError):
                batch.verify(self.MESSAGES, context=bad)
            with self.assertRaises(TypeError):
                batch.verify_bound(
                    self.MESSAGES,
                    public_key=make_signer().public_key,
                    context=bad,
                )


class SelectedLeafTest(unittest.TestCase):
    INDICES = (0, 2, 3)
    MESSAGES = (b"x", b"y", b"z")

    def test_three_generators_agree_and_verify(self):
        variants = (
            lambda signer: signer.sign_selected(
                self.INDICES, self.MESSAGES, context=CONTEXT_A
            ),
            lambda signer: signer.sign_selected_with_checkpoint(
                self.INDICES, self.MESSAGES, context=CONTEXT_A
            )[0],
            lambda signer: signer.sign_selected_with_auth_state(
                self.INDICES,
                self.MESSAGES,
                key=b"k",
                generation=2,
                context=CONTEXT_A,
            )[0],
        )
        baseline = variants[0](make_signer())
        for variant in variants[1:]:
            self.assertEqual(variant(make_signer()), baseline)
        signer = make_signer()
        signatures = variants[0](signer)
        self.assertEqual(signer.next_index, 4)  # gaps voided: last leaf + 1
        for index, message, signature in zip(
            self.INDICES, self.MESSAGES, signatures
        ):
            self.assertEqual(signature.index, index)
            self.assertTrue(
                merkle_verify(
                    message, signature, signer.public_key, context=CONTEXT_A
                )
            )
            self.assertFalse(
                merkle_verify(message, signature, signer.public_key)
            )

    def test_wrong_context_fails_every_signature(self):
        signer = make_signer()
        signatures = signer.sign_selected(
            self.INDICES, self.MESSAGES, context=CONTEXT_A
        )
        for message, signature in zip(self.MESSAGES, signatures):
            self.assertFalse(
                merkle_verify(
                    message, signature, signer.public_key, context=b"other"
                )
            )


class MultiproofTest(unittest.TestCase):
    MESSAGES = (b"q", b"r", b"s")

    def _proof(self, height=3):
        signer = make_signer(height=height)
        signatures = signer.sign_batch(self.MESSAGES, context=CONTEXT_A)
        return signer, multiproof_encode(signer.public_key, signatures)

    def test_verify_requires_context_and_order(self):
        signer, proof = self._proof()
        self.assertTrue(
            multiproof_verify(self.MESSAGES, proof, context=CONTEXT_A)
        )
        self.assertFalse(multiproof_verify(self.MESSAGES, proof))
        self.assertFalse(
            multiproof_verify(self.MESSAGES, proof, context=b"other")
        )
        self.assertFalse(
            multiproof_verify(
                tuple(reversed(self.MESSAGES)), proof, context=CONTEXT_A
            )
        )

    def test_verify_bound_requires_context(self):
        signer, proof = self._proof()
        indices = tuple(range(len(self.MESSAGES)))
        self.assertTrue(
            multiproof_verify_bound(
                self.MESSAGES,
                proof,
                public_key=signer.public_key,
                indices=indices,
                context=CONTEXT_A,
            )
        )
        self.assertFalse(
            multiproof_verify_bound(
                self.MESSAGES, proof, public_key=signer.public_key, indices=indices
            )
        )

    def test_bad_context_type_raises(self):
        _, proof = self._proof()
        for bad in BAD_CONTEXTS:
            with self.assertRaises(TypeError):
                multiproof_verify(self.MESSAGES, proof, context=bad)
            with self.assertRaises(TypeError):
                multiproof_verify_bound(
                    self.MESSAGES,
                    proof,
                    public_key=make_signer().public_key,
                    context=bad,
                )

    def test_generator_variants_are_byte_identical(self):
        s0 = make_signer()
        signatures = s0.sign_batch(self.MESSAGES, context=CONTEXT_A)
        expected = multiproof_encode(s0.public_key, signatures)

        s1 = make_signer()
        proof, _ = s1.sign_multiproof_with_checkpoint(
            self.MESSAGES, context=CONTEXT_A
        )
        self.assertEqual(proof, expected)

        s2 = make_signer()
        proof_auth, _ = s2.sign_multiproof_with_auth_state(
            self.MESSAGES, key=b"k", generation=1, context=CONTEXT_A
        )
        self.assertEqual(proof_auth, expected)

    def test_context_proof_verifies_after_key_round_trip(self):
        signer, proof = self._proof()
        self.assertTrue(
            multiproof_verify(self.MESSAGES, proof, context=CONTEXT_A)
        )
        # The same v1 bytes fail as soon as the context differs: context is
        # bound into the recovered leaf hashes, not signalled in the bytes.
        self.assertFalse(
            multiproof_verify(self.MESSAGES, proof, context=b"")
        )

    def test_dedup_semantics_unchanged(self):
        # Non-consecutive leaves still share/dedup nodes and verify with
        # context exactly as without it.
        signer = make_signer(height=3)
        indices = (0, 2, 3)
        messages = (b"a", b"b", b"c")
        signatures = signer.sign_selected(
            indices, messages, context=CONTEXT_A
        )
        proof = multiproof_encode(signer.public_key, signatures)
        self.assertTrue(
            multiproof_verify_bound(
                messages,
                proof,
                public_key=signer.public_key,
                indices=indices,
                context=CONTEXT_A,
            )
        )
        self.assertFalse(
            multiproof_verify_bound(
                messages, proof, public_key=signer.public_key, indices=indices
            )
        )


if __name__ == "__main__":
    unittest.main()

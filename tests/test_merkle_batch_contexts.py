"""Per-message context binding (``contexts=``) for Merkle batch entries.

Covers ``MerkleSigner.sign_batch`` / ``sign_batch_with_checkpoint`` and the
verification entries ``MerkleBatchProof.verify`` / ``verify_bound`` and
``multiproof_verify`` / ``multiproof_verify_bound``: positional per-message
contexts, equivalence with sequential single-sign calls, the fixed
validation order (types, then length/conflict, then capacity), the
all-or-nothing state rules and the unchanged legacy behaviour when
``contexts`` is omitted.
"""

import unittest

from pqattest import (
    KeyExhaustedError,
    MerkleBatchProof,
    MerkleSigner,
    merkle_verify,
    multiproof_encode,
    multiproof_verify,
    multiproof_verify_bound,
)

SEED = bytes(range(32))
MESSAGES = (b"alpha", b"beta", "gamma")
CONTEXTS = (b"ctx-a", "ctx-b/ü", None)  # None == no context for that slot
CONTEXTS_BYTES = tuple(
    None if c is None else (c.encode("utf-8") if isinstance(c, str) else c)
    for c in CONTEXTS
)

BAD_CONTEXTS = (1, 1.5, ["ctx"], {"ctx": 1}, object())


def make_signer(seed: bytes = SEED, height: int = 3, w: int = 4) -> MerkleSigner:
    return MerkleSigner.from_seed(seed, height=height, w=w)


def sequential_sign(messages, contexts, height=3, w=4):
    signer = make_signer(height=height, w=w)
    return tuple(
        signer.sign(message, context=context)
        for message, context in zip(messages, contexts)
    )


class SignBatchContextsTest(unittest.TestCase):
    def test_matches_sequential_single_signing(self):
        expected = sequential_sign(MESSAGES, CONTEXTS)
        for w in (4, 8):
            with self.subTest(w=w):
                signer = make_signer(w=w)
                signatures = signer.sign_batch(
                    MESSAGES, contexts=CONTEXTS
                )
                self.assertEqual(
                    signatures, sequential_sign(MESSAGES, CONTEXTS, w=w)
                )
                self.assertEqual(signer.next_index, len(MESSAGES))
        self.assertEqual(
            make_signer().sign_batch(MESSAGES, contexts=CONTEXTS), expected
        )

    def test_each_signature_verifies_independently(self):
        signer = make_signer()
        public_key = signer.public_key
        signatures = signer.sign_batch(MESSAGES, contexts=CONTEXTS)
        for message, context, signature in zip(
            MESSAGES, CONTEXTS_BYTES, signatures
        ):
            self.assertTrue(
                merkle_verify(message, signature, public_key, context=context)
            )
        # A slot's context does not verify any other slot.
        self.assertFalse(
            merkle_verify(
                MESSAGES[0], signatures[0], public_key, context=CONTEXTS_BYTES[1]
            )
        )
        self.assertFalse(
            merkle_verify(MESSAGES[0], signatures[0], public_key)
        )
        # The None slot is an ordinary unbound signature.
        self.assertTrue(merkle_verify(MESSAGES[2], signatures[2], public_key))

    def test_none_contexts_is_legacy_identical(self):
        signer = make_signer()
        legacy = make_signer().sign_batch(MESSAGES, context=b"shared")
        self.assertEqual(
            signer.sign_batch(MESSAGES, context=b"shared", contexts=None), legacy
        )
        self.assertEqual(make_signer().sign_batch(MESSAGES), make_signer().sign_batch(MESSAGES, contexts=None))

    def test_all_empty_members_equal_unbound_batch(self):
        bound = make_signer().sign_batch(MESSAGES, contexts=(None, b"", ""))
        self.assertEqual(bound, make_signer().sign_batch(MESSAGES))

    def test_empty_batch_with_empty_contexts(self):
        signer = make_signer()
        self.assertEqual(signer.sign_batch((), contexts=()), ())
        self.assertEqual(signer.next_index, 0)
        signatures, checkpoint = signer.sign_batch_with_checkpoint(
            (), contexts=()
        )
        self.assertEqual(signatures, ())
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(
            MerkleSigner.from_checkpoint(checkpoint).public_key, signer.public_key
        )

    def test_checkpoint_variant_matches_and_resumes(self):
        signer = make_signer()
        signatures, checkpoint = signer.sign_batch_with_checkpoint(
            MESSAGES, contexts=CONTEXTS
        )
        self.assertEqual(signatures, sequential_sign(MESSAGES, CONTEXTS))
        self.assertEqual(signer.next_index, len(MESSAGES))
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, len(MESSAGES))
        self.assertEqual(restored.public_key, signer.public_key)
        # Resuming from the checkpoint continues at the next leaf.
        follow_up = restored.sign(b"follow-up", context=b"ctx-d")
        self.assertEqual(follow_up.index, len(MESSAGES))
        self.assertTrue(
            merkle_verify(
                b"follow-up", follow_up, signer.public_key, context=b"ctx-d"
            )
        )

    def test_checkpoint_bytes_ignore_contexts(self):
        # Contexts are bound into digests only: the checkpoint of the same
        # advanced state is byte-identical with and without contexts.
        _, with_contexts = make_signer().sign_batch_with_checkpoint(
            MESSAGES, contexts=CONTEXTS
        )
        _, plain = make_signer().sign_batch_with_checkpoint(MESSAGES)
        self.assertEqual(with_contexts, plain)


class SignBatchContextsValidationTest(unittest.TestCase):
    def test_container_type_errors(self):
        for bad in ([b"a"], "ctx", 42, b"ctx"):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    make_signer().sign_batch(MESSAGES, contexts=bad)
                with self.assertRaises(TypeError):
                    make_signer().sign_batch_with_checkpoint(
                        MESSAGES, contexts=bad
                    )

    def test_member_type_errors(self):
        for bad in BAD_CONTEXTS:
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    make_signer().sign_batch(MESSAGES, contexts=(b"a", bad, None))
                with self.assertRaises(TypeError):
                    make_signer().sign_batch_with_checkpoint(
                        MESSAGES, contexts=(b"a", bad, None)
                    )

    def test_message_type_errors_still_raise(self):
        with self.assertRaises(TypeError):
            make_signer().sign_batch([b"a"], contexts=(b"x",))
        with self.assertRaises(TypeError):
            make_signer().sign_batch((b"a", 42, b"c"), contexts=CONTEXTS)
        with self.assertRaises(TypeError):
            make_signer().sign_batch_with_checkpoint(
                (b"a", 42, b"c"), contexts=CONTEXTS
            )

    def test_length_mismatch_raises_value_error(self):
        for contexts in ((), (b"a",), (b"a",) * 4):
            with self.subTest(count=len(contexts)):
                with self.assertRaises(ValueError):
                    make_signer().sign_batch(MESSAGES, contexts=contexts)
                with self.assertRaises(ValueError):
                    make_signer().sign_batch_with_checkpoint(
                        MESSAGES, contexts=contexts
                    )

    def test_shared_context_conflict_raises_value_error(self):
        for context in (b"shared", "shared", bytearray(b"shared")):
            with self.subTest(context=repr(context)):
                with self.assertRaises(ValueError):
                    make_signer().sign_batch(
                        MESSAGES, context=context, contexts=CONTEXTS
                    )
                with self.assertRaises(ValueError):
                    make_signer().sign_batch_with_checkpoint(
                        MESSAGES, context=context, contexts=CONTEXTS
                    )
        # An empty shared context is no context and does not conflict.
        self.assertEqual(
            make_signer().sign_batch(MESSAGES, context=b"", contexts=CONTEXTS),
            sequential_sign(MESSAGES, CONTEXTS),
        )

    def test_type_errors_precede_length_and_conflict(self):
        # A bad contexts member type wins over the length and conflict rules.
        with self.assertRaises(TypeError):
            make_signer().sign_batch(
                MESSAGES, context=b"shared", contexts=(42,)
            )
        # A bad message member type wins over the conflict rule.
        with self.assertRaises(TypeError):
            make_signer().sign_batch(
                (b"a", 42, b"c"), context=b"shared", contexts=CONTEXTS
            )

    def test_capacity_checked_last(self):
        signer = make_signer(height=1)  # 2 leaves
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch(MESSAGES, contexts=CONTEXTS)
        self.assertEqual(signer.next_index, 0)
        # Type and conflict errors still win over exhaustion.
        with self.assertRaises(TypeError):
            signer.sign_batch(MESSAGES, contexts=(b"a", 42, None))
        with self.assertRaises(ValueError):
            signer.sign_batch(MESSAGES, context=b"c", contexts=CONTEXTS)
        with self.assertRaises(ValueError):
            signer.sign_batch(MESSAGES, contexts=(b"a",))
        self.assertEqual(signer.next_index, 0)

    def test_failures_consume_no_leaf(self):
        signer = make_signer()
        calls = (
            lambda: signer.sign_batch(MESSAGES, contexts=(b"a",)),
            lambda: signer.sign_batch(MESSAGES, contexts=(b"a", 42, None)),
            lambda: signer.sign_batch(
                MESSAGES, context=b"shared", contexts=CONTEXTS
            ),
            lambda: signer.sign_batch_with_checkpoint(
                MESSAGES, contexts=(b"a",)
            ),
        )
        for call in calls:
            with self.assertRaises((TypeError, ValueError)):
                call()
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign(b"ok").index, 0)


class BatchProofContextsTest(unittest.TestCase):
    def _batch(self, w=4):
        signer = make_signer(w=w)
        signatures = signer.sign_batch(MESSAGES, contexts=CONTEXTS)
        return signer, MerkleBatchProof(signer.public_key, signatures)

    def test_verify_with_per_message_contexts(self):
        for w in (4, 8):
            with self.subTest(w=w):
                _, batch = self._batch(w=w)
                self.assertTrue(batch.verify(MESSAGES, contexts=CONTEXTS))
                # Any single context mismatch fails the whole batch.
                wrong = (CONTEXTS[0], b"other", CONTEXTS[2])
                self.assertFalse(batch.verify(MESSAGES, contexts=wrong))
                self.assertFalse(batch.verify(MESSAGES, contexts=(None,) * 3))
                self.assertFalse(batch.verify(MESSAGES))
                self.assertFalse(batch.verify(MESSAGES, context=b"shared"))

    def test_verify_contexts_count_mismatch_returns_false(self):
        _, batch = self._batch()
        self.assertFalse(batch.verify(MESSAGES, contexts=(b"a",)))
        self.assertFalse(batch.verify(MESSAGES, contexts=CONTEXTS + (None,)))
        self.assertFalse(batch.verify(MESSAGES[:2], contexts=CONTEXTS[:2]))

    def test_verify_contexts_type_and_conflict_errors(self):
        _, batch = self._batch()
        for bad in BAD_CONTEXTS:
            with self.assertRaises(TypeError):
                batch.verify(MESSAGES, contexts=(b"a", bad, None))
        with self.assertRaises(TypeError):
            batch.verify(MESSAGES, contexts=[b"a", b"b", None])
        with self.assertRaises(ValueError):
            batch.verify(MESSAGES, context=b"shared", contexts=CONTEXTS)

    def test_verify_bound_with_per_message_contexts(self):
        signer, batch = self._batch()
        indices = tuple(range(len(MESSAGES)))
        self.assertTrue(
            batch.verify_bound(
                MESSAGES,
                public_key=signer.public_key,
                indices=indices,
                contexts=CONTEXTS,
            )
        )
        # The binding to key and leaf indices still holds.
        self.assertFalse(
            batch.verify_bound(
                MESSAGES,
                public_key=make_signer(height=2).public_key,
                contexts=CONTEXTS,
            )
        )
        self.assertFalse(
            batch.verify_bound(
                MESSAGES,
                public_key=signer.public_key,
                indices=(1, 2, 3),
                contexts=CONTEXTS,
            )
        )
        self.assertFalse(
            batch.verify_bound(
                MESSAGES,
                public_key=signer.public_key,
                indices=indices,
                contexts=(CONTEXTS[0], CONTEXTS[0], CONTEXTS[2]),
            )
        )
        self.assertFalse(
            batch.verify_bound(
                MESSAGES,
                public_key=signer.public_key,
                indices=indices,
                contexts=(b"a",),
            )
        )

    def test_verify_bound_contexts_type_and_conflict_errors(self):
        signer, batch = self._batch()
        for bad in BAD_CONTEXTS:
            with self.assertRaises(TypeError):
                batch.verify_bound(
                    MESSAGES,
                    public_key=signer.public_key,
                    contexts=(b"a", bad, None),
                )
        with self.assertRaises(ValueError):
            batch.verify_bound(
                MESSAGES,
                public_key=signer.public_key,
                context=b"shared",
                contexts=CONTEXTS,
            )

    def test_serialized_batch_round_trip(self):
        signer, batch = self._batch()
        parsed = MerkleBatchProof.from_bytes(batch.to_bytes())
        self.assertEqual(parsed, batch)
        self.assertTrue(parsed.verify(MESSAGES, contexts=CONTEXTS))


class MultiproofContextsTest(unittest.TestCase):
    def _proof(self, w=4, height=3):
        signer = make_signer(w=w, height=height)
        signatures = signer.sign_batch(MESSAGES, contexts=CONTEXTS)
        return signer, multiproof_encode(signer.public_key, signatures)

    def test_verify_with_per_message_contexts(self):
        for w in (4, 8):
            with self.subTest(w=w):
                _, proof = self._proof(w=w)
                self.assertTrue(
                    multiproof_verify(MESSAGES, proof, contexts=CONTEXTS)
                )
                wrong = (CONTEXTS[0], b"other", CONTEXTS[2])
                self.assertFalse(multiproof_verify(MESSAGES, proof, contexts=wrong))
                self.assertFalse(multiproof_verify(MESSAGES, proof))
                self.assertFalse(
                    multiproof_verify(
                        tuple(reversed(MESSAGES)), proof, contexts=CONTEXTS
                    )
                )

    def test_verify_contexts_count_mismatch_returns_false(self):
        _, proof = self._proof()
        self.assertFalse(multiproof_verify(MESSAGES, proof, contexts=(b"a",)))
        self.assertFalse(
            multiproof_verify(MESSAGES, proof, contexts=CONTEXTS + (None,))
        )

    def test_verify_contexts_type_and_conflict_errors(self):
        _, proof = self._proof()
        for bad in BAD_CONTEXTS:
            with self.assertRaises(TypeError):
                multiproof_verify(MESSAGES, proof, contexts=(b"a", bad, None))
        with self.assertRaises(TypeError):
            multiproof_verify(MESSAGES, proof, contexts="ctx")
        with self.assertRaises(ValueError):
            multiproof_verify(
                MESSAGES, proof, context=b"shared", contexts=CONTEXTS
            )

    def test_verify_bound_with_per_message_contexts(self):
        signer, proof = self._proof()
        indices = tuple(range(len(MESSAGES)))
        self.assertTrue(
            multiproof_verify_bound(
                MESSAGES,
                proof,
                public_key=signer.public_key,
                indices=indices,
                contexts=CONTEXTS,
            )
        )
        self.assertFalse(
            multiproof_verify_bound(
                MESSAGES,
                proof,
                public_key=signer.public_key,
                indices=(1, 2, 3),
                contexts=CONTEXTS,
            )
        )
        self.assertFalse(
            multiproof_verify_bound(
                MESSAGES,
                proof,
                public_key=make_signer(height=2).public_key,
                contexts=CONTEXTS,
            )
        )
        self.assertFalse(
            multiproof_verify_bound(
                MESSAGES,
                proof,
                public_key=signer.public_key,
                contexts=(CONTEXTS[0], b"other", CONTEXTS[2]),
            )
        )
        self.assertFalse(
            multiproof_verify_bound(
                MESSAGES, proof, public_key=signer.public_key, contexts=(b"a",)
            )
        )

    def test_verify_bound_contexts_type_and_conflict_errors(self):
        signer, proof = self._proof()
        for bad in BAD_CONTEXTS:
            with self.assertRaises(TypeError):
                multiproof_verify_bound(
                    MESSAGES,
                    proof,
                    public_key=signer.public_key,
                    contexts=(bad, b"b", None),
                )
        with self.assertRaises(ValueError):
            multiproof_verify_bound(
                MESSAGES,
                proof,
                public_key=signer.public_key,
                context="shared",
                contexts=CONTEXTS,
            )

    def test_proof_bytes_ignore_contexts(self):
        # Contexts never enter the wire format: the multiproof of a
        # per-message batch equals the multiproof of the same signatures.
        signer = make_signer()
        signatures = signer.sign_batch(MESSAGES, contexts=CONTEXTS)
        self.assertEqual(
            multiproof_encode(signer.public_key, signatures),
            multiproof_encode(
                signer.public_key, sequential_sign(MESSAGES, CONTEXTS)
            ),
        )

    def test_min_height_tree(self):
        # height=1: a two-leaf batch with per-message contexts fills the tree.
        signer = make_signer(height=1)
        messages = (b"x", b"y")
        contexts = (b"c1", "c2")
        signatures = signer.sign_batch(messages, contexts=contexts)
        self.assertEqual(signer.next_index, 2)
        proof = multiproof_encode(signer.public_key, signatures)
        self.assertTrue(multiproof_verify(messages, proof, contexts=contexts))
        self.assertFalse(multiproof_verify(messages, proof, contexts=(b"c1", b"c1")))
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch((b"z",), contexts=(None,))


if __name__ == "__main__":
    unittest.main()

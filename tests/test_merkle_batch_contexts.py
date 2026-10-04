"""Per-message context binding for the consecutive Merkle batch entries.

Covers the keyword-only ``contexts`` parameter on
``MerkleSigner.sign_batch`` / ``sign_batch_with_checkpoint`` and on
``MerkleBatchProof.verify`` / ``verify_bound`` and the top-level
``multiproof_verify`` / ``multiproof_verify_bound``: legacy equivalence,
value-for-value equality with sequential single signing, per-leaf
independent verification, checkpoint resume, batch-proof and multiproof
round trips, the fixed validation order (types, then length/conflict,
then capacity), all-or-nothing failure semantics, concurrent leaf
allocation, and ``w``/height compatibility.
"""

import threading
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

SEED = bytes((i + 7 for i in range(32)))
CONTEXT_A = b"context-a"
CONTEXT_B = "café/context-b"  # str on purpose: UTF-8 must match its bytes
CONTEXT_B_BYTES = CONTEXT_B.encode("utf-8")


def make_signer(seed: bytes = SEED, height: int = 3, w: int = 4) -> MerkleSigner:
    return MerkleSigner.from_seed(seed, height=height, w=w)


MESSAGES = (b"m0", "m1", bytearray(b"m2"), b"m3")
# Mix of every accepted member kind; None and ""/b"" mean no context.
CONTEXTS = (CONTEXT_A, None, bytearray(b""), CONTEXT_B)
CONTEXTS_NORMALISED = (CONTEXT_A, b"", b"", CONTEXT_B_BYTES)


class SignBatchPerMessageContextsTest(unittest.TestCase):
    def test_value_for_value_equal_to_sequential_sign(self):
        batched = make_signer().sign_batch(MESSAGES, contexts=CONTEXTS)
        sequential_signer = make_signer()
        sequential = tuple(
            sequential_signer.sign(message, context=context)
            for message, context in zip(MESSAGES, CONTEXTS)
        )
        self.assertEqual(batched, sequential)

    def test_consecutive_indices_and_state_advance(self):
        signer = make_signer()
        signer.sign("warm-up")
        batch = signer.sign_batch(MESSAGES, contexts=CONTEXTS)
        self.assertEqual([signature.index for signature in batch], [1, 2, 3, 4])
        self.assertEqual(signer.next_index, 5)
        self.assertEqual(signer.remaining, 8 - 5)
        self.assertEqual(signer.sign("next").index, 5)

    def test_every_signature_verifies_independently_with_single_entry(self):
        signer = make_signer()
        batch = signer.sign_batch(MESSAGES, contexts=CONTEXTS)
        for message, signature, context in zip(MESSAGES, batch, CONTEXTS):
            self.assertTrue(
                merkle_verify(message, signature, signer.public_key, context=context)
            )
            # A str context and its UTF-8 bytes are the same binding.
            if isinstance(context, str):
                self.assertTrue(
                    merkle_verify(
                        message,
                        signature,
                        signer.public_key,
                        context=context.encode("utf-8"),
                    )
                )
            if context is not None and len(context):
                # A non-empty binding rejects no/empty/other contexts.
                for wrong in (None, b"", b"something-else"):
                    self.assertFalse(
                        merkle_verify(
                            message, signature, signer.public_key, context=wrong
                        )
                    )
            else:
                # An unbound signature keeps verifying unbound, but not under
                # a different context.
                self.assertTrue(
                    merkle_verify(message, signature, signer.public_key)
                )
                self.assertFalse(
                    merkle_verify(
                        message,
                        signature,
                        signer.public_key,
                        context=b"something-else",
                    )
                )

    def test_bound_messages_do_not_verify_without_their_contexts(self):
        signer = make_signer()
        batch = signer.sign_batch(MESSAGES, contexts=CONTEXTS)
        proof = MerkleBatchProof(public_key=signer.public_key, signatures=batch)
        self.assertFalse(proof.verify(MESSAGES))
        self.assertFalse(proof.verify(MESSAGES, contexts=(b"",) * len(MESSAGES)))

    def test_all_empty_contexts_tuple_matches_legacy_bytes(self):
        legacy = make_signer().sign_batch(MESSAGES)
        per_message = make_signer().sign_batch(
            MESSAGES, contexts=(None, b"", bytearray(b""), "")
        )
        self.assertEqual(legacy, per_message)

    def test_contexts_is_keyword_only(self):
        signer = make_signer()
        with self.assertRaises(TypeError):
            signer.sign_batch(MESSAGES, None, CONTEXTS)  # type: ignore[misc]

    def test_w8_is_supported(self):
        messages = (b"a", "b")
        contexts = (CONTEXT_A, CONTEXT_B)
        batched = make_signer(w=8).sign_batch(messages, contexts=contexts)
        sequential_signer = make_signer(w=8)
        sequential = tuple(
            sequential_signer.sign(message, context=context)
            for message, context in zip(messages, contexts)
        )
        self.assertEqual(batched, sequential)

    def test_height_8_is_supported(self):
        signer = make_signer(height=8)
        batch = signer.sign_batch(MESSAGES, contexts=CONTEXTS)
        self.assertEqual([signature.index for signature in batch], [0, 1, 2, 3])
        for message, signature, context in zip(MESSAGES, batch, CONTEXTS):
            self.assertTrue(
                merkle_verify(message, signature, signer.public_key, context=context)
            )


class SignBatchValidationTest(unittest.TestCase):
    def test_contexts_container_wrong_type_raises_type_error(self):
        signer = make_signer()
        generator = (None for _ in (0,))
        for bad in ([CONTEXT_A], generator, "ctx", 7, b"ctx"):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_batch(MESSAGES, contexts=bad)
        self.assertEqual(signer.next_index, 0)

    def test_contexts_member_wrong_type_raises_type_error(self):
        signer = make_signer()
        for bad in (1, 1.5, [b"ctx"], {"ctx": 1}, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_batch(MESSAGES, contexts=(None, bad, None, None))
        self.assertEqual(signer.next_index, 0)

    def test_messages_checked_before_contexts(self):
        signer = make_signer()
        # A non-tuple messages container and a non-tuple contexts container
        # together: the message error is the one reported.
        with self.assertRaises(TypeError):
            signer.sign_batch([b"m"], contexts=[None])
        # A bad message member outranks a bad contexts container.
        with self.assertRaises(TypeError):
            signer.sign_batch((b"ok", 7), contexts=[None, None])
        self.assertEqual(signer.next_index, 0)

    def test_length_mismatch_raises_value_error(self):
        signer = make_signer()
        with self.assertRaises(ValueError):
            signer.sign_batch(MESSAGES, contexts=CONTEXTS[:3])
        with self.assertRaises(ValueError):
            signer.sign_batch(MESSAGES, contexts=CONTEXTS + (b"extra",))
        self.assertEqual(signer.next_index, 0)

    def test_conflict_with_non_empty_shared_context_raises_value_error(self):
        signer = make_signer()
        with self.assertRaises(ValueError):
            signer.sign_batch(
                MESSAGES, context=CONTEXT_A, contexts=(None,) * len(MESSAGES)
            )
        # An empty shared context is the legacy "no context" and is allowed.
        batch = signer.sign_batch(
            MESSAGES, context="", contexts=tuple(CONTEXTS)
        )
        self.assertEqual(len(batch), len(MESSAGES))

    def test_empty_messages_with_empty_contexts_keeps_empty_batch_behaviour(self):
        signer = make_signer()
        self.assertEqual(signer.sign_batch((), contexts=()), ())
        self.assertEqual(signer.next_index, 0)
        signatures, checkpoint = signer.sign_batch_with_checkpoint((), contexts=())
        self.assertEqual(signatures, ())
        self.assertEqual(MerkleSigner.from_checkpoint(checkpoint).next_index, 0)

    def test_non_empty_messages_with_empty_contexts_raises_value_error(self):
        signer = make_signer()
        with self.assertRaises(ValueError):
            signer.sign_batch(MESSAGES, contexts=())
        self.assertEqual(signer.next_index, 0)

    def test_validation_order_on_an_exhausted_signer(self):
        signer = make_signer(height=1)  # 2 leaves
        signer.sign_batch((b"a", b"b"))
        self.assertEqual(signer.remaining, 0)
        # Types are reported first, even on an exhausted signer.
        with self.assertRaises(TypeError):
            signer.sign_batch((b"m", 9), contexts=(None, None))
        with self.assertRaises(TypeError):
            signer.sign_batch((b"m",), contexts=[None])
        with self.assertRaises(TypeError):
            signer.sign_batch((b"m",), contexts=(7,))
        # Then the count / conflict checks.
        with self.assertRaises(ValueError):
            signer.sign_batch((b"m", b"n"), contexts=(None,))
        with self.assertRaises(ValueError):
            signer.sign_batch((b"m",), context=CONTEXT_A, contexts=(None,))
        # Capacity is last.
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch((b"m",), contexts=(None,))
        # The empty batch is still legal on an exhausted signer.
        self.assertEqual(signer.sign_batch((), contexts=()), ())
        self.assertEqual(signer.next_index, 2)

    def test_failure_consumes_no_leaf_and_returns_nothing_partial(self):
        signer = make_signer(height=2)
        with self.assertRaises(ValueError):
            signer.sign_batch(MESSAGES, contexts=CONTEXTS[:3])
        self.assertEqual(signer.next_index, 0)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch(MESSAGES + (b"m4",), contexts=(None,) * 5)
        self.assertEqual(signer.next_index, 0)

    def test_checkpoint_variant_validates_in_the_same_order(self):
        signer = make_signer(height=1)
        signer.sign_batch((b"a", b"b"))
        with self.assertRaises(TypeError):
            signer.sign_batch_with_checkpoint((b"m",), contexts=(7,))
        with self.assertRaises(ValueError):
            signer.sign_batch_with_checkpoint((b"m", b"n"), contexts=(None,))
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_with_checkpoint((b"m",), contexts=(None,))
        self.assertEqual(signer.next_index, 2)


class SignBatchCheckpointTest(unittest.TestCase):
    def test_checkpoint_variant_matches_plain_batch_and_resumes(self):
        signer = make_signer()
        signatures, checkpoint = signer.sign_batch_with_checkpoint(
            MESSAGES, contexts=CONTEXTS
        )
        self.assertEqual(signatures, make_signer().sign_batch(MESSAGES, contexts=CONTEXTS))
        self.assertEqual(signer.next_index, 4)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 4)
        # Resume at the next leaf with another per-message context.
        next_signature = restored.sign(b"later", context=CONTEXT_A)
        self.assertEqual(next_signature.index, 4)
        self.assertTrue(
            merkle_verify(
                b"later", next_signature, signer.public_key, context=CONTEXT_A
            )
        )

    def test_checkpoint_does_not_carry_contexts(self):
        # Contexts change signatures but never state: the post-batch
        # checkpoint must be byte-identical to a context-free batch over
        # the same (state-relevant) inputs.
        _, bound = make_signer().sign_batch_with_checkpoint(
            MESSAGES, contexts=CONTEXTS
        )
        _, unbound = make_signer().sign_batch_with_checkpoint(MESSAGES)
        self.assertEqual(bound, unbound)


class BatchProofPerMessageContextsTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.signatures = self.signer.sign_batch(MESSAGES, contexts=CONTEXTS)
        self.proof = MerkleBatchProof(
            public_key=self.signer.public_key, signatures=self.signatures
        )

    def test_verify_matches_in_proof_order(self):
        self.assertTrue(self.proof.verify(MESSAGES, contexts=CONTEXTS))
        self.assertTrue(
            self.proof.verify(MESSAGES, contexts=CONTEXTS_NORMALISED)
        )

    def test_verify_rejects_wrong_swapped_or_missing_context(self):
        self.assertFalse(
            self.proof.verify(MESSAGES, contexts=(b"x", None, b"", CONTEXT_B_BYTES))
        )
        # Two contexts swapped: every item is still present, but positions
        # matter.
        swapped = (CONTEXTS[1], CONTEXTS[0]) + CONTEXTS[2:]
        self.assertFalse(self.proof.verify(MESSAGES, contexts=swapped))
        self.assertFalse(self.proof.verify(MESSAGES))

    def test_verify_count_mismatch_returns_false(self):
        self.assertFalse(self.proof.verify(MESSAGES, contexts=CONTEXTS[:3]))
        self.assertFalse(
            self.proof.verify(MESSAGES, contexts=CONTEXTS + (b"extra",))
        )
        self.assertFalse(self.proof.verify(MESSAGES[:3], contexts=CONTEXTS))

    def test_verify_context_type_errors_raise(self):
        for bad in ([CONTEXT_A], 7, b"ctx"):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self.proof.verify(MESSAGES, contexts=bad)
        with self.assertRaises(TypeError):
            self.proof.verify(MESSAGES, contexts=(1,) * len(MESSAGES))

    def test_verify_shared_context_conflict_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.proof.verify(
                MESSAGES, context=CONTEXT_A, contexts=(None,) * len(MESSAGES)
            )
        # An empty shared context stays compatible.
        self.assertTrue(
            self.proof.verify(MESSAGES, context=b"", contexts=CONTEXTS)
        )

    def test_verify_bound_still_constrains_key_indices_and_contexts(self):
        indices = tuple(signature.index for signature in self.signatures)
        self.assertTrue(
            self.proof.verify_bound(
                MESSAGES,
                public_key=self.signer.public_key,
                indices=indices,
                contexts=CONTEXTS,
            )
        )
        other_key = make_signer(seed=bytes([1]) * 32).public_key
        self.assertFalse(
            self.proof.verify_bound(
                MESSAGES, public_key=other_key, indices=indices, contexts=CONTEXTS
            )
        )
        self.assertFalse(
            self.proof.verify_bound(
                MESSAGES,
                public_key=self.signer.public_key,
                indices=(0, 1, 2, 99),
                contexts=CONTEXTS,
            )
        )
        self.assertFalse(
            self.proof.verify_bound(
                MESSAGES,
                public_key=self.signer.public_key,
                indices=indices,
                contexts=(b"wrong",) + CONTEXTS[1:],
            )
        )
        with self.assertRaises(TypeError):
            self.proof.verify_bound(
                MESSAGES,
                public_key=self.signer.public_key,
                contexts=[None] * len(MESSAGES),
            )
        with self.assertRaises(ValueError):
            self.proof.verify_bound(
                MESSAGES,
                public_key=self.signer.public_key,
                context=CONTEXT_A,
                contexts=(None,) * len(MESSAGES),
            )

    def test_wire_bytes_are_the_unchanged_v1_batch_format(self):
        # Contexts never enter the proof: re-parsing the bytes yields a
        # proof that verifies with the same contexts.
        round_trip = MerkleBatchProof.from_bytes(self.proof.to_bytes())
        self.assertEqual(round_trip.to_bytes(), self.proof.to_bytes())
        self.assertTrue(round_trip.verify(MESSAGES, contexts=CONTEXTS))


class MultiproofPerMessageContextsTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.signatures = self.signer.sign_batch(MESSAGES, contexts=CONTEXTS)
        self.indices = tuple(signature.index for signature in self.signatures)
        self.proof_bytes = multiproof_encode(self.signer.public_key, self.signatures)

    def test_round_trip_in_proof_leaf_order(self):
        self.assertTrue(
            multiproof_verify(MESSAGES, self.proof_bytes, contexts=CONTEXTS)
        )
        self.assertTrue(
            multiproof_verify(
                MESSAGES, self.proof_bytes, contexts=CONTEXTS_NORMALISED
            )
        )

    def test_any_context_mismatch_returns_false(self):
        self.assertFalse(
            multiproof_verify(
                MESSAGES,
                self.proof_bytes,
                contexts=(CONTEXT_A, None, b"", b"other"),
            )
        )
        swapped = (CONTEXTS[1], CONTEXTS[0]) + CONTEXTS[2:]
        self.assertFalse(
            multiproof_verify(MESSAGES, self.proof_bytes, contexts=swapped)
        )
        self.assertFalse(multiproof_verify(MESSAGES, self.proof_bytes))

    def test_count_mismatch_returns_false(self):
        self.assertFalse(
            multiproof_verify(MESSAGES, self.proof_bytes, contexts=CONTEXTS[:3])
        )
        self.assertFalse(
            multiproof_verify(MESSAGES[:3], self.proof_bytes, contexts=CONTEXTS[:3])
        )

    def test_context_type_errors_raise(self):
        with self.assertRaises(TypeError):
            multiproof_verify(MESSAGES, self.proof_bytes, contexts=[None] * 4)
        with self.assertRaises(TypeError):
            multiproof_verify(
                MESSAGES, self.proof_bytes, contexts=(None, 4, None, None)
            )

    def test_shared_context_conflict_raises_value_error(self):
        with self.assertRaises(ValueError):
            multiproof_verify(
                MESSAGES,
                self.proof_bytes,
                context=CONTEXT_A,
                contexts=(None,) * len(MESSAGES),
            )

    def test_verify_bound_constrains_key_indices_and_contexts(self):
        self.assertTrue(
            multiproof_verify_bound(
                MESSAGES,
                self.proof_bytes,
                public_key=self.signer.public_key,
                indices=self.indices,
                contexts=CONTEXTS,
            )
        )
        other_key = make_signer(seed=bytes([9]) * 32).public_key
        self.assertFalse(
            multiproof_verify_bound(
                MESSAGES,
                self.proof_bytes,
                public_key=other_key,
                indices=self.indices,
                contexts=CONTEXTS,
            )
        )
        wrong_indices = tuple(index + 1 for index in self.indices)
        self.assertFalse(
            multiproof_verify_bound(
                MESSAGES,
                self.proof_bytes,
                public_key=self.signer.public_key,
                indices=wrong_indices,
                contexts=CONTEXTS,
            )
        )
        self.assertFalse(
            multiproof_verify_bound(
                MESSAGES,
                self.proof_bytes,
                public_key=self.signer.public_key,
                indices=self.indices,
                contexts=(b"wrong", None, b"", CONTEXT_B_BYTES),
            )
        )
        with self.assertRaises(TypeError):
            multiproof_verify_bound(
                MESSAGES,
                self.proof_bytes,
                public_key=self.signer.public_key,
                contexts=7,
            )
        with self.assertRaises(ValueError):
            multiproof_verify_bound(
                MESSAGES,
                self.proof_bytes,
                public_key=self.signer.public_key,
                context=CONTEXT_A,
                contexts=(None,) * len(MESSAGES),
            )

    def test_contexts_are_not_written_into_the_proof(self):
        # The same proof bytes must not verify as a shared-context proof,
        # and they remain parseable after transport with no context field.
        self.assertFalse(
            multiproof_verify(MESSAGES, self.proof_bytes, context=b"")
        )
        self.assertTrue(
            multiproof_verify(MESSAGES, self.proof_bytes, contexts=CONTEXTS)
        )


class ConcurrentPerMessageBatchesTest(unittest.TestCase):
    def test_concurrent_batches_never_share_a_leaf(self):
        height = 5  # 32 leaves
        signer = make_signer(height=height)
        thread_count = 8
        batch_size = 4
        barrier = threading.Barrier(thread_count)
        allocated = []
        errors = []
        lock = threading.Lock()

        def worker(worker_id):
            contexts = tuple(
                f"worker/{worker_id}/leaf/{i}".encode() for i in range(batch_size)
            )
            messages = tuple(
                f"message-{worker_id}-{i}".encode() for i in range(batch_size)
            )
            try:
                barrier.wait(timeout=10)
                signatures = signer.sign_batch(messages, contexts=contexts)
            except KeyExhaustedError:
                return
            except Exception as exc:  # pragma: no cover - fails the test below
                with lock:
                    errors.append(exc)
                return
            for message, signature, context in zip(messages, signatures, contexts):
                self.assertTrue(
                    merkle_verify(message, signature, signer.public_key, context=context)
                )
            with lock:
                allocated.extend(signature.index for signature in signatures)

        threads = [
            threading.Thread(target=worker, args=(i,)) for i in range(thread_count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        # Exactly one full set of 32 disjoint leaves was signed.
        self.assertEqual(sorted(allocated), list(range(1 << height)))


class OtherEntriesUnchangedTest(unittest.TestCase):
    def test_contexts_kwarg_is_not_silently_accepted_elsewhere(self):
        signer = make_signer()
        signatures = signer.sign_batch((b"a", b"b"), contexts=(CONTEXT_A, None))
        proof = MerkleBatchProof(public_key=signer.public_key, signatures=signatures)
        data = proof.to_bytes()
        # Proof conversion, explicit leaf selection and the other
        # multiproof entries keep their existing signatures.
        with self.assertRaises(TypeError):
            signer.sign_selected(  # type: ignore[misc]
                (2,), (b"c"), contexts=(None,)
            )
        with self.assertRaises(TypeError):
            multiproof_encode(  # type: ignore[misc]
                signer.public_key, signatures, contexts=(CONTEXT_A, None)
            )
        self.assertIsInstance(data, bytes)


if __name__ == "__main__":
    unittest.main()

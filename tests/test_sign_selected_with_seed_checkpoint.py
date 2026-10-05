"""Tests for MerkleSigner.sign_selected_with_seed_checkpoint."""

import threading
import unittest
from unittest import mock

import pqattest.merkle
from pqattest import (
    KeyExhaustedError,
    MerkleSignature,
    MerkleSigner,
    merkle_verify,
    multiproof_encode,
    multiproof_verify,
)
from pqattest.merkle import _SEED_CHECKPOINT_BYTES

SEED = bytes(range(32))


def make_seed_signer(height=3, w=4, seed=SEED):
    return MerkleSigner.from_seed(seed, height=height, w=w)


class SignSelectedWithSeedCheckpointTest(unittest.TestCase):
    def test_returns_signatures_tuple_and_109_bytes(self):
        signer = make_seed_signer()
        signatures, blob = signer.sign_selected_with_seed_checkpoint(
            (0, 2, 5), ("a", "b", "c")
        )
        self.assertIsInstance(signatures, tuple)
        self.assertEqual(len(signatures), 3)
        for signature in signatures:
            self.assertIsInstance(signature, MerkleSignature)
        self.assertIsInstance(blob, bytes)
        self.assertEqual(len(blob), 109)
        self.assertEqual(len(blob), _SEED_CHECKPOINT_BYTES)

    def test_signatures_match_sign_selected_without_context(self):
        signer = make_seed_signer(height=4)
        reference = make_seed_signer(height=4)
        signer.sign("warmup")
        reference.sign("warmup")
        indices = (1, 3, 4, 9)
        messages = ("one", "two", "three", "four")
        signatures, _ = signer.sign_selected_with_seed_checkpoint(
            indices, messages
        )
        self.assertEqual(
            signatures, reference.sign_selected(indices, messages)
        )

    def test_signatures_match_sign_selected_with_shared_context(self):
        signer = make_seed_signer()
        reference = make_seed_signer()
        indices = (0, 2)
        messages = ("one", "two")
        signatures, _ = signer.sign_selected_with_seed_checkpoint(
            indices, messages, context="CTX"
        )
        self.assertEqual(
            signatures,
            reference.sign_selected(indices, messages, context="CTX"),
        )
        for message, signature in zip(messages, signatures):
            self.assertTrue(
                merkle_verify(
                    message, signature, signer.public_key, context="CTX"
                )
            )
            self.assertFalse(
                merkle_verify(message, signature, signer.public_key)
            )

    def test_signatures_match_sign_selected_with_per_leaf_contexts(self):
        signer = make_seed_signer(height=4)
        reference = make_seed_signer(height=4)
        indices = (1, 4, 6)
        messages = ("one", b"two", bytearray(b"three"))
        contexts = ("c1", None, b"")
        signatures, _ = signer.sign_selected_with_seed_checkpoint(
            indices, messages, contexts=contexts
        )
        self.assertEqual(
            signatures,
            reference.sign_selected(indices, messages, contexts=contexts),
        )
        for position, (message, context) in enumerate(zip(messages, contexts)):
            self.assertTrue(
                merkle_verify(
                    message, signatures[position], signer.public_key,
                    context=context,
                )
            )

    def test_empty_context_values_are_all_no_context(self):
        signer = make_seed_signer()
        reference = make_seed_signer()
        indices = (0, 1, 3)
        messages = ("a", "b", "c")
        signatures, _ = signer.sign_selected_with_seed_checkpoint(
            indices, messages, contexts=(None, b"", "")
        )
        self.assertEqual(
            signatures, reference.sign_selected(indices, messages)
        )

    def test_supported_heights_and_w(self):
        for height in (1, 2, 3, 4, 5):
            for w in (4, 8):
                with self.subTest(height=height, w=w):
                    signer = make_seed_signer(height=height, w=w)
                    reference = make_seed_signer(height=height, w=w)
                    last = (1 << height) - 1
                    indices = (0, last) if last else (0,)
                    messages = tuple(f"m{i}" for i in range(len(indices)))
                    signatures, blob = (
                        signer.sign_selected_with_seed_checkpoint(
                            indices, messages
                        )
                    )
                    self.assertEqual(
                        signatures,
                        reference.sign_selected(indices, messages),
                    )
                    self.assertEqual(blob, reference.seed_checkpoint())
                    self.assertEqual(signer.next_index, last + 1)

    def test_gap_leaves_voided_and_next_index_after_last(self):
        signer = make_seed_signer(height=3)
        signatures, blob = signer.sign_selected_with_seed_checkpoint(
            (1, 4), ("a", "b")
        )
        self.assertEqual([s.index for s in signatures], [1, 4])
        self.assertEqual(signer.next_index, 5)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 5)
        self.assertEqual(signer.remaining, 8 - 5)
        # The skipped leaves below the last chosen one are voided for good.
        for gap in (0, 2, 3):
            with self.subTest(gap=gap):
                with self.assertRaises(ValueError):
                    signer.sign_selected((gap,), ("x",))
        self.assertEqual(signer.next_index, 5)

    def test_checkpoint_matches_seed_checkpoint_taken_right_after(self):
        signer = make_seed_signer(height=4)
        reference = make_seed_signer(height=4)
        indices = (2, 3, 7)
        messages = ("one", "two", "three")
        _, blob = signer.sign_selected_with_seed_checkpoint(
            indices, messages, context="x"
        )
        reference.sign_selected(indices, messages, context="x")
        self.assertEqual(blob, reference.seed_checkpoint())
        self.assertEqual(blob, signer.seed_checkpoint())

    def test_checkpoint_independent_of_messages_and_contexts(self):
        first = make_seed_signer()
        second = make_seed_signer()
        _, blob_one = first.sign_selected_with_seed_checkpoint(
            (0, 2), ("a", "b"), context="CTX"
        )
        _, blob_two = second.sign_selected_with_seed_checkpoint(
            (0, 2), ("different", b"messages"), contexts=("x", "y")
        )
        # Same seed, parameters and final index => identical checkpoint
        # bytes even though the messages, contexts and signatures differ.
        self.assertEqual(blob_one, blob_two)

    def test_restored_signer_keeps_public_key_and_resumes(self):
        signer = make_seed_signer(height=4)
        indices = (1, 3, 5)
        messages = ("one", "two", "three")
        signatures, blob = signer.sign_selected_with_seed_checkpoint(
            indices, messages
        )
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, signatures[-1].index + 1)
        self.assertEqual(restored.next_index, signer.next_index)
        self.assertEqual(restored.remaining, signer.remaining)
        self.assertEqual(restored.seed_checkpoint(), blob)
        # Continued signing on the restored signer matches the original.
        self.assertEqual(restored.sign("four"), signer.sign("four"))

    def test_restored_signer_is_itself_seed_derived(self):
        signer = make_seed_signer()
        _, blob = signer.sign_selected_with_seed_checkpoint((0, 1), ("a", "b"))
        restored = MerkleSigner.from_seed_checkpoint(blob)
        signatures, next_blob = restored.sign_selected_with_seed_checkpoint(
            (3,), ("c",)
        )
        self.assertEqual([s.index for s in signatures], [3])
        self.assertEqual(next_blob, restored.seed_checkpoint())

    def test_last_leaf_selection_restores_remaining_zero(self):
        signer = make_seed_signer(height=2)
        signatures, blob = signer.sign_selected_with_seed_checkpoint(
            (3,), ("end",)
        )
        self.assertEqual(signatures[0].index, 3)
        self.assertEqual(signer.remaining, 0)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 4)
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign_selected_with_seed_checkpoint((3,), ("x",))

    def test_signatures_feed_multiproof_and_batch_proof(self):
        signer = make_seed_signer(height=4)
        indices = (2, 4, 7)
        messages = ("p", "q", "r")
        contexts = (None, "ctx", b"")
        signatures, _ = signer.sign_selected_with_seed_checkpoint(
            indices, messages, contexts=contexts
        )
        public_key = signer.public_key
        proof = multiproof_encode(public_key, signatures)
        self.assertTrue(
            multiproof_verify(messages, proof, contexts=contexts)
        )

    def test_invalid_container_types_raise_typeerror_without_spending(self):
        signer = make_seed_signer()
        for bad in (None, 42, "m", b"m", [0], {0: "m"}, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_seed_checkpoint(bad, ("m",))
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_seed_checkpoint((0,), bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_member_types_raise_typeerror_without_spending(self):
        signer = make_seed_signer()
        for bad_indices in (("0",), (None,), (1.5,), (object(),)):
            with self.subTest(bad=bad_indices):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_seed_checkpoint(
                        bad_indices, ("m",)
                    )
        for bad_messages in ((123,), (None,), (object(),)):
            with self.subTest(bad=bad_messages):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_seed_checkpoint(
                        (0,), bad_messages
                    )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_context_types_raise_typeerror(self):
        signer = make_seed_signer()
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint((0,), ("m",), context=1)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint(
                (0,), ("m",), contexts=[None]
            )
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint(
                (0,), ("m",), contexts=(123,)
            )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_types_checked_before_structure(self):
        # A bad member type combined with a structural violation must still
        # surface TypeError.
        signer = make_seed_signer()
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint(("x",), ("m",))
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint((0, 1), ("m", 5))
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint(
                (0,), ("m",), contexts=(object(),)
            )
        self.assertEqual(signer.next_index, 0)

    def test_empty_selection_rejected(self):
        signer = make_seed_signer()
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((), ())
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((), (), contexts=())
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_length_mismatch_raises_valueerror(self):
        signer = make_seed_signer()
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((0, 1), ("only",))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((0,), ("a", "b"))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint(
                (0, 1), ("a", "b"), contexts=("only-one",)
            )
        self.assertEqual(signer.next_index, 0)

    def test_boolean_duplicate_and_unordered_indices_raise_valueerror(self):
        signer = make_seed_signer()
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((True,), ("m",))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((1, 1), ("a", "b"))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((2, 1), ("a", "b"))
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_shared_context_conflict_raises_valueerror(self):
        signer = make_seed_signer()
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint(
                (0, 1), ("a", "b"), context="shared", contexts=(None, None)
            )
        # An empty shared context is "no context" and does not conflict.
        signatures, _ = signer.sign_selected_with_seed_checkpoint(
            (0,), ("a",), context="", contexts=(None,)
        )
        self.assertEqual(len(signatures), 1)

    def test_random_signer_rejected_even_with_valid_selection(self):
        signer = MerkleSigner(height=2)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((0,), ("m",))
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_full_checkpoint_restore_loses_seed_even_from_seed_origin(self):
        seed_signer = make_seed_signer()
        restored = MerkleSigner.from_checkpoint(seed_signer.checkpoint())
        with self.assertRaises(ValueError):
            restored.sign_selected_with_seed_checkpoint((0,), ("m",))
        self.assertEqual(restored.next_index, 0)
        # The seed ValueError comes before the exhaustion check.
        exhausted = MerkleSigner.from_checkpoint(
            make_seed_signer(height=1).checkpoint()
        )
        exhausted.advance_to(2)
        with self.assertRaises(ValueError):
            exhausted.sign_selected_with_seed_checkpoint((1,), ("m",))
        self.assertEqual(exhausted.next_index, 2)

    def test_structure_checked_before_seed(self):
        # Structural violations surface even on a non-seed signer.
        signer = MerkleSigner(height=2)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint([0], ("m",))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((), ())
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((True,), ("m",))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((0, 0), ("a", "b"))
        self.assertEqual(signer.next_index, 0)

    def test_exhaustion_checked_before_range(self):
        # An exhausted seed signer reports KeyExhaustedError even for an
        # out-of-range index.
        signer = make_seed_signer(height=1)
        signer.advance_to(2)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected_with_seed_checkpoint((99,), ("m",))
        self.assertEqual(signer.next_index, 2)

    def test_index_range_checked_last(self):
        signer = make_seed_signer(height=2)
        signer.sign_selected((0, 1), ("a", "b"))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((1,), ("m",))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((4,), ("m",))
        self.assertEqual(signer.next_index, 2)
        signatures, blob = signer.sign_selected_with_seed_checkpoint(
            (2,), ("m",)
        )
        self.assertEqual([s.index for s in signatures], [2])
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 3)

    def test_input_errors_surfaced_before_exhaustion(self):
        signer = make_seed_signer(height=1)
        signer.advance_to(2)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint((0,), (1,))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((0, 0), ("a", "b"))
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected_with_seed_checkpoint((0,), ("m",))
        self.assertEqual(signer.next_index, 2)

    def test_failures_leave_state_untouched(self):
        signer = make_seed_signer(height=2)
        before_blob = signer.seed_checkpoint()
        attempts = [
            lambda: signer.sign_selected_with_seed_checkpoint((0, 0), ("a", "b")),
            lambda: signer.sign_selected_with_seed_checkpoint((3, 1), ("a", "b")),
            lambda: signer.sign_selected_with_seed_checkpoint((0,), ("a", "b")),
            lambda: signer.sign_selected_with_seed_checkpoint((9,), ("a",)),
            lambda: signer.sign_selected_with_seed_checkpoint((0,), (object(),)),
        ]
        for attempt in attempts:
            with self.assertRaises((TypeError, ValueError)):
                attempt()
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.seed_checkpoint(), before_blob)
        self.assertEqual(signer.sign("m").index, 0)

    def test_draws_no_extra_randomness(self):
        signer = make_seed_signer(height=2)

        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_selected_with_seed_checkpoint must not draw randomness"
            )

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            signatures, blob = signer.sign_selected_with_seed_checkpoint(
                (0, 2), ("a", "b"), contexts=("c", None)
            )
        self.assertEqual([s.index for s in signatures], [0, 2])
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 3)

    def test_deterministic_across_seed_derivations(self):
        first = make_seed_signer(height=2)
        second = make_seed_signer(height=2)
        indices = (0, 1, 3)
        messages = ("a", b"b", bytearray(b"c"))
        contexts = ("x", None, "")
        left, left_blob = first.sign_selected_with_seed_checkpoint(
            indices, messages, contexts=contexts
        )
        right, right_blob = second.sign_selected_with_seed_checkpoint(
            indices, messages, contexts=contexts
        )
        self.assertEqual(left, right)
        self.assertEqual(left_blob, right_blob)


class SignSelectedWithSeedCheckpointConcurrencyTest(unittest.TestCase):
    def test_linearises_with_all_state_operations(self):
        height = 4
        leaf_count = 1 << height
        signer = make_seed_signer(height=height)
        results = []
        seed_snapshots = []
        reads = []
        errors = []
        exhausted = []
        barrier = threading.Barrier(leaf_count)
        lock = threading.Lock()

        def worker(i):
            try:
                barrier.wait(timeout=10)
                if i == leaf_count - 1:
                    signer.advance_to(leaf_count)
                elif i % 4 == 0:
                    indices = (i, i + 1)
                    messages = (f"m{i}a", f"m{i}b")
                    signatures, blob = (
                        signer.sign_selected_with_seed_checkpoint(
                            indices, messages, context=f"ctx{i}"
                        )
                    )
                    with lock:
                        results.append((messages, f"ctx{i}", signatures, blob))
                elif i % 4 == 1:
                    signer.sign(f"m{i}")
                elif i % 4 == 2:
                    with lock:
                        seed_snapshots.append(signer.seed_checkpoint())
                else:
                    reads.append((signer.next_index, signer.remaining))
            except (KeyExhaustedError, ValueError):
                # ValueError: a selection raced past its chosen leaves.
                exhausted.append(i)
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(i,)) for i in range(leaf_count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])

        used = sorted(
            signature.index
            for _, _, signatures, _ in results
            for signature in signatures
        )
        self.assertEqual(len(used), len(set(used)))
        self.assertEqual(signer.next_index, leaf_count)
        self.assertEqual(signer.remaining, 0)
        for next_index, remaining in reads:
            self.assertTrue(0 <= next_index <= leaf_count)
            self.assertTrue(0 <= remaining <= leaf_count)

        # Each returned checkpoint matches the state right at the end of its
        # own call: restore, check the public key and the resume position,
        # and verify the signatures with the call's context.
        for messages, context, signatures, blob in results:
            with self.subTest(indices=[s.index for s in signatures]):
                self.assertEqual(len(blob), 109)
                restored = MerkleSigner.from_seed_checkpoint(blob)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertEqual(
                    restored.next_index, signatures[-1].index + 1
                )
                self.assertEqual(
                    int.from_bytes(blob[11:13], "big"),
                    signatures[-1].index + 1,
                )
                for message, signature in zip(messages, signatures):
                    self.assertTrue(
                        merkle_verify(
                            message,
                            signature,
                            signer.public_key,
                            context=context,
                        )
                    )
        for blob in seed_snapshots:
            restored = MerkleSigner.from_seed_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)


if __name__ == "__main__":
    unittest.main()

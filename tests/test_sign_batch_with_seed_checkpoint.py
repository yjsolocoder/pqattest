import threading
import unittest

from pqattest import (
    KeyExhaustedError,
    MerkleBatchProof,
    MerkleSigner,
    merkle_verify,
)
from pqattest.merkle import _SEED_CHECKPOINT_BYTES

SEED = bytes(range(32))
OTHER_SEED = bytes(range(1, 33))


def make_signer(height=2, w=4, seed=SEED):
    return MerkleSigner.from_seed(seed, height=height, w=w)


class SignBatchWithSeedCheckpointTest(unittest.TestCase):
    def test_returns_signatures_tuple_and_109_byte_checkpoint(self):
        signer = make_signer()
        signatures, blob = signer.sign_batch_with_seed_checkpoint(("a", "b"))
        self.assertIsInstance(signatures, tuple)
        self.assertEqual(len(signatures), 2)
        self.assertIsInstance(blob, bytes)
        self.assertEqual(len(blob), _SEED_CHECKPOINT_BYTES)
        self.assertEqual(len(blob), 109)

    def test_signatures_match_sign_batch_shared_context(self):
        signer = make_signer()
        reference = make_signer()
        messages = (b"one", bytearray(b"two"), "three")
        signatures, _ = signer.sign_batch_with_seed_checkpoint(
            messages, context="ctx"
        )
        self.assertEqual(signatures, reference.sign_batch(messages, context="ctx"))

    def test_signatures_match_sign_batch_per_message_contexts(self):
        signer = make_signer()
        reference = make_signer()
        messages = (b"one", bytearray(b"two"), "three")
        contexts = (None, b"", "ctx")
        signatures, _ = signer.sign_batch_with_seed_checkpoint(
            messages, contexts=contexts
        )
        self.assertEqual(signatures, reference.sign_batch(messages, contexts=contexts))

    def test_leaves_are_consecutive_and_state_advances_by_batch_size(self):
        signer = make_signer()
        signer.sign("skipped")
        before = signer.next_index
        messages = ("a", "b", "c")
        signatures, blob = signer.sign_batch_with_seed_checkpoint(messages)
        self.assertEqual(
            [signature.index for signature in signatures],
            [before, before + 1, before + 2],
        )
        self.assertEqual(signer.next_index, before + 3)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), before + 3)

    def test_checkpoint_equals_immediate_seed_checkpoint_after_sign_batch(self):
        signer = make_signer()
        reference = make_signer()
        messages = ("one", "two")
        _, blob = signer.sign_batch_with_seed_checkpoint(
            messages, contexts=(None, "ctx")
        )
        reference.sign_batch(messages, contexts=(None, "ctx"))
        self.assertEqual(blob, reference.seed_checkpoint())

    def test_checkpoint_is_deterministic_for_the_same_state(self):
        messages = ("a", "b")
        first = make_signer(seed=OTHER_SEED)
        second = make_signer(seed=OTHER_SEED)
        _, blob_a = first.sign_batch_with_seed_checkpoint(messages)
        _, blob_b = second.sign_batch_with_seed_checkpoint(messages)
        self.assertEqual(blob_a, blob_b)

    def test_signatures_verify_with_matching_contexts(self):
        signer = make_signer(height=3)
        messages = ("a", b"b", bytearray(b"c"), "d")
        contexts = ("one", None, b"", "four")
        signatures, _ = signer.sign_batch_with_seed_checkpoint(
            messages, contexts=contexts
        )
        for message, signature, context in zip(messages, signatures, contexts):
            self.assertTrue(
                merkle_verify(message, signature, signer.public_key, context=context)
            )
        # A bound/omitted context fails verification like on any signature.
        self.assertFalse(
            merkle_verify("a", signatures[0], signer.public_key)
        )
        # The batch proof verification entry accepts the same contexts.
        proof = MerkleBatchProof(
            public_key=signer.public_key, signatures=signatures
        )
        self.assertTrue(proof.verify(messages, contexts=contexts))

    def test_restored_checkpoint_keeps_public_key_and_resumes(self):
        signer = make_signer(height=3)
        messages = ("one", "two")
        signatures, blob = signer.sign_batch_with_seed_checkpoint(messages)
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 2)
        self.assertEqual(restored.remaining, 6)
        resumed = restored.sign_batch(("three", "four"))
        self.assertEqual([s.index for s in resumed], [2, 3])
        reference = make_signer(height=3)
        self.assertEqual(
            reference.sign_batch(("one", "two", "three", "four")),
            signatures + resumed,
        )

    def test_restored_signer_supports_the_entry_again(self):
        signer = make_signer(height=2)
        _, blob = signer.sign_batch_with_seed_checkpoint(("a",))
        restored = MerkleSigner.from_seed_checkpoint(blob)
        signatures, blob2 = restored.sign_batch_with_seed_checkpoint(("b",))
        self.assertEqual([s.index for s in signatures], [1])
        self.assertEqual(MerkleSigner.from_seed_checkpoint(blob2).next_index, 2)

    def test_checkpoint_at_exact_exhaustion_restores_remaining_zero(self):
        signer = make_signer(height=2)
        signatures, blob = signer.sign_batch_with_seed_checkpoint(
            ("a", "b", "c", "d")
        )
        self.assertEqual([s.index for s in signatures], [0, 1, 2, 3])
        self.assertEqual(signer.remaining, 0)
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("x")

    def test_empty_batch_returns_empty_tuple_and_unchanged_state_checkpoint(self):
        signer = make_signer()
        before = signer.seed_checkpoint()
        signatures, blob = signer.sign_batch_with_seed_checkpoint(())
        self.assertEqual(signatures, ())
        self.assertEqual(blob, before)
        self.assertEqual(signer.next_index, 0)

    def test_empty_batch_with_empty_contexts(self):
        signer = make_signer()
        before = signer.seed_checkpoint()
        signatures, blob = signer.sign_batch_with_seed_checkpoint((), contexts=())
        self.assertEqual(signatures, ())
        self.assertEqual(blob, before)

    def test_empty_batch_legal_on_exhausted_signer(self):
        signer = make_signer(height=2)
        signer.advance_to(4)
        exhausted_blob = signer.seed_checkpoint()
        signatures, blob = signer.sign_batch_with_seed_checkpoint(())
        self.assertEqual(signatures, ())
        self.assertEqual(blob, exhausted_blob)
        signatures, blob = signer.sign_batch_with_seed_checkpoint((), contexts=())
        self.assertEqual(signatures, ())
        self.assertEqual(blob, exhausted_blob)
        self.assertEqual(signer.next_index, 4)

    def test_random_signer_rejected_even_with_valid_inputs(self):
        signer = MerkleSigner(height=2)
        with self.assertRaises(ValueError):
            signer.sign_batch_with_seed_checkpoint(("a",))

    def test_full_checkpoint_restore_rejected_even_when_originally_seeded(self):
        signer = MerkleSigner.from_checkpoint(make_signer().checkpoint())
        with self.assertRaises(ValueError):
            signer.sign_batch_with_seed_checkpoint(("a",))

    def test_contexts_not_written_into_checkpoint(self):
        signer = make_signer()
        plain = make_signer()
        messages = ("a", "b")
        _, blob_contexts = signer.sign_batch_with_seed_checkpoint(
            messages, contexts=("x", "y")
        )
        _, blob_plain = plain.sign_batch_with_seed_checkpoint(messages)
        self.assertEqual(blob_contexts, blob_plain)

    def test_type_errors_are_raised_before_value_errors(self):
        signer = make_signer()
        # Non-tuple messages.
        for bad_messages in (["a"], "a", b"ab"):
            with self.subTest(bad_messages=type(bad_messages)):
                with self.assertRaises(TypeError):
                    signer.sign_batch_with_seed_checkpoint(bad_messages)
        # Illegal message members.
        for bad_member in (1, None, object()):
            with self.subTest(bad_member=type(bad_member)):
                with self.assertRaises(TypeError):
                    signer.sign_batch_with_seed_checkpoint((bad_member,))
        # Bad shared context.
        with self.assertRaises(TypeError):
            signer.sign_batch_with_seed_checkpoint(("a",), context=4)
        # Non-tuple contexts or illegal context members.
        with self.assertRaises(TypeError):
            signer.sign_batch_with_seed_checkpoint(("a",), contexts=[None])
        with self.assertRaises(TypeError):
            signer.sign_batch_with_seed_checkpoint(("a",), contexts=(4,))
        # Container/member type errors win even over exhaustion.
        exhausted = make_signer(height=1)
        exhausted.advance_to(2)
        with self.assertRaises(TypeError):
            exhausted.sign_batch_with_seed_checkpoint(["a"])
        with self.assertRaises(TypeError):
            exhausted.sign_batch_with_seed_checkpoint((1,))

    def test_value_errors_follow_type_errors(self):
        signer = make_signer()
        # contexts count mismatch.
        with self.assertRaises(ValueError):
            signer.sign_batch_with_seed_checkpoint(("a", "b"), contexts=(None,))
        # Non-empty shared context combined with contexts.
        with self.assertRaises(ValueError):
            signer.sign_batch_with_seed_checkpoint(
                ("a",), context="c", contexts=(None,)
            )
        # Empty shared context combined with contexts is not a conflict.
        signatures, _ = signer.sign_batch_with_seed_checkpoint(
            ("a",), context="", contexts=(None,)
        )
        self.assertEqual(len(signatures), 1)

    def test_count_and_conflict_checked_before_seed_retention(self):
        # A non-seed signer would raise ValueError for lacking a seed, but the
        # count/conflict ValueError must come first.
        random_signer = MerkleSigner(height=2)
        with self.assertRaises(ValueError):
            random_signer.sign_batch_with_seed_checkpoint(
                ("a", "b"), contexts=(None,)
            )
        with self.assertRaises(ValueError):
            random_signer.sign_batch_with_seed_checkpoint(
                ("a",), context="c", contexts=(None,)
            )

    def test_seed_retention_checked_before_capacity(self):
        # Valid non-empty inputs on a non-seed, fully exhausted signer: seed
        # retention (ValueError) wins over capacity (KeyExhaustedError).
        signer = MerkleSigner(height=2)
        signer.advance_to(4)
        with self.assertRaises(ValueError):
            signer.sign_batch_with_seed_checkpoint(("a",))

    def test_non_empty_oversized_batch_raises_exhausted(self):
        signer = make_signer(height=2)
        signer.advance_to(3)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_with_seed_checkpoint(("a", "b"))
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_with_seed_checkpoint(
                ("a", "b"), contexts=(None, "x")
            )

    def test_failed_capacity_check_consumes_no_leaf(self):
        signer = make_signer(height=2)
        before = signer.seed_checkpoint()
        next_before = signer.next_index
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_with_seed_checkpoint(("a",) * 5)
        self.assertEqual(signer.next_index, next_before)
        self.assertEqual(signer.seed_checkpoint(), before)

    def test_failed_validation_consumes_no_leaf(self):
        signer = make_signer(height=2)
        before = signer.seed_checkpoint()
        next_before = signer.next_index
        with self.assertRaises(TypeError):
            signer.sign_batch_with_seed_checkpoint((1, 2))
        with self.assertRaises(ValueError):
            signer.sign_batch_with_seed_checkpoint(("a", "b"), contexts=(None,))
        with self.assertRaises(ValueError):
            signer.sign_batch_with_seed_checkpoint(
                ("a",), context="c", contexts=(None,)
            )
        self.assertEqual(signer.next_index, next_before)
        self.assertEqual(signer.seed_checkpoint(), before)

    def test_concurrent_batches_partition_leaves_and_match_their_checkpoints(self):
        signer = make_signer(height=8)
        leaf_count = 256
        batch_size = 4
        results = []
        lock = threading.Lock()

        def worker() -> None:
            while True:
                messages = tuple(f"m-{threading.get_ident()}-{i}" for i in range(batch_size))
                try:
                    signatures, blob = signer.sign_batch_with_seed_checkpoint(messages)
                except KeyExhaustedError:
                    return
                with lock:
                    results.append((signatures, blob))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # Every leaf allocated exactly once, in contiguous per-batch runs, and
        # each checkpoint records the end of its own batch.
        all_indices = []
        for signatures, blob in results:
            indices = [signature.index for signature in signatures]
            self.assertEqual(indices, list(range(indices[0], indices[0] + batch_size)))
            self.assertEqual(
                int.from_bytes(blob[11:13], "big"), indices[-1] + 1
            )
            all_indices.extend(indices)
        self.assertEqual(sorted(all_indices), list(range(leaf_count)))
        self.assertEqual(signer.remaining, 0)


if __name__ == "__main__":
    unittest.main()

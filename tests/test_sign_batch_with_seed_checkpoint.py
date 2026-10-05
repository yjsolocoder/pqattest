import threading
import unittest

from pqattest import KeyExhaustedError, MerkleSignature, MerkleSigner, merkle_verify
from pqattest.merkle import _SEED_CHECKPOINT_BYTES

SEED = bytes(range(32))


def make_seed_signer(height=2, w=4, seed=SEED):
    return MerkleSigner.from_seed(seed, height=height, w=w)


class SignBatchWithSeedCheckpointTest(unittest.TestCase):
    def test_returns_signatures_tuple_and_109_bytes(self):
        signer = make_seed_signer()
        signatures, blob = signer.sign_batch_with_seed_checkpoint(("a", "b"))
        self.assertIsInstance(signatures, tuple)
        self.assertEqual(len(signatures), 2)
        for signature in signatures:
            self.assertIsInstance(signature, MerkleSignature)
        self.assertIsInstance(blob, bytes)
        self.assertEqual(len(blob), 109)
        self.assertEqual(len(blob), _SEED_CHECKPOINT_BYTES)

    def test_signatures_match_sign_batch_without_context(self):
        signer = make_seed_signer(height=3)
        reference = make_seed_signer(height=3)
        signer.sign("warmup")
        reference.sign("warmup")
        messages = ("one", "two", "three")
        signatures, _ = signer.sign_batch_with_seed_checkpoint(messages)
        self.assertEqual(signatures, reference.sign_batch(messages))

    def test_signatures_match_sign_batch_with_shared_context(self):
        signer = make_seed_signer()
        reference = make_seed_signer()
        messages = ("one", "two")
        signatures, _ = signer.sign_batch_with_seed_checkpoint(
            messages, context="CTX"
        )
        self.assertEqual(
            signatures, reference.sign_batch(messages, context="CTX")
        )
        for message, signature in zip(messages, signatures):
            self.assertTrue(
                merkle_verify(message, signature, signer.public_key, context="CTX")
            )
            self.assertFalse(
                merkle_verify(message, signature, signer.public_key)
            )

    def test_signatures_match_sign_batch_with_per_message_contexts(self):
        signer = make_seed_signer(height=3)
        reference = make_seed_signer(height=3)
        messages = ("one", b"two", bytearray(b"three"))
        contexts = ("c1", None, b"")
        signatures, _ = signer.sign_batch_with_seed_checkpoint(
            messages, contexts=contexts
        )
        self.assertEqual(
            signatures, reference.sign_batch(messages, contexts=contexts)
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
        messages = ("a", "b", "c")
        signatures, _ = signer.sign_batch_with_seed_checkpoint(
            messages, contexts=(None, b"", "")
        )
        self.assertEqual(signatures, reference.sign_batch(messages))

    def test_accepts_bytes_bytearray_and_str_members(self):
        signer = make_seed_signer(height=2)
        messages = (b"m", bytearray(b"m"), "m")
        signatures, blob = signer.sign_batch_with_seed_checkpoint(messages)
        for signature in signatures:
            self.assertTrue(merkle_verify(b"m", signature, signer.public_key))
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 3)

    def test_indices_consecutive_and_state_advances_by_count(self):
        signer = make_seed_signer(height=3)
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
        self.assertEqual(signer.remaining, 8 - (before + 3))

    def test_checkpoint_matches_seed_checkpoint_taken_right_after(self):
        signer = make_seed_signer(height=3)
        reference = make_seed_signer(height=3)
        messages = ("one", "two")
        _, blob = signer.sign_batch_with_seed_checkpoint(messages, context="x")
        reference.sign_batch(messages, context="x")
        self.assertEqual(blob, reference.seed_checkpoint())
        self.assertEqual(blob, signer.seed_checkpoint())

    def test_checkpoint_independent_of_messages_and_contexts(self):
        first = make_seed_signer()
        second = make_seed_signer()
        _, blob_one = first.sign_batch_with_seed_checkpoint(
            ("a", "b"), context="CTX"
        )
        _, blob_two = second.sign_batch_with_seed_checkpoint(
            ("different", b"messages"), contexts=("x", "y")
        )
        # Same index/seed/root parameters => identical checkpoint bytes even
        # though the messages, contexts and signatures differ.
        self.assertEqual(blob_one, blob_two)

    def test_restored_signer_keeps_public_key_and_resumes(self):
        signer = make_seed_signer(height=3)
        messages = ("one", "two", "three")
        signatures, blob = signer.sign_batch_with_seed_checkpoint(messages)
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, signatures[-1].index + 1)
        self.assertEqual(restored.remaining, signer.remaining)
        self.assertEqual(restored.seed_checkpoint(), blob)
        signature = restored.sign("four", context="c")
        self.assertEqual(signature.index, 3)
        self.assertTrue(
            merkle_verify("four", signature, restored.public_key, context="c")
        )

    def test_exact_exhaustion_restores_remaining_zero(self):
        signer = make_seed_signer(height=2)
        signatures, blob = signer.sign_batch_with_seed_checkpoint(
            ("a", "b", "c", "d")
        )
        self.assertEqual(signer.remaining, 0)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 4)
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("x")
        self.assertEqual([s.index for s in signatures], [0, 1, 2, 3])

    def test_empty_batch_returns_empty_tuple_and_unchanged_checkpoint(self):
        signer = make_seed_signer(height=2)
        signer.sign("spent")
        before = signer.next_index
        signatures, blob = signer.sign_batch_with_seed_checkpoint(())
        self.assertEqual(signatures, ())
        self.assertEqual(signer.next_index, before)
        self.assertEqual(blob, signer.seed_checkpoint())
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.next_index, before)

    def test_empty_batch_with_empty_contexts_is_legal(self):
        signer = make_seed_signer()
        signatures, blob = signer.sign_batch_with_seed_checkpoint(
            (), contexts=()
        )
        self.assertEqual(signatures, ())
        self.assertEqual(blob, signer.seed_checkpoint())

    def test_empty_batch_works_when_exhausted(self):
        signer = make_seed_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        self.assertEqual(signer.remaining, 0)
        signatures, blob = signer.sign_batch_with_seed_checkpoint(())
        self.assertEqual(signatures, ())
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.remaining, 0)
        signatures, blob = signer.sign_batch_with_seed_checkpoint(
            (), contexts=()
        )
        self.assertEqual(signatures, ())
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)

    def test_invalid_messages_type_raises_typeerror_without_spending(self):
        signer = make_seed_signer()
        for bad in (None, 42, "m", b"m", [b"m"], {"m": 1}, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_batch_with_seed_checkpoint(bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_message_member_raises_typeerror_without_spending(self):
        signer = make_seed_signer()
        for bad in (("good", 123, "also good"), (object(),), (b"m", None)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    signer.sign_batch_with_seed_checkpoint(bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_context_types_raise_typeerror(self):
        signer = make_seed_signer()
        with self.assertRaises(TypeError):
            signer.sign_batch_with_seed_checkpoint(("m",), context=123)
        with self.assertRaises(TypeError):
            signer.sign_batch_with_seed_checkpoint(("m",), contexts=[None])
        with self.assertRaises(TypeError):
            signer.sign_batch_with_seed_checkpoint(("m",), contexts=(123,))
        with self.assertRaises(TypeError):
            signer.sign_batch_with_seed_checkpoint(("m",), contexts=(object(),))
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_all_types_checked_before_count_and_conflict(self):
        # Bad member type with a wrong count must still surface TypeError.
        signer = make_seed_signer()
        with self.assertRaises(TypeError):
            signer.sign_batch_with_seed_checkpoint(
                ("ok", 1), contexts=("only-one",)
            )
        with self.assertRaises(TypeError):
            signer.sign_batch_with_seed_checkpoint(
                ("ok", "ok"), contexts=(object(), None)
            )
        self.assertEqual(signer.next_index, 0)

    def test_context_count_mismatch_raises_valueerror(self):
        signer = make_seed_signer()
        with self.assertRaises(ValueError):
            signer.sign_batch_with_seed_checkpoint(
                ("a", "b"), contexts=("only-one",)
            )
        with self.assertRaises(ValueError):
            signer.sign_batch_with_seed_checkpoint(
                ("a",), contexts=("x", "y")
            )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_shared_context_conflict_raises_valueerror(self):
        signer = make_seed_signer()
        with self.assertRaises(ValueError):
            signer.sign_batch_with_seed_checkpoint(
                ("a", "b"), context="shared", contexts=(None, None)
            )
        # An empty shared context is "no context" and does not conflict.
        signatures, _ = signer.sign_batch_with_seed_checkpoint(
            ("a",), context="", contexts=(None,)
        )
        self.assertEqual(len(signatures), 1)

    def test_random_signer_rejected_even_with_valid_batch(self):
        signer = MerkleSigner(height=2)
        with self.assertRaises(ValueError):
            signer.sign_batch_with_seed_checkpoint(("a", "b"))
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_full_checkpoint_restore_loses_seed_even_from_seed_origin(self):
        seed_signer = make_seed_signer()
        restored = MerkleSigner.from_checkpoint(seed_signer.checkpoint())
        with self.assertRaises(ValueError):
            restored.seed_checkpoint()
        with self.assertRaises(ValueError):
            restored.sign_batch_with_seed_checkpoint(("a",))
        # The seed ValueError comes before the capacity check.
        exhausted = MerkleSigner.from_checkpoint(
            make_seed_signer(height=1).checkpoint()
        )
        exhausted.advance_to(2)
        with self.assertRaises(ValueError):
            exhausted.sign_batch_with_seed_checkpoint(("a", "b"))
        self.assertEqual(exhausted.next_index, 2)

    def test_seed_check_comes_before_capacity(self):
        # An oversized, otherwise valid batch on a non-seed signer reports
        # the missing seed, not exhaustion.
        signer = MerkleSigner(height=1)
        with self.assertRaises(ValueError):
            signer.sign_batch_with_seed_checkpoint(("a", "b", "c"))

    def test_oversized_batch_raises_without_partial_result(self):
        signer = make_seed_signer(height=1)
        signer.sign("one")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_with_seed_checkpoint(("two", "three"))
        self.assertEqual(signer.next_index, 1)
        signatures, blob = signer.sign_batch_with_seed_checkpoint(("two",))
        self.assertEqual([s.index for s in signatures], [1])
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_with_seed_checkpoint(("x",))
        self.assertEqual(signer.next_index, 2)
        self.assertEqual(signer.remaining, 0)

    def test_input_errors_surfaced_before_exhaustion(self):
        signer = make_seed_signer(height=1)
        signer.advance_to(2)
        with self.assertRaises(TypeError):
            signer.sign_batch_with_seed_checkpoint(("m", 1))
        with self.assertRaises(ValueError):
            signer.sign_batch_with_seed_checkpoint(
                ("m", "n"), contexts=("only-one",)
            )
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_with_seed_checkpoint(("m",))
        self.assertEqual(signer.next_index, 2)

    def test_draws_no_extra_randomness(self):
        import pqattest.merkle
        from unittest import mock

        signer = make_seed_signer(height=2)

        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_batch_with_seed_checkpoint must not draw randomness"
            )

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            signatures, blob = signer.sign_batch_with_seed_checkpoint(
                ("a", "b"), contexts=("c", None)
            )
        self.assertEqual([s.index for s in signatures], [0, 1])
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)

    def test_deterministic_across_seed_derivations(self):
        first = make_seed_signer(height=2)
        second = make_seed_signer(height=2)
        messages = ("a", b"b", bytearray(b"c"), "d")
        left, left_blob = first.sign_batch_with_seed_checkpoint(
            messages, contexts=("x", None, "", "z")
        )
        right, right_blob = second.sign_batch_with_seed_checkpoint(
            messages, contexts=("x", None, "", "z")
        )
        self.assertEqual(left, right)
        self.assertEqual(left_blob, right_blob)


class SignBatchWithSeedCheckpointConcurrencyTest(unittest.TestCase):
    def test_linearises_with_all_state_operations(self):
        height = 4
        leaf_count = 1 << height
        signer = make_seed_signer(height=height)
        results = []
        seed_snapshots = []
        full_snapshots = []
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
                elif i % 5 == 0:
                    messages = (f"m{i}a", f"m{i}b")
                    signatures, blob = (
                        signer.sign_batch_with_seed_checkpoint(
                            messages, context=f"ctx{i}"
                        )
                    )
                    with lock:
                        results.append((messages, f"ctx{i}", signatures, blob))
                elif i % 5 == 1:
                    signer.sign(f"m{i}")
                elif i % 5 == 2:
                    signer.sign_batch((f"m{i}a", f"m{i}b"))
                elif i % 5 == 3:
                    with lock:
                        seed_snapshots.append(signer.seed_checkpoint())
                else:
                    with lock:
                        full_snapshots.append(signer.checkpoint())
                    reads.append((signer.next_index, signer.remaining))
            except KeyExhaustedError:
                exhausted.append(i)
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(leaf_count)]
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
        self.assertLessEqual(len(used) + len(exhausted), leaf_count)
        self.assertEqual(signer.next_index, leaf_count)
        self.assertEqual(signer.remaining, 0)
        for next_index, remaining in reads:
            self.assertTrue(0 <= next_index <= leaf_count)
            self.assertTrue(0 <= remaining <= leaf_count)

        # Each seed checkpoint matches the state right at the end of its own
        # batch: restore, check the public key and the resume position, and
        # verify the signatures with the batch's context.
        for messages, context, signatures, blob in results:
            with self.subTest(indices=[s.index for s in signatures]):
                self.assertEqual(len(blob), 109)
                restored = MerkleSigner.from_seed_checkpoint(blob)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertEqual(restored.next_index, signatures[-1].index + 1)
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
        # Concurrent seed snapshots always restore the same public key.
        for blob in seed_snapshots:
            restored = MerkleSigner.from_seed_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)
        for blob in full_snapshots:
            restored = MerkleSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)


if __name__ == "__main__":
    unittest.main()

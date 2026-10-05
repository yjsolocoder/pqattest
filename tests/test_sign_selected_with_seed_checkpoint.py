"""Tests for MerkleSigner.sign_selected_with_seed_checkpoint."""

import threading
import unittest
from unittest import mock

import pqattest.merkle
from pqattest import (
    KeyExhaustedError,
    MerkleSignature,
    MerkleSigner,
    MerkleBatchProof,
    merkle_verify,
    multiproof_encode,
    multiproof_verify,
    multiproof_verify_bound,
)
from pqattest.merkle import _SEED_CHECKPOINT_BYTES

SEED = bytes(range(32))
OTHER_SEED = b"\xaa" * 32


def make_seed_signer(height=3, w=4, seed=SEED):
    return MerkleSigner.from_seed(seed, height=height, w=w)


class SignSelectedWithSeedCheckpointBasicTest(unittest.TestCase):
    def test_returns_signatures_tuple_and_109_bytes(self):
        signer = make_seed_signer()
        signatures, blob = signer.sign_selected_with_seed_checkpoint(
            (0, 2, 4), ("m0", "m2", "m4")
        )
        self.assertIsInstance(signatures, tuple)
        self.assertEqual(len(signatures), 3)
        for signature in signatures:
            self.assertIsInstance(signature, MerkleSignature)
        self.assertEqual([s.index for s in signatures], [0, 2, 4])
        self.assertIsInstance(blob, bytes)
        self.assertEqual(len(blob), 109)
        self.assertEqual(len(blob), _SEED_CHECKPOINT_BYTES)

    def test_matches_sign_selected_from_same_state(self):
        indices = (1, 3, 6)
        messages = ("a", b"b", bytearray(b"c"))
        atomic = make_seed_signer().sign_selected_with_seed_checkpoint(
            indices, messages
        )[0]
        plain = make_seed_signer().sign_selected(indices, messages)
        self.assertEqual(atomic, plain)

    def test_matches_sign_selected_after_prior_spend(self):
        indices = (3, 5)
        messages = ("x", "y")
        atomic_signer = make_seed_signer()
        plain_signer = make_seed_signer()
        atomic_signer.sign("warm-up")
        plain_signer.sign("warm-up")
        atomic_signer.sign_batch(("a", "b"))
        plain_signer.sign_batch(("a", "b"))
        self.assertEqual(
            atomic_signer.sign_selected_with_seed_checkpoint(indices, messages)[0],
            plain_signer.sign_selected(indices, messages),
        )

    def test_consecutive_selection_matches_sign_batch(self):
        messages = ("a", "b", "c")
        atomic = make_seed_signer().sign_selected_with_seed_checkpoint(
            (0, 1, 2), messages
        )[0]
        batched = make_seed_signer().sign_batch(messages)
        self.assertEqual(atomic, batched)

    def test_gaps_voided_and_state_advances_to_last_plus_one(self):
        signer = make_seed_signer()
        signatures, blob = signer.sign_selected_with_seed_checkpoint(
            (1, 4), ("m1", "m4")
        )
        self.assertEqual([s.index for s in signatures], [1, 4])
        self.assertEqual(signer.next_index, 5)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 5)
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.next_index, 5)
        # Gap leaves (2, 3) stay voided after restore.
        with self.assertRaises(ValueError):
            restored.sign_selected((2,), ("old",))
        next_signature = restored.sign("d")
        self.assertEqual(next_signature.index, 5)

    def test_checkpoint_matches_seed_checkpoint_right_after(self):
        indices = (1, 4)
        messages = ("a", "b")
        signer = make_seed_signer()
        _, atomic_blob = signer.sign_selected_with_seed_checkpoint(indices, messages)
        reference = make_seed_signer()
        reference.sign_selected(indices, messages)
        self.assertEqual(atomic_blob, reference.seed_checkpoint())
        self.assertEqual(atomic_blob, signer.seed_checkpoint())

    def check_restored_signer(
        self, height, w, indices, messages, *, contexts=None, context=None
    ):
        signer = make_seed_signer(height=height, w=w)
        signatures, blob = signer.sign_selected_with_seed_checkpoint(
            indices,
            messages,
            context=context,
            contexts=contexts,
        )
        self.assertEqual(len(blob), 109)
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, indices[-1] + 1)
        self.assertEqual(restored.remaining, (1 << height) - (indices[-1] + 1))
        self.assertEqual(restored.seed_checkpoint(), blob)
        # Re-signing from the same state on a fresh equal instance gives the
        # same signatures.
        twin = make_seed_signer(height=height, w=w)
        self.assertEqual(
            twin.sign_selected(
                indices, messages, context=context, contexts=contexts
            ),
            signatures,
        )
        return signer, restored, signatures

    def test_all_heights_and_w_values(self):
        for height in range(1, 9):
            for w in (4, 8):
                with self.subTest(height=height, w=w):
                    last = (1 << height) - 1
                    indices = tuple(sorted({0, last // 2, last}))
                    messages = tuple(f"m{i}" for i in indices)
                    signer, restored, signatures = self.check_restored_signer(
                        height, w, indices, messages
                    )
                    for message, signature in zip(messages, signatures):
                        self.assertTrue(
                            merkle_verify(message, signature, signer.public_key)
                        )
                    self.assertEqual(restored.remaining, 0)

    def test_last_leaf_reachable_and_exhausts(self):
        signer = make_seed_signer(height=2)
        signatures, blob = signer.sign_selected_with_seed_checkpoint(
            (3,), ("last",)
        )
        self.assertEqual([s.index for s in signatures], [3])
        self.assertEqual(signer.next_index, 4)
        self.assertEqual(signer.remaining, 0)
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("more")

    def test_signatures_verify_single_batch_and_multiproof(self):
        signer = make_seed_signer()
        indices = (1, 2, 5)
        messages = ("m1", b"m2", bytearray(b"m5"))
        contexts = ("c1", None, b"c5")
        signatures, _ = signer.sign_selected_with_seed_checkpoint(
            indices, messages, contexts=contexts
        )
        # Single-signature verification with the matching per-leaf context.
        for message, signature, per_context in zip(
            messages, signatures, contexts
        ):
            self.assertTrue(
                merkle_verify(
                    message, signature, signer.public_key, context=per_context
                )
            )
            self.assertFalse(
                merkle_verify(message, signature, signer.public_key, context="nope")
            )
        # Batch proof verification, bound and unbound.
        batch = MerkleBatchProof(
            public_key=signer.public_key, signatures=signatures
        )
        self.assertTrue(batch.verify(messages, contexts=contexts))
        self.assertTrue(
            batch.verify_bound(
                messages,
                public_key=signer.public_key,
                indices=indices,
                contexts=contexts,
            )
        )
        # Multi-proof verification, bound and unbound.
        proof = multiproof_encode(signer.public_key, signatures)
        self.assertTrue(multiproof_verify(messages, proof, contexts=contexts))
        self.assertTrue(
            multiproof_verify_bound(
                messages, proof, public_key=signer.public_key,
                indices=indices, contexts=contexts,
            )
        )

    def test_shared_context_bound_into_every_digest(self):
        signer = make_seed_signer()
        messages = ("a", "b")
        signatures, _ = signer.sign_selected_with_seed_checkpoint(
            (0, 2), messages, context="CTX"
        )
        reference = make_seed_signer()
        self.assertEqual(
            signatures,
            reference.sign_selected((0, 2), messages, context="CTX"),
        )
        for message, signature in zip(messages, signatures):
            self.assertTrue(
                merkle_verify(message, signature, signer.public_key, context="CTX")
            )
            self.assertFalse(
                merkle_verify(message, signature, signer.public_key)
            )

    def test_per_leaf_contexts_match_sequential_single_signs(self):
        signer = make_seed_signer(height=3)
        reference = make_seed_signer(height=3)
        messages = ("one", b"two", bytearray(b"three"))
        contexts = ("c1", None, b"")
        signatures, _ = signer.sign_selected_with_seed_checkpoint(
            (0, 2, 4), messages, contexts=contexts
        )
        expected = []
        for index, message, per_context in zip((0, 2, 4), messages, contexts):
            if reference.next_index < index:
                reference.advance_to(index)
            expected.append(reference.sign(message, context=per_context))
        self.assertEqual(signatures, tuple(expected))
        for message, signature, per_context in zip(messages, signatures, contexts):
            self.assertTrue(
                merkle_verify(
                    message, signature, signer.public_key, context=per_context
                )
            )

    def test_utf8_str_context(self):
        signer = make_seed_signer()
        signatures, blob = signer.sign_selected_with_seed_checkpoint(
            (0,), ("m",), context="上下文"
        )
        self.assertTrue(
            merkle_verify("m", signatures[0], signer.public_key, context="上下文")
        )
        self.assertEqual(len(blob), 109)

    def test_checkpoint_independent_of_messages_and_contexts(self):
        first = make_seed_signer()
        second = make_seed_signer()
        _, blob_one = first.sign_selected_with_seed_checkpoint(
            (0, 2), ("a", "b"), context="CTX"
        )
        _, blob_two = second.sign_selected_with_seed_checkpoint(
            (0, 2), ("different", b"messages"), contexts=("x", "y")
        )
        # Same seed/parameters/end index => identical checkpoint bytes even
        # though messages, contexts and signatures differ.
        self.assertEqual(blob_one, blob_two)

    def test_different_end_index_gives_different_checkpoint(self):
        first = make_seed_signer()
        second = make_seed_signer()
        _, blob_one = first.sign_selected_with_seed_checkpoint((0,), ("a",))
        _, blob_two = second.sign_selected_with_seed_checkpoint((0, 1), ("a", "b"))
        self.assertNotEqual(blob_one, blob_two)
        self.assertEqual(int.from_bytes(blob_one[11:13], "big"), 1)
        self.assertEqual(int.from_bytes(blob_two[11:13], "big"), 2)

    def test_deterministic_value_for_value(self):
        first = make_seed_signer()
        second = make_seed_signer()
        self.assertEqual(
            first.sign_selected_with_seed_checkpoint(
                (0, 4, 7), ("a", "b", "c"), contexts=("x", None, "z")
            ),
            second.sign_selected_with_seed_checkpoint(
                (0, 4, 7), ("a", "b", "c"), contexts=("x", None, "z")
            ),
        )

    def test_restore_then_resign_same_result(self):
        signer = make_seed_signer(height=3)
        signatures, blob = signer.sign_selected_with_seed_checkpoint(
            (1, 3), ("a", "b"), contexts=("c1", "c2")
        )
        restored = MerkleSigner.from_seed_checkpoint(blob)
        # A later sign on the original signer and on the restored signer must
        # be identical.
        self.assertEqual(
            signer.sign("later", context="lc"),
            restored.sign("later", context="lc"),
        )

    def test_checkpoint_has_no_message_or_context_bytes(self):
        signer = make_seed_signer()
        marker = b"UNIQUE-MARKER"
        _, blob = signer.sign_selected_with_seed_checkpoint(
            (0, 1), (marker, marker + b"x"), context="CTX-MARKER"
        )
        self.assertNotIn(marker, blob)
        self.assertNotIn("CTX-MARKER".encode("utf-8"), blob)

    def test_draws_no_randomness(self):
        signer = make_seed_signer()

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


class SignSelectedWithSeedCheckpointValidationTest(unittest.TestCase):
    def test_non_tuple_arguments_raise_typeerror(self):
        signer = make_seed_signer(height=2)
        for bad_indices in (None, 42, [0, 1], {0, 1}, "01"):
            with self.subTest(bad=type(bad_indices).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_seed_checkpoint(
                        bad_indices, ("a", "b")
                    )
        for bad_messages in (None, 42, ["a", "b"], {0: "a"}, "ab"):
            with self.subTest(bad=type(bad_messages).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_seed_checkpoint((0, 1), bad_messages)

    def test_non_integer_index_members_raise_typeerror(self):
        signer = make_seed_signer(height=2)
        for bad in (("0", "1"), (0, 1.0), (None,), (0, object())):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_seed_checkpoint(
                        bad, tuple("m" for _ in bad)
                    )

    def test_unsupported_message_members_raise_typeerror(self):
        signer = make_seed_signer(height=2)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint((0, 1), ("good", 123))
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint((0,), (object(),))

    def test_invalid_context_types_raise_typeerror(self):
        signer = make_seed_signer()
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint(
                (0,), ("m",), context=123
            )
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint(
                (0,), ("m",), contexts=[None]
            )
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint(
                (0,), ("m",), contexts=(123,)
            )
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint(
                (0,), ("m",), contexts=(object(),)
            )
        self.assertEqual(signer.next_index, 0)

    def test_empty_selection_raises_valueerror(self):
        signer = make_seed_signer(height=2)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((), ())
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((), ("a",))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((0,), ())
        # Empty contexts do not rescue an empty selection, and the
        # empty-batch allowance of sign_batch_with_seed_checkpoint is not
        # inherited.
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((), (), contexts=())
        self.assertEqual(signer.next_index, 0)

    def test_length_mismatch_raises_valueerror(self):
        signer = make_seed_signer(height=3)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((0, 1), ("a",))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((0,), ("a", "b"))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint(
                (0, 1), ("a", "b"), contexts=("only-one",)
            )

    def test_boolean_indices_raise_valueerror(self):
        signer = make_seed_signer(height=3)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((True, 1), ("a", "b"))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((0, False), ("a", "b"))

    def test_duplicate_or_unordered_indices_raise_valueerror(self):
        signer = make_seed_signer(height=3)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((1, 1), ("a", "b"))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((2, 1), ("a", "b"))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint(
                (3, 2, 1), ("a", "b", "c")
            )

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
            signer.sign_selected_with_seed_checkpoint((0, 1), ("a", "b"))
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_full_checkpoint_restore_loses_seed_even_from_seed_origin(self):
        seed_signer = make_seed_signer()
        restored = MerkleSigner.from_checkpoint(seed_signer.checkpoint())
        with self.assertRaises(ValueError):
            restored.seed_checkpoint()
        with self.assertRaises(ValueError):
            restored.sign_selected_with_seed_checkpoint((0,), ("a",))

    def test_seed_check_comes_after_structure_but_before_exhaustion(self):
        # Structural problems on a non-seed signer still surface first.
        signer = MerkleSigner(height=2)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint("not a tuple", ("a",))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((), ())
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((1, 1), ("a", "b"))
        # A structurally valid selection on a seed-derived-but-exhausted
        # signer reports the missing seed, not exhaustion or the range.
        exhausted_full = MerkleSigner.from_checkpoint(
            make_seed_signer(height=1).checkpoint()
        )
        exhausted_full.advance_to(2)
        with self.assertRaises(ValueError):
            exhausted_full.sign_selected_with_seed_checkpoint((0,), ("a",))
        self.assertEqual(exhausted_full.next_index, 2)
        # An out-of-range but otherwise valid selection on a non-seed
        # signer reports the missing seed, not the range error.
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((4,), ("past",))

    def test_exhausted_seed_signer_raises_key_exhausted(self):
        signer = make_seed_signer(height=2)
        signer.advance_to(4)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected_with_seed_checkpoint((3,), ("late",))
        # Structural validation precedes the seed and exhaustion checks.
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint("not a tuple", ())
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((), ())
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected_with_seed_checkpoint((0,), ("late",))
        self.assertEqual(signer.next_index, 4)

    def test_index_below_next_leaf_raises_valueerror(self):
        signer = make_seed_signer(height=3)
        signer.sign_batch(("a", "b", "c"))  # next_index == 3
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((2, 4), ("old", "new"))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((0,), ("old",))
        self.assertEqual(signer.next_index, 3)

    def test_index_past_last_leaf_raises_valueerror(self):
        signer = make_seed_signer(height=2)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((4,), ("past",))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint((0, 4), ("ok", "past"))
        self.assertEqual(signer.next_index, 0)

    def test_validation_order_full(self):
        # Types/structure -> seed -> exhaustion -> range.
        random_signer = MerkleSigner(height=1)
        with self.assertRaises(TypeError):
            random_signer.sign_selected_with_seed_checkpoint((0,), (123,))
        with self.assertRaises(ValueError):
            random_signer.sign_selected_with_seed_checkpoint((), ())
        exhausted = make_seed_signer(height=1)
        exhausted.advance_to(2)
        with self.assertRaises(KeyExhaustedError):
            exhausted.sign_selected_with_seed_checkpoint((0,), ("x",))
        fresh = make_seed_signer(height=1)
        with self.assertRaises(ValueError):
            fresh.sign_selected_with_seed_checkpoint((2,), ("x",))
        with self.assertRaises(ValueError):
            fresh.sign_selected_with_seed_checkpoint((-1,), ("x",))

    def test_failure_consumes_no_leaf(self):
        signer = make_seed_signer(height=3)
        for bad_indices, bad_messages in (
            ((1, 1), ("a", "b")),
            ((8,), ("ok",)),
            ((0, 1), ("only-one",)),
        ):
            with self.assertRaises(ValueError):
                signer.sign_selected_with_seed_checkpoint(bad_indices, bad_messages)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_seed_checkpoint((0, 1), ("a", 2))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_seed_checkpoint(
                (0, 1), ("a", "b"), context="x", contexts=(None, None)
            )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("first").index, 0)


class SignSelectedWithSeedCheckpointConcurrencyTest(unittest.TestCase):
    def test_concurrent_selections_never_share_a_leaf(self):
        height = 4
        signer = make_seed_signer(height=height)
        leaf_count = 1 << height
        picked = []
        checkpoints = []
        errors = []
        list_lock = threading.Lock()
        barrier = threading.Barrier(4)

        def worker(offset):
            try:
                indices = tuple(range(offset, leaf_count, 4))
                messages = tuple(f"w{offset}-{i}" for i in indices)
                barrier.wait(timeout=10)
                signatures, checkpoint = (
                    signer.sign_selected_with_seed_checkpoint(indices, messages)
                )
                with list_lock:
                    picked.extend(s.index for s in signatures)
                    checkpoints.append(checkpoint)
            except Exception as exc:  # pragma: no cover - failure path
                with list_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertGreaterEqual(len(errors), 3)
        winner_picked = sorted(picked)
        self.assertEqual(winner_picked, sorted(set(winner_picked)))
        self.assertEqual(signer.next_index, max(winner_picked) + 1)
        # The single winner's checkpoint is exactly 109 bytes and restores
        # the committed state.
        self.assertEqual(len(checkpoints), 1)
        restored = MerkleSigner.from_seed_checkpoint(checkpoints[0])
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, signer.next_index)
        self.assertEqual(restored.remaining, signer.remaining)

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
                elif i % 6 == 0:
                    indices = (i,)
                    messages = (f"m{i}",)
                    signatures, blob = (
                        signer.sign_selected_with_seed_checkpoint(
                            indices, messages, context=f"ctx{i}"
                        )
                    )
                    with lock:
                        results.append((messages, f"ctx{i}", signatures, blob))
                elif i % 6 == 1:
                    signer.sign(f"m{i}")
                elif i % 6 == 2:
                    signer.sign_batch((f"m{i}a", f"m{i}b"))
                elif i % 6 == 3:
                    signer.sign_selected((i,), (f"m{i}",))
                elif i % 6 == 4:
                    with lock:
                        seed_snapshots.append(signer.seed_checkpoint())
                else:
                    with lock:
                        full_snapshots.append(signer.checkpoint())
                    reads.append((signer.next_index, signer.remaining))
            except KeyExhaustedError:
                exhausted.append(i)
            except ValueError:
                # A sign_selected race that finds leaf i already spent is a
                # normal lost-race outcome, not a test failure.
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
        self.assertLessEqual(len(used) + len(exhausted), leaf_count)
        self.assertEqual(signer.next_index, leaf_count)
        self.assertEqual(signer.remaining, 0)
        for next_index, remaining in reads:
            self.assertTrue(0 <= next_index <= leaf_count)
            self.assertTrue(0 <= remaining <= leaf_count)

        # Each returned seed checkpoint matches the state at the end of its
        # own selection and excludes later concurrent advances.
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
        for blob in seed_snapshots:
            restored = MerkleSigner.from_seed_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)
        for blob in full_snapshots:
            restored = MerkleSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)


if __name__ == "__main__":
    unittest.main()

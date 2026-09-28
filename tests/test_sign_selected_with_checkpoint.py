"""Tests for MerkleSigner.sign_selected_with_checkpoint."""

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
    multiproof_verify_bound,
)


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=3, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


class SignSelectedWithCheckpointBasicTest(unittest.TestCase):
    def test_returns_signatures_tuple_and_bytes(self):
        signer = make_signer()
        signatures, checkpoint = signer.sign_selected_with_checkpoint(
            (0, 2, 4), (b"m0", b"m2", b"m4")
        )
        self.assertIsInstance(signatures, tuple)
        self.assertEqual(len(signatures), 3)
        for signature in signatures:
            self.assertIsInstance(signature, MerkleSignature)
        self.assertEqual([s.index for s in signatures], [0, 2, 4])
        self.assertIsInstance(checkpoint, bytes)

    def test_signatures_match_sign_selected_from_same_state(self):
        indices = (1, 3, 6)
        messages = ("a", b"b", bytearray(b"c"))
        atomic = make_signer().sign_selected_with_checkpoint(indices, messages)[0]
        plain = make_signer().sign_selected(indices, messages)
        self.assertEqual(atomic, plain)

    def test_consecutive_selection_matches_sign_batch(self):
        messages = ("a", "b", "c")
        atomic = make_signer().sign_selected_with_checkpoint((0, 1, 2), messages)[0]
        batched = make_signer().sign_batch(messages)
        self.assertEqual(atomic, batched)

    def test_checkpoint_matches_checkpoint_after_sign_selected(self):
        indices = (1, 4)
        messages = ("a", "b")
        signer = make_signer()
        _, atomic_blob = signer.sign_selected_with_checkpoint(indices, messages)
        reference = make_signer()
        reference.sign_selected(indices, messages)
        self.assertEqual(atomic_blob, reference.checkpoint())

    def test_checkpoint_restores_same_key_and_resumes_after_last_leaf(self):
        signer = make_signer()
        messages = ("m1", "m4")
        signatures, checkpoint = signer.sign_selected_with_checkpoint(
            (1, 4), messages
        )
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 5)
        for message, signature in zip(messages, signatures):
            self.assertTrue(merkle_verify(message, signature, signer.public_key))
        # Gaps stay voided after restore; signing resumes after the last pick.
        with self.assertRaises(ValueError):
            restored.sign_selected((2,), ("old",))
        next_signature = restored.sign("d")
        self.assertEqual(next_signature.index, 5)

    def test_state_advances_to_last_index_plus_one(self):
        signer = make_signer()
        signer.sign("warm-up")
        signatures, _ = signer.sign_selected_with_checkpoint(
            (2, 5), ("x", "y")
        )
        self.assertEqual([s.index for s in signatures], [2, 5])
        self.assertEqual(signer.next_index, 6)

    def test_last_leaf_reachable_and_exhausts(self):
        signer = make_signer(height=2)
        signatures, checkpoint = signer.sign_selected_with_checkpoint(
            (3,), ("last",)
        )
        self.assertEqual([s.index for s in signatures], [3])
        self.assertEqual(signer.next_index, 4)
        self.assertEqual(signer.remaining, 0)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 4)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("more")

    def test_multiproof_packs_the_selection(self):
        signer = make_signer()
        indices = (1, 2, 5)
        messages = ("m1", b"m2", bytearray(b"m5"))
        signatures, _ = signer.sign_selected_with_checkpoint(indices, messages)
        proof = multiproof_encode(signer.public_key, signatures)
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertTrue(
            multiproof_verify_bound(
                messages, proof, public_key=signer.public_key, indices=indices
            )
        )

    def test_deterministic_value_for_value(self):
        first = make_signer()
        second = make_signer()
        self.assertEqual(
            first.sign_selected_with_checkpoint((0, 4, 7), ("a", "b", "c")),
            second.sign_selected_with_checkpoint((0, 4, 7), ("a", "b", "c")),
        )

    def test_draws_no_randomness(self):
        signer = make_signer()

        def exploding_token_bytes(size):
            raise AssertionError("sign_selected_with_checkpoint must not draw randomness")

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            signatures, checkpoint = signer.sign_selected_with_checkpoint(
                (0, 2), ("a", "b")
            )
        self.assertEqual([s.index for s in signatures], [0, 2])
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 3)


class SignSelectedWithCheckpointValidationTest(unittest.TestCase):
    def test_non_tuple_arguments_raise_typeerror(self):
        signer = make_signer(height=2)
        for bad_indices in (None, 42, [0, 1], {0, 1}, "01"):
            with self.subTest(bad=type(bad_indices).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_checkpoint(bad_indices, ("a", "b"))
        for bad_messages in (None, 42, ["a", "b"], {0: "a"}, "ab"):
            with self.subTest(bad=type(bad_messages).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_checkpoint((0, 1), bad_messages)

    def test_non_integer_index_members_raise_typeerror(self):
        signer = make_signer(height=2)
        for bad in (("0", "1"), (0, 1.0), (None,), (0, object())):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_checkpoint(
                        bad, tuple("m" for _ in bad)
                    )

    def test_unsupported_message_members_raise_typeerror(self):
        signer = make_signer(height=2)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_checkpoint((0, 1), ("good", 123))
        with self.assertRaises(TypeError):
            signer.sign_selected_with_checkpoint((0,), (object(),))

    def test_empty_tuples_raise_valueerror(self):
        signer = make_signer(height=2)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((), ())
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((), ("a",))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((0,), ())

    def test_length_mismatch_raises_valueerror(self):
        signer = make_signer(height=3)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((0, 1), ("a",))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((0,), ("a", "b"))

    def test_boolean_indices_raise_valueerror(self):
        signer = make_signer(height=3)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((True, 1), ("a", "b"))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((0, False), ("a", "b"))

    def test_duplicate_or_unordered_indices_raise_valueerror(self):
        signer = make_signer(height=3)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((1, 1), ("a", "b"))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((2, 1), ("a", "b"))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((3, 2, 1), ("a", "b", "c"))

    def test_index_below_next_leaf_raises_valueerror(self):
        signer = make_signer(height=3)
        signer.sign_batch(("a", "b", "c"))  # next_index == 3
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((2, 4), ("old", "new"))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((0,), ("old",))
        self.assertEqual(signer.next_index, 3)

    def test_index_past_last_leaf_raises_valueerror(self):
        signer = make_signer(height=2)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((4,), ("past",))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((0, 4), ("ok", "past"))
        self.assertEqual(signer.next_index, 0)

    def test_exhausted_signer_raises_key_exhausted(self):
        signer = make_signer(height=2)
        signer.advance_to(4)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected_with_checkpoint((3,), ("late",))
        # Structural validation precedes the exhaustion check.
        with self.assertRaises(TypeError):
            signer.sign_selected_with_checkpoint("not a tuple", ())
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((), ())
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected_with_checkpoint((0,), ("late",))

    def test_validation_order_type_structure_then_exhaustion_then_range(self):
        signer = make_signer(height=1)
        signer.advance_to(2)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_checkpoint((0,), (123,))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((), ())
        fresh = make_signer(height=1)
        with self.assertRaises(ValueError):
            fresh.sign_selected_with_checkpoint((2,), ("x",))
        with self.assertRaises(ValueError):
            fresh.sign_selected_with_checkpoint((-1,), ("x",))

    def test_failure_consumes_no_leaf(self):
        signer = make_signer(height=3)
        for bad_indices, bad_messages in (
            ((1, 1), ("a", "b")),
            ((8,), ("ok",)),
            ((0, 1), ("only-one",)),
        ):
            with self.assertRaises(ValueError):
                signer.sign_selected_with_checkpoint(bad_indices, bad_messages)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_checkpoint((0, 1), ("a", 2))
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("first").index, 0)


class SignSelectedWithCheckpointConcurrencyTest(unittest.TestCase):
    def test_concurrent_selections_never_share_a_leaf(self):
        height = 4
        signer = make_signer(height=height)
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
                    signer.sign_selected_with_checkpoint(indices, messages)
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
        # The single winner's checkpoint restores the committed state.
        self.assertEqual(len(checkpoints), 1)
        restored = MerkleSigner.from_checkpoint(checkpoints[0])
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, signer.next_index)


if __name__ == "__main__":
    unittest.main()

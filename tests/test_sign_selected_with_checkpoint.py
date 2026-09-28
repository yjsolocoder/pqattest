"""Tests for MerkleSigner.sign_selected_with_checkpoint."""

import threading
import unittest

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
        signer = make_signer(height=3)
        signatures, blob = signer.sign_selected_with_checkpoint(
            (1, 3, 5), ("a", b"b", bytearray(b"c"))
        )
        self.assertIsInstance(signatures, tuple)
        self.assertEqual(len(signatures), 3)
        for signature in signatures:
            self.assertIsInstance(signature, MerkleSignature)
        self.assertIsInstance(blob, bytes)

    def test_signatures_match_sign_selected_from_same_state(self):
        indices = (1, 4, 6)
        messages = ("one", b"two", bytearray(b"three"))
        signer = make_signer(height=3)
        reference = make_signer(height=3)
        signatures, _ = signer.sign_selected_with_checkpoint(indices, messages)
        self.assertEqual(signatures, reference.sign_selected(indices, messages))

    def test_signatures_match_after_warmup(self):
        indices = (2, 5)
        messages = ("x", "y")
        signer = make_signer(height=3)
        reference = make_signer(height=3)
        signer.sign("warm-up")
        reference.sign("warm-up")
        signatures, _ = signer.sign_selected_with_checkpoint(indices, messages)
        self.assertEqual(signatures, reference.sign_selected(indices, messages))
        self.assertEqual(signer.next_index, 6)

    def test_gap_leaves_are_voided(self):
        signer = make_signer(height=3)
        signatures, blob = signer.sign_selected_with_checkpoint(
            (1, 4), ("a", "b")
        )
        self.assertEqual([s.index for s in signatures], [1, 4])
        self.assertEqual(signer.next_index, 5)
        self.assertEqual(signer.remaining, 3)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 5)
        with self.assertRaises(ValueError):
            signer.sign_selected((2,), ("too late",))
        next_signature = signer.sign("c")
        self.assertEqual(next_signature.index, 5)

    def test_every_signature_verifies_bound_to_its_leaf(self):
        signer = make_signer(height=3)
        indices = (0, 2, 4, 7)
        messages = (b"m0", "m2", bytearray(b"m4"), b"m7")
        signatures, _ = signer.sign_selected_with_checkpoint(indices, messages)
        self.assertEqual([s.index for s in signatures], list(indices))
        for index, message, signature in zip(indices, messages, signatures):
            self.assertEqual(signature.index, index)
            self.assertTrue(merkle_verify(message, signature, signer.public_key))

    def test_multiproof_packs_and_verifies(self):
        signer = make_signer(height=3)
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
        self.assertFalse(
            multiproof_verify_bound(
                messages, proof, public_key=signer.public_key, indices=(0, 2, 5)
            )
        )

    def test_consecutive_selection_matches_batch_value_for_value(self):
        messages = ("a", b"b", bytearray(b"c"), "d")
        selected = make_signer(height=3).sign_selected_with_checkpoint(
            (0, 1, 2, 3), messages
        )[0]
        batched = make_signer(height=3).sign_batch(messages)
        self.assertEqual(selected, batched)

    def test_deterministic_value_for_value(self):
        first = make_signer(height=3)
        second = make_signer(height=3)
        self.assertEqual(
            first.sign_selected_with_checkpoint((0, 4, 7), ("a", "b", "c")),
            second.sign_selected_with_checkpoint((0, 4, 7), ("a", "b", "c")),
        )


class SignSelectedWithCheckpointSnapshotTest(unittest.TestCase):
    def test_checkpoint_matches_post_selection_checkpoint(self):
        signer = make_signer(height=3)
        reference = make_signer(height=3)
        indices = (1, 4)
        messages = ("a", "b")
        _, blob = signer.sign_selected_with_checkpoint(indices, messages)
        reference.sign_selected(indices, messages)
        self.assertEqual(blob, reference.checkpoint())

    def test_checkpoint_matches_advance_to_checkpoint_bytes(self):
        signer = make_signer(height=2)
        other = make_signer(height=2)
        _, blob = signer.sign_selected_with_checkpoint((0, 2), ("a", "b"))
        other.advance_to(3)
        self.assertEqual(blob, other.checkpoint())

    def test_checkpoint_restores_same_public_key_resuming_after_last_item(self):
        signer = make_signer(height=3)
        signatures, blob = signer.sign_selected_with_checkpoint(
            (1, 4), ("a", "b")
        )
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 5)
        self.assertEqual(restored.remaining, 3)
        with self.assertRaises(ValueError):
            restored.sign_selected((2,), ("old",))
        signature = restored.sign("d")
        self.assertEqual(signature.index, 5)
        self.assertTrue(merkle_verify("d", signature, restored.public_key))
        self.assertEqual(signatures[-1].index, 4)

    def test_last_leaf_checkpoint_restores_exhausted(self):
        signer = make_signer(height=2)
        signatures, blob = signer.sign_selected_with_checkpoint(
            (3,), ("last",)
        )
        self.assertEqual([s.index for s in signatures], [3])
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("more")


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
        signer = make_signer(height=2)  # leaves 0..3
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((4,), ("past",))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((0, 4), ("ok", "past"))
        self.assertEqual(signer.next_index, 0)

    def test_negative_index_raises_valueerror(self):
        signer = make_signer(height=2)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((-1,), ("x",))

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
        signer = make_signer(height=1)  # leaves 0, 1
        signer.advance_to(2)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_checkpoint((0,), (123,))
        with self.assertRaises(ValueError):
            signer.sign_selected_with_checkpoint((), ())
        fresh = make_signer(height=1)
        # Leaves remain, so an out-of-range index is ValueError, never
        # KeyExhaustedError.
        with self.assertRaises(ValueError):
            fresh.sign_selected_with_checkpoint((2,), ("x",))

    def test_failure_consumes_no_leaf_and_returns_nothing_partial(self):
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
    def test_concurrent_calls_never_share_a_leaf(self):
        height = 4
        signer = make_signer(height=height)
        leaf_count = 1 << height
        picked = []
        next_indices = []
        errors = []
        list_lock = threading.Lock()
        barrier = threading.Barrier(4)

        def worker(offset):
            try:
                indices = tuple(range(offset, leaf_count, 4))
                messages = tuple(f"w{offset}-{i}" for i in indices)
                barrier.wait(timeout=10)
                signatures, blob = signer.sign_selected_with_checkpoint(
                    indices, messages
                )
                with list_lock:
                    picked.extend(s.index for s in signatures)
                    next_indices.append(int.from_bytes(blob[11:13], "big"))
            except Exception as exc:  # pragma: no cover - failure path
                with list_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertGreaterEqual(len(errors), 3)
        # Exactly one winner; no leaf is signed twice and its checkpoint sits
        # one past its last chosen leaf.
        self.assertEqual(picked, sorted(set(picked)))
        self.assertEqual(len(next_indices), 1)
        self.assertEqual(next_indices[0], signer.next_index)
        self.assertEqual(next_indices[0], max(picked) + 1)

    def test_concurrent_plain_signs_never_overlap_selection(self):
        height = 3
        signer = make_signer(height=height)
        results = []
        errors = []
        result_lock = threading.Lock()
        barrier = threading.Barrier(2)

        def plain():
            try:
                barrier.wait(timeout=10)
                for _ in range(1 << height):
                    results.append(signer.sign("p").index)
            except KeyExhaustedError:
                pass
            except Exception as exc:  # pragma: no cover - failure path
                with result_lock:
                    errors.append(exc)

        def selected():
            try:
                barrier.wait(timeout=10)
                signer.sign_selected_with_checkpoint(
                    (0, 2, 4, 6), tuple("sxyzwvut"[:4])
                )
            except ValueError:
                pass  # Lost the race: indices already spent.
            except Exception as exc:  # pragma: no cover - failure path
                with result_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=plain), threading.Thread(target=selected)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(results, sorted(set(results)))


if __name__ == "__main__":
    unittest.main()

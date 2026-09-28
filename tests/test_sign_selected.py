"""Tests for MerkleSigner.sign_selected: explicit leaf-set atomic signing."""

import threading
import unittest

from pqattest import (
    KeyExhaustedError,
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


class SignSelectedBasicTest(unittest.TestCase):
    def test_signs_explicit_indices_in_order(self):
        signer = make_signer(height=3)
        signatures = signer.sign_selected((0, 2, 4), (b"m0", b"m2", b"m4"))
        self.assertIsInstance(signatures, tuple)
        self.assertEqual([s.index for s in signatures], [0, 2, 4])
        for message, signature in zip((b"m0", b"m2", b"m4"), signatures):
            self.assertTrue(merkle_verify(message, signature, signer.public_key))

    def test_gap_leaves_are_voided(self):
        signer = make_signer(height=3)
        signer.sign_selected((1, 4), ("a", "b"))
        # Leaves 0, 2 and 3 were skipped and are now voided: the next usable
        # leaf is the one right after the last chosen leaf.
        self.assertEqual(signer.next_index, 5)
        self.assertEqual(signer.remaining, 3)
        with self.assertRaises(ValueError):
            signer.sign_selected((2,), ("too late",))
        with self.assertRaises(ValueError):
            signer.sign_selected((0,), ("too late",))
        next_signature = signer.sign("c")
        self.assertEqual(next_signature.index, 5)

    def test_starting_above_zero(self):
        signer = make_signer(height=3)
        signer.sign("warm-up")
        signatures = signer.sign_selected((2, 5), ("x", "y"))
        self.assertEqual([s.index for s in signatures], [2, 5])
        self.assertEqual(signer.next_index, 6)

    def test_consecutive_selection_matches_sign_batch_value_for_value(self):
        messages = ("a", b"b", bytearray(b"c"), "d")
        selected = make_signer(height=3).sign_selected((0, 1, 2, 3), messages)
        batched = make_signer(height=3).sign_batch(messages)
        self.assertEqual(selected, batched)
        signer = make_signer(height=3)
        signer.sign_batch(("warm", "up"))
        selected_after = signer.sign_selected((2, 3, 4), ("e", "f", "g"))
        other = make_signer(height=3)
        other.sign_batch(("warm", "up"))
        batched_after = other.sign_batch(("e", "f", "g"))
        self.assertEqual(selected_after, batched_after)

    def test_last_leaf_is_reachable_and_exhausts(self):
        signer = make_signer(height=2)  # 4 leaves
        signatures = signer.sign_selected((3,), ("last",))
        self.assertEqual([s.index for s in signatures], [3])
        self.assertEqual(signer.next_index, 4)
        self.assertEqual(signer.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            signer.sign("more")
        # Structural validation still precedes the exhaustion check.
        with self.assertRaises(ValueError):
            signer.sign_selected((), ("x",))
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected((3,), ("x",))

    def test_accepts_all_message_types(self):
        signer = make_signer(height=3)
        signatures = signer.sign_selected((1, 3, 5), (b"a", bytearray(b"b"), "c"))
        for message, signature in zip((b"a", b"b", b"c"), signatures):
            self.assertTrue(merkle_verify(message, signature, signer.public_key))

    def test_deterministic_value_for_value(self):
        first = make_signer(height=3)
        second = make_signer(height=3)
        self.assertEqual(
            first.sign_selected((0, 4, 7), ("a", "b", "c")),
            second.sign_selected((0, 4, 7), ("a", "b", "c")),
        )


class SignSelectedValidationTest(unittest.TestCase):
    def test_non_tuple_arguments_raise_typeerror(self):
        signer = make_signer(height=2)
        for bad_indices in (None, 42, [0, 1], {0, 1}, "01"):
            with self.subTest(bad=type(bad_indices).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected(bad_indices, ("a", "b"))
        for bad_messages in (None, 42, ["a", "b"], {0: "a"}, "ab"):
            with self.subTest(bad=type(bad_messages).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected((0, 1), bad_messages)

    def test_non_integer_index_members_raise_typeerror(self):
        signer = make_signer(height=2)
        for bad in (("0", "1"), (0, 1.0), (None,), (0, object())):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    signer.sign_selected(bad, tuple("m" for _ in bad))

    def test_unsupported_message_members_raise_typeerror(self):
        signer = make_signer(height=2)
        with self.assertRaises(TypeError):
            signer.sign_selected((0, 1), ("good", 123))
        with self.assertRaises(TypeError):
            signer.sign_selected((0,), (object(),))

    def test_empty_tuples_raise_valueerror(self):
        signer = make_signer(height=2)
        with self.assertRaises(ValueError):
            signer.sign_selected((), ())
        with self.assertRaises(ValueError):
            signer.sign_selected((), ("a",))
        with self.assertRaises(ValueError):
            signer.sign_selected((0,), ())

    def test_length_mismatch_raises_valueerror(self):
        signer = make_signer(height=3)
        with self.assertRaises(ValueError):
            signer.sign_selected((0, 1), ("a",))
        with self.assertRaises(ValueError):
            signer.sign_selected((0,), ("a", "b"))

    def test_boolean_indices_raise_valueerror(self):
        signer = make_signer(height=3)
        with self.assertRaises(ValueError):
            signer.sign_selected((True, 1), ("a", "b"))
        with self.assertRaises(ValueError):
            signer.sign_selected((0, False), ("a", "b"))

    def test_duplicate_or_unordered_indices_raise_valueerror(self):
        signer = make_signer(height=3)
        with self.assertRaises(ValueError):
            signer.sign_selected((1, 1), ("a", "b"))
        with self.assertRaises(ValueError):
            signer.sign_selected((2, 1), ("a", "b"))
        with self.assertRaises(ValueError):
            signer.sign_selected((3, 2, 1), ("a", "b", "c"))

    def test_index_below_next_leaf_raises_valueerror(self):
        signer = make_signer(height=3)
        signer.sign_batch(("a", "b", "c"))  # next_index == 3
        with self.assertRaises(ValueError):
            signer.sign_selected((2, 4), ("old", "new"))
        with self.assertRaises(ValueError):
            signer.sign_selected((0,), ("old",))
        # The rejected calls voided nothing.
        self.assertEqual(signer.next_index, 3)

    def test_index_past_last_leaf_raises_valueerror(self):
        signer = make_signer(height=2)  # leaves 0..3
        with self.assertRaises(ValueError):
            signer.sign_selected((4,), ("past",))
        with self.assertRaises(ValueError):
            signer.sign_selected((0, 4), ("ok", "past"))
        self.assertEqual(signer.next_index, 0)

    def test_exhausted_signer_raises_key_exhausted(self):
        signer = make_signer(height=2)
        signer.advance_to(4)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected((3,), ("late",))
        # Structural validation precedes the exhaustion check.
        with self.assertRaises(TypeError):
            signer.sign_selected("not a tuple", ())
        with self.assertRaises(ValueError):
            signer.sign_selected((), ())
        # But a structurally valid, in-range-looking request reports exhaustion.
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected((0,), ("late",))

    def test_validation_order_type_structure_then_exhaustion_then_range(self):
        signer = make_signer(height=1)  # leaves 0, 1
        signer.advance_to(2)
        # Bad message type still raises TypeError on an exhausted signer.
        with self.assertRaises(TypeError):
            signer.sign_selected((0,), (123,))
        # Empty selection still raises ValueError on an exhausted signer.
        with self.assertRaises(ValueError):
            signer.sign_selected((), ())
        # A fresh signer: an out-of-range index is reported as ValueError,
        # never as KeyExhaustedError, because leaves remain.
        fresh = make_signer(height=1)
        with self.assertRaises(ValueError):
            fresh.sign_selected((2,), ("x",))
        with self.assertRaises(ValueError):
            fresh.sign_selected((-1,), ("x",))

    def test_failure_consumes_no_leaf(self):
        signer = make_signer(height=3)
        for bad_indices, bad_messages in (
            ((1, 1), ("a", "b")),
            ((8,), ("ok",)),
            ((0, 1), ("only-one",)),
        ):
            with self.assertRaises(ValueError):
                signer.sign_selected(bad_indices, bad_messages)
        with self.assertRaises(TypeError):
            signer.sign_selected((0, 1), ("a", 2))
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("first").index, 0)


class SignSelectedProofTest(unittest.TestCase):
    def test_multiproof_verifies_messages_and_binds_selection(self):
        signer = make_signer(height=3)
        indices = (1, 2, 5)
        messages = ("m1", b"m2", bytearray(b"m5"))
        signatures = signer.sign_selected(indices, messages)
        proof = multiproof_encode(signer.public_key, signatures)
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertTrue(
            multiproof_verify_bound(
                messages, proof, public_key=signer.public_key, indices=indices
            )
        )
        # The same proof does not bind to a different leaf selection.
        self.assertFalse(
            multiproof_verify_bound(
                messages, proof, public_key=signer.public_key, indices=(0, 2, 5)
            )
        )
        # A swapped message fails verification.
        self.assertFalse(multiproof_verify(("m2", "m1", b"m5"), proof))

    def test_consecutive_selection_multiproof_matches_batch(self):
        messages = ("a", "b", "c", "d")
        selected = make_signer(height=3).sign_selected((0, 1, 2, 3), messages)
        batched = make_signer(height=3).sign_batch(messages)
        self.assertEqual(
            multiproof_encode(make_signer(height=3).public_key, selected),
            multiproof_encode(make_signer(height=3).public_key, batched),
        )


class SignSelectedCheckpointTest(unittest.TestCase):
    def test_checkpoint_resumes_after_last_selected_leaf(self):
        signer = make_signer(height=3)
        signer.sign_selected((1, 4), ("a", "b"))
        blob = signer.checkpoint()
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 5)
        # Skipped leaves stay voided after restore.
        with self.assertRaises(ValueError):
            restored.sign_selected((2,), ("old",))
        signature = restored.sign("d")
        self.assertEqual(signature.index, 5)
        self.assertTrue(merkle_verify("d", signature, restored.public_key))

    def test_checkpoint_bytes_unchanged_format(self):
        signer = make_signer(height=2)
        signer.sign_selected((0, 2), ("a", "b"))
        other = make_signer(height=2)
        other.advance_to(3)
        self.assertEqual(signer.checkpoint(), other.checkpoint())


class SignSelectedConcurrencyTest(unittest.TestCase):
    def test_concurrent_selections_never_share_a_leaf(self):
        height = 4
        signer = make_signer(height=height)
        leaf_count = 1 << height
        picked = []
        errors = []
        list_lock = threading.Lock()
        barrier = threading.Barrier(4)

        def worker(offset):
            try:
                # Four disjoint gapped selections that together cover all 16
                # leaves: each worker takes its residue class modulo 4.
                indices = tuple(range(offset, leaf_count, 4))
                messages = tuple(f"w{offset}-{i}" for i in indices)
                barrier.wait(timeout=10)
                signatures = signer.sign_selected(indices, messages)
                with list_lock:
                    picked.extend(s.index for s in signatures)
            except Exception as exc:  # pragma: no cover - failure path
                with list_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # The selections overlap (each worker's first index is below another
        # worker's last), so exactly one must win and the rest be rejected
        # without any leaf being signed twice.
        self.assertGreaterEqual(len(errors), 3)
        winner_picked = sorted(picked)
        self.assertEqual(winner_picked, sorted(set(winner_picked)))
        self.assertTrue(all(0 <= index < leaf_count for index in winner_picked))
        # Every index up to the winner's last one is now spent or voided.
        self.assertEqual(signer.next_index, max(winner_picked) + 1)
        remaining = list(range(signer.next_index, leaf_count))
        if remaining:
            follow_up = signer.sign_selected(
                tuple(remaining), tuple(f"f{i}" for i in remaining)
            )
            self.assertEqual([s.index for s in follow_up], remaining)
        else:
            self.assertEqual(signer.remaining, 0)
            with self.assertRaises(KeyExhaustedError):
                signer.sign("late")

    def test_concurrent_sign_and_selected_never_overlap(self):
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
                signer.sign_selected((0, 2, 4, 6), tuple("sxyzwvut"[:4]))
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
        self.assertEqual(signer.remaining, 0)


if __name__ == "__main__":
    unittest.main()

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


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=3, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


class SignSelectedBasicsTest(unittest.TestCase):
    def test_gap_selection_signs_chosen_leaves_and_voids_gaps(self):
        signer = make_signer()
        messages = ("a", b"b", bytearray(b"c"))
        signatures = signer.sign_selected((1, 3, 4), messages)
        self.assertEqual(len(signatures), 3)
        self.assertEqual(tuple(signature.index for signature in signatures), (1, 3, 4))
        for message, signature in zip(messages, signatures):
            self.assertTrue(merkle_verify(message, signature, signer.public_key))
        # Leaves 0 and 2 were skipped: they are spent/voided and the next
        # available leaf is the one after the last selected leaf.
        self.assertEqual(signer.next_index, 5)
        self.assertEqual(signer.remaining, 3)

    def test_consecutive_selection_equals_sign_batch_value_for_value(self):
        messages = ("m0", "m1", "m2")
        selected = make_signer()
        batch = make_signer()
        signatures = selected.sign_selected((0, 1, 2), messages)
        expected = batch.sign_batch(messages)
        self.assertEqual(signatures, expected)
        self.assertEqual(selected.next_index, batch.next_index)

    def test_consecutive_selection_after_prior_spend(self):
        messages = ("x", "y")
        selected = make_signer()
        batch = make_signer()
        selected.sign("warmup")
        batch.sign("warmup")
        signatures = selected.sign_selected((1, 2), messages)
        expected = batch.sign_batch(messages)
        self.assertEqual(signatures, expected)
        self.assertEqual(selected.next_index, 3)

    def test_returns_a_tuple(self):
        signer = make_signer()
        result = signer.sign_selected((0,), ("only",))
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 1)

    def test_each_signature_bound_to_its_leaf_encoding_round_trips(self):
        signer = make_signer()
        signatures = signer.sign_selected((0, 2, 5), ("p", "q", "r"))
        for message, signature in zip(("p", "q", "r"), signatures):
            blob = signature.to_bytes(signer.public_key)
            from pqattest import MerkleSignature

            restored = MerkleSignature.from_bytes(blob, signer.public_key)
            self.assertEqual(restored, signature)
            self.assertTrue(merkle_verify(message, restored, signer.public_key))

    def test_single_selected_leaf_advances_past_gaps(self):
        signer = make_signer()
        (signature,) = signer.sign_selected((6,), ("late",))
        self.assertEqual(signature.index, 6)
        self.assertEqual(signer.next_index, 7)
        # Every lower leaf is voided now.
        with self.assertRaises(ValueError):
            signer.sign_selected((6,), ("again",))
        (last,) = signer.sign_selected((7,), ("finish",))
        self.assertEqual(last.index, 7)
        self.assertEqual(signer.next_index, 8)

    def test_str_bytes_bytearray_messages(self):
        signer = make_signer()
        signatures = signer.sign_selected((0, 1, 2), ("s", b"b", bytearray(b"c")))
        self.assertEqual(len(signatures), 3)
        self.assertTrue(merkle_verify("s", signatures[0], signer.public_key))
        self.assertTrue(merkle_verify(b"b", signatures[1], signer.public_key))
        self.assertTrue(merkle_verify(b"c", signatures[2], signer.public_key))


class SignSelectedMultiproofTest(unittest.TestCase):
    def test_multiproof_over_selection_verifies_and_binds(self):
        signer = make_signer()
        indices = (1, 3, 6)
        messages = ("one", "two", "three")
        signatures = signer.sign_selected(indices, messages)
        proof = multiproof_encode(signer.public_key, signatures)
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertTrue(
            multiproof_verify_bound(
                messages, proof, public_key=signer.public_key, indices=indices
            )
        )
        # The bound check fails for any other selection.
        self.assertFalse(
            multiproof_verify_bound(
                messages, proof, public_key=signer.public_key, indices=(0, 3, 6)
            )
        )
        self.assertFalse(
            multiproof_verify_bound(
                ("one", "two", "x"),
                proof,
                public_key=signer.public_key,
                indices=indices,
            )
        )
        # Without an indices argument the same proof still verifies.
        self.assertTrue(
            multiproof_verify_bound(messages, proof, public_key=signer.public_key)
        )

    def test_batch_proof_over_gap_selection_verifies(self):
        signer = make_signer()
        indices = (2, 4, 7)
        messages = ("a", "b", "c")
        signatures = signer.sign_selected(indices, messages)
        batch = MerkleBatchProof(public_key=signer.public_key, signatures=signatures)
        self.assertTrue(batch.verify(messages))
        self.assertTrue(
            batch.verify_bound(
                messages, public_key=signer.public_key, indices=indices
            )
        )

    def test_multiproof_consecutive_matches_batch_output(self):
        messages = ("m0", "m1", "m2")
        selected_signer = make_signer()
        batch_signer = make_signer()
        selected_sigs = selected_signer.sign_selected((0, 1, 2), messages)
        batch_sigs = batch_signer.sign_batch(messages)
        self.assertEqual(
            multiproof_encode(selected_signer.public_key, selected_sigs),
            multiproof_encode(batch_signer.public_key, batch_sigs),
        )


class SignSelectedCheckpointTest(unittest.TestCase):
    def checkpoint_provider(self, w=4, height=3):
        return make_signer(height=height, w=w)

    def test_checkpoint_resume_after_gap_signing(self):
        signer = make_signer()
        signer.sign_selected((1, 3), ("a", "b"))
        blob = signer.checkpoint()
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 4)
        signatures = restored.sign_batch(("c", "d"))
        self.assertEqual(tuple(s.index for s in signatures), (4, 5))

    def test_signing_then_checkpoint_advances_one_commit(self):
        signer = make_signer()
        signatures = signer.sign_selected((0, 2, 7), ("a", "b", "c"))
        blob = signer.checkpoint()
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.next_index, 8)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("d")
        for message, signature in zip(("a", "b", "c"), signatures):
            self.assertTrue(merkle_verify(message, signature, restored.public_key))

    def test_failed_call_checkpoint_shows_no_advance(self):
        signer = make_signer()
        blob_before = signer.checkpoint()
        with self.assertRaises(ValueError):
            signer.sign_selected((0, 0), ("ok", "dup"))
        self.assertEqual(signer.checkpoint(), blob_before)

    def test_last_leaf_selected_then_restored_exhausted(self):
        signer = make_signer(height=2)
        signer.sign_selected((3,), ("last",))
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign_selected((3,), ("again",))
        # The structural checks run first even when exhausted.
        with self.assertRaises(TypeError):
            restored.sign_selected((3,), "not-a-tuple")
        with self.assertRaises(ValueError):
            restored.sign_selected((), ())


class SignSelectedValidationOrderTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()

    # -- TypeError: container types --------------------------------------
    def test_indices_must_be_tuple(self):
        with self.assertRaises(TypeError):
            self.signer.sign_selected([0, 1], ("a", "b"))
        with self.assertRaises(TypeError):
            self.signer.sign_selected(b"\x00\x01", ("a", "b"))

    def test_messages_must_be_tuple(self):
        with self.assertRaises(TypeError):
            self.signer.sign_selected((0, 1), ["a", "b"])
        with self.assertRaises(TypeError):
            self.signer.sign_selected((0,), "a")

    def test_index_members_must_be_integer(self):
        with self.assertRaises(TypeError):
            self.signer.sign_selected((0, "1"), ("a", "b"))
        with self.assertRaises(TypeError):
            self.signer.sign_selected((0, 1.0), ("a", "b"))
        with self.assertRaises(TypeError):
            self.signer.sign_selected((None,), ("a",))

    def test_unsupported_message_type(self):
        with self.assertRaises(TypeError):
            self.signer.sign_selected((0, 1), ("ok", 7))
        with self.assertRaises(TypeError):
            self.signer.sign_selected((0,), (None,))

    # -- ValueError: structure --------------------------------------------
    def test_empty_tuples_value_error(self):
        with self.assertRaises(ValueError):
            self.signer.sign_selected((), ())
        with self.assertRaises(ValueError):
            self.signer.sign_selected((), ("a",))
        with self.assertRaises(ValueError):
            self.signer.sign_selected((0,), ())

    def test_length_mismatch_value_error(self):
        with self.assertRaises(ValueError):
            self.signer.sign_selected((0, 1), ("a",))
        with self.assertRaises(ValueError):
            self.signer.sign_selected((0,), ("a", "b"))

    def test_boolean_index_value_error(self):
        with self.assertRaises(ValueError):
            self.signer.sign_selected((True,), ("a",))
        with self.assertRaises(ValueError):
            self.signer.sign_selected((0, False), ("a", "b"))

    def test_duplicate_indices_value_error(self):
        with self.assertRaises(ValueError):
            self.signer.sign_selected((1, 1), ("a", "b"))

    def test_out_of_order_indices_value_error(self):
        with self.assertRaises(ValueError):
            self.signer.sign_selected((2, 1), ("a", "b"))

    # -- exhaustion before range ------------------------------------------
    def test_exhausted_routes_structural_failures_first(self):
        signer = make_signer(height=1)
        signer.sign_selected((1,), ("x",))
        self.assertEqual(signer.remaining, 0)
        # Structural problems still beat exhaustion.
        with self.assertRaises(TypeError):
            signer.sign_selected("no", ("a",))
        with self.assertRaises(ValueError):
            signer.sign_selected((), ())
        # Well-formed and in nominal range, but the signer is exhausted.
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected((0,), ("a",))
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected((1,), ("a",))

    def test_exhausted_via_advance_to(self):
        signer = make_signer(height=2)
        signer.advance_to(4)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected((0,), ("a",))

    # -- range checked last -----------------------------------------------
    def test_index_below_next_index(self):
        self.signer.sign_selected((2,), ("a",))
        self.assertEqual(self.signer.next_index, 3)
        with self.assertRaises(ValueError):
            self.signer.sign_selected((2,), ("b",))
        with self.assertRaises(ValueError):
            self.signer.sign_selected((0,), ("b",))
        with self.assertRaises(ValueError):
            self.signer.sign_selected((2, 5), ("b", "c"))
        # A strictly increasing tuple whose first member is at or above the
        # frontier cannot hide a stale member; the first-index check is the
        # range gate, and it still rejects below-frontier starts.
        with self.assertRaises(ValueError):
            self.signer.sign_selected((1, 7), ("b", "c"))

    def test_index_past_last_leaf(self):
        with self.assertRaises(ValueError):
            self.signer.sign_selected((8,), ("a",))
        with self.assertRaises(ValueError):
            self.signer.sign_selected((0, 8), ("a", "b"))
        with self.assertRaises(ValueError):
            self.signer.sign_selected((-1,), ("a",))

    def test_partial_overhang_not_exhaustion(self):
        # Current index 0, 8 leaves exist: a well-formed selection whose
        # first index is available but whose tail runs past the tree is a
        # range ValueError, not exhaustion.
        with self.assertRaises(ValueError):
            self.signer.sign_selected((6, 7, 8), ("a", "b", "c"))
        self.assertEqual(self.signer.next_index, 0)

    def test_negative_index_value_error(self):
        with self.assertRaises(ValueError):
            self.signer.sign_selected((-1, 0), ("a", "b"))


class SignSelectedAllOrNothingTest(unittest.TestCase):
    def test_failure_consumes_no_leaf(self):
        signer = make_signer()
        with self.assertRaises(TypeError):
            signer.sign_selected((0, 1, 2), ("a", "b", 9))
        self.assertEqual(signer.next_index, 0)
        # Leaf 0 must still carry the freshly signed message.
        signature = signer.sign("first")
        self.assertEqual(signature.index, 0)
        self.assertTrue(merkle_verify("first", signature, signer.public_key))

    def test_duplicate_selection_consumes_no_leaf(self):
        signer = make_signer()
        with self.assertRaises(ValueError):
            signer.sign_selected((0, 0), ("a", "b"))
        self.assertEqual(signer.next_index, 0)

    def test_range_failure_consumes_no_leaf(self):
        signer = make_signer()
        signer.sign("done")
        before = signer.checkpoint()
        with self.assertRaises(ValueError):
            signer.sign_selected((1, 9), ("a", "b"))
        self.assertEqual(signer.checkpoint(), before)
        self.assertEqual(signer.next_index, 1)

    def test_no_partial_results_observable(self):
        signer = make_signer()
        try:
            signer.sign_selected((0, 1, 2), ("a", "b", object()))
        except TypeError:
            pass
        self.assertEqual(signer.next_index, 0)

    def test_deterministic_no_randomness(self):
        first = make_signer()
        second = make_signer()
        s1 = first.sign_selected((1, 3, 5), ("a", "b", "c"))
        s2 = second.sign_selected((1, 3, 5), ("a", "b", "c"))
        self.assertEqual(s1, s2)
        self.assertEqual(first.checkpoint(), second.checkpoint())


class SignSelectedConcurrencyTest(unittest.TestCase):
    def test_concurrent_single_leaves_never_double_allocate(self):
        # The scheduling order is deliberately unconstrained: whichever
        # selection wins the lock may void lower leaves, so losing threads
        # fail with ValueError (their leaf is below the new frontier) or,
        # when the winner reaches the top, KeyExhaustedError. The invariant
        # is that every *successful* allocation is a distinct leaf.
        height = 4
        signer = make_signer(height=height)
        leaf_count = 1 << height
        errors = []
        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(leaf_count)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                message = f"m{i}"
                (signature,) = signer.sign_selected((i,), (message,))
                with lock:
                    results.append((signature, message))
            except (KeyExhaustedError, ValueError) as exc:
                with lock:
                    errors.append((i, type(exc).__name__))

        threads = [
            threading.Thread(target=worker, args=(i,)) for i in range(leaf_count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        allocated = [signature.index for signature, _ in results]
        self.assertEqual(len(allocated), len(set(allocated)))
        for signature, message in results:
            self.assertTrue(merkle_verify(message, signature, signer.public_key))
            self.assertLess(signature.index, signer.next_index)
        # Successes plus failures cover every attempt, and the final state
        # restores cleanly through the existing checkpoint format.
        self.assertEqual(len(results) + len(errors), leaf_count)
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        self.assertEqual(restored.next_index, signer.next_index)

    def test_concurrent_batches_either_whole_or_rejected(self):
        signer = make_signer(height=3)
        barrier = threading.Barrier(2)
        outcomes = []
        lock = threading.Lock()

        def run(selection, messages):
            try:
                barrier.wait(timeout=10)
                signatures = signer.sign_selected(selection, messages)
                with lock:
                    outcomes.append(
                        ("ok", tuple(s.index for s in signatures))
                    )
            except ValueError as exc:
                with lock:
                    outcomes.append(("value", str(exc)))

        # Overlapping selections: exactly one can win.
        t1 = threading.Thread(target=run, args=((0, 2, 4), ("a", "b", "c")))
        t2 = threading.Thread(target=run, args=((0, 3, 6), ("d", "e", "f")))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        statuses = sorted(outcome[0] for outcome in outcomes)
        self.assertEqual(statuses, ["ok", "value"])
        # No matter who won, next_index is the winner's last leaf + 1 and
        # no leaf got signed twice.
        winner = next(outcome for outcome in outcomes if outcome[0] == "ok")
        self.assertEqual(signer.next_index, winner[1][-1] + 1)
        self.assertLessEqual(signer.next_index, 8)


if __name__ == "__main__":
    unittest.main()

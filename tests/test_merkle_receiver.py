"""Tests for MerkleReceiver: per-instance receiver-side leaf deduplication.

A receiver is bound to one expected MerklePublicKey and accepts a
MerkleBatchProof or a v1 multiproof (bytes/bytearray) through
``accept(messages, proof, *, context=None, contexts=None)``: the proof is
verified in full and bound to the expected key by value, and only a batch
whose leaves are all unrecorded is accepted and recorded atomically. The
record lives only inside the instance.
"""

from __future__ import annotations

import threading
import unittest

from pqattest import (
    MerkleBatchProof,
    MerklePublicKey,
    MerkleReceiver,
    MerkleSigner,
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


def make_batch_proof(signer, indices, messages, **kwargs):
    signatures = signer.sign_selected(tuple(indices), tuple(messages), **kwargs)
    return MerkleBatchProof(public_key=signer.public_key, signatures=signatures)


def corrupted_key(**overrides):
    key = MerklePublicKey(w=4, height=2, root=b"\x11" * 32)
    for field, value in overrides.items():
        object.__setattr__(key, field, value)
    return key


class ReceiverConstructionTest(unittest.TestCase):
    def test_public_key_and_empty_record(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        self.assertIs(receiver.public_key, signer.public_key)
        self.assertEqual(receiver.accepted_indices, ())

    def test_wrong_key_type_rejected(self):
        for bad in (None, 4, "key", b"\x00" * 43, (4, 2, b"\x00" * 32), object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    MerkleReceiver(bad)

    def test_corrupted_key_fields_rejected(self):
        for overrides in (
            {"w": 2},
            {"w": True},
            {"w": "4"},
            {"height": 0},
            {"height": 9},
            {"height": True},
            {"root": b"\x00" * 31},
            {"root": b"\x00" * 33},
            {"root": bytearray(32)},
            {"root": None},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    MerkleReceiver(corrupted_key(**overrides))

    def test_properties_read_only(self):
        receiver = MerkleReceiver(make_signer().public_key)
        with self.assertRaises(AttributeError):
            receiver.public_key = receiver.public_key
        with self.assertRaises(AttributeError):
            receiver.accepted_indices = ()


class ReceiverAcceptTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.receiver = MerkleReceiver(self.signer.public_key)

    def test_accept_batch_proof_records_indices(self):
        batch = make_batch_proof(self.signer, (0, 1, 2), ("a", "b", "c"))
        self.assertTrue(self.receiver.accept(("a", "b", "c"), batch))
        self.assertEqual(self.receiver.accepted_indices, (0, 1, 2))

    def test_accept_multiproof_bytes_and_bytearray(self):
        batch = make_batch_proof(self.signer, (0, 1), ("a", "b"))
        data = multiproof_encode(batch.public_key, batch.signatures)
        self.assertTrue(self.receiver.accept(("a", "b"), data))
        self.assertEqual(self.receiver.accepted_indices, (0, 1))
        other = MerkleReceiver(self.signer.public_key)
        self.assertTrue(other.accept(("a", "b"), bytearray(data)))
        self.assertEqual(other.accepted_indices, (0, 1))

    def test_resubmission_rejected_even_identical(self):
        batch = make_batch_proof(self.signer, (0, 1), ("a", "b"))
        self.assertTrue(self.receiver.accept(("a", "b"), batch))
        snapshot = self.receiver.accepted_indices
        self.assertFalse(self.receiver.accept(("a", "b"), batch))
        self.assertEqual(self.receiver.accepted_indices, snapshot)

    def test_formats_share_one_record(self):
        batch = make_batch_proof(self.signer, (0, 1), ("a", "b"))
        data = multiproof_encode(batch.public_key, batch.signatures)
        self.assertTrue(self.receiver.accept(("a", "b"), batch))
        self.assertFalse(self.receiver.accept(("a", "b"), data))
        other = MerkleReceiver(self.signer.public_key)
        self.assertTrue(other.accept(("a", "b"), data))
        self.assertFalse(other.accept(("a", "b"), batch))

    def test_same_message_on_different_leaves_accepted(self):
        first = make_batch_proof(self.signer, (0,), ("same",))
        second = make_batch_proof(self.signer, (1,), ("same",))
        self.assertTrue(self.receiver.accept(("same",), first))
        self.assertTrue(self.receiver.accept(("same",), second))
        self.assertEqual(self.receiver.accepted_indices, (0, 1))

    def test_high_index_first_does_not_block_lower(self):
        high = make_batch_proof(self.signer, (5, 6), ("e", "f"))
        self.assertTrue(self.receiver.accept(("e", "f"), high))
        self.assertEqual(self.receiver.accepted_indices, (5, 6))
        # The signer's own next_index has moved past leaf 2, so the lower
        # batch is produced by a twin signer over the identical tree.
        twin = make_signer(height=3)
        low = make_batch_proof(twin, (2,), ("c",))
        self.assertTrue(self.receiver.accept(("c",), low))
        self.assertEqual(self.receiver.accepted_indices, (2, 5, 6))

    def test_mixed_old_and_new_leaves_fail_atomically(self):
        first = make_batch_proof(self.signer, (0, 1, 2), ("a", "b", "c"))
        self.assertTrue(self.receiver.accept(("a", "b", "c"), first))
        # Leaves 2 (recorded) and 3 (fresh) in one batch: rejected as a whole.
        twin = make_signer(height=3)
        mixed = make_batch_proof(twin, (2, 3), ("c", "d"))
        self.assertFalse(self.receiver.accept(("c", "d"), mixed))
        self.assertEqual(self.receiver.accepted_indices, (0, 1, 2))
        # The fresh leaf remains acceptable in a later, separate proof.
        fresh = make_batch_proof(self.signer, (3,), ("d",))
        self.assertTrue(self.receiver.accept(("d",), fresh))
        self.assertEqual(self.receiver.accepted_indices, (0, 1, 2, 3))

    def test_snapshot_is_stable(self):
        batch = make_batch_proof(self.signer, (0,), ("a",))
        self.assertTrue(self.receiver.accept(("a",), batch))
        snapshot = self.receiver.accepted_indices
        self.assertEqual(snapshot, (0,))
        more = make_batch_proof(self.signer, (1, 2), ("b", "c"))
        self.assertTrue(self.receiver.accept(("b", "c"), more))
        self.assertEqual(snapshot, (0,))
        self.assertEqual(self.receiver.accepted_indices, (0, 1, 2))

    def test_new_instance_starts_empty(self):
        batch = make_batch_proof(self.signer, (0,), ("a",))
        self.assertTrue(self.receiver.accept(("a",), batch))
        fresh = MerkleReceiver(self.signer.public_key)
        self.assertEqual(fresh.accepted_indices, ())
        self.assertTrue(fresh.accept(("a",), batch))


class ReceiverArgumentTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.receiver = MerkleReceiver(self.signer.public_key)
        self.batch = make_batch_proof(self.signer, (0, 1), ("a", "b"))
        self.data = multiproof_encode(self.batch.public_key, self.batch.signatures)

    def test_wrong_proof_type_rejected(self):
        for bad in (None, 7, "proof", self.batch.public_key, self.batch.signatures):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    self.receiver.accept(("a", "b"), bad)

    def test_proof_type_checked_before_context_conflict(self):
        with self.assertRaises(TypeError):
            self.receiver.accept(("a", "b"), None, context="x", contexts=("y", "y"))

    def test_bad_context_type_rejected(self):
        for bad in (7, 3.5, object(), ["x"], {"x": 1}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    self.receiver.accept(("a", "b"), self.batch, context=bad)

    def test_bad_contexts_type_rejected(self):
        for bad in (["x", "y"], "xy", (7, "y"), (object(), None)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    self.receiver.accept(("a", "b"), self.batch, contexts=bad)

    def test_contexts_with_non_empty_context_rejected(self):
        with self.assertRaises(ValueError):
            self.receiver.accept(("a", "b"), self.batch, context="x", contexts=("y", "y"))
        with self.assertRaises(ValueError):
            self.receiver.accept(("a", "b"), self.data, context="x", contexts=("y", "y"))

    def test_context_checks_precede_verification(self):
        # A bad context type raises even when the proof bytes are garbage.
        with self.assertRaises(TypeError):
            self.receiver.accept(("a", "b"), b"garbage", context=object())
        # And the contexts/context conflict raises before verification too.
        with self.assertRaises(ValueError):
            self.receiver.accept(("a", "b"), b"garbage", context="x", contexts=("y", "y"))

    def test_failed_argument_checks_do_not_record(self):
        for call in (
            lambda: self.receiver.accept(("a", "b"), self.batch, context=object()),
            lambda: self.receiver.accept(
                ("a", "b"), self.batch, context="x", contexts=("y", "y")
            ),
        ):
            with self.assertRaises((TypeError, ValueError)):
                call()
        self.assertEqual(self.receiver.accepted_indices, ())


class ReceiverFailureTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.receiver = MerkleReceiver(self.signer.public_key)
        self.batch = make_batch_proof(self.signer, (0, 1), ("a", "b"))
        self.data = multiproof_encode(self.batch.public_key, self.batch.signatures)

    def assert_rejected(self, messages, proof, **kwargs):
        self.assertFalse(self.receiver.accept(messages, proof, **kwargs))
        self.assertEqual(self.receiver.accepted_indices, ())

    def test_non_tuple_messages(self):
        self.assert_rejected(["a", "b"], self.batch)
        self.assert_rejected("ab", self.data)

    def test_message_count_mismatch(self):
        self.assert_rejected(("a",), self.batch)
        self.assert_rejected(("a", "b", "c"), self.batch)
        self.assert_rejected((), self.batch)
        self.assert_rejected(("a",), self.data)

    def test_contexts_count_mismatch(self):
        self.assert_rejected(("a", "b"), self.batch, contexts=("x",))
        self.assert_rejected(("a", "b"), self.data, contexts=("x", "y", "z"))

    def test_illegal_message_member(self):
        self.assert_rejected(("a", 7), self.batch)
        self.assert_rejected(("a", None), self.data)

    def test_corrupted_multiproof_encoding(self):
        for bad in (
            b"",
            b"\x00" * 17,
            self.data[: len(self.data) - 1],
            self.data + b"\x00",
            b"X" + self.data[1:],
            self.data[:8] + b"\x02" + self.data[9:],
            self.data[:-33] + bytes([self.data[-33] ^ 1]) + self.data[-32:],
        ):
            with self.subTest(bad=bad[:12]):
                self.assert_rejected(("a", "b"), bad)

    def test_batch_proof_bytes_are_not_a_multiproof(self):
        # The batch wire format is not accepted as multiproof bytes.
        self.assert_rejected(("a", "b"), self.batch.to_bytes())

    def test_wrong_expected_key(self):
        other = MerkleReceiver(make_signer(height=3, start=1000).public_key)
        self.assertFalse(other.accept(("a", "b"), self.batch))
        self.assertFalse(other.accept(("a", "b"), self.data))
        self.assertEqual(other.accepted_indices, ())

    def test_different_height_key(self):
        other = MerkleReceiver(make_signer(height=4, start=2000).public_key)
        self.assertFalse(other.accept(("a", "b"), self.batch))
        self.assertEqual(other.accepted_indices, ())

    def test_wrong_message(self):
        self.assert_rejected(("a", "B"), self.batch)
        self.assert_rejected(("a", "B"), self.data)

    def test_wrong_context(self):
        self.assert_rejected(("a", "b"), self.batch, context="nope")
        self.assert_rejected(("a", "b"), self.data, contexts=(None, "nope"))

    def test_failures_do_not_record_partially(self):
        # A batch whose first leaf would verify but second fails records nothing.
        self.assertFalse(self.receiver.accept(("a", "B"), self.batch))
        self.assertEqual(self.receiver.accepted_indices, ())
        self.assertTrue(self.receiver.accept(("a", "b"), self.batch))
        self.assertEqual(self.receiver.accepted_indices, (0, 1))


class ReceiverContextTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.receiver = MerkleReceiver(self.signer.public_key)

    def test_shared_context_roundtrip(self):
        batch = make_batch_proof(self.signer, (0, 1), ("a", "b"), context="ctx")
        self.assertFalse(self.receiver.accept(("a", "b"), batch))
        self.assertFalse(self.receiver.accept(("a", "b"), batch, context="other"))
        self.assertTrue(self.receiver.accept(("a", "b"), batch, context="ctx"))
        self.assertEqual(self.receiver.accepted_indices, (0, 1))

    def test_per_leaf_contexts_roundtrip(self):
        contexts = ("c0", None)
        batch = make_batch_proof(self.signer, (0, 1), ("a", "b"), contexts=contexts)
        data = multiproof_encode(batch.public_key, batch.signatures)
        self.assertFalse(self.receiver.accept(("a", "b"), batch, contexts=("c0", "x")))
        self.assertTrue(self.receiver.accept(("a", "b"), batch, contexts=contexts))
        self.assertEqual(self.receiver.accepted_indices, (0, 1))
        other = MerkleReceiver(self.signer.public_key)
        self.assertTrue(other.accept(("a", "b"), data, contexts=(b"c0", b"")))
        self.assertEqual(other.accepted_indices, (0, 1))

    def test_str_context_utf8(self):
        batch = make_batch_proof(self.signer, (0,), ("héllo",), context="ctx")
        self.assertTrue(self.receiver.accept(("héllo",), batch, context="ctx"))


class ReceiverConcurrencyTest(unittest.TestCase):
    def test_overlapping_batches_at_most_one_success(self):
        signer = make_signer(height=4)
        receiver = MerkleReceiver(signer.public_key)
        # Two batches overlapping on leaf 2, plus one disjoint batch. The
        # second and third come from a twin signer over the identical tree
        # because the first signer's next_index has moved on.
        batch_a = make_batch_proof(signer, (0, 1, 2), ("a0", "a1", "a2"))
        twin = make_signer(height=4)
        batch_b = make_batch_proof(twin, (2, 3, 4), ("a2", "b3", "b4"))
        batch_c = make_batch_proof(twin, (5, 6), ("c5", "c6"))

        submissions = [
            (("a0", "a1", "a2"), batch_a),
            (("a2", "b3", "b4"), batch_b),
            (("c5", "c6"), batch_c),
        ]
        results = {}
        snapshots = []
        barrier = threading.Barrier(2 * len(submissions))

        def run(name, messages, proof):
            barrier.wait()
            results[name] = receiver.accept(messages, proof)

        def watch():
            barrier.wait()
            for _ in range(20):
                snapshots.append(receiver.accepted_indices)

        threads = [
            threading.Thread(target=run, args=(f"sub{i}", messages, proof))
            for i, (messages, proof) in enumerate(submissions)
        ] + [threading.Thread(target=watch) for _ in submissions]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # The overlapping batches (0,1,2) and (2,3,4) conflict on leaf 2:
        # at most one of them succeeded. The disjoint batch (5,6) succeeded.
        overlap_wins = [name for name in ("sub0", "sub1") if results[name]]
        self.assertLessEqual(len(overlap_wins), 1)
        self.assertTrue(results["sub2"])
        # The final record is the disjoint batch plus at most one of the
        # overlapping batches.
        final = receiver.accepted_indices
        self.assertTrue({5, 6} <= set(final))
        self.assertIn(set(final) - {5, 6}, (set(), {0, 1, 2}, {2, 3, 4}))
        # Every snapshot is ascending, a subset of the final record, and
        # never shows half of an accepted batch.
        batches = [frozenset((0, 1, 2)), frozenset((2, 3, 4)), frozenset((5, 6))]
        for snapshot in snapshots:
            self.assertEqual(tuple(sorted(snapshot)), snapshot)
            self.assertTrue(set(snapshot) <= set(final))
            for batch in batches:
                intersection = set(snapshot) & batch
                self.assertIn(intersection, (set(), batch & set(final)))


class ReceiverCoverageTest(unittest.TestCase):
    def test_all_heights_and_both_w(self):
        for w in (4, 8):
            for height in (1, 2, 3, 4):
                with self.subTest(w=w, height=height):
                    signer = make_signer(height=height, w=w, start=height * 100 + w)
                    receiver = MerkleReceiver(signer.public_key)
                    last = (1 << height) - 1
                    indices = (0, last) if last else (0,)
                    messages = tuple(f"m{i}" for i in indices)
                    batch = make_batch_proof(signer, indices, messages)
                    data = multiproof_encode(batch.public_key, batch.signatures)
                    self.assertTrue(receiver.accept(messages, data))
                    self.assertEqual(receiver.accepted_indices, tuple(sorted(indices)))
                    self.assertFalse(receiver.accept(messages, batch))

    def test_taller_heights(self):
        for height in (5, 6, 7, 8):
            with self.subTest(height=height):
                signer = make_signer(height=height, start=height)
                receiver = MerkleReceiver(signer.public_key)
                batch = make_batch_proof(signer, (0, 1), ("a", "b"))
                self.assertTrue(receiver.accept(("a", "b"), batch))
                self.assertEqual(receiver.accepted_indices, (0, 1))

    def test_stateless_verify_still_reusable(self):
        # Recording on the receiver consumes nothing: the same proof still
        # verifies through the existing stateless entries, and neither the
        # inputs nor the signer state are modified.
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        batch = make_batch_proof(signer, (0, 1), ("a", "b"))
        data = multiproof_encode(batch.public_key, batch.signatures)
        self.assertTrue(receiver.accept(("a", "b"), batch))
        self.assertTrue(batch.verify(("a", "b")))
        self.assertTrue(batch.verify_bound(("a", "b"), public_key=signer.public_key))
        self.assertTrue(multiproof_verify(("a", "b"), data))
        self.assertTrue(
            multiproof_verify_bound(("a", "b"), data, public_key=signer.public_key)
        )
        self.assertEqual(receiver.accepted_indices, (0, 1))
        self.assertEqual(signer.next_index, 2)


if __name__ == "__main__":
    unittest.main()

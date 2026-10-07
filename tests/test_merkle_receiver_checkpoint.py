"""Tests for MerkleReceiver.checkpoint / MerkleReceiver.from_checkpoint.

A receiver checkpoint is a versioned, deterministic export of the expected
public key and the full accepted-leaf record, protected by a trailing
SHA-256 checksum. ``from_checkpoint(data, *, public_key)`` restores a new
receiver bound to the expected key (compared by value) with exactly the
recorded accepted set; the two instances are independent afterwards.
"""

from __future__ import annotations

import hashlib
import threading
import unittest

from pqattest import (
    MerkleBatchProof,
    MerklePublicKey,
    MerkleReceiver,
    MerkleSigner,
    multiproof_encode,
)
from pqattest.merkle import _RECEIVER_CHECKPOINT_MAGIC


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


def accept_leaves(receiver, signer, indices, proof_format="batch"):
    messages = tuple(f"m{i}" for i in indices)
    batch = make_batch_proof(signer, indices, messages)
    if proof_format == "multiproof":
        proof = multiproof_encode(batch.public_key, batch.signatures)
    else:
        proof = batch
    assert receiver.accept(messages, proof)


def craft_checkpoint(w, height, root, indices, magic=_RECEIVER_CHECKPOINT_MAGIC, version=1):
    body = (
        magic
        + bytes((version, w, height))
        + root
        + len(indices).to_bytes(2, "big")
        + b"".join(index.to_bytes(2, "big") for index in indices)
    )
    return body + hashlib.sha256(body).digest()


class ReceiverCheckpointFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        signer = make_signer(height=3, w=8)
        receiver = MerkleReceiver(signer.public_key)
        accept_leaves(receiver, signer, (1, 3, 5))
        blob = receiver.checkpoint()
        header = 8 + 1 + 1 + 1 + 32 + 2
        self.assertEqual(len(blob), header + 3 * 2 + 32)
        self.assertEqual(blob[:8], _RECEIVER_CHECKPOINT_MAGIC)
        self.assertEqual(blob[8], 1)  # version
        self.assertEqual(blob[9], 8)  # w
        self.assertEqual(blob[10], 3)  # height
        self.assertEqual(blob[11:43], signer.public_key.root)
        self.assertEqual(int.from_bytes(blob[43:45], "big"), 3)  # count
        # Indices are stored ascending as 2 big-endian bytes each.
        self.assertEqual(blob[45:51], b"\x00\x01\x00\x03\x00\x05")
        body, checksum = blob[:-32], blob[-32:]
        self.assertEqual(hashlib.sha256(body).digest(), checksum)

    def test_checkpoint_returns_bytes(self):
        receiver = MerkleReceiver(make_signer().public_key)
        self.assertIsInstance(receiver.checkpoint(), bytes)

    def test_empty_record_layout(self):
        signer = make_signer(height=2)
        blob = MerkleReceiver(signer.public_key).checkpoint()
        self.assertEqual(len(blob), 8 + 1 + 1 + 1 + 32 + 2 + 32)
        self.assertEqual(int.from_bytes(blob[43:45], "big"), 0)

    def test_export_does_not_change_record(self):
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        accept_leaves(receiver, signer, (0, 1))
        before = receiver.accepted_indices
        receiver.checkpoint()
        self.assertEqual(receiver.accepted_indices, before)
        accept_leaves(receiver, signer, (2,))
        self.assertEqual(receiver.accepted_indices, (0, 1, 2))


class ReceiverCheckpointRoundTripTest(unittest.TestCase):
    def round_trip(self, receiver, public_key):
        restored = MerkleReceiver.from_checkpoint(
            receiver.checkpoint(), public_key=public_key
        )
        self.assertEqual(restored.public_key, public_key)
        self.assertEqual(restored.accepted_indices, receiver.accepted_indices)
        return restored

    def test_empty_record_round_trip(self):
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        self.round_trip(receiver, signer.public_key)

    def test_sparse_record_round_trip(self):
        signer = make_signer(height=4)
        receiver = MerkleReceiver(signer.public_key)
        accept_leaves(receiver, signer, (0, 5, 6))
        accept_leaves(receiver, signer, (15,), proof_format="multiproof")
        self.round_trip(receiver, signer.public_key)

    def test_full_record_round_trip(self):
        for w in (4, 8):
            with self.subTest(w=w):
                signer = make_signer(height=4, w=w)
                receiver = MerkleReceiver(signer.public_key)
                accept_leaves(receiver, signer, tuple(range(16)))
                self.assertEqual(receiver.accepted_indices, tuple(range(16)))
                self.round_trip(receiver, signer.public_key)

    def test_all_w_and_heights_round_trip(self):
        for w in (4, 8):
            for height in range(1, 9):
                with self.subTest(w=w, height=height):
                    signer = make_signer(height=height, w=w, start=height * 100 + w)
                    receiver = MerkleReceiver(signer.public_key)
                    last = (1 << height) - 1
                    accept_leaves(receiver, signer, (0, last) if last else (0,))
                    self.round_trip(receiver, signer.public_key)

    def test_restored_checkpoint_is_byte_identical(self):
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        accept_leaves(receiver, signer, (2,))
        # A twin signer over the identical tree signs the lower leaf.
        accept_leaves(receiver, make_signer(height=3), (0,))
        blob = receiver.checkpoint()
        restored = MerkleReceiver.from_checkpoint(blob, public_key=signer.public_key)
        self.assertEqual(restored.checkpoint(), blob)

    def test_export_independent_of_accept_order_and_format(self):
        signer = make_signer(height=3)
        first = MerkleReceiver(signer.public_key)
        accept_leaves(first, signer, (0, 1, 2))
        accept_leaves(first, signer, (3,), proof_format="multiproof")
        # The same set accepted in a different order, batching and proof
        # format; twin signers over the identical tree sign out of order.
        second = MerkleReceiver(signer.public_key)
        accept_leaves(second, make_signer(height=3), (3,))
        accept_leaves(second, make_signer(height=3), (0, 1), proof_format="multiproof")
        accept_leaves(second, make_signer(height=3), (2,))
        self.assertEqual(first.accepted_indices, second.accepted_indices)
        self.assertEqual(first.checkpoint(), second.checkpoint())

    def test_accepts_bytearray_and_ignores_later_mutation(self):
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        accept_leaves(receiver, signer, (0, 1))
        blob = receiver.checkpoint()
        mutable = bytearray(blob)
        restored = MerkleReceiver.from_checkpoint(mutable, public_key=signer.public_key)
        mutable[:] = b"\x00" * len(mutable)
        self.assertEqual(restored.accepted_indices, (0, 1))
        self.assertEqual(restored.checkpoint(), blob)

    def test_equal_key_instance_accepted(self):
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        accept_leaves(receiver, signer, (0,))
        twin_key = MerklePublicKey(
            w=signer.public_key.w,
            height=signer.public_key.height,
            root=signer.public_key.root,
        )
        restored = MerkleReceiver.from_checkpoint(
            receiver.checkpoint(), public_key=twin_key
        )
        self.assertEqual(restored.public_key, twin_key)
        self.assertEqual(restored.accepted_indices, (0,))

    def test_instances_are_independent(self):
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        accept_leaves(receiver, signer, (0,))
        restored = self.round_trip(receiver, signer.public_key)
        accept_leaves(receiver, signer, (1,))
        accept_leaves(restored, signer, (2,))
        self.assertEqual(receiver.accepted_indices, (0, 1))
        self.assertEqual(restored.accepted_indices, (0, 2))

    def test_plain_constructor_still_starts_empty(self):
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        accept_leaves(receiver, signer, (0,))
        MerkleReceiver.from_checkpoint(
            receiver.checkpoint(), public_key=signer.public_key
        )
        fresh = MerkleReceiver(signer.public_key)
        self.assertEqual(fresh.accepted_indices, ())


class ReceiverCheckpointArgumentTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.receiver = MerkleReceiver(self.signer.public_key)
        accept_leaves(self.receiver, self.signer, (0, 1))
        self.blob = self.receiver.checkpoint()

    def test_wrong_data_type_rejected(self):
        for bad in (None, 7, "checkpoint", [self.blob], {"data": self.blob}, object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    MerkleReceiver.from_checkpoint(bad, public_key=self.signer.public_key)

    def test_wrong_public_key_type_rejected(self):
        for bad in (None, 4, "key", self.signer.public_key.to_bytes(), object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    MerkleReceiver.from_checkpoint(self.blob, public_key=bad)

    def test_types_checked_before_content(self):
        # A wrong data type raises TypeError even for a wrong key type, and
        # a wrong key type raises TypeError even for garbage content.
        with self.assertRaises(TypeError):
            MerkleReceiver.from_checkpoint(None, public_key=None)
        with self.assertRaises(TypeError):
            MerkleReceiver.from_checkpoint(b"garbage", public_key=None)

    def test_public_key_is_keyword_only(self):
        with self.assertRaises(TypeError):
            MerkleReceiver.from_checkpoint(self.blob, self.signer.public_key)


class ReceiverCheckpointCorruptionTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.receiver = MerkleReceiver(self.signer.public_key)
        accept_leaves(self.receiver, self.signer, (0, 5))
        self.blob = self.receiver.checkpoint()
        self.key = self.signer.public_key

    def assert_value_error(self, data):
        with self.assertRaises(ValueError):
            MerkleReceiver.from_checkpoint(data, public_key=self.key)

    def test_every_single_byte_corruption_detected(self):
        for position in range(len(self.blob)):
            with self.subTest(position=position):
                corrupted = bytearray(self.blob)
                corrupted[position] ^= 0x01
                self.assert_value_error(bytes(corrupted))

    def test_bad_magic(self):
        self.assert_value_error(b"X" + self.blob[1:])
        self.assert_value_error(
            craft_checkpoint(4, 3, self.key.root, (0, 5), magic=b"PQAMSCP\0")
        )

    def test_unknown_version(self):
        self.assert_value_error(
            craft_checkpoint(4, 3, self.key.root, (0, 5), version=2)
        )

    def test_truncation(self):
        self.assert_value_error(b"")
        self.assert_value_error(self.blob[:10])
        self.assert_value_error(self.blob[: len(self.blob) - 1])
        self.assert_value_error(self.blob[:-32])

    def test_trailing_bytes(self):
        self.assert_value_error(self.blob + b"\x00")
        self.assert_value_error(self.blob + self.blob)

    def test_invalid_encoded_key_fields(self):
        for bad_w in (0, 2, 16, 255):
            with self.subTest(bad_w=bad_w):
                self.assert_value_error(
                    craft_checkpoint(bad_w, 3, self.key.root, (0, 5))
                )
        for bad_height in (0, 9, 255):
            with self.subTest(bad_height=bad_height):
                self.assert_value_error(
                    craft_checkpoint(4, bad_height, self.key.root, (0, 5))
                )

    def test_illegal_accepted_set(self):
        # Index at or beyond the leaf count.
        self.assert_value_error(craft_checkpoint(4, 3, self.key.root, (0, 8)))
        self.assert_value_error(craft_checkpoint(4, 3, self.key.root, (255,)))
        # Duplicated and out-of-order indices.
        self.assert_value_error(craft_checkpoint(4, 3, self.key.root, (1, 1)))
        self.assert_value_error(craft_checkpoint(4, 3, self.key.root, (5, 0)))
        # A count that cannot fit the tree.
        self.assert_value_error(craft_checkpoint(4, 1, self.key.root, (0, 1, 2)))

    def test_expected_key_mismatch(self):
        other_root = MerkleReceiver(make_signer(height=3, start=1000).public_key)
        with self.assertRaises(ValueError):
            MerkleReceiver.from_checkpoint(self.blob, public_key=other_root.public_key)
        with self.assertRaises(ValueError):
            MerkleReceiver.from_checkpoint(
                self.blob, public_key=make_signer(height=3, w=8, start=2000).public_key
            )
        with self.assertRaises(ValueError):
            MerkleReceiver.from_checkpoint(
                self.blob, public_key=make_signer(height=4, start=3000).public_key
            )

    def test_signer_checkpoint_not_accepted(self):
        signer = make_signer(height=3)
        self.assert_value_error(signer.checkpoint())
        self.assert_value_error(MerkleSigner.from_seed(b"\x01" * 32, height=3, w=4).seed_checkpoint())


class ReceiverCheckpointRestoredBehaviourTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.receiver = MerkleReceiver(self.signer.public_key)
        accept_leaves(self.receiver, self.signer, (0, 1, 2))
        self.restored = MerkleReceiver.from_checkpoint(
            self.receiver.checkpoint(), public_key=self.signer.public_key
        )

    def test_recorded_leaf_rejected_in_either_format(self):
        # A twin signer over the identical tree re-signs the recorded leaf.
        batch = make_batch_proof(make_signer(height=3), (1,), ("m1",))
        data = multiproof_encode(batch.public_key, batch.signatures)
        self.assertFalse(self.restored.accept(("m1",), batch))
        self.assertFalse(self.restored.accept(("m1",), data))
        self.assertEqual(self.restored.accepted_indices, (0, 1, 2))

    def test_mixed_batch_fails_atomically(self):
        # Leaf 2 (recorded) and leaf 3 (fresh) in one batch, signed by a
        # twin over the identical tree: rejected as a whole.
        mixed = make_batch_proof(make_signer(height=3), (2, 3), ("m2", "m3"))
        self.assertFalse(self.restored.accept(("m2", "m3"), mixed))
        self.assertEqual(self.restored.accepted_indices, (0, 1, 2))
        fresh = make_batch_proof(self.signer, (3,), ("m3",))
        self.assertTrue(self.restored.accept(("m3",), fresh))
        self.assertEqual(self.restored.accepted_indices, (0, 1, 2, 3))

    def test_lower_fresh_index_accepted(self):
        signer = make_signer(height=4)
        receiver = MerkleReceiver(signer.public_key)
        accept_leaves(receiver, signer, (5, 6))
        restored = MerkleReceiver.from_checkpoint(
            receiver.checkpoint(), public_key=signer.public_key
        )
        twin = make_signer(height=4)
        low = make_batch_proof(twin, (2,), ("m2",))
        self.assertTrue(restored.accept(("m2",), low))
        self.assertEqual(restored.accepted_indices, (2, 5, 6))

    def test_context_semantics_preserved(self):
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        restored = MerkleReceiver.from_checkpoint(
            receiver.checkpoint(), public_key=signer.public_key
        )
        batch = make_batch_proof(signer, (0, 1), ("a", "b"), context="ctx")
        self.assertFalse(restored.accept(("a", "b"), batch))
        self.assertFalse(restored.accept(("a", "b"), batch, context="other"))
        self.assertTrue(restored.accept(("a", "b"), batch, context="ctx"))
        with self.assertRaises(TypeError):
            restored.accept(("a", "b"), None)
        with self.assertRaises(TypeError):
            restored.accept(("a", "b"), batch, context=object())
        with self.assertRaises(ValueError):
            restored.accept(("a", "b"), batch, context="x", contexts=("y", "y"))


class ReceiverCheckpointConcurrencyTest(unittest.TestCase):
    def test_snapshots_never_show_half_a_batch(self):
        signer = make_signer(height=4)
        receiver = MerkleReceiver(signer.public_key)
        batch_a = make_batch_proof(signer, (0, 1, 2), ("a0", "a1", "a2"))
        twin = make_signer(height=4)
        batch_b = make_batch_proof(twin, (3, 4), ("b3", "b4"))

        submissions = [
            (("a0", "a1", "a2"), batch_a),
            (("b3", "b4"), batch_b),
        ]
        blobs = []
        barrier = threading.Barrier(2 * len(submissions))

        def run(messages, proof):
            barrier.wait()
            receiver.accept(messages, proof)

        def watch():
            barrier.wait()
            for _ in range(20):
                blobs.append(receiver.checkpoint())

        threads = [
            threading.Thread(target=run, args=(messages, proof))
            for messages, proof in submissions
        ] + [threading.Thread(target=watch) for _ in submissions]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        final = set(receiver.accepted_indices)
        self.assertEqual(final, {0, 1, 2, 3, 4})
        batches = [frozenset((0, 1, 2)), frozenset((3, 4))]
        for blob in blobs:
            restored = MerkleReceiver.from_checkpoint(
                blob, public_key=signer.public_key
            )
            snapshot = set(restored.accepted_indices)
            self.assertTrue(snapshot <= final)
            for batch in batches:
                self.assertIn(snapshot & batch, (set(), batch))


if __name__ == "__main__":
    unittest.main()

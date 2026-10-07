"""Tests for MerkleReceiver.checkpoint / MerkleReceiver.from_checkpoint.

A receiver checkpoint is a deterministic, versioned v1 byte block holding
the expected public key (w, height, root) and the full accepted-leaf set,
plus a SHA-256 trailer against accidental corruption. Restoring binds a
fresh receiver to an expected public key given by value and resumes with
exactly the exported accepted set; the accept semantics (both proof
formats, context/contexts, atomic batch recording) are unchanged.
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

MAGIC = b"PQAMRCP\0"
HEADER_BYTES = 8 + 1 + 1 + 1 + 32 + 4
CHECKSUM_BYTES = 32


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


def make_multiproof(signer, indices, messages, **kwargs):
    batch = make_batch_proof(signer, indices, messages, **kwargs)
    return multiproof_encode(batch.public_key, batch.signatures)


def craft(w, height, root, indices, *, magic=MAGIC, version=1, count=None):
    """Build a well-formed-looking receiver checkpoint with a valid checksum."""
    if count is None:
        count = len(indices)
    body = (
        magic
        + bytes((version, w, height))
        + root
        + count.to_bytes(4, "big")
        + b"".join(index.to_bytes(2, "big") for index in indices)
    )
    return body + hashlib.sha256(body).digest()


class ReceiverCheckpointRoundTripTest(unittest.TestCase):
    def test_empty_record_all_w_and_heights(self):
        for w in (4, 8):
            for height in (1, 2, 3, 4):
                with self.subTest(w=w, height=height):
                    signer = make_signer(height=height, w=w, start=height * 100 + w)
                    receiver = MerkleReceiver(signer.public_key)
                    blob = receiver.checkpoint()
                    self.assertIsInstance(blob, bytes)
                    self.assertEqual(len(blob), HEADER_BYTES + CHECKSUM_BYTES)
                    restored = MerkleReceiver.from_checkpoint(
                        blob, public_key=signer.public_key
                    )
                    self.assertEqual(restored.public_key, signer.public_key)
                    self.assertEqual(restored.accepted_indices, ())
                    self.assertEqual(restored.checkpoint(), blob)

    def test_empty_record_taller_heights(self):
        for height in (5, 6, 7, 8):
            with self.subTest(height=height):
                signer = make_signer(height=height, start=height)
                receiver = MerkleReceiver(signer.public_key)
                blob = receiver.checkpoint()
                restored = MerkleReceiver.from_checkpoint(
                    blob, public_key=signer.public_key
                )
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertEqual(restored.accepted_indices, ())
                self.assertEqual(restored.checkpoint(), blob)

    def test_sparse_record_round_trip(self):
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        high = make_batch_proof(signer, (5, 6), ("e", "f"))
        self.assertTrue(receiver.accept(("e", "f"), high))
        twin = make_signer(height=3)
        low = make_multiproof(twin, (2,), ("c",))
        self.assertTrue(receiver.accept(("c",), low))
        self.assertEqual(receiver.accepted_indices, (2, 5, 6))
        blob = receiver.checkpoint()
        self.assertEqual(len(blob), HEADER_BYTES + 3 * 2 + CHECKSUM_BYTES)
        restored = MerkleReceiver.from_checkpoint(blob, public_key=signer.public_key)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.accepted_indices, (2, 5, 6))
        self.assertEqual(restored.checkpoint(), blob)

    def test_full_record_round_trip(self):
        for height in (1, 2, 3):
            with self.subTest(height=height):
                signer = make_signer(height=height, start=height)
                receiver = MerkleReceiver(signer.public_key)
                indices = tuple(range(1 << height))
                messages = tuple(f"m{i}" for i in indices)
                batch = make_batch_proof(signer, indices, messages)
                self.assertTrue(receiver.accept(messages, batch))
                self.assertEqual(receiver.accepted_indices, indices)
                blob = receiver.checkpoint()
                restored = MerkleReceiver.from_checkpoint(
                    blob, public_key=signer.public_key
                )
                self.assertEqual(restored.accepted_indices, indices)
                self.assertEqual(restored.checkpoint(), blob)
                # Every leaf is recorded: resubmission in either format fails.
                self.assertFalse(restored.accept(messages, batch))
                data = multiproof_encode(batch.public_key, batch.signatures)
                self.assertFalse(restored.accept(messages, data))

    def test_export_does_not_change_record(self):
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        batch = make_batch_proof(signer, (0, 1), ("a", "b"))
        self.assertTrue(receiver.accept(("a", "b"), batch))
        before = receiver.accepted_indices
        receiver.checkpoint()
        receiver.checkpoint()
        self.assertEqual(receiver.accepted_indices, before)
        more = make_batch_proof(signer, (2,), ("c",))
        self.assertTrue(receiver.accept(("c",), more))
        self.assertEqual(receiver.accepted_indices, (0, 1, 2))


class ReceiverCheckpointDeterminismTest(unittest.TestCase):
    def test_same_set_same_bytes_regardless_of_history(self):
        signer = make_signer(height=3)
        # Every proof comes from a fresh deterministic twin over the
        # identical tree, so a signer's next_index never blocks a leaf.
        def twin():
            return make_signer(height=3)

        blobs = []
        # Same final set {0, 1, 2, 5} reached four different ways.
        receiver = MerkleReceiver(signer.public_key)
        self.assertTrue(
            receiver.accept(("a", "b"), make_batch_proof(twin(), (0, 1), ("a", "b")))
        )
        self.assertTrue(
            receiver.accept(("c", "f"), make_multiproof(twin(), (2, 5), ("c", "f")))
        )
        blobs.append(receiver.checkpoint())

        receiver = MerkleReceiver(signer.public_key)
        self.assertTrue(receiver.accept(("f",), make_multiproof(twin(), (5,), ("f",))))
        self.assertTrue(
            receiver.accept(
                ("a", "b", "c"), make_batch_proof(twin(), (0, 1, 2), ("a", "b", "c"))
            )
        )
        blobs.append(receiver.checkpoint())

        receiver = MerkleReceiver(signer.public_key)
        self.assertTrue(
            receiver.accept(
                ("a", "b", "c", "f"),
                make_multiproof(twin(), (0, 1, 2, 5), ("a", "b", "c", "f")),
            )
        )
        blobs.append(receiver.checkpoint())

        receiver = MerkleReceiver(signer.public_key)
        self.assertTrue(receiver.accept(("c",), make_batch_proof(twin(), (2,), ("c",))))
        self.assertTrue(receiver.accept(("a",), make_multiproof(twin(), (0,), ("a",))))
        self.assertTrue(receiver.accept(("f",), make_batch_proof(twin(), (5,), ("f",))))
        self.assertTrue(receiver.accept(("b",), make_multiproof(twin(), (1,), ("b",))))
        blobs.append(receiver.checkpoint())

        self.assertEqual(len(set(blobs)), 1)
        restored = MerkleReceiver.from_checkpoint(
            blobs[0], public_key=signer.public_key
        )
        self.assertEqual(restored.accepted_indices, (0, 1, 2, 5))
        self.assertEqual(restored.checkpoint(), blobs[0])

    def test_repeated_export_identical(self):
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        self.assertEqual(receiver.checkpoint(), receiver.checkpoint())
        batch = make_batch_proof(signer, (3,), ("d",))
        self.assertTrue(receiver.accept(("d",), batch))
        self.assertEqual(receiver.checkpoint(), receiver.checkpoint())


class ReceiverCheckpointArgumentTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.receiver = MerkleReceiver(self.signer.public_key)
        self.blob = self.receiver.checkpoint()

    def test_data_type_checked(self):
        for bad in (None, 7, 3.5, "blob", [1, 2], {"x": 1}, object(), memoryview(self.blob)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    MerkleReceiver.from_checkpoint(bad, public_key=self.signer.public_key)

    def test_public_key_type_checked(self):
        for bad in (None, 4, "key", b"\x00" * 43, (4, 3, b"\x00" * 32), object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    MerkleReceiver.from_checkpoint(self.blob, public_key=bad)

    def test_type_checks_precede_content_parsing(self):
        # Both type checks run before any byte of the content is looked at.
        with self.assertRaises(TypeError):
            MerkleReceiver.from_checkpoint("not-bytes", public_key="not-a-key")
        with self.assertRaises(TypeError):
            MerkleReceiver.from_checkpoint(b"garbage", public_key="not-a-key")
        with self.assertRaises(TypeError):
            MerkleReceiver.from_checkpoint(None, public_key=self.signer.public_key)

    def test_bytearray_input_accepted_and_copied(self):
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        batch = make_batch_proof(signer, (1, 4), ("b", "e"))
        self.assertTrue(receiver.accept(("b", "e"), batch))
        blob = receiver.checkpoint()
        mutable = bytearray(blob)
        restored = MerkleReceiver.from_checkpoint(
            mutable, public_key=signer.public_key
        )
        # Later mutation of the caller's buffer cannot affect the receiver.
        mutable[:] = b"\x00" * len(mutable)
        self.assertEqual(restored.accepted_indices, (1, 4))
        self.assertEqual(restored.checkpoint(), blob)

    def test_expected_key_compared_by_value(self):
        signer = make_signer(height=3)
        receiver = MerkleReceiver(signer.public_key)
        batch = make_batch_proof(signer, (0,), ("a",))
        self.assertTrue(receiver.accept(("a",), batch))
        blob = receiver.checkpoint()
        twin_key = MerklePublicKey(
            w=signer.public_key.w,
            height=signer.public_key.height,
            root=signer.public_key.root,
        )
        self.assertIsNot(twin_key, signer.public_key)
        restored = MerkleReceiver.from_checkpoint(blob, public_key=twin_key)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.accepted_indices, (0,))


class ReceiverCheckpointCorruptionTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.receiver = MerkleReceiver(self.signer.public_key)
        batch = make_batch_proof(self.signer, (0, 2, 5), ("a", "c", "f"))
        self.assertTrue(self.receiver.accept(("a", "c", "f"), batch))
        self.blob = self.receiver.checkpoint()
        self.key = self.signer.public_key

    def assert_invalid(self, data):
        with self.assertRaises(ValueError):
            MerkleReceiver.from_checkpoint(data, public_key=self.key)

    def test_every_single_byte_corruption_detected(self):
        for position in range(len(self.blob)):
            corrupted = bytearray(self.blob)
            corrupted[position] ^= 0xFF
            with self.subTest(position=position):
                self.assert_invalid(bytes(corrupted))

    def test_bad_magic(self):
        self.assert_invalid(craft(4, 3, self.key.root, (0, 2, 5), magic=b"XQAMRCP\0"))

    def test_unknown_version(self):
        self.assert_invalid(craft(4, 3, self.key.root, (0, 2, 5), version=2))
        self.assert_invalid(craft(4, 3, self.key.root, (0, 2, 5), version=0))

    def test_truncated(self):
        self.assert_invalid(b"")
        self.assert_invalid(self.blob[: HEADER_BYTES + CHECKSUM_BYTES - 1])
        self.assert_invalid(self.blob[: len(self.blob) - 1])
        self.assert_invalid(self.blob[:HEADER_BYTES])

    def test_trailing_bytes(self):
        self.assert_invalid(self.blob + b"\x00")
        self.assert_invalid(self.blob + self.blob)

    def test_checksum_mismatch(self):
        body = self.blob[:-CHECKSUM_BYTES]
        self.assert_invalid(body + b"\x00" * CHECKSUM_BYTES)
        self.assert_invalid(body + hashlib.sha256(b"other").digest())

    def test_illegal_key_fields(self):
        root = self.key.root
        for w, height in ((2, 3), (16, 3), (True, 3), (4, 0), (4, 9), (4, True)):
            with self.subTest(w=w, height=height):
                self.assert_invalid(craft(w, height, root, (0, 2, 5)))

    def test_count_exceeds_leaf_count(self):
        # height 3 has 8 leaves; a set cannot hold 9 distinct indices.
        self.assert_invalid(craft(4, 3, self.key.root, (), count=9))

    def test_length_count_mismatch(self):
        # count says 3 but no index bytes follow.
        self.assert_invalid(craft(4, 3, self.key.root, (), count=3))
        # count says 1 but three index slots are present.
        self.assert_invalid(craft(4, 3, self.key.root, (0, 2, 5), count=1))

    def test_index_out_of_range(self):
        self.assert_invalid(craft(4, 3, self.key.root, (0, 2, 8)))
        self.assert_invalid(craft(4, 3, self.key.root, (0, 2, 0xFFFF)))

    def test_indices_not_strictly_ascending(self):
        self.assert_invalid(craft(4, 3, self.key.root, (0, 2, 2)))
        self.assert_invalid(craft(4, 3, self.key.root, (2, 0, 5)))
        self.assert_invalid(craft(4, 3, self.key.root, (5, 2, 0)))

    def test_expected_key_mismatch(self):
        other = make_signer(height=3, start=1000)
        self.assertNotEqual(other.public_key.root, self.key.root)
        with self.assertRaises(ValueError):
            MerkleReceiver.from_checkpoint(self.blob, public_key=other.public_key)
        taller = make_signer(height=4, start=2000)
        with self.assertRaises(ValueError):
            MerkleReceiver.from_checkpoint(self.blob, public_key=taller.public_key)
        wider = make_signer(height=3, w=8, start=3000)
        with self.assertRaises(ValueError):
            MerkleReceiver.from_checkpoint(self.blob, public_key=wider.public_key)

    def test_signer_checkpoint_not_a_receiver_checkpoint(self):
        signer_checkpoint = self.signer.checkpoint()
        self.assert_invalid(signer_checkpoint)


class ReceiverCheckpointRestoredSemanticsTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.twin = make_signer(height=3)
        self.receiver = MerkleReceiver(self.signer.public_key)
        batch = make_batch_proof(self.signer, (0, 1, 2), ("a", "b", "c"))
        self.assertTrue(self.receiver.accept(("a", "b", "c"), batch))
        self.restored = MerkleReceiver.from_checkpoint(
            self.receiver.checkpoint(), public_key=self.signer.public_key
        )

    def test_recorded_leaf_rejected_in_other_format(self):
        batch = make_batch_proof(self.twin, (1,), ("b",))
        data = multiproof_encode(batch.public_key, batch.signatures)
        self.assertFalse(self.restored.accept(("b",), batch))
        self.assertFalse(self.restored.accept(("b",), data))
        self.assertEqual(self.restored.accepted_indices, (0, 1, 2))

    def test_mixed_batch_fails_atomically(self):
        mixed = make_batch_proof(self.twin, (2, 3), ("c", "d"))
        self.assertFalse(self.restored.accept(("c", "d"), mixed))
        self.assertEqual(self.restored.accepted_indices, (0, 1, 2))
        fresh = make_batch_proof(self.signer, (3,), ("d",))
        self.assertTrue(self.restored.accept(("d",), fresh))
        self.assertEqual(self.restored.accepted_indices, (0, 1, 2, 3))

    def test_smaller_fresh_index_accepted(self):
        high = make_batch_proof(self.signer, (6, 7), ("g", "h"))
        receiver = MerkleReceiver(self.signer.public_key)
        self.assertTrue(receiver.accept(("g", "h"), high))
        restored = MerkleReceiver.from_checkpoint(
            receiver.checkpoint(), public_key=self.signer.public_key
        )
        low = make_batch_proof(self.twin, (1,), ("b",))
        self.assertTrue(restored.accept(("b",), low))
        self.assertEqual(restored.accepted_indices, (1, 6, 7))

    def test_context_rules_preserved(self):
        batch = make_batch_proof(self.signer, (3, 4), ("d", "e"), context="ctx")
        self.assertFalse(self.restored.accept(("d", "e"), batch))
        self.assertFalse(self.restored.accept(("d", "e"), batch, context="other"))
        self.assertTrue(self.restored.accept(("d", "e"), batch, context="ctx"))
        self.assertEqual(self.restored.accepted_indices, (0, 1, 2, 3, 4))

    def test_contexts_rules_preserved(self):
        contexts = ("c0", None)
        batch = make_batch_proof(self.signer, (3, 4), ("d", "e"), contexts=contexts)
        self.assertFalse(self.restored.accept(("d", "e"), batch, contexts=("c0", "x")))
        self.assertTrue(self.restored.accept(("d", "e"), batch, contexts=contexts))
        with self.assertRaises(ValueError):
            self.restored.accept(("d", "e"), batch, context="x", contexts=("y", "y"))
        with self.assertRaises(TypeError):
            self.restored.accept(("d", "e"), batch, context=object())

    def test_argument_and_failure_semantics_preserved(self):
        with self.assertRaises(TypeError):
            self.restored.accept(("a",), None)
        batch = make_batch_proof(self.twin, (3,), ("d",))
        self.assertFalse(self.restored.accept(("wrong",), batch))
        self.assertFalse(self.restored.accept(("d", "e"), batch))
        self.assertEqual(self.restored.accepted_indices, (0, 1, 2))

    def test_instances_are_independent(self):
        batch = make_batch_proof(self.signer, (3,), ("d",))
        self.assertTrue(self.restored.accept(("d",), batch))
        self.assertEqual(self.receiver.accepted_indices, (0, 1, 2))
        self.assertEqual(self.restored.accepted_indices, (0, 1, 2, 3))
        other = make_batch_proof(self.twin, (4,), ("e",))
        self.assertTrue(self.receiver.accept(("e",), other))
        self.assertEqual(self.restored.accepted_indices, (0, 1, 2, 3))

    def test_plain_constructor_still_starts_empty(self):
        fresh = MerkleReceiver(self.signer.public_key)
        self.assertEqual(fresh.accepted_indices, ())
        batch = make_batch_proof(self.twin, (0,), ("a",))
        self.assertTrue(fresh.accept(("a",), batch))


class ReceiverCheckpointConcurrencyTest(unittest.TestCase):
    def test_snapshots_never_show_half_a_batch(self):
        signer = make_signer(height=4)
        receiver = MerkleReceiver(signer.public_key)
        batch_a = make_batch_proof(signer, (0, 1, 2), ("a0", "a1", "a2"))
        twin = make_signer(height=4)
        batch_b = make_batch_proof(twin, (2, 3, 4), ("a2", "b3", "b4"))
        batch_c = make_batch_proof(twin, (5, 6), ("c5", "c6"))

        submissions = [
            (("a0", "a1", "a2"), batch_a),
            (("a2", "b3", "b4"), batch_b),
            (("c5", "c6"), batch_c),
        ]
        snapshots = []
        barrier = threading.Barrier(2 * len(submissions))

        def run(messages, proof):
            barrier.wait()
            receiver.accept(messages, proof)

        def watch():
            barrier.wait()
            for _ in range(20):
                snapshots.append(receiver.checkpoint())

        threads = [
            threading.Thread(target=run, args=(messages, proof))
            for messages, proof in submissions
        ] + [threading.Thread(target=watch) for _ in submissions]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        final = set(receiver.accepted_indices)
        batches = [frozenset((0, 1, 2)), frozenset((2, 3, 4)), frozenset((5, 6))]
        for blob in snapshots:
            restored = MerkleReceiver.from_checkpoint(
                blob, public_key=signer.public_key
            )
            recorded = set(restored.accepted_indices)
            self.assertTrue(recorded <= final)
            for batch in batches:
                intersection = recorded & batch
                self.assertIn(intersection, (set(), batch & final))


if __name__ == "__main__":
    unittest.main()

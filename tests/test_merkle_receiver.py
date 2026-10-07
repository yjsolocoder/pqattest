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

SEED = b"\x11" * 32
OTHER_SEED = b"\x22" * 32


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def seed_signer(height=2, w=4, seed=SEED):
    return MerkleSigner.from_seed(seed, height=height, w=w)


def make_batch(signer, indices, messages, **kwargs):
    signatures = signer.sign_selected(tuple(indices), tuple(messages), **kwargs)
    return MerkleBatchProof(public_key=signer.public_key, signatures=signatures)


def make_multiproof(signer, indices, messages, **kwargs):
    signatures = signer.sign_selected(tuple(indices), tuple(messages), **kwargs)
    return multiproof_encode(signer.public_key, signatures)


class ReceiverConstructionTest(unittest.TestCase):
    def test_public_key_and_empty_record(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        self.assertIs(receiver.public_key, signer.public_key)
        self.assertEqual(receiver.accepted_indices, ())
        self.assertIsInstance(receiver.accepted_indices, tuple)

    def test_public_key_type_errors(self):
        for bad in (None, 42, "key", b"bytes", (1, 2), object()):
            with self.assertRaises(TypeError):
                MerkleReceiver(bad)

    def test_corrupted_public_key_fields_raise_value_error(self):
        signer = make_signer()
        for field, value in (
            ("w", 3),
            ("w", "4"),
            ("height", 0),
            ("height", 9),
            ("root", b"short"),
            ("root", "not-bytes"),
        ):
            key = MerklePublicKey(
                w=signer.public_key.w,
                height=signer.public_key.height,
                root=signer.public_key.root,
            )
            object.__setattr__(key, field, value)
            with self.assertRaises(ValueError):
                MerkleReceiver(key)

    def test_record_is_per_instance(self):
        signer = make_signer()
        batch = make_batch(signer, (0,), ("m",))
        first = MerkleReceiver(signer.public_key)
        second = MerkleReceiver(signer.public_key)
        self.assertTrue(first.accept(("m",), batch))
        self.assertFalse(first.accept(("m",), batch))
        self.assertTrue(second.accept(("m",), batch))
        self.assertEqual(second.accepted_indices, (0,))


class ReceiverAcceptBatchTest(unittest.TestCase):
    def test_accept_then_replay_refused(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        batch = make_batch(signer, (0, 1, 2), ("a", "b", "c"))
        self.assertTrue(receiver.accept(("a", "b", "c"), batch))
        self.assertEqual(receiver.accepted_indices, (0, 1, 2))
        # Identical messages and signatures are still refused.
        self.assertFalse(receiver.accept(("a", "b", "c"), batch))
        self.assertEqual(receiver.accepted_indices, (0, 1, 2))

    def test_snapshot_is_stable(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        snapshot = receiver.accepted_indices
        batch = make_batch(signer, (0,), ("a",))
        self.assertTrue(receiver.accept(("a",), batch))
        self.assertEqual(snapshot, ())
        later = receiver.accepted_indices
        batch2 = make_batch(signer, (1,), ("b",))
        self.assertTrue(receiver.accept(("b",), batch2))
        self.assertEqual(later, (0,))
        self.assertEqual(receiver.accepted_indices, (0, 1))

    def test_same_message_on_different_leaves(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        batch = make_batch(signer, (0, 1, 2), ("dup", "dup", "dup"))
        self.assertTrue(receiver.accept(("dup", "dup", "dup"), batch))
        self.assertEqual(receiver.accepted_indices, (0, 1, 2))

    def test_high_index_first_does_not_block_lower(self):
        receiver = MerkleReceiver(seed_signer().public_key)
        high = make_batch(seed_signer(), (3,), ("high",))
        low = make_batch(seed_signer(), (1,), ("low",))
        self.assertTrue(receiver.accept(("high",), high))
        self.assertTrue(receiver.accept(("low",), low))
        self.assertEqual(receiver.accepted_indices, (1, 3))

    def test_mixed_old_and_new_leaves_fail_as_a_whole(self):
        receiver = MerkleReceiver(seed_signer().public_key)
        first = make_batch(seed_signer(), (0, 1), ("a", "b"))
        self.assertTrue(receiver.accept(("a", "b"), first))
        mixed = make_batch(seed_signer(), (1, 2), ("b", "c"))
        self.assertFalse(receiver.accept(("b", "c"), mixed))
        self.assertEqual(receiver.accepted_indices, (0, 1))
        # The fresh leaf is still acceptable on its own afterwards.
        standalone = make_batch(seed_signer(), (2,), ("c",))
        self.assertTrue(receiver.accept(("c",), standalone))
        self.assertEqual(receiver.accepted_indices, (0, 1, 2))

    def test_failed_accept_changes_nothing(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        good = make_batch(signer, (0,), ("a",))
        self.assertTrue(receiver.accept(("a",), good))
        other = make_signer()
        foreign = make_batch(other, (0,), ("x",))
        self.assertFalse(receiver.accept(("x",), foreign))
        self.assertFalse(receiver.accept(("wrong",), good))
        self.assertFalse(receiver.accept(["a"], good))
        self.assertFalse(receiver.accept(("a", "extra"), good))
        self.assertFalse(receiver.accept((42,), good))
        self.assertEqual(receiver.accepted_indices, (0,))

    def test_empty_and_corrupted_batch_fields(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        batch = make_batch(signer, (0,), ("a",))
        object.__setattr__(batch, "signatures", ())
        self.assertFalse(receiver.accept((), batch))
        batch2 = make_batch(signer, (1,), ("b",))
        object.__setattr__(batch2, "public_key", "not-a-key")
        self.assertFalse(receiver.accept(("b",), batch2))
        self.assertEqual(receiver.accepted_indices, ())

    def test_wrong_expected_key_refused(self):
        signer = make_signer()
        other = make_signer(start=100)
        receiver = MerkleReceiver(other.public_key)
        batch = make_batch(signer, (0,), ("a",))
        self.assertFalse(receiver.accept(("a",), batch))
        self.assertEqual(receiver.accepted_indices, ())


class ReceiverAcceptMultiproofTest(unittest.TestCase):
    def test_bytes_and_bytearray(self):
        receiver = MerkleReceiver(seed_signer().public_key)
        blob = make_multiproof(seed_signer(), (0, 1), ("a", "b"))
        self.assertTrue(receiver.accept(("a", "b"), bytes(blob)))
        blob2 = make_multiproof(seed_signer(), (2,), ("c",))
        self.assertTrue(receiver.accept(("c",), bytearray(blob2)))
        self.assertEqual(receiver.accepted_indices, (0, 1, 2))

    def test_formats_share_one_record(self):
        receiver = MerkleReceiver(seed_signer().public_key)
        batch = make_batch(seed_signer(), (0, 1), ("a", "b"))
        self.assertTrue(receiver.accept(("a", "b"), batch))
        # The same leaves re-submitted as a multiproof are refused.
        blob = make_multiproof(seed_signer(), (0, 1), ("a", "b"))
        self.assertFalse(receiver.accept(("a", "b"), blob))
        self.assertFalse(receiver.accept(("a", "b"), batch))
        self.assertEqual(receiver.accepted_indices, (0, 1))
        # And the other direction: multiproof first, batch replay refused.
        receiver2 = MerkleReceiver(seed_signer().public_key)
        self.assertTrue(receiver2.accept(("a", "b"), blob))
        self.assertFalse(receiver2.accept(("a", "b"), batch))

    def test_corrupted_encoding_returns_false(self):
        receiver = MerkleReceiver(seed_signer().public_key)
        blob = bytearray(make_multiproof(seed_signer(), (0,), ("a",)))
        blob[-1] ^= 0x01
        self.assertFalse(receiver.accept(("a",), bytes(blob)))
        self.assertFalse(receiver.accept(("a",), b""))
        self.assertFalse(receiver.accept(("a",), b"PQAMMUL\0\x01"))
        self.assertEqual(receiver.accepted_indices, ())

    def test_wrong_expected_key_refused(self):
        receiver = MerkleReceiver(seed_signer(seed=OTHER_SEED).public_key)
        blob = make_multiproof(seed_signer(), (0,), ("a",))
        self.assertFalse(receiver.accept(("a",), blob))
        self.assertEqual(receiver.accepted_indices, ())


class ReceiverProofTypeTest(unittest.TestCase):
    def test_non_proof_types_raise_type_error(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        for bad in (None, 42, 4.5, "proof", object(), [], {}, (b"x",)):
            with self.assertRaises(TypeError):
                receiver.accept(("a",), bad)
        self.assertEqual(receiver.accepted_indices, ())


class ReceiverContextTest(unittest.TestCase):
    def test_shared_context_batch(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        batch = make_batch(signer, (0,), ("a",), context="ctx")
        self.assertFalse(receiver.accept(("a",), batch))
        self.assertFalse(receiver.accept(("a",), batch, context="other"))
        self.assertTrue(receiver.accept(("a",), batch, context="ctx"))
        self.assertEqual(receiver.accepted_indices, (0,))

    def test_shared_context_multiproof(self):
        receiver = MerkleReceiver(seed_signer().public_key)
        blob = make_multiproof(seed_signer(), (0, 1), ("a", "b"), context=b"ctx")
        self.assertFalse(receiver.accept(("a", "b"), blob))
        self.assertTrue(receiver.accept(("a", "b"), blob, context=b"ctx"))
        self.assertEqual(receiver.accepted_indices, (0, 1))

    def test_per_leaf_contexts(self):
        receiver = MerkleReceiver(seed_signer().public_key)
        contexts = ("one", None, b"three")
        blob = make_multiproof(
            seed_signer(), (0, 1, 2), ("a", "b", "c"), contexts=contexts
        )
        self.assertFalse(receiver.accept(("a", "b", "c"), blob))
        self.assertFalse(
            receiver.accept(("a", "b", "c"), blob, contexts=("one", None, "wrong"))
        )
        self.assertTrue(
            receiver.accept(("a", "b", "c"), blob, contexts=contexts)
        )
        self.assertEqual(receiver.accepted_indices, (0, 1, 2))
        batch = make_batch(seed_signer(), (3,), ("d",), contexts=("four",))
        self.assertTrue(
            receiver.accept(("d",), batch, contexts=(bytearray(b"four"),))
        )
        self.assertEqual(receiver.accepted_indices, (0, 1, 2, 3))

    def test_context_type_errors(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        batch = make_batch(signer, (0,), ("a",))
        with self.assertRaises(TypeError):
            receiver.accept(("a",), batch, context=42)
        with self.assertRaises(TypeError):
            receiver.accept(("a",), batch, contexts=["x"])
        with self.assertRaises(TypeError):
            receiver.accept(("a",), batch, contexts=(42,))
        self.assertEqual(receiver.accepted_indices, ())

    def test_context_conflict_raises_value_error(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        batch = make_batch(signer, (0,), ("a",))
        with self.assertRaises(ValueError):
            receiver.accept(("a",), batch, context="x", contexts=("y",))
        self.assertEqual(receiver.accepted_indices, ())

    def test_contexts_count_mismatch_returns_false(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        batch = make_batch(signer, (0, 1), ("a", "b"))
        self.assertFalse(receiver.accept(("a", "b"), batch, contexts=("x",)))
        self.assertEqual(receiver.accepted_indices, ())

    def test_argument_checks_precede_verification(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        batch = make_batch(signer, (0,), ("a",))
        # A bad context type raises even though the message would not verify.
        with self.assertRaises(TypeError):
            receiver.accept(("wrong",), batch, context=object())
        # The context/contexts conflict raises even for a foreign proof.
        foreign = make_batch(make_signer(start=50), (0,), ("z",))
        with self.assertRaises(ValueError):
            receiver.accept(("z",), foreign, context="x", contexts=("y",))
        self.assertEqual(receiver.accepted_indices, ())


class ReceiverParametersTest(unittest.TestCase):
    def test_all_heights_and_both_w(self):
        for w in (4, 8):
            for height in range(1, 9):
                if w == 8 and height > 3:
                    continue  # keep the w=8 key generation cost bounded
                with self.subTest(w=w, height=height):
                    signer = make_signer(height=height, w=w)
                    receiver = MerkleReceiver(signer.public_key)
                    last = (1 << height) - 1
                    batch = make_batch(signer, (0,), ("first",))
                    blob = make_multiproof(signer, (last,), ("last",))
                    self.assertTrue(receiver.accept(("first",), batch))
                    self.assertTrue(receiver.accept(("last",), blob))
                    self.assertEqual(receiver.accepted_indices, (0, last))
                    self.assertFalse(receiver.accept(("first",), batch))
                    self.assertFalse(receiver.accept(("last",), blob))

    def test_stateless_verification_unaffected(self):
        signer = make_signer()
        receiver = MerkleReceiver(signer.public_key)
        batch = make_batch(signer, (0, 1), ("a", "b"))
        blob = multiproof_encode(signer.public_key, batch.signatures)
        self.assertTrue(receiver.accept(("a", "b"), batch))
        # The same proofs still verify through the stateless entries.
        self.assertTrue(batch.verify(("a", "b")))
        self.assertTrue(
            batch.verify_bound(("a", "b"), public_key=signer.public_key)
        )
        self.assertTrue(multiproof_verify(("a", "b"), blob))
        self.assertTrue(
            multiproof_verify_bound(
                ("a", "b"), blob, public_key=signer.public_key
            )
        )
        # The receiver did not mutate the inputs.
        self.assertEqual(
            batch.signatures, make_batch(make_signer(), (0, 1), ("a", "b")).signatures
        )


class ReceiverConcurrencyTest(unittest.TestCase):
    def _run_threads(self, workers):
        barrier = threading.Barrier(len(workers))
        results = [None] * len(workers)

        def wrap(index, worker):
            barrier.wait()
            results[index] = worker()

        threads = [
            threading.Thread(target=wrap, args=(i, worker))
            for i, worker in enumerate(workers)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return results

    def test_overlapping_batches_succeed_at_most_once(self):
        height = 4
        public_key = seed_signer(height=height).public_key
        receiver = MerkleReceiver(public_key)
        # Eight threads all race to submit the same leaves, half as batch
        # proofs and half as multiproofs.
        batch = make_batch(seed_signer(height=height), (0, 1), ("a", "b"))
        blob = make_multiproof(seed_signer(height=height), (0, 1), ("a", "b"))
        proofs = [batch, blob] * 4
        workers = [
            (lambda proof=proof: receiver.accept(("a", "b"), proof))
            for proof in proofs
        ]
        results = self._run_threads(workers)
        self.assertEqual(sum(1 for result in results if result), 1)
        self.assertEqual(receiver.accepted_indices, (0, 1))

    def test_disjoint_batches_all_succeed(self):
        height = 4
        public_key = seed_signer(height=height).public_key
        receiver = MerkleReceiver(public_key)
        pairs = [(2 * i, 2 * i + 1) for i in range(8)]
        proofs = []
        for pair in pairs:
            messages = tuple(f"m{index}" for index in pair)
            if pair[0] % 4 == 0:
                proofs.append(
                    (messages, make_batch(seed_signer(height=height), pair, messages))
                )
            else:
                proofs.append(
                    (
                        messages,
                        make_multiproof(seed_signer(height=height), pair, messages),
                    )
                )
        workers = [
            (lambda entry=entry: receiver.accept(entry[0], entry[1]))
            for entry in proofs
        ]
        results = self._run_threads(workers)
        self.assertTrue(all(results))
        self.assertEqual(receiver.accepted_indices, tuple(range(16)))

    def test_snapshots_never_show_half_a_batch(self):
        height = 4
        public_key = seed_signer(height=height).public_key
        receiver = MerkleReceiver(public_key)
        proofs = [
            make_multiproof(
                seed_signer(height=height),
                (2 * i, 2 * i + 1),
                (f"a{i}", f"b{i}"),
            )
            for i in range(8)
        ]
        messages = [(f"a{i}", f"b{i}") for i in range(8)]
        stop = threading.Event()
        violations = []

        def reader():
            while not stop.is_set():
                snapshot = receiver.accepted_indices
                for i in range(8):
                    if (2 * i in snapshot) != (2 * i + 1 in snapshot):
                        violations.append(snapshot)
                        break

        def submitter():
            for proof, message_pair in zip(proofs, messages):
                receiver.accept(message_pair, proof)

        thread = threading.Thread(target=reader)
        thread.start()
        submitter()
        stop.set()
        thread.join()
        self.assertEqual(violations, [])
        self.assertEqual(receiver.accepted_indices, tuple(range(16)))


if __name__ == "__main__":
    unittest.main()

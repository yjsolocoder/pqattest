import threading
import unittest
from dataclasses import replace

from pqattest import (
    KeyExhaustedError,
    MerklePublicKey,
    MerkleSignature,
    MerkleSigner,
    PublicKey as LamportPublicKey,
    merkle_verify,
    wots_keygen,
)
from pqattest.merkle import _leaf_hash, _node_hash
from pqattest.wots import _chain_walk


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


class ParameterTest(unittest.TestCase):
    def test_defaults(self):
        signer = MerkleSigner(token_bytes=counter_tokens())
        self.assertEqual(signer.public_key.w, 4)
        self.assertEqual(signer.public_key.height, 4)
        self.assertEqual(signer.public_key.leaf_count, 16)

    def test_invalid_w_rejected(self):
        for bad_w in (2, 16, 0, -4, 4.0, None, True, "4"):
            with self.subTest(bad_w=bad_w):
                with self.assertRaises(ValueError):
                    MerkleSigner(w=bad_w)

    def test_invalid_height_rejected(self):
        for bad_height in (0, 9, -1, 4.0, None, True, False, "4"):
            with self.subTest(bad_height=bad_height):
                with self.assertRaises(ValueError):
                    MerkleSigner(height=bad_height)

    def test_height_bounds_accepted(self):
        for height in (1, 8):
            with self.subTest(height=height):
                signer = MerkleSigner(height=height, token_bytes=counter_tokens())
                self.assertEqual(signer.public_key.height, height)

    def test_token_length_enforced(self):
        with self.assertRaises(ValueError):
            MerkleSigner(token_bytes=lambda size: b"short")


class KeyShapeTest(unittest.TestCase):
    def test_public_key_shape(self):
        signer = make_signer(height=3)
        public_key = signer.public_key
        self.assertIsInstance(public_key, MerklePublicKey)
        self.assertIsInstance(public_key.root, bytes)
        self.assertEqual(len(public_key.root), 32)
        self.assertEqual(public_key.leaf_count, 8)

    def test_public_key_is_read_only(self):
        signer = make_signer()
        with self.assertRaises(AttributeError):
            signer.public_key = MerklePublicKey(w=4, height=2, root=b"\x00" * 32)

    def test_keys_are_frozen(self):
        signer = make_signer()
        signature = signer.sign("m")
        with self.assertRaises(AttributeError):
            signer.public_key.root = b"\x00" * 32
        with self.assertRaises(AttributeError):
            signature.index = 1
        with self.assertRaises(AttributeError):
            signature.auth_path = ()

    def test_known_answer_tree(self):
        # Rebuild the tree from the W-OTS public endpoints by hand.
        w, height, chains = 4, 2, 67
        signer = make_signer(height=height, w=w)
        leaves = []
        for leaf in range(1 << height):
            starts = tuple(
                (leaf * chains + j + 1).to_bytes(8, "big").rjust(32, b"\x00")
                for j in range(chains)
            )
            endpoints = tuple(_chain_walk(start, 15) for start in starts)
            leaves.append(_leaf_hash(w, endpoints))
        level = leaves
        while len(level) > 1:
            level = [
                _node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)
            ]
        self.assertEqual(signer.public_key.root, level[0])

    def test_bad_public_key_fields(self):
        with self.assertRaises(ValueError):
            MerklePublicKey(w=2, height=2, root=b"\x00" * 32)
        with self.assertRaises(ValueError):
            MerklePublicKey(w=4, height=0, root=b"\x00" * 32)
        with self.assertRaises(ValueError):
            MerklePublicKey(w=4, height=True, root=b"\x00" * 32)
        with self.assertRaises(ValueError):
            MerklePublicKey(w=4, height=2, root=b"short")
        with self.assertRaises(ValueError):
            MerklePublicKey(w=4, height=2, root=b"\x00" * 33)

    def test_bad_signature_fields(self):
        good = make_signer().sign("m")
        with self.assertRaises(ValueError):
            MerkleSignature(index=-1, wots_signature=good.wots_signature, auth_path=good.auth_path)
        with self.assertRaises(ValueError):
            MerkleSignature(index=True, wots_signature=good.wots_signature, auth_path=good.auth_path)
        with self.assertRaises(TypeError):
            MerkleSignature(index=0, wots_signature=list(good.wots_signature), auth_path=good.auth_path)
        with self.assertRaises(ValueError):
            MerkleSignature(index=0, wots_signature=(b"short",) * 67, auth_path=good.auth_path)
        with self.assertRaises(ValueError):
            MerkleSignature(index=0, wots_signature=good.wots_signature, auth_path=(b"short",) * 2)


class SignVerifyTest(unittest.TestCase):
    def test_round_trip_both_w(self):
        for w in (4, 8):
            with self.subTest(w=w):
                signer = make_signer(height=2, w=w)
                for message in (b"position claim", bytearray(b"position claim"), "position claim"):
                    signature = signer.sign(message)
                    self.assertIsInstance(signature, MerkleSignature)
                    self.assertTrue(merkle_verify(message, signature, signer.public_key))

    def test_indices_increase_from_zero(self):
        signer = make_signer(height=2)
        indices = [signer.sign(f"m{i}").index for i in range(4)]
        self.assertEqual(indices, [0, 1, 2, 3])

    def test_auth_path_shape(self):
        signer = make_signer(height=3)
        signature = signer.sign("m")
        self.assertEqual(len(signature.auth_path), 3)
        for node in signature.auth_path:
            self.assertIsInstance(node, bytes)
            self.assertEqual(len(node), 32)

    def test_auth_path_matches_leaf_order(self):
        # Path runs from the leaf level up: first sibling is the other leaf.
        signer = make_signer(height=2)
        first = signer.sign("one")
        second = signer.sign("two")
        self.assertEqual(first.index, 0)
        self.assertEqual(second.index, 1)
        self.assertNotEqual(first.auth_path[0], second.auth_path[0])
        # Leaves 0 and 1 share every ancestor above the leaf level.
        self.assertEqual(first.auth_path[1:], second.auth_path[1:])

    def test_every_leaf_verifies(self):
        signer = make_signer(height=3)
        for i in range(8):
            message = f"leaf-{i}"
            self.assertTrue(merkle_verify(message, signer.sign(message), signer.public_key))

    def test_different_message_fails(self):
        signer = make_signer()
        signature = signer.sign("position claim")
        self.assertFalse(merkle_verify("position claim!", signature, signer.public_key))

    def test_tampered_wots_element_fails(self):
        signer = make_signer()
        signature = signer.sign("m")
        tampered = bytearray(signature.wots_signature[0])
        tampered[0] ^= 0x01
        bad = replace(
            signature, wots_signature=(bytes(tampered),) + signature.wots_signature[1:]
        )
        self.assertFalse(merkle_verify("m", bad, signer.public_key))

    def test_tampered_auth_path_fails(self):
        signer = make_signer()
        signature = signer.sign("m")
        tampered = bytearray(signature.auth_path[0])
        tampered[0] ^= 0x01
        bad = replace(signature, auth_path=(bytes(tampered),) + signature.auth_path[1:])
        self.assertFalse(merkle_verify("m", bad, signer.public_key))

    def test_wrong_index_fails(self):
        signer = make_signer()
        signature = signer.sign("m")
        bad = replace(signature, index=signature.index + 1)
        self.assertFalse(merkle_verify("m", bad, signer.public_key))

    def test_truncated_and_extended_auth_path_fail(self):
        signer = make_signer()
        signature = signer.sign("m")
        short = replace(signature, auth_path=signature.auth_path[:-1])
        long = replace(signature, auth_path=signature.auth_path + (b"\x00" * 32,))
        self.assertFalse(merkle_verify("m", short, signer.public_key))
        self.assertFalse(merkle_verify("m", long, signer.public_key))

    def test_out_of_range_index_fails(self):
        signer = make_signer(height=2)
        signature = signer.sign("m")
        bad = replace(signature, index=4)
        self.assertFalse(merkle_verify("m", bad, signer.public_key))

    def test_tampered_root_fails(self):
        signer = make_signer()
        signature = signer.sign("m")
        root = bytearray(signer.public_key.root)
        root[0] ^= 0x01
        bad_key = replace(signer.public_key, root=bytes(root))
        self.assertFalse(merkle_verify("m", signature, bad_key))

    def test_other_tree_fails(self):
        signer = make_signer(start=0)
        other = make_signer(start=1000)
        signature = signer.sign("m")
        self.assertFalse(merkle_verify("m", signature, other.public_key))

    def test_w_mismatch_fails(self):
        signer4 = make_signer(w=4)
        signer8 = make_signer(w=8)
        signature = signer4.sign("m")
        self.assertFalse(merkle_verify("m", signature, signer8.public_key))

    def test_wrong_signature_lengths_fail(self):
        signer = make_signer()
        signature = signer.sign("m")
        short = replace(signature, wots_signature=signature.wots_signature[:-1])
        long = replace(signature, wots_signature=signature.wots_signature + (b"\x00" * 32,))
        self.assertFalse(merkle_verify("m", short, signer.public_key))
        self.assertFalse(merkle_verify("m", long, signer.public_key))

    def test_non_merkle_signature_fails(self):
        signer = make_signer()
        for bad in (object(), None, 42, "sig", (b"\x00" * 32,)):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(merkle_verify("m", bad, signer.public_key))

    def test_bad_message_type_returns_false(self):
        signer = make_signer()
        signature = signer.sign("m")
        self.assertFalse(merkle_verify(123, signature, signer.public_key))
        with self.assertRaises(TypeError):
            signer.sign(123)


class SignBatchTest(unittest.TestCase):
    def test_empty_tuple_returns_empty_and_keeps_state(self):
        signer = make_signer(height=2)
        self.assertEqual(signer.sign_batch(()), ())
        self.assertEqual(signer.sign("first").index, 0)

    def test_indices_are_consecutive_from_next_index(self):
        signer = make_signer(height=3)
        signer.sign("warm-up")
        batch = signer.sign_batch(("a", "b", "c"))
        self.assertIsInstance(batch, tuple)
        self.assertEqual([s.index for s in batch], [1, 2, 3])
        self.assertEqual(signer.sign("next").index, 4)

    def test_matches_sequential_signing_value_for_value(self):
        messages = ("m0", b"m1", bytearray(b"m2"), "m3")
        batched = make_signer(height=3).sign_batch(messages)
        sequential_signer = make_signer(height=3)
        sequential = tuple(sequential_signer.sign(m) for m in messages)
        self.assertEqual(batched, sequential)
        for message, signature in zip(messages, batched):
            self.assertTrue(
                merkle_verify(message, signature, sequential_signer.public_key)
            )

    def test_accepts_all_message_types(self):
        signer = make_signer(height=2)
        batch = signer.sign_batch((b"a", bytearray(b"b"), "c"))
        self.assertEqual(len(batch), 3)
        for message, signature in zip((b"a", b"b", b"c"), batch):
            self.assertTrue(merkle_verify(message, signature, signer.public_key))

    def test_non_tuple_rejected_without_state_change(self):
        signer = make_signer(height=2)
        for bad in (None, 42, "m", b"m", ["a", "b"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_batch(bad)
        self.assertEqual(signer.sign("first").index, 0)

    def test_bad_member_rejected_atomically(self):
        signer = make_signer(height=2)
        with self.assertRaises(TypeError):
            signer.sign_batch(("good", 123, "also good"))
        with self.assertRaises(TypeError):
            signer.sign_batch((object(),))
        # No leaf was consumed by either failed batch.
        self.assertEqual(signer.sign("first").index, 0)

    def test_insufficient_leaves_rejected_atomically(self):
        signer = make_signer(height=1)  # 2 leaves
        signer.sign("one")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch(("two", "three"))
        # The failed batch consumed nothing: the last leaf is still there.
        self.assertEqual(signer.sign("two").index, 1)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch(("x",))
        # An empty batch is still fine on an exhausted signer.
        self.assertEqual(signer.sign_batch(()), ())

    def test_exact_fit_batch_then_exhaustion(self):
        signer = make_signer(height=1)
        batch = signer.sign_batch(("one", "two"))
        self.assertEqual([s.index for s in batch], [0, 1])
        with self.assertRaises(KeyExhaustedError):
            signer.sign("three")

    def test_concurrent_batches_never_overlap(self):
        height = 3
        signer = make_signer(height=height)
        results = []
        errors = []
        lock = threading.Lock()
        barrier = threading.Barrier(4)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                batch = signer.sign_batch((f"m{i}a", f"m{i}b"))
                with lock:
                    results.extend(s.index for s in batch)
            except Exception as exc:  # pragma: no cover - failure path
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), list(range(1 << height)))

    def test_checkpoint_reflects_batch_state(self):
        signer = make_signer(height=2)
        signer.sign_batch(("a", "b"))
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        self.assertEqual(restored.sign("c").index, 2)


class TypeErrorTest(unittest.TestCase):
    def test_verify_requires_merkle_public_key(self):
        signer = make_signer()
        signature = signer.sign("m")
        _, wots_public = wots_keygen(token_bytes=counter_tokens())
        for bad_key in (object(), None, "key", wots_public, LamportPublicKey(())):
            with self.subTest(bad_key=type(bad_key).__name__):
                with self.assertRaises(TypeError):
                    merkle_verify("m", signature, bad_key)


class ExhaustionTest(unittest.TestCase):
    def test_exhaustion_raises(self):
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        with self.assertRaises(KeyExhaustedError):
            signer.sign("three")
        with self.assertRaises(RuntimeError):
            signer.sign("three")

    def test_failed_sign_does_not_consume_leaf(self):
        signer = make_signer(height=1)
        with self.assertRaises(TypeError):
            signer.sign(123)
        with self.assertRaises(TypeError):
            signer.sign(object())
        self.assertEqual(signer.sign("one").index, 0)
        self.assertEqual(signer.sign("two").index, 1)
        with self.assertRaises(KeyExhaustedError):
            signer.sign("three")

    def test_concurrent_signers_get_unique_leaves(self):
        height = 3
        signer = make_signer(height=height)
        results = []
        errors = []
        barrier = threading.Barrier(1 << height)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                results.append(signer.sign(f"m{i}").index)
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(1 << height)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), list(range(1 << height)))
        with self.assertRaises(KeyExhaustedError):
            signer.sign("one too many")

    def test_concurrent_oversubscription_never_duplicates(self):
        height = 2
        signer = make_signer(height=height)
        results = []
        exhausted = []
        lock = threading.Lock()
        barrier = threading.Barrier(2 << height)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                signature = signer.sign(f"m{i}")
                with lock:
                    results.append(signature.index)
            except KeyExhaustedError:
                with lock:
                    exhausted.append(i)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2 << height)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results), list(range(1 << height)))
        self.assertEqual(len(exhausted), 1 << height)


if __name__ == "__main__":
    unittest.main()

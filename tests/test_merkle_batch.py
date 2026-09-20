import threading
import unittest

from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    merkle_verify,
)


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=3, w=4):
    # Deterministic key material: two signers made this way share state.
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(0))


class SignBatchShapeTest(unittest.TestCase):
    def test_empty_batch_returns_empty_tuple_without_state_change(self):
        signer = make_signer()
        result = signer.sign_batch(())
        self.assertEqual(result, ())
        self.assertIsInstance(result, tuple)
        # State untouched: the next ordinary sign spends leaf 0.
        self.assertEqual(signer.sign(b"after").index, 0)

    def test_empty_batch_succeeds_even_when_exhausted(self):
        signer = make_signer(height=1)
        signer.sign(b"a")
        signer.sign(b"b")
        with self.assertRaises(KeyExhaustedError):
            signer.sign(b"c")
        self.assertEqual(signer.sign_batch(()), ())

    def test_returns_tuple_in_message_order(self):
        signer = make_signer()
        messages = (b"zero", "one", bytearray(b"two"))
        signatures = signer.sign_batch(messages)
        self.assertIsInstance(signatures, tuple)
        self.assertEqual(len(signatures), 3)
        self.assertEqual([sig.index for sig in signatures], [0, 1, 2])

    def test_indices_strictly_increasing_and_contiguous(self):
        signer = make_signer(height=3)
        signer.sign(b"before")
        signatures = signer.sign_batch(tuple(f"m{i}" for i in range(5)))
        self.assertEqual([sig.index for sig in signatures], [1, 2, 3, 4, 5])

    def test_each_signature_verifies_against_its_own_message(self):
        signer = make_signer()
        public_key = signer.public_key
        messages = (b"alpha", "beta", b"gamma", "delta")
        signatures = signer.sign_batch(messages)
        for message, signature in zip(messages, signatures):
            self.assertTrue(merkle_verify(message, signature, public_key))
        # Position i must not verify another member's message.
        self.assertFalse(
            merkle_verify(b"alpha", signatures[1], public_key)
        )


class SignBatchEquivalenceTest(unittest.TestCase):
    def test_batch_equals_sequential_sign_from_same_state(self):
        first = make_signer(height=3)
        second = make_signer(height=3)
        first.sign(b"shared-prefix")
        second.sign(b"shared-prefix")

        messages = (b"m0", "m1", bytearray(b"m2"), b"m3")
        batched = first.sign_batch(messages)
        sequential = tuple(second.sign(message) for message in messages)

        # Equal value: index, every W-OTS element and every auth node.
        self.assertEqual(batched, sequential)

    def test_state_after_batch_matches_sequential_signs(self):
        first = make_signer(height=2)
        second = make_signer(height=2)
        messages = (b"a", b"b", b"c")
        first.sign_batch(messages)
        for message in messages:
            second.sign(message)
        self.assertEqual(first.checkpoint(), second.checkpoint())

    def test_batch_then_sign_continues_at_next_leaf(self):
        signer = make_signer(height=2)
        signatures = signer.sign_batch((b"a", b"b"))
        self.assertEqual([sig.index for sig in signatures], [0, 1])
        self.assertEqual(signer.sign(b"c").index, 2)
        signatures = signer.sign_batch((b"d",))
        self.assertEqual(signatures[0].index, 3)
        with self.assertRaises(KeyExhaustedError):
            signer.sign(b"e")

    def test_exact_remaining_leaves_succeeds(self):
        signer = make_signer(height=2)
        signer.sign(b"one")
        signatures = signer.sign_batch((b"a", b"b", b"c"))
        self.assertEqual([sig.index for sig in signatures], [1, 2, 3])
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch((b"too many",))

    def test_encoding_unchanged(self):
        signer = make_signer(height=2)
        batched = signer.sign_batch((b"a", b"b"))
        for signature in batched:
            encoded = signature.to_bytes(signer.public_key)
            decoded = type(signature).from_bytes(encoded, signer.public_key)
            self.assertEqual(decoded, signature)


class SignBatchAtomicityTest(unittest.TestCase):
    def test_non_tuple_input_rejected(self):
        signer = make_signer()
        for bad in ([b"a", b"b"], b"ab", "ab", {b"a"}, iter((b"a", b"b")), None):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_batch(bad)
        # Nothing was spent.
        self.assertEqual(signer.sign(b"after").index, 0)

    def test_boolean_member_rejected_like_sign(self):
        signer = make_signer()
        with self.assertRaises(TypeError):
            signer.sign_batch((b"ok", True))
        self.assertEqual(signer.sign(b"after").index, 0)

    def test_illegal_member_anywhere_consumes_nothing(self):
        for position in range(3):
            signer = make_signer(height=2)
            messages = [b"a", b"b", b"c"]
            messages[position] = 123
            with self.subTest(position=position):
                with self.assertRaises(TypeError):
                    signer.sign_batch(tuple(messages))
                # Retry from the untouched state allocates leaves 0..2.
                signatures = signer.sign_batch((b"a", b"b", b"c"))
                self.assertEqual(
                    [sig.index for sig in signatures], [0, 1, 2]
                )

    def test_too_many_messages_consumes_nothing(self):
        signer = make_signer(height=2)
        signer.sign(b"prefix")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch((b"a", b"b", b"c", b"d"))
        # Still only the prefix leaf spent; the retry takes 1..3.
        signatures = signer.sign_batch((b"a", b"b", b"c"))
        self.assertEqual([sig.index for sig in signatures], [1, 2, 3])
        with self.assertRaises(KeyExhaustedError):
            signer.sign(b"last")

    def test_bad_message_takes_precedence_without_touching_leaves(self):
        # An over-large batch that also contains an illegal message is a
        # TypeError either way; afterwards the full leaf range is intact.
        signer = make_signer(height=1)
        with self.assertRaises(TypeError):
            signer.sign_batch((b"a", object()))
        signatures = signer.sign_batch((b"a", b"b"))
        self.assertEqual([sig.index for sig in signatures], [0, 1])


class SignBatchConcurrencyTest(unittest.TestCase):
    def test_concurrent_batches_never_share_leaves(self):
        height = 4  # 16 leaves
        threads_count = 4
        batch_size = 4
        signer = make_signer(height=height)
        results = []
        errors = []
        result_lock = threading.Lock()
        barrier = threading.Barrier(threads_count)

        def worker(worker_id):
            try:
                barrier.wait(timeout=10)
                signatures = signer.sign_batch(
                    tuple(f"w{worker_id}-m{j}" for j in range(batch_size))
                )
                with result_lock:
                    results.append(signatures)
            except Exception as exc:  # pragma: no cover - failure path
                with result_lock:
                    errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(i,))
            for i in range(threads_count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(results), threads_count)
        all_indices = sorted(
            signature.index
            for signatures in results
            for signature in signatures
        )
        self.assertEqual(all_indices, list(range(1 << height)))
        # Each batch itself stays contiguous and strictly increasing.
        for signatures in results:
            indices = [signature.index for signature in signatures]
            self.assertEqual(indices, list(range(indices[0], indices[0] + batch_size)))
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch((b"one too many",))

    def test_concurrent_oversubscription_has_no_duplicates_and_no_partial_state(self):
        height = 3  # 8 leaves
        threads_count = 5
        batch_size = 2
        signer = make_signer(height=height)
        taken = []
        exhausted = []
        guard = threading.Lock()
        barrier = threading.Barrier(threads_count)

        def worker(worker_id):
            try:
                barrier.wait(timeout=10)
                signatures = signer.sign_batch(
                    tuple(f"w{worker_id}-m{j}" for j in range(batch_size))
                )
                with guard:
                    taken.extend(signature.index for signature in signatures)
            except KeyExhaustedError:
                with guard:
                    exhausted.append(worker_id)

        threads = [
            threading.Thread(target=worker, args=(i,))
            for i in range(threads_count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(sorted(taken), list(range(1 << height)))
        self.assertEqual(len(exhausted), threads_count - (1 << height) // batch_size)
        # No partial allocation left the signer half-spendable: all leaves used.
        with self.assertRaises(KeyExhaustedError):
            signer.sign(b"final")


if __name__ == "__main__":
    unittest.main()

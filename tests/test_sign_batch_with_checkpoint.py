import threading
import unittest

from pqattest import KeyExhaustedError, MerkleSignature, MerkleSigner, merkle_verify


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


class SignBatchWithCheckpointTest(unittest.TestCase):
    def test_returns_signatures_tuple_and_bytes(self):
        signer = make_signer()
        signatures, blob = signer.sign_batch_with_checkpoint(("a", "b"))
        self.assertIsInstance(signatures, tuple)
        self.assertEqual(len(signatures), 2)
        for signature in signatures:
            self.assertIsInstance(signature, MerkleSignature)
        self.assertIsInstance(blob, bytes)

    def test_signatures_match_sign_batch_from_same_state(self):
        signer = make_signer()
        reference = make_signer()
        messages = ("one", "two", "three")
        signatures, _ = signer.sign_batch_with_checkpoint(messages)
        self.assertEqual(signatures, reference.sign_batch(messages))

    def test_indices_are_strictly_increasing(self):
        signer = make_signer()
        signer.sign("skipped")
        before = signer.next_index
        messages = ("a", "b", "c")
        signatures, blob = signer.sign_batch_with_checkpoint(messages)
        self.assertEqual(
            [signature.index for signature in signatures],
            [before, before + 1, before + 2],
        )
        self.assertEqual(signer.next_index, before + 3)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), before + 3)

    def test_checkpoint_matches_post_batch_checkpoint(self):
        signer = make_signer()
        reference = make_signer()
        messages = ("one", "two")
        _, blob = signer.sign_batch_with_checkpoint(messages)
        reference.sign_batch(messages)
        self.assertEqual(blob, reference.checkpoint())

    def test_checkpoint_restores_advanced_signer(self):
        signer = make_signer()
        messages = ("one", "two", "three")
        signatures, blob = signer.sign_batch_with_checkpoint(messages)
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, signatures[-1].index + 1)
        for message, signature in zip(messages, signatures):
            self.assertTrue(merkle_verify(message, signature, signer.public_key))

    def test_accepts_bytes_bytearray_and_str_members(self):
        signer = make_signer(height=2)
        messages = (b"m", bytearray(b"m"), "m")
        signatures, blob = signer.sign_batch_with_checkpoint(messages)
        for signature in signatures:
            self.assertTrue(merkle_verify(b"m", signature, signer.public_key))
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.next_index, signatures[-1].index + 1)

    def test_empty_batch_returns_empty_tuple_and_unchanged_checkpoint(self):
        signer = make_signer()
        signer.sign("spent")
        before = signer.next_index
        signatures, blob = signer.sign_batch_with_checkpoint(())
        self.assertEqual(signatures, ())
        self.assertEqual(signer.next_index, before)
        self.assertEqual(blob, signer.checkpoint())
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.next_index, before)

    def test_empty_batch_on_exhausted_signer_still_snapshots(self):
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        signatures, blob = signer.sign_batch_with_checkpoint(())
        self.assertEqual(signatures, ())
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)

    def test_invalid_messages_type_raises_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, "m", b"m", [b"m"], {"m": 1}, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_batch_with_checkpoint(bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_message_member_raises_without_spending(self):
        signer = make_signer()
        for bad in (("good", 123, "also good"), (object(),), (b"m", None)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    signer.sign_batch_with_checkpoint(bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_all_members_validated_before_capacity_check(self):
        # An exhausted signer must still reject bad input with the input
        # error, not KeyExhaustedError.
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        with self.assertRaises(TypeError):
            signer.sign_batch_with_checkpoint(("m", 1))
        with self.assertRaises(TypeError):
            signer.sign_batch_with_checkpoint([b"m"])
        self.assertEqual(signer.next_index, 2)

    def test_oversized_batch_raises_without_partial_result(self):
        signer = make_signer(height=1)
        signer.sign("one")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_with_checkpoint(("two", "three"))
        self.assertEqual(signer.next_index, 1)
        signatures, blob = signer.sign_batch_with_checkpoint(("two",))
        self.assertEqual([s.index for s in signatures], [1])
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_with_checkpoint(("x",))
        self.assertEqual(signer.next_index, 2)
        self.assertEqual(signer.remaining, 0)

    def test_draws_no_extra_randomness(self):
        tokens = counter_tokens()
        signer = MerkleSigner(height=2, w=4, token_bytes=tokens)

        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_batch_with_checkpoint must not draw randomness"
            )

        import pqattest.merkle
        from unittest import mock

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            signatures, blob = signer.sign_batch_with_checkpoint(("a", "b"))
        self.assertEqual([s.index for s in signatures], [0, 1])
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)


class SignBatchWithCheckpointConcurrencyTest(unittest.TestCase):
    def test_linearises_with_all_state_operations(self):
        height = 4
        leaf_count = 1 << height
        signer = make_signer(height=height)
        results = []
        snapshots = []
        reads = []
        errors = []
        exhausted = []
        barrier = threading.Barrier(leaf_count)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                if i == leaf_count - 1:
                    # Jumping to the leaf count always succeeds and voids
                    # whatever the signers have not spent yet.
                    signer.advance_to(leaf_count)
                elif i % 4 == 0:
                    messages = (f"m{i}a", f"m{i}b")
                    signatures, blob = signer.sign_batch_with_checkpoint(messages)
                    results.append((messages, signatures, blob))
                elif i % 4 == 1:
                    signer.sign(f"m{i}")
                elif i % 4 == 2:
                    snapshots.append(signer.checkpoint())
                else:
                    reads.append((signer.next_index, signer.remaining))
            except KeyExhaustedError:
                # Expected when the advance-to-end worker wins the race.
                exhausted.append(i)
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(leaf_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])

        # Every successful batch got distinct consecutive leaves, and every
        # leaf was accounted for exactly once by a sign or the advance.
        used = sorted(
            signature.index for _, signatures, _ in results for signature in signatures
        )
        self.assertEqual(len(used), len(set(used)))
        self.assertLessEqual(len(used) + len(exhausted), leaf_count)
        self.assertEqual(signer.next_index, leaf_count)
        self.assertEqual(signer.remaining, 0)
        for next_index, remaining in reads:
            self.assertTrue(0 <= next_index <= leaf_count)
            self.assertTrue(0 <= remaining <= leaf_count)

        # Each checkpoint matches the state immediately after its own batch.
        for messages, signatures, blob in results:
            with self.subTest(indices=[s.index for s in signatures]):
                restored = MerkleSigner.from_checkpoint(blob)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertEqual(restored.next_index, signatures[-1].index + 1)
                for message, signature in zip(messages, signatures):
                    self.assertTrue(
                        merkle_verify(message, signature, signer.public_key)
                    )
        for blob in snapshots:
            restored = MerkleSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)


if __name__ == "__main__":
    unittest.main()

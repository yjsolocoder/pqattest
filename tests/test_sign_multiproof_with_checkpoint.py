import threading
import unittest

from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    multiproof_encode,
    multiproof_verify,
)


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


class SignMultiproofWithCheckpointTest(unittest.TestCase):
    def test_returns_proof_bytes_and_checkpoint_bytes(self):
        signer = make_signer()
        proof, blob = signer.sign_multiproof_with_checkpoint(("a", "b"))
        self.assertIsInstance(proof, bytes)
        self.assertIsInstance(blob, bytes)

    def test_proof_matches_multiproof_encode_of_sign_batch_from_same_state(self):
        signer = make_signer()
        reference = make_signer()
        messages = ("one", "two", "three")
        proof, _ = signer.sign_multiproof_with_checkpoint(messages)
        signatures = reference.sign_batch(messages)
        self.assertEqual(
            proof, multiproof_encode(reference.public_key, signatures)
        )

    def test_proof_verifies_against_the_signed_messages(self):
        signer = make_signer()
        messages = (b"claim 0", bytearray(b"claim 1"), "claim 2")
        proof, _ = signer.sign_multiproof_with_checkpoint(messages)
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertTrue(multiproof_verify((b"claim 0", b"claim 1", b"claim 2"), proof))
        self.assertFalse(
            multiproof_verify((b"claim 0", b"claim 1", b"other"), proof)
        )

    def test_leaves_are_consecutive_from_next_index(self):
        signer = make_signer()
        signer.sign("skipped")
        before = signer.next_index
        messages = ("a", "b", "c")
        proof, blob = signer.sign_multiproof_with_checkpoint(messages)
        self.assertEqual(signer.next_index, before + 3)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), before + 3)
        reference = make_signer()
        reference.advance_to(before)
        signatures = reference.sign_batch(messages)
        self.assertEqual(
            [signature.index for signature in signatures],
            [before, before + 1, before + 2],
        )
        self.assertEqual(proof, multiproof_encode(reference.public_key, signatures))

    def test_checkpoint_matches_post_batch_checkpoint(self):
        signer = make_signer()
        reference = make_signer()
        messages = ("one", "two")
        _, blob = signer.sign_multiproof_with_checkpoint(messages)
        reference.sign_batch(messages)
        self.assertEqual(blob, reference.checkpoint())

    def test_checkpoint_restores_advanced_signer(self):
        signer = make_signer()
        messages = ("one", "two", "three")
        proof, blob = signer.sign_multiproof_with_checkpoint(messages)
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, signer.next_index)
        self.assertTrue(multiproof_verify(messages, proof))

    def test_single_message_batch(self):
        signer = make_signer()
        proof, blob = signer.sign_multiproof_with_checkpoint(("only",))
        self.assertTrue(multiproof_verify(("only",), proof))
        self.assertEqual(signer.next_index, 1)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 1)

    def test_invalid_messages_type_raises_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, "m", b"m", [b"m"], {"m": 1}, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_multiproof_with_checkpoint(bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_message_member_raises_without_spending(self):
        signer = make_signer()
        for bad in (("good", 123, "also good"), (object(),), (b"m", None)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    signer.sign_multiproof_with_checkpoint(bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_empty_messages_raises_without_spending(self):
        signer = make_signer()
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_checkpoint(())
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_all_members_validated_before_capacity_check(self):
        # An exhausted signer must still reject bad input with the input
        # error, not KeyExhaustedError.
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        with self.assertRaises(TypeError):
            signer.sign_multiproof_with_checkpoint(("m", 1))
        with self.assertRaises(TypeError):
            signer.sign_multiproof_with_checkpoint([b"m"])
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_checkpoint(())
        self.assertEqual(signer.next_index, 2)

    def test_oversized_batch_raises_without_partial_result(self):
        signer = make_signer(height=1)
        signer.sign("one")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_multiproof_with_checkpoint(("two", "three"))
        self.assertEqual(signer.next_index, 1)
        proof, blob = signer.sign_multiproof_with_checkpoint(("two",))
        self.assertTrue(multiproof_verify(("two",), proof))
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_multiproof_with_checkpoint(("x",))
        self.assertEqual(signer.next_index, 2)
        self.assertEqual(signer.remaining, 0)

    def test_draws_no_extra_randomness(self):
        tokens = counter_tokens()
        signer = MerkleSigner(height=2, w=4, token_bytes=tokens)

        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_multiproof_with_checkpoint must not draw randomness"
            )

        import pqattest.merkle
        from unittest import mock

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            proof, blob = signer.sign_multiproof_with_checkpoint(("a", "b"))
        self.assertTrue(multiproof_verify(("a", "b"), proof))
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)


class SignMultiproofWithCheckpointConcurrencyTest(unittest.TestCase):
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
                    proof, blob = signer.sign_multiproof_with_checkpoint(messages)
                    results.append((messages, proof, blob))
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

        self.assertEqual(signer.next_index, leaf_count)
        self.assertEqual(signer.remaining, 0)
        for next_index, remaining in reads:
            self.assertTrue(0 <= next_index <= leaf_count)
            self.assertTrue(0 <= remaining <= leaf_count)

        # Each proof verifies against its own messages, and each checkpoint
        # restores a signer whose next_index sits right after that batch's
        # consecutive leaves (the first leaf index is read back from the
        # proof's first leaf block).
        for messages, proof, blob in results:
            with self.subTest(messages=messages):
                self.assertTrue(multiproof_verify(messages, proof))
                restored = MerkleSigner.from_checkpoint(blob)
                self.assertEqual(restored.public_key, signer.public_key)
                key_length = int.from_bytes(proof[9:13], "big")
                first_index = int.from_bytes(
                    proof[17 + key_length : 19 + key_length], "big"
                )
                self.assertEqual(restored.next_index, first_index + len(messages))
        for blob in snapshots:
            restored = MerkleSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)


if __name__ == "__main__":
    unittest.main()

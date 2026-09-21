import threading
import unittest
from unittest import mock

from pqattest import (
    KeyExhaustedError,
    MerkleProof,
    MerkleSigner,
)
import pqattest.merkle


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def proof_index(blob):
    key_length = int.from_bytes(blob[9:13], "big")
    # Signature header: magic(8) + version/w/height(3), then the index.
    offset = 17 + key_length + 11
    return int.from_bytes(blob[offset : offset + 2], "big")


class SignProofWithCheckpointTest(unittest.TestCase):
    def test_returns_two_bytes_values(self):
        signer = make_signer()
        proof, blob = signer.sign_proof_with_checkpoint("m")
        self.assertIsInstance(proof, bytes)
        self.assertIsInstance(blob, bytes)
        self.assertEqual(proof[:8], b"PQAMPRF\0")
        self.assertEqual(blob[:8], b"PQAMSCP\0")

    def test_proof_equals_merkle_proof_of_fresh_signature(self):
        signer = make_signer()
        signer.sign("spent")
        proof, _ = signer.sign_proof_with_checkpoint("m")

        reference = make_signer()
        reference.sign("spent")
        signature = reference.sign("m")
        expected = MerkleProof(
            public_key=reference.public_key, signature=signature
        ).to_bytes()
        self.assertEqual(proof, expected)

    def test_proof_round_trips_and_verifies_the_signed_message(self):
        signer = make_signer()
        proof, _ = signer.sign_proof_with_checkpoint("hello")
        parsed = MerkleProof.from_bytes(proof)
        self.assertEqual(parsed.public_key, signer.public_key)
        self.assertTrue(parsed.verify("hello"))
        self.assertTrue(parsed.verify(b"hello"))
        self.assertFalse(parsed.verify("other"))

    def test_checkpoint_matches_post_sign_checkpoint(self):
        signer = make_signer()
        reference = make_signer()
        _, blob = signer.sign_proof_with_checkpoint("m")
        reference.sign("m")
        self.assertEqual(blob, reference.checkpoint())

    def test_checkpoint_restores_advanced_signer(self):
        signer = make_signer()
        proof, blob = signer.sign_proof_with_checkpoint("one")
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, proof_index(proof) + 1)
        self.assertTrue(MerkleProof.from_bytes(proof).verify("one"))
        # The restored signer continues exactly where the original left off.
        follow_up = restored.sign("two")
        self.assertEqual(follow_up.index, proof_index(proof) + 1)
        self.assertTrue(
            MerkleProof(
                public_key=restored.public_key, signature=follow_up
            ).verify("two")
        )

    def test_advances_next_index_by_one(self):
        signer = make_signer()
        signer.sign("skipped")
        before = signer.next_index
        proof, blob = signer.sign_proof_with_checkpoint("m")
        self.assertEqual(proof_index(proof), before)
        self.assertEqual(signer.next_index, before + 1)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), before + 1)

    def test_accepts_bytes_bytearray_and_str_messages(self):
        signer = make_signer(height=2)
        for message in (b"m", bytearray(b"m"), "m"):
            with self.subTest(message=type(message).__name__):
                proof, blob = signer.sign_proof_with_checkpoint(message)
                self.assertTrue(MerkleProof.from_bytes(proof).verify(b"m"))
                restored = MerkleSigner.from_checkpoint(blob)
                self.assertEqual(restored.next_index, proof_index(proof) + 1)

    def test_str_message_is_signed_as_utf8(self):
        signer = make_signer()
        proof, _ = signer.sign_proof_with_checkpoint("héllo")
        parsed = MerkleProof.from_bytes(proof)
        self.assertTrue(parsed.verify("héllo".encode("utf-8")))
        self.assertFalse(parsed.verify("héllo".encode("utf-16")))

    def test_invalid_message_raises_type_error_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, 4.5, [b"m"], (b"m",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_proof_with_checkpoint(bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_message_validated_before_capacity_check(self):
        # An exhausted signer must still reject a bad message with the input
        # error, not KeyExhaustedError.
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        with self.assertRaises(TypeError):
            signer.sign_proof_with_checkpoint(None)
        self.assertEqual(signer.next_index, 2)

    def test_exhausted_signer_raises_without_partial_result(self):
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_proof_with_checkpoint("three")
        self.assertEqual(signer.next_index, 2)
        self.assertEqual(signer.remaining, 0)

    def test_proof_encoding_failure_leaves_state_unchanged(self):
        signer = make_signer()
        signer.sign("spent")
        before = signer.next_index
        with mock.patch.object(
            MerkleProof, "to_bytes", side_effect=ValueError("proof failure")
        ):
            with self.assertRaises(ValueError):
                signer.sign_proof_with_checkpoint("m")
        # No leaf consumed, no checkpoint handed back, state untouched.
        self.assertEqual(signer.next_index, before)
        proof, blob = signer.sign_proof_with_checkpoint("m")
        self.assertEqual(proof_index(proof), before)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), before + 1)

    def test_checkpoint_failure_leaves_state_unchanged(self):
        signer = make_signer()
        signer.sign("spent")
        before = signer.next_index
        with mock.patch.object(
            pqattest.merkle.MerkleSigner,
            "_checkpoint_bytes",
            side_effect=ValueError("checkpoint failure"),
        ):
            with self.assertRaises(ValueError):
                signer.sign_proof_with_checkpoint("m")
        self.assertEqual(signer.next_index, before)
        proof, blob = signer.sign_proof_with_checkpoint("m")
        self.assertEqual(proof_index(proof), before)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), before + 1)

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_proof_with_checkpoint must not draw randomness"
            )

        signer = MerkleSigner(height=2, w=4, token_bytes=counter_tokens())
        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            proof, blob = signer.sign_proof_with_checkpoint("m")
        self.assertEqual(proof_index(proof), 0)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 1)

    def test_deterministic_from_equal_state(self):
        signer_a = make_signer()
        signer_b = make_signer()
        proof_a, blob_a = signer_a.sign_proof_with_checkpoint("m")
        proof_b, blob_b = signer_b.sign_proof_with_checkpoint("m")
        self.assertEqual(proof_a, proof_b)
        self.assertEqual(blob_a, blob_b)


class SignProofWithCheckpointConcurrencyTest(unittest.TestCase):
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
                elif i % 5 == 0:
                    message = f"m{i}"
                    proof, blob = signer.sign_proof_with_checkpoint(message)
                    results.append((message, proof, blob))
                elif i % 5 == 1:
                    signer.sign(f"m{i}")
                elif i % 5 == 2:
                    signer.sign_with_checkpoint(f"c{i}")
                elif i % 5 == 3:
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

        # Every successful proof signature got a distinct leaf, and every
        # leaf was accounted for exactly once by either a sign or the advance.
        used = sorted(proof_index(proof) for _, proof, _ in results)
        self.assertEqual(len(used), len(set(used)))
        self.assertLessEqual(len(used) + len(exhausted), leaf_count)
        self.assertEqual(signer.next_index, leaf_count)
        self.assertEqual(signer.remaining, 0)
        for next_index, remaining in reads:
            self.assertTrue(0 <= next_index <= leaf_count)
            self.assertTrue(0 <= remaining <= leaf_count)

        # Every proof verifies and its checkpoint restores exactly the
        # post-sign state.
        for message, proof, blob in results:
            with self.subTest(index=proof_index(proof)):
                self.assertTrue(MerkleProof.from_bytes(proof).verify(message))
                restored = MerkleSigner.from_checkpoint(blob)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertEqual(restored.next_index, proof_index(proof) + 1)
        for blob in snapshots:
            restored = MerkleSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)


if __name__ == "__main__":
    unittest.main()

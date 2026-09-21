import threading
import unittest
from unittest import mock

from pqattest import (
    KeyExhaustedError,
    MerkleBatchProof,
    MerkleSigner,
)
import pqattest.merkle
from pqattest.merkle import _BATCH_PROOF_HEADER_BYTES


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def leaf_indices(blob):
    key_length = int.from_bytes(blob[9:13], "big")
    sig_count = int.from_bytes(blob[13:15], "big")
    offset = _BATCH_PROOF_HEADER_BYTES + key_length
    indices = []
    for _ in range(sig_count):
        sig_length = int.from_bytes(blob[offset : offset + 4], "big")
        sig_start = offset + 4
        # Signature: magic(8) + version/w/height(3), then the 2-byte index.
        indices.append(int.from_bytes(blob[sig_start + 11 : sig_start + 13], "big"))
        offset = sig_start + sig_length
    return indices


class SignBatchProofWithCheckpointTest(unittest.TestCase):
    def test_returns_two_bytes_values(self):
        signer = make_signer()
        proof, blob = signer.sign_batch_proof_with_checkpoint(("a", "b"))
        self.assertIsInstance(proof, bytes)
        self.assertIsInstance(blob, bytes)
        self.assertEqual(proof[:8], b"PQAMBAT\0")
        self.assertEqual(blob[:8], b"PQAMSCP\0")

    def test_proof_equals_batch_proof_of_consecutive_signatures(self):
        signer = make_signer()
        signer.sign("spent")
        messages = ("one", "two", "three")
        proof, _ = signer.sign_batch_proof_with_checkpoint(messages)

        reference = make_signer()
        reference.sign("spent")
        signatures = reference.sign_batch(messages)
        expected = MerkleBatchProof(
            public_key=reference.public_key, signatures=signatures
        ).to_bytes()
        self.assertEqual(proof, expected)

    def test_proof_round_trips_and_verifies_the_signed_messages(self):
        signer = make_signer(height=3)
        messages = ("one", b"two", bytearray(b"three"))
        proof, blob = signer.sign_batch_proof_with_checkpoint(messages)
        parsed = MerkleBatchProof.from_bytes(proof)
        self.assertEqual(parsed.public_key, signer.public_key)
        self.assertEqual(len(parsed.signatures), 3)
        self.assertTrue(parsed.verify(("one", b"two", b"three")))
        self.assertTrue(parsed.verify(("one", bytearray(b"two"), b"three")))
        self.assertFalse(parsed.verify(("one", "other", b"three")))
        self.assertFalse(parsed.verify(("one", b"two")))
        # A bytearray copy of the encoding parses identically.
        self.assertEqual(
            MerkleBatchProof.from_bytes(bytearray(proof)).signatures,
            parsed.signatures,
        )

    def test_str_members_are_utf8_encoded(self):
        signer = make_signer()
        messages = ("héllo",)
        proof, _ = signer.sign_batch_proof_with_checkpoint(messages)
        parsed = MerkleBatchProof.from_bytes(proof)
        self.assertTrue(parsed.verify(("héllo",)))
        self.assertTrue(parsed.verify((b"h\xc3\xa9llo",)))
        self.assertFalse(parsed.verify(("hEllo",)))

    def test_checkpoint_matches_post_batch_checkpoint(self):
        signer = make_signer()
        reference = make_signer()
        messages = ("one", "two")
        _, blob = signer.sign_batch_proof_with_checkpoint(messages)
        reference.sign_batch(messages)
        self.assertEqual(blob, reference.checkpoint())

    def test_checkpoint_restores_advanced_signer(self):
        signer = make_signer(height=3)
        messages = ("one", "two", "three")
        proof, blob = signer.sign_batch_proof_with_checkpoint(messages)
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 3)
        self.assertTrue(MerkleBatchProof.from_bytes(proof).verify(messages))
        # The restored signer continues exactly where the original left off.
        self.assertEqual(restored.sign("fourth").index, 3)

    def test_leaves_are_consecutive_from_current_next_index(self):
        signer = make_signer(height=4)
        signer.sign_batch(("s0", "s1"))
        before = signer.next_index
        messages = ("a", "b", "c")
        proof, blob = signer.sign_batch_proof_with_checkpoint(messages)
        self.assertEqual(leaf_indices(proof), [before, before + 1, before + 2])
        self.assertEqual(signer.next_index, before + 3)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), before + 3)

    def test_single_message_is_a_valid_one_signature_batch_proof(self):
        signer = make_signer()
        proof, blob = signer.sign_batch_proof_with_checkpoint(("only",))
        self.assertEqual(int.from_bytes(proof[13:15], "big"), 1)
        self.assertTrue(MerkleBatchProof.from_bytes(proof).verify(("only",)))
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 1)

    def test_accepts_bytes_bytearray_and_str_members(self):
        signer = make_signer(height=2)
        messages = (b"m", bytearray(b"m"), "m")
        proof, blob = signer.sign_batch_proof_with_checkpoint(messages)
        self.assertTrue(MerkleBatchProof.from_bytes(proof).verify((b"m", b"m", b"m")))
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.next_index, 3)

    def test_non_tuple_raises_type_error_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, "m", b"m", [b"m"], {"m": 1}, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_batch_proof_with_checkpoint(bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_illegal_member_raises_type_error_without_spending(self):
        signer = make_signer()
        for bad in (("good", 123), (object(),), (b"m", None)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    signer.sign_batch_proof_with_checkpoint(bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_empty_tuple_raises_value_error_without_spending(self):
        signer = make_signer()
        signer.sign("spent")
        before = signer.next_index
        with self.assertRaises(ValueError):
            signer.sign_batch_proof_with_checkpoint(())
        self.assertEqual(signer.next_index, before)
        self.assertEqual(signer.sign("m").index, before)

    def test_all_members_validated_before_capacity_check(self):
        # An exhausted signer must still reject bad input with the input
        # error, not KeyExhaustedError.
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        with self.assertRaises(TypeError):
            signer.sign_batch_proof_with_checkpoint(("m", 1))
        with self.assertRaises(TypeError):
            signer.sign_batch_proof_with_checkpoint([b"m"])
        with self.assertRaises(ValueError):
            signer.sign_batch_proof_with_checkpoint(())
        self.assertEqual(signer.next_index, 2)

    def test_oversized_tuple_raises_without_partial_result(self):
        signer = make_signer(height=1)
        signer.sign("one")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_proof_with_checkpoint(("two", "three"))
        self.assertEqual(signer.next_index, 1)
        proof, blob = signer.sign_batch_proof_with_checkpoint(("two",))
        self.assertEqual(leaf_indices(proof), [1])
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_proof_with_checkpoint(("x",))
        self.assertEqual(signer.next_index, 2)
        self.assertEqual(signer.remaining, 0)

    def test_proof_failure_raises_without_spending_or_advancing(self):
        signer = make_signer()
        signer.sign("spent")
        before = signer.next_index
        with mock.patch.object(
            MerkleBatchProof, "to_bytes", side_effect=ValueError("proof failure")
        ):
            with self.assertRaises(ValueError):
                signer.sign_batch_proof_with_checkpoint(("a", "b"))
        # No leaf consumed, no checkpoint handed back, state untouched.
        self.assertEqual(signer.next_index, before)
        proof, blob = signer.sign_batch_proof_with_checkpoint(("a", "b"))
        self.assertEqual(leaf_indices(proof), [before, before + 1])
        self.assertEqual(int.from_bytes(blob[11:13], "big"), before + 2)

    def test_checkpoint_failure_raises_without_spending_or_advancing(self):
        signer = make_signer()
        signer.sign("spent")
        before = signer.next_index
        with mock.patch.object(
            MerkleSigner,
            "_checkpoint_bytes",
            side_effect=ValueError("checkpoint failure"),
        ):
            with self.assertRaises(ValueError):
                signer.sign_batch_proof_with_checkpoint(("a", "b"))
        # The index commits only after both outputs have been built.
        self.assertEqual(signer.next_index, before)
        proof, blob = signer.sign_batch_proof_with_checkpoint(("a", "b"))
        self.assertEqual(leaf_indices(proof), [before, before + 1])
        self.assertEqual(signer.next_index, before + 2)

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_batch_proof_with_checkpoint must not draw randomness"
            )

        signer = MerkleSigner(height=2, w=4, token_bytes=counter_tokens())
        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            proof, blob = signer.sign_batch_proof_with_checkpoint(("a", "b"))
        self.assertEqual(leaf_indices(proof), [0, 1])
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)

    def test_deterministic_from_equal_state(self):
        messages = ("a", "b", "c")
        signer_a = make_signer()
        signer_b = make_signer()
        proof_a, blob_a = signer_a.sign_batch_proof_with_checkpoint(messages)
        proof_b, blob_b = signer_b.sign_batch_proof_with_checkpoint(messages)
        self.assertEqual(proof_a, proof_b)
        self.assertEqual(blob_a, blob_b)


class SignBatchProofWithCheckpointConcurrencyTest(unittest.TestCase):
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
                    messages = (f"m{i}a", f"m{i}b")
                    proof, blob = signer.sign_batch_proof_with_checkpoint(messages)
                    results.append((messages, proof, blob))
                elif i % 5 == 1:
                    signer.sign(f"m{i}")
                elif i % 5 == 2:
                    signer.sign_batch((f"b{i}a", f"b{i}b"))
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

        used = sorted(
            index
            for _, proof, _ in results
            for index in leaf_indices(proof)
        )
        self.assertEqual(len(used), len(set(used)))
        self.assertLessEqual(len(used) + len(exhausted), leaf_count)
        self.assertEqual(signer.next_index, leaf_count)
        self.assertEqual(signer.remaining, 0)
        for next_index, remaining in reads:
            self.assertTrue(0 <= next_index <= leaf_count)
            self.assertTrue(0 <= remaining <= leaf_count)

        # Every proof verifies against its messages and its checkpoint
        # restores exactly the post-proof state.
        for messages, proof, blob in results:
            with self.subTest(indices=leaf_indices(proof)):
                self.assertTrue(MerkleBatchProof.from_bytes(proof).verify(messages))
                restored = MerkleSigner.from_checkpoint(blob)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertEqual(
                    restored.next_index, leaf_indices(proof)[-1] + 1
                )
        for blob in snapshots:
            restored = MerkleSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)


if __name__ == "__main__":
    unittest.main()

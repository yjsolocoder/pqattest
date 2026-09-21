import threading
import unittest
from unittest import mock

from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    merkle_verify,
    multiproof_encode,
    multiproof_verify,
)
import pqattest.merkle
from pqattest.merkle import _MULTIPROOF_HEADER_BYTES


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
    leaf_count = int.from_bytes(blob[13:15], "big")
    offset = _MULTIPROOF_HEADER_BYTES + key_length
    indices = []
    for _ in range(leaf_count):
        indices.append(int.from_bytes(blob[offset : offset + 2], "big"))
        element_count = int.from_bytes(blob[offset + 2 : offset + 4], "big")
        offset += 4 + element_count * 32
    return indices


class SignMultiproofWithCheckpointTest(unittest.TestCase):
    def test_returns_two_bytes_values(self):
        signer = make_signer()
        proof, blob = signer.sign_multiproof_with_checkpoint(("a", "b"))
        self.assertIsInstance(proof, bytes)
        self.assertIsInstance(blob, bytes)
        self.assertEqual(proof[:8], b"PQAMMUL\0")
        self.assertEqual(blob[:8], b"PQAMSCP\0")

    def test_proof_equals_multiproof_encode_of_consecutive_signatures(self):
        signer = make_signer()
        signer.sign("spent")
        messages = ("one", "two", "three")
        proof, _ = signer.sign_multiproof_with_checkpoint(messages)

        reference = make_signer()
        reference.sign("spent")
        signatures = reference.sign_batch(messages)
        self.assertEqual(
            proof, multiproof_encode(reference.public_key, signatures)
        )

    def test_proof_verifies_with_existing_multiproof_verify(self):
        signer = make_signer(height=3)
        messages = tuple(f"m{i}" for i in (0, 2, 3))
        proof, blob = signer.sign_multiproof_with_checkpoint(messages)
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertTrue(multiproof_verify(messages, bytearray(proof)))
        self.assertFalse(multiproof_verify(tuple("x" for _ in messages), proof))

    def test_leaves_are_consecutive_from_current_next_index(self):
        signer = make_signer(height=4)
        signer.sign_batch(("s0", "s1"))
        before = signer.next_index
        messages = ("a", "b", "c")
        proof, blob = signer.sign_multiproof_with_checkpoint(messages)
        self.assertEqual(leaf_indices(proof), [before, before + 1, before + 2])
        self.assertEqual(signer.next_index, before + 3)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), before + 3)

    def test_checkpoint_matches_post_batch_checkpoint(self):
        signer = make_signer()
        reference = make_signer()
        messages = ("one", "two")
        _, blob = signer.sign_multiproof_with_checkpoint(messages)
        reference.sign_batch(messages)
        self.assertEqual(blob, reference.checkpoint())

    def test_checkpoint_restores_advanced_signer(self):
        signer = make_signer(height=3)
        messages = ("one", "two", "three")
        proof, blob = signer.sign_multiproof_with_checkpoint(messages)
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 3)
        self.assertTrue(multiproof_verify(messages, proof))
        # The restored signer continues exactly where the original left off.
        self.assertEqual(restored.sign("fourth").index, 3)

    def test_single_message_is_a_valid_one_leaf_multiproof(self):
        signer = make_signer()
        proof, blob = signer.sign_multiproof_with_checkpoint(("only",))
        self.assertEqual(int.from_bytes(proof[13:15], "big"), 1)
        self.assertTrue(multiproof_verify(("only",), proof))
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 1)

    def test_accepts_bytes_bytearray_and_str_members(self):
        signer = make_signer(height=2)
        messages = (b"m", bytearray(b"m"), "m")
        proof, blob = signer.sign_multiproof_with_checkpoint(messages)
        self.assertTrue(multiproof_verify((b"m", b"m", b"m"), proof))
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.next_index, 3)

    def test_full_tree_dedupes_every_node(self):
        height = 3
        signer = make_signer(height=height)
        messages = tuple(f"m{i}" for i in range(1 << height))
        proof, _ = signer.sign_multiproof_with_checkpoint(messages)
        self.assertEqual(int.from_bytes(proof[15:17], "big"), 0)
        self.assertTrue(multiproof_verify(messages, proof))

    def test_non_tuple_raises_type_error_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, "m", b"m", [b"m"], {"m": 1}, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_multiproof_with_checkpoint(bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_illegal_member_raises_type_error_without_spending(self):
        signer = make_signer()
        for bad in (("good", 123), (object(),), (b"m", None)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    signer.sign_multiproof_with_checkpoint(bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_empty_tuple_raises_value_error_without_spending(self):
        signer = make_signer()
        signer.sign("spent")
        before = signer.next_index
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_checkpoint(())
        self.assertEqual(signer.next_index, before)
        self.assertEqual(signer.sign("m").index, before)

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

    def test_oversized_tuple_raises_without_partial_result(self):
        signer = make_signer(height=1)
        signer.sign("one")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_multiproof_with_checkpoint(("two", "three"))
        self.assertEqual(signer.next_index, 1)
        proof, blob = signer.sign_multiproof_with_checkpoint(("two",))
        self.assertEqual(leaf_indices(proof), [1])
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_multiproof_with_checkpoint(("x",))
        self.assertEqual(signer.next_index, 2)
        self.assertEqual(signer.remaining, 0)

    def test_proof_structure_failure_raises_value_error_without_spending(self):
        signer = make_signer()
        signer.sign("spent")
        before = signer.next_index
        with mock.patch.object(
            pqattest.merkle,
            "multiproof_encode",
            side_effect=ValueError("structural failure"),
        ):
            with self.assertRaises(ValueError):
                signer.sign_multiproof_with_checkpoint(("a", "b"))
        # No leaf consumed, no checkpoint handed back, state untouched.
        self.assertEqual(signer.next_index, before)
        proof, blob = signer.sign_multiproof_with_checkpoint(("a", "b"))
        self.assertEqual(leaf_indices(proof), [before, before + 1])
        self.assertEqual(int.from_bytes(blob[11:13], "big"), before + 2)

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_multiproof_with_checkpoint must not draw randomness"
            )

        signer = MerkleSigner(
            height=2, w=4, token_bytes=counter_tokens()
        )
        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            proof, blob = signer.sign_multiproof_with_checkpoint(("a", "b"))
        self.assertEqual(leaf_indices(proof), [0, 1])
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)

    def test_deterministic_from_equal_state(self):
        messages = ("a", "b", "c")
        signer_a = make_signer()
        signer_b = make_signer()
        proof_a, blob_a = signer_a.sign_multiproof_with_checkpoint(messages)
        proof_b, blob_b = signer_b.sign_multiproof_with_checkpoint(messages)
        self.assertEqual(proof_a, proof_b)
        self.assertEqual(blob_a, blob_b)

    def test_each_signature_individually_verifies(self):
        # The multiproof must carry the same per-leaf signatures the ordinary
        # signing path produces from the same deterministic state.
        signer = make_signer(height=3)
        messages = ("a", "b", "d", "e")
        proof, _ = signer.sign_multiproof_with_checkpoint(messages)
        reference = make_signer(height=3)
        signatures = reference.sign_batch(messages)
        for message, signature in zip(messages, signatures):
            self.assertTrue(merkle_verify(message, signature, signer.public_key))
        self.assertTrue(multiproof_verify(messages, proof))


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
                elif i % 5 == 0:
                    messages = (f"m{i}a", f"m{i}b")
                    proof, blob = signer.sign_multiproof_with_checkpoint(
                        messages
                    )
                    results.append((messages, proof, blob))
                elif i % 5 == 1:
                    signer.sign(f"m{i}")
                elif i % 5 == 2:
                    messages = (f"b{i}a", f"b{i}b")
                    signer.sign_batch(messages)
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

        used = sorted(index for _, proof, _ in results for index in leaf_indices(proof))
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
                self.assertTrue(multiproof_verify(messages, proof))
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

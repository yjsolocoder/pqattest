import threading
import unittest
from unittest import mock

from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    auth_state_unwrap,
    auth_state_wrap,
    multiproof_encode,
    multiproof_verify,
)
import pqattest.merkle
from pqattest.merkle import _MULTIPROOF_HEADER_BYTES

KEY = b"shared-secret-key"
UINT64_MAX = 2**64 - 1


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


class SignMultiproofWithAuthStateTest(unittest.TestCase):
    def test_returns_two_bytes_values(self):
        signer = make_signer()
        proof, envelope = signer.sign_multiproof_with_auth_state(
            ("a", "b"), key=KEY, generation=0
        )
        self.assertIsInstance(proof, bytes)
        self.assertIsInstance(envelope, bytes)
        self.assertEqual(proof[:8], b"PQAMMUL\0")
        self.assertEqual(envelope[:8], b"PQAAUTH\0")

    def test_proof_equals_multiproof_encode_of_consecutive_signatures(self):
        signer = make_signer()
        signer.sign("spent")
        messages = ("one", "two", "three")
        proof, _ = signer.sign_multiproof_with_auth_state(
            messages, key=KEY, generation=0
        )

        reference = make_signer()
        reference.sign("spent")
        signatures = reference.sign_batch(messages)
        self.assertEqual(proof, multiproof_encode(reference.public_key, signatures))

    def test_proof_verifies_with_existing_multiproof_verify(self):
        signer = make_signer(height=3)
        messages = tuple(f"m{i}" for i in (0, 2, 3))
        proof, _ = signer.sign_multiproof_with_auth_state(
            messages, key=KEY, generation=1
        )
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertTrue(multiproof_verify(messages, bytearray(proof)))
        self.assertFalse(multiproof_verify(tuple("x" for _ in messages), proof))

    def test_envelope_matches_explicit_wrap_of_post_batch_checkpoint(self):
        signer = make_signer()
        reference = make_signer()
        generation = 7
        messages = ("one", "two")
        _, envelope = signer.sign_multiproof_with_auth_state(
            messages, key=KEY, generation=generation
        )
        reference.sign_batch(messages)
        expected = auth_state_wrap(
            reference.checkpoint(),
            scheme="merkle",
            key=KEY,
            generation=generation,
        )
        self.assertEqual(envelope, expected)

    def test_envelope_unwraps_to_advanced_checkpoint(self):
        signer = make_signer(height=3)
        messages = ("one", "two", "three")
        proof, envelope = signer.sign_multiproof_with_auth_state(
            messages, key=KEY, generation=42
        )
        scheme, generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(scheme, "merkle")
        self.assertEqual(generation, 42)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, leaf_indices(proof)[-1] + 1)
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertEqual(restored.sign("fourth").index, 3)

    def test_leaves_are_consecutive_from_current_next_index(self):
        signer = make_signer(height=4)
        signer.sign_batch(("s0", "s1"))
        before = signer.next_index
        messages = ("a", "b", "c")
        proof, envelope = signer.sign_multiproof_with_auth_state(
            messages, key=KEY, generation=0
        )
        self.assertEqual(leaf_indices(proof), [before, before + 1, before + 2])
        self.assertEqual(signer.next_index, before + 3)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), before + 3)

    def test_generation_is_bound_in_envelope(self):
        signer = make_signer()
        _, envelope = signer.sign_multiproof_with_auth_state(
            ("m",), key=KEY, generation=UINT64_MAX
        )
        # magic(8) + version(1) + scheme(1), then the 8-byte generation.
        self.assertEqual(int.from_bytes(envelope[10:18], "big"), UINT64_MAX)
        self.assertEqual(envelope[8], 2)
        self.assertEqual(envelope[9], 3)  # scheme identifier for merkle.
        scheme, generation, _ = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual((scheme, generation), ("merkle", UINT64_MAX))

    def test_wrong_key_fails_to_unwrap(self):
        signer = make_signer()
        _, envelope = signer.sign_multiproof_with_auth_state(
            ("m",), key=KEY, generation=0
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(envelope, key=b"other-secret")

    def test_accepts_bytes_bytearray_and_str_members(self):
        signer = make_signer(height=2)
        messages = (b"m", bytearray(b"m"), "m")
        proof, envelope = signer.sign_multiproof_with_auth_state(
            messages, key=bytearray(KEY), generation=1
        )
        self.assertTrue(multiproof_verify((b"m", b"m", b"m"), proof))
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 3)

    def test_single_message_is_a_valid_one_leaf_multiproof(self):
        signer = make_signer()
        proof, _ = signer.sign_multiproof_with_auth_state(
            ("only",), key=KEY, generation=0
        )
        self.assertEqual(int.from_bytes(proof[13:15], "big"), 1)
        self.assertTrue(multiproof_verify(("only",), proof))

    def test_full_tree_dedupes_every_node(self):
        height = 3
        signer = make_signer(height=height)
        messages = tuple(f"m{i}" for i in range(1 << height))
        proof, _ = signer.sign_multiproof_with_auth_state(
            messages, key=KEY, generation=0
        )
        self.assertEqual(int.from_bytes(proof[15:17], "big"), 0)
        self.assertTrue(multiproof_verify(messages, proof))

    def test_keyword_only_arguments(self):
        signer = make_signer()
        with self.assertRaises(TypeError):
            signer.sign_multiproof_with_auth_state(("m",), KEY, 0)

    def test_non_tuple_raises_type_error_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, "m", b"m", [b"m"], {"m": 1}, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_multiproof_with_auth_state(
                        bad, key=KEY, generation=0
                    )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_illegal_member_raises_type_error_without_spending(self):
        signer = make_signer()
        for bad in (("good", 123), (object(),), (b"m", None)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    signer.sign_multiproof_with_auth_state(
                        bad, key=KEY, generation=0
                    )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_empty_tuple_raises_value_error_without_spending(self):
        signer = make_signer()
        signer.sign("spent")
        before = signer.next_index
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_auth_state((), key=KEY, generation=0)
        self.assertEqual(signer.next_index, before)
        self.assertEqual(signer.sign("m").index, before)

    def test_invalid_key_raises_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, "secret", ["k"], b"", bytearray()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises((TypeError, ValueError)):
                    signer.sign_multiproof_with_auth_state(
                        ("m",), key=bad, generation=0
                    )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_generation_raises_without_spending(self):
        signer = make_signer()
        type_errors = (None, 1.5, "0", [0], True, False)
        range_errors = (-1, UINT64_MAX + 1)
        for bad in type_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    signer.sign_multiproof_with_auth_state(
                        ("m",), key=KEY, generation=bad
                    )
        for bad in range_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    signer.sign_multiproof_with_auth_state(
                        ("m",), key=KEY, generation=bad
                    )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_all_inputs_validated_before_capacity_check(self):
        # An exhausted signer must still reject bad input with the input
        # error, not KeyExhaustedError.
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        with self.assertRaises(TypeError):
            signer.sign_multiproof_with_auth_state(
                ("m", 1), key=KEY, generation=0
            )
        with self.assertRaises(TypeError):
            signer.sign_multiproof_with_auth_state([b"m"], key=KEY, generation=0)
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_auth_state((), key=KEY, generation=0)
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_auth_state(
                ("m",), key=b"", generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_auth_state(
                ("m",), key=KEY, generation=-1
            )
        self.assertEqual(signer.next_index, 2)

    def test_oversized_tuple_raises_without_partial_result(self):
        signer = make_signer(height=1)
        signer.sign("one")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_multiproof_with_auth_state(
                ("two", "three"), key=KEY, generation=0
            )
        self.assertEqual(signer.next_index, 1)
        proof, _ = signer.sign_multiproof_with_auth_state(
            ("two",), key=KEY, generation=0
        )
        self.assertEqual(leaf_indices(proof), [1])
        with self.assertRaises(KeyExhaustedError):
            signer.sign_multiproof_with_auth_state(
                ("x",), key=KEY, generation=0
            )
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
                signer.sign_multiproof_with_auth_state(
                    ("a", "b"), key=KEY, generation=0
                )
        # No leaf consumed, no envelope handed back, state untouched.
        self.assertEqual(signer.next_index, before)
        proof, envelope = signer.sign_multiproof_with_auth_state(
            ("a", "b"), key=KEY, generation=0
        )
        self.assertEqual(leaf_indices(proof), [before, before + 1])
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), before + 2)

    def test_wrap_failure_raises_without_spending_or_advancing(self):
        signer = make_signer()
        signer.sign("spent")
        before = signer.next_index
        with mock.patch.object(
            pqattest.merkle,
            "auth_state_wrap",
            side_effect=ValueError("wrap failure"),
        ):
            with self.assertRaises(ValueError):
                signer.sign_multiproof_with_auth_state(
                    ("a", "b"), key=KEY, generation=0
                )
        # The index commits only after both proof and envelope succeed.
        self.assertEqual(signer.next_index, before)
        proof, envelope = signer.sign_multiproof_with_auth_state(
            ("a", "b"), key=KEY, generation=0
        )
        self.assertEqual(leaf_indices(proof), [before, before + 1])
        self.assertEqual(signer.next_index, before + 2)

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_multiproof_with_auth_state must not draw randomness"
            )

        signer = MerkleSigner(height=2, w=4, token_bytes=counter_tokens())
        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            proof, envelope = signer.sign_multiproof_with_auth_state(
                ("a", "b"), key=KEY, generation=0
            )
        self.assertEqual(leaf_indices(proof), [0, 1])
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 2)

    def test_deterministic_from_equal_state(self):
        messages = ("a", "b", "c")
        signer_a = make_signer()
        signer_b = make_signer()
        proof_a, envelope_a = signer_a.sign_multiproof_with_auth_state(
            messages, key=KEY, generation=11
        )
        proof_b, envelope_b = signer_b.sign_multiproof_with_auth_state(
            messages, key=KEY, generation=11
        )
        self.assertEqual(proof_a, proof_b)
        self.assertEqual(envelope_a, envelope_b)


class SignMultiproofWithAuthStateConcurrencyTest(unittest.TestCase):
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
                elif i % 6 == 0:
                    messages = (f"m{i}a", f"m{i}b")
                    proof, envelope = signer.sign_multiproof_with_auth_state(
                        messages, key=KEY, generation=i
                    )
                    results.append((i, messages, proof, envelope))
                elif i % 6 == 1:
                    signer.sign(f"m{i}")
                elif i % 6 == 2:
                    signer.sign_batch((f"b{i}a", f"b{i}b"))
                elif i % 6 == 3:
                    signer.sign_batch_with_auth_state(
                        (f"a{i}",), key=KEY, generation=i
                    )
                elif i % 6 == 4:
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
            for _, _, proof, _ in results
            for index in leaf_indices(proof)
        )
        self.assertEqual(len(used), len(set(used)))
        self.assertLessEqual(len(used) + len(exhausted), leaf_count)
        self.assertEqual(signer.next_index, leaf_count)
        self.assertEqual(signer.remaining, 0)
        for next_index, remaining in reads:
            self.assertTrue(0 <= next_index <= leaf_count)
            self.assertTrue(0 <= remaining <= leaf_count)

        # Every proof verifies and its envelope restores exactly the
        # post-proof state at the bound generation.
        for worker_i, messages, proof, envelope in results:
            with self.subTest(indices=leaf_indices(proof)):
                self.assertTrue(multiproof_verify(messages, proof))
                scheme, generation, checkpoint = auth_state_unwrap(
                    envelope, key=KEY, expect="merkle"
                )
                self.assertEqual(scheme, "merkle")
                self.assertEqual(generation, worker_i)
                restored = MerkleSigner.from_checkpoint(checkpoint)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertEqual(
                    restored.next_index, leaf_indices(proof)[-1] + 1
                )
        for blob in snapshots:
            restored = MerkleSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)


if __name__ == "__main__":
    unittest.main()

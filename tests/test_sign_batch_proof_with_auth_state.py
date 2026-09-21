import threading
import unittest
from unittest import mock

from pqattest import (
    KeyExhaustedError,
    MerkleBatchProof,
    MerkleSigner,
    auth_state_unwrap,
    auth_state_wrap,
)
import pqattest.merkle
from pqattest.merkle import _BATCH_PROOF_HEADER_BYTES

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


class SignBatchProofWithAuthStateTest(unittest.TestCase):
    def test_returns_two_bytes_values(self):
        signer = make_signer()
        proof, envelope = signer.sign_batch_proof_with_auth_state(
            ("a", "b"), key=KEY, generation=0
        )
        self.assertIsInstance(proof, bytes)
        self.assertIsInstance(envelope, bytes)
        self.assertEqual(proof[:8], b"PQAMBAT\0")
        self.assertEqual(envelope[:8], b"PQAAUTH\0")

    def test_proof_equals_batch_proof_of_consecutive_signatures(self):
        signer = make_signer()
        signer.sign("spent")
        messages = ("one", "two", "three")
        proof, _ = signer.sign_batch_proof_with_auth_state(
            messages, key=KEY, generation=0
        )

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
        proof, _ = signer.sign_batch_proof_with_auth_state(
            messages, key=KEY, generation=1
        )
        parsed = MerkleBatchProof.from_bytes(proof)
        self.assertEqual(parsed.public_key, signer.public_key)
        self.assertEqual(len(parsed.signatures), 3)
        self.assertTrue(parsed.verify(("one", b"two", b"three")))
        self.assertTrue(parsed.verify(("one", bytearray(b"two"), b"three")))
        self.assertFalse(parsed.verify(("one", "other", b"three")))
        self.assertFalse(parsed.verify(("one", b"two")))

    def test_str_members_are_utf8_encoded(self):
        signer = make_signer()
        messages = ("héllo",)
        proof, _ = signer.sign_batch_proof_with_auth_state(
            messages, key=KEY, generation=0
        )
        parsed = MerkleBatchProof.from_bytes(proof)
        self.assertTrue(parsed.verify(("héllo",)))
        self.assertTrue(parsed.verify((b"h\xc3\xa9llo",)))
        self.assertFalse(parsed.verify(("hEllo",)))

    def test_envelope_matches_explicit_wrap_of_post_batch_checkpoint(self):
        signer = make_signer()
        reference = make_signer()
        generation = 7
        messages = ("one", "two")
        _, envelope = signer.sign_batch_proof_with_auth_state(
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
        proof, envelope = signer.sign_batch_proof_with_auth_state(
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
        self.assertTrue(MerkleBatchProof.from_bytes(proof).verify(messages))
        # The restored signer continues at the first index after the batch.
        self.assertEqual(restored.sign("fourth").index, 3)

    def test_leaves_are_consecutive_from_current_next_index(self):
        signer = make_signer(height=4)
        signer.sign_batch(("s0", "s1"))
        before = signer.next_index
        messages = ("a", "b", "c")
        proof, envelope = signer.sign_batch_proof_with_auth_state(
            messages, key=KEY, generation=0
        )
        self.assertEqual(leaf_indices(proof), [before, before + 1, before + 2])
        self.assertEqual(signer.next_index, before + 3)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), before + 3)

    def test_generation_is_bound_in_envelope(self):
        signer = make_signer()
        _, envelope = signer.sign_batch_proof_with_auth_state(
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
        _, envelope = signer.sign_batch_proof_with_auth_state(
            ("m",), key=KEY, generation=0
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(envelope, key=b"other-secret")

    def test_accepts_bytes_bytearray_and_str_members(self):
        signer = make_signer(height=2)
        messages = (b"m", bytearray(b"m"), "m")
        proof, envelope = signer.sign_batch_proof_with_auth_state(
            messages, key=bytearray(KEY), generation=1
        )
        self.assertTrue(MerkleBatchProof.from_bytes(proof).verify((b"m", b"m", b"m")))
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 3)

    def test_single_message_is_a_valid_one_signature_batch_proof(self):
        signer = make_signer()
        proof, _ = signer.sign_batch_proof_with_auth_state(
            ("only",), key=KEY, generation=0
        )
        self.assertEqual(int.from_bytes(proof[13:15], "big"), 1)
        self.assertTrue(MerkleBatchProof.from_bytes(proof).verify(("only",)))

    def test_keyword_only_arguments(self):
        signer = make_signer()
        with self.assertRaises(TypeError):
            signer.sign_batch_proof_with_auth_state(("m",), KEY, 0)

    def test_non_tuple_raises_type_error_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, "m", b"m", [b"m"], {"m": 1}, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_batch_proof_with_auth_state(
                        bad, key=KEY, generation=0
                    )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_illegal_member_raises_type_error_without_spending(self):
        signer = make_signer()
        for bad in (("good", 123), (object(),), (b"m", None)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    signer.sign_batch_proof_with_auth_state(
                        bad, key=KEY, generation=0
                    )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_empty_tuple_raises_value_error_without_spending(self):
        signer = make_signer()
        signer.sign("spent")
        before = signer.next_index
        with self.assertRaises(ValueError):
            signer.sign_batch_proof_with_auth_state((), key=KEY, generation=0)
        self.assertEqual(signer.next_index, before)
        self.assertEqual(signer.sign("m").index, before)

    def test_invalid_key_raises_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, "secret", ["k"], b"", bytearray()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises((TypeError, ValueError)):
                    signer.sign_batch_proof_with_auth_state(
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
                    signer.sign_batch_proof_with_auth_state(
                        ("m",), key=KEY, generation=bad
                    )
        for bad in range_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    signer.sign_batch_proof_with_auth_state(
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
            signer.sign_batch_proof_with_auth_state(
                ("m", 1), key=KEY, generation=0
            )
        with self.assertRaises(TypeError):
            signer.sign_batch_proof_with_auth_state([b"m"], key=KEY, generation=0)
        with self.assertRaises(ValueError):
            signer.sign_batch_proof_with_auth_state((), key=KEY, generation=0)
        with self.assertRaises(ValueError):
            signer.sign_batch_proof_with_auth_state(
                ("m",), key=b"", generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_batch_proof_with_auth_state(
                ("m",), key=KEY, generation=-1
            )
        self.assertEqual(signer.next_index, 2)

    def test_oversized_tuple_raises_without_partial_result(self):
        signer = make_signer(height=1)
        signer.sign("one")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_proof_with_auth_state(
                ("two", "three"), key=KEY, generation=0
            )
        self.assertEqual(signer.next_index, 1)
        proof, _ = signer.sign_batch_proof_with_auth_state(
            ("two",), key=KEY, generation=0
        )
        self.assertEqual(leaf_indices(proof), [1])
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_proof_with_auth_state(
                ("x",), key=KEY, generation=0
            )
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
                signer.sign_batch_proof_with_auth_state(
                    ("a", "b"), key=KEY, generation=0
                )
        # No leaf consumed, no envelope handed back, state untouched.
        self.assertEqual(signer.next_index, before)
        proof, envelope = signer.sign_batch_proof_with_auth_state(
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
                signer.sign_batch_proof_with_auth_state(
                    ("a", "b"), key=KEY, generation=0
                )
        # The index commits only after both proof and envelope succeed.
        self.assertEqual(signer.next_index, before)
        proof, envelope = signer.sign_batch_proof_with_auth_state(
            ("a", "b"), key=KEY, generation=0
        )
        self.assertEqual(leaf_indices(proof), [before, before + 1])
        self.assertEqual(signer.next_index, before + 2)

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_batch_proof_with_auth_state must not draw randomness"
            )

        signer = MerkleSigner(height=2, w=4, token_bytes=counter_tokens())
        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            proof, envelope = signer.sign_batch_proof_with_auth_state(
                ("a", "b"), key=KEY, generation=0
            )
        self.assertEqual(leaf_indices(proof), [0, 1])
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 2)

    def test_deterministic_from_equal_state(self):
        messages = ("a", "b", "c")
        signer_a = make_signer()
        signer_b = make_signer()
        proof_a, envelope_a = signer_a.sign_batch_proof_with_auth_state(
            messages, key=KEY, generation=11
        )
        proof_b, envelope_b = signer_b.sign_batch_proof_with_auth_state(
            messages, key=KEY, generation=11
        )
        self.assertEqual(proof_a, proof_b)
        self.assertEqual(envelope_a, envelope_b)


class SignBatchProofWithAuthStateConcurrencyTest(unittest.TestCase):
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
                    proof, envelope = signer.sign_batch_proof_with_auth_state(
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
                self.assertTrue(MerkleBatchProof.from_bytes(proof).verify(messages))
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

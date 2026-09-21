import threading
import unittest
from unittest import mock

from pqattest import (
    KeyExhaustedError,
    MerkleProof,
    MerkleSigner,
    auth_state_unwrap,
    auth_state_wrap,
)
import pqattest.merkle

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


def proof_index(blob):
    key_length = int.from_bytes(blob[9:13], "big")
    # Signature header: magic(8) + version/w/height(3), then the index.
    offset = 17 + key_length + 11
    return int.from_bytes(blob[offset : offset + 2], "big")


class SignProofWithAuthStateTest(unittest.TestCase):
    def test_returns_two_bytes_values(self):
        signer = make_signer()
        proof, envelope = signer.sign_proof_with_auth_state(
            "m", key=KEY, generation=0
        )
        self.assertIsInstance(proof, bytes)
        self.assertIsInstance(envelope, bytes)
        self.assertEqual(proof[:8], b"PQAMPRF\0")
        self.assertEqual(envelope[:8], b"PQAAUTH\0")

    def test_proof_equals_merkle_proof_of_fresh_signature(self):
        signer = make_signer()
        signer.sign("spent")
        proof, _ = signer.sign_proof_with_auth_state("m", key=KEY, generation=0)

        reference = make_signer()
        reference.sign("spent")
        signature = reference.sign("m")
        expected = MerkleProof(
            public_key=reference.public_key, signature=signature
        ).to_bytes()
        self.assertEqual(proof, expected)

    def test_proof_round_trips_and_verifies_the_signed_message(self):
        signer = make_signer()
        proof, _ = signer.sign_proof_with_auth_state(
            "hello", key=KEY, generation=0
        )
        parsed = MerkleProof.from_bytes(proof)
        self.assertEqual(parsed.public_key, signer.public_key)
        self.assertTrue(parsed.verify("hello"))
        self.assertTrue(parsed.verify(b"hello"))
        self.assertFalse(parsed.verify("other"))

    def test_envelope_matches_explicit_wrap_of_post_sign_checkpoint(self):
        signer = make_signer()
        reference = make_signer()
        generation = 7
        _, envelope = signer.sign_proof_with_auth_state(
            "m", key=KEY, generation=generation
        )
        reference.sign("m")
        expected = auth_state_wrap(
            reference.checkpoint(),
            scheme="merkle",
            key=KEY,
            generation=generation,
        )
        self.assertEqual(envelope, expected)

    def test_envelope_unwraps_to_advanced_checkpoint(self):
        signer = make_signer()
        proof, envelope = signer.sign_proof_with_auth_state(
            "one", key=KEY, generation=42
        )
        scheme, generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(scheme, "merkle")
        self.assertEqual(generation, 42)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, proof_index(proof) + 1)
        self.assertTrue(MerkleProof.from_bytes(proof).verify("one"))

    def test_advances_next_index_by_one(self):
        signer = make_signer()
        signer.sign("skipped")
        before = signer.next_index
        proof, envelope = signer.sign_proof_with_auth_state(
            "m", key=KEY, generation=0
        )
        self.assertEqual(proof_index(proof), before)
        self.assertEqual(signer.next_index, before + 1)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), before + 1)

    def test_generation_is_bound_in_envelope(self):
        signer = make_signer()
        _, envelope = signer.sign_proof_with_auth_state(
            "m", key=KEY, generation=UINT64_MAX
        )
        # magic(8) + version(1) + scheme(1), then the 8-byte generation.
        self.assertEqual(int.from_bytes(envelope[10:18], "big"), UINT64_MAX)
        self.assertEqual(envelope[8], 2)
        self.assertEqual(envelope[9], 3)  # scheme identifier for merkle.
        scheme, generation, _ = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual((scheme, generation), ("merkle", UINT64_MAX))

    def test_wrong_key_fails_to_unwrap(self):
        signer = make_signer()
        _, envelope = signer.sign_proof_with_auth_state(
            "m", key=KEY, generation=0
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(envelope, key=b"other-secret")

    def test_accepts_bytes_bytearray_message_and_key(self):
        signer = make_signer(height=2)
        for message in (b"m", bytearray(b"m"), "m"):
            with self.subTest(message=type(message).__name__):
                proof, envelope = signer.sign_proof_with_auth_state(
                    message, key=bytearray(KEY), generation=1
                )
                self.assertTrue(MerkleProof.from_bytes(proof).verify(b"m"))
                _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
                restored = MerkleSigner.from_checkpoint(checkpoint)
                self.assertEqual(restored.next_index, proof_index(proof) + 1)

    def test_keyword_only_arguments(self):
        signer = make_signer()
        with self.assertRaises(TypeError):
            signer.sign_proof_with_auth_state("m", KEY, 0)

    def test_invalid_message_raises_type_error_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, 4.5, [b"m"], (b"m",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_proof_with_auth_state(bad, key=KEY, generation=0)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_key_raises_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, "secret", ["k"], b"", bytearray()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises((TypeError, ValueError)):
                    signer.sign_proof_with_auth_state("m", key=bad, generation=0)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_generation_raises_without_spending(self):
        signer = make_signer()
        type_errors = (None, 1.5, "0", [0], True, False)
        range_errors = (-1, UINT64_MAX + 1)
        for bad in type_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    signer.sign_proof_with_auth_state("m", key=KEY, generation=bad)
        for bad in range_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    signer.sign_proof_with_auth_state("m", key=KEY, generation=bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_all_inputs_validated_before_capacity_check(self):
        # An exhausted signer must still reject bad input with the input
        # error, not KeyExhaustedError.
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        with self.assertRaises(TypeError):
            signer.sign_proof_with_auth_state(None, key=KEY, generation=0)
        with self.assertRaises(ValueError):
            signer.sign_proof_with_auth_state("m", key=b"", generation=0)
        with self.assertRaises(ValueError):
            signer.sign_proof_with_auth_state("m", key=KEY, generation=-1)
        with self.assertRaises(TypeError):
            signer.sign_proof_with_auth_state("m", key=KEY, generation=True)
        self.assertEqual(signer.next_index, 2)

    def test_exhausted_signer_raises_without_partial_result(self):
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_proof_with_auth_state("three", key=KEY, generation=0)
        self.assertEqual(signer.next_index, 2)
        self.assertEqual(signer.remaining, 0)

    def test_proof_failure_raises_without_spending_or_advancing(self):
        signer = make_signer()
        signer.sign("spent")
        before = signer.next_index
        with mock.patch.object(
            MerkleProof, "to_bytes", side_effect=ValueError("proof failure")
        ):
            with self.assertRaises(ValueError):
                signer.sign_proof_with_auth_state("m", key=KEY, generation=0)
        # No leaf consumed, no envelope handed back, state untouched.
        self.assertEqual(signer.next_index, before)
        proof, envelope = signer.sign_proof_with_auth_state(
            "m", key=KEY, generation=0
        )
        self.assertEqual(proof_index(proof), before)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), before + 1)

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
                signer.sign_proof_with_auth_state("m", key=KEY, generation=0)
        # The index commits only after both proof and envelope succeed.
        self.assertEqual(signer.next_index, before)
        proof, envelope = signer.sign_proof_with_auth_state(
            "m", key=KEY, generation=0
        )
        self.assertEqual(proof_index(proof), before)
        self.assertEqual(signer.next_index, before + 1)

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_proof_with_auth_state must not draw randomness"
            )

        signer = MerkleSigner(height=2, w=4, token_bytes=counter_tokens())
        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            proof, envelope = signer.sign_proof_with_auth_state(
                "m", key=KEY, generation=0
            )
        self.assertEqual(proof_index(proof), 0)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 1)

    def test_deterministic_from_equal_state(self):
        signer_a = make_signer()
        signer_b = make_signer()
        proof_a, envelope_a = signer_a.sign_proof_with_auth_state(
            "m", key=KEY, generation=11
        )
        proof_b, envelope_b = signer_b.sign_proof_with_auth_state(
            "m", key=KEY, generation=11
        )
        self.assertEqual(proof_a, proof_b)
        self.assertEqual(envelope_a, envelope_b)


class SignProofWithAuthStateConcurrencyTest(unittest.TestCase):
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
                    proof, envelope = signer.sign_proof_with_auth_state(
                        message, key=KEY, generation=i
                    )
                    results.append((i, message, proof, envelope))
                elif i % 5 == 1:
                    signer.sign(f"m{i}")
                elif i % 5 == 2:
                    signer.sign_with_auth_state(f"a{i}", key=KEY, generation=i)
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
        used = sorted(proof_index(proof) for _, _, proof, _ in results)
        self.assertEqual(len(used), len(set(used)))
        self.assertLessEqual(len(used) + len(exhausted), leaf_count)
        self.assertEqual(signer.next_index, leaf_count)
        self.assertEqual(signer.remaining, 0)
        for next_index, remaining in reads:
            self.assertTrue(0 <= next_index <= leaf_count)
            self.assertTrue(0 <= remaining <= leaf_count)

        # Every proof verifies and its envelope restores exactly the
        # post-sign state at the bound generation.
        for worker_i, message, proof, envelope in results:
            with self.subTest(index=proof_index(proof)):
                self.assertTrue(MerkleProof.from_bytes(proof).verify(message))
                scheme, generation, checkpoint = auth_state_unwrap(
                    envelope, key=KEY, expect="merkle"
                )
                self.assertEqual(scheme, "merkle")
                self.assertEqual(generation, worker_i)
                restored = MerkleSigner.from_checkpoint(checkpoint)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertEqual(restored.next_index, proof_index(proof) + 1)
        for blob in snapshots:
            restored = MerkleSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)


if __name__ == "__main__":
    unittest.main()

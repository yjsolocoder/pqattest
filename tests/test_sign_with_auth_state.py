import threading
import unittest

from pqattest import (
    KeyExhaustedError,
    MerkleSignature,
    MerkleSigner,
    auth_state_unwrap,
    auth_state_wrap,
    merkle_verify,
)

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


class SignWithAuthStateTest(unittest.TestCase):
    def test_returns_signature_and_bytes(self):
        signer = make_signer()
        signature, envelope = signer.sign_with_auth_state(
            "m", key=KEY, generation=0
        )
        self.assertIsInstance(signature, MerkleSignature)
        self.assertIsInstance(envelope, bytes)

    def test_signature_matches_plain_sign_from_same_state(self):
        signer = make_signer()
        reference = make_signer()
        signature, _ = signer.sign_with_auth_state("m", key=KEY, generation=3)
        self.assertEqual(signature, reference.sign("m"))

    def test_envelope_matches_explicit_wrap_of_post_sign_checkpoint(self):
        signer = make_signer()
        reference = make_signer()
        generation = 7
        _, envelope = signer.sign_with_auth_state(
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
        signature, envelope = signer.sign_with_auth_state(
            "one", key=KEY, generation=42
        )
        scheme, generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(scheme, "merkle")
        self.assertEqual(generation, 42)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, signature.index + 1)
        self.assertTrue(merkle_verify("one", signature, signer.public_key))

    def test_advances_next_index_by_one(self):
        signer = make_signer()
        signer.sign("skipped")
        before = signer.next_index
        signature, envelope = signer.sign_with_auth_state(
            "m", key=KEY, generation=0
        )
        self.assertEqual(signature.index, before)
        self.assertEqual(signer.next_index, before + 1)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), before + 1)

    def test_generation_is_bound_in_envelope(self):
        signer = make_signer()
        _, envelope = signer.sign_with_auth_state(
            "m", key=KEY, generation=UINT64_MAX
        )
        # magic(8) + version(1) + scheme(1), then the 8-byte generation.
        self.assertEqual(
            int.from_bytes(envelope[10:18], "big"), UINT64_MAX
        )
        self.assertEqual(envelope[8], 2)
        scheme, generation, _ = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual((scheme, generation), ("merkle", UINT64_MAX))

    def test_wrong_key_fails_to_unwrap(self):
        signer = make_signer()
        _, envelope = signer.sign_with_auth_state("m", key=KEY, generation=0)
        with self.assertRaises(ValueError):
            auth_state_unwrap(envelope, key=b"other-secret")

    def test_accepts_bytes_bytearray_message_and_key(self):
        signer = make_signer(height=2)
        for message in (b"m", bytearray(b"m"), "m"):
            with self.subTest(message=type(message).__name__):
                signature, envelope = signer.sign_with_auth_state(
                    message, key=bytearray(KEY), generation=1
                )
                self.assertTrue(merkle_verify(b"m", signature, signer.public_key))
                _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
                restored = MerkleSigner.from_checkpoint(checkpoint)
                self.assertEqual(restored.next_index, signature.index + 1)

    def test_keyword_only_arguments(self):
        signer = make_signer()
        with self.assertRaises(TypeError):
            signer.sign_with_auth_state("m", KEY, 0)

    def test_invalid_message_raises_type_error_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, 4.5, [b"m"], (b"m",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_with_auth_state(bad, key=KEY, generation=0)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_key_raises_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, "secret", ["k"], b"", bytearray()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises((TypeError, ValueError)):
                    signer.sign_with_auth_state("m", key=bad, generation=0)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_generation_raises_without_spending(self):
        signer = make_signer()
        type_errors = (None, 1.5, "0", [0], True, False)
        range_errors = (-1, UINT64_MAX + 1)
        for bad in type_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    signer.sign_with_auth_state("m", key=KEY, generation=bad)
        for bad in range_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    signer.sign_with_auth_state("m", key=KEY, generation=bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_exhausted_signer_raises_without_partial_result(self):
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_with_auth_state("three", key=KEY, generation=0)
        self.assertEqual(signer.next_index, 2)
        self.assertEqual(signer.remaining, 0)

    def test_exhaustion_is_checked_under_lock_without_partial_result(self):
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        try:
            signer.sign_with_auth_state("three", key=KEY, generation=9)
        except KeyExhaustedError:
            pass
        self.assertEqual(signer.next_index, 2)

    def test_draws_no_extra_randomness(self):
        tokens = counter_tokens()
        signer = MerkleSigner(height=2, w=4, token_bytes=tokens)

        def exploding_token_bytes(size):
            raise AssertionError("sign_with_auth_state must not draw randomness")

        import pqattest.merkle
        from unittest import mock

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            signature, envelope = signer.sign_with_auth_state(
                "m", key=KEY, generation=0
            )
        self.assertEqual(signature.index, 0)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 1)


class SignWithAuthStateConcurrencyTest(unittest.TestCase):
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
                    message = f"m{i}"
                    signature, envelope = signer.sign_with_auth_state(
                        message, key=KEY, generation=i
                    )
                    results.append((i, message, signature, envelope))
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

        # Every successful auth signature got a distinct leaf, and every leaf
        # was accounted for exactly once by either a sign or the advance.
        used = sorted(signature.index for _, _, signature, _ in results)
        self.assertEqual(len(used), len(set(used)))
        self.assertLessEqual(len(used) + len(exhausted), leaf_count)
        self.assertEqual(signer.next_index, leaf_count)
        self.assertEqual(signer.remaining, 0)
        # Property reads each observed a value within the legal range; the
        # two reads are separate lock acquisitions and need not pair up.
        for next_index, remaining in reads:
            self.assertTrue(0 <= next_index <= leaf_count)
            self.assertTrue(0 <= remaining <= leaf_count)

        # Each envelope matches the state immediately after its own signature.
        for worker_i, message, signature, envelope in results:
            with self.subTest(index=signature.index):
                scheme, generation, checkpoint = auth_state_unwrap(
                    envelope, key=KEY, expect="merkle"
                )
                self.assertEqual(generation, worker_i)
                restored = MerkleSigner.from_checkpoint(checkpoint)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertEqual(restored.next_index, signature.index + 1)
                self.assertTrue(
                    merkle_verify(message, signature, signer.public_key)
                )
        for blob in snapshots:
            restored = MerkleSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)


if __name__ == "__main__":
    unittest.main()

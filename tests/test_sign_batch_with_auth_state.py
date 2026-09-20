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


class SignBatchWithAuthStateTest(unittest.TestCase):
    def test_returns_signatures_tuple_and_bytes(self):
        signer = make_signer()
        signatures, envelope = signer.sign_batch_with_auth_state(
            ("a", "b"), key=KEY, generation=0
        )
        self.assertIsInstance(signatures, tuple)
        self.assertEqual(len(signatures), 2)
        for signature in signatures:
            self.assertIsInstance(signature, MerkleSignature)
        self.assertIsInstance(envelope, bytes)

    def test_signatures_match_sign_batch_from_same_state(self):
        signer = make_signer()
        reference = make_signer()
        messages = ("one", "two", "three")
        signatures, _ = signer.sign_batch_with_auth_state(
            messages, key=KEY, generation=5
        )
        self.assertEqual(signatures, reference.sign_batch(messages))

    def test_envelope_matches_explicit_wrap_of_post_batch_checkpoint(self):
        signer = make_signer()
        reference = make_signer()
        generation = 7
        messages = ("one", "two")
        _, envelope = signer.sign_batch_with_auth_state(
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
        signer = make_signer()
        messages = ("one", "two", "three")
        signatures, envelope = signer.sign_batch_with_auth_state(
            messages, key=KEY, generation=42
        )
        scheme, generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(scheme, "merkle")
        self.assertEqual(generation, 42)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, signatures[-1].index + 1)
        for message, signature in zip(messages, signatures):
            self.assertTrue(merkle_verify(message, signature, signer.public_key))

    def test_advances_next_index_once_by_batch_size(self):
        signer = make_signer()
        signer.sign("skipped")
        before = signer.next_index
        messages = ("a", "b", "c")
        signatures, envelope = signer.sign_batch_with_auth_state(
            messages, key=KEY, generation=0
        )
        self.assertEqual(
            [signature.index for signature in signatures],
            [before, before + 1, before + 2],
        )
        self.assertEqual(signer.next_index, before + 3)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), before + 3)

    def test_generation_is_bound_in_envelope(self):
        signer = make_signer()
        _, envelope = signer.sign_batch_with_auth_state(
            ("m",), key=KEY, generation=UINT64_MAX
        )
        # magic(8) + version(1) + scheme(1), then the 8-byte generation.
        self.assertEqual(int.from_bytes(envelope[10:18], "big"), UINT64_MAX)
        self.assertEqual(envelope[8], 2)
        scheme, generation, _ = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual((scheme, generation), ("merkle", UINT64_MAX))

    def test_wrong_key_fails_to_unwrap(self):
        signer = make_signer()
        _, envelope = signer.sign_batch_with_auth_state(
            ("m",), key=KEY, generation=0
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(envelope, key=b"other-secret")

    def test_accepts_bytes_bytearray_messages_and_key(self):
        signer = make_signer(height=2)
        messages = (b"m", bytearray(b"m"), "m")
        signatures, envelope = signer.sign_batch_with_auth_state(
            messages, key=bytearray(KEY), generation=1
        )
        for signature in signatures:
            self.assertTrue(merkle_verify(b"m", signature, signer.public_key))
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, signatures[-1].index + 1)

    def test_keyword_only_arguments(self):
        signer = make_signer()
        with self.assertRaises(TypeError):
            signer.sign_batch_with_auth_state(("m",), KEY, 0)

    def test_empty_batch_returns_empty_tuple_and_wraps_unchanged_state(self):
        signer = make_signer()
        signer.sign("spent")
        before = signer.next_index
        signatures, envelope = signer.sign_batch_with_auth_state(
            (), key=KEY, generation=9
        )
        self.assertEqual(signatures, ())
        self.assertEqual(signer.next_index, before)
        scheme, generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual((scheme, generation), ("merkle", 9))
        self.assertEqual(checkpoint, signer.checkpoint())
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, before)

    def test_empty_batch_on_exhausted_signer_still_wraps(self):
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        signatures, envelope = signer.sign_batch_with_auth_state(
            (), key=KEY, generation=0
        )
        self.assertEqual(signatures, ())
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 2)

    def test_invalid_messages_type_raises_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, "m", b"m", [b"m"], {"m": 1}, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_batch_with_auth_state(bad, key=KEY, generation=0)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_message_member_raises_without_spending(self):
        signer = make_signer()
        for bad in (("good", 123, "also good"), (object(),), (b"m", None)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    signer.sign_batch_with_auth_state(bad, key=KEY, generation=0)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_key_raises_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, "secret", ["k"], b"", bytearray()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises((TypeError, ValueError)):
                    signer.sign_batch_with_auth_state(
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
                    signer.sign_batch_with_auth_state(
                        ("m",), key=KEY, generation=bad
                    )
        for bad in range_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    signer.sign_batch_with_auth_state(
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
            signer.sign_batch_with_auth_state(("m", 1), key=KEY, generation=0)
        with self.assertRaises(ValueError):
            signer.sign_batch_with_auth_state(("m",), key=b"", generation=0)
        with self.assertRaises(ValueError):
            signer.sign_batch_with_auth_state(("m",), key=KEY, generation=-1)
        self.assertEqual(signer.next_index, 2)

    def test_oversized_batch_raises_without_partial_result(self):
        signer = make_signer(height=1)
        signer.sign("one")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_with_auth_state(
                ("two", "three"), key=KEY, generation=0
            )
        self.assertEqual(signer.next_index, 1)
        signatures, envelope = signer.sign_batch_with_auth_state(
            ("two",), key=KEY, generation=0
        )
        self.assertEqual([s.index for s in signatures], [1])
        with self.assertRaises(KeyExhaustedError):
            signer.sign_batch_with_auth_state(("x",), key=KEY, generation=0)
        self.assertEqual(signer.next_index, 2)
        self.assertEqual(signer.remaining, 0)

    def test_draws_no_extra_randomness(self):
        tokens = counter_tokens()
        signer = MerkleSigner(height=2, w=4, token_bytes=tokens)

        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_batch_with_auth_state must not draw randomness"
            )

        import pqattest.merkle
        from unittest import mock

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            signatures, envelope = signer.sign_batch_with_auth_state(
                ("a", "b"), key=KEY, generation=0
            )
        self.assertEqual([s.index for s in signatures], [0, 1])
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 2)


class SignBatchWithAuthStateConcurrencyTest(unittest.TestCase):
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
                    signatures, envelope = signer.sign_batch_with_auth_state(
                        messages, key=KEY, generation=i
                    )
                    results.append((i, messages, signatures, envelope))
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
            signature.index for _, _, signatures, _ in results for signature in signatures
        )
        self.assertEqual(len(used), len(set(used)))
        self.assertLessEqual(len(used) + len(exhausted), leaf_count)
        self.assertEqual(signer.next_index, leaf_count)
        self.assertEqual(signer.remaining, 0)
        for next_index, remaining in reads:
            self.assertTrue(0 <= next_index <= leaf_count)
            self.assertTrue(0 <= remaining <= leaf_count)

        # Each envelope matches the state immediately after its own batch.
        for worker_i, messages, signatures, envelope in results:
            with self.subTest(indices=[s.index for s in signatures]):
                scheme, generation, checkpoint = auth_state_unwrap(
                    envelope, key=KEY, expect="merkle"
                )
                self.assertEqual(generation, worker_i)
                restored = MerkleSigner.from_checkpoint(checkpoint)
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

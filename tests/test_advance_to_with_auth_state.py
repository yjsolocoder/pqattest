import threading
import unittest

from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    auth_state_unwrap,
    auth_state_wrap,
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


class AdvanceToWithAuthStateTest(unittest.TestCase):
    def test_returns_inner_tuple_and_bytes_envelope(self):
        signer = make_signer()
        result = signer.advance_to_with_auth_state(3, key=KEY, generation=0)
        self.assertEqual(result, ((0, 3), result[1]))
        (before, after), envelope = result
        self.assertEqual((before, after), (0, 3))
        self.assertIsInstance(envelope, bytes)

    def test_inner_tuple_matches_plain_advance_to(self):
        signer = make_signer(height=3)
        reference = make_signer(height=3)
        signer.sign("a")
        reference.sign("a")
        result = signer.advance_to_with_auth_state(6, key=KEY, generation=1)
        self.assertEqual(result[0], reference.advance_to(6))
        self.assertEqual(signer.next_index, 6)

    def test_envelope_matches_explicit_wrap_of_post_advance_checkpoint(self):
        signer = make_signer()
        reference = make_signer()
        generation = 7
        _, envelope = signer.advance_to_with_auth_state(
            3, key=KEY, generation=generation
        )
        reference.advance_to(3)
        expected = auth_state_wrap(
            reference.checkpoint(),
            scheme="merkle",
            key=KEY,
            generation=generation,
        )
        self.assertEqual(envelope, expected)

    def test_envelope_unwraps_to_advanced_checkpoint(self):
        signer = make_signer()
        (before, after), envelope = signer.advance_to_with_auth_state(
            2, key=KEY, generation=42
        )
        scheme, generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(scheme, "merkle")
        self.assertEqual(generation, 42)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, after)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 2)

    def test_equal_target_succeeds_and_still_wraps_state(self):
        signer = make_signer()
        signer.advance_to(3)
        checkpoint_before = signer.checkpoint()
        (before, after), envelope = signer.advance_to_with_auth_state(
            3, key=KEY, generation=9
        )
        self.assertEqual((before, after), (3, 3))
        self.assertEqual(signer.next_index, 3)
        _, generation, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(generation, 9)
        self.assertEqual(checkpoint, checkpoint_before)
        # Unchanged state still signs the same leaf.
        self.assertEqual(signer.sign("m").index, 3)

    def test_advance_to_leaf_count_exhausts(self):
        signer = make_signer(height=2)
        (before, after), envelope = signer.advance_to_with_auth_state(
            4, key=KEY, generation=0
        )
        self.assertEqual((before, after), (0, 4))
        self.assertEqual(signer.next_index, 4)
        self.assertEqual(signer.remaining, 0)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)

    def test_does_not_change_public_or_private_keys(self):
        signer = make_signer()
        public_key = signer.public_key
        checkpoint_before = signer.checkpoint()
        _, envelope = signer.advance_to_with_auth_state(2, key=KEY, generation=1)
        self.assertIs(signer.public_key, public_key)
        _, _, checkpoint_after = auth_state_unwrap(envelope, key=KEY)
        # Element count, root and every private element are unchanged
        # (body after the next_index field, excluding the trailing checksum
        # which authenticates the whole body); only next_index differs.
        self.assertEqual(checkpoint_before[13:-32], checkpoint_after[13:-32])
        self.assertNotEqual(checkpoint_before[11:13], checkpoint_after[11:13])

    def test_accepts_bytearray_key(self):
        signer = make_signer()
        (before, after), envelope = signer.advance_to_with_auth_state(
            1, key=bytearray(KEY), generation=0
        )
        auth_state_unwrap(envelope, key=KEY)

    def test_generation_is_bound_in_envelope(self):
        signer = make_signer()
        _, envelope = signer.advance_to_with_auth_state(
            1, key=KEY, generation=UINT64_MAX
        )
        # magic(8) + version(1) + scheme(1), then the 8-byte generation.
        self.assertEqual(envelope[8], 2)
        self.assertEqual(int.from_bytes(envelope[10:18], "big"), UINT64_MAX)
        scheme, generation, _ = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual((scheme, generation), ("merkle", UINT64_MAX))

    def test_wrong_key_fails_to_unwrap(self):
        signer = make_signer()
        _, envelope = signer.advance_to_with_auth_state(1, key=KEY, generation=0)
        with self.assertRaises(ValueError):
            auth_state_unwrap(envelope, key=b"other-secret")

    def test_keyword_only_arguments(self):
        signer = make_signer()
        with self.assertRaises(TypeError):
            signer.advance_to_with_auth_state(1, KEY, 0)

    def test_non_integer_target_raises_type_error_without_moving(self):
        signer = make_signer()
        for bad in (True, False, 1.0, "1", None, [1], (1,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.advance_to_with_auth_state(bad, key=KEY, generation=0)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_key_raises_without_moving(self):
        signer = make_signer()
        for bad in (None, 42, "secret", ["k"], b"", bytearray()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises((TypeError, ValueError)):
                    signer.advance_to_with_auth_state(2, key=bad, generation=0)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_generation_raises_without_moving(self):
        signer = make_signer()
        type_errors = (None, 1.5, "0", [0], True, False)
        range_errors = (-1, UINT64_MAX + 1)
        for bad in type_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    signer.advance_to_with_auth_state(2, key=KEY, generation=bad)
        for bad in range_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    signer.advance_to_with_auth_state(2, key=KEY, generation=bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_backwards_target_raises_value_error(self):
        signer = make_signer(height=3)
        signer.sign("a")
        for bad in (0, -1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    signer.advance_to_with_auth_state(bad, key=KEY, generation=0)
        self.assertEqual(signer.next_index, 1)

    def test_target_above_leaf_count_raises_value_error(self):
        signer = make_signer(height=2)  # 4 leaves
        for bad in (5, 8, 1 << 16):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    signer.advance_to_with_auth_state(bad, key=KEY, generation=0)
        self.assertEqual(signer.next_index, 0)
        signer.advance_to(3)
        with self.assertRaises(ValueError):
            signer.advance_to_with_auth_state(2, key=KEY, generation=0)
        self.assertEqual(signer.next_index, 3)

    def test_all_arguments_validated_before_advance(self):
        # An out-of-range target together with a bad key still raises the
        # key/type error, and never moves the state.
        signer = make_signer()
        with self.assertRaises(TypeError):
            signer.advance_to_with_auth_state(True, key=KEY, generation=0)
        with self.assertRaises(ValueError):
            signer.advance_to_with_auth_state(9, key=b"", generation=0)
        self.assertEqual(signer.next_index, 0)

    def test_draws_no_randomness(self):
        tokens = counter_tokens()
        signer = MerkleSigner(height=2, w=4, token_bytes=tokens)

        import pqattest.merkle
        from unittest import mock

        def exploding_token_bytes(size):
            raise AssertionError(
                "advance_to_with_auth_state must not draw randomness"
            )

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            result = signer.advance_to_with_auth_state(2, key=KEY, generation=0)
        self.assertEqual(result[0], (0, 2))
        _, _, checkpoint = auth_state_unwrap(result[1], key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 2)

    def test_equal_target_draws_no_randomness(self):
        signer = make_signer()
        signer.advance_to(2)

        import pqattest.merkle
        from unittest import mock

        def exploding_token_bytes(size):
            raise AssertionError(
                "advance_to_with_auth_state must not draw randomness"
            )

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            self.assertEqual(
                signer.advance_to_with_auth_state(2, key=KEY, generation=0)[0],
                (2, 2),
            )


class AdvanceToWithAuthStateConcurrencyTest(unittest.TestCase):
    def test_linearises_with_all_state_operations(self):
        height = 4
        leaf_count = 1 << height
        signer = make_signer(height=height)
        advances = []
        snapshots = []
        reads = []
        errors = []
        exhausted = []
        barrier = threading.Barrier(leaf_count)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                if i % 4 == 0:
                    result = signer.advance_to_with_auth_state(
                        leaf_count, key=KEY, generation=i
                    )
                    advances.append((i, result))
                elif i % 4 == 1:
                    try:
                        signer.sign(f"m{i}")
                    except KeyExhaustedError:
                        # Expected when an advance-to-end worker wins the race.
                        pass
                elif i % 4 == 2:
                    snapshots.append(signer.checkpoint())
                else:
                    reads.append((signer.next_index, signer.remaining))
            except ValueError:
                # A racing advance-to-end can make the equal target fail for
                # a loser that read a stale index; it never corrupts state.
                pass
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

        # Every successful envelope wraps the post-advance (exhausted) state.
        for worker_i, ((before, after), envelope) in advances:
            with self.subTest(worker=worker_i):
                self.assertEqual(after, leaf_count)
                self.assertLessEqual(before, leaf_count)
                scheme, generation, checkpoint = auth_state_unwrap(
                    envelope, key=KEY, expect="merkle"
                )
                self.assertEqual(generation, worker_i)
                restored = MerkleSigner.from_checkpoint(checkpoint)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertEqual(restored.next_index, leaf_count)
        for blob in snapshots:
            restored = MerkleSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)
        for next_index, remaining in reads:
            self.assertTrue(0 <= next_index <= leaf_count)
            self.assertTrue(0 <= remaining <= leaf_count)


if __name__ == "__main__":
    unittest.main()

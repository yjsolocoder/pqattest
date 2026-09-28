"""Tests for MerkleSigner.sign_selected_with_auth_state."""

import threading
import unittest
from unittest import mock

import pqattest.merkle
from pqattest import (
    KeyExhaustedError,
    MerkleSignature,
    MerkleSigner,
    auth_state_unwrap,
    auth_state_wrap,
    merkle_verify,
    multiproof_encode,
    multiproof_verify,
    multiproof_verify_bound,
)


KEY = b"shared-secret-key"
UINT64_MAX = 2**64 - 1


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=3, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


class SignSelectedWithAuthStateBasicTest(unittest.TestCase):
    def test_returns_signatures_tuple_and_bytes(self):
        signer = make_signer(height=2)
        signatures, envelope = signer.sign_selected_with_auth_state(
            (0, 2), ("a", "b"), key=KEY, generation=0
        )
        self.assertIsInstance(signatures, tuple)
        self.assertEqual(len(signatures), 2)
        for signature in signatures:
            self.assertIsInstance(signature, MerkleSignature)
        self.assertEqual([s.index for s in signatures], [0, 2])
        self.assertIsInstance(envelope, bytes)

    def test_signatures_match_sign_selected_from_same_state(self):
        indices = (1, 3, 6)
        messages = ("a", b"b", bytearray(b"c"))
        atomic = make_signer().sign_selected_with_auth_state(
            indices, messages, key=KEY, generation=3
        )[0]
        plain = make_signer().sign_selected(indices, messages)
        self.assertEqual(atomic, plain)

    def test_envelope_matches_explicit_wrap_of_post_selection_checkpoint(self):
        indices = (1, 4)
        messages = ("a", "b")
        generation = 7
        signer = make_signer()
        _, envelope = signer.sign_selected_with_auth_state(
            indices, messages, key=KEY, generation=generation
        )
        reference = make_signer()
        reference.sign_selected(indices, messages)
        expected = auth_state_wrap(
            reference.checkpoint(),
            scheme="merkle",
            key=KEY,
            generation=generation,
        )
        self.assertEqual(envelope, expected)

    def test_envelope_unwraps_to_advanced_checkpoint(self):
        signer = make_signer()
        indices = (1, 4)
        messages = ("m1", "m4")
        signatures, envelope = signer.sign_selected_with_auth_state(
            indices, messages, key=KEY, generation=42
        )
        scheme, generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(scheme, "merkle")
        self.assertEqual(generation, 42)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 5)
        for message, signature in zip(messages, signatures):
            self.assertTrue(merkle_verify(message, signature, signer.public_key))
        # Gaps stay voided after restore; signing resumes after the last pick.
        with self.assertRaises(ValueError):
            restored.sign_selected((2,), ("old",))
        self.assertEqual(restored.sign("d").index, 5)

    def test_advances_state_to_last_index_plus_one(self):
        signer = make_signer()
        signer.sign("warm-up")
        indices = (2, 5)
        signatures, envelope = signer.sign_selected_with_auth_state(
            indices, ("x", "y"), key=KEY, generation=0
        )
        self.assertEqual([s.index for s in signatures], [2, 5])
        self.assertEqual(signer.next_index, 6)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 6)

    def test_last_leaf_reachable_and_exhausts(self):
        signer = make_signer(height=2)
        signatures, envelope = signer.sign_selected_with_auth_state(
            (3,), ("last",), key=KEY, generation=1
        )
        self.assertEqual([s.index for s in signatures], [3])
        self.assertEqual(signer.next_index, 4)
        self.assertEqual(signer.remaining, 0)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 4)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("more")

    def test_generation_is_bound_in_envelope(self):
        signer = make_signer(height=2)
        _, envelope = signer.sign_selected_with_auth_state(
            (1,), ("m",), key=KEY, generation=UINT64_MAX
        )
        # magic(8) + version(1) + scheme(1), then the 8-byte generation.
        self.assertEqual(envelope[8], 2)
        self.assertEqual(int.from_bytes(envelope[10:18], "big"), UINT64_MAX)
        scheme, generation, _ = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual((scheme, generation), ("merkle", UINT64_MAX))

    def test_wrong_key_fails_to_unwrap(self):
        signer = make_signer(height=2)
        _, envelope = signer.sign_selected_with_auth_state(
            (0,), ("m",), key=KEY, generation=0
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(envelope, key=b"other-secret")

    def test_accepts_all_message_types_and_bytearray_key(self):
        signer = make_signer(height=2)
        indices = (0, 1, 3)
        messages = (b"m", bytearray(b"m"), "m")
        signatures, envelope = signer.sign_selected_with_auth_state(
            indices, messages, key=bytearray(KEY), generation=1
        )
        for signature in signatures:
            self.assertTrue(merkle_verify(b"m", signature, signer.public_key))
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 4)

    def test_multiproof_packs_the_selection(self):
        signer = make_signer()
        indices = (1, 2, 5)
        messages = ("m1", b"m2", bytearray(b"m5"))
        signatures, _ = signer.sign_selected_with_auth_state(
            indices, messages, key=KEY, generation=0
        )
        proof = multiproof_encode(signer.public_key, signatures)
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertTrue(
            multiproof_verify_bound(
                messages, proof, public_key=signer.public_key, indices=indices
            )
        )

    def test_keyword_only_arguments(self):
        signer = make_signer(height=2)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state((0,), ("m",), KEY, 0)

    def test_deterministic_value_for_value(self):
        first = make_signer()
        second = make_signer()
        self.assertEqual(
            first.sign_selected_with_auth_state(
                (0, 4, 7), ("a", "b", "c"), key=KEY, generation=11
            ),
            second.sign_selected_with_auth_state(
                (0, 4, 7), ("a", "b", "c"), key=KEY, generation=11
            ),
        )

    def test_draws_no_randomness(self):
        signer = make_signer()

        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_selected_with_auth_state must not draw randomness"
            )

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            signatures, envelope = signer.sign_selected_with_auth_state(
                (0, 2), ("a", "b"), key=KEY, generation=0
            )
        self.assertEqual([s.index for s in signatures], [0, 2])
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 3)


class SignSelectedWithAuthStateValidationTest(unittest.TestCase):
    def test_non_tuple_arguments_raise_typeerror(self):
        signer = make_signer(height=2)
        for bad_indices in (None, 42, [0, 1], {0, 1}, "01"):
            with self.subTest(bad=type(bad_indices).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_auth_state(
                        bad_indices, ("a", "b"), key=KEY, generation=0
                    )
        for bad_messages in (None, 42, ["a", "b"], {0: "a"}, "ab"):
            with self.subTest(bad=type(bad_messages).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_auth_state(
                        (0, 1), bad_messages, key=KEY, generation=0
                    )

    def test_non_integer_index_members_raise_typeerror(self):
        signer = make_signer(height=2)
        for bad in (("0", "1"), (0, 1.0), (None,), (0, object())):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_auth_state(
                        bad, tuple("m" for _ in bad), key=KEY, generation=0
                    )

    def test_unsupported_message_members_raise_typeerror(self):
        signer = make_signer(height=2)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                (0, 1), ("good", 123), key=KEY, generation=0
            )
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                (0,), (object(),), key=KEY, generation=0
            )

    def test_empty_tuples_raise_valueerror(self):
        signer = make_signer(height=2)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state((), (), key=KEY, generation=0)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (), ("a",), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), (), key=KEY, generation=0
            )

    def test_length_mismatch_raises_valueerror(self):
        signer = make_signer(height=3)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0, 1), ("a",), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), ("a", "b"), key=KEY, generation=0
            )

    def test_boolean_indices_raise_valueerror(self):
        signer = make_signer(height=3)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (True, 1), ("a", "b"), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0, False), ("a", "b"), key=KEY, generation=0
            )

    def test_duplicate_or_unordered_indices_raise_valueerror(self):
        signer = make_signer(height=3)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (1, 1), ("a", "b"), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (2, 1), ("a", "b"), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (3, 2, 1), ("a", "b", "c"), key=KEY, generation=0
            )

    def test_index_below_next_leaf_raises_valueerror(self):
        signer = make_signer(height=3)
        signer.sign_batch(("a", "b", "c"))  # next_index == 3
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (2, 4), ("old", "new"), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), ("old",), key=KEY, generation=0
            )
        self.assertEqual(signer.next_index, 3)

    def test_index_past_last_leaf_raises_valueerror(self):
        signer = make_signer(height=2)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (4,), ("past",), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0, 4), ("ok", "past"), key=KEY, generation=0
            )
        self.assertEqual(signer.next_index, 0)

    def test_invalid_key_raises_without_spending(self):
        signer = make_signer(height=2)
        for bad in (None, 42, "secret", ["k"], b"", bytearray()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises((TypeError, ValueError)):
                    signer.sign_selected_with_auth_state(
                        (0, 1), ("a", "b"), key=bad, generation=0
                    )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_invalid_generation_raises_without_spending(self):
        signer = make_signer(height=2)
        for bad in (None, 1.5, "0", [0], True, False):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_auth_state(
                        (0,), ("m",), key=KEY, generation=bad
                    )
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    signer.sign_selected_with_auth_state(
                        (0,), ("m",), key=KEY, generation=bad
                    )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_all_inputs_validated_before_capacity_check(self):
        # An exhausted signer must still reject bad input with the input
        # error, not KeyExhaustedError.
        signer = make_signer(height=1)
        signer.advance_to(2)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                (0,), (123,), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state((), (), key=KEY, generation=0)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=b"", generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=KEY, generation=-1
            )
        self.assertEqual(signer.next_index, 2)

    def test_exhausted_signer_raises_key_exhausted(self):
        signer = make_signer(height=2)
        signer.advance_to(4)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected_with_auth_state(
                (3,), ("late",), key=KEY, generation=0
            )
        # Structural validation precedes the exhaustion check.
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                "not a tuple", (), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (), (), key=KEY, generation=0
            )
        # A structurally valid request on the exhausted signer reports
        # exhaustion, not an index-range error.
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected_with_auth_state(
                (0,), ("late",), key=KEY, generation=0
            )

    def test_range_error_on_fresh_signer_never_exhaustion(self):
        fresh = make_signer(height=1)
        with self.assertRaises(ValueError):
            fresh.sign_selected_with_auth_state(
                (2,), ("x",), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            fresh.sign_selected_with_auth_state(
                (-1,), ("x",), key=KEY, generation=0
            )
        self.assertEqual(fresh.next_index, 0)

    def test_failure_consumes_no_leaf(self):
        signer = make_signer(height=3)
        for bad_indices, bad_messages in (
            ((1, 1), ("a", "b")),
            ((8,), ("ok",)),
            ((0, 1), ("only-one",)),
        ):
            with self.assertRaises(ValueError):
                signer.sign_selected_with_auth_state(
                    bad_indices, bad_messages, key=KEY, generation=0
                )
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                (0, 1), ("a", 2), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), ("a",), key=KEY, generation=UINT64_MAX + 1
            )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("first").index, 0)


class SignSelectedWithAuthStateConcurrencyTest(unittest.TestCase):
    def test_linearises_with_all_state_operations(self):
        height = 4
        leaf_count = 1 << height
        signer = make_signer(height=height)
        results = []
        snapshots = []
        reads = []
        errors = []
        exhausted = []
        list_lock = threading.Lock()
        barrier = threading.Barrier(leaf_count)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                if i == leaf_count - 1:
                    signer.advance_to(leaf_count)
                elif i % 4 == 0:
                    indices = (i, min(i + 1, leaf_count - 1))
                    if indices[0] == indices[1]:
                        indices = (i,)
                    messages = tuple(f"m{i}-{j}" for j in indices)
                    signatures, envelope = (
                        signer.sign_selected_with_auth_state(
                            indices, messages, key=KEY, generation=i
                        )
                    )
                    with list_lock:
                        results.append((i, indices, messages, signatures, envelope))
                elif i % 4 == 1:
                    signer.sign(f"m{i}")
                elif i % 4 == 2:
                    with list_lock:
                        snapshots.append(signer.checkpoint())
                else:
                    with list_lock:
                        reads.append((signer.next_index, signer.remaining))
            except KeyExhaustedError:
                with list_lock:
                    exhausted.append(i)
            except ValueError:
                # Lost the race against the advance-to-end worker.
                with list_lock:
                    exhausted.append(i)
            except Exception as exc:  # pragma: no cover - failure path
                with list_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(leaf_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])

        used = sorted(
            signature.index
            for _, _, _, signatures, _ in results
            for signature in signatures
        )
        self.assertEqual(used, sorted(set(used)))
        self.assertEqual(signer.next_index, leaf_count)
        self.assertEqual(signer.remaining, 0)

        for worker_i, indices, messages, signatures, envelope in results:
            with self.subTest(indices=[s.index for s in signatures]):
                scheme, generation, checkpoint = auth_state_unwrap(
                    envelope, key=KEY, expect="merkle"
                )
                self.assertEqual(generation, worker_i)
                restored = MerkleSigner.from_checkpoint(checkpoint)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertEqual(restored.next_index, indices[-1] + 1)
                self.assertEqual(
                    [s.index for s in signatures], list(indices)
                )
                for message, signature in zip(messages, signatures):
                    self.assertTrue(
                        merkle_verify(message, signature, signer.public_key)
                    )
        for blob in snapshots:
            restored = MerkleSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)

    def test_concurrent_selections_never_share_a_leaf(self):
        height = 4
        signer = make_signer(height=height)
        leaf_count = 1 << height
        picked = []
        envelopes = []
        errors = []
        list_lock = threading.Lock()
        barrier = threading.Barrier(4)

        def worker(offset):
            try:
                indices = tuple(range(offset, leaf_count, 4))
                messages = tuple(f"w{offset}-{i}" for i in indices)
                barrier.wait(timeout=10)
                signatures, envelope = signer.sign_selected_with_auth_state(
                    indices, messages, key=KEY, generation=offset
                )
                with list_lock:
                    picked.extend(s.index for s in signatures)
                    envelopes.append(envelope)
            except Exception as exc:  # pragma: no cover - failure path
                with list_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertGreaterEqual(len(errors), 3)
        winner_picked = sorted(picked)
        self.assertEqual(winner_picked, sorted(set(winner_picked)))
        self.assertEqual(signer.next_index, max(winner_picked) + 1)
        self.assertEqual(len(envelopes), 1)
        _, _, checkpoint = auth_state_unwrap(envelopes[0], key=KEY)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, signer.next_index)


if __name__ == "__main__":
    unittest.main()

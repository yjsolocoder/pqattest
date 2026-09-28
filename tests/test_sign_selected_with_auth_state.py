"""Tests for MerkleSigner.sign_selected_with_auth_state."""

import threading
import unittest

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
        signer = make_signer(height=3)
        signatures, envelope = signer.sign_selected_with_auth_state(
            (1, 3, 5), ("a", b"b", bytearray(b"c")), key=KEY, generation=0
        )
        self.assertIsInstance(signatures, tuple)
        self.assertEqual(len(signatures), 3)
        for signature in signatures:
            self.assertIsInstance(signature, MerkleSignature)
        self.assertIsInstance(envelope, bytes)

    def test_signatures_match_sign_selected_from_same_state(self):
        indices = (1, 4, 6)
        messages = ("one", b"two", bytearray(b"three"))
        signer = make_signer(height=3)
        reference = make_signer(height=3)
        signatures, _ = signer.sign_selected_with_auth_state(
            indices, messages, key=KEY, generation=9
        )
        self.assertEqual(signatures, reference.sign_selected(indices, messages))

    def test_gap_leaves_are_voided(self):
        signer = make_signer(height=3)
        signatures, envelope = signer.sign_selected_with_auth_state(
            (1, 4), ("a", "b"), key=KEY, generation=0
        )
        self.assertEqual([s.index for s in signatures], [1, 4])
        self.assertEqual(signer.next_index, 5)
        self.assertEqual(signer.remaining, 3)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 5)
        with self.assertRaises(ValueError):
            signer.sign_selected((2,), ("too late",))
        self.assertEqual(signer.sign("c").index, 5)

    def test_every_signature_verifies_bound_to_its_leaf(self):
        signer = make_signer(height=3)
        indices = (0, 2, 4, 7)
        messages = (b"m0", "m2", bytearray(b"m4"), b"m7")
        signatures, _ = signer.sign_selected_with_auth_state(
            indices, messages, key=KEY, generation=1
        )
        for index, message, signature in zip(indices, messages, signatures):
            self.assertEqual(signature.index, index)
            self.assertTrue(merkle_verify(message, signature, signer.public_key))

    def test_multiproof_packs_and_verifies(self):
        signer = make_signer(height=3)
        indices = (1, 2, 5)
        messages = ("m1", b"m2", bytearray(b"m5"))
        signatures, _ = signer.sign_selected_with_auth_state(
            indices, messages, key=KEY, generation=2
        )
        proof = multiproof_encode(signer.public_key, signatures)
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertTrue(
            multiproof_verify_bound(
                messages, proof, public_key=signer.public_key, indices=indices
            )
        )

    def test_consecutive_selection_matches_batch_value_for_value(self):
        messages = ("a", b"b", bytearray(b"c"), "d")
        selected = make_signer(height=3).sign_selected_with_auth_state(
            (0, 1, 2, 3), messages, key=KEY, generation=0
        )[0]
        batched = make_signer(height=3).sign_batch(messages)
        self.assertEqual(selected, batched)

    def test_deterministic_value_for_value(self):
        first = make_signer(height=3)
        second = make_signer(height=3)
        self.assertEqual(
            first.sign_selected_with_auth_state(
                (0, 4, 7), ("a", "b", "c"), key=KEY, generation=12
            ),
            second.sign_selected_with_auth_state(
                (0, 4, 7), ("a", "b", "c"), key=KEY, generation=12
            ),
        )


class SignSelectedWithAuthStateEnvelopeTest(unittest.TestCase):
    def test_envelope_matches_explicit_wrap_of_post_selection_checkpoint(self):
        signer = make_signer(height=3)
        reference = make_signer(height=3)
        indices = (1, 4)
        messages = ("a", "b")
        generation = 7
        _, envelope = signer.sign_selected_with_auth_state(
            indices, messages, key=KEY, generation=generation
        )
        reference.sign_selected(indices, messages)
        expected = auth_state_wrap(
            reference.checkpoint(),
            scheme="merkle",
            key=KEY,
            generation=generation,
        )
        self.assertEqual(envelope, expected)

    def test_envelope_matches_two_step_sign_then_wrap(self):
        signer = make_signer(height=2)
        indices = (0, 2)
        messages = ("a", bytearray(b"b"))
        signatures, envelope = signer.sign_selected_with_auth_state(
            indices, messages, key=KEY, generation=55
        )
        # A second signer doing the same selection and wrapping the
        # afterwards-exported checkpoint must produce identical bytes.
        other = make_signer(height=2)
        other_signatures = other.sign_selected(indices, messages)
        self.assertEqual(signatures, other_signatures)
        self.assertEqual(
            envelope,
            auth_state_wrap(
                other.checkpoint(), scheme="merkle", key=KEY, generation=55
            ),
        )

    def test_envelope_unwraps_with_scheme_and_generation(self):
        signer = make_signer(height=3)
        signatures, envelope = signer.sign_selected_with_auth_state(
            (1, 4), ("a", "b"), key=KEY, generation=42
        )
        scheme, generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(scheme, "merkle")
        self.assertEqual(generation, 42)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, signatures[-1].index + 1)

    def test_from_auth_state_restores_resuming_after_last_item(self):
        signer = make_signer(height=3)
        signatures, envelope = signer.sign_selected_with_auth_state(
            (0, 2, 5), ("a", "b", "c"), key=KEY, generation=3
        )
        restored, generation = MerkleSigner.from_auth_state(
            envelope, key=KEY, min_generation=3
        )
        self.assertEqual(generation, 3)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 6)
        with self.assertRaises(ValueError):
            restored.sign_selected((2,), ("old",))
        signature = restored.sign("d")
        self.assertEqual(signature.index, 6)
        self.assertTrue(merkle_verify("d", signature, restored.public_key))
        self.assertEqual(signatures[-1].index, 5)

    def test_envelope_uses_existing_v2_generation_semantics(self):
        signer = make_signer(height=2)
        _, envelope = signer.sign_selected_with_auth_state(
            (1,), ("m",), key=KEY, generation=UINT64_MAX
        )
        # v2 version byte sits at offset 8; generation is the 8 bytes at 10:18.
        self.assertEqual(envelope[8], 2)
        self.assertEqual(
            int.from_bytes(envelope[10:18], "big"), UINT64_MAX
        )
        # The uint64-max generation verifies under the existing unwrap rule.
        scheme, generation, _ = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual((scheme, generation), ("merkle", UINT64_MAX))

    def test_wrong_key_fails_to_unwrap(self):
        signer = make_signer(height=2)
        _, envelope = signer.sign_selected_with_auth_state(
            (0,), ("m",), key=KEY, generation=0
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(envelope, key=b"other-key")


class SignSelectedWithAuthStateValidationTest(unittest.TestCase):
    def test_non_tuple_arguments_raise_typeerror(self):
        signer = make_signer(height=2)
        for bad_indices in (None, 42, [0, 1], {0}, "01"):
            with self.subTest(bad=type(bad_indices).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_auth_state(
                        bad_indices, ("a",), key=KEY, generation=0
                    )
        for bad_messages in (None, 42, ["a"], {0: "a"}, "a"):
            with self.subTest(bad=type(bad_messages).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_auth_state(
                        (0,), bad_messages, key=KEY, generation=0
                    )

    def test_non_integer_index_members_raise_typeerror(self):
        signer = make_signer(height=2)
        for bad in (("0",), (1.0,), (None,), (object(),)):
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

    def test_empty_or_mismatched_or_unordered_selection_raises_valueerror(self):
        signer = make_signer(height=3)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (), (), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), (), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0, 1), ("a",), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (True, 1), ("a", "b"), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (1, 1), ("a", "b"), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (2, 1), ("a", "b"), key=KEY, generation=0
            )

    def test_bad_key_type_raises_typeerror(self):
        signer = make_signer(height=2)
        for bad_key in (None, 123, ["k"], {"k": 1}, "secret"):
            with self.subTest(bad=type(bad_key).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_auth_state(
                        (0,), ("m",), key=bad_key, generation=0
                    )

    def test_key_accepts_bytes_and_bytearray(self):
        signer = make_signer(height=2)
        _, envelope_a = signer.sign_selected_with_auth_state(
            (0,), ("m",), key=b"k", generation=0
        )
        _, envelope_b = make_signer(height=2).sign_selected_with_auth_state(
            (0,), ("m",), key=bytearray(b"k"), generation=0
        )
        self.assertEqual(envelope_a, envelope_b)

    def test_empty_key_raises_valueerror(self):
        signer = make_signer(height=2)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=b"", generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=bytearray(), generation=0
            )

    def test_bad_generation_type_raises_typeerror(self):
        signer = make_signer(height=2)
        for bad_generation in (None, 1.5, "0", b"0", [0]):
            with self.subTest(bad=type(bad_generation).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_auth_state(
                        (0,), ("m",), key=KEY, generation=bad_generation
                    )

    def test_boolean_generation_raises_typeerror(self):
        signer = make_signer(height=2)
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=KEY, generation=True
            )
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=KEY, generation=False
            )

    def test_generation_out_of_uint64_raises_valueerror(self):
        signer = make_signer(height=2)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=KEY, generation=-1
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=KEY, generation=UINT64_MAX + 1
            )

    def test_key_and_generation_validated_before_lock_and_exhaustion(self):
        signer = make_signer(height=1)
        signer.advance_to(2)
        # Type/structure errors surface even though the signer is exhausted.
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                (0,), (123,), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (), (), key=KEY, generation=0
            )
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=123, generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=b"", generation=0
            )
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=KEY, generation=True
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=KEY, generation=UINT64_MAX + 1
            )
        # A fully validated request on the exhausted signer raises exhaustion.
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=KEY, generation=0
            )

    def test_index_range_checked_last_inside_the_lock(self):
        exhausted = make_signer(height=2)
        exhausted.advance_to(4)
        with self.assertRaises(KeyExhaustedError):
            exhausted.sign_selected_with_auth_state(
                (0,), ("late",), key=KEY, generation=0
            )
        fresh = make_signer(height=1)
        with self.assertRaises(ValueError):
            fresh.sign_selected_with_auth_state(
                (2,), ("past",), key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            fresh.sign_selected_with_auth_state(
                (-1,), ("past",), key=KEY, generation=0
            )

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
                (0,), ("m",), key=b"", generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), key=KEY, generation=UINT64_MAX + 1
            )
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("first").index, 0)


class SignSelectedWithAuthStateConcurrencyTest(unittest.TestCase):
    def test_concurrent_calls_never_share_a_leaf(self):
        height = 4
        signer = make_signer(height=height)
        leaf_count = 1 << height
        picked = []
        errors = []
        list_lock = threading.Lock()
        barrier = threading.Barrier(4)

        def worker(offset):
            try:
                indices = tuple(range(offset, leaf_count, 4))
                messages = tuple(f"w{offset}-{i}" for i in indices)
                barrier.wait(timeout=10)
                signatures, _ = signer.sign_selected_with_auth_state(
                    indices, messages, key=KEY, generation=offset
                )
                with list_lock:
                    picked.extend(s.index for s in signatures)
            except Exception as exc:  # pragma: no cover - failure path
                with list_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertGreaterEqual(len(errors), 3)
        self.assertEqual(picked, sorted(set(picked)))
        self.assertEqual(signer.next_index, max(picked) + 1)

    def test_concurrent_plain_signs_never_overlap_selection(self):
        height = 3
        signer = make_signer(height=height)
        results = []
        errors = []
        result_lock = threading.Lock()
        barrier = threading.Barrier(2)

        def plain():
            try:
                barrier.wait(timeout=10)
                for _ in range(1 << height):
                    results.append(signer.sign("p").index)
            except KeyExhaustedError:
                pass
            except Exception as exc:  # pragma: no cover - failure path
                with result_lock:
                    errors.append(exc)

        def selected():
            try:
                barrier.wait(timeout=10)
                signer.sign_selected_with_auth_state(
                    (0, 2, 4, 6), tuple("sxyzwvut"[:4]), key=KEY, generation=0
                )
            except ValueError:
                pass  # Lost the race: indices already spent.
            except Exception as exc:  # pragma: no cover - failure path
                with result_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=plain), threading.Thread(target=selected)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(results, sorted(set(results)))


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest import mock

import pqattest
from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    OneTimeSigner,
    WOTSOneTimeSigner,
    advance_and_sign_merkle_auth_state,
    auth_state_unwrap,
    auth_state_wrap,
    auth_wrap,
    keygen,
    merkle_verify,
    wots_keygen,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret"
UINT64_MAX = 2**64 - 1


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def wrap_merkle(signer, *, generation=7, key=KEY):
    return auth_state_wrap(
        signer.checkpoint(), scheme="merkle", key=key, generation=generation
    )


class RecordingClaim:
    """Callable that records every token it is given and returns a fixed value."""

    def __init__(self, result=True):
        self.calls = []
        self.result = result

    def __call__(self, token):
        self.calls.append(token)
        return self.result


def accept(token):
    return True


class AdvanceAndSignMerkleAuthStateTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.envelope = wrap_merkle(self.signer, generation=11)

    def test_returns_pair_signature_envelope_and_generation(self):
        result = advance_and_sign_merkle_auth_state(
            self.envelope, 3, b"m", key=KEY, claim=accept
        )
        self.assertEqual(len(result), 4)
        (before, target), signature, envelope, generation = result
        self.assertEqual((before, target), (0, 3))
        self.assertEqual(signature.index, 3)
        self.assertIsInstance(envelope, bytes)
        self.assertEqual(generation, 12)
        self.assertIsInstance(generation, int)
        self.assertNotIsInstance(generation, bool)

    def test_signature_matches_advance_then_sign(self):
        reference = make_signer()
        reference.advance_to(3)
        expected = reference.sign(b"m")
        (_, target), signature, _, _ = advance_and_sign_merkle_auth_state(
            self.envelope, 3, b"m", key=KEY, claim=accept
        )
        self.assertEqual(target, 3)
        self.assertEqual(signature, expected)
        self.assertTrue(
            merkle_verify(b"m", signature, self.signer.public_key)
        )
        self.assertFalse(
            merkle_verify(b"other", signature, self.signer.public_key)
        )

    def test_signature_from_nonzero_current_index(self):
        signer = make_signer(height=3)
        signer.sign(b"a")
        envelope = wrap_merkle(signer, generation=5)
        (before, target), signature, _, generation = (
            advance_and_sign_merkle_auth_state(
                envelope, 6, b"m", key=KEY, claim=accept
            )
        )
        self.assertEqual((before, target), (1, 6))
        self.assertEqual(generation, 6)
        self.assertEqual(signature.index, 6)
        self.assertTrue(merkle_verify(b"m", signature, signer.public_key))

    def test_envelope_matches_explicit_wrap_at_g_plus_one(self):
        reference = make_signer()
        _, _, envelope, generation = advance_and_sign_merkle_auth_state(
            self.envelope, 3, b"m", key=KEY, claim=accept
        )
        reference.advance_to(3)
        reference.sign(b"m")
        expected = auth_state_wrap(
            reference.checkpoint(),
            scheme="merkle",
            key=KEY,
            generation=12,
        )
        self.assertEqual(generation, 12)
        self.assertEqual(envelope, expected)

    def test_returned_envelope_unwraps_to_target_plus_one_state(self):
        (before, target), signature, envelope, generation = (
            advance_and_sign_merkle_auth_state(
                self.envelope, 2, b"m", key=KEY, claim=accept
            )
        )
        scheme, wrapped_generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(scheme, "merkle")
        self.assertEqual(wrapped_generation, generation)
        self.assertEqual(generation, 12)
        self.assertEqual((before, target), (0, 2))
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, self.signer.public_key)
        self.assertEqual(restored.next_index, 3)
        self.assertEqual(restored.remaining, 1)
        # Leaves below the target were skipped; only the final leaf remains.
        self.assertEqual(restored.sign(b"again").index, 3)
        with self.assertRaises(KeyExhaustedError):
            restored.sign(b"once more")
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 3)

    def test_equal_target_is_legal_and_still_advances_generation(self):
        signer = make_signer()
        signer.advance_to(3)
        envelope = wrap_merkle(signer, generation=9)
        (before, after), signature, out_envelope, generation = (
            advance_and_sign_merkle_auth_state(
                envelope, 3, b"m", key=KEY, claim=accept
            )
        )
        self.assertEqual((before, after), (3, 3))
        self.assertEqual(signature.index, 3)
        self.assertEqual(generation, 10)
        _, wrapped_generation, checkpoint = auth_state_unwrap(
            out_envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(wrapped_generation, 10)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 4)

    def test_target_at_last_leaf_signs_and_exhausts(self):
        signer = make_signer(height=2)  # leaves 0..3
        envelope = wrap_merkle(signer, generation=0)
        (before, after), signature, out_envelope, generation = (
            advance_and_sign_merkle_auth_state(
                envelope, 3, b"m", key=KEY, claim=accept
            )
        )
        self.assertEqual((before, after), (0, 3))
        self.assertEqual(signature.index, 3)
        self.assertEqual(generation, 1)
        _, _, checkpoint = auth_state_unwrap(out_envelope, key=KEY)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)

    def test_accepts_bytearray_inputs(self):
        reference = make_signer()
        result = advance_and_sign_merkle_auth_state(
            bytearray(self.envelope), 1, b"m", key=bytearray(KEY), claim=accept
        )
        reference.advance_to(1)
        reference.sign(b"m")
        (before, after), signature, envelope, generation = result
        self.assertEqual((before, after), (0, 1))
        self.assertEqual(generation, 12)
        self.assertEqual(
            envelope,
            auth_state_wrap(
                reference.checkpoint(),
                scheme="merkle",
                key=KEY,
                generation=12,
            ),
        )

    def test_accepts_str_message(self):
        (_, _), signature, _, _ = advance_and_sign_merkle_auth_state(
            self.envelope, 1, "message", key=KEY, claim=accept
        )
        self.assertTrue(
            merkle_verify("message", signature, self.signer.public_key)
        )

    def test_generation_endpoints(self):
        low = wrap_merkle(self.signer, generation=0)
        _, _, _, generation = advance_and_sign_merkle_auth_state(
            low, 1, b"m", key=KEY, claim=accept
        )
        self.assertEqual(generation, 1)
        ceiling = wrap_merkle(self.signer, generation=UINT64_MAX - 1)
        _, _, envelope, generation = advance_and_sign_merkle_auth_state(
            ceiling, 1, b"m", key=KEY, claim=accept
        )
        self.assertEqual(generation, UINT64_MAX)
        _, wrapped_generation, _ = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(wrapped_generation, UINT64_MAX)

    def test_stateless_chaining_through_envelopes(self):
        signer = make_signer(height=2)
        envelope = wrap_merkle(signer, generation=0)
        for target, message in ((0, b"a"), (1, b"b"), (3, b"c")):
            (_, _), signature, envelope, generation = (
                advance_and_sign_merkle_auth_state(
                    envelope, target, message, key=KEY, claim=accept
                )
            )
            self.assertEqual(signature.index, target)
            self.assertTrue(
                merkle_verify(message, signature, signer.public_key)
            )
        self.assertEqual(generation, 3)
        _, _, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)

    def test_stateless_same_envelope_replays_identically(self):
        first = advance_and_sign_merkle_auth_state(
            self.envelope, 2, b"m", key=KEY, claim=accept
        )
        second = advance_and_sign_merkle_auth_state(
            self.envelope, 2, b"m", key=KEY, claim=accept
        )
        self.assertEqual(first, second)
        self.assertEqual(first[0], (0, 2))

    def test_does_not_mutate_state_behind_input_envelope(self):
        signer = make_signer()
        signer.advance_to(2)
        envelope = wrap_merkle(signer, generation=3)
        self.assertEqual(signer.next_index, 2)
        advance_and_sign_merkle_auth_state(
            envelope, 3, b"m", key=KEY, claim=accept
        )
        self.assertEqual(signer.next_index, 2)
        # The source signer can still sign the leaf the conversion jumped to.
        signature = signer.sign(b"m")
        self.assertEqual(signature.index, 2)

    def test_floor_equal_and_below_pass(self):
        envelope = wrap_merkle(self.signer, generation=7)
        advance_and_sign_merkle_auth_state(
            envelope, 1, b"m", key=KEY, min_generation=7, claim=accept
        )
        advance_and_sign_merkle_auth_state(
            envelope, 1, b"m", key=KEY, min_generation=6, claim=accept
        )

    def test_floor_above_generation_fails_without_claim(self):
        claim = RecordingClaim()
        envelope = wrap_merkle(self.signer, generation=7)
        with self.assertRaises(ValueError):
            advance_and_sign_merkle_auth_state(
                envelope, 1, b"m", key=KEY, min_generation=8, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_backwards_target_raises_value_error_without_claim(self):
        signer = make_signer(height=3)
        signer.sign(b"a")
        envelope = wrap_merkle(signer, generation=4)
        claim = RecordingClaim()
        for bad in (0, -1):
            with self.subTest(bad=bad):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    advance_and_sign_merkle_auth_state(
                        envelope, bad, b"m", key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])
        # The input envelope is still usable.
        (before, after), _, _, generation = advance_and_sign_merkle_auth_state(
            envelope, 2, b"m", key=KEY, claim=accept
        )
        self.assertEqual((before, after), (1, 2))
        self.assertEqual(generation, 5)

    def test_target_at_or_above_leaf_count_raises_value_error(self):
        signer = make_signer(height=2)  # 4 leaves; signable targets 0..3
        envelope = wrap_merkle(signer, generation=0)
        claim = RecordingClaim()
        for bad in (4, 5, 8, 1 << 16):
            with self.subTest(bad=bad):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    advance_and_sign_merkle_auth_state(
                        envelope, bad, b"m", key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])

    def test_exhausted_state_raises_key_exhausted_without_claim(self):
        signer = make_signer(height=2)
        signer.advance_to(4)
        envelope = wrap_merkle(signer, generation=3)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            advance_and_sign_merkle_auth_state(
                envelope, 3, b"m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError(
                "advance_and_sign_merkle_auth_state must not draw randomness"
            )

        with mock.patch.object(
            pqattest.secrets, "token_bytes", exploding_token_bytes
        ):
            result = advance_and_sign_merkle_auth_state(
                self.envelope, 2, b"m", key=KEY, claim=accept
            )
        self.assertEqual(result[0], (0, 2))
        self.assertEqual(result[3], 12)
        _, _, checkpoint = auth_state_unwrap(result[2], key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 3)

    def test_equal_target_draws_no_randomness(self):
        signer = make_signer()
        signer.advance_to(2)
        envelope = wrap_merkle(signer, generation=0)

        def exploding_token_bytes(size):
            raise AssertionError(
                "advance_and_sign_merkle_auth_state must not draw randomness"
            )

        with mock.patch.object(
            pqattest.secrets, "token_bytes", exploding_token_bytes
        ):
            self.assertEqual(
                advance_and_sign_merkle_auth_state(
                    envelope, 2, b"m", key=KEY, claim=accept
                )[0],
                (2, 2),
            )


class AdvanceAndSignMerkleAuthStateClaimTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.envelope = wrap_merkle(self.signer, generation=7)

    def test_claim_receives_exact_paired_token(self):
        claim = RecordingClaim()
        advance_and_sign_merkle_auth_state(
            self.envelope, 3, b"m", key=KEY, claim=claim
        )
        self.assertEqual(claim.calls, [(("merkle", 7), ("merkle", 8))])

    def test_claim_called_exactly_once(self):
        claim = RecordingClaim()
        advance_and_sign_merkle_auth_state(
            self.envelope, 3, b"m", key=KEY, claim=claim
        )
        self.assertEqual(len(claim.calls), 1)

    def test_claim_token_is_a_pair_of_plain_tuples(self):
        seen = []
        advance_and_sign_merkle_auth_state(
            self.envelope, 3, b"m", key=KEY,
            claim=lambda token: (seen.append(token), True)[1],
        )
        token = seen[0]
        self.assertIsInstance(token, tuple)
        self.assertEqual(len(token), 2)
        for side in token:
            self.assertIsInstance(side, tuple)
            self.assertEqual(len(side), 2)
            self.assertEqual(side[0], "merkle")
            self.assertIs(type(side[1]), int)
            self.assertIsNot(type(side[1]), bool)
        self.assertEqual(token[0][1], 7)
        self.assertEqual(token[1][1], 8)

    def test_claim_false_rejected_after_outputs_exist(self):
        claim = RecordingClaim(result=False)
        with self.assertRaises(ValueError):
            advance_and_sign_merkle_auth_state(
                self.envelope, 3, b"m", key=KEY, claim=claim
            )
        self.assertEqual(len(claim.calls), 1)

    def test_truthy_non_true_rejected(self):
        for result in (1, "True", b"True", object()):
            with self.subTest(result=repr(result)):
                claim = RecordingClaim(result=result)
                with self.assertRaises(ValueError):
                    advance_and_sign_merkle_auth_state(
                        self.envelope, 3, b"m", key=KEY, claim=claim
                    )
                self.assertEqual(len(claim.calls), 1)

    def test_claim_exception_propagates_untouched(self):
        class Boom(Exception):
            pass

        def boom(token):
            raise Boom

        with self.assertRaises(Boom):
            advance_and_sign_merkle_auth_state(
                self.envelope, 3, b"m", key=KEY, claim=boom
            )

    def test_claim_not_called_on_wrong_key(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            advance_and_sign_merkle_auth_state(
                self.envelope, 3, b"m", key=OTHER_KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_tamper(self):
        claim = RecordingClaim()
        forged = bytearray(self.envelope)
        forged[30] ^= 0x01
        with self.assertRaises(ValueError):
            advance_and_sign_merkle_auth_state(
                bytes(forged), 3, b"m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_v1_envelope(self):
        claim = RecordingClaim()
        v1 = auth_wrap(self.signer.checkpoint(), scheme="merkle", key=KEY)
        with self.assertRaises(ValueError):
            advance_and_sign_merkle_auth_state(
                v1, 3, b"m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_other_scheme(self):
        claim = RecordingClaim()
        lamport = OneTimeSigner(keygen(bits=32)[0])
        lamport_envelope = auth_state_wrap(
            lamport.checkpoint(), scheme="lamport", key=KEY, generation=7
        )
        wots = WOTSOneTimeSigner(wots_keygen(w=4)[0])
        wots_envelope = auth_state_wrap(
            wots.checkpoint(), scheme="wots", key=KEY, generation=7
        )
        for envelope in (lamport_envelope, wots_envelope):
            with self.subTest(scheme=envelope[9]):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    advance_and_sign_merkle_auth_state(
                        envelope, 3, b"m", key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_garbage(self):
        claim = RecordingClaim()
        for bad in (b"", b"\x00", b"PQAAUTH\0", b"\x00" * 54,
                    self.envelope[:-1], self.envelope + b"\x00"):
            with self.subTest(length=len(bad)):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    advance_and_sign_merkle_auth_state(
                        bad, 3, b"m", key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_invalid_checkpoint(self):
        import hashlib
        import hmac

        payload = b"PQAMSCP\0" + b"\x00" * 20
        body = (
            b"PQAAUTH\0"
            + bytes((2, 3))
            + (7).to_bytes(8, "big")
            + len(payload).to_bytes(4, "big")
            + payload
        )
        blob = body + hmac.new(KEY, body, hashlib.sha256).digest()
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            advance_and_sign_merkle_auth_state(
                blob, 3, b"m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_at_generation_ceiling(self):
        envelope = wrap_merkle(self.signer, generation=UINT64_MAX)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            advance_and_sign_merkle_auth_state(
                envelope, 3, b"m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_backwards_or_overshoot_target(self):
        signer = make_signer(height=3)
        signer.sign(b"a")
        envelope = wrap_merkle(signer, generation=2)
        claim = RecordingClaim()
        for bad in (0, 8, 9):
            with self.subTest(bad=bad):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    advance_and_sign_merkle_auth_state(
                        envelope, bad, b"m", key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_exhaustion(self):
        signer = make_signer(height=1)
        signer.sign(b"a")
        signer.sign(b"b")
        envelope = wrap_merkle(signer, generation=9)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            advance_and_sign_merkle_auth_state(
                envelope, 1, b"c", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_bad_message(self):
        claim = RecordingClaim()
        for bad in (123, object(), [b"m"]):
            with self.subTest(bad=type(bad).__name__):
                claim.calls.clear()
                with self.assertRaises(TypeError):
                    advance_and_sign_merkle_auth_state(
                        self.envelope, 3, bad, key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])


class AdvanceAndSignMerkleAuthStateTypesTest(unittest.TestCase):
    def setUp(self):
        self.envelope = wrap_merkle(make_signer(), generation=1)

    def test_keyword_only_arguments(self):
        with self.assertRaises(TypeError):
            advance_and_sign_merkle_auth_state(
                self.envelope, 3, b"m", KEY, None, accept
            )
        with self.assertRaises(TypeError):
            advance_and_sign_merkle_auth_state(
                self.envelope, 3, b"m", KEY, claim=accept
            )

    def test_claim_is_required(self):
        with self.assertRaises(TypeError):
            advance_and_sign_merkle_auth_state(
                self.envelope, 3, b"m", key=KEY
            )

    def test_non_bytes_data_type_error(self):
        for bad in (None, 42, 4.5, "blob", [self.envelope], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    advance_and_sign_merkle_auth_state(
                        bad, 3, b"m", key=KEY, claim=accept
                    )

    def test_non_integer_target_type_error(self):
        for bad in (True, False, 1.0, "1", None, [1], (1,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    advance_and_sign_merkle_auth_state(
                        self.envelope, bad, b"m", key=KEY, claim=accept
                    )

    def test_non_bytes_key_type_error(self):
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    advance_and_sign_merkle_auth_state(
                        self.envelope, 3, b"m", key=bad, claim=accept
                    )

    def test_non_callable_claim_type_error(self):
        for bad in (None, True, 1, "claim", b"claim", (lambda: True,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    advance_and_sign_merkle_auth_state(
                        self.envelope, 3, b"m", key=KEY, claim=bad
                    )

    def test_bad_min_generation_type_error(self):
        for bad in (1.5, "0", [0], (0,), object(), True, False):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    advance_and_sign_merkle_auth_state(
                        self.envelope, 3, b"m", key=KEY,
                        min_generation=bad, claim=accept,
                    )

    def test_empty_key_value_error(self):
        for bad in (b"", bytearray()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    advance_and_sign_merkle_auth_state(
                        self.envelope, 3, b"m", key=bad, claim=accept
                    )

    def test_min_generation_out_of_range_value_error(self):
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    advance_and_sign_merkle_auth_state(
                        self.envelope, 3, b"m", key=KEY,
                        min_generation=bad, claim=accept,
                    )

    def test_types_checked_before_envelope(self):
        with self.assertRaises(TypeError):
            advance_and_sign_merkle_auth_state(
                b"", 3, b"m", key=42, claim=accept
            )
        with self.assertRaises(TypeError):
            advance_and_sign_merkle_auth_state(
                object(), 3, b"m", key=KEY, claim=accept
            )
        with self.assertRaises(TypeError):
            advance_and_sign_merkle_auth_state(
                b"", 3, b"m", key=KEY, min_generation=True, claim=accept
            )
        with self.assertRaises(TypeError):
            advance_and_sign_merkle_auth_state(
                b"", 3, b"m", key=KEY, claim="claim"
            )
        with self.assertRaises(TypeError):
            advance_and_sign_merkle_auth_state(
                b"", True, b"m", key=KEY, claim=accept
            )


if __name__ == "__main__":
    unittest.main()

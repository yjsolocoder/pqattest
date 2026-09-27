import unittest
from unittest import mock

import pqattest
from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    OneTimeSigner,
    WOTSOneTimeSigner,
    auth_state_unwrap,
    auth_state_wrap,
    auth_wrap,
    keygen,
    sign_wots_auth_state,
    wots_keygen,
    wots_verify,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret"
UINT64_MAX = 2**64 - 1
SCHEME = "wots"


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(w=4):
    return WOTSOneTimeSigner(wots_keygen(w=w, token_bytes=counter_tokens())[0])


def wrap(signer, *, generation=7, key=KEY):
    return auth_state_wrap(
        signer.checkpoint(), scheme=SCHEME, key=key, generation=generation
    )


def _checkpoint_after(signer, message):
    signer.sign(message)
    return signer.checkpoint()


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


class SignWotsAuthStateTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.envelope = wrap(self.signer, generation=11)

    def test_returns_signature_envelope_and_generation(self):
        result = sign_wots_auth_state(
            self.envelope, b"m", key=KEY, claim=accept
        )
        self.assertEqual(len(result), 3)
        signature, envelope, generation = result
        self.assertIsInstance(signature, tuple)
        self.assertTrue(all(isinstance(element, bytes) for element in signature))
        self.assertIsInstance(envelope, bytes)
        self.assertEqual(generation, 12)
        self.assertIsInstance(generation, int)
        self.assertNotIsInstance(generation, bool)

    def test_signature_matches_plain_sign_from_same_state(self):
        reference = make_signer()
        signature, _, generation = sign_wots_auth_state(
            self.envelope, b"m", key=KEY, claim=accept
        )
        self.assertEqual(signature, reference.sign(b"m"))
        self.assertEqual(generation, 12)
        self.assertTrue(wots_verify(b"m", signature, self.signer.public_key))

    def test_signature_holds_for_w8_too(self):
        signer = make_signer(w=8)
        envelope = wrap(signer, generation=2)
        signature, next_envelope, generation = sign_wots_auth_state(
            envelope, b"m", key=KEY, claim=accept
        )
        self.assertTrue(wots_verify(b"m", signature, signer.public_key))
        self.assertEqual(len(signature), 34)
        self.assertEqual(generation, 3)
        scheme, _, checkpoint = auth_state_unwrap(
            next_envelope, key=KEY, expect=SCHEME
        )
        self.assertEqual(scheme, SCHEME)
        self.assertTrue(WOTSOneTimeSigner.from_checkpoint(checkpoint).used)

    def test_envelope_matches_explicit_wrap_at_g_plus_one(self):
        reference = make_signer()
        _, envelope, generation = sign_wots_auth_state(
            self.envelope, b"m", key=KEY, claim=accept
        )
        expected = auth_state_wrap(
            _checkpoint_after(reference, b"m"),
            scheme=SCHEME,
            key=KEY,
            generation=12,
        )
        self.assertEqual(generation, 12)
        self.assertEqual(envelope, expected)

    def test_returned_envelope_unwraps_to_used_state(self):
        signature, envelope, generation = sign_wots_auth_state(
            self.envelope, b"one", key=KEY, claim=accept
        )
        scheme, wrapped_generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect=SCHEME
        )
        self.assertEqual(scheme, SCHEME)
        self.assertEqual(wrapped_generation, generation)
        self.assertEqual(generation, 12)
        restored = WOTSOneTimeSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, self.signer.public_key)
        self.assertTrue(restored.used)
        with self.assertRaises(KeyExhaustedError):
            restored.sign(b"two")
        self.assertTrue(wots_verify(b"one", signature, self.signer.public_key))

    def test_accepts_str_message_and_bytearray_inputs(self):
        signature, envelope, generation = sign_wots_auth_state(
            bytearray(self.envelope),
            "message",
            key=bytearray(KEY),
            claim=accept,
        )
        reference = make_signer()
        reference_signature, reference_checkpoint = reference.sign_with_checkpoint(
            "message"
        )
        self.assertEqual(signature, reference_signature)
        self.assertEqual(generation, 12)
        self.assertEqual(
            envelope,
            auth_state_wrap(
                reference_checkpoint,
                scheme=SCHEME,
                key=KEY,
                generation=12,
            ),
        )

    def test_generation_endpoints(self):
        low = wrap(self.signer, generation=0)
        _, _, generation = sign_wots_auth_state(
            low, b"m", key=KEY, claim=accept
        )
        self.assertEqual(generation, 1)
        ceiling = wrap(self.signer, generation=UINT64_MAX - 1)
        _, envelope, generation = sign_wots_auth_state(
            ceiling, b"m", key=KEY, claim=accept
        )
        self.assertEqual(generation, UINT64_MAX)
        _, wrapped_generation, _ = auth_state_unwrap(
            envelope, key=KEY, expect=SCHEME
        )
        self.assertEqual(wrapped_generation, UINT64_MAX)

    def test_stateless_same_envelope_replays_identically(self):
        first = sign_wots_auth_state(
            self.envelope, b"m", key=KEY, claim=accept
        )
        second = sign_wots_auth_state(
            self.envelope, b"m", key=KEY, claim=accept
        )
        self.assertEqual(first, second)

    def test_does_not_mutate_state_behind_input_envelope(self):
        signer = make_signer()
        envelope = wrap(signer, generation=3)
        self.assertFalse(signer.used)
        sign_wots_auth_state(envelope, b"m", key=KEY, claim=accept)
        self.assertFalse(signer.used)
        signature = signer.sign(b"m")
        self.assertTrue(wots_verify(b"m", signature, signer.public_key))

    def test_floor_equal_and_below_pass(self):
        envelope = wrap(self.signer, generation=7)
        sign_wots_auth_state(envelope, b"m", key=KEY, min_generation=7,
                             claim=accept)
        sign_wots_auth_state(envelope, b"m", key=KEY, min_generation=6,
                             claim=accept)

    def test_floor_above_generation_fails_without_claim(self):
        claim = RecordingClaim()
        envelope = wrap(self.signer, generation=7)
        with self.assertRaises(ValueError):
            sign_wots_auth_state(
                envelope, b"m", key=KEY, min_generation=8, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_used_restored_signer_raises_key_exhausted_without_claim(self):
        signer = make_signer()
        signer.sign(b"a")
        envelope = wrap(signer, generation=3)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            sign_wots_auth_state(envelope, b"b", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError("sign_wots_auth_state must not draw randomness")

        with mock.patch.object(
            pqattest.secrets, "token_bytes", exploding_token_bytes
        ):
            signature, envelope, generation = sign_wots_auth_state(
                self.envelope, b"m", key=KEY, claim=accept
            )
        self.assertTrue(wots_verify(b"m", signature, self.signer.public_key))
        self.assertEqual(generation, 12)
        self.assertIsInstance(envelope, bytes)


class SignWotsAuthStateClaimTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.envelope = wrap(self.signer, generation=7)

    def test_claim_receives_exact_paired_token(self):
        claim = RecordingClaim()
        sign_wots_auth_state(self.envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [(("wots", 7), ("wots", 8))])

    def test_claim_called_exactly_once(self):
        claim = RecordingClaim()
        sign_wots_auth_state(self.envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(len(claim.calls), 1)

    def test_claim_token_is_a_pair_of_plain_tuples(self):
        seen = []
        sign_wots_auth_state(
            self.envelope, b"m", key=KEY,
            claim=lambda token: (seen.append(token), True)[1],
        )
        token = seen[0]
        self.assertIsInstance(token, tuple)
        self.assertEqual(len(token), 2)
        for side in token:
            self.assertIsInstance(side, tuple)
            self.assertEqual(len(side), 2)
            self.assertEqual(side[0], "wots")
            self.assertIs(type(side[1]), int)
            self.assertIsNot(type(side[1]), bool)
        self.assertEqual(token[0][1], 7)
        self.assertEqual(token[1][1], 8)
        self.assertEqual(token[1][1], token[0][1] + 1)

    def test_claim_false_rejected_after_outputs_exist(self):
        claim = RecordingClaim(result=False)
        with self.assertRaises(ValueError):
            sign_wots_auth_state(self.envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(len(claim.calls), 1)

    def test_truthy_non_true_rejected(self):
        for result in (1, "True", b"True", object()):
            with self.subTest(result=repr(result)):
                claim = RecordingClaim(result=result)
                with self.assertRaises(ValueError):
                    sign_wots_auth_state(
                        self.envelope, b"m", key=KEY, claim=claim
                    )
                self.assertEqual(len(claim.calls), 1)

    def test_claim_exception_propagates_untouched(self):
        class Boom(Exception):
            pass

        def boom(token):
            raise Boom

        with self.assertRaises(Boom):
            sign_wots_auth_state(self.envelope, b"m", key=KEY, claim=boom)

    def test_claim_not_called_on_wrong_key(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_wots_auth_state(
                self.envelope, b"m", key=OTHER_KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_tamper(self):
        claim = RecordingClaim()
        forged = bytearray(self.envelope)
        forged[30] ^= 0x01
        with self.assertRaises(ValueError):
            sign_wots_auth_state(bytes(forged), b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_v1_envelope(self):
        claim = RecordingClaim()
        v1 = auth_wrap(self.signer.checkpoint(), scheme=SCHEME, key=KEY)
        with self.assertRaises(ValueError):
            sign_wots_auth_state(v1, b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_other_scheme(self):
        lamport = OneTimeSigner(keygen(bits=32)[0])
        lamport_envelope = auth_state_wrap(
            lamport.checkpoint(), scheme="lamport", key=KEY, generation=7
        )

        def merkle_tokens(size):
            merkle_tokens.value += 1
            return merkle_tokens.value.to_bytes(8, "big").rjust(size, b"\x00")

        merkle_tokens.value = 0
        merkle = MerkleSigner(height=1, w=4, token_bytes=merkle_tokens)
        merkle_envelope = auth_state_wrap(
            merkle.checkpoint(), scheme="merkle", key=KEY, generation=7
        )
        claim = RecordingClaim()
        for envelope in (lamport_envelope, merkle_envelope):
            with self.subTest(scheme=envelope[9]):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    sign_wots_auth_state(
                        envelope, b"m", key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_garbage(self):
        claim = RecordingClaim()
        for bad in (b"", b"\x00", b"PQAAUTH\0", b"\x00" * 54,
                    self.envelope[:-1], self.envelope + b"\x00"):
            with self.subTest(length=len(bad)):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    sign_wots_auth_state(bad, b"m", key=KEY, claim=claim)
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_invalid_checkpoint(self):
        import hashlib
        import hmac

        payload = b"PQAWCP\0\0" + b"\x00" * 20
        body = (
            b"PQAAUTH\0"
            + bytes((2, 2))
            + (7).to_bytes(8, "big")
            + len(payload).to_bytes(4, "big")
            + payload
        )
        blob = body + hmac.new(KEY, body, hashlib.sha256).digest()
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_wots_auth_state(blob, b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_at_generation_ceiling(self):
        envelope = wrap(self.signer, generation=UINT64_MAX)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_wots_auth_state(envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_exhaustion(self):
        signer = make_signer()
        signer.sign(b"a")
        envelope = wrap(signer, generation=9)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            sign_wots_auth_state(envelope, b"b", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_bad_message(self):
        claim = RecordingClaim()
        for bad in (123, object(), [b"m"], None):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_wots_auth_state(
                        self.envelope, bad, key=KEY, claim=claim
                    )
        self.assertEqual(claim.calls, [])


class SignWotsAuthStateTypesTest(unittest.TestCase):
    def setUp(self):
        self.envelope = wrap(make_signer(), generation=1)

    def test_keyword_only_arguments(self):
        with self.assertRaises(TypeError):
            sign_wots_auth_state(self.envelope, b"m", KEY, None, accept)
        with self.assertRaises(TypeError):
            sign_wots_auth_state(self.envelope, b"m", KEY, claim=accept)

    def test_claim_is_required(self):
        with self.assertRaises(TypeError):
            sign_wots_auth_state(self.envelope, b"m", key=KEY)

    def test_non_bytes_data_type_error(self):
        for bad in (None, 42, 4.5, "blob", [self.envelope], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_wots_auth_state(bad, b"m", key=KEY, claim=accept)

    def test_non_bytes_key_type_error(self):
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_wots_auth_state(
                        self.envelope, b"m", key=bad, claim=accept
                    )

    def test_non_callable_claim_type_error(self):
        for bad in (None, True, 1, "claim", b"claim", (lambda: True,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_wots_auth_state(
                        self.envelope, b"m", key=KEY, claim=bad
                    )

    def test_bad_min_generation_type_error(self):
        for bad in (1.5, "0", [0], (0,), object(), True, False):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    sign_wots_auth_state(
                        self.envelope, b"m", key=KEY,
                        min_generation=bad, claim=accept,
                    )

    def test_empty_key_value_error(self):
        for bad in (b"", bytearray()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    sign_wots_auth_state(
                        self.envelope, b"m", key=bad, claim=accept
                    )

    def test_min_generation_out_of_range_value_error(self):
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    sign_wots_auth_state(
                        self.envelope, b"m", key=KEY,
                        min_generation=bad, claim=accept,
                    )

    def test_types_checked_before_envelope(self):
        with self.assertRaises(TypeError):
            sign_wots_auth_state(b"", b"m", key=42, claim=accept)
        with self.assertRaises(TypeError):
            sign_wots_auth_state(object(), b"m", key=KEY, claim=accept)
        with self.assertRaises(TypeError):
            sign_wots_auth_state(
                b"", b"m", key=KEY, min_generation=True, claim=accept
            )
        with self.assertRaises(TypeError):
            sign_wots_auth_state(b"", b"m", key=KEY, claim="claim")
        with self.assertRaises(TypeError):
            sign_wots_auth_state(b"", 123, key=KEY, claim=accept)


if __name__ == "__main__":
    unittest.main()

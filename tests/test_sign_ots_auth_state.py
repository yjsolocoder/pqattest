import hashlib
import hmac
import unittest
from unittest import mock

import pqattest
from pqattest import (
    KeyExhaustedError,
    OneTimeSigner,
    WOTSOneTimeSigner,
    auth_state_unwrap,
    auth_state_wrap,
    auth_wrap,
    keygen,
    sign_lamport_auth_state,
    sign_wots_auth_state,
    verify,
    wots_keygen,
    wots_verify,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret"
UINT64_MAX = 2**64 - 1


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


class _SchemeSpec:
    """Everything a test needs to exercise one one-time-scheme conversion."""

    scheme = None
    conversion = None
    other_scheme = None

    def fresh_signer(self):
        raise NotImplementedError

    def checkpoint(self, signer):
        return signer.checkpoint()

    def verify(self, message, signature, public_key):
        raise NotImplementedError

    def wrap(self, signer, *, generation=7, key=KEY):
        return auth_state_wrap(
            self.checkpoint(signer),
            scheme=self.scheme,
            key=key,
            generation=generation,
        )

    def wrap_bytes(self, payload, *, generation, key=KEY):
        return auth_state_wrap(
            payload, scheme=self.scheme, key=key, generation=generation
        )

    def other_envelope(self, generation=7):
        raise NotImplementedError

    def malformed_payload(self):
        raise NotImplementedError


class LamportSpec(_SchemeSpec):
    scheme = "lamport"
    conversion = staticmethod(sign_lamport_auth_state)
    other_scheme = "wots"

    def fresh_signer(self):
        return OneTimeSigner(keygen(bits=32)[0])

    def verify(self, message, signature, public_key):
        return verify(message, signature, public_key)

    def other_envelope(self, generation=7):
        signer = WOTSOneTimeSigner(wots_keygen(w=4)[0])
        return auth_state_wrap(
            signer.checkpoint(),
            scheme="wots",
            key=KEY,
            generation=generation,
        )

    def malformed_payload(self):
        return b"PQALCP\0\0" + b"\x00" * 20


class WotsSpec(_SchemeSpec):
    scheme = "wots"
    conversion = staticmethod(sign_wots_auth_state)
    other_scheme = "lamport"

    def __init__(self, w=4):
        self.w = w

    def fresh_signer(self):
        return WOTSOneTimeSigner(wots_keygen(w=self.w)[0])

    def verify(self, message, signature, public_key):
        return wots_verify(message, signature, public_key)

    def other_envelope(self, generation=7):
        signer = OneTimeSigner(keygen(bits=32)[0])
        return auth_state_wrap(
            signer.checkpoint(),
            scheme="lamport",
            key=KEY,
            generation=generation,
        )

    def malformed_payload(self):
        return b"PQAWCP\0\0" + b"\x00" * 20


class _SignOtsAuthStateMixin:
    """Shared behaviour tests; subclasses set ``self.spec``."""

    def setUp(self):
        self.spec = self.make_spec()
        self.signer = self.spec.fresh_signer()
        self.envelope = self.spec.wrap(self.signer, generation=11)

    # -- happy path ---------------------------------------------------------

    def test_returns_signature_envelope_and_generation(self):
        result = self.spec.conversion(self.envelope, b"m", key=KEY, claim=accept)
        self.assertEqual(len(result), 3)
        signature, envelope, generation = result
        self.assertIsInstance(signature, tuple)
        self.assertIsInstance(envelope, bytes)
        self.assertEqual(generation, 12)
        self.assertIs(type(generation), int)
        self.assertIsNot(type(generation), bool)

    def test_signature_matches_plain_first_sign_from_same_state(self):
        signature, _, generation = self.spec.conversion(
            self.envelope, b"m", key=KEY, claim=accept
        )
        reference = self.spec.fresh_signer()
        # The reference must be the same key the envelope holds; specs build
        # deterministic per-test keys via the signer, so rebuild via a fresh
        # envelope round trip instead (see the dedicated equality test below).
        self.assertEqual(generation, 12)
        self.assertTrue(self.spec.verify(b"m", signature, self.signer.public_key))

    def test_signature_value_equals_restored_signer_first_sign(self):
        signature, _, _ = self.spec.conversion(
            self.envelope, b"m", key=KEY, claim=accept
        )
        _, _, checkpoint = auth_state_unwrap(
            self.envelope, key=KEY, expect=self.spec.scheme
        )
        restored = type(self.signer).from_checkpoint(checkpoint)
        self.assertEqual(signature, restored.sign(b"m"))

    def test_envelope_matches_explicit_wrap_at_g_plus_one(self):
        signature, envelope, generation = self.spec.conversion(
            self.envelope, b"m", key=KEY, claim=accept
        )
        reference = type(self.signer).from_checkpoint(
            auth_state_unwrap(
                self.envelope, key=KEY, expect=self.spec.scheme
            )[2]
        )
        reference.sign(b"m")
        expected = auth_state_wrap(
            reference.checkpoint(),
            scheme=self.spec.scheme,
            key=KEY,
            generation=12,
        )
        self.assertEqual(generation, 12)
        self.assertEqual(envelope, expected)

    def test_returned_envelope_unwraps_to_used_state(self):
        signature, envelope, generation = self.spec.conversion(
            self.envelope, b"one", key=KEY, claim=accept
        )
        scheme, wrapped_generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect=self.spec.scheme
        )
        self.assertEqual(scheme, self.spec.scheme)
        self.assertEqual(wrapped_generation, generation)
        self.assertEqual(generation, 12)
        restored = type(self.signer).from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, self.signer.public_key)
        self.assertTrue(restored.used)
        with self.assertRaises(KeyExhaustedError):
            restored.sign(b"two")

    def test_accepts_str_message_and_bytearray_inputs(self):
        signature, envelope, generation = self.spec.conversion(
            bytearray(self.envelope),
            "message",
            key=bytearray(KEY),
            claim=accept,
        )
        self.assertEqual(generation, 12)
        self.assertTrue(self.spec.verify("message", signature, self.signer.public_key))
        reference = type(self.signer).from_checkpoint(
            auth_state_unwrap(
                self.envelope, key=KEY, expect=self.spec.scheme
            )[2]
        )
        self.assertEqual(signature, reference.sign("message"))
        self.assertEqual(
            envelope,
            auth_state_wrap(
                type(self.signer).from_checkpoint(
                    auth_state_unwrap(
                        self.envelope, key=KEY, expect=self.spec.scheme
                    )[2]
                ).sign_with_checkpoint("message")[1],
                scheme=self.spec.scheme,
                key=KEY,
                generation=12,
            ),
        )

    def test_generation_endpoints(self):
        low = self.spec.wrap(self.signer, generation=0)
        _, _, generation = self.spec.conversion(
            low, b"m", key=KEY, claim=accept
        )
        self.assertEqual(generation, 1)
        ceiling = self.spec.wrap(self.signer, generation=UINT64_MAX - 1)
        _, envelope, generation = self.spec.conversion(
            ceiling, b"m", key=KEY, claim=accept
        )
        self.assertEqual(generation, UINT64_MAX)
        _, wrapped_generation, _ = auth_state_unwrap(
            envelope, key=KEY, expect=self.spec.scheme
        )
        self.assertEqual(wrapped_generation, UINT64_MAX)

    def test_stateless_same_envelope_replays_identically(self):
        first = self.spec.conversion(self.envelope, b"m", key=KEY, claim=accept)
        second = self.spec.conversion(self.envelope, b"m", key=KEY, claim=accept)
        self.assertEqual(first, second)

    def test_advanced_envelope_is_exhausted(self):
        _, envelope, _ = self.spec.conversion(
            self.envelope, b"m", key=KEY, claim=accept
        )
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            self.spec.conversion(envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_does_not_mutate_state_behind_input_envelope(self):
        self.assertFalse(self.signer.used)
        self.spec.conversion(self.envelope, b"m", key=KEY, claim=accept)
        self.assertFalse(self.signer.used)
        # The original signer can still sign: nothing was spent in place.
        self.spec.conversion(
            self.spec.wrap(self.signer, generation=12),
            b"m",
            key=KEY,
            claim=accept,
        )

    def test_floor_equal_and_below_pass(self):
        envelope = self.spec.wrap(self.signer, generation=7)
        self.spec.conversion(
            envelope, b"m", key=KEY, min_generation=7, claim=accept
        )
        self.spec.conversion(
            envelope, b"m", key=KEY, min_generation=6, claim=accept
        )

    def test_floor_above_generation_fails_without_claim(self):
        claim = RecordingClaim()
        envelope = self.spec.wrap(self.signer, generation=7)
        with self.assertRaises(ValueError):
            self.spec.conversion(
                envelope, b"m", key=KEY, min_generation=8, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_exhausted_restored_signer_raises_without_claim(self):
        self.signer.sign(b"a")
        envelope = self.spec.wrap(self.signer, generation=3)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            self.spec.conversion(envelope, b"c", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError("conversion must not draw randomness")

        with mock.patch.object(
            pqattest.secrets, "token_bytes", exploding_token_bytes
        ):
            signature, envelope, generation = self.spec.conversion(
                self.envelope, b"m", key=KEY, claim=accept
            )
        self.assertTrue(
            self.spec.verify(b"m", signature, self.signer.public_key)
        )
        self.assertEqual(generation, 12)
        self.assertIsInstance(envelope, bytes)

    # -- claim semantics ----------------------------------------------------

    def test_claim_receives_exact_paired_token(self):
        claim = RecordingClaim()
        self.spec.conversion(self.envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(
            claim.calls,
            [((self.spec.scheme, 11), (self.spec.scheme, 12))],
        )

    def test_claim_called_exactly_once(self):
        claim = RecordingClaim()
        self.spec.conversion(self.envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(len(claim.calls), 1)

    def test_claim_token_is_a_pair_of_plain_tuples_old_first(self):
        seen = []
        self.spec.conversion(
            self.envelope, b"m", key=KEY,
            claim=lambda token: (seen.append(token), True)[1],
        )
        token = seen[0]
        self.assertIsInstance(token, tuple)
        self.assertEqual(len(token), 2)
        old, new = token
        self.assertEqual(old, (self.spec.scheme, 11))
        self.assertEqual(new, (self.spec.scheme, 12))
        for side in token:
            self.assertIsInstance(side, tuple)
            self.assertEqual(len(side), 2)
            self.assertEqual(side[0], self.spec.scheme)
            self.assertIs(type(side[1]), int)
            self.assertIsNot(type(side[1]), bool)

    def test_claim_false_rejected_after_outputs_exist(self):
        claim = RecordingClaim(result=False)
        with self.assertRaises(ValueError):
            self.spec.conversion(self.envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(len(claim.calls), 1)

    def test_truthy_non_true_rejected(self):
        for result in (1, "True", b"True", object()):
            with self.subTest(result=repr(result)):
                claim = RecordingClaim(result=result)
                with self.assertRaises(ValueError):
                    self.spec.conversion(
                        self.envelope, b"m", key=KEY, claim=claim
                    )
                self.assertEqual(len(claim.calls), 1)

    def test_claim_exception_propagates_untouched(self):
        class Boom(Exception):
            pass

        def boom(token):
            raise Boom

        with self.assertRaises(Boom):
            self.spec.conversion(self.envelope, b"m", key=KEY, claim=boom)

    def test_claim_not_called_on_wrong_key(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            self.spec.conversion(
                self.envelope, b"m", key=OTHER_KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_tamper(self):
        claim = RecordingClaim()
        forged = bytearray(self.envelope)
        forged[30] ^= 0x01
        with self.assertRaises(ValueError):
            self.spec.conversion(bytes(forged), b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_v1_envelope(self):
        claim = RecordingClaim()
        v1 = auth_wrap(
            self.signer.checkpoint(), scheme=self.spec.scheme, key=KEY
        )
        with self.assertRaises(ValueError):
            self.spec.conversion(v1, b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_other_scheme(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            self.spec.conversion(
                self.spec.other_envelope(generation=7), b"m", key=KEY,
                claim=claim,
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_garbage(self):
        claim = RecordingClaim()
        for bad in (b"", b"\x00", b"PQAAUTH\0", b"\x00" * 54,
                    self.envelope[:-1], self.envelope + b"\x00"):
            with self.subTest(length=len(bad)):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    self.spec.conversion(bad, b"m", key=KEY, claim=claim)
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_invalid_checkpoint(self):
        payload = self.spec.malformed_payload()
        body = (
            b"PQAAUTH\0"
            + bytes((2, 1 if self.spec.scheme == "lamport" else 2))
            + (7).to_bytes(8, "big")
            + len(payload).to_bytes(4, "big")
            + payload
        )
        blob = body + hmac.new(KEY, body, hashlib.sha256).digest()
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            self.spec.conversion(blob, b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_at_generation_ceiling(self):
        envelope = self.spec.wrap(self.signer, generation=UINT64_MAX)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            self.spec.conversion(envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_exhaustion(self):
        self.signer.sign(b"a")
        envelope = self.spec.wrap(self.signer, generation=9)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            self.spec.conversion(envelope, b"c", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_bad_message(self):
        claim = RecordingClaim()
        for bad in (123, object(), [b"m"]):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self.spec.conversion(
                        self.envelope, bad, key=KEY, claim=claim
                    )
        self.assertEqual(claim.calls, [])

    # -- argument types -----------------------------------------------------

    def test_keyword_only_arguments(self):
        with self.assertRaises(TypeError):
            self.spec.conversion(self.envelope, b"m", KEY, None, accept)
        with self.assertRaises(TypeError):
            self.spec.conversion(self.envelope, b"m", KEY, claim=accept)

    def test_claim_is_required(self):
        with self.assertRaises(TypeError):
            self.spec.conversion(self.envelope, b"m", key=KEY)

    def test_non_bytes_data_type_error(self):
        for bad in (None, 42, 4.5, "blob", [self.envelope], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self.spec.conversion(bad, b"m", key=KEY, claim=accept)

    def test_non_bytes_key_type_error(self):
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self.spec.conversion(
                        self.envelope, b"m", key=bad, claim=accept
                    )

    def test_non_callable_claim_type_error(self):
        for bad in (None, True, 1, "claim", b"claim", (lambda: True,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self.spec.conversion(
                        self.envelope, b"m", key=KEY, claim=bad
                    )

    def test_bad_min_generation_type_error(self):
        for bad in (1.5, "0", [0], (0,), object(), True, False):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    self.spec.conversion(
                        self.envelope, b"m", key=KEY,
                        min_generation=bad, claim=accept,
                    )

    def test_empty_key_value_error(self):
        for bad in (b"", bytearray()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    self.spec.conversion(
                        self.envelope, b"m", key=bad, claim=accept
                    )

    def test_min_generation_out_of_range_value_error(self):
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.spec.conversion(
                        self.envelope, b"m", key=KEY,
                        min_generation=bad, claim=accept,
                    )

    def test_types_checked_before_envelope(self):
        with self.assertRaises(TypeError):
            self.spec.conversion(b"", b"m", key=42, claim=accept)
        with self.assertRaises(TypeError):
            self.spec.conversion(object(), b"m", key=KEY, claim=accept)
        with self.assertRaises(TypeError):
            self.spec.conversion(
                b"", b"m", key=KEY, min_generation=True, claim=accept
            )
        with self.assertRaises(TypeError):
            self.spec.conversion(b"", b"m", key=KEY, claim="claim")
        with self.assertRaises(TypeError):
            self.spec.conversion(b"", 123, key=KEY, claim=accept)


class SignLamportAuthStateTest(_SignOtsAuthStateMixin, unittest.TestCase):
    def make_spec(self):
        return LamportSpec()


class SignWotsAuthStateTestW4(_SignOtsAuthStateMixin, unittest.TestCase):
    def make_spec(self):
        return WotsSpec(w=4)


class SignWotsAuthStateTestW8(_SignOtsAuthStateMixin, unittest.TestCase):
    def make_spec(self):
        return WotsSpec(w=8)


if __name__ == "__main__":
    unittest.main()

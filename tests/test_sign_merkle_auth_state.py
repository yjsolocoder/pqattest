import unittest
from unittest import mock

import pqattest
from pqattest import (
    KeyExhaustedError,
    MerkleSignature,
    MerkleSigner,
    OneTimeSigner,
    auth_state_wrap,
    auth_wrap,
    keygen,
    merkle_verify,
    sign_merkle_auth_state,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret"
UINT64_MAX = 2**64 - 1


def make_merkle(height=2, w=4):
    return MerkleSigner(height=height, w=w)


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


class SignMerkleAuthStateTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_merkle()
        self.envelope = wrap_merkle(self.signer, generation=11)

    def test_returns_signature_envelope_and_generation(self):
        signature, envelope, generation = sign_merkle_auth_state(
            self.envelope, b"msg", key=KEY, claim=lambda token: True
        )
        self.assertIsInstance(signature, MerkleSignature)
        self.assertIsInstance(envelope, bytes)
        self.assertEqual(generation, 12)
        self.assertIsInstance(generation, int)
        self.assertNotIsInstance(generation, bool)

    def test_signature_matches_manual_restore_and_sign(self):
        reference = MerkleSigner.from_checkpoint(self.signer.checkpoint())
        expected = reference.sign(b"msg")
        signature, _, _ = sign_merkle_auth_state(
            self.envelope, b"msg", key=KEY, claim=lambda token: True
        )
        self.assertEqual(signature, expected)
        self.assertEqual(signature.index, 0)
        self.assertTrue(merkle_verify(b"msg", signature, self.signer.public_key))

    def test_signs_current_lowest_leaf_of_restored_state(self):
        self.signer.sign(b"earlier")
        envelope = wrap_merkle(self.signer, generation=3)
        signature, _, generation = sign_merkle_auth_state(
            envelope, b"msg", key=KEY, claim=lambda token: True
        )
        self.assertEqual(signature.index, 1)
        self.assertEqual(generation, 4)
        self.assertTrue(merkle_verify(b"msg", signature, self.signer.public_key))

    def test_envelope_matches_manual_sign_and_wrap(self):
        reference = MerkleSigner.from_checkpoint(self.signer.checkpoint())
        reference.sign(b"msg")
        expected = auth_state_wrap(
            reference.checkpoint(), scheme="merkle", key=KEY, generation=12
        )
        _, envelope, _ = sign_merkle_auth_state(
            self.envelope, b"msg", key=KEY, claim=lambda token: True
        )
        self.assertEqual(envelope, expected)

    def test_output_envelope_restores_advanced_state(self):
        _, envelope, generation = sign_merkle_auth_state(
            self.envelope, b"msg", key=KEY, claim=lambda token: True
        )
        restored, restored_generation = MerkleSigner.from_auth_state(
            envelope, key=KEY
        )
        self.assertEqual(restored_generation, generation)
        self.assertEqual(restored.public_key, self.signer.public_key)
        self.assertEqual(restored.next_index, 1)

    def test_chained_calls_advance_generation_and_leaf(self):
        envelope = self.envelope
        for expected_index, expected_generation in ((0, 12), (1, 13), (2, 14)):
            signature, envelope, generation = sign_merkle_auth_state(
                envelope, b"m", key=KEY, claim=lambda token: True
            )
            self.assertEqual(signature.index, expected_index)
            self.assertEqual(generation, expected_generation)

    def test_accepts_bytearray_data_and_key(self):
        signature, envelope, generation = sign_merkle_auth_state(
            bytearray(self.envelope),
            b"msg",
            key=bytearray(KEY),
            claim=lambda token: True,
        )
        self.assertEqual(generation, 12)
        self.assertTrue(merkle_verify(b"msg", signature, self.signer.public_key))

    def test_message_rules_match_sign(self):
        for message in (b"bytes", bytearray(b"bytes"), "text"):
            with self.subTest(message=type(message).__name__):
                signature, _, _ = sign_merkle_auth_state(
                    self.envelope, message, key=KEY, claim=lambda token: True
                )
                self.assertTrue(
                    merkle_verify(message, signature, self.signer.public_key)
                )

    def test_floor_equal_and_below_pass(self):
        envelope = wrap_merkle(self.signer, generation=7)
        for floor in (None, 6, 7):
            with self.subTest(floor=floor):
                _, _, generation = sign_merkle_auth_state(
                    envelope, b"m", key=KEY, min_generation=floor,
                    claim=lambda token: True,
                )
                self.assertEqual(generation, 8)

    def test_floor_above_generation_fails_without_claim(self):
        claim = RecordingClaim()
        envelope = wrap_merkle(self.signer, generation=7)
        with self.assertRaises(ValueError):
            sign_merkle_auth_state(
                envelope, b"m", key=KEY, min_generation=8, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_exhausted_checkpoint_raises_without_claim(self):
        signer = make_merkle(height=1)
        signer.sign(b"a")
        signer.sign(b"b")
        envelope = wrap_merkle(signer, generation=3)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            sign_merkle_auth_state(envelope, b"c", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_max_generation_raises_value_error_without_claim(self):
        envelope = wrap_merkle(self.signer, generation=UINT64_MAX)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_merkle_auth_state(envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_generation_below_max_round_trips(self):
        envelope = wrap_merkle(self.signer, generation=UINT64_MAX - 1)
        _, _, generation = sign_merkle_auth_state(
            envelope, b"m", key=KEY, claim=lambda token: True
        )
        self.assertEqual(generation, UINT64_MAX)

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError("sign_merkle_auth_state must not draw randomness")

        with mock.patch.object(
            pqattest.secrets, "token_bytes", exploding_token_bytes
        ):
            signature, _, _ = sign_merkle_auth_state(
                self.envelope, b"m", key=KEY, claim=lambda token: True
            )
        self.assertTrue(merkle_verify(b"m", signature, self.signer.public_key))


class SignMerkleAuthStateClaimTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_merkle()
        self.envelope = wrap_merkle(self.signer, generation=7)

    def test_claim_receives_exact_single_token(self):
        claim = RecordingClaim()
        sign_merkle_auth_state(self.envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [(("merkle", 7), ("merkle", 8))])

    def test_claim_called_exactly_once(self):
        claim = RecordingClaim()
        sign_merkle_auth_state(self.envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(len(claim.calls), 1)

    def test_claim_token_shape(self):
        seen = []
        sign_merkle_auth_state(
            self.envelope, b"m", key=KEY,
            claim=lambda token: (seen.append(token), True)[1],
        )
        token = seen[0]
        self.assertIsInstance(token, tuple)
        self.assertEqual(len(token), 2)
        for position, generation in ((0, 7), (1, 8)):
            part = token[position]
            self.assertIsInstance(part, tuple)
            self.assertEqual(part[0], "merkle")
            self.assertEqual(part[1], generation)
            self.assertIs(type(part[1]), int)

    def test_claim_false_rejected(self):
        claim = RecordingClaim(result=False)
        with self.assertRaises(ValueError):
            sign_merkle_auth_state(self.envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(len(claim.calls), 1)

    def test_truthy_non_true_rejected(self):
        for result in (1, "True", b"True", object()):
            with self.subTest(result=repr(result)):
                claim = RecordingClaim(result=result)
                with self.assertRaises(ValueError):
                    sign_merkle_auth_state(self.envelope, b"m", key=KEY, claim=claim)
                self.assertEqual(len(claim.calls), 1)

    def test_claim_exception_propagates(self):
        class Boom(Exception):
            pass

        def boom(token):
            raise Boom

        with self.assertRaises(Boom):
            sign_merkle_auth_state(self.envelope, b"m", key=KEY, claim=boom)

    def test_claim_not_called_on_wrong_key(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_merkle_auth_state(self.envelope, b"m", key=OTHER_KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_tamper(self):
        claim = RecordingClaim()
        forged = bytearray(self.envelope)
        forged[30] ^= 0x01
        with self.assertRaises(ValueError):
            sign_merkle_auth_state(bytes(forged), b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_v1_envelope(self):
        claim = RecordingClaim()
        v1 = auth_wrap(self.signer.checkpoint(), scheme="merkle", key=KEY)
        with self.assertRaises(ValueError):
            sign_merkle_auth_state(v1, b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_other_scheme(self):
        lamport = OneTimeSigner(keygen(bits=32)[0])
        lamport_envelope = auth_state_wrap(
            lamport.checkpoint(), scheme="lamport", key=KEY, generation=7
        )
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_merkle_auth_state(lamport_envelope, b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_garbage(self):
        claim = RecordingClaim()
        for bad in (b"", b"\x00", b"PQAAUTH\0", b"\x00" * 54,
                    self.envelope[:-1], self.envelope + b"\x00"):
            with self.subTest(length=len(bad)):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    sign_merkle_auth_state(bad, b"m", key=KEY, claim=claim)
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
            sign_merkle_auth_state(blob, b"m", key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])


class SignMerkleAuthStateTypesTest(unittest.TestCase):
    def setUp(self):
        self.envelope = wrap_merkle(make_merkle(), generation=1)

    def test_keyword_only_arguments(self):
        with self.assertRaises(TypeError):
            sign_merkle_auth_state(
                self.envelope, b"m", KEY, None, lambda token: True
            )
        with self.assertRaises(TypeError):
            sign_merkle_auth_state(self.envelope, b"m", KEY, claim=lambda token: True)

    def test_claim_is_required(self):
        with self.assertRaises(TypeError):
            sign_merkle_auth_state(self.envelope, b"m", key=KEY)

    def test_non_bytes_data_type_error(self):
        for bad in (None, 42, 4.5, "blob", [self.envelope], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_merkle_auth_state(
                        bad, b"m", key=KEY, claim=lambda token: True
                    )

    def test_bad_message_type_error(self):
        for bad in (None, 42, 4.5, [b"m"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_merkle_auth_state(
                        self.envelope, bad, key=KEY, claim=lambda token: True
                    )

    def test_non_bytes_key_type_error(self):
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_merkle_auth_state(
                        self.envelope, b"m", key=bad, claim=lambda token: True
                    )

    def test_non_callable_claim_type_error(self):
        for bad in (None, True, 1, "claim", b"claim", (lambda: True,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_merkle_auth_state(self.envelope, b"m", key=KEY, claim=bad)

    def test_bad_min_generation_type_error(self):
        for bad in (1.5, "0", [0], (0,), object(), True, False):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    sign_merkle_auth_state(
                        self.envelope, b"m", key=KEY, min_generation=bad,
                        claim=lambda token: True,
                    )

    def test_empty_key_value_error(self):
        for bad in (b"", bytearray()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    sign_merkle_auth_state(
                        self.envelope, b"m", key=bad, claim=lambda token: True
                    )

    def test_min_generation_out_of_range_value_error(self):
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    sign_merkle_auth_state(
                        self.envelope, b"m", key=KEY, min_generation=bad,
                        claim=lambda token: True,
                    )

    def test_types_checked_before_envelope(self):
        with self.assertRaises(TypeError):
            sign_merkle_auth_state(b"", b"m", key=42, claim=lambda token: True)
        with self.assertRaises(TypeError):
            sign_merkle_auth_state(object(), b"m", key=KEY, claim=lambda token: True)
        with self.assertRaises(TypeError):
            sign_merkle_auth_state(b"", None, key=KEY, claim=lambda token: True)
        with self.assertRaises(TypeError):
            sign_merkle_auth_state(
                b"", b"m", key=KEY, min_generation=True, claim=lambda token: True
            )
        with self.assertRaises(TypeError):
            sign_merkle_auth_state(b"", b"m", key=KEY, claim="claim")


if __name__ == "__main__":
    unittest.main()

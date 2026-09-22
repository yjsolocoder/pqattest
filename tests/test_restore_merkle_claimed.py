import unittest
from unittest import mock

import pqattest
from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    OneTimeSigner,
    WOTSOneTimeSigner,
    auth_state_wrap,
    auth_wrap,
    keygen,
    restore_merkle_claimed,
    wots_keygen,
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


class RestoreMerkleClaimedTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_merkle()
        self.envelope = wrap_merkle(self.signer, generation=11)

    def test_returns_signer_and_generation(self):
        restored, generation = restore_merkle_claimed(
            self.envelope, key=KEY, claim=lambda token: True
        )
        self.assertIsInstance(restored, MerkleSigner)
        self.assertEqual(generation, 11)
        self.assertIsInstance(generation, int)
        self.assertNotIsInstance(generation, bool)

    def test_restores_public_key_and_next_index(self):
        self.signer.sign(b"one")
        envelope = wrap_merkle(self.signer, generation=5)
        restored, generation = restore_merkle_claimed(
            envelope, key=KEY, claim=lambda token: True
        )
        self.assertEqual(restored.public_key, self.signer.public_key)
        self.assertEqual(restored.next_index, 1)
        self.assertEqual(generation, 5)

    def test_restored_signer_resumes_signing(self):
        restored, generation = restore_merkle_claimed(
            self.envelope, key=KEY, claim=lambda token: True
        )
        self.assertEqual(generation, 11)
        restored.sign(b"m")
        self.assertEqual(restored.next_index, 1)

    def test_restored_exhausted_signer_stays_exhausted(self):
        signer = make_merkle(height=1)
        signer.sign(b"a")
        signer.sign(b"b")
        envelope = wrap_merkle(signer, generation=3)
        restored, generation = restore_merkle_claimed(
            envelope, key=KEY, claim=lambda token: True
        )
        self.assertEqual(generation, 3)
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign(b"c")

    def test_accepts_bytearray_inputs(self):
        restored, generation = restore_merkle_claimed(
            bytearray(self.envelope),
            key=bytearray(KEY),
            claim=lambda token: True,
        )
        self.assertEqual(restored.public_key, self.signer.public_key)
        self.assertEqual(generation, 11)

    def test_generation_endpoints_round_trip(self):
        for generation in (0, UINT64_MAX):
            with self.subTest(generation=generation):
                envelope = wrap_merkle(self.signer, generation=generation)
                _, restored_generation = restore_merkle_claimed(
                    envelope, key=KEY, claim=lambda token: True
                )
                self.assertEqual(restored_generation, generation)

    def test_floor_equal_and_below_pass(self):
        envelope = wrap_merkle(self.signer, generation=7)
        restore_merkle_claimed(
            envelope, key=KEY, floor=7, claim=lambda token: True
        )
        restore_merkle_claimed(
            envelope, key=KEY, floor=6, claim=lambda token: True
        )

    def test_floor_above_generation_fails_without_claim(self):
        claim = RecordingClaim()
        envelope = wrap_merkle(self.signer, generation=7)
        with self.assertRaises(ValueError):
            restore_merkle_claimed(envelope, key=KEY, floor=8, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError("restore_merkle_claimed must not draw randomness")

        with mock.patch.object(
            pqattest.secrets, "token_bytes", exploding_token_bytes
        ):
            restored, _ = restore_merkle_claimed(
                self.envelope, key=KEY, claim=lambda token: True
            )
        self.assertEqual(restored.public_key, self.signer.public_key)


class RestoreMerkleClaimedClaimTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_merkle()
        self.envelope = wrap_merkle(self.signer, generation=7)

    def test_claim_receives_exact_single_token(self):
        claim = RecordingClaim()
        restore_merkle_claimed(self.envelope, key=KEY, claim=claim)
        self.assertEqual(claim.calls, [("merkle", 7)])

    def test_claim_called_exactly_once(self):
        claim = RecordingClaim()
        restore_merkle_claimed(self.envelope, key=KEY, claim=claim)
        self.assertEqual(len(claim.calls), 1)

    def test_claim_token_is_a_plain_tuple_of_str_and_int(self):
        seen = []
        restore_merkle_claimed(
            self.envelope, key=KEY, claim=lambda token: (seen.append(token), True)[1]
        )
        token = seen[0]
        self.assertIsInstance(token, tuple)
        self.assertEqual(len(token), 2)
        self.assertEqual(token[0], "merkle")
        self.assertEqual(token[1], 7)
        self.assertIs(type(token[1]), int)
        self.assertIsNot(type(token[1]), bool)

    def test_claim_false_rejected(self):
        claim = RecordingClaim(result=False)
        with self.assertRaises(ValueError):
            restore_merkle_claimed(self.envelope, key=KEY, claim=claim)
        self.assertEqual(len(claim.calls), 1)

    def test_truthy_non_true_rejected(self):
        for result in (1, "True", b"True", object()):
            with self.subTest(result=repr(result)):
                claim = RecordingClaim(result=result)
                with self.assertRaises(ValueError):
                    restore_merkle_claimed(self.envelope, key=KEY, claim=claim)
                self.assertEqual(len(claim.calls), 1)

    def test_claim_exception_propagates(self):
        class Boom(Exception):
            pass

        def boom(token):
            raise Boom

        with self.assertRaises(Boom):
            restore_merkle_claimed(self.envelope, key=KEY, claim=boom)

    def test_claim_not_called_on_wrong_key(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            restore_merkle_claimed(self.envelope, key=OTHER_KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_tamper(self):
        claim = RecordingClaim()
        forged = bytearray(self.envelope)
        forged[30] ^= 0x01
        with self.assertRaises(ValueError):
            restore_merkle_claimed(bytes(forged), key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_v1_envelope(self):
        claim = RecordingClaim()
        v1 = auth_wrap(self.signer.checkpoint(), scheme="merkle", key=KEY)
        with self.assertRaises(ValueError):
            restore_merkle_claimed(v1, key=KEY, claim=claim)
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
                    restore_merkle_claimed(envelope, key=KEY, claim=claim)
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_garbage(self):
        claim = RecordingClaim()
        for bad in (b"", b"\x00", b"PQAAUTH\0", b"\x00" * 54,
                    self.envelope[:-1], self.envelope + b"\x00"):
            with self.subTest(length=len(bad)):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    restore_merkle_claimed(bad, key=KEY, claim=claim)
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
            restore_merkle_claimed(blob, key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])


class RestoreMerkleClaimedTypesTest(unittest.TestCase):
    def setUp(self):
        self.envelope = wrap_merkle(make_merkle(), generation=1)

    def test_keyword_only_arguments(self):
        with self.assertRaises(TypeError):
            restore_merkle_claimed(self.envelope, KEY, None, lambda token: True)
        with self.assertRaises(TypeError):
            restore_merkle_claimed(self.envelope, KEY, claim=lambda token: True)

    def test_claim_is_required(self):
        with self.assertRaises(TypeError):
            restore_merkle_claimed(self.envelope, key=KEY)

    def test_non_bytes_data_type_error(self):
        for bad in (None, 42, 4.5, "blob", [self.envelope], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    restore_merkle_claimed(bad, key=KEY, claim=lambda token: True)

    def test_non_bytes_key_type_error(self):
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    restore_merkle_claimed(
                        self.envelope, key=bad, claim=lambda token: True
                    )

    def test_non_callable_claim_type_error(self):
        for bad in (None, True, 1, "claim", b"claim", (lambda: True,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    restore_merkle_claimed(self.envelope, key=KEY, claim=bad)

    def test_bad_floor_type_error(self):
        for bad in (1.5, "0", [0], (0,), object(), True, False):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    restore_merkle_claimed(
                        self.envelope, key=KEY, floor=bad,
                        claim=lambda token: True,
                    )

    def test_empty_key_value_error(self):
        for bad in (b"", bytearray()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    restore_merkle_claimed(
                        self.envelope, key=bad, claim=lambda token: True
                    )

    def test_floor_out_of_range_value_error(self):
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    restore_merkle_claimed(
                        self.envelope, key=KEY, floor=bad,
                        claim=lambda token: True,
                    )

    def test_types_checked_before_envelope(self):
        with self.assertRaises(TypeError):
            restore_merkle_claimed(b"", key=42, claim=lambda token: True)
        with self.assertRaises(TypeError):
            restore_merkle_claimed(object(), key=KEY, claim=lambda token: True)
        with self.assertRaises(TypeError):
            restore_merkle_claimed(
                b"", key=KEY, floor=True, claim=lambda token: True
            )
        with self.assertRaises(TypeError):
            restore_merkle_claimed(b"", key=KEY, claim="claim")


if __name__ == "__main__":
    unittest.main()

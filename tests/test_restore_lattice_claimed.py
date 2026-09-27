import hashlib
import hmac
import unittest
from unittest import mock

import pqattest
from pqattest import (
    OneTimeSigner,
    ToyLatticePrivateKey,
    auth_state_unwrap,
    auth_state_wrap,
    auth_unwrap,
    auth_wrap,
    keygen,
    restore_lattice_claimed,
    toy_lattice_keygen,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret"
UINT64_MAX = 2**64 - 1


def make_private_key():
    private_key, _ = toy_lattice_keygen()
    return private_key


def wrap_lattice(private_key, *, generation=7, key=KEY):
    return auth_state_wrap(
        private_key.to_bytes(), scheme="lattice", key=key, generation=generation
    )


class RecordingClaim:
    """Callable that records every token it is given and returns a fixed value."""

    def __init__(self, result=True):
        self.calls = []
        self.result = result

    def __call__(self, token):
        self.calls.append(token)
        return self.result


class LatticeAuthWrapTest(unittest.TestCase):
    def setUp(self):
        self.private_key = make_private_key()
        self.payload = self.private_key.to_bytes()

    def test_v1_round_trip(self):
        blob = auth_wrap(self.payload, scheme="lattice", key=KEY)
        scheme, payload = auth_unwrap(blob, key=KEY)
        self.assertEqual(scheme, "lattice")
        self.assertEqual(payload, self.payload)
        self.assertIsInstance(payload, bytes)

    def test_v1_expect_lattice(self):
        blob = auth_wrap(self.payload, scheme="lattice", key=KEY)
        scheme, _ = auth_unwrap(blob, key=KEY, expect="lattice")
        self.assertEqual(scheme, "lattice")

    def test_v1_scheme_identifier_is_4(self):
        blob = auth_wrap(self.payload, scheme="lattice", key=KEY)
        self.assertEqual(blob[8], 1)
        self.assertEqual(blob[9], 4)

    def test_v1_deterministic(self):
        self.assertEqual(
            auth_wrap(self.payload, scheme="lattice", key=KEY),
            auth_wrap(self.payload, scheme="lattice", key=KEY),
        )

    def test_v1_accepts_bytearray(self):
        blob = auth_wrap(bytearray(self.payload), scheme="lattice", key=KEY)
        scheme, payload = auth_unwrap(
            bytearray(blob), key=bytearray(KEY), expect="lattice"
        )
        self.assertEqual((scheme, payload), ("lattice", self.payload))

    def test_v1_payload_magic_mismatch(self):
        for bad in (b"", b"PQALSK\0", b"PQALPK\0\0" + self.payload[8:]):
            with self.subTest(bad=bad[:8]):
                with self.assertRaises(ValueError):
                    auth_wrap(bad, scheme="lattice", key=KEY)

    def test_v1_non_bytes_checkpoint_type_error(self):
        for bad in (None, 42, "payload", [self.payload], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_wrap(bad, scheme="lattice", key=KEY)

    def test_v1_expect_other_scheme_rejected(self):
        blob = auth_wrap(self.payload, scheme="lattice", key=KEY)
        for expect in ("lamport", "wots", "merkle"):
            with self.subTest(expect=expect):
                with self.assertRaises(ValueError):
                    auth_unwrap(blob, key=KEY, expect=expect)

    def test_v2_round_trip(self):
        envelope = wrap_lattice(self.private_key, generation=9)
        scheme, generation, payload = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(scheme, "lattice")
        self.assertEqual(generation, 9)
        self.assertEqual(payload, self.payload)

    def test_v2_expect_lattice(self):
        envelope = wrap_lattice(self.private_key, generation=9)
        scheme, generation, _ = auth_state_unwrap(
            envelope, key=KEY, expect="lattice"
        )
        self.assertEqual((scheme, generation), ("lattice", 9))

    def test_v2_scheme_identifier_is_4(self):
        envelope = wrap_lattice(self.private_key, generation=9)
        self.assertEqual(envelope[8], 2)
        self.assertEqual(envelope[9], 4)

    def test_v2_min_generation_floor(self):
        envelope = wrap_lattice(self.private_key, generation=7)
        auth_state_unwrap(envelope, key=KEY, min_generation=7)
        with self.assertRaises(ValueError):
            auth_state_unwrap(envelope, key=KEY, min_generation=8)

    def test_v2_payload_magic_mismatch(self):
        with self.assertRaises(ValueError):
            auth_state_wrap(
                b"PQALPK\0\0" + self.payload[8:],
                scheme="lattice",
                key=KEY,
                generation=0,
            )

    def test_existing_schemes_unchanged(self):
        lamport = OneTimeSigner(keygen(bits=8)[0])
        blob = auth_wrap(lamport.checkpoint(), scheme="lamport", key=KEY)
        self.assertEqual(blob[9], 1)
        scheme, payload = auth_unwrap(blob, key=KEY, expect="lamport")
        self.assertEqual(scheme, "lamport")
        self.assertEqual(payload, lamport.checkpoint())


class RestoreLatticeClaimedTest(unittest.TestCase):
    def setUp(self):
        self.private_key = make_private_key()
        self.envelope = wrap_lattice(self.private_key, generation=11)

    def test_returns_private_key_and_generation(self):
        restored, generation = restore_lattice_claimed(
            self.envelope, key=KEY, claim=lambda token: True
        )
        self.assertIsInstance(restored, ToyLatticePrivateKey)
        self.assertEqual(generation, 11)
        self.assertIsInstance(generation, int)
        self.assertNotIsInstance(generation, bool)

    def test_restored_key_equal_by_value(self):
        restored, _ = restore_lattice_claimed(
            self.envelope, key=KEY, claim=lambda token: True
        )
        self.assertEqual(restored, self.private_key)
        self.assertEqual(restored.to_bytes(), self.private_key.to_bytes())

    def test_restored_key_decapsulates(self):
        from pqattest import toy_lattice_decapsulate, toy_lattice_encapsulate

        private_key, public_key = toy_lattice_keygen()
        envelope = wrap_lattice(private_key, generation=1)
        restored, _ = restore_lattice_claimed(
            envelope, key=KEY, claim=lambda token: True
        )
        ciphertext, shared = toy_lattice_encapsulate(public_key)
        self.assertEqual(toy_lattice_decapsulate(ciphertext, restored), shared)

    def test_accepts_bytearray_inputs(self):
        restored, generation = restore_lattice_claimed(
            bytearray(self.envelope),
            key=bytearray(KEY),
            claim=lambda token: True,
        )
        self.assertEqual(restored, self.private_key)
        self.assertEqual(generation, 11)

    def test_generation_endpoints_round_trip(self):
        for generation in (0, UINT64_MAX):
            with self.subTest(generation=generation):
                envelope = wrap_lattice(self.private_key, generation=generation)
                _, restored_generation = restore_lattice_claimed(
                    envelope, key=KEY, claim=lambda token: True
                )
                self.assertEqual(restored_generation, generation)

    def test_floor_equal_and_below_pass(self):
        envelope = wrap_lattice(self.private_key, generation=7)
        restore_lattice_claimed(
            envelope, key=KEY, floor=7, claim=lambda token: True
        )
        restore_lattice_claimed(
            envelope, key=KEY, floor=6, claim=lambda token: True
        )

    def test_floor_above_generation_fails_without_claim(self):
        claim = RecordingClaim()
        envelope = wrap_lattice(self.private_key, generation=7)
        with self.assertRaises(ValueError):
            restore_lattice_claimed(envelope, key=KEY, floor=8, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError("restore_lattice_claimed must not draw randomness")

        with mock.patch.object(
            pqattest.secrets, "token_bytes", exploding_token_bytes
        ):
            restored, _ = restore_lattice_claimed(
                self.envelope, key=KEY, claim=lambda token: True
            )
        self.assertEqual(restored, self.private_key)


class RestoreLatticeClaimedClaimTest(unittest.TestCase):
    def setUp(self):
        self.private_key = make_private_key()
        self.envelope = wrap_lattice(self.private_key, generation=7)

    def test_claim_receives_exact_single_token(self):
        claim = RecordingClaim()
        restore_lattice_claimed(self.envelope, key=KEY, claim=claim)
        self.assertEqual(claim.calls, [("lattice", 7)])

    def test_claim_called_exactly_once(self):
        claim = RecordingClaim()
        restore_lattice_claimed(self.envelope, key=KEY, claim=claim)
        self.assertEqual(len(claim.calls), 1)

    def test_claim_token_is_a_plain_tuple_of_str_and_int(self):
        seen = []
        restore_lattice_claimed(
            self.envelope, key=KEY, claim=lambda token: (seen.append(token), True)[1]
        )
        token = seen[0]
        self.assertIsInstance(token, tuple)
        self.assertEqual(len(token), 2)
        self.assertEqual(token[0], "lattice")
        self.assertEqual(token[1], 7)
        self.assertIs(type(token[1]), int)
        self.assertIsNot(type(token[1]), bool)

    def test_claim_false_rejected(self):
        claim = RecordingClaim(result=False)
        with self.assertRaises(ValueError):
            restore_lattice_claimed(self.envelope, key=KEY, claim=claim)
        self.assertEqual(len(claim.calls), 1)

    def test_truthy_non_true_rejected(self):
        for result in (1, "True", b"True", object()):
            with self.subTest(result=repr(result)):
                claim = RecordingClaim(result=result)
                with self.assertRaises(ValueError):
                    restore_lattice_claimed(self.envelope, key=KEY, claim=claim)
                self.assertEqual(len(claim.calls), 1)

    def test_claim_exception_propagates(self):
        class Boom(Exception):
            pass

        def boom(token):
            raise Boom

        with self.assertRaises(Boom):
            restore_lattice_claimed(self.envelope, key=KEY, claim=boom)

    def test_claim_not_called_on_wrong_key(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            restore_lattice_claimed(self.envelope, key=OTHER_KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_tamper(self):
        claim = RecordingClaim()
        forged = bytearray(self.envelope)
        forged[30] ^= 0x01
        with self.assertRaises(ValueError):
            restore_lattice_claimed(bytes(forged), key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_v1_envelope(self):
        claim = RecordingClaim()
        v1 = auth_wrap(self.private_key.to_bytes(), scheme="lattice", key=KEY)
        with self.assertRaises(ValueError):
            restore_lattice_claimed(v1, key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_other_scheme(self):
        claim = RecordingClaim()
        lamport = OneTimeSigner(keygen(bits=8)[0])
        lamport_envelope = auth_state_wrap(
            lamport.checkpoint(), scheme="lamport", key=KEY, generation=7
        )
        with self.assertRaises(ValueError):
            restore_lattice_claimed(lamport_envelope, key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_garbage(self):
        claim = RecordingClaim()
        for bad in (b"", b"\x00", b"PQAAUTH\0", b"\x00" * 54,
                    self.envelope[:-1], self.envelope + b"\x00"):
            with self.subTest(length=len(bad)):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    restore_lattice_claimed(bad, key=KEY, claim=claim)
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_invalid_key_encoding(self):
        for payload in (
            b"PQALSK\0\0",  # truncated
            b"PQALSK\0\0\x02" + b"\x00" * 16,  # bad version
            self.private_key.to_bytes() + b"\x00",  # trailing
            b"PQALSK\0\0\x01" + b"\x01\x01" * 8,  # coefficients > 256
        ):
            with self.subTest(payload=payload[:12]):
                body = (
                    b"PQAAUTH\0"
                    + bytes((2, 4))
                    + (7).to_bytes(8, "big")
                    + len(payload).to_bytes(4, "big")
                    + payload
                )
                blob = body + hmac.new(KEY, body, hashlib.sha256).digest()
                claim = RecordingClaim()
                with self.assertRaises(ValueError):
                    restore_lattice_claimed(blob, key=KEY, claim=claim)
                self.assertEqual(claim.calls, [])


class RestoreLatticeClaimedTypesTest(unittest.TestCase):
    def setUp(self):
        self.envelope = wrap_lattice(make_private_key(), generation=1)

    def test_keyword_only_arguments(self):
        with self.assertRaises(TypeError):
            restore_lattice_claimed(self.envelope, KEY, None, lambda token: True)
        with self.assertRaises(TypeError):
            restore_lattice_claimed(self.envelope, KEY, claim=lambda token: True)

    def test_claim_is_required(self):
        with self.assertRaises(TypeError):
            restore_lattice_claimed(self.envelope, key=KEY)

    def test_non_bytes_data_type_error(self):
        for bad in (None, 42, 4.5, "blob", [self.envelope], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    restore_lattice_claimed(bad, key=KEY, claim=lambda token: True)

    def test_non_bytes_key_type_error(self):
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    restore_lattice_claimed(
                        self.envelope, key=bad, claim=lambda token: True
                    )

    def test_non_callable_claim_type_error(self):
        for bad in (None, True, 1, "claim", b"claim", (lambda: True,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    restore_lattice_claimed(self.envelope, key=KEY, claim=bad)

    def test_bad_floor_type_error(self):
        for bad in (1.5, "0", [0], (0,), object(), True, False):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    restore_lattice_claimed(
                        self.envelope, key=KEY, floor=bad,
                        claim=lambda token: True,
                    )

    def test_empty_key_value_error(self):
        for bad in (b"", bytearray()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    restore_lattice_claimed(
                        self.envelope, key=bad, claim=lambda token: True
                    )

    def test_floor_out_of_range_value_error(self):
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    restore_lattice_claimed(
                        self.envelope, key=KEY, floor=bad,
                        claim=lambda token: True,
                    )

    def test_types_checked_before_envelope(self):
        with self.assertRaises(TypeError):
            restore_lattice_claimed(b"", key=42, claim=lambda token: True)
        with self.assertRaises(TypeError):
            restore_lattice_claimed(object(), key=KEY, claim=lambda token: True)
        with self.assertRaises(TypeError):
            restore_lattice_claimed(
                b"", key=KEY, floor=True, claim=lambda token: True
            )
        with self.assertRaises(TypeError):
            restore_lattice_claimed(b"", key=KEY, claim="claim")


if __name__ == "__main__":
    unittest.main()

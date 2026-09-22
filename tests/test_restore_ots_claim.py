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
    restore_ots_pair,
    wots_keygen,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret"
UINT64_MAX = 2**64 - 1


def make_lamport(bits=32):
    return OneTimeSigner(keygen(bits=bits)[0])


def make_wots(w=4):
    return WOTSOneTimeSigner(wots_keygen(w=w)[0])


def wrap_lamport(signer, *, generation=7, key=KEY):
    return auth_state_wrap(
        signer.checkpoint(), scheme="lamport", key=key, generation=generation
    )


def wrap_wots(signer, *, generation=7, key=KEY):
    return auth_state_wrap(
        signer.checkpoint(), scheme="wots", key=key, generation=generation
    )


class RecordingClaim:
    """Callable that records every token it is given and returns a fixed value."""

    def __init__(self, result=True):
        self.calls = []
        self.result = result

    def __call__(self, token):
        self.calls.append(token)
        return self.result


class LamportFromAuthStateTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_lamport()
        self.envelope = wrap_lamport(self.signer, generation=11)

    def test_returns_signer_and_generation(self):
        restored, generation = OneTimeSigner.from_auth_state(
            self.envelope, key=KEY, claim=lambda token: True
        )
        self.assertIsInstance(restored, OneTimeSigner)
        self.assertEqual(generation, 11)
        self.assertIsInstance(generation, int)
        self.assertNotIsInstance(generation, bool)

    def test_restores_public_key_and_used_flag(self):
        self.signer.sign(b"one")
        envelope = wrap_lamport(self.signer, generation=5)
        restored, generation = OneTimeSigner.from_auth_state(
            envelope, key=KEY, claim=lambda token: True
        )
        self.assertEqual(restored.public_key, self.signer.public_key)
        self.assertTrue(restored.used)
        self.assertEqual(generation, 5)
        with self.assertRaises(KeyExhaustedError):
            restored.sign(b"two")

    def test_restored_unused_signer_still_signs_once(self):
        restored, generation = OneTimeSigner.from_auth_state(
            self.envelope, key=KEY, claim=lambda token: True
        )
        self.assertEqual(generation, 11)
        signature = restored.sign(b"m")
        self.assertEqual(len(signature), 32)
        with self.assertRaises(KeyExhaustedError):
            restored.sign(b"m2")

    def test_accepts_bytearray_inputs(self):
        restored, generation = OneTimeSigner.from_auth_state(
            bytearray(self.envelope),
            key=bytearray(KEY),
            claim=lambda token: True,
        )
        self.assertEqual(restored.public_key, self.signer.public_key)
        self.assertEqual(generation, 11)

    def test_generation_endpoints_round_trip(self):
        for generation in (0, UINT64_MAX):
            with self.subTest(generation=generation):
                envelope = wrap_lamport(self.signer, generation=generation)
                _, restored_generation = OneTimeSigner.from_auth_state(
                    envelope, key=KEY, claim=lambda token: True
                )
                self.assertEqual(restored_generation, generation)

    def test_floor_equal_and_below_pass(self):
        envelope = wrap_lamport(self.signer, generation=7)
        OneTimeSigner.from_auth_state(
            envelope, key=KEY, min_generation=7, claim=lambda token: True
        )
        OneTimeSigner.from_auth_state(
            envelope, key=KEY, min_generation=6, claim=lambda token: True
        )

    def test_floor_above_generation_fails_without_claim(self):
        claim = RecordingClaim()
        envelope = wrap_lamport(self.signer, generation=7)
        with self.assertRaises(ValueError):
            OneTimeSigner.from_auth_state(
                envelope, key=KEY, min_generation=8, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError("from_auth_state must not draw randomness")

        with mock.patch.object(
            pqattest.secrets, "token_bytes", exploding_token_bytes
        ):
            restored, _ = OneTimeSigner.from_auth_state(
                self.envelope, key=KEY, claim=lambda token: True
            )
        self.assertEqual(restored.public_key, self.signer.public_key)


class LamportClaimTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_lamport()
        self.envelope = wrap_lamport(self.signer, generation=7)

    def test_claim_receives_exact_single_token(self):
        claim = RecordingClaim()
        OneTimeSigner.from_auth_state(self.envelope, key=KEY, claim=claim)
        self.assertEqual(claim.calls, [("lamport", 7)])

    def test_claim_called_exactly_once(self):
        claim = RecordingClaim()
        OneTimeSigner.from_auth_state(self.envelope, key=KEY, claim=claim)
        self.assertEqual(len(claim.calls), 1)

    def test_claim_token_is_a_plain_tuple_of_str_and_int(self):
        seen = []
        OneTimeSigner.from_auth_state(
            self.envelope, key=KEY, claim=lambda token: (seen.append(token), True)[1]
        )
        token = seen[0]
        self.assertIsInstance(token, tuple)
        self.assertEqual(len(token), 2)
        self.assertEqual(token[0], "lamport")
        self.assertEqual(token[1], 7)
        self.assertIs(type(token[1]), int)
        self.assertIsNot(type(token[1]), bool)

    def test_claim_false_rejected(self):
        claim = RecordingClaim(result=False)
        with self.assertRaises(ValueError):
            OneTimeSigner.from_auth_state(self.envelope, key=KEY, claim=claim)
        self.assertEqual(len(claim.calls), 1)

    def test_truthy_non_true_rejected(self):
        for result in (1, "True", b"True", object()):
            with self.subTest(result=repr(result)):
                claim = RecordingClaim(result=result)
                with self.assertRaises(ValueError):
                    OneTimeSigner.from_auth_state(self.envelope, key=KEY, claim=claim)
                self.assertEqual(len(claim.calls), 1)

    def test_claim_exception_propagates(self):
        class Boom(Exception):
            pass

        def boom(token):
            raise Boom

        with self.assertRaises(Boom):
            OneTimeSigner.from_auth_state(self.envelope, key=KEY, claim=boom)

    def test_claim_not_called_on_wrong_key(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            OneTimeSigner.from_auth_state(self.envelope, key=OTHER_KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_tamper(self):
        claim = RecordingClaim()
        forged = bytearray(self.envelope)
        forged[30] ^= 0x01
        with self.assertRaises(ValueError):
            OneTimeSigner.from_auth_state(bytes(forged), key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_v1_envelope(self):
        claim = RecordingClaim()
        v1 = auth_wrap(self.signer.checkpoint(), scheme="lamport", key=KEY)
        with self.assertRaises(ValueError):
            OneTimeSigner.from_auth_state(v1, key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_other_scheme(self):
        claim = RecordingClaim()
        wots_envelope = wrap_wots(make_wots(), generation=7)
        with self.assertRaises(ValueError):
            OneTimeSigner.from_auth_state(wots_envelope, key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_garbage(self):
        claim = RecordingClaim()
        for bad in (b"", b"\x00", b"PQAAUTH\0", b"\x00" * 54,
                    self.envelope[:-1], self.envelope + b"\x00"):
            with self.subTest(length=len(bad)):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    OneTimeSigner.from_auth_state(bad, key=KEY, claim=claim)
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_invalid_checkpoint(self):
        import hashlib
        import hmac

        payload = b"PQALCP\0\0" + b"\x00" * 20
        body = (
            b"PQAAUTH\0"
            + bytes((2, 1))
            + (7).to_bytes(8, "big")
            + len(payload).to_bytes(4, "big")
            + payload
        )
        blob = body + hmac.new(KEY, body, hashlib.sha256).digest()
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            OneTimeSigner.from_auth_state(blob, key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])


class WotsFromAuthStateTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_wots(w=4)
        self.envelope = wrap_wots(self.signer, generation=9)

    def test_returns_signer_and_generation(self):
        claim = RecordingClaim()
        restored, generation = WOTSOneTimeSigner.from_auth_state(
            self.envelope, key=KEY, claim=claim
        )
        self.assertIsInstance(restored, WOTSOneTimeSigner)
        self.assertEqual(generation, 9)
        self.assertIsInstance(generation, int)
        self.assertNotIsInstance(generation, bool)
        self.assertEqual(claim.calls, [("wots", 9)])

    def test_restores_public_key_and_used_flag(self):
        self.signer.sign(b"one")
        envelope = wrap_wots(self.signer, generation=3)
        restored, generation = WOTSOneTimeSigner.from_auth_state(
            envelope, key=KEY, claim=lambda token: True
        )
        self.assertEqual(restored.public_key, self.signer.public_key)
        self.assertTrue(restored.used)
        self.assertEqual(generation, 3)
        with self.assertRaises(KeyExhaustedError):
            restored.sign(b"two")

    def test_restored_unused_signer_signs(self):
        restored, _ = WOTSOneTimeSigner.from_auth_state(
            self.envelope, key=KEY, claim=lambda token: True
        )
        signature = restored.sign(b"m")
        self.assertEqual(len(signature), 67)

    def test_rejects_lamport_envelope(self):
        claim = RecordingClaim()
        lamport_envelope = wrap_lamport(make_lamport(), generation=9)
        with self.assertRaises(ValueError):
            WOTSOneTimeSigner.from_auth_state(
                lamport_envelope, key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_floor_and_claim_semantics(self):
        claim = RecordingClaim()
        WOTSOneTimeSigner.from_auth_state(
            self.envelope, key=KEY, min_generation=9, claim=claim
        )
        self.assertEqual(claim.calls, [("wots", 9)])
        with self.assertRaises(ValueError):
            WOTSOneTimeSigner.from_auth_state(
                self.envelope, key=KEY, min_generation=10, claim=RecordingClaim()
            )


class FromAuthStateTypesTest(unittest.TestCase):
    def setUp(self):
        self.lamport = wrap_lamport(make_lamport(), generation=1)
        self.wots = wrap_wots(make_wots(), generation=1)

    def _assert(self, cls, envelope, **kwargs):
        with self.assertRaises(TypeError):
            cls.from_auth_state(envelope, **kwargs)

    def test_keyword_only_arguments(self):
        for cls, envelope in (
            (OneTimeSigner, self.lamport),
            (WOTSOneTimeSigner, self.wots),
        ):
            with self.subTest(cls=cls.__name__):
                with self.assertRaises(TypeError):
                    cls.from_auth_state(envelope, KEY, None, lambda token: True)
                with self.assertRaises(TypeError):
                    cls.from_auth_state(envelope, KEY, claim=lambda token: True)

    def test_claim_is_required(self):
        for cls, envelope in (
            (OneTimeSigner, self.lamport),
            (WOTSOneTimeSigner, self.wots),
        ):
            with self.subTest(cls=cls.__name__):
                with self.assertRaises(TypeError):
                    cls.from_auth_state(envelope, key=KEY)

    def test_non_bytes_data_type_error(self):
        for bad in (None, 42, 4.5, "blob", [self.lamport], object()):
            with self.subTest(bad=type(bad).__name__):
                self._assert(
                    OneTimeSigner, bad, key=KEY, claim=lambda token: True
                )
                self._assert(
                    WOTSOneTimeSigner, bad, key=KEY, claim=lambda token: True
                )

    def test_non_bytes_key_type_error(self):
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                self._assert(
                    OneTimeSigner, self.lamport, key=bad,
                    claim=lambda token: True,
                )
                self._assert(
                    WOTSOneTimeSigner, self.wots, key=bad,
                    claim=lambda token: True,
                )

    def test_non_callable_claim_type_error(self):
        for bad in (None, True, 1, "claim", b"claim", (lambda: True,), object()):
            with self.subTest(bad=type(bad).__name__):
                self._assert(
                    OneTimeSigner, self.lamport, key=KEY, claim=bad
                )
                self._assert(
                    WOTSOneTimeSigner, self.wots, key=KEY, claim=bad
                )

    def test_bad_floor_type_error(self):
        for bad in (1.5, "0", [0], (0,), object()):
            with self.subTest(bad=repr(bad)):
                self._assert(
                    OneTimeSigner, self.lamport, key=KEY,
                    min_generation=bad, claim=lambda token: True,
                )
                self._assert(
                    WOTSOneTimeSigner, self.wots, key=KEY,
                    min_generation=bad, claim=lambda token: True,
                )

    def test_boolean_floor_type_error(self):
        for bad in (True, False):
            with self.subTest(bad=bad):
                self._assert(
                    OneTimeSigner, self.lamport, key=KEY,
                    min_generation=bad, claim=lambda token: True,
                )
                self._assert(
                    WOTSOneTimeSigner, self.wots, key=KEY,
                    min_generation=bad, claim=lambda token: True,
                )

    def test_empty_key_value_error(self):
        for bad in (b"", bytearray()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    OneTimeSigner.from_auth_state(
                        self.lamport, key=bad, claim=lambda token: True
                    )
                with self.assertRaises(ValueError):
                    WOTSOneTimeSigner.from_auth_state(
                        self.wots, key=bad, claim=lambda token: True
                    )

    def test_floor_out_of_range_value_error(self):
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    OneTimeSigner.from_auth_state(
                        self.lamport, key=KEY, min_generation=bad,
                        claim=lambda token: True,
                    )
                with self.assertRaises(ValueError):
                    WOTSOneTimeSigner.from_auth_state(
                        self.wots, key=KEY, min_generation=bad,
                        claim=lambda token: True,
                    )

    def test_types_checked_before_envelope(self):
        with self.assertRaises(TypeError):
            OneTimeSigner.from_auth_state(b"", key=42, claim=lambda token: True)
        with self.assertRaises(TypeError):
            OneTimeSigner.from_auth_state(
                object(), key=KEY, claim=lambda token: True
            )
        with self.assertRaises(TypeError):
            OneTimeSigner.from_auth_state(
                b"", key=KEY, min_generation=True, claim=lambda token: True
            )
        with self.assertRaises(TypeError):
            OneTimeSigner.from_auth_state(b"", key=KEY, claim="claim")


class RestoreOtsPairTest(unittest.TestCase):
    def setUp(self):
        self.lamport = make_lamport()
        self.wots = make_wots(w=4)
        self.envelope_a = wrap_lamport(self.lamport, generation=5)
        self.envelope_b = wrap_wots(self.wots, generation=5)

    def _restore(self, a=None, b=None, *, floor=None, claim=None):
        return restore_ots_pair(
            self.envelope_a if a is None else a,
            self.envelope_b if b is None else b,
            key=KEY,
            floor=floor,
            claim=lambda token: True if claim is None else claim,
        )

    def test_returns_pair_and_generation(self):
        claim = RecordingClaim()
        (lamport_signer, wots_signer), generation = restore_ots_pair(
            self.envelope_a, self.envelope_b, key=KEY, claim=claim
        )
        self.assertIsInstance(lamport_signer, OneTimeSigner)
        self.assertIsInstance(wots_signer, WOTSOneTimeSigner)
        self.assertEqual(generation, 5)
        self.assertIsInstance(generation, int)
        self.assertNotIsInstance(generation, bool)
        self.assertEqual(lamport_signer.public_key, self.lamport.public_key)
        self.assertEqual(wots_signer.public_key, self.wots.public_key)
        self.assertEqual(
            claim.calls,
            [(("lamport", 5), ("wots", 5))],
        )

    def test_paired_claim_called_exactly_once(self):
        claim = RecordingClaim()
        restore_ots_pair(
            self.envelope_a, self.envelope_b, key=KEY, claim=claim
        )
        self.assertEqual(len(claim.calls), 1)

    def test_paired_token_shape(self):
        seen = []
        restore_ots_pair(
            self.envelope_a, self.envelope_b, key=KEY,
            claim=lambda token: (seen.append(token), True)[1],
        )
        token = seen[0]
        self.assertEqual(
            token, (("lamport", 5), ("wots", 5))
        )
        self.assertIsInstance(token, tuple)
        self.assertEqual(len(token), 2)
        self.assertEqual(token[0][0], "lamport")
        self.assertEqual(token[1][0], "wots")
        self.assertEqual(token[0][1], token[1][1])
        self.assertIs(type(token[0][1]), int)
        self.assertIsNot(type(token[0][1]), bool)

    def test_restored_signers_are_independent_and_usable(self):
        (lamport_signer, wots_signer), generation = self._restore()
        self.assertFalse(lamport_signer.used)
        self.assertFalse(wots_signer.used)
        self.assertEqual(len(lamport_signer.sign(b"lm")), 32)
        self.assertEqual(len(wots_signer.sign(b"wm")), 67)
        with self.assertRaises(KeyExhaustedError):
            lamport_signer.sign(b"again")
        with self.assertRaises(KeyExhaustedError):
            wots_signer.sign(b"again")
        self.assertEqual(generation, 5)

    def test_generations_must_match(self):
        envelope_b = wrap_wots(self.wots, generation=6)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            restore_ots_pair(
                self.envelope_a, envelope_b, key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_equal_generation_zero_and_uint64_max(self):
        for generation in (0, UINT64_MAX):
            with self.subTest(generation=generation):
                a = wrap_lamport(self.lamport, generation=generation)
                b = wrap_wots(self.wots, generation=generation)
                claim = RecordingClaim()
                (_, _), restored_generation = restore_ots_pair(
                    a, b, key=KEY, claim=claim
                )
                self.assertEqual(restored_generation, generation)
                self.assertEqual(
                    claim.calls,
                    [(("lamport", generation), ("wots", generation))],
                )

    def test_sides_are_position_fixed(self):
        # a must be lamport, b must be wots: swapping is a scheme mismatch.
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            restore_ots_pair(
                self.envelope_b, self.envelope_a, key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_merkle_envelopes_rejected_on_either_side(self):
        merkle = MerkleSigner(height=1, w=4)
        merkle_envelope = auth_state_wrap(
            merkle.checkpoint(), scheme="merkle", key=KEY, generation=5
        )
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            restore_ots_pair(
                merkle_envelope, self.envelope_b, key=KEY, claim=claim
            )
        with self.assertRaises(ValueError):
            restore_ots_pair(
                self.envelope_a, merkle_envelope, key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_v1_envelopes_rejected(self):
        v1_a = auth_wrap(self.lamport.checkpoint(), scheme="lamport", key=KEY)
        v1_b = auth_wrap(self.wots.checkpoint(), scheme="wots", key=KEY)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            restore_ots_pair(v1_a, self.envelope_b, key=KEY, claim=claim)
        with self.assertRaises(ValueError):
            restore_ots_pair(self.envelope_a, v1_b, key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_wrong_key_either_side_fails_without_claim(self):
        claim = RecordingClaim()
        other_a = wrap_lamport(self.lamport, generation=5, key=OTHER_KEY)
        other_b = wrap_wots(self.wots, generation=5, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            restore_ots_pair(other_a, self.envelope_b, key=KEY, claim=claim)
        with self.assertRaises(ValueError):
            restore_ots_pair(self.envelope_a, other_b, key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_tampered_either_side_fails_without_claim(self):
        claim = RecordingClaim()
        for side in ("a", "b"):
            with self.subTest(side=side):
                claim.calls.clear()
                if side == "a":
                    forged = bytearray(self.envelope_a)
                    forged[30] ^= 0x01
                    a, b = bytes(forged), self.envelope_b
                else:
                    forged = bytearray(self.envelope_b)
                    forged[30] ^= 0x01
                    a, b = self.envelope_a, bytes(forged)
                with self.assertRaises(ValueError):
                    restore_ots_pair(a, b, key=KEY, claim=claim)
                self.assertEqual(claim.calls, [])

    def test_invalid_checkpoint_either_side_no_claim(self):
        import hashlib
        import hmac

        def envelope(scheme_id, payload):
            body = (
                b"PQAAUTH\0"
                + bytes((2, scheme_id))
                + (5).to_bytes(8, "big")
                + len(payload).to_bytes(4, "big")
                + payload
            )
            return body + hmac.new(KEY, body, hashlib.sha256).digest()

        bad_lamport = envelope(1, b"PQALCP\0\0" + b"\x00" * 20)
        bad_wots = envelope(2, b"PQAWCP\0\0" + b"\x00" * 20)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            restore_ots_pair(bad_lamport, self.envelope_b, key=KEY, claim=claim)
        with self.assertRaises(ValueError):
            restore_ots_pair(self.envelope_a, bad_wots, key=KEY, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_floor_equal_passes_above_fails(self):
        claim = RecordingClaim()
        restore_ots_pair(
            self.envelope_a, self.envelope_b, key=KEY, floor=5, claim=claim
        )
        self.assertEqual(
            claim.calls, [(("lamport", 5), ("wots", 5))]
        )
        with self.assertRaises(ValueError):
            restore_ots_pair(
                self.envelope_a, self.envelope_b, key=KEY, floor=6,
                claim=RecordingClaim(),
            )

    def test_floor_checks_both_sides(self):
        # One side above the floor, the other below: rejected, no claim.
        a = wrap_lamport(self.lamport, generation=5)
        b = wrap_wots(self.wots, generation=4)
        # generations also mismatch; the floor alone must reject the low side
        # even when generations are aligned:
        a_low = wrap_lamport(self.lamport, generation=4)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            restore_ots_pair(a, b, key=KEY, floor=5, claim=claim)
        with self.assertRaises(ValueError):
            restore_ots_pair(a_low, b, key=KEY, floor=5, claim=claim)
        self.assertEqual(claim.calls, [])

    def test_claim_false_or_truthy_non_true_rejected(self):
        for result in (False, 1, "yes", object()):
            with self.subTest(result=repr(result)):
                with self.assertRaises(ValueError):
                    restore_ots_pair(
                        self.envelope_a, self.envelope_b, key=KEY,
                        claim=lambda token, r=result: r,
                    )

    def test_claim_exception_propagates(self):
        class Boom(Exception):
            pass

        with self.assertRaises(Boom):
            restore_ots_pair(
                self.envelope_a, self.envelope_b, key=KEY,
                claim=lambda token: (_ for _ in ()).throw(Boom),
            )

    def test_accepts_bytearrays(self):
        claim = RecordingClaim()
        (lamport_signer, wots_signer), generation = restore_ots_pair(
            bytearray(self.envelope_a),
            bytearray(self.envelope_b),
            key=bytearray(KEY),
            claim=claim,
        )
        self.assertEqual(generation, 5)
        self.assertEqual(lamport_signer.public_key, self.lamport.public_key)
        self.assertEqual(wots_signer.public_key, self.wots.public_key)
        self.assertEqual(len(claim.calls), 1)

    def test_envelopes_not_mutated(self):
        a_snapshot = bytes(self.envelope_a)
        b_snapshot = bytes(self.envelope_b)
        restore_ots_pair(
            bytearray(self.envelope_a),
            bytearray(self.envelope_b),
            key=KEY,
            claim=lambda token: True,
        )
        self.assertEqual(bytes(self.envelope_a), a_snapshot)
        self.assertEqual(bytes(self.envelope_b), b_snapshot)

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError("restore_ots_pair must not draw randomness")

        with mock.patch.object(
            pqattest.secrets, "token_bytes", exploding_token_bytes
        ):
            (lamport_signer, wots_signer), _ = restore_ots_pair(
                self.envelope_a, self.envelope_b, key=KEY,
                claim=lambda token: True,
            )
        self.assertEqual(lamport_signer.public_key, self.lamport.public_key)
        self.assertEqual(wots_signer.public_key, self.wots.public_key)


class RestoreOtsPairTypesTest(unittest.TestCase):
    def setUp(self):
        self.a = wrap_lamport(make_lamport(), generation=1)
        self.b = wrap_wots(make_wots(), generation=1)

    def test_keyword_only_arguments(self):
        with self.assertRaises(TypeError):
            restore_ots_pair(self.a, self.b, KEY, None, lambda token: True)
        with self.assertRaises(TypeError):
            restore_ots_pair(self.a, self.b, KEY, claim=lambda token: True)

    def test_claim_is_required(self):
        with self.assertRaises(TypeError):
            restore_ots_pair(self.a, self.b, key=KEY)

    def test_non_bytes_data_type_error(self):
        for bad in (None, 42, "blob", [self.a], object()):
            with self.subTest(bad=type(bad).__name__, side="a"):
                with self.assertRaises(TypeError):
                    restore_ots_pair(bad, self.b, key=KEY, claim=lambda t: True)
            with self.subTest(bad=type(bad).__name__, side="b"):
                with self.assertRaises(TypeError):
                    restore_ots_pair(self.a, bad, key=KEY, claim=lambda t: True)

    def test_non_bytes_key_type_error(self):
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    restore_ots_pair(self.a, self.b, key=bad, claim=lambda t: True)

    def test_non_callable_claim_type_error(self):
        for bad in (None, True, 1, "claim", (lambda: True,)):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    restore_ots_pair(self.a, self.b, key=KEY, claim=bad)

    def test_bad_floor_type_error(self):
        for bad in (1.5, "0", [0], (0,), object(), True, False):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    restore_ots_pair(
                        self.a, self.b, key=KEY, floor=bad, claim=lambda t: True
                    )

    def test_empty_key_value_error(self):
        with self.assertRaises(ValueError):
            restore_ots_pair(self.a, self.b, key=b"", claim=lambda t: True)

    def test_floor_out_of_range_value_error(self):
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    restore_ots_pair(
                        self.a, self.b, key=KEY, floor=bad, claim=lambda t: True
                    )

    def test_types_checked_before_envelope(self):
        with self.assertRaises(TypeError):
            restore_ots_pair(b"", b"", key=42, claim=lambda t: True)
        with self.assertRaises(TypeError):
            restore_ots_pair(object(), self.b, key=KEY, claim=lambda t: True)
        with self.assertRaises(TypeError):
            restore_ots_pair(
                b"", b"", key=KEY, floor=True, claim=lambda t: True
            )
        with self.assertRaises(TypeError):
            restore_ots_pair(b"", b"", key=KEY, claim="claim")


class ExistingInterfacesUnchangedTest(unittest.TestCase):
    def test_merkle_from_auth_state_has_no_claim_parameter(self):
        signer = MerkleSigner(height=1, w=4)
        envelope = auth_state_wrap(
            signer.checkpoint(), scheme="merkle", key=KEY, generation=2
        )
        restored, generation = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(generation, 2)
        self.assertEqual(restored.public_key, signer.public_key)
        with self.assertRaises(TypeError):
            MerkleSigner.from_auth_state(
                envelope, key=KEY, claim=lambda token: True
            )

    def test_lamport_from_checkpoint_unchanged(self):
        signer = make_lamport()
        restored = OneTimeSigner.from_checkpoint(signer.checkpoint())
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertFalse(restored.used)

    def test_wots_from_checkpoint_unchanged(self):
        signer = make_wots()
        restored = WOTSOneTimeSigner.from_checkpoint(signer.checkpoint())
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertFalse(restored.used)


if __name__ == "__main__":
    unittest.main()

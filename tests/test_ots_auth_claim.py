import hashlib
import hmac
import unittest
from unittest import mock

from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    OneTimeSigner,
    WOTSOneTimeSigner,
    auth_state_unwrap,
    auth_state_wrap,
    auth_wrap,
    keygen,
    restore_ots_pair,
    wots_keygen,
)
import pqattest
import pqattest.wots

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret"
UINT64_MAX = 2**64 - 1


def wrap_lamport(signer, *, generation=7, key=KEY):
    return auth_state_wrap(
        signer.checkpoint(), scheme="lamport", key=key, generation=generation
    )


def wrap_wots(signer, *, generation=7, key=KEY):
    return auth_state_wrap(
        signer.checkpoint(), scheme="wots", key=key, generation=generation
    )


def make_lamport():
    return OneTimeSigner(keygen()[0])


def make_wots(w=4):
    return WOTSOneTimeSigner(wots_keygen(w=w)[0])


def make_pair_envelopes(lamport=None, wots=None, *, generation=7, key=KEY):
    lamport = lamport or make_lamport()
    wots = wots or make_wots()
    return (
        lamport,
        wots,
        wrap_lamport(lamport, generation=generation, key=key),
        wrap_wots(wots, generation=generation, key=key),
    )


class RecordingClaim:
    """Claim callback recording every token it is handed."""

    def __init__(self, result=True, error=None):
        self.tokens = []
        self.calls = 0
        self.result = result
        self.error = error

    def __call__(self, token):
        self.calls += 1
        self.tokens.append(token)
        if self.error is not None:
            raise self.error
        return self.result


class LamportFromAuthStateClaimTest(unittest.TestCase):
    def test_returns_signer_and_generation(self):
        signer = make_lamport()
        envelope = wrap_lamport(signer, generation=11)
        claim = RecordingClaim()
        restored, generation = OneTimeSigner.from_auth_state(
            envelope, key=KEY, claim=claim
        )
        self.assertIsInstance(restored, OneTimeSigner)
        self.assertEqual(generation, 11)
        self.assertNotIsInstance(generation, bool)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertFalse(restored.used)
        self.assertEqual(claim.calls, 1)
        self.assertEqual(claim.tokens, [("lamport", 11)])

    def test_restores_used_state(self):
        signer = make_lamport()
        signer.sign(b"already signed")
        envelope = wrap_lamport(signer, generation=3)
        claim = RecordingClaim()
        restored, generation = OneTimeSigner.from_auth_state(
            envelope, key=KEY, claim=claim
        )
        self.assertTrue(restored.used)
        self.assertEqual(generation, 3)
        with self.assertRaises(KeyExhaustedError):
            restored.sign(b"again")
        self.assertEqual(claim.tokens, [("lamport", 3)])

    def test_restored_unused_signer_can_still_sign_once(self):
        signer = make_lamport()
        envelope = wrap_lamport(signer, generation=0)
        restored, generation = OneTimeSigner.from_auth_state(
            envelope, key=KEY, claim=RecordingClaim()
        )
        restored.sign(b"one")
        with self.assertRaises(KeyExhaustedError):
            restored.sign(b"two")
        self.assertEqual(generation, 0)

    def test_accepts_bytearray_inputs_and_floor(self):
        signer = make_lamport()
        envelope = wrap_lamport(signer, generation=8)
        claim = RecordingClaim()
        restored, generation = OneTimeSigner.from_auth_state(
            bytearray(envelope), key=bytearray(KEY), min_generation=8, claim=claim
        )
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(generation, 8)
        self.assertEqual(claim.tokens, [("lamport", 8)])

    def test_uint64_generation_edges(self):
        for generation in (0, UINT64_MAX):
            with self.subTest(generation=generation):
                envelope = wrap_lamport(make_lamport(), generation=generation)
                claim = RecordingClaim()
                _, restored_generation = OneTimeSigner.from_auth_state(
                    envelope, key=KEY, claim=claim
                )
                self.assertEqual(restored_generation, generation)
                self.assertEqual(claim.tokens, [("lamport", generation)])

    def test_claim_is_keyword_only(self):
        envelope = wrap_lamport(make_lamport())
        with self.assertRaises(TypeError):
            OneTimeSigner.from_auth_state(envelope, KEY, None, RecordingClaim())

    def test_non_callable_claim_type_error(self):
        envelope = wrap_lamport(make_lamport())
        for bad in (None, 42, "claim", b"x", [RecordingClaim()], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    OneTimeSigner.from_auth_state(envelope, key=KEY, claim=bad)

    def test_other_type_errors(self):
        envelope = wrap_lamport(make_lamport())
        for bad in (None, 42, 4.5, "blob", [envelope], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    OneTimeSigner.from_auth_state(bad, key=KEY, claim=RecordingClaim())
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    OneTimeSigner.from_auth_state(envelope, key=bad, claim=RecordingClaim())
        for bad in (True, False, 1.5, "0", [0]):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    OneTimeSigner.from_auth_state(
                        envelope, key=KEY, min_generation=bad, claim=RecordingClaim()
                    )

    def test_claim_non_true_value_error_and_no_return(self):
        envelope = wrap_lamport(make_lamport(), generation=4)
        for result in (False, 1, 0, None, "True", object()):
            with self.subTest(result=repr(result)):
                with self.assertRaises(ValueError):
                    OneTimeSigner.from_auth_state(
                        envelope, key=KEY, claim=RecordingClaim(result=result)
                    )

    def test_claim_exception_propagates(self):
        class Boom(Exception):
            pass

        envelope = wrap_lamport(make_lamport())
        claim = RecordingClaim(error=Boom())
        with self.assertRaises(Boom):
            OneTimeSigner.from_auth_state(envelope, key=KEY, claim=claim)
        self.assertEqual(claim.tokens, [("lamport", 7)])

    def test_claim_never_called_on_validation_failure(self):
        signer = make_lamport()
        envelope = wrap_lamport(signer, generation=7)
        v1 = auth_wrap(signer.checkpoint(), scheme="lamport", key=KEY)
        wots_envelope = wrap_wots(make_wots())
        merkle_envelope = auth_state_wrap(
            MerkleSigner(height=1).checkpoint(),
            scheme="merkle",
            key=KEY,
            generation=7,
        )
        tampered = bytearray(envelope)
        tampered[-1] ^= 0x01

        def rewrap(payload, generation=7, identifier=1):
            body = (
                b"PQAAUTH\0"
                + bytes((2, identifier))
                + generation.to_bytes(8, "big")
                + len(payload).to_bytes(4, "big")
                + payload
            )
            return body + hmac.new(KEY, body, hashlib.sha256).digest()

        # Valid HMAC but corrupted lamport checkpoint payload.
        broken_checkpoint = bytearray(signer.checkpoint())
        broken_checkpoint[20] ^= 0x01
        corrupt_payload = rewrap(bytes(broken_checkpoint))

        failures = {
            "wrong key": dict(key=OTHER_KEY),
            "floor too high": dict(key=KEY, min_generation=8),
            "floor out of range": dict(key=KEY, min_generation=-1),
            "empty key": dict(key=b""),
            "v1 envelope": dict(data=v1, key=KEY),
            "wots scheme": dict(data=wots_envelope, key=KEY),
            "merkle scheme": dict(data=merkle_envelope, key=KEY),
            "bad tag": dict(data=bytes(tampered), key=KEY),
            "garbage": dict(data=b"", key=KEY),
            "truncated": dict(data=envelope[:-1], key=KEY),
            "trailing": dict(data=envelope + b"\x00", key=KEY),
            "corrupt checkpoint": dict(data=corrupt_payload, key=KEY),
        }
        for label, kwargs in failures.items():
            with self.subTest(label=label):
                data = kwargs.pop("data", envelope)
                claim = RecordingClaim()
                with self.assertRaises(ValueError):
                    OneTimeSigner.from_auth_state(data, claim=claim, **kwargs)
                self.assertEqual(claim.calls, 0)

    def test_types_checked_before_envelope_and_claim(self):
        claim = RecordingClaim()
        with self.assertRaises(TypeError):
            OneTimeSigner.from_auth_state(b"", key=42, claim=claim)
        with self.assertRaises(TypeError):
            OneTimeSigner.from_auth_state(object(), key=KEY, claim=claim)
        with self.assertRaises(TypeError):
            OneTimeSigner.from_auth_state(
                b"", key=KEY, min_generation=True, claim=claim
            )
        self.assertEqual(claim.calls, 0)

    def test_draws_no_randomness(self):
        envelope = wrap_lamport(make_lamport())

        def exploding(size):
            raise AssertionError("from_auth_state must not draw randomness")

        with mock.patch.object(pqattest.secrets, "token_bytes", exploding):
            restored, generation = OneTimeSigner.from_auth_state(
                envelope, key=KEY, claim=RecordingClaim()
            )
        self.assertEqual(generation, 7)


class WOTSFromAuthStateClaimTest(unittest.TestCase):
    def test_returns_signer_and_generation(self):
        for w in (4, 8):
            with self.subTest(w=w):
                signer = make_wots(w)
                envelope = wrap_wots(signer, generation=12)
                claim = RecordingClaim()
                restored, generation = WOTSOneTimeSigner.from_auth_state(
                    envelope, key=KEY, claim=claim
                )
                self.assertIsInstance(restored, WOTSOneTimeSigner)
                self.assertEqual(generation, 12)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertFalse(restored.used)
                self.assertEqual(claim.tokens, [("wots", 12)])

    def test_restores_used_state(self):
        signer = make_wots()
        signer.sign(b"already signed")
        envelope = wrap_wots(signer, generation=2)
        restored, generation = WOTSOneTimeSigner.from_auth_state(
            envelope, key=KEY, claim=RecordingClaim()
        )
        self.assertTrue(restored.used)
        with self.assertRaises(KeyExhaustedError):
            restored.sign(b"again")
        self.assertEqual(generation, 2)

    def test_accepts_bytearray_inputs_and_floor(self):
        signer = make_wots(w=8)
        envelope = wrap_wots(signer, generation=6)
        claim = RecordingClaim()
        restored, generation = WOTSOneTimeSigner.from_auth_state(
            bytearray(envelope), key=bytearray(KEY), min_generation=5, claim=claim
        )
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(generation, 6)
        self.assertEqual(claim.tokens, [("wots", 6)])

    def test_claim_is_keyword_only(self):
        envelope = wrap_wots(make_wots())
        with self.assertRaises(TypeError):
            WOTSOneTimeSigner.from_auth_state(envelope, KEY, None, RecordingClaim())

    def test_non_callable_claim_type_error(self):
        envelope = wrap_wots(make_wots())
        for bad in (None, 42, "claim", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    WOTSOneTimeSigner.from_auth_state(envelope, key=KEY, claim=bad)

    def test_other_type_errors(self):
        envelope = wrap_wots(make_wots())
        for bad in (None, 42, 4.5, "blob", [envelope], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    WOTSOneTimeSigner.from_auth_state(
                        bad, key=KEY, claim=RecordingClaim()
                    )
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    WOTSOneTimeSigner.from_auth_state(
                        envelope, key=bad, claim=RecordingClaim()
                    )
        for bad in (True, False, 1.5, "0", (0,)):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    WOTSOneTimeSigner.from_auth_state(
                        envelope, key=KEY, min_generation=bad, claim=RecordingClaim()
                    )

    def test_claim_non_true_value_error(self):
        envelope = wrap_wots(make_wots(), generation=4)
        for result in (False, 1, None, "yes"):
            with self.subTest(result=repr(result)):
                with self.assertRaises(ValueError):
                    WOTSOneTimeSigner.from_auth_state(
                        envelope, key=KEY, claim=RecordingClaim(result=result)
                    )

    def test_claim_exception_propagates(self):
        class Boom(Exception):
            pass

        envelope = wrap_wots(make_wots())
        with self.assertRaises(Boom):
            WOTSOneTimeSigner.from_auth_state(
                envelope, key=KEY, claim=RecordingClaim(error=Boom())
            )

    def test_claim_never_called_on_validation_failure(self):
        signer = make_wots()
        envelope = wrap_wots(signer, generation=7)
        lamport_envelope = wrap_lamport(make_lamport())
        v1 = auth_wrap(signer.checkpoint(), scheme="wots", key=KEY)
        tampered = bytearray(envelope)
        tampered[-1] ^= 0x01

        failures = {
            "wrong key": dict(key=OTHER_KEY),
            "floor too high": dict(key=KEY, min_generation=8),
            "empty key": dict(key=b""),
            "v1 envelope": dict(data=v1, key=KEY),
            "lamport scheme": dict(data=lamport_envelope, key=KEY),
            "bad tag": dict(data=bytes(tampered), key=KEY),
            "garbage": dict(data=b"\x00" * 40, key=KEY),
            "trailing": dict(data=envelope + b"\x00", key=KEY),
        }
        for label, kwargs in failures.items():
            with self.subTest(label=label):
                data = kwargs.pop("data", envelope)
                claim = RecordingClaim()
                with self.assertRaises(ValueError):
                    WOTSOneTimeSigner.from_auth_state(data, claim=claim, **kwargs)
                self.assertEqual(claim.calls, 0)

    def test_draws_no_randomness(self):
        envelope = wrap_wots(make_wots())

        def exploding(size):
            raise AssertionError("from_auth_state must not draw randomness")

        with mock.patch.object(pqattest.wots.secrets, "token_bytes", exploding):
            restored, generation = WOTSOneTimeSigner.from_auth_state(
                envelope, key=KEY, claim=RecordingClaim()
            )
        self.assertEqual(generation, 7)


class RestoreOTSPairTest(unittest.TestCase):
    def test_restores_pair_and_generation(self):
        lamport, wots, env_l, env_w = make_pair_envelopes(generation=9)
        claim = RecordingClaim()
        (l, w), generation = restore_ots_pair(env_l, env_w, key=KEY, claim=claim)
        self.assertIsInstance(l, OneTimeSigner)
        self.assertIsInstance(w, WOTSOneTimeSigner)
        self.assertEqual(l.public_key, lamport.public_key)
        self.assertEqual(w.public_key, wots.public_key)
        self.assertEqual(generation, 9)
        self.assertEqual(claim.calls, 1)
        self.assertEqual(claim.tokens, [(("lamport", 9), ("wots", 9))])

    def test_paired_claim_token_shape(self):
        _, _, env_l, env_w = make_pair_envelopes(generation=0)
        claim = RecordingClaim()
        _, generation = restore_ots_pair(env_l, env_w, key=KEY, claim=claim)
        token = claim.tokens[0]
        self.assertEqual(len(token), 2)
        self.assertEqual(token[0], ("lamport", 0))
        self.assertEqual(token[1], ("wots", 0))
        self.assertEqual(token[0][1], token[1][1])
        self.assertEqual(generation, 0)

    def test_restores_used_states(self):
        lamport, wots = make_lamport(), make_wots(w=8)
        lamport.sign(b"l")
        wots.sign(b"w")
        _, _, env_l, env_w = make_pair_envelopes(lamport, wots, generation=4)
        claim = RecordingClaim()
        (l, w), generation = restore_ots_pair(env_l, env_w, key=KEY, claim=claim)
        self.assertTrue(l.used and w.used)
        with self.assertRaises(KeyExhaustedError):
            l.sign(b"x")
        with self.assertRaises(KeyExhaustedError):
            w.sign(b"x")
        self.assertEqual(generation, 4)
        self.assertEqual(claim.tokens, [(("lamport", 4), ("wots", 4))])

    def test_claim_called_exactly_once(self):
        _, _, env_l, env_w = make_pair_envelopes(generation=11)
        claim = RecordingClaim()
        restore_ots_pair(env_l, env_w, key=KEY, floor=11, claim=claim)
        self.assertEqual(claim.calls, 1)

    def test_floor_equal_and_below_pass(self):
        _, _, env_l, env_w = make_pair_envelopes(generation=7)
        for floor in (0, 6, 7):
            with self.subTest(floor=floor):
                claim = RecordingClaim()
                (l, w), generation = restore_ots_pair(
                    env_l, env_w, key=KEY, floor=floor, claim=claim
                )
                self.assertEqual(generation, 7)
                self.assertEqual(claim.calls, 1)

    def test_accepts_bytearrays(self):
        lamport, wots, env_l, env_w = make_pair_envelopes(generation=3)
        claim = RecordingClaim()
        (l, w), generation = restore_ots_pair(
            bytearray(env_l), bytearray(env_w), key=bytearray(KEY), claim=claim
        )
        self.assertEqual(l.public_key, lamport.public_key)
        self.assertEqual(w.public_key, wots.public_key)
        self.assertEqual(generation, 3)

    def test_arguments_keyword_only(self):
        _, _, env_l, env_w = make_pair_envelopes()
        with self.assertRaises(TypeError):
            restore_ots_pair(env_l, env_w, KEY, None, RecordingClaim())

    def test_generation_mismatch_rejected_both_orders(self):
        _, wots, env_l, env_w_7 = make_pair_envelopes(generation=7)
        env_w_5 = wrap_wots(wots, generation=5)
        lamport5 = make_lamport()
        env_l_5 = wrap_lamport(lamport5, generation=5)
        env_l_7 = wrap_lamport(make_lamport(), generation=7)
        for a, b in ((env_l_7, env_w_5), (env_l_5, env_w_7)):
            with self.subTest(order=(a is env_l_7)):
                claim = RecordingClaim()
                with self.assertRaises(ValueError):
                    restore_ots_pair(a, b, key=KEY, claim=claim)
                self.assertEqual(claim.calls, 0)

    def test_swapped_slots_rejected(self):
        _, _, env_l, env_w = make_pair_envelopes(generation=7)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            restore_ots_pair(env_w, env_l, key=KEY, claim=claim)
        self.assertEqual(claim.calls, 0)

    def test_floor_above_generation_rejected(self):
        _, _, env_l, env_w = make_pair_envelopes(generation=7)
        for floor in (8, UINT64_MAX):
            with self.subTest(floor=floor):
                claim = RecordingClaim()
                with self.assertRaises(ValueError):
                    restore_ots_pair(
                        env_l, env_w, key=KEY, floor=floor, claim=claim
                    )
                self.assertEqual(claim.calls, 0)

    def test_wrong_key_on_either_side_rejected(self):
        _, _, good_l, env_w = make_pair_envelopes(generation=7)
        env_l_other = wrap_lamport(make_lamport(), generation=7, key=OTHER_KEY)
        env_w_other = wrap_wots(make_wots(), generation=7, key=OTHER_KEY)
        for a, b in ((env_l_other, env_w), (good_l, env_w_other)):
            with self.subTest(side="a" if a is env_l_other else "b"):
                claim = RecordingClaim()
                with self.assertRaises(ValueError):
                    restore_ots_pair(a, b, key=KEY, claim=claim)
                self.assertEqual(claim.calls, 0)

    def test_tampering_either_side_rejected(self):
        _, _, env_l, env_w = make_pair_envelopes(generation=7)
        bad_l = bytearray(env_l)
        bad_l[-1] ^= 0x01
        bad_w = bytearray(env_w)
        bad_w[-1] ^= 0x01
        for a, b in ((bytes(bad_l), env_w), (env_l, bytes(bad_w))):
            with self.subTest(side="a" if a is bytes(bad_l) else "b"):
                claim = RecordingClaim()
                with self.assertRaises(ValueError):
                    restore_ots_pair(a, b, key=KEY, claim=claim)
                self.assertEqual(claim.calls, 0)

    def test_v1_envelope_either_side_rejected(self):
        lamport, wots = make_lamport(), make_wots()
        v1_l = auth_wrap(lamport.checkpoint(), scheme="lamport", key=KEY)
        v1_w = auth_wrap(wots.checkpoint(), scheme="wots", key=KEY)
        env_l = wrap_lamport(lamport)
        env_w = wrap_wots(wots)
        for a, b in ((v1_l, env_w), (env_l, v1_w)):
            with self.subTest():
                claim = RecordingClaim()
                with self.assertRaises(ValueError):
                    restore_ots_pair(a, b, key=KEY, claim=claim)
                self.assertEqual(claim.calls, 0)

    def test_corrupt_checkpoint_either_side_rejected(self):
        lamport, wots = make_lamport(), make_wots()

        def rewrap(payload, identifier):
            body = (
                b"PQAAUTH\0"
                + bytes((2, identifier))
                + (7).to_bytes(8, "big")
                + len(payload).to_bytes(4, "big")
                + payload
            )
            return body + hmac.new(KEY, body, hashlib.sha256).digest()

        broken_l = bytearray(lamport.checkpoint())
        broken_l[20] ^= 0x01
        broken_w = bytearray(wots.checkpoint())
        broken_w[20] ^= 0x01
        env_l, env_w = wrap_lamport(lamport), wrap_wots(wots)
        bad_l = rewrap(bytes(broken_l), 1)
        bad_w = rewrap(bytes(broken_w), 2)
        for a, b in ((bad_l, env_w), (env_l, bad_w)):
            with self.subTest():
                claim = RecordingClaim()
                with self.assertRaises(ValueError):
                    restore_ots_pair(a, b, key=KEY, claim=claim)
                self.assertEqual(claim.calls, 0)

    def test_type_errors(self):
        _, _, env_l, env_w = make_pair_envelopes()
        for bad in (None, 42, "x", [env_l], object()):
            with self.subTest(slot="a", bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    restore_ots_pair(bad, env_w, key=KEY, claim=RecordingClaim())
            with self.subTest(slot="b", bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    restore_ots_pair(env_l, bad, key=KEY, claim=RecordingClaim())
        for bad in (None, 42, "k", []):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    restore_ots_pair(env_l, env_w, key=bad, claim=RecordingClaim())
        for bad in (True, False, 1.5, "7", [7]):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    restore_ots_pair(
                        env_l, env_w, key=KEY, floor=bad, claim=RecordingClaim()
                    )
        for bad in (None, 42, "claim", b"x", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    restore_ots_pair(env_l, env_w, key=KEY, claim=bad)

    def test_empty_key_value_error(self):
        _, _, env_l, env_w = make_pair_envelopes()
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            restore_ots_pair(env_l, env_w, key=b"", claim=claim)
        self.assertEqual(claim.calls, 0)

    def test_floor_out_of_range_value_error(self):
        _, _, env_l, env_w = make_pair_envelopes(generation=7)
        for floor in (-1, UINT64_MAX + 1):
            with self.subTest(floor=floor):
                claim = RecordingClaim()
                with self.assertRaises(ValueError):
                    restore_ots_pair(
                        env_l, env_w, key=KEY, floor=floor, claim=claim
                    )
                self.assertEqual(claim.calls, 0)

    def test_types_checked_before_envelope_and_claim(self):
        claim = RecordingClaim()
        with self.assertRaises(TypeError):
            restore_ots_pair(b"", b"", key=42, claim=claim)
        with self.assertRaises(TypeError):
            restore_ots_pair(object(), b"", key=KEY, claim=claim)
        with self.assertRaises(TypeError):
            restore_ots_pair(b"", b"", key=KEY, floor=True, claim=claim)
        with self.assertRaises(TypeError):
            restore_ots_pair(b"", b"", key=KEY, claim=42)
        self.assertEqual(claim.calls, 0)

    def test_claim_non_true_value_error(self):
        _, _, env_l, env_w = make_pair_envelopes(generation=7)
        for result in (False, 1, 0, None, "True"):
            with self.subTest(result=repr(result)):
                with self.assertRaises(ValueError):
                    restore_ots_pair(
                        env_l, env_w, key=KEY,
                        claim=RecordingClaim(result=result),
                    )

    def test_claim_exception_propagates(self):
        class Boom(Exception):
            pass

        _, _, env_l, env_w = make_pair_envelopes(generation=7)
        claim = RecordingClaim(error=Boom())
        with self.assertRaises(Boom):
            restore_ots_pair(env_l, env_w, key=KEY, claim=claim)
        self.assertEqual(claim.tokens, [(("lamport", 7), ("wots", 7))])

    def test_draws_no_randomness(self):
        _, _, env_l, env_w = make_pair_envelopes()

        def exploding(size):
            raise AssertionError("restore_ots_pair must not draw randomness")

        with mock.patch.object(pqattest.secrets, "token_bytes", exploding), \
                mock.patch.object(pqattest.wots.secrets, "token_bytes", exploding):
            (l, w), generation = restore_ots_pair(
                env_l, env_w, key=KEY, claim=RecordingClaim()
            )
        self.assertEqual(generation, 7)

    def test_envelopes_remain_standard_v2(self):
        # No new wire format: the accepted blobs are exactly auth_state_wrap
        # output and still parse through the existing public unwrap API.
        _, _, env_l, env_w = make_pair_envelopes(generation=7)
        scheme_l, generation_l, checkpoint_l = auth_state_unwrap(
            env_l, key=KEY, expect="lamport"
        )
        scheme_w, generation_w, checkpoint_w = auth_state_unwrap(
            env_w, key=KEY, expect="wots"
        )
        self.assertEqual((scheme_l, generation_l), ("lamport", 7))
        self.assertEqual((scheme_w, generation_w), ("wots", 7))
        claim = RecordingClaim()
        (l, w), generation = restore_ots_pair(env_l, env_w, key=KEY, claim=claim)
        self.assertEqual(l.checkpoint(), checkpoint_l)
        self.assertEqual(w.checkpoint(), checkpoint_w)
        self.assertEqual(generation, 7)
        self.assertEqual(generation_l, generation_w)


if __name__ == "__main__":
    unittest.main()

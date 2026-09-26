import secrets
import unittest
from unittest import mock

from pqattest import (
    KeyExhaustedError,
    LamportProof,
    OneTimeSigner,
    OtsPairProof,
    WOTSOneTimeSigner,
    WOTSProof,
    auth_state_unwrap,
    auth_state_wrap,
    auth_wrap,
    keygen,
    sign_ots_pair_proof_auth_state,
    verify,
    wots_keygen,
    wots_verify,
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


def make_lamport(start=0):
    private_key, _ = keygen(token_bytes=counter_tokens(start))
    return OneTimeSigner(private_key)


def make_wots(start=1000, w=4):
    private_key, _ = wots_keygen(w=w, token_bytes=counter_tokens(start))
    return WOTSOneTimeSigner(private_key)


def make_pair():
    return make_lamport(), make_wots()


def wrap_lamport(signer, *, generation=7, key=KEY):
    return auth_state_wrap(
        signer.checkpoint(), scheme="lamport", key=key, generation=generation
    )


def wrap_wots(signer, *, generation=7, key=KEY):
    return auth_state_wrap(
        signer.checkpoint(), scheme="wots", key=key, generation=generation
    )


def make_envelopes(generation=7):
    lamport, wots = make_pair()
    return (
        wrap_lamport(lamport, generation=generation),
        wrap_wots(wots, generation=generation),
        lamport,
        wots,
    )


class RecordingClaim:
    """Callable that records every token it is given and returns a fixed value."""

    def __init__(self, result=True):
        self.calls = []
        self.result = result

    def __call__(self, token):
        self.calls.append(token)
        return self.result


class SignOtsPairProofAuthStateTest(unittest.TestCase):
    def test_returns_fixed_triple(self):
        a, b, _, _ = make_envelopes(generation=7)
        result = sign_ots_pair_proof_auth_state(
            a, b, "m", key=KEY, claim=lambda token: True
        )
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)
        pair_proof, envelopes, generation = result
        self.assertIsInstance(pair_proof, OtsPairProof)
        self.assertIsInstance(envelopes, tuple)
        self.assertEqual(len(envelopes), 2)
        self.assertIsInstance(envelopes[0], bytes)
        self.assertIsInstance(envelopes[1], bytes)
        self.assertEqual(generation, 8)
        self.assertIs(type(generation), int)
        self.assertIsNot(type(generation), bool)

    def test_proof_members_are_lamport_first_wots_second(self):
        a, b, lamport, wots = make_envelopes(generation=3)
        pair_proof, _, generation = sign_ots_pair_proof_auth_state(
            a, b, "m", key=KEY, claim=lambda token: True
        )
        self.assertEqual(generation, 4)
        self.assertIsInstance(pair_proof.lamport, LamportProof)
        self.assertIsInstance(pair_proof.wots, WOTSProof)
        self.assertEqual(pair_proof.lamport.public_key, lamport.public_key)
        self.assertEqual(pair_proof.wots.public_key, wots.public_key)

    def test_proof_verifies_for_signed_message_only(self):
        a, b, _, _ = make_envelopes()
        pair_proof, _, _ = sign_ots_pair_proof_auth_state(
            a, b, "m", key=KEY, claim=lambda token: True
        )
        self.assertTrue(pair_proof.verify("m"))
        self.assertTrue(pair_proof.verify(b"m"))
        self.assertFalse(pair_proof.verify(b"other"))
        self.assertTrue(
            verify("m", pair_proof.lamport.signature, pair_proof.lamport.public_key)
        )
        self.assertTrue(
            wots_verify("m", pair_proof.wots.signature, pair_proof.wots.public_key)
        )

    def test_signatures_match_first_sign_of_restored_signers(self):
        a, b, _, _ = make_envelopes(generation=5)
        pair_proof, _, _ = sign_ots_pair_proof_auth_state(
            a, b, "m", key=KEY, claim=lambda token: True
        )
        # Independently restore the same envelopes and sign for the first time.
        lamport = OneTimeSigner.from_auth_state(
            a, key=KEY, claim=lambda token: True
        )[0]
        wots = WOTSOneTimeSigner.from_auth_state(
            b, key=KEY, claim=lambda token: True
        )[0]
        self.assertEqual(pair_proof.lamport.signature, lamport.sign("m"))
        self.assertEqual(pair_proof.wots.signature, wots.sign("m"))

    def test_encoding_matches_hand_assembled_pair(self):
        a, b, _, _ = make_envelopes()
        pair_proof, _, _ = sign_ots_pair_proof_auth_state(
            a, b, "m", key=KEY, claim=lambda token: True
        )
        reference_lamport = OneTimeSigner.from_auth_state(
            a, key=KEY, claim=lambda token: True
        )[0]
        reference_wots = WOTSOneTimeSigner.from_auth_state(
            b, key=KEY, claim=lambda token: True
        )[0]
        hand_assembled = OtsPairProof(
            lamport=LamportProof(
                public_key=reference_lamport.public_key,
                signature=reference_lamport.sign("m"),
            ),
            wots=WOTSProof(
                public_key=reference_wots.public_key,
                signature=reference_wots.sign("m"),
            ),
        )
        self.assertEqual(pair_proof, hand_assembled)
        self.assertEqual(pair_proof.to_bytes(), hand_assembled.to_bytes())
        restored = OtsPairProof.from_bytes(pair_proof.to_bytes())
        self.assertEqual(restored, pair_proof)
        self.assertTrue(restored.verify("m"))

    def test_envelopes_bind_generation_plus_one_and_match_direct_wrap(self):
        a, b, lamport, wots = make_envelopes(generation=7)
        _, (lamport_envelope, wots_envelope), generation = (
            sign_ots_pair_proof_auth_state(
                a, b, "m", key=KEY, claim=lambda token: True
            )
        )
        self.assertEqual(generation, 8)
        # Reference: restore, sign, wrap the post-sign checkpoint at g+1.
        reference_lamport = OneTimeSigner.from_auth_state(
            a, key=KEY, claim=lambda token: True
        )[0]
        reference_wots = WOTSOneTimeSigner.from_auth_state(
            b, key=KEY, claim=lambda token: True
        )[0]
        reference_lamport.sign("m")
        reference_wots.sign("m")
        self.assertEqual(
            lamport_envelope,
            auth_state_wrap(
                reference_lamport.checkpoint(),
                scheme="lamport",
                key=KEY,
                generation=8,
            ),
        )
        self.assertEqual(
            wots_envelope,
            auth_state_wrap(
                reference_wots.checkpoint(),
                scheme="wots",
                key=KEY,
                generation=8,
            ),
        )
        scheme, got_generation, checkpoint = auth_state_unwrap(
            lamport_envelope, key=KEY, expect="lamport"
        )
        self.assertEqual((scheme, got_generation), ("lamport", 8))
        restored_lamport = OneTimeSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored_lamport.public_key, lamport.public_key)
        self.assertTrue(restored_lamport.used)
        with self.assertRaises(KeyExhaustedError):
            restored_lamport.sign("m")
        scheme, got_generation, checkpoint = auth_state_unwrap(
            wots_envelope, key=KEY, expect="wots"
        )
        self.assertEqual((scheme, got_generation), ("wots", 8))
        restored_wots = WOTSOneTimeSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored_wots.public_key, wots.public_key)
        self.assertTrue(restored_wots.used)
        with self.assertRaises(KeyExhaustedError):
            restored_wots.sign("m")

    def test_accepts_bytes_bytearray_and_str_message(self):
        for message in (b"m", bytearray(b"m"), "m"):
            with self.subTest(message=type(message).__name__):
                a, b, _, _ = make_envelopes()
                pair_proof, envelopes, generation = (
                    sign_ots_pair_proof_auth_state(
                        a, b, message, key=bytearray(KEY),
                        min_generation=None, claim=lambda token: True,
                    )
                )
                self.assertTrue(pair_proof.verify(b"m"))
                self.assertEqual(len(envelopes), 2)
                self.assertEqual(generation, 8)

    def test_deterministic_across_repeated_calls(self):
        a, b, _, _ = make_envelopes(generation=5)
        first = sign_ots_pair_proof_auth_state(
            a, b, "m", key=KEY, claim=lambda token: True
        )
        second = sign_ots_pair_proof_auth_state(
            a, b, "m", key=KEY, claim=lambda token: True
        )
        self.assertEqual(first[0].to_bytes(), second[0].to_bytes())
        self.assertEqual(first[1], second[1])
        self.assertEqual(first[2], second[2])

    def test_does_not_mutate_inputs(self):
        a, b, _, _ = make_envelopes()
        message = bytearray(b"m")
        a_mutable, b_mutable = bytearray(a), bytearray(b)
        sign_ots_pair_proof_auth_state(
            a_mutable, b_mutable, message, key=KEY, claim=lambda token: True
        )
        self.assertEqual(bytes(message), b"m")
        self.assertEqual(bytes(a_mutable), a)
        self.assertEqual(bytes(b_mutable), b)

    def test_draws_no_randomness(self):
        a, b, _, _ = make_envelopes()

        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_ots_pair_proof_auth_state must not draw randomness"
            )

        with mock.patch.object(secrets, "token_bytes", exploding_token_bytes):
            pair_proof, envelopes, generation = (
                sign_ots_pair_proof_auth_state(
                    a, b, "m", key=KEY, claim=lambda token: True
                )
            )
        self.assertTrue(pair_proof.verify("m"))
        self.assertEqual(generation, 8)
        self.assertEqual(len(envelopes), 2)


class ClaimTest(unittest.TestCase):
    def setUp(self):
        self.a, self.b, _, _ = make_envelopes(generation=7)

    def test_claim_receives_exact_transition_token(self):
        claim = RecordingClaim()
        sign_ots_pair_proof_auth_state(
            self.a, self.b, "m", key=KEY, claim=claim
        )
        self.assertEqual(
            claim.calls,
            [
                (
                    (("lamport", 7), ("wots", 7)),
                    (("lamport", 8), ("wots", 8)),
                )
            ],
        )

    def test_claim_called_exactly_once(self):
        claim = RecordingClaim()
        sign_ots_pair_proof_auth_state(
            self.a, self.b, "m", key=KEY, claim=claim
        )
        self.assertEqual(len(claim.calls), 1)

    def test_old_token_precedes_new_token_and_order_is_fixed(self):
        seen = []
        sign_ots_pair_proof_auth_state(
            self.a, self.b, "m", key=KEY,
            claim=lambda token: (seen.append(token), True)[1],
        )
        token = seen[0]
        self.assertIsInstance(token, tuple)
        self.assertEqual(len(token), 2)
        old, new = token
        # Old/new generations cannot be swapped.
        self.assertEqual(old, (("lamport", 7), ("wots", 7)))
        self.assertEqual(new, (("lamport", 8), ("wots", 8)))
        # Each half keeps the restore_ots_pair pair-token shape and order.
        self.assertEqual((old[0][0], old[1][0]), ("lamport", "wots"))
        self.assertEqual((new[0][0], new[1][0]), ("lamport", "wots"))
        self.assertIs(type(old[0][1]), int)
        self.assertIsNot(type(old[0][1]), bool)

    def test_claim_false_rejected(self):
        claim = RecordingClaim(result=False)
        with self.assertRaises(ValueError):
            sign_ots_pair_proof_auth_state(
                self.a, self.b, "m", key=KEY, claim=claim
            )
        self.assertEqual(len(claim.calls), 1)

    def test_truthy_non_true_rejected(self):
        for result in (1, "True", b"True", object()):
            with self.subTest(result=repr(result)):
                claim = RecordingClaim(result=result)
                with self.assertRaises(ValueError):
                    sign_ots_pair_proof_auth_state(
                        self.a, self.b, "m", key=KEY, claim=claim
                    )
                self.assertEqual(len(claim.calls), 1)

    def test_claim_exception_propagates_untouched(self):
        class Boom(Exception):
            pass

        def boom(token):
            raise Boom

        with self.assertRaises(Boom):
            sign_ots_pair_proof_auth_state(
                self.a, self.b, "m", key=KEY, claim=boom
            )

    def test_claim_not_called_on_wrong_key(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_ots_pair_proof_auth_state(
                self.a, self.b, "m", key=OTHER_KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_tamper(self):
        claim = RecordingClaim()
        for side in ("a", "b"):
            with self.subTest(side=side):
                claim.calls.clear()
                if side == "a":
                    forged = bytearray(self.a)
                    forged[30] ^= 0x01
                    a, b = bytes(forged), self.b
                else:
                    forged = bytearray(self.b)
                    forged[30] ^= 0x01
                    a, b = self.a, bytes(forged)
                with self.assertRaises(ValueError):
                    sign_ots_pair_proof_auth_state(
                        a, b, "m", key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])

    def test_both_tags_verified_before_any_field_parsed(self):
        # Side a authenticates but is in the wrong scheme position; side b's
        # tag does not verify. The tag mismatch must win: both HMACs are
        # checked before either envelope's fields are parsed.
        wrong_scheme_a = wrap_wots(make_wots(), generation=7)
        forged_b = bytearray(self.b)
        forged_b[-1] ^= 0x01
        claim = RecordingClaim()
        with self.assertRaisesRegex(ValueError, "tag mismatch"):
            sign_ots_pair_proof_auth_state(
                wrong_scheme_a, bytes(forged_b), "m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])
        # Mirrored.
        forged_a = bytearray(self.a)
        forged_a[-1] ^= 0x01
        wrong_scheme_b = wrap_lamport(make_lamport(), generation=7)
        with self.assertRaisesRegex(ValueError, "tag mismatch"):
            sign_ots_pair_proof_auth_state(
                bytes(forged_a), wrong_scheme_b, "m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_swapped_sides(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_ots_pair_proof_auth_state(
                self.b, self.a, "m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_v1_envelopes(self):
        lamport, wots = make_pair()
        v1_a = auth_wrap(lamport.checkpoint(), scheme="lamport", key=KEY)
        v1_b = auth_wrap(wots.checkpoint(), scheme="wots", key=KEY)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_ots_pair_proof_auth_state(
                v1_a, self.b, "m", key=KEY, claim=claim
            )
        with self.assertRaises(ValueError):
            sign_ots_pair_proof_auth_state(
                self.a, v1_b, "m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_mismatched_generations(self):
        _, _, lamport, wots = make_envelopes(generation=7)
        b_other = wrap_wots(wots, generation=8)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_ots_pair_proof_auth_state(
                self.a, b_other, "m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_below_floor(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_ots_pair_proof_auth_state(
                self.a, self.b, "m", key=KEY, min_generation=8, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_floor_equal_passes(self):
        claim = RecordingClaim()
        sign_ots_pair_proof_auth_state(
            self.a, self.b, "m", key=KEY, min_generation=7, claim=claim
        )
        self.assertEqual(len(claim.calls), 1)

    def test_claim_not_called_at_uint64_ceiling(self):
        lamport, wots = make_pair()
        a = wrap_lamport(lamport, generation=UINT64_MAX)
        b = wrap_wots(wots, generation=UINT64_MAX)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_ots_pair_proof_auth_state(
                a, b, "m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_garbage(self):
        claim = RecordingClaim()
        for bad in (b"", b"\x00", b"PQAAUTH\0", b"\x00" * 54,
                    self.a[:-1], self.a + b"\x00"):
            with self.subTest(length=len(bad)):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    sign_ots_pair_proof_auth_state(
                        bad, self.b, "m", key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])


class KeyExhaustedTest(unittest.TestCase):
    def test_used_lamport_state_raises_without_claim(self):
        lamport, wots = make_pair()
        lamport.sign("earlier")
        a = wrap_lamport(lamport, generation=7)
        b = wrap_wots(wots, generation=7)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            sign_ots_pair_proof_auth_state(
                a, b, "m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_used_wots_state_raises_without_claim(self):
        lamport, wots = make_pair()
        wots.sign("earlier")
        a = wrap_lamport(lamport, generation=7)
        b = wrap_wots(wots, generation=7)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            sign_ots_pair_proof_auth_state(
                a, b, "m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_one_side_used_leaves_the_other_envelope_reusable(self):
        # Stateless: an exhausted side must not consume the other envelope:
        # swapping in a fresh partner makes the untouched side succeed.
        lamport, wots = make_pair()
        lamport.sign("earlier")
        a_used = wrap_lamport(lamport, generation=7)
        b = wrap_wots(wots, generation=7)
        with self.assertRaises(KeyExhaustedError):
            sign_ots_pair_proof_auth_state(
                a_used, b, "m", key=KEY, claim=lambda token: True
            )
        fresh_lamport = make_lamport()
        a_fresh = wrap_lamport(fresh_lamport, generation=7)
        pair_proof, envelopes, generation = (
            sign_ots_pair_proof_auth_state(
                a_fresh, b, "m", key=KEY, claim=lambda token: True
            )
        )
        self.assertTrue(pair_proof.verify("m"))
        self.assertEqual(generation, 8)
        self.assertEqual(
            pair_proof.wots.public_key, wots.public_key
        )
        self.assertEqual(len(envelopes), 2)

    def test_used_state_wins_over_ceiling_in_parse_order(self):
        # Both defects present: the ceiling check precedes checkpoint
        # restore, so the ceiling ValueError surfaces, never a claim.
        lamport, wots = make_pair()
        lamport.sign("earlier")
        a = wrap_lamport(lamport, generation=UINT64_MAX)
        b = wrap_wots(wots, generation=UINT64_MAX)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_ots_pair_proof_auth_state(
                a, b, "m", key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])


class TypesTest(unittest.TestCase):
    def setUp(self):
        self.a, self.b, _, _ = make_envelopes(generation=1)

    def test_keyword_only_arguments(self):
        with self.assertRaises(TypeError):
            sign_ots_pair_proof_auth_state(
                self.a, self.b, "m", KEY, None, lambda token: True
            )

    def test_claim_is_required(self):
        with self.assertRaises(TypeError):
            sign_ots_pair_proof_auth_state(self.a, self.b, "m", key=KEY)

    def test_non_bytes_data_type_error(self):
        for bad in (None, 42, 4.5, "blob", [self.a], object()):
            with self.subTest(bad=type(bad).__name__, side="a"):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_auth_state(
                        bad, self.b, "m", key=KEY, claim=lambda t: True
                    )
            with self.subTest(bad=type(bad).__name__, side="b"):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_auth_state(
                        self.a, bad, "m", key=KEY, claim=lambda t: True
                    )

    def test_non_bytes_key_type_error(self):
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_auth_state(
                        self.a, self.b, "m", key=bad, claim=lambda t: True
                    )

    def test_non_callable_claim_type_error(self):
        for bad in (None, True, 1, "claim", b"claim", (lambda: True,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_auth_state(
                        self.a, self.b, "m", key=KEY, claim=bad
                    )

    def test_bad_floor_type_error(self):
        for bad in (1.5, "0", [0], (0,), object(), True, False):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_auth_state(
                        self.a, self.b, "m", key=KEY,
                        min_generation=bad, claim=lambda t: True,
                    )

    def test_bad_message_type_error(self):
        for bad in (None, 42, 4.5, [b"m"], (b"m",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_auth_state(
                        self.a, self.b, bad, key=KEY, claim=lambda t: True
                    )

    def test_empty_key_value_error(self):
        for bad in (b"", bytearray()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    sign_ots_pair_proof_auth_state(
                        self.a, self.b, "m", key=bad, claim=lambda t: True
                    )

    def test_floor_out_of_range_value_error(self):
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    sign_ots_pair_proof_auth_state(
                        self.a, self.b, "m", key=KEY,
                        min_generation=bad, claim=lambda t: True,
                    )

    def test_types_checked_before_any_envelope_touch(self):
        # Type errors win even when the envelope bytes are garbage.
        with self.assertRaises(TypeError):
            sign_ots_pair_proof_auth_state(
                b"", b"", "m", key=42, claim=lambda t: True
            )
        with self.assertRaises(TypeError):
            sign_ots_pair_proof_auth_state(
                object(), self.b, "m", key=KEY, claim=lambda t: True
            )
        with self.assertRaises(TypeError):
            sign_ots_pair_proof_auth_state(
                b"", b"", "m", key=KEY, min_generation=True,
                claim=lambda t: True,
            )
        with self.assertRaises(TypeError):
            sign_ots_pair_proof_auth_state(
                b"", b"", "m", key=KEY, claim="claim"
            )
        with self.assertRaises(TypeError):
            sign_ots_pair_proof_auth_state(
                b"", b"", 42, key=KEY, claim=lambda t: True
            )


class OutputsChainTest(unittest.TestCase):
    def test_next_envelopes_can_be_restored_as_a_pair(self):
        from pqattest import restore_ots_pair

        a, b, _, _ = make_envelopes(generation=7)
        pair_proof, (next_a, next_b), generation = (
            sign_ots_pair_proof_auth_state(
                a, b, "m", key=KEY, claim=lambda token: True
            )
        )
        self.assertEqual(generation, 8)
        (lamport, wots), restored_generation = restore_ots_pair(
            next_a, next_b, key=KEY, claim=lambda token: True
        )
        self.assertEqual(restored_generation, 8)
        self.assertTrue(lamport.used)
        self.assertTrue(wots.used)
        self.assertEqual(pair_proof.lamport.public_key, lamport.public_key)
        self.assertEqual(pair_proof.wots.public_key, wots.public_key)


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest import mock

import pqattest
from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    OneTimeSigner,
    WOTSOneTimeSigner,
    advance_and_multiproof_merkle_auth_state,
    auth_state_unwrap,
    auth_state_wrap,
    auth_wrap,
    keygen,
    multiproof_encode,
    multiproof_verify,
    wots_keygen,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret"
UINT64_MAX = 2**64 - 1

MESSAGES = (b"m0", b"m1", b"m2")


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


class AdvanceAndMultiproofMerkleAuthStateTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.envelope = wrap_merkle(self.signer, generation=11)

    def test_returns_inner_tuple_proof_envelope_and_generation(self):
        result = advance_and_multiproof_merkle_auth_state(
            self.envelope, 1, (b"a", b"b"), key=KEY, claim=accept
        )
        self.assertEqual(len(result), 4)
        (before, target), proof, envelope, generation = result
        self.assertEqual((before, target), (0, 1))
        self.assertIsInstance(proof, bytes)
        self.assertTrue(multiproof_verify((b"a", b"b"), proof))
        self.assertIsInstance(envelope, bytes)
        self.assertEqual(generation, 12)
        self.assertIs(type(generation), int)
        self.assertIsNot(type(generation), bool)

    def test_proof_matches_advance_to_then_sign_batch_then_multiproof_encode(self):
        reference = make_signer()
        (before, target), proof, envelope, generation = (
            advance_and_multiproof_merkle_auth_state(
                self.envelope, 1, MESSAGES, key=KEY, claim=accept
            )
        )
        self.assertEqual((before, target), (0, 1))
        reference.advance_to(1)
        signatures = reference.sign_batch(MESSAGES)
        expected_proof = multiproof_encode(reference.public_key, signatures)
        self.assertEqual(proof, expected_proof)
        self.assertTrue(multiproof_verify(MESSAGES, proof))
        self.assertEqual(generation, 12)

    def test_proof_uses_consecutive_leaves_of_restored_state(self):
        signer = make_signer(height=3)
        signer.sign(b"a")
        envelope = wrap_merkle(signer, generation=5)
        reference = make_signer(height=3)
        reference.sign(b"a")
        messages = (b"c", b"d")
        (before, target), proof, _, generation = (
            advance_and_multiproof_merkle_auth_state(
                envelope, 6, messages, key=KEY, claim=accept
            )
        )
        reference.advance_to(6)
        signatures = reference.sign_batch(messages)
        self.assertEqual((before, target), (1, 6))
        self.assertEqual(
            proof, multiproof_encode(reference.public_key, signatures)
        )
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertFalse(multiproof_verify((b"c", b"x"), proof))
        self.assertEqual(generation, 6)

    def test_single_message_proof_verifies(self):
        (before, target), proof, _, _ = (
            advance_and_multiproof_merkle_auth_state(
                self.envelope, 2, (b"only",), key=KEY, claim=accept
            )
        )
        self.assertEqual((before, target), (0, 2))
        self.assertTrue(multiproof_verify((b"only",), proof))
        self.assertFalse(multiproof_verify((b"other",), proof))

    def test_wrong_message_count_does_not_verify(self):
        _, proof, _, _ = advance_and_multiproof_merkle_auth_state(
            self.envelope, 1, MESSAGES, key=KEY, claim=accept
        )
        self.assertFalse(multiproof_verify((b"m0", b"m1"), proof))
        self.assertFalse(
            multiproof_verify((b"m0", b"m1", b"m2", b"m3"), proof)
        )

    def test_envelope_matches_explicit_wrap_at_g_plus_one(self):
        reference = make_signer()
        _, _, envelope, generation = (
            advance_and_multiproof_merkle_auth_state(
                self.envelope, 1, MESSAGES, key=KEY, claim=accept
            )
        )
        reference.advance_to(1)
        reference.sign_batch(MESSAGES)
        expected = auth_state_wrap(
            reference.checkpoint(),
            scheme="merkle",
            key=KEY,
            generation=12,
        )
        self.assertEqual(generation, 12)
        self.assertEqual(envelope, expected)

    def test_returned_envelope_unwraps_to_post_batch_state(self):
        (before, target), proof, envelope, generation = (
            advance_and_multiproof_merkle_auth_state(
                self.envelope, 1, (b"one", b"two"), key=KEY, claim=accept
            )
        )
        self.assertTrue(multiproof_verify((b"one", b"two"), proof))
        scheme, wrapped_generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(scheme, "merkle")
        self.assertEqual(wrapped_generation, generation)
        self.assertEqual(generation, 12)
        self.assertEqual((before, target), (0, 1))
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, self.signer.public_key)
        self.assertEqual(restored.next_index, 3)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 3)
        follow_up = restored.sign(b"three")
        self.assertEqual(follow_up.index, 3)

    def test_equal_target_is_legal(self):
        signer = make_signer(height=3)
        signer.advance_to(3)
        envelope = wrap_merkle(signer, generation=9)
        reference = make_signer(height=3)
        reference.advance_to(3)
        messages = (b"m", b"n")
        (before, target), proof, out_envelope, generation = (
            advance_and_multiproof_merkle_auth_state(
                envelope, 3, messages, key=KEY, claim=accept
            )
        )
        self.assertEqual((before, target), (3, 3))
        self.assertEqual(
            proof,
            multiproof_encode(reference.public_key, reference.sign_batch(messages)),
        )
        self.assertEqual(generation, 10)
        _, wrapped_generation, checkpoint = auth_state_unwrap(
            out_envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(wrapped_generation, 10)
        self.assertEqual(checkpoint, reference.checkpoint())

    def test_last_leaf_batch_of_one_succeeds(self):
        signer = make_signer(height=2)  # 4 leaves
        (before, target), proof, out_envelope, generation = (
            advance_and_multiproof_merkle_auth_state(
                wrap_merkle(signer, generation=0), 3, (b"last",),
                key=KEY, claim=accept,
            )
        )
        self.assertEqual((before, target), (0, 3))
        self.assertTrue(multiproof_verify((b"last",), proof))
        self.assertEqual(generation, 1)
        _, _, checkpoint = auth_state_unwrap(out_envelope, key=KEY)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)

    def test_batch_exactly_filling_from_target_succeeds(self):
        signer = make_signer(height=2)
        (before, target), proof, _, generation = (
            advance_and_multiproof_merkle_auth_state(
                wrap_merkle(signer, generation=2), 2, (b"a", b"b"),
                key=KEY, claim=accept,
            )
        )
        self.assertEqual((before, target), (0, 2))
        self.assertTrue(multiproof_verify((b"a", b"b"), proof))
        self.assertEqual(generation, 3)

    def test_batch_running_past_last_leaf_raises_key_exhausted_without_claim(self):
        signer = make_signer(height=2)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            advance_and_multiproof_merkle_auth_state(
                wrap_merkle(signer, generation=0), 2, (b"a", b"b", b"c"),
                key=KEY, claim=claim,
            )
        self.assertEqual(claim.calls, [])

    def test_accepts_str_bytearray_members_and_bytearray_inputs(self):
        messages = ("m0", bytearray(b"m1"), b"m2")
        (before, target), proof, envelope, generation = (
            advance_and_multiproof_merkle_auth_state(
                bytearray(self.envelope), 1, messages,
                key=bytearray(KEY), claim=accept,
            )
        )
        reference = make_signer()
        reference.advance_to(1)
        signatures = reference.sign_batch(("m0", b"m1", b"m2"))
        self.assertEqual((before, target), (0, 1))
        self.assertEqual(
            proof, multiproof_encode(reference.public_key, signatures)
        )
        self.assertTrue(multiproof_verify(("m0", b"m1", b"m2"), proof))
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

    def test_generation_endpoints(self):
        low = wrap_merkle(self.signer, generation=0)
        _, _, _, generation = advance_and_multiproof_merkle_auth_state(
            low, 1, (b"m",), key=KEY, claim=accept
        )
        self.assertEqual(generation, 1)
        ceiling = wrap_merkle(self.signer, generation=UINT64_MAX - 1)
        _, proof, envelope, generation = advance_and_multiproof_merkle_auth_state(
            ceiling, 1, (b"m",), key=KEY, claim=accept
        )
        self.assertTrue(multiproof_verify((b"m",), proof))
        self.assertEqual(generation, UINT64_MAX)
        _, wrapped_generation, _ = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(wrapped_generation, UINT64_MAX)

    def test_stateless_chaining_through_envelopes(self):
        signer = make_signer(height=3)
        envelope = wrap_merkle(signer, generation=0)
        _, proof, envelope, generation = (
            advance_and_multiproof_merkle_auth_state(
                envelope, 1, (b"m1", b"m2"), key=KEY, claim=accept
            )
        )
        self.assertTrue(multiproof_verify((b"m1", b"m2"), proof))
        self.assertEqual(generation, 1)
        _, proof, envelope, generation = (
            advance_and_multiproof_merkle_auth_state(
                envelope, 5, (b"m5", b"m6", b"m7"), key=KEY, claim=accept
            )
        )
        self.assertTrue(multiproof_verify((b"m5", b"m6", b"m7"), proof))
        self.assertEqual(generation, 2)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY, expect="merkle")
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 8)
        self.assertEqual(restored.remaining, 0)

    def test_stateless_same_envelope_replays_identically(self):
        first = advance_and_multiproof_merkle_auth_state(
            self.envelope, 1, (b"m", b"n"), key=KEY, claim=accept
        )
        second = advance_and_multiproof_merkle_auth_state(
            self.envelope, 1, (b"m", b"n"), key=KEY, claim=accept
        )
        self.assertEqual(first, second)
        self.assertEqual(first[0], (0, 1))

    def test_does_not_mutate_state_behind_input_envelope(self):
        signer = make_signer()
        envelope = wrap_merkle(signer, generation=3)
        self.assertEqual(signer.next_index, 0)
        advance_and_multiproof_merkle_auth_state(
            envelope, 3, (b"m",), key=KEY, claim=accept
        )
        self.assertEqual(signer.next_index, 0)

    def test_floor_equal_and_below_pass(self):
        envelope = wrap_merkle(self.signer, generation=7)
        advance_and_multiproof_merkle_auth_state(
            envelope, 1, (b"m",), key=KEY, min_generation=7, claim=accept
        )
        advance_and_multiproof_merkle_auth_state(
            envelope, 1, (b"m",), key=KEY, min_generation=6, claim=accept
        )

    def test_floor_above_generation_fails_without_claim(self):
        claim = RecordingClaim()
        envelope = wrap_merkle(self.signer, generation=7)
        with self.assertRaises(ValueError):
            advance_and_multiproof_merkle_auth_state(
                envelope, 1, (b"m",), key=KEY, min_generation=8, claim=claim
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
                    advance_and_multiproof_merkle_auth_state(
                        envelope, bad, (b"m",), key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])
        (before, target), _, _, generation = (
            advance_and_multiproof_merkle_auth_state(
                envelope, 2, (b"m",), key=KEY, claim=accept
            )
        )
        self.assertEqual((before, target), (1, 2))
        self.assertEqual(generation, 5)

    def test_leaf_count_and_above_raise_value_error(self):
        signer = make_signer(height=2)  # 4 leaves
        envelope = wrap_merkle(signer, generation=0)
        claim = RecordingClaim()
        for bad in (4, 5, 8, 1 << 16):
            with self.subTest(bad=bad):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    advance_and_multiproof_merkle_auth_state(
                        envelope, bad, (b"m",), key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])

    def test_exhausted_restored_state_raises_value_error_without_claim(self):
        signer = make_signer(height=2)
        signer.advance_to(4)
        envelope = wrap_merkle(signer, generation=2)
        claim = RecordingClaim()
        for bad in (3, 4):
            with self.subTest(bad=bad):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    advance_and_multiproof_merkle_auth_state(
                        envelope, bad, (b"m",), key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])

    def test_empty_batch_rejected_before_envelope_use(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            advance_and_multiproof_merkle_auth_state(
                b"garbage", 1, (), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError(
                "advance_and_multiproof_merkle_auth_state must not draw randomness"
            )

        with mock.patch.object(
            pqattest.secrets, "token_bytes", exploding_token_bytes
        ):
            result = advance_and_multiproof_merkle_auth_state(
                self.envelope, 2, (b"m", b"n"), key=KEY, claim=accept
            )
        self.assertEqual(result[0], (0, 2))
        self.assertEqual(result[3], 12)
        _, _, checkpoint = auth_state_unwrap(result[2], key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 4)


class AdvanceAndMultiproofMerkleAuthStateClaimTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.envelope = wrap_merkle(self.signer, generation=7)

    def test_claim_receives_exact_paired_token(self):
        claim = RecordingClaim()
        advance_and_multiproof_merkle_auth_state(
            self.envelope, 2, (b"m", b"n"), key=KEY, claim=claim
        )
        self.assertEqual(claim.calls, [(("merkle", 7), ("merkle", 8))])

    def test_claim_called_exactly_once_regardless_of_batch_size(self):
        for size in (1, 2, 3, 4):
            with self.subTest(size=size):
                claim = RecordingClaim()
                messages = tuple(f"m{i}".encode() for i in range(size))
                advance_and_multiproof_merkle_auth_state(
                    self.envelope, 0, messages, key=KEY, claim=claim
                )
                self.assertEqual(len(claim.calls), 1)

    def test_claim_token_is_a_pair_of_plain_tuples(self):
        seen = []
        advance_and_multiproof_merkle_auth_state(
            self.envelope, 3, (b"m",), key=KEY,
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
            advance_and_multiproof_merkle_auth_state(
                self.envelope, 3, (b"m",), key=KEY, claim=claim
            )
        self.assertEqual(len(claim.calls), 1)

    def test_truthy_non_true_rejected(self):
        for result in (1, "True", b"True", object()):
            with self.subTest(result=repr(result)):
                claim = RecordingClaim(result=result)
                with self.assertRaises(ValueError):
                    advance_and_multiproof_merkle_auth_state(
                        self.envelope, 3, (b"m",), key=KEY, claim=claim
                    )
                self.assertEqual(len(claim.calls), 1)

    def test_claim_exception_propagates_untouched(self):
        class Boom(Exception):
            pass

        def boom(token):
            raise Boom

        with self.assertRaises(Boom):
            advance_and_multiproof_merkle_auth_state(
                self.envelope, 3, (b"m",), key=KEY, claim=boom
            )

    def test_claim_not_called_on_wrong_key(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            advance_and_multiproof_merkle_auth_state(
                self.envelope, 3, (b"m",), key=OTHER_KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_tamper(self):
        claim = RecordingClaim()
        forged = bytearray(self.envelope)
        forged[30] ^= 0x01
        with self.assertRaises(ValueError):
            advance_and_multiproof_merkle_auth_state(
                bytes(forged), 3, (b"m",), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_v1_envelope(self):
        claim = RecordingClaim()
        v1 = auth_wrap(self.signer.checkpoint(), scheme="merkle", key=KEY)
        with self.assertRaises(ValueError):
            advance_and_multiproof_merkle_auth_state(
                v1, 3, (b"m",), key=KEY, claim=claim
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
                    advance_and_multiproof_merkle_auth_state(
                        envelope, 3, (b"m",), key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_garbage(self):
        claim = RecordingClaim()
        for bad in (b"", b"\x00", b"PQAAUTH\0", b"\x00" * 54,
                    self.envelope[:-1], self.envelope + b"\x00"):
            with self.subTest(length=len(bad)):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    advance_and_multiproof_merkle_auth_state(
                        bad, 3, (b"m",), key=KEY, claim=claim
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
            advance_and_multiproof_merkle_auth_state(
                blob, 3, (b"m",), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_at_generation_ceiling(self):
        envelope = wrap_merkle(self.signer, generation=UINT64_MAX)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            advance_and_multiproof_merkle_auth_state(
                envelope, 3, (b"m",), key=KEY, claim=claim
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
                    advance_and_multiproof_merkle_auth_state(
                        envelope, bad, (b"m",), key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_empty_batch(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            advance_and_multiproof_merkle_auth_state(
                self.envelope, 3, (), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_bad_message_member(self):
        claim = RecordingClaim()
        for bad in (123, object(), [b"m"], None, 4.5):
            with self.subTest(bad=type(bad).__name__):
                claim.calls.clear()
                with self.assertRaises(TypeError):
                    advance_and_multiproof_merkle_auth_state(
                        self.envelope, 3, (b"ok", bad), key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_insufficient_capacity(self):
        signer = make_signer(height=1)
        signer.sign(b"a")
        envelope = wrap_merkle(signer, generation=9)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            advance_and_multiproof_merkle_auth_state(
                envelope, 1, (b"b", b"c"), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])


class AdvanceAndMultiproofMerkleAuthStateTypesTest(unittest.TestCase):
    def setUp(self):
        self.envelope = wrap_merkle(make_signer(), generation=1)

    def test_keyword_only_arguments(self):
        with self.assertRaises(TypeError):
            advance_and_multiproof_merkle_auth_state(
                self.envelope, 3, (b"m",), KEY, None, accept
            )
        with self.assertRaises(TypeError):
            advance_and_multiproof_merkle_auth_state(
                self.envelope, 3, (b"m",), KEY, claim=accept
            )

    def test_claim_is_required(self):
        with self.assertRaises(TypeError):
            advance_and_multiproof_merkle_auth_state(
                self.envelope, 3, (b"m",), key=KEY
            )

    def test_non_bytes_data_type_error(self):
        for bad in (None, 42, 4.5, "blob", [self.envelope], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    advance_and_multiproof_merkle_auth_state(
                        bad, 3, (b"m",), key=KEY, claim=accept
                    )

    def test_non_integer_target_type_error(self):
        for bad in (True, False, 1.0, "1", None, [1], (1,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    advance_and_multiproof_merkle_auth_state(
                        self.envelope, bad, (b"m",), key=KEY, claim=accept
                    )

    def test_non_tuple_messages_type_error(self):
        for bad in (
            [b"m0", b"m1"],
            {b"m0"},
            b"m0m1",
            "m0",
            None,
            42,
            iter((b"m0",)),
        ):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    advance_and_multiproof_merkle_auth_state(
                        self.envelope, 3, bad, key=KEY, claim=accept
                    )

    def test_non_bytes_key_type_error(self):
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    advance_and_multiproof_merkle_auth_state(
                        self.envelope, 3, (b"m",), key=bad, claim=accept
                    )

    def test_non_callable_claim_type_error(self):
        for bad in (None, True, 1, "claim", b"claim", (lambda: True,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    advance_and_multiproof_merkle_auth_state(
                        self.envelope, 3, (b"m",), key=KEY, claim=bad
                    )

    def test_bad_min_generation_type_error(self):
        for bad in (1.5, "0", [0], (0,), object(), True, False):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    advance_and_multiproof_merkle_auth_state(
                        self.envelope, 3, (b"m",), key=KEY,
                        min_generation=bad, claim=accept,
                    )

    def test_empty_key_value_error(self):
        for bad in (b"", bytearray()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    advance_and_multiproof_merkle_auth_state(
                        self.envelope, 3, (b"m",), key=bad, claim=accept
                    )

    def test_empty_messages_value_error(self):
        with self.assertRaises(ValueError):
            advance_and_multiproof_merkle_auth_state(
                self.envelope, 3, (), key=KEY, claim=accept
            )

    def test_min_generation_out_of_range_value_error(self):
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    advance_and_multiproof_merkle_auth_state(
                        self.envelope, 3, (b"m",), key=KEY,
                        min_generation=bad, claim=accept,
                    )

    def test_types_checked_before_envelope(self):
        with self.assertRaises(TypeError):
            advance_and_multiproof_merkle_auth_state(
                b"", 3, (b"m",), key=42, claim=accept
            )
        with self.assertRaises(TypeError):
            advance_and_multiproof_merkle_auth_state(
                object(), 3, (b"m",), key=KEY, claim=accept
            )
        with self.assertRaises(TypeError):
            advance_and_multiproof_merkle_auth_state(
                b"", 3, (b"m",), key=KEY, min_generation=True, claim=accept
            )
        with self.assertRaises(TypeError):
            advance_and_multiproof_merkle_auth_state(
                b"", 3, (b"m",), key=KEY, claim="claim"
            )
        with self.assertRaises(TypeError):
            advance_and_multiproof_merkle_auth_state(
                b"", True, (b"m",), key=KEY, claim=accept
            )
        with self.assertRaises(TypeError):
            advance_and_multiproof_merkle_auth_state(
                b"", 3, [b"m"], key=KEY, claim=accept
            )
        with self.assertRaises(TypeError):
            advance_and_multiproof_merkle_auth_state(
                b"", 3, (123,), key=KEY, claim=accept
            )


if __name__ == "__main__":
    unittest.main()

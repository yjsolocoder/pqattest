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
    merkle_verify,
    sign_merkle_auth_state_batch,
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


MESSAGES = (b"m0", b"m1", b"m2")


class SignMerkleAuthStateBatchTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.envelope = wrap_merkle(self.signer, generation=11)

    def test_returns_signatures_envelope_and_generation(self):
        result = sign_merkle_auth_state_batch(
            self.envelope, MESSAGES, key=KEY, claim=accept
        )
        self.assertEqual(len(result), 3)
        signatures, envelope, generation = result
        self.assertIsInstance(signatures, tuple)
        self.assertEqual(len(signatures), 3)
        for signature in signatures:
            self.assertIsInstance(signature, pqattest.MerkleSignature)
        self.assertIsInstance(envelope, bytes)
        self.assertEqual(generation, 12)
        self.assertIs(type(generation), int)
        self.assertIsNot(type(generation), bool)

    def test_signatures_match_plain_sign_batch_from_same_state(self):
        reference = make_signer()
        signatures, _, generation = sign_merkle_auth_state_batch(
            self.envelope, MESSAGES, key=KEY, claim=accept
        )
        self.assertEqual(signatures, reference.sign_batch(MESSAGES))
        self.assertEqual(tuple(signature.index for signature in signatures), (0, 1, 2))
        self.assertEqual(generation, 12)
        for message, signature in zip(MESSAGES, signatures):
            self.assertTrue(merkle_verify(message, signature, self.signer.public_key))

    def test_signs_consecutive_leaves_of_restored_state(self):
        signer = make_signer()
        signer.sign(b"a")
        signer.sign(b"b")
        envelope = wrap_merkle(signer, generation=5)
        reference = make_signer()
        reference.sign(b"a")
        reference.sign(b"b")
        messages = (b"c", b"d")
        signatures, _, generation = sign_merkle_auth_state_batch(
            envelope, messages, key=KEY, claim=accept
        )
        self.assertEqual(signatures, reference.sign_batch(messages))
        self.assertEqual(tuple(signature.index for signature in signatures), (2, 3))
        self.assertEqual(generation, 6)

    def test_envelope_matches_explicit_wrap_at_g_plus_one(self):
        reference = make_signer()
        _, envelope, generation = sign_merkle_auth_state_batch(
            self.envelope, MESSAGES, key=KEY, claim=accept
        )
        reference.sign_batch(MESSAGES)
        expected = auth_state_wrap(
            reference.checkpoint(),
            scheme="merkle",
            key=KEY,
            generation=12,
        )
        self.assertEqual(generation, 12)
        self.assertEqual(envelope, expected)

    def test_envelope_advances_exactly_one_generation_regardless_of_batch_size(self):
        for size in (1, 2, 3, 4):
            with self.subTest(size=size):
                signer = make_signer()
                envelope = wrap_merkle(signer, generation=41)
                messages = tuple(f"m{i}".encode() for i in range(size))
                signatures, next_envelope, generation = (
                    sign_merkle_auth_state_batch(
                        envelope, messages, key=KEY, claim=accept
                    )
                )
                self.assertEqual(generation, 42)
                self.assertEqual(len(signatures), size)
                _, wrapped_generation, checkpoint = auth_state_unwrap(
                    next_envelope, key=KEY, expect="merkle"
                )
                self.assertEqual(wrapped_generation, 42)
                restored = MerkleSigner.from_checkpoint(checkpoint)
                self.assertEqual(restored.next_index, size)

    def test_returned_envelope_unwraps_to_advanced_state(self):
        signatures, envelope, generation = (
            sign_merkle_auth_state_batch(
                self.envelope, MESSAGES, key=KEY, claim=accept
            )
        )
        scheme, wrapped_generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(scheme, "merkle")
        self.assertEqual(wrapped_generation, generation)
        self.assertEqual(generation, 12)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, self.signer.public_key)
        self.assertEqual(restored.next_index, signatures[-1].index + 1)
        self.assertEqual(restored.next_index, 3)

    def test_accepts_str_bytearray_members_and_bytearray_inputs(self):
        messages = ("m0", bytearray(b"m1"), b"m2")
        signatures, envelope, generation = sign_merkle_auth_state_batch(
            bytearray(self.envelope),
            messages,
            key=bytearray(KEY),
            claim=accept,
        )
        reference = make_signer()
        self.assertEqual(signatures, reference.sign_batch(("m0", b"m1", b"m2")))
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
        _, _, generation = sign_merkle_auth_state_batch(
            low, MESSAGES, key=KEY, claim=accept
        )
        self.assertEqual(generation, 1)
        ceiling = wrap_merkle(self.signer, generation=UINT64_MAX - 1)
        _, envelope, generation = sign_merkle_auth_state_batch(
            ceiling, (b"m",), key=KEY, claim=accept
        )
        self.assertEqual(generation, UINT64_MAX)
        _, wrapped_generation, _ = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(wrapped_generation, UINT64_MAX)

    def test_stateless_chaining_through_envelopes(self):
        signer = make_signer(height=2)
        envelope = wrap_merkle(signer, generation=0)
        signatures, envelope, generation = sign_merkle_auth_state_batch(
            envelope, (b"a", b"b"), key=KEY, claim=accept
        )
        self.assertEqual(tuple(s.index for s in signatures), (0, 1))
        self.assertEqual(generation, 1)
        signatures, envelope, generation = sign_merkle_auth_state_batch(
            envelope, (b"c", b"d"), key=KEY, claim=accept
        )
        self.assertEqual(tuple(s.index for s in signatures), (2, 3))
        self.assertEqual(generation, 2)
        _, _, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)

    def test_stateless_same_inputs_replay_identically(self):
        first = sign_merkle_auth_state_batch(
            self.envelope, MESSAGES, key=KEY, claim=accept
        )
        second = sign_merkle_auth_state_batch(
            self.envelope, MESSAGES, key=KEY, claim=accept
        )
        self.assertEqual(first, second)
        self.assertEqual(tuple(s.index for s in first[0]), (0, 1, 2))

    def test_does_not_mutate_state_behind_input_envelope(self):
        signer = make_signer()
        envelope = wrap_merkle(signer, generation=3)
        self.assertEqual(signer.next_index, 0)
        sign_merkle_auth_state_batch(
            envelope, MESSAGES, key=KEY, claim=accept
        )
        self.assertEqual(signer.next_index, 0)

    def test_batch_exactly_filling_remaining_leaves_succeeds(self):
        signer = make_signer(height=1)
        signer.sign(b"a")
        envelope = wrap_merkle(signer, generation=3)
        signatures, _, generation = sign_merkle_auth_state_batch(
            envelope, (b"b",), key=KEY, claim=accept
        )
        self.assertEqual(signatures[0].index, 1)
        self.assertEqual(generation, 4)

    def test_floor_equal_and_below_pass(self):
        envelope = wrap_merkle(self.signer, generation=7)
        sign_merkle_auth_state_batch(
            envelope, MESSAGES, key=KEY, min_generation=7, claim=accept
        )
        sign_merkle_auth_state_batch(
            envelope, MESSAGES, key=KEY, min_generation=6, claim=accept
        )

    def test_floor_above_generation_fails_without_claim(self):
        claim = RecordingClaim()
        envelope = wrap_merkle(self.signer, generation=7)
        with self.assertRaises(ValueError):
            sign_merkle_auth_state_batch(
                envelope, MESSAGES, key=KEY, min_generation=8, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_insufficient_capacity_raises_key_exhausted_without_claim(self):
        signer = make_signer(height=1)
        signer.sign(b"a")
        envelope = wrap_merkle(signer, generation=3)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            sign_merkle_auth_state_batch(
                envelope, (b"b", b"c"), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_exhausted_restored_signer_raises_key_exhausted_without_claim(self):
        signer = make_signer(height=1)
        signer.sign(b"a")
        signer.sign(b"b")
        envelope = wrap_merkle(signer, generation=3)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            sign_merkle_auth_state_batch(
                envelope, (b"c",), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_merkle_auth_state_batch must not draw randomness"
            )

        with mock.patch.object(
            pqattest.secrets, "token_bytes", exploding_token_bytes
        ):
            signatures, envelope, generation = sign_merkle_auth_state_batch(
                self.envelope, MESSAGES, key=KEY, claim=accept
            )
        for message, signature in zip(MESSAGES, signatures):
            self.assertTrue(merkle_verify(message, signature, self.signer.public_key))
        self.assertEqual(generation, 12)
        self.assertIsInstance(envelope, bytes)


class SignMerkleAuthStateBatchClaimTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.envelope = wrap_merkle(self.signer, generation=7)

    def test_claim_receives_exact_paired_token(self):
        claim = RecordingClaim()
        sign_merkle_auth_state_batch(
            self.envelope, MESSAGES, key=KEY, claim=claim
        )
        self.assertEqual(claim.calls, [(("merkle", 7), ("merkle", 8))])

    def test_claim_called_exactly_once(self):
        claim = RecordingClaim()
        sign_merkle_auth_state_batch(
            self.envelope, MESSAGES, key=KEY, claim=claim
        )
        self.assertEqual(len(claim.calls), 1)

    def test_claim_token_is_a_pair_of_plain_tuples(self):
        seen = []
        sign_merkle_auth_state_batch(
            self.envelope,
            MESSAGES,
            key=KEY,
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
            sign_merkle_auth_state_batch(
                self.envelope, MESSAGES, key=KEY, claim=claim
            )
        self.assertEqual(len(claim.calls), 1)

    def test_truthy_non_true_rejected(self):
        for result in (1, "True", b"True", object()):
            with self.subTest(result=repr(result)):
                claim = RecordingClaim(result=result)
                with self.assertRaises(ValueError):
                    sign_merkle_auth_state_batch(
                        self.envelope, MESSAGES, key=KEY, claim=claim
                    )
                self.assertEqual(len(claim.calls), 1)

    def test_claim_exception_propagates_untouched(self):
        class Boom(Exception):
            pass

        def boom(token):
            raise Boom

        with self.assertRaises(Boom):
            sign_merkle_auth_state_batch(
                self.envelope, MESSAGES, key=KEY, claim=boom
            )

    def test_claim_not_called_on_wrong_key(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_merkle_auth_state_batch(
                self.envelope, MESSAGES, key=OTHER_KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_tamper(self):
        claim = RecordingClaim()
        forged = bytearray(self.envelope)
        forged[30] ^= 0x01
        with self.assertRaises(ValueError):
            sign_merkle_auth_state_batch(
                bytes(forged), MESSAGES, key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_v1_envelope(self):
        claim = RecordingClaim()
        v1 = auth_wrap(self.signer.checkpoint(), scheme="merkle", key=KEY)
        with self.assertRaises(ValueError):
            sign_merkle_auth_state_batch(
                v1, MESSAGES, key=KEY, claim=claim
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
                    sign_merkle_auth_state_batch(
                        envelope, MESSAGES, key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_garbage(self):
        claim = RecordingClaim()
        for bad in (b"", b"\x00", b"PQAAUTH\0", b"\x00" * 54,
                    self.envelope[:-1], self.envelope + b"\x00"):
            with self.subTest(length=len(bad)):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    sign_merkle_auth_state_batch(
                        bad, MESSAGES, key=KEY, claim=claim
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
            sign_merkle_auth_state_batch(
                blob, MESSAGES, key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_at_generation_ceiling(self):
        envelope = wrap_merkle(self.signer, generation=UINT64_MAX)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_merkle_auth_state_batch(
                envelope, MESSAGES, key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_exhaustion(self):
        signer = make_signer(height=1)
        signer.sign(b"a")
        signer.sign(b"b")
        envelope = wrap_merkle(signer, generation=9)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            sign_merkle_auth_state_batch(
                envelope, MESSAGES, key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_empty_batch(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_merkle_auth_state_batch(
                self.envelope, (), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_bad_message_member(self):
        claim = RecordingClaim()
        for bad in (123, object(), [b"m"], None, 4.5):
            with self.subTest(bad=type(bad).__name__):
                claim.calls.clear()
                with self.assertRaises(TypeError):
                    sign_merkle_auth_state_batch(
                        self.envelope, (b"ok", bad), key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])


class SignMerkleAuthStateBatchTypesTest(unittest.TestCase):
    def setUp(self):
        self.envelope = wrap_merkle(make_signer(), generation=1)

    def test_keyword_only_arguments(self):
        with self.assertRaises(TypeError):
            sign_merkle_auth_state_batch(self.envelope, MESSAGES, KEY, None, accept)
        with self.assertRaises(TypeError):
            sign_merkle_auth_state_batch(self.envelope, MESSAGES, KEY, claim=accept)

    def test_claim_is_required(self):
        with self.assertRaises(TypeError):
            sign_merkle_auth_state_batch(self.envelope, MESSAGES, key=KEY)

    def test_non_bytes_data_type_error(self):
        for bad in (None, 42, 4.5, "blob", [self.envelope], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_merkle_auth_state_batch(
                        bad, MESSAGES, key=KEY, claim=accept
                    )

    def test_non_bytes_key_type_error(self):
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_merkle_auth_state_batch(
                        self.envelope, MESSAGES, key=bad, claim=accept
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
                    sign_merkle_auth_state_batch(
                        self.envelope, bad, key=KEY, claim=accept
                    )

    def test_empty_messages_value_error(self):
        with self.assertRaises(ValueError):
            sign_merkle_auth_state_batch(
                self.envelope, (), key=KEY, claim=accept
            )

    def test_non_callable_claim_type_error(self):
        for bad in (None, True, 1, "claim", b"claim", (lambda: True,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_merkle_auth_state_batch(
                        self.envelope, MESSAGES, key=KEY, claim=bad
                    )

    def test_bad_min_generation_type_error(self):
        for bad in (1.5, "0", [0], (0,), object(), True, False):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    sign_merkle_auth_state_batch(
                        self.envelope, MESSAGES, key=KEY,
                        min_generation=bad, claim=accept,
                    )

    def test_empty_key_value_error(self):
        for bad in (b"", bytearray()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    sign_merkle_auth_state_batch(
                        self.envelope, MESSAGES, key=bad, claim=accept
                    )

    def test_min_generation_out_of_range_value_error(self):
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    sign_merkle_auth_state_batch(
                        self.envelope, MESSAGES, key=KEY,
                        min_generation=bad, claim=accept,
                    )

    def test_types_checked_before_envelope(self):
        with self.assertRaises(TypeError):
            sign_merkle_auth_state_batch(b"", MESSAGES, key=42, claim=accept)
        with self.assertRaises(TypeError):
            sign_merkle_auth_state_batch(object(), MESSAGES, key=KEY, claim=accept)
        with self.assertRaises(TypeError):
            sign_merkle_auth_state_batch(
                b"", MESSAGES, key=KEY, min_generation=True, claim=accept
            )
        with self.assertRaises(TypeError):
            sign_merkle_auth_state_batch(b"", MESSAGES, key=KEY, claim="claim")
        with self.assertRaises(TypeError):
            sign_merkle_auth_state_batch(b"", [b"m"], key=KEY, claim=accept)
        with self.assertRaises(TypeError):
            sign_merkle_auth_state_batch(
                b"", (123,), key=KEY, claim=accept
            )

    def test_empty_batch_rejected_even_for_exhausted_or_garbage_envelope(self):
        # The empty-batch ValueError must not depend on the envelope at all.
        with self.assertRaises(ValueError):
            sign_merkle_auth_state_batch(
                b"garbage", (), key=KEY, claim=accept
            )


if __name__ == "__main__":
    unittest.main()

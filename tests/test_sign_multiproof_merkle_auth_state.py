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
    multiproof_encode,
    multiproof_verify,
    sign_multiproof_merkle_auth_state,
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


def reference_gapped_signatures(height, w, messages, indices):
    """Sign messages at arbitrary increasing leaves via advance_to + sign."""
    signer = make_signer(height=height, w=w)
    signatures = []
    for index, message in zip(indices, messages):
        signer.advance_to(index)
        signatures.append(signer.sign(message))
    return signer, tuple(signatures)


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


class SignMultiproofMerkleAuthStateTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.envelope = wrap_merkle(self.signer, generation=11)

    def test_returns_proof_envelope_and_generation(self):
        result = sign_multiproof_merkle_auth_state(
            self.envelope, MESSAGES, key=KEY, claim=accept
        )
        self.assertEqual(len(result), 3)
        proof, envelope, generation = result
        self.assertIsInstance(proof, bytes)
        self.assertIsInstance(envelope, bytes)
        self.assertEqual(generation, 12)
        self.assertIs(type(generation), int)
        self.assertIsNot(type(generation), bool)

    def test_default_indices_means_consecutive_from_current_leaf(self):
        proof, _, generation = sign_multiproof_merkle_auth_state(
            self.envelope, MESSAGES, key=KEY, claim=accept
        )
        reference = make_signer()
        signatures = reference.sign_batch(MESSAGES)
        self.assertEqual(proof, multiproof_encode(reference.public_key, signatures))
        self.assertEqual(tuple(signature.index for signature in signatures), (0, 1, 2))
        self.assertEqual(generation, 12)
        self.assertTrue(multiproof_verify(MESSAGES, proof))

    def test_explicit_none_indices_matches_default(self):
        default = sign_multiproof_merkle_auth_state(
            self.envelope, MESSAGES, key=KEY, claim=accept
        )
        explicit_none = sign_multiproof_merkle_auth_state(
            self.envelope, MESSAGES, indices=None, key=KEY, claim=accept
        )
        self.assertEqual(default, explicit_none)

    def test_default_indices_from_advanced_state(self):
        signer = make_signer(height=3)
        signer.sign(b"a")
        signer.sign(b"b")
        envelope = wrap_merkle(signer, generation=5)
        messages = (b"c", b"d")
        proof, _, generation = sign_multiproof_merkle_auth_state(
            envelope, messages, key=KEY, claim=accept
        )
        reference = make_signer(height=3)
        reference.sign(b"a")
        reference.sign(b"b")
        signatures = reference.sign_batch(messages)
        self.assertEqual(proof, multiproof_encode(reference.public_key, signatures))
        self.assertEqual(tuple(signature.index for signature in signatures), (2, 3))
        self.assertEqual(generation, 6)
        self.assertTrue(multiproof_verify(messages, proof))

    def test_explicit_indices_select_named_leaves(self):
        messages = (b"a", b"c", b"e")
        proof, _, generation = sign_multiproof_merkle_auth_state(
            self.envelope, messages, indices=(0, 2, 3), key=KEY, claim=accept
        )
        reference, signatures = reference_gapped_signatures(
            2, 4, messages, (0, 2, 3)
        )
        self.assertEqual(tuple(s.index for s in signatures), (0, 2, 3))
        self.assertEqual(proof, multiproof_encode(reference.public_key, signatures))
        self.assertEqual(generation, 12)
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertFalse(multiproof_verify((b"a", b"c", b"other"), proof))

    def test_explicit_indices_starting_above_current_voids_gap(self):
        messages = (b"m5", b"m7")
        proof, envelope, generation = sign_multiproof_merkle_auth_state(
            self.envelope, messages, indices=(1, 3), key=KEY, claim=accept
        )
        reference, signatures = reference_gapped_signatures(
            2, 4, messages, (1, 3)
        )
        self.assertEqual(proof, multiproof_encode(reference.public_key, signatures))
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertEqual(generation, 12)
        # Leaves 0 and 2 are voided: next_index is the last selected leaf + 1.
        expected = auth_state_wrap(
            reference.checkpoint(), scheme="merkle", key=KEY, generation=12
        )
        self.assertEqual(envelope, expected)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY, expect="merkle")
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)

    def test_internal_gap_is_voided(self):
        signer = make_signer(height=3)
        envelope = wrap_merkle(signer, generation=0)
        messages = (b"m1", b"m3", b"m6")
        _, envelope, generation = sign_multiproof_merkle_auth_state(
            envelope, messages, indices=(1, 3, 6), key=KEY, claim=accept
        )
        self.assertEqual(generation, 1)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY, expect="merkle")
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 7)
        self.assertEqual(restored.remaining, 1)
        # The skipped leaves 0, 2, 4 and 5 can never be signed again: the
        # next selectable leaf is only leaf 7.
        proof, envelope, _ = sign_multiproof_merkle_auth_state(
            envelope, (b"m7",), indices=(7,), key=KEY, claim=accept
        )
        self.assertTrue(multiproof_verify((b"m7",), proof))
        for skipped in (0, 2, 4, 5, 6):
            with self.subTest(skipped=skipped):
                with self.assertRaises(ValueError):
                    sign_multiproof_merkle_auth_state(
                        envelope, (b"late",), indices=(skipped,),
                        key=KEY, claim=accept,
                    )

    def test_envelope_matches_explicit_wrap_at_last_index_plus_one(self):
        messages = (b"a", b"d")
        _, envelope, generation = sign_multiproof_merkle_auth_state(
            self.envelope, messages, indices=(0, 3), key=KEY, claim=accept
        )
        reference, _ = reference_gapped_signatures(2, 4, messages, (0, 3))
        expected = auth_state_wrap(
            reference.checkpoint(), scheme="merkle", key=KEY, generation=12
        )
        self.assertEqual(generation, 12)
        self.assertEqual(envelope, expected)

    def test_returned_envelope_unwraps_to_post_signing_state(self):
        messages = (b"one", b"three")
        proof, envelope, generation = sign_multiproof_merkle_auth_state(
            self.envelope, messages, indices=(0, 2), key=KEY, claim=accept
        )
        scheme, wrapped_generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(scheme, "merkle")
        self.assertEqual(wrapped_generation, generation)
        self.assertEqual(generation, 12)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, self.signer.public_key)
        self.assertEqual(restored.next_index, 3)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 3)
        self.assertTrue(multiproof_verify(messages, proof))

    def test_single_selection_at_current_leaf(self):
        proof, envelope, generation = sign_multiproof_merkle_auth_state(
            self.envelope, (b"only",), indices=(0,), key=KEY, claim=accept
        )
        reference, signatures = reference_gapped_signatures(
            2, 4, (b"only",), (0,)
        )
        self.assertEqual(proof, multiproof_encode(reference.public_key, signatures))
        self.assertTrue(multiproof_verify((b"only",), proof))
        self.assertEqual(generation, 12)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(MerkleSigner.from_checkpoint(checkpoint).next_index, 1)

    def test_last_leaf_selection_succeeds_and_exhausts(self):
        signer = make_signer(height=2)  # 4 leaves
        proof, envelope, generation = sign_multiproof_merkle_auth_state(
            wrap_merkle(signer, generation=0), (b"last",), indices=(3,),
            key=KEY, claim=accept,
        )
        self.assertTrue(multiproof_verify((b"last",), proof))
        self.assertEqual(generation, 1)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)

    def test_last_leaf_from_already_advanced_state(self):
        signer = make_signer(height=2)
        signer.advance_to(3)
        envelope = wrap_merkle(signer, generation=4)
        proof, envelope, generation = sign_multiproof_merkle_auth_state(
            envelope, (b"last",), indices=(3,), key=KEY, claim=accept
        )
        self.assertTrue(multiproof_verify((b"last",), proof))
        self.assertEqual(generation, 5)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(MerkleSigner.from_checkpoint(checkpoint).remaining, 0)

    def test_accepts_str_bytearray_members_and_bytearray_inputs(self):
        messages = ("m0", bytearray(b"m2"), b"m3")
        proof, envelope, generation = sign_multiproof_merkle_auth_state(
            bytearray(self.envelope), messages, indices=(0, 2, 3),
            key=bytearray(KEY), claim=accept,
        )
        reference, signatures = reference_gapped_signatures(
            2, 4, ("m0", b"m2", b"m3"), (0, 2, 3)
        )
        self.assertEqual(proof, multiproof_encode(reference.public_key, signatures))
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertEqual(generation, 12)
        self.assertEqual(
            envelope,
            auth_state_wrap(
                reference.checkpoint(), scheme="merkle", key=KEY, generation=12
            ),
        )

    def test_generation_endpoints(self):
        low = wrap_merkle(self.signer, generation=0)
        _, _, generation = sign_multiproof_merkle_auth_state(
            low, (b"m",), indices=(0,), key=KEY, claim=accept
        )
        self.assertEqual(generation, 1)
        ceiling = wrap_merkle(self.signer, generation=UINT64_MAX - 1)
        _, envelope, generation = sign_multiproof_merkle_auth_state(
            ceiling, (b"m",), indices=(0,), key=KEY, claim=accept
        )
        self.assertEqual(generation, UINT64_MAX)
        _, wrapped_generation, _ = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(wrapped_generation, UINT64_MAX)

    def test_stateless_chaining_through_envelopes(self):
        signer = make_signer(height=3)
        envelope = wrap_merkle(signer, generation=0)
        proof, envelope, generation = sign_multiproof_merkle_auth_state(
            envelope, (b"m1", b"m3"), indices=(1, 3), key=KEY, claim=accept
        )
        self.assertTrue(multiproof_verify((b"m1", b"m3"), proof))
        self.assertEqual(generation, 1)
        proof, envelope, generation = sign_multiproof_merkle_auth_state(
            envelope, (b"m6", b"m7"), indices=(6, 7), key=KEY, claim=accept
        )
        self.assertTrue(multiproof_verify((b"m6", b"m7"), proof))
        self.assertEqual(generation, 2)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY, expect="merkle")
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 8)
        self.assertEqual(restored.remaining, 0)

    def test_stateless_same_envelope_replays_identically(self):
        first = sign_multiproof_merkle_auth_state(
            self.envelope, (b"m", b"n"), indices=(1, 2), key=KEY, claim=accept
        )
        second = sign_multiproof_merkle_auth_state(
            self.envelope, (b"m", b"n"), indices=(1, 2), key=KEY, claim=accept
        )
        self.assertEqual(first, second)

    def test_does_not_mutate_state_behind_input_envelope(self):
        signer = make_signer()
        envelope = wrap_merkle(signer, generation=3)
        self.assertEqual(signer.next_index, 0)
        sign_multiproof_merkle_auth_state(
            envelope, (b"m",), indices=(3,), key=KEY, claim=accept
        )
        self.assertEqual(signer.next_index, 0)

    def test_floor_equal_and_below_pass(self):
        envelope = wrap_merkle(self.signer, generation=7)
        sign_multiproof_merkle_auth_state(
            envelope, (b"m",), indices=(0,), key=KEY,
            min_generation=7, claim=accept,
        )
        sign_multiproof_merkle_auth_state(
            envelope, (b"m",), indices=(0,), key=KEY,
            min_generation=6, claim=accept,
        )

    def test_floor_above_generation_fails_without_claim(self):
        claim = RecordingClaim()
        envelope = wrap_merkle(self.signer, generation=7)
        with self.assertRaises(ValueError):
            sign_multiproof_merkle_auth_state(
                envelope, (b"m",), indices=(0,), key=KEY,
                min_generation=8, claim=claim,
            )
        self.assertEqual(claim.calls, [])

    def test_default_indices_capacity_shortfall_is_key_exhausted(self):
        signer = make_signer(height=2)
        signer.advance_to(3)
        envelope = wrap_merkle(signer, generation=0)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            sign_multiproof_merkle_auth_state(
                envelope, (b"a", b"b"), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_explicit_last_leaf_still_works_where_default_would_exhaust(self):
        signer = make_signer(height=2)
        signer.advance_to(3)
        envelope = wrap_merkle(signer, generation=0)
        proof, _, generation = sign_multiproof_merkle_auth_state(
            envelope, (b"a",), indices=(3,), key=KEY, claim=accept
        )
        self.assertTrue(multiproof_verify((b"a",), proof))
        self.assertEqual(generation, 1)

    def test_draws_no_randomness(self):
        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_multiproof_merkle_auth_state must not draw randomness"
            )

        with mock.patch.object(
            pqattest.secrets, "token_bytes", exploding_token_bytes
        ):
            result = sign_multiproof_merkle_auth_state(
                self.envelope, (b"m", b"n"), indices=(2, 3), key=KEY, claim=accept
            )
        proof, envelope, generation = result
        self.assertTrue(multiproof_verify((b"m", b"n"), proof))
        self.assertEqual(generation, 12)
        _, _, checkpoint = auth_state_unwrap(envelope, key=KEY)
        self.assertEqual(int.from_bytes(checkpoint[11:13], "big"), 4)


class SignMultiproofMerkleAuthStateIndicesTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.envelope = wrap_merkle(self.signer, generation=7)

    def _fails(self, exc, messages, indices):
        claim = RecordingClaim()
        with self.assertRaises(exc):
            sign_multiproof_merkle_auth_state(
                self.envelope, messages, indices=indices, key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_non_tuple_indices_type_error(self):
        for bad in ([0], {0}, b"\x00", "0", 0, iter((0,))):
            with self.subTest(bad=type(bad).__name__):
                self._fails(TypeError, (b"m",), bad)

    def test_non_integer_or_boolean_index_type_error(self):
        for bad in (True, False, 1.0, "1", None, [1], (1,)):
            with self.subTest(bad=repr(bad)):
                self._fails(TypeError, (b"m",), (bad,))
        self._fails(TypeError, (b"a", b"b"), (0, True))
        self._fails(TypeError, (b"a", b"b"), (1.0, 2))

    def test_indices_length_must_match_messages(self):
        self._fails(ValueError, (b"a",), (0, 1))
        self._fails(ValueError, (b"a", b"b"), (0,))
        self._fails(ValueError, (b"a", b"b", b"c"), (0, 1))

    def test_indices_must_be_strictly_increasing(self):
        self._fails(ValueError, (b"a", b"b"), (0, 0))
        self._fails(ValueError, (b"a", b"b"), (2, 1))
        self._fails(ValueError, (b"a", b"b", b"c"), (0, 2, 2))
        self._fails(ValueError, (b"a", b"b", b"c"), (0, 5, 4))

    def test_indices_below_current_leaf_rejected(self):
        signer = make_signer(height=3)
        signer.sign(b"a")
        signer.sign(b"b")
        envelope = wrap_merkle(signer, generation=2)
        claim = RecordingClaim()
        for bad in (0, 1):
            with self.subTest(bad=bad):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    sign_multiproof_merkle_auth_state(
                        envelope, (b"m",), indices=(bad,), key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])
        # The current leaf itself is legal.
        proof, _, _ = sign_multiproof_merkle_auth_state(
            envelope, (b"m",), indices=(2,), key=KEY, claim=accept
        )
        self.assertTrue(multiproof_verify((b"m",), proof))

    def test_indices_past_last_leaf_rejected(self):
        for bad in (4, 5, 8, 1 << 16, -1):
            with self.subTest(bad=bad):
                self._fails(ValueError, (b"m",), (bad,))

    def test_fully_exhausted_state_rejects_every_index(self):
        signer = make_signer(height=2)
        signer.advance_to(4)
        envelope = wrap_merkle(signer, generation=2)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_multiproof_merkle_auth_state(
                envelope, (b"m",), indices=(4,), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_indices_validated_before_envelope_is_opened(self):
        # A bad indices shape must raise without ever touching garbage data.
        with self.assertRaises(TypeError):
            sign_multiproof_merkle_auth_state(
                b"garbage", (b"m",), indices=[0], key=KEY, claim=accept
            )
        with self.assertRaises(ValueError):
            sign_multiproof_merkle_auth_state(
                b"garbage", (b"m",), indices=(0, 1), key=KEY, claim=accept
            )
        with self.assertRaises(ValueError):
            sign_multiproof_merkle_auth_state(
                b"garbage", (b"m", b"n"), indices=(2, 2), key=KEY, claim=accept
            )


class SignMultiproofMerkleAuthStateClaimTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.envelope = wrap_merkle(self.signer, generation=7)

    def test_claim_receives_exact_paired_token(self):
        claim = RecordingClaim()
        sign_multiproof_merkle_auth_state(
            self.envelope, (b"m", b"n"), indices=(2, 3), key=KEY, claim=claim
        )
        self.assertEqual(claim.calls, [(("merkle", 7), ("merkle", 8))])

    def test_claim_called_exactly_once_regardless_of_selection(self):
        for indices in (None, (0,), (1, 2), (0, 2, 3)):
            with self.subTest(indices=indices):
                claim = RecordingClaim()
                count = 3 if indices is None else len(indices)
                messages = tuple(f"m{i}".encode() for i in range(count))
                sign_multiproof_merkle_auth_state(
                    self.envelope, messages, indices=indices, key=KEY, claim=claim
                )
                self.assertEqual(len(claim.calls), 1)

    def test_claim_token_is_a_pair_of_plain_tuples(self):
        seen = []
        sign_multiproof_merkle_auth_state(
            self.envelope, (b"m",), indices=(3,), key=KEY,
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
            sign_multiproof_merkle_auth_state(
                self.envelope, (b"m",), indices=(3,), key=KEY, claim=claim
            )
        self.assertEqual(len(claim.calls), 1)

    def test_truthy_non_true_rejected(self):
        for result in (1, "True", b"True", object()):
            with self.subTest(result=repr(result)):
                claim = RecordingClaim(result=result)
                with self.assertRaises(ValueError):
                    sign_multiproof_merkle_auth_state(
                        self.envelope, (b"m",), indices=(3,), key=KEY, claim=claim
                    )
                self.assertEqual(len(claim.calls), 1)

    def test_claim_exception_propagates_untouched(self):
        class Boom(Exception):
            pass

        def boom(token):
            raise Boom

        with self.assertRaises(Boom):
            sign_multiproof_merkle_auth_state(
                self.envelope, (b"m",), indices=(3,), key=KEY, claim=boom
            )

    def test_claim_not_called_on_wrong_key(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_multiproof_merkle_auth_state(
                self.envelope, (b"m",), indices=(3,), key=OTHER_KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_tamper(self):
        claim = RecordingClaim()
        forged = bytearray(self.envelope)
        forged[30] ^= 0x01
        with self.assertRaises(ValueError):
            sign_multiproof_merkle_auth_state(
                bytes(forged), (b"m",), indices=(3,), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_v1_envelope(self):
        claim = RecordingClaim()
        v1 = auth_wrap(self.signer.checkpoint(), scheme="merkle", key=KEY)
        with self.assertRaises(ValueError):
            sign_multiproof_merkle_auth_state(
                v1, (b"m",), indices=(3,), key=KEY, claim=claim
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
                    sign_multiproof_merkle_auth_state(
                        envelope, (b"m",), indices=(3,), key=KEY, claim=claim
                    )
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_garbage(self):
        claim = RecordingClaim()
        for bad in (b"", b"\x00", b"PQAAUTH\0", b"\x00" * 54,
                    self.envelope[:-1], self.envelope + b"\x00"):
            with self.subTest(length=len(bad)):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    sign_multiproof_merkle_auth_state(
                        bad, (b"m",), indices=(3,), key=KEY, claim=claim
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
            sign_multiproof_merkle_auth_state(
                blob, (b"m",), indices=(3,), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_at_generation_ceiling(self):
        envelope = wrap_merkle(self.signer, generation=UINT64_MAX)
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_multiproof_merkle_auth_state(
                envelope, (b"m",), indices=(3,), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_bad_indices(self):
        claim = RecordingClaim()
        for bad in ((4,), (0, 0), (-1,)):
            with self.subTest(bad=bad):
                claim.calls.clear()
                with self.assertRaises(ValueError):
                    sign_multiproof_merkle_auth_state(
                        self.envelope, (b"m",) * len(bad), indices=bad,
                        key=KEY, claim=claim,
                    )
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_empty_batch(self):
        claim = RecordingClaim()
        with self.assertRaises(ValueError):
            sign_multiproof_merkle_auth_state(
                self.envelope, (), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])
        with self.assertRaises(ValueError):
            sign_multiproof_merkle_auth_state(
                self.envelope, (), indices=(), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_bad_message_member(self):
        claim = RecordingClaim()
        for bad in (123, object(), [b"m"], None, 4.5):
            with self.subTest(bad=type(bad).__name__):
                claim.calls.clear()
                with self.assertRaises(TypeError):
                    sign_multiproof_merkle_auth_state(
                        self.envelope, (b"ok", bad), indices=(0, 1),
                        key=KEY, claim=claim,
                    )
                self.assertEqual(claim.calls, [])

    def test_claim_not_called_on_insufficient_capacity(self):
        signer = make_signer(height=1)
        signer.sign(b"a")
        envelope = wrap_merkle(signer, generation=9)
        claim = RecordingClaim()
        with self.assertRaises(KeyExhaustedError):
            sign_multiproof_merkle_auth_state(
                envelope, (b"b", b"c"), key=KEY, claim=claim
            )
        self.assertEqual(claim.calls, [])


class SignMultiproofMerkleAuthStateTypesTest(unittest.TestCase):
    def setUp(self):
        self.envelope = wrap_merkle(make_signer(), generation=1)

    def test_keyword_only_arguments(self):
        with self.assertRaises(TypeError):
            sign_multiproof_merkle_auth_state(
                self.envelope, (b"m",), None, KEY, None, accept
            )
        with self.assertRaises(TypeError):
            sign_multiproof_merkle_auth_state(
                self.envelope, (b"m",), KEY, claim=accept
            )

    def test_claim_is_required(self):
        with self.assertRaises(TypeError):
            sign_multiproof_merkle_auth_state(
                self.envelope, (b"m",), key=KEY
            )

    def test_non_bytes_data_type_error(self):
        for bad in (None, 42, 4.5, "blob", [self.envelope], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_multiproof_merkle_auth_state(
                        bad, (b"m",), key=KEY, claim=accept
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
                    sign_multiproof_merkle_auth_state(
                        self.envelope, bad, key=KEY, claim=accept
                    )

    def test_non_bytes_key_type_error(self):
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_multiproof_merkle_auth_state(
                        self.envelope, (b"m",), key=bad, claim=accept
                    )

    def test_non_callable_claim_type_error(self):
        for bad in (None, True, 1, "claim", b"claim", (lambda: True,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_multiproof_merkle_auth_state(
                        self.envelope, (b"m",), key=KEY, claim=bad
                    )

    def test_bad_min_generation_type_error(self):
        for bad in (1.5, "0", [0], (0,), object(), True, False):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    sign_multiproof_merkle_auth_state(
                        self.envelope, (b"m",), key=KEY,
                        min_generation=bad, claim=accept,
                    )

    def test_empty_key_value_error(self):
        for bad in (b"", bytearray()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    sign_multiproof_merkle_auth_state(
                        self.envelope, (b"m",), key=bad, claim=accept
                    )

    def test_empty_messages_value_error(self):
        with self.assertRaises(ValueError):
            sign_multiproof_merkle_auth_state(
                self.envelope, (), key=KEY, claim=accept
            )

    def test_min_generation_out_of_range_value_error(self):
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    sign_multiproof_merkle_auth_state(
                        self.envelope, (b"m",), key=KEY,
                        min_generation=bad, claim=accept,
                    )

    def test_types_checked_before_envelope(self):
        with self.assertRaises(TypeError):
            sign_multiproof_merkle_auth_state(
                b"", (b"m",), key=42, claim=accept
            )
        with self.assertRaises(TypeError):
            sign_multiproof_merkle_auth_state(
                object(), (b"m",), key=KEY, claim=accept
            )
        with self.assertRaises(TypeError):
            sign_multiproof_merkle_auth_state(
                b"", (b"m",), key=KEY, min_generation=True, claim=accept
            )
        with self.assertRaises(TypeError):
            sign_multiproof_merkle_auth_state(
                b"", (b"m",), key=KEY, claim="claim"
            )
        with self.assertRaises(TypeError):
            sign_multiproof_merkle_auth_state(
                b"", [b"m"], key=KEY, claim=accept
            )
        with self.assertRaises(TypeError):
            sign_multiproof_merkle_auth_state(
                b"", (123,), key=KEY, claim=accept
            )
        with self.assertRaises(TypeError):
            sign_multiproof_merkle_auth_state(
                b"", (b"m",), indices=[0], key=KEY, claim=accept
            )
        with self.assertRaises(TypeError):
            sign_multiproof_merkle_auth_state(
                b"", (b"m",), indices=(False,), key=KEY, claim=accept
            )


if __name__ == "__main__":
    unittest.main()

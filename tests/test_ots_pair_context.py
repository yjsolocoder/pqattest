"""Optional context binding for the paired Lamport/W-OTS OtsPairProof.

Covers ``OtsPairProof.verify`` / ``verify_bound`` and every paired
generation entry: ``sign_ots_pair``, ``sign_ots_pair_with_checkpoint``,
``sign_ots_pair_proof_with_checkpoint``,
``sign_ots_pair_proof_with_auth_state`` and the stateless
``sign_ots_pair_proof_auth_state``. The single context binds both halves
(each under its own scheme domain), so the whole pair verifies or fails
together.
"""

import unittest

from pqattest import (
    KeyExhaustedError,
    LamportProof,
    OneTimeSigner,
    OtsPairProof,
    WOTSOneTimeSigner,
    WOTSProof,
    auth_state_wrap,
    keygen,
    sign_ots_pair,
    sign_ots_pair_proof_auth_state,
    sign_ots_pair_proof_with_auth_state,
    sign_ots_pair_proof_with_checkpoint,
    sign_ots_pair_with_checkpoint,
    verify,
    wots_keygen,
    wots_verify,
)

MESSAGE = b"the signed message"
CONTEXT_A = b"context-a"
CONTEXT_B = "café/context-b"  # str on purpose: UTF-8 must match its bytes
CONTEXT_B_BYTES = CONTEXT_B.encode("utf-8")

BAD_CONTEXTS = (1, 1.5, ["ctx"], {"ctx": 1}, object())
KEY = b"shared-secret-key"


def counter_tokens(start=0):
    state = {"value": start}

    def token_bytes(size):
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_lamport(start=0):
    private, _ = keygen(bits=64, token_bytes=counter_tokens(start))
    return OneTimeSigner(private)


def make_wots(start=1000):
    private, _ = wots_keygen(token_bytes=counter_tokens(start))
    return WOTSOneTimeSigner(private)


def make_pair():
    return make_lamport(), make_wots()


class OtsPairVerifyTest(unittest.TestCase):
    def _proof(self, context=CONTEXT_A):
        lamport, wots = make_pair()
        pair, _ = sign_ots_pair_proof_with_checkpoint(
            lamport, wots, MESSAGE, context=context
        )
        return lamport, wots, pair

    def test_pair_verifies_only_under_the_same_context(self):
        lamport, wots, pair = self._proof()
        self.assertTrue(pair.verify(MESSAGE, context=CONTEXT_A))
        self.assertFalse(pair.verify(MESSAGE))
        self.assertFalse(pair.verify(MESSAGE, context=b"other"))
        self.assertFalse(pair.verify(b"wrong", context=CONTEXT_A))

    def test_bound_pair_requires_context_and_both_keys(self):
        lamport, wots, pair = self._proof()
        kwargs = dict(lamport_key=lamport.public_key, wots_key=wots.public_key)
        self.assertTrue(pair.verify_bound(MESSAGE, context=CONTEXT_A, **kwargs))
        self.assertFalse(pair.verify_bound(MESSAGE, **kwargs))
        self.assertFalse(
            pair.verify_bound(MESSAGE, context=b"other", **kwargs)
        )

    def test_bound_pair_wrong_either_key_fails(self):
        lamport, wots, pair = self._proof()
        other_lamport = make_lamport(start=900)
        other_wots = make_wots(start=9000)
        self.assertFalse(
            pair.verify_bound(
                MESSAGE,
                lamport_key=other_lamport.public_key,
                wots_key=wots.public_key,
                context=CONTEXT_A,
            )
        )
        self.assertFalse(
            pair.verify_bound(
                MESSAGE,
                lamport_key=lamport.public_key,
                wots_key=other_wots.public_key,
                context=CONTEXT_A,
            )
        )

    def test_bound_pair_wrong_key_type_raises(self):
        _, _, pair = self._proof()
        with self.assertRaises(TypeError):
            pair.verify_bound(
                MESSAGE,
                lamport_key=b"not a key",
                wots_key=make_wots().public_key,
                context=CONTEXT_A,
            )
        with self.assertRaises(TypeError):
            pair.verify_bound(
                MESSAGE,
                lamport_key=make_lamport().public_key,
                wots_key=b"not a key",
                context=CONTEXT_A,
            )

    def test_bad_context_type_raises(self):
        _, _, pair = self._proof()
        for bad in BAD_CONTEXTS:
            with self.assertRaises(TypeError):
                pair.verify(MESSAGE, context=bad)
            with self.assertRaises(TypeError):
                pair.verify_bound(
                    MESSAGE,
                    lamport_key=make_lamport().public_key,
                    wots_key=make_wots().public_key,
                    context=bad,
                )

    def test_serialised_pair_round_trip_with_context(self):
        _, _, pair = self._proof()
        restored = OtsPairProof.from_bytes(pair.to_bytes())
        self.assertEqual(restored, pair)
        self.assertTrue(restored.verify(MESSAGE, context=CONTEXT_A))
        self.assertFalse(restored.verify(MESSAGE))

    def test_unbound_pair_is_legacy_compatible(self):
        _, _, pair = self._proof(context=None)
        self.assertTrue(pair.verify(MESSAGE))
        self.assertTrue(pair.verify(MESSAGE, context=b""))
        self.assertFalse(pair.verify(MESSAGE, context=CONTEXT_A))


class PairGeneratorTest(unittest.TestCase):
    def test_sign_ots_pair_context_flows_to_both_halves(self):
        lamport, wots = make_pair()
        (lsig, wsig), _ = sign_ots_pair(
            lamport, wots, MESSAGE, key=KEY, generation=2, context=CONTEXT_A
        )
        self.assertTrue(verify(MESSAGE, lsig, lamport.public_key, context=CONTEXT_A))
        self.assertTrue(wots_verify(MESSAGE, wsig, wots.public_key, context=CONTEXT_A))
        self.assertFalse(verify(MESSAGE, lsig, lamport.public_key))
        self.assertFalse(wots_verify(MESSAGE, wsig, wots.public_key))

    def test_sign_ots_pair_no_context_is_byte_identical_to_plain_signs(self):
        lamport, wots = make_pair()
        (lsig, wsig), _ = sign_ots_pair(
            lamport, wots, MESSAGE, key=KEY, generation=2
        )
        # Fresh but identical-key signers via the deterministic counters.
        plain_l = make_lamport()
        plain_w = make_wots()
        self.assertEqual(lsig, plain_l.sign(MESSAGE))
        self.assertEqual(wsig, plain_w.sign(MESSAGE))

    def test_sign_ots_pair_with_checkpoint_context(self):
        lamport, wots = make_pair()
        (lsig, wsig), (cpl, cpw) = sign_ots_pair_with_checkpoint(
            lamport, wots, MESSAGE, context=CONTEXT_A
        )
        self.assertTrue(verify(MESSAGE, lsig, lamport.public_key, context=CONTEXT_A))
        self.assertTrue(wots_verify(MESSAGE, wsig, wots.public_key, context=CONTEXT_A))
        # The checkpoints carry no context: same keys, same used state.
        self.assertEqual(OneTimeSigner.from_checkpoint(cpl).used, True)
        self.assertEqual(WOTSOneTimeSigner.from_checkpoint(cpw).used, True)

    def test_proof_with_auth_state_context(self):
        lamport, wots = make_pair()
        pair, (env_l, env_w) = sign_ots_pair_proof_with_auth_state(
            lamport, wots, MESSAGE, key=KEY, generation=4, context=CONTEXT_A
        )
        self.assertTrue(pair.verify(MESSAGE, context=CONTEXT_A))
        self.assertFalse(pair.verify(MESSAGE))
        # Envelopes depend on the used checkpoint, not the context.
        lamport2, wots2 = make_pair()
        _, (env_l2, env_w2) = sign_ots_pair_proof_with_auth_state(
            lamport2, wots2, MESSAGE, key=KEY, generation=4
        )
        self.assertEqual(env_l, env_l2)
        self.assertEqual(env_w, env_w2)

    def test_bad_context_is_atomic_and_consumes_neither(self):
        for factory in (
            lambda l, w: sign_ots_pair(l, w, MESSAGE, key=KEY, generation=0, context=42),
            lambda l, w: sign_ots_pair_with_checkpoint(l, w, MESSAGE, context=42),
            lambda l, w: sign_ots_pair_proof_with_checkpoint(l, w, MESSAGE, context=42),
            lambda l, w: sign_ots_pair_proof_with_auth_state(
                l, w, MESSAGE, key=KEY, generation=0, context=42
            ),
        ):
            lamport, wots = make_pair()
            with self.assertRaises(TypeError):
                factory(lamport, wots)
            self.assertFalse(lamport.used)
            self.assertFalse(wots.used)

    def test_exhausted_with_context_still_raises(self):
        lamport, wots = make_pair()
        lamport.sign(b"x")
        with self.assertRaises(KeyExhaustedError):
            sign_ots_pair_with_checkpoint(lamport, wots, MESSAGE, context=CONTEXT_A)
        self.assertFalse(wots.used)


class StatelessPairAuthStateTest(unittest.TestCase):
    def _envelopes(self, generation=7):
        lamport = make_lamport()
        wots = make_wots()
        env_l = auth_state_wrap(
            lamport.checkpoint(), scheme="lamport", key=KEY, generation=generation
        )
        env_w = auth_state_wrap(
            wots.checkpoint(), scheme="wots", key=KEY, generation=generation
        )
        return lamport, wots, env_l, env_w

    def test_context_flows_through_stateless_pair(self):
        lamport, wots, env_l, env_w = self._envelopes()
        pair, _envelopes, generation = sign_ots_pair_proof_auth_state(
            env_l,
            env_w,
            MESSAGE,
            key=KEY,
            claim=lambda token: True,
            context=CONTEXT_A,
        )
        self.assertEqual(generation, 8)
        self.assertTrue(pair.verify(MESSAGE, context=CONTEXT_A))
        self.assertFalse(pair.verify(MESSAGE))
        self.assertTrue(
            pair.verify_bound(
                MESSAGE,
                lamport_key=lamport.public_key,
                wots_key=wots.public_key,
                context=CONTEXT_A,
            )
        )

    def test_bad_context_type_raises_and_claim_not_called(self):
        _, _, env_l, env_w = self._envelopes()

        def claim(token):
            raise AssertionError("claim must not run on validation failure")

        for bad in BAD_CONTEXTS:
            with self.assertRaises(TypeError):
                sign_ots_pair_proof_auth_state(
                    env_l,
                    env_w,
                    MESSAGE,
                    key=KEY,
                    claim=claim,
                    context=bad,
                )

    def test_no_context_pair_matches_plain_pair(self):
        lamport, wots, env_l, env_w = self._envelopes(generation=0)
        pair, _envelopes, generation = sign_ots_pair_proof_auth_state(
            env_l, env_w, MESSAGE, key=KEY, claim=lambda token: True
        )
        self.assertEqual(generation, 1)
        # A directly-built unbound pair over the same deterministic keys matches.
        plain_l = make_lamport()
        plain_w = make_wots()
        plain, _ = sign_ots_pair_proof_with_checkpoint(plain_l, plain_w, MESSAGE)
        self.assertEqual(pair, plain)


if __name__ == "__main__":
    unittest.main()

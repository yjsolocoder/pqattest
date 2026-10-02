"""Optional context binding for the standalone Lamport one-time signature.

Covers ``sign`` / ``verify``, ``OneTimeSigner.sign`` /
``sign_with_checkpoint`` / ``sign_with_auth_state``,
``LamportProof.verify`` / ``verify_bound`` and the stateless
``sign_lamport_auth_state``.
"""

import unittest

from pqattest import (
    KeyExhaustedError,
    LamportProof,
    OneTimeSigner,
    PrivateKey,
    PublicKey,
    auth_state_wrap,
    keygen,
    sign,
    sign_lamport_auth_state,
    verify,
)

MESSAGE = b"the signed message"
CONTEXT_A = b"context-a"
CONTEXT_B = "café/context-b"  # str on purpose: UTF-8 must match its bytes
CONTEXT_B_BYTES = CONTEXT_B.encode("utf-8")

BAD_CONTEXTS = (1, 1.5, ["ctx"], {"ctx": 1}, object())


def counter_tokens(start=0):
    state = {"value": start}

    def token_bytes(size):
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def fresh_bits(bits=64, start=0):
    private, public = keygen(bits=bits, token_bytes=counter_tokens(start))
    return private, public


class NormalisationTest(unittest.TestCase):
    def test_none_and_empty_are_legacy_identical(self):
        private, public = fresh_bits()
        baseline = sign(MESSAGE, private)
        for context in (None, b"", bytearray(b""), ""):
            with self.subTest(context=repr(context)):
                key, pub = fresh_bits()
                got = (
                    sign(MESSAGE, key)
                    if context is None
                    else sign(MESSAGE, key, context=context)
                )
                self.assertEqual(got, baseline)
                self.assertTrue(
                    verify(MESSAGE, baseline, pub, context=context)
                )

    def test_context_changes_the_signature_but_not_the_shape(self):
        private, public = fresh_bits()
        bound = sign(MESSAGE, private, context=CONTEXT_A)
        unbound = sign(MESSAGE, fresh_bits()[0])
        self.assertEqual(len(bound), len(unbound))
        self.assertNotEqual(bound, unbound)

    def test_str_context_uses_utf8_and_is_deterministic(self):
        first = sign(MESSAGE, fresh_bits()[0], context=CONTEXT_B)
        second = sign(MESSAGE, fresh_bits()[0], context=CONTEXT_B_BYTES)
        third = sign(MESSAGE, fresh_bits()[0], context=CONTEXT_B)
        self.assertEqual(first, second)
        self.assertEqual(first, third)

    def test_bytearray_context_accepted(self):
        private, public = fresh_bits()
        signature = sign(MESSAGE, private, context=bytearray(CONTEXT_A))
        self.assertTrue(verify(MESSAGE, signature, public, context=CONTEXT_A))


class StatelessSignVerifyTest(unittest.TestCase):
    def test_matching_context_verifies(self):
        private, public = fresh_bits()
        signature = sign(MESSAGE, private, context=CONTEXT_A)
        self.assertTrue(verify(MESSAGE, signature, public, context=CONTEXT_A))

    def test_wrong_context_or_message_fails(self):
        private, public = fresh_bits()
        signature = sign(MESSAGE, private, context=CONTEXT_A)
        self.assertFalse(verify(MESSAGE, signature, public))
        self.assertFalse(
            verify(MESSAGE, signature, public, context=CONTEXT_B_BYTES)
        )
        self.assertFalse(
            verify(b"wrong message", signature, public, context=CONTEXT_A)
        )

    def test_empty_and_non_empty_contexts_are_separated(self):
        private, public = fresh_bits()
        with_context = sign(MESSAGE, private, context=CONTEXT_A)
        key2, _ = fresh_bits()
        without_context = sign(MESSAGE, key2)
        self.assertNotEqual(with_context, without_context)

    def test_context_is_keyword_only(self):
        private, _ = fresh_bits()
        with self.assertRaises(TypeError):
            sign(MESSAGE, private, CONTEXT_A)  # positional context forbidden

    def test_bad_context_type_signing_raises(self):
        private, _ = fresh_bits()
        for bad in BAD_CONTEXTS:
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign(MESSAGE, private, context=bad)

    def test_bad_context_type_verifying_raises(self):
        private, public = fresh_bits()
        signature = sign(MESSAGE, private, context=CONTEXT_A)
        for bad in BAD_CONTEXTS:
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    verify(MESSAGE, signature, public, context=bad)

    def test_wrong_public_key_type_still_raises(self):
        private, _ = fresh_bits()
        signature = sign(MESSAGE, private, context=CONTEXT_A)
        with self.assertRaises(TypeError):
            verify(MESSAGE, signature, PrivateKey(()), context=CONTEXT_A)


class OneTimeSignerTest(unittest.TestCase):
    def _signer(self):
        return OneTimeSigner(fresh_bits()[0])

    def test_sign_with_context_round_trip(self):
        signer = self._signer()
        signature = signer.sign(MESSAGE, context=CONTEXT_A)
        self.assertTrue(
            verify(MESSAGE, signature, signer.public_key, context=CONTEXT_A)
        )
        self.assertFalse(verify(MESSAGE, signature, signer.public_key))

    def test_no_context_output_matches_stateless(self):
        signer = self._signer()
        signature = signer.sign(MESSAGE)
        self.assertEqual(signature, sign(MESSAGE, signer._private_key))

    def test_bad_context_does_not_consume(self):
        signer = self._signer()
        for bad in BAD_CONTEXTS:
            with self.assertRaises(TypeError):
                signer.sign(MESSAGE, context=bad)
        self.assertFalse(signer.used)
        # The key still signs exactly once, normally.
        signer.sign(MESSAGE)
        self.assertTrue(signer.used)
        with self.assertRaises(KeyExhaustedError):
            signer.sign(MESSAGE, context=CONTEXT_A)

    def test_bad_message_does_not_consume_with_context(self):
        signer = self._signer()
        with self.assertRaises(TypeError):
            signer.sign(42, context=CONTEXT_A)
        self.assertFalse(signer.used)

    def test_sign_with_checkpoint_context(self):
        signer = self._signer()
        signature, checkpoint = signer.sign_with_checkpoint(
            MESSAGE, context=CONTEXT_A
        )
        self.assertTrue(
            verify(MESSAGE, signature, signer.public_key, context=CONTEXT_A)
        )
        restored = OneTimeSigner.from_checkpoint(checkpoint)
        self.assertTrue(restored.used)
        # Context is not in the checkpoint: a no-context checkpoint after the
        # same signature is byte-for-byte identical.
        other = self._signer()
        other.sign(MESSAGE)  # advance used
        self.assertEqual(checkpoint, other.checkpoint())

    def test_sign_with_checkpoint_bad_context_atomic(self):
        signer = self._signer()
        with self.assertRaises(TypeError):
            signer.sign_with_checkpoint(MESSAGE, context=42)
        self.assertFalse(signer.used)

    def test_sign_with_auth_state_context(self):
        signer = self._signer()
        signature, envelope = signer.sign_with_auth_state(
            MESSAGE, key=b"key", generation=5, context=CONTEXT_A
        )
        self.assertTrue(
            verify(MESSAGE, signature, signer.public_key, context=CONTEXT_A)
        )
        # The envelope must not depend on the context.
        other = self._signer()
        other_sig, other_envelope = other.sign_with_auth_state(
            MESSAGE, key=b"key", generation=5
        )
        self.assertEqual(envelope, other_envelope)
        self.assertNotEqual(signature, other_sig)

    def test_sign_with_auth_state_bad_context_atomic(self):
        signer = self._signer()
        with self.assertRaises(TypeError):
            signer.sign_with_auth_state(
                MESSAGE, key=b"key", generation=0, context=42
            )
        self.assertFalse(signer.used)


class LamportProofTest(unittest.TestCase):
    def _proof(self):
        private, public = fresh_bits()
        signature = sign(MESSAGE, private, context=CONTEXT_A)
        return public, LamportProof(public, signature)

    def test_verify_requires_matching_context(self):
        _, proof = self._proof()
        self.assertTrue(proof.verify(MESSAGE, context=CONTEXT_A))
        self.assertFalse(proof.verify(MESSAGE))
        self.assertFalse(proof.verify(MESSAGE, context=b"other"))
        self.assertFalse(proof.verify(b"wrong", context=CONTEXT_A))

    def test_verify_bound_requires_matching_context(self):
        public, proof = self._proof()
        self.assertTrue(
            proof.verify_bound(MESSAGE, public_key=public, context=CONTEXT_A)
        )
        self.assertFalse(proof.verify_bound(MESSAGE, public_key=public))
        self.assertFalse(
            proof.verify_bound(
                MESSAGE, public_key=public, context=b"other"
            )
        )

    def test_verify_bound_wrong_embedded_key_fails(self):
        _, proof = self._proof()
        _, other_public = fresh_bits(start=999)
        self.assertFalse(
            proof.verify_bound(MESSAGE, public_key=other_public, context=CONTEXT_A)
        )

    def test_bad_context_type_raises(self):
        public, proof = self._proof()
        for bad in BAD_CONTEXTS:
            with self.assertRaises(TypeError):
                proof.verify(MESSAGE, context=bad)
            with self.assertRaises(TypeError):
                proof.verify_bound(MESSAGE, public_key=public, context=bad)

    def test_wrong_bound_key_type_raises(self):
        _, proof = self._proof()
        with self.assertRaises(TypeError):
            proof.verify_bound(MESSAGE, public_key=b"not a key", context=CONTEXT_A)

    def test_serialised_proof_round_trip_with_context(self):
        public, proof = self._proof()
        restored = LamportProof.from_bytes(proof.to_bytes())
        self.assertEqual(restored, proof)
        self.assertTrue(restored.verify(MESSAGE, context=CONTEXT_A))
        self.assertFalse(restored.verify(MESSAGE))


class StatelessAuthStateTest(unittest.TestCase):
    def _fresh_envelope(self, private):
        signer = OneTimeSigner(private)
        envelope = auth_state_wrap(
            signer.checkpoint(), scheme="lamport", key=b"key", generation=0
        )
        return signer, envelope

    def test_context_flows_through_restore_sign_wrap(self):
        private, public = fresh_bits()
        _, envelope = self._fresh_envelope(private)
        signature, _next_envelope, generation = sign_lamport_auth_state(
            envelope,
            MESSAGE,
            key=b"key",
            claim=lambda token: True,
            context=CONTEXT_A,
        )
        self.assertEqual(generation, 1)
        self.assertFalse(verify(MESSAGE, signature, public))
        self.assertTrue(verify(MESSAGE, signature, public, context=CONTEXT_A))

    def test_bad_context_type_raises_and_claim_not_called(self):
        _, envelope = self._fresh_envelope(fresh_bits()[0])

        def claim(token):
            raise AssertionError("claim must not run on validation failure")

        for bad in BAD_CONTEXTS:
            with self.assertRaises(TypeError):
                sign_lamport_auth_state(
                    envelope,
                    MESSAGE,
                    key=b"key",
                    claim=claim,
                    context=bad,
                )

    def test_no_context_matches_stateless_baseline(self):
        private, _ = fresh_bits()
        signer, envelope = self._fresh_envelope(private)
        signature, _, generation = sign_lamport_auth_state(
            envelope, MESSAGE, key=b"key", claim=lambda token: True
        )
        self.assertEqual(generation, 1)
        self.assertEqual(signature, sign(MESSAGE, signer._private_key))


if __name__ == "__main__":
    unittest.main()

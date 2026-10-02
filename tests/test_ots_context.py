"""Optional context binding for the standalone Lamport and W-OTS APIs.

Covers the keyword-only ``context`` parameter of :func:`sign` /
:func:`verify`, :func:`wots_sign` / :func:`wots_verify`,
:class:`OneTimeSigner` / :class:`WOTSOneTimeSigner`
(``sign`` / ``sign_with_checkpoint`` / ``sign_with_auth_state``),
:class:`LamportProof` / :class:`WOTSProof` / :class:`OtsPairProof`
(``verify`` / ``verify_bound``) and the paired/stateless signing entries
``sign_ots_pair``, ``sign_ots_pair_with_checkpoint``,
``sign_ots_pair_proof_with_checkpoint``,
``sign_ots_pair_proof_with_auth_state``, ``sign_lamport_auth_state`` and
``sign_wots_auth_state``: normalisation (``None`` and empty values mean
"no context", ``str`` encoded as UTF-8), byte-for-byte compatibility
with legacy unbound outputs, context separation, type errors, failure
to consume signer state, and unchanged wire formats and persisted state.
"""

import unittest

from pqattest import (
    KeyExhaustedError,
    LamportProof,
    OneTimeSigner,
    OtsPairProof,
    PrivateKey,
    WOTSOneTimeSigner,
    WOTSPrivateKey,
    WOTSProof,
    auth_state_unwrap,
    auth_state_wrap,
    keygen,
    sign,
    sign_lamport_auth_state,
    sign_ots_pair,
    sign_ots_pair_proof_auth_state,
    sign_ots_pair_proof_with_auth_state,
    sign_ots_pair_proof_with_checkpoint,
    sign_ots_pair_with_checkpoint,
    sign_wots_auth_state,
    verify,
    wots_keygen,
    wots_sign,
    wots_verify,
)

MESSAGE = b"the signed message"
CONTEXT_A = b"context-a"
CONTEXT_B = "café/context-b"  # str on purpose: UTF-8 must match its bytes
CONTEXT_B_BYTES = CONTEXT_B.encode("utf-8")
KEY = b"unit-test-shared-secret-key"

BAD_CONTEXTS = (0, 1, 1.5, ["ctx"], {"ctx": 1}, object(), True)
EMPTY_CONTEXTS = (None, b"", bytearray(b""), "")


class NormalisationTest(unittest.TestCase):
    def test_lamport_none_and_empty_are_legacy_identical(self):
        private_key, public_key = keygen()
        legacy = sign(MESSAGE, private_key)
        for context in EMPTY_CONTEXTS:
            with self.subTest(context=repr(context)):
                got = sign(MESSAGE, private_key, context=context)
                self.assertEqual(got, legacy)
                self.assertTrue(
                    verify(MESSAGE, got, public_key, context=context)
                )

    def test_wots_none_and_empty_are_legacy_identical(self):
        private_key, public_key = wots_keygen()
        legacy = wots_sign(MESSAGE, private_key)
        for context in EMPTY_CONTEXTS:
            with self.subTest(context=repr(context)):
                got = wots_sign(MESSAGE, private_key, context=context)
                self.assertEqual(got, legacy)
                self.assertTrue(
                    wots_verify(MESSAGE, got, public_key, context=context)
                )

    def test_str_context_uses_utf8_and_is_deterministic(self):
        l_private, _ = keygen()
        self.assertEqual(
            sign(MESSAGE, l_private, context=CONTEXT_B),
            sign(MESSAGE, l_private, context=CONTEXT_B_BYTES),
        )
        w_private, _ = wots_keygen()
        self.assertEqual(
            wots_sign(MESSAGE, w_private, context=CONTEXT_B),
            wots_sign(MESSAGE, w_private, context=CONTEXT_B_BYTES),
        )

    def test_bytearray_context_accepted(self):
        l_private, l_public = keygen()
        l_sig = sign(MESSAGE, l_private, context=bytearray(CONTEXT_A))
        self.assertTrue(
            verify(MESSAGE, l_sig, l_public, context=CONTEXT_A)
        )
        w_private, w_public = wots_keygen()
        w_sig = wots_sign(MESSAGE, w_private, context=bytearray(CONTEXT_A))
        self.assertTrue(
            wots_verify(MESSAGE, w_sig, w_public, context=CONTEXT_A)
        )

    def test_context_is_keyword_only(self):
        l_private, l_public = keygen()
        w_private, w_public = wots_keygen()
        with self.assertRaises(TypeError):
            sign(MESSAGE, l_private, CONTEXT_A)
        with self.assertRaises(TypeError):
            wots_sign(MESSAGE, w_private, CONTEXT_A)
        l_sig = sign(MESSAGE, l_private)
        w_sig = wots_sign(MESSAGE, w_private)
        with self.assertRaises(TypeError):
            verify(MESSAGE, l_sig, l_public, CONTEXT_A)
        with self.assertRaises(TypeError):
            wots_verify(MESSAGE, w_sig, w_public, CONTEXT_A)


class BindingTest(unittest.TestCase):
    def test_lamport_context_separates_signatures(self):
        private_key, public_key = keygen()
        bound = sign(MESSAGE, private_key, context=CONTEXT_A)
        legacy_key, legacy_public = keygen()
        legacy = sign(MESSAGE, legacy_key)
        self.assertTrue(verify(MESSAGE, bound, public_key, context=CONTEXT_A))
        for wrong in (None, b"", CONTEXT_B_BYTES):
            self.assertFalse(
                verify(MESSAGE, bound, public_key, context=wrong)
            )
        self.assertFalse(
            verify(MESSAGE, legacy, legacy_public, context=CONTEXT_A)
        )
        self.assertTrue(verify(MESSAGE, legacy, legacy_public))
        self.assertFalse(
            verify(b"wrong message", bound, public_key, context=CONTEXT_A)
        )

    def test_wots_context_separates_signatures(self):
        private_key, public_key = wots_keygen()
        bound = wots_sign(MESSAGE, private_key, context=CONTEXT_A)
        legacy_key, legacy_public = wots_keygen()
        legacy = wots_sign(MESSAGE, legacy_key)
        self.assertTrue(
            wots_verify(MESSAGE, bound, public_key, context=CONTEXT_A)
        )
        for wrong in (None, b"", CONTEXT_B_BYTES):
            self.assertFalse(
                wots_verify(MESSAGE, bound, public_key, context=wrong)
            )
        self.assertFalse(
            wots_verify(MESSAGE, legacy, legacy_public, context=CONTEXT_A)
        )
        self.assertTrue(wots_verify(MESSAGE, legacy, legacy_public))
        self.assertFalse(
            wots_verify(b"wrong message", bound, public_key, context=CONTEXT_A)
        )

    def test_length_prefixing_is_unambiguous(self):
        # Signing (message m, context c) must not validate another
        # context/message split of the same concatenated bytes.
        for scheme_sign, scheme_verify, keygen_fn in (
            (sign, verify, keygen),
            (wots_sign, wots_verify, wots_keygen),
        ):
            with self.subTest(scheme=scheme_sign.__name__):
                private_key, public_key = keygen_fn()
                bound = scheme_sign(MESSAGE, private_key, context=CONTEXT_A)
                joined = CONTEXT_A + MESSAGE
                split_at = len(CONTEXT_A)
                for split in range(len(joined) + 1):
                    context = joined[:split]
                    message = joined[split:]
                    result = scheme_verify(
                        message, bound, public_key, context=context
                    )
                    self.assertIs(
                        result, split == split_at and message == MESSAGE
                    )

    def test_wrong_message_type_semantics_are_unchanged(self):
        # W-OTS verify reports every non-key-type problem as False, even a
        # bad message type under a context.
        _, w_public = wots_keygen()
        self.assertFalse(wots_verify(123, (), w_public, context=CONTEXT_A))
        # Lamport's raw verify keeps its historical behaviour: a bad
        # message type raises TypeError, with or without a context (the
        # proof wrappers still turn it into False).
        l_private, l_public = keygen()
        signature = sign(MESSAGE, l_private, context=CONTEXT_A)
        with self.assertRaises(TypeError):
            verify(123, signature, l_public, context=CONTEXT_A)
        proof = LamportProof(l_public, signature)
        self.assertFalse(proof.verify(123, context=CONTEXT_A))


class TypeErrorTest(unittest.TestCase):
    def test_bad_context_type_raises_on_module_entries(self):
        l_private, l_public = keygen()
        w_private, w_public = wots_keygen()
        for bad in BAD_CONTEXTS:
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign(MESSAGE, l_private, context=bad)
                with self.assertRaises(TypeError):
                    verify(MESSAGE, (), l_public, context=bad)
                with self.assertRaises(TypeError):
                    wots_sign(MESSAGE, w_private, context=bad)
                with self.assertRaises(TypeError):
                    wots_verify(MESSAGE, (), w_public, context=bad)


class SignerContextTest(unittest.TestCase):
    def _lamport(self):
        private_key, public_key = keygen()
        return OneTimeSigner(private_key), private_key, public_key

    def _wots(self):
        private_key, public_key = wots_keygen()
        return WOTSOneTimeSigner(private_key), private_key, public_key

    def test_empty_context_matches_unbound_signature(self):
        for context in EMPTY_CONTEXTS:
            with self.subTest(context=repr(context)):
                signer, private_key, public_key = self._lamport()
                got = signer.sign(MESSAGE, context=context)
                self.assertEqual(got, sign(MESSAGE, private_key))
                self.assertTrue(
                    verify(MESSAGE, got, public_key, context=context)
                )
                signer, private_key, public_key = self._wots()
                got = signer.sign(MESSAGE, context=context)
                self.assertEqual(got, wots_sign(MESSAGE, private_key))
                self.assertTrue(
                    wots_verify(MESSAGE, got, public_key, context=context)
                )

    def test_bound_signature_verifies_only_with_context(self):
        signer, _, public_key = self._lamport()
        l_sig = signer.sign(MESSAGE, context=CONTEXT_A)
        self.assertTrue(verify(MESSAGE, l_sig, public_key, context=CONTEXT_A))
        self.assertFalse(verify(MESSAGE, l_sig, public_key))
        signer, _, public_key = self._wots()
        w_sig = signer.sign(MESSAGE, context=CONTEXT_A)
        self.assertTrue(
            wots_verify(MESSAGE, w_sig, public_key, context=CONTEXT_A)
        )
        self.assertFalse(wots_verify(MESSAGE, w_sig, public_key))

    def test_bad_context_does_not_consume_the_key(self):
        for factory, verify_fn in (
            (self._lamport, verify),
            (self._wots, wots_verify),
        ):
            signer, _, public_key = factory()
            for bad in BAD_CONTEXTS:
                with self.assertRaises(TypeError):
                    signer.sign(MESSAGE, context=bad)
            self.assertFalse(signer.used)
            signature = signer.sign(MESSAGE, context=CONTEXT_A)
            self.assertTrue(
                verify_fn(MESSAGE, signature, public_key, context=CONTEXT_A)
            )
            with self.assertRaises(KeyExhaustedError):
                signer.sign(MESSAGE)

    def test_bad_message_under_context_does_not_consume(self):
        lamport, _, _ = self._lamport()
        wots, _, _ = self._wots()
        with self.assertRaises(TypeError):
            lamport.sign(123, context=CONTEXT_A)
        with self.assertRaises(TypeError):
            wots.sign(123, context=CONTEXT_A)
        self.assertFalse(lamport.used or wots.used)

    def test_checkpoint_does_not_carry_context(self):
        signer, private_key, _ = self._lamport()
        twin = OneTimeSigner(PrivateKey(private_key.secrets))
        _, bound_checkpoint = signer.sign_with_checkpoint(
            MESSAGE, context=CONTEXT_A
        )
        _, legacy_checkpoint = twin.sign_with_checkpoint(MESSAGE)
        self.assertEqual(bound_checkpoint, legacy_checkpoint)

        signer, private_key, _ = self._wots()
        twin = WOTSOneTimeSigner(
            WOTSPrivateKey(w=private_key.w, elements=private_key.elements)
        )
        _, bound_checkpoint = signer.sign_with_checkpoint(
            MESSAGE, context=CONTEXT_A
        )
        _, legacy_checkpoint = twin.sign_with_checkpoint(MESSAGE)
        self.assertEqual(bound_checkpoint, legacy_checkpoint)

    def test_auth_envelope_does_not_carry_context(self):
        signer, private_key, _ = self._wots()
        twin = WOTSOneTimeSigner(
            WOTSPrivateKey(w=private_key.w, elements=private_key.elements)
        )
        _, bound_envelope = signer.sign_with_auth_state(
            MESSAGE, key=KEY, generation=3, context=CONTEXT_A
        )
        _, legacy_envelope = twin.sign_with_auth_state(
            MESSAGE, key=KEY, generation=3
        )
        self.assertEqual(bound_envelope, legacy_envelope)
        scheme, generation, _ = auth_state_unwrap(
            bound_envelope, key=KEY, expect="wots"
        )
        self.assertEqual((scheme, generation), ("wots", 3))

    def test_sign_with_checkpoint_context_roundtrip(self):
        signer, _, public_key = self._lamport()
        signature, checkpoint = signer.sign_with_checkpoint(
            MESSAGE, context=CONTEXT_A
        )
        restored = OneTimeSigner.from_checkpoint(checkpoint)
        self.assertTrue(restored.used)
        self.assertEqual(restored.public_key, public_key)
        self.assertTrue(
            verify(MESSAGE, signature, public_key, context=CONTEXT_A)
        )

    def test_sign_with_auth_state_bad_context_does_not_consume(self):
        lamport, _, _ = self._lamport()
        wots, _, _ = self._wots()
        for bad in BAD_CONTEXTS:
            with self.assertRaises(TypeError):
                lamport.sign_with_auth_state(
                    MESSAGE, key=KEY, generation=0, context=bad
                )
            with self.assertRaises(TypeError):
                wots.sign_with_auth_state(
                    MESSAGE, key=KEY, generation=0, context=bad
                )
        self.assertFalse(lamport.used or wots.used)
        # A bad context also must not mask a bad generation by advancing.
        wots2, _, _ = self._wots()
        with self.assertRaises(TypeError):
            wots2.sign_with_auth_state(
                MESSAGE, key=KEY, generation=True, context=42
            )
        self.assertFalse(wots2.used)

    def test_context_is_keyword_only_on_signer_methods(self):
        lamport, _, _ = self._lamport()
        wots, _, _ = self._wots()
        with self.assertRaises(TypeError):
            lamport.sign(MESSAGE, CONTEXT_A)
        with self.assertRaises(TypeError):
            wots.sign(MESSAGE, CONTEXT_A)
        with self.assertRaises(TypeError):
            lamport.sign_with_checkpoint(MESSAGE, CONTEXT_A)
        with self.assertRaises(TypeError):
            wots.sign_with_checkpoint(MESSAGE, CONTEXT_A)
        with self.assertRaises(TypeError):
            lamport.sign_with_auth_state(MESSAGE, KEY, 0, CONTEXT_A)
        with self.assertRaises(TypeError):
            wots.sign_with_auth_state(MESSAGE, KEY, 0, CONTEXT_A)


def _proof_pair():
    l_private, l_public = keygen()
    w_private, w_public = wots_keygen()
    l_bound = LamportProof(
        l_public, sign(MESSAGE, l_private, context=CONTEXT_A)
    )
    w_bound = WOTSProof(
        w_public, wots_sign(MESSAGE, w_private, context=CONTEXT_A)
    )
    l_legacy_private, l_legacy_public = keygen()
    w_legacy_private, w_legacy_public = wots_keygen()
    l_legacy = LamportProof(
        l_legacy_public, sign(MESSAGE, l_legacy_private)
    )
    w_legacy = WOTSProof(
        w_legacy_public, wots_sign(MESSAGE, w_legacy_private)
    )
    return (
        l_bound,
        w_bound,
        l_public,
        w_public,
        l_legacy,
        w_legacy,
    )


class ProofContextTest(unittest.TestCase):
    def setUp(self):
        (
            self.lamport,
            self.wots,
            self.lamport_key,
            self.wots_key,
            self.lamport_legacy,
            self.wots_legacy,
        ) = _proof_pair()
        self.pair = OtsPairProof(self.lamport, self.wots)
        self.legacy_pair = OtsPairProof(self.lamport_legacy, self.wots_legacy)

    def test_matching_context_passes(self):
        self.assertTrue(self.lamport.verify(MESSAGE, context=CONTEXT_A))
        self.assertTrue(self.wots.verify(MESSAGE, context=CONTEXT_A))
        self.assertTrue(self.pair.verify(MESSAGE, context=CONTEXT_A))
        self.assertTrue(
            self.lamport.verify_bound(
                MESSAGE, public_key=self.lamport_key, context=CONTEXT_A
            )
        )
        self.assertTrue(
            self.wots.verify_bound(
                MESSAGE, public_key=self.wots_key, context=CONTEXT_A
            )
        )
        self.assertTrue(
            self.pair.verify_bound(
                MESSAGE,
                lamport_key=self.lamport_key,
                wots_key=self.wots_key,
                context=CONTEXT_A,
            )
        )

    def test_context_mismatch_is_false(self):
        for wrong in (None, b"", CONTEXT_B_BYTES):
            self.assertFalse(self.lamport.verify(MESSAGE, context=wrong))
            self.assertFalse(self.wots.verify(MESSAGE, context=wrong))
            self.assertFalse(self.pair.verify(MESSAGE, context=wrong))
        self.assertFalse(
            self.lamport_legacy.verify(MESSAGE, context=CONTEXT_A)
        )
        self.assertFalse(
            self.wots_legacy.verify(MESSAGE, context=CONTEXT_A)
        )
        self.assertFalse(
            self.legacy_pair.verify(MESSAGE, context=CONTEXT_A)
        )
        self.assertTrue(self.legacy_pair.verify(MESSAGE))
        self.assertFalse(self.pair.verify(MESSAGE))
        self.assertFalse(
            self.lamport.verify_bound(
                MESSAGE, public_key=self.lamport_key
            )
        )
        self.assertFalse(
            self.pair.verify_bound(
                MESSAGE,
                lamport_key=self.lamport_key,
                wots_key=self.wots_key,
                context=CONTEXT_B_BYTES,
            )
        )

    def test_bound_pair_passes_or_fails_as_a_whole(self):
        # The two halves carry the same context; supplying a mismatching
        # expected key fails even with the right context.
        other_wots_key = self.wots_legacy.public_key
        self.assertFalse(
            self.pair.verify_bound(
                MESSAGE,
                lamport_key=self.lamport_key,
                wots_key=other_wots_key,
                context=CONTEXT_A,
            )
        )

    def test_bad_context_type_raises(self):
        for bad in BAD_CONTEXTS:
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self.lamport.verify(MESSAGE, context=bad)
                with self.assertRaises(TypeError):
                    self.wots.verify(MESSAGE, context=bad)
                with self.assertRaises(TypeError):
                    self.pair.verify(MESSAGE, context=bad)
                with self.assertRaises(TypeError):
                    self.lamport.verify_bound(
                        MESSAGE, public_key=self.lamport_key, context=bad
                    )
                with self.assertRaises(TypeError):
                    self.wots.verify_bound(
                        MESSAGE, public_key=self.wots_key, context=bad
                    )
                with self.assertRaises(TypeError):
                    self.pair.verify_bound(
                        MESSAGE,
                        lamport_key=self.lamport_key,
                        wots_key=self.wots_key,
                        context=bad,
                    )

    def test_wire_format_is_unchanged_and_roundtrips(self):
        for proof in (self.lamport, self.wots, self.pair):
            with self.subTest(proof=type(proof).__name__):
                blob = proof.to_bytes()
                restored = type(proof).from_bytes(blob)
                self.assertEqual(restored.to_bytes(), blob)
        self.assertTrue(
            LamportProof.from_bytes(self.lamport.to_bytes()).verify(
                MESSAGE, context=CONTEXT_A
            )
        )
        self.assertTrue(
            WOTSProof.from_bytes(self.wots.to_bytes()).verify(
                MESSAGE, context=CONTEXT_A
            )
        )
        restored_pair = OtsPairProof.from_bytes(self.pair.to_bytes())
        self.assertTrue(restored_pair.verify(MESSAGE, context=CONTEXT_A))
        self.assertFalse(restored_pair.verify(MESSAGE))


def _signer_pair():
    l_private, l_public = keygen()
    w_private, w_public = wots_keygen()
    return (
        OneTimeSigner(l_private),
        WOTSOneTimeSigner(w_private),
        l_public,
        w_public,
        l_private,
        w_private,
    )


class PairEntriesContextTest(unittest.TestCase):
    def test_pair_with_checkpoint_binds_both_halves(self):
        lamport, wots, l_public, w_public, _, _ = _signer_pair()
        (l_signature, w_signature), _ = sign_ots_pair_with_checkpoint(
            lamport, wots, MESSAGE, context=CONTEXT_A
        )
        self.assertTrue(
            verify(MESSAGE, l_signature, l_public, context=CONTEXT_A)
        )
        self.assertTrue(
            wots_verify(MESSAGE, w_signature, w_public, context=CONTEXT_A)
        )
        self.assertFalse(verify(MESSAGE, l_signature, l_public))
        self.assertFalse(wots_verify(MESSAGE, w_signature, w_public))

    def test_empty_context_is_byte_identical_to_no_argument(self):
        lamport, wots, _, _, l_private, w_private = _signer_pair()
        l_twin = OneTimeSigner(PrivateKey(l_private.secrets))
        w_twin = WOTSOneTimeSigner(
            WOTSPrivateKey(w=w_private.w, elements=w_private.elements)
        )
        (s1_l, s1_w), (cp1_l, cp1_w) = sign_ots_pair_with_checkpoint(
            lamport, wots, MESSAGE
        )
        (s2_l, s2_w), (cp2_l, cp2_w) = sign_ots_pair_with_checkpoint(
            l_twin, w_twin, MESSAGE, context=""
        )
        self.assertEqual((s1_l, s1_w, cp1_l, cp1_w), (s2_l, s2_w, cp2_l, cp2_w))

    def test_pair_proof_with_checkpoint_context(self):
        lamport, wots, l_public, w_public, _, _ = _signer_pair()
        proof, (l_checkpoint, w_checkpoint) = (
            sign_ots_pair_proof_with_checkpoint(
                lamport, wots, MESSAGE, context=CONTEXT_A
            )
        )
        self.assertIsInstance(proof, OtsPairProof)
        self.assertTrue(
            proof.verify_bound(
                MESSAGE,
                lamport_key=l_public,
                wots_key=w_public,
                context=CONTEXT_A,
            )
        )
        self.assertFalse(proof.verify(MESSAGE))
        # Checkpoints only depend on key + used, not on the context.
        restored_l = OneTimeSigner.from_checkpoint(l_checkpoint)
        restored_w = WOTSOneTimeSigner.from_checkpoint(w_checkpoint)
        self.assertTrue(restored_l.used and restored_w.used)
        self.assertEqual(restored_l.public_key, l_public)
        self.assertEqual(restored_w.public_key, w_public)

    def test_pair_auth_state_context(self):
        lamport, wots, l_public, w_public, _, _ = _signer_pair()
        (l_signature, w_signature), (l_envelope, w_envelope) = sign_ots_pair(
            lamport, wots, MESSAGE, key=KEY, generation=5, context=CONTEXT_A
        )
        self.assertTrue(
            verify(MESSAGE, l_signature, l_public, context=CONTEXT_A)
        )
        self.assertTrue(
            wots_verify(MESSAGE, w_signature, w_public, context=CONTEXT_A)
        )
        self.assertEqual(
            auth_state_unwrap(l_envelope, key=KEY, expect="lamport")[:2],
            ("lamport", 5),
        )
        self.assertEqual(
            auth_state_unwrap(w_envelope, key=KEY, expect="wots")[:2],
            ("wots", 5),
        )

        lamport, wots, l_public, w_public, _, _ = _signer_pair()
        proof, _ = sign_ots_pair_proof_with_auth_state(
            lamport, wots, MESSAGE, key=KEY, generation=6, context=CONTEXT_A
        )
        self.assertTrue(
            proof.verify_bound(
                MESSAGE,
                lamport_key=l_public,
                wots_key=w_public,
                context=CONTEXT_A,
            )
        )

    def test_pair_context_type_error_consumes_neither_half(self):
        lamport, wots, _, _, _, _ = _signer_pair()
        for bad in BAD_CONTEXTS:
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_ots_pair_with_checkpoint(
                        lamport, wots, MESSAGE, context=bad
                    )
                with self.assertRaises(TypeError):
                    sign_ots_pair(
                        lamport,
                        wots,
                        MESSAGE,
                        key=KEY,
                        generation=0,
                        context=bad,
                    )
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_with_checkpoint(
                        lamport, wots, MESSAGE, context=bad
                    )
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_with_auth_state(
                        lamport,
                        wots,
                        MESSAGE,
                        key=KEY,
                        generation=0,
                        context=bad,
                    )
        self.assertFalse(lamport.used or wots.used)
        # The pair still signs exactly once, atomically bound.
        proof, _ = sign_ots_pair_proof_with_checkpoint(
            lamport, wots, MESSAGE, context=CONTEXT_A
        )
        self.assertTrue(proof.verify(MESSAGE, context=CONTEXT_A))
        self.assertTrue(lamport.used and wots.used)

    def test_pair_bad_message_under_context_consumes_neither(self):
        lamport, wots, _, _, _, _ = _signer_pair()
        with self.assertRaises(TypeError):
            sign_ots_pair(
                lamport, wots, 123, key=KEY, generation=0, context=CONTEXT_A
            )
        with self.assertRaises(TypeError):
            sign_ots_pair_proof_with_auth_state(
                lamport, wots, 123, key=KEY, generation=0, context=CONTEXT_A
            )
        self.assertFalse(lamport.used or wots.used)

    def test_pair_context_is_keyword_only(self):
        lamport, wots, _, _, _, _ = _signer_pair()
        with self.assertRaises(TypeError):
            sign_ots_pair(lamport, wots, MESSAGE, KEY, 0, CONTEXT_A)
        with self.assertRaises(TypeError):
            sign_ots_pair_with_checkpoint(
                lamport, wots, MESSAGE, CONTEXT_A
            )
        with self.assertRaises(TypeError):
            sign_ots_pair_proof_with_checkpoint(
                lamport, wots, MESSAGE, CONTEXT_A
            )
        with self.assertRaises(TypeError):
            sign_ots_pair_proof_with_auth_state(
                lamport, wots, MESSAGE, KEY, 0, CONTEXT_A
            )

    def test_stateless_pair_entry_is_not_extended(self):
        # sign_ots_pair_proof_auth_state stays an unbound entry: a context
        # kwarg is a TypeError and its proof verifies with no context.
        lamport, wots, _, _, _, _ = _signer_pair()
        a = auth_state_wrap(
            lamport.checkpoint(), scheme="lamport", key=KEY, generation=0
        )
        b = auth_state_wrap(
            wots.checkpoint(), scheme="wots", key=KEY, generation=0
        )
        with self.assertRaises(TypeError):
            sign_ots_pair_proof_auth_state(
                a, b, MESSAGE, key=KEY, claim=lambda token: True,
                context=CONTEXT_A,
            )
        proof, _, generation = sign_ots_pair_proof_auth_state(
            a, b, MESSAGE, key=KEY, claim=lambda token: True
        )
        self.assertEqual(generation, 1)
        self.assertTrue(proof.verify(MESSAGE))


class StatelessConversionContextTest(unittest.TestCase):
    def _envelope(self, scheme, signer):
        return auth_state_wrap(
            signer.checkpoint(), scheme=scheme, key=KEY, generation=0
        )

    def test_lamport_conversion_binds_context(self):
        private_key, public_key = keygen()
        signer = OneTimeSigner(private_key)
        data = self._envelope("lamport", signer)
        claims = []
        signature, envelope, generation = sign_lamport_auth_state(
            data,
            MESSAGE,
            key=KEY,
            claim=lambda token: claims.append(token) or True,
            context=CONTEXT_A,
        )
        self.assertEqual(generation, 1)
        self.assertEqual(len(claims), 1)
        self.assertEqual(
            claims[0], (("lamport", 0), ("lamport", 1))
        )
        self.assertTrue(
            verify(MESSAGE, signature, public_key, context=CONTEXT_A)
        )
        self.assertFalse(verify(MESSAGE, signature, public_key))
        self.assertEqual(
            auth_state_unwrap(envelope, key=KEY, expect="lamport")[:2],
            ("lamport", 1),
        )

    def test_wots_conversion_binds_context(self):
        private_key, public_key = wots_keygen()
        signer = WOTSOneTimeSigner(private_key)
        data = self._envelope("wots", signer)
        signature, envelope, generation = sign_wots_auth_state(
            data,
            MESSAGE,
            key=KEY,
            claim=lambda token: True,
            context=CONTEXT_A,
        )
        self.assertEqual(generation, 1)
        self.assertTrue(
            wots_verify(MESSAGE, signature, public_key, context=CONTEXT_A)
        )
        self.assertFalse(wots_verify(MESSAGE, signature, public_key))
        self.assertEqual(
            auth_state_unwrap(envelope, key=KEY, expect="wots")[:2],
            ("wots", 1),
        )

    def test_empty_context_matches_unbound_outputs(self):
        private_key, _ = keygen()
        first = OneTimeSigner(PrivateKey(private_key.secrets))
        second = OneTimeSigner(PrivateKey(private_key.secrets))
        _, envelope_a, _ = sign_lamport_auth_state(
            self._envelope("lamport", first),
            MESSAGE,
            key=KEY,
            claim=lambda token: True,
        )
        _, envelope_b, _ = sign_lamport_auth_state(
            self._envelope("lamport", second),
            MESSAGE,
            key=KEY,
            claim=lambda token: True,
            context="",
        )
        self.assertEqual(envelope_a, envelope_b)

    def test_bad_context_type_raises_without_claim(self):
        def boom(token):
            raise AssertionError("claim must not be called")

        w_private, _ = wots_keygen()
        wots = WOTSOneTimeSigner(w_private)
        data = self._envelope("wots", wots)
        for bad in BAD_CONTEXTS:
            with self.subTest(bad=type(bad).__name__):
                lamport = OneTimeSigner(keygen()[0])
                with self.assertRaises(TypeError):
                    sign_lamport_auth_state(
                        self._envelope("lamport", lamport),
                        MESSAGE,
                        key=KEY,
                        claim=boom,
                        context=bad,
                    )
                with self.assertRaises(TypeError):
                    sign_wots_auth_state(
                        data, MESSAGE, key=KEY, claim=boom, context=bad
                    )

    def test_bad_message_under_context_raises(self):
        lamport = OneTimeSigner(keygen()[0])
        with self.assertRaises(TypeError):
            sign_lamport_auth_state(
                self._envelope("lamport", lamport),
                123,
                key=KEY,
                claim=lambda token: True,
                context=CONTEXT_A,
            )

    def test_context_is_keyword_only(self):
        lamport = OneTimeSigner(keygen()[0])
        data = self._envelope("lamport", lamport)
        with self.assertRaises(TypeError):
            sign_lamport_auth_state(
                data, MESSAGE, KEY, None, lambda token: True, CONTEXT_A
            )
        wots = WOTSOneTimeSigner(wots_keygen()[0])
        wdata = self._envelope("wots", wots)
        with self.assertRaises(TypeError):
            sign_wots_auth_state(
                wdata, MESSAGE, KEY, None, lambda token: True, CONTEXT_A
            )


if __name__ == "__main__":
    unittest.main()

"""Optional context binding for the toy lattice signature.

Covers ``toy_lattice_sign`` / ``toy_lattice_verify`` and the
``ToyLatticeProof.verify`` / ``ToyLatticeProof.verify_bound`` context
parameter: normalisation (``None`` and empty values mean "no context",
``str`` encoded as UTF-8), byte-for-byte compatibility with legacy
unbound signatures, context separation on every bound field, type
errors for illegal contexts, and unchanged v1 serialisation.
"""

import unittest

from pqattest import (
    ToyLatticeProof,
    ToyLatticePublicKey,
    ToyLatticeSignature,
    toy_lattice_keygen,
    toy_lattice_sign,
    toy_lattice_verify,
)

MESSAGE = b"the signed message"
CONTEXT_A = b"context-a"
CONTEXT_B = "café/context-b"  # str on purpose: UTF-8 must match its bytes
CONTEXT_B_BYTES = CONTEXT_B.encode("utf-8")

BAD_CONTEXTS = (0, 1, 1.5, ["ctx"], {"ctx": 1}, object())


def fixed_tokens(value: bytes):
    def token_bytes(size: int) -> bytes:
        assert size == len(value)
        return value

    return token_bytes


TOKEN_BYTES = b"R" * 8


def key_pair():
    return toy_lattice_keygen(token_bytes=fixed_tokens(b"K" * 8))


def sign(message=MESSAGE, *, context=None, token_bytes=fixed_tokens(TOKEN_BYTES)):
    private_key, _ = key_pair()
    return private_key, toy_lattice_sign(
        message, private_key, token_bytes=token_bytes, context=context
    )


class ContextNormalisationTest(unittest.TestCase):
    def test_none_and_empty_are_legacy_identical(self):
        private_key, _ = key_pair()
        legacy = toy_lattice_sign(
            MESSAGE, private_key, token_bytes=fixed_tokens(TOKEN_BYTES)
        )
        for context in (None, b"", bytearray(b""), ""):
            with self.subTest(context=repr(context)):
                got = toy_lattice_sign(
                    MESSAGE,
                    private_key,
                    token_bytes=fixed_tokens(TOKEN_BYTES),
                    context=context,
                )
                # Same key, message, randomness and no context: the tag and
                # vector are byte-for-byte identical, including v1 encoding.
                self.assertEqual(got, legacy)
                self.assertEqual(got.to_bytes(), legacy.to_bytes())
                _, public_key = key_pair()
                self.assertTrue(
                    toy_lattice_verify(MESSAGE, got, public_key, context=context)
                )

    def test_non_empty_context_changes_the_tag_not_the_vector(self):
        private_key, _ = key_pair()
        bound = toy_lattice_sign(
            MESSAGE,
            private_key,
            token_bytes=fixed_tokens(TOKEN_BYTES),
            context=CONTEXT_A,
        )
        unbound = toy_lattice_sign(
            MESSAGE, private_key, token_bytes=fixed_tokens(TOKEN_BYTES)
        )
        self.assertNotEqual(bound, unbound)
        self.assertNotEqual(bound.tag, unbound.tag)
        # The random vector u is drawn independently of the context; only the
        # chain key (and hence the tag) changes.
        self.assertEqual(bound.u, unbound.u)

    def test_str_context_uses_utf8_and_is_deterministic(self):
        private_key, _ = key_pair()
        first = toy_lattice_sign(
            MESSAGE,
            private_key,
            token_bytes=fixed_tokens(TOKEN_BYTES),
            context=CONTEXT_B,
        )
        second = toy_lattice_sign(
            MESSAGE,
            private_key,
            token_bytes=fixed_tokens(TOKEN_BYTES),
            context=CONTEXT_B_BYTES,
        )
        third = toy_lattice_sign(
            MESSAGE,
            private_key,
            token_bytes=fixed_tokens(TOKEN_BYTES),
            context=CONTEXT_B,
        )
        self.assertEqual(first, second)
        self.assertEqual(first, third)

    def test_bytearray_context_accepted(self):
        _, signature = sign(context=bytearray(CONTEXT_A))
        _, public_key = key_pair()
        self.assertTrue(
            toy_lattice_verify(
                MESSAGE, signature, public_key, context=CONTEXT_A
            )
        )

    def test_context_is_keyword_only(self):
        private_key, signature = sign()
        _, public_key = key_pair()
        with self.assertRaises(TypeError):
            toy_lattice_sign(MESSAGE, private_key, fixed_tokens(TOKEN_BYTES), b"c")
        with self.assertRaises(TypeError):
            toy_lattice_verify(MESSAGE, signature, public_key, b"c")
        proof = ToyLatticeProof(public_key, signature)
        with self.assertRaises(TypeError):
            proof.verify(MESSAGE, b"c")
        with self.assertRaises(TypeError):
            proof.verify_bound(MESSAGE, public_key, b"c")


class SignContextTypeErrorTest(unittest.TestCase):
    def test_bad_context_type_raises_type_error(self):
        private_key, _ = key_pair()
        for bad in BAD_CONTEXTS:
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    toy_lattice_sign(
                        MESSAGE,
                        private_key,
                        token_bytes=fixed_tokens(TOKEN_BYTES),
                        context=bad,
                    )

    def test_bad_context_type_does_not_consume_randomness(self):
        private_key, _ = key_pair()

        def boom(size):
            raise AssertionError("randomness must not be drawn")

        with self.assertRaises(TypeError):
            toy_lattice_sign(MESSAGE, private_key, token_bytes=boom, context=42)


class VerifyBindingTest(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = key_pair()
        self.bound = toy_lattice_sign(
            MESSAGE,
            self.private_key,
            token_bytes=fixed_tokens(TOKEN_BYTES),
            context=CONTEXT_A,
        )
        self.unbound = toy_lattice_sign(
            MESSAGE, self.private_key, token_bytes=fixed_tokens(TOKEN_BYTES)
        )

    def verify(self, message, signature, *, context):
        return toy_lattice_verify(
            message, signature, self.public_key, context=context
        )

    def test_matching_context_passes(self):
        self.assertTrue(self.verify(MESSAGE, self.bound, context=CONTEXT_A))
        self.assertTrue(
            toy_lattice_verify(
                MESSAGE, self.bound, self.public_key, context=bytearray(CONTEXT_A)
            )
        )

    def test_only_message_signature_key_and_context_all_match(self):
        # Wrong context (including unbound and empty): no pass.
        for context in (None, b"", CONTEXT_B_BYTES):
            with self.subTest(context=repr(context)):
                self.assertFalse(self.verify(MESSAGE, self.bound, context=context))
        # A legacy unbound signature must not pass under a non-empty context.
        self.assertFalse(self.verify(MESSAGE, self.unbound, context=CONTEXT_A))
        # Wrong message under the right context.
        self.assertFalse(self.verify(b"wrong message", self.bound, context=CONTEXT_A))
        # Right message and context, wrong public key.
        _, other_public = toy_lattice_keygen(
            token_bytes=fixed_tokens(b"otherkey")
        )
        self.assertFalse(
            toy_lattice_verify(
                MESSAGE, self.bound, other_public, context=CONTEXT_A
            )
        )

    def test_tampered_signature_fields_fail(self):
        tampered_tag = ToyLatticeSignature(
            self.bound.u, self.bound.tag[:-1] + bytes([self.bound.tag[-1] ^ 1])
        )
        self.assertFalse(self.verify(MESSAGE, tampered_tag, context=CONTEXT_A))
        # A different u re-derives a different chain key.
        other_u = toy_lattice_sign(
            MESSAGE,
            self.private_key,
            token_bytes=fixed_tokens(b"S" * 8),
            context=CONTEXT_A,
        ).u
        self.assertNotEqual(other_u, self.bound.u)
        swapped = ToyLatticeSignature(other_u, self.bound.tag)
        self.assertFalse(self.verify(MESSAGE, swapped, context=CONTEXT_A))

    def test_context_cannot_be_used_as_message_shuffling(self):
        # Signing (message m, context c) must not validate (m2, c') for any
        # other split c'/m2 of the same concatenated bytes: the length-prefixed
        # domain-separated encoding makes the binding unambiguous.
        joined = b"".join([CONTEXT_A, MESSAGE])
        legitimate_split = len(CONTEXT_A)
        for split in range(len(joined) + 1):
            context = joined[:split]
            message = joined[split:]
            with self.subTest(split=split):
                result = toy_lattice_verify(
                    message, self.bound, self.public_key, context=context
                )
                if split == legitimate_split and message == MESSAGE:
                    self.assertTrue(result)
                else:
                    self.assertFalse(result)

    def test_bad_context_type_raises_type_error(self):
        for bad in BAD_CONTEXTS:
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    toy_lattice_verify(
                        MESSAGE, self.bound, self.public_key, context=bad
                    )

    def test_bad_public_key_type_still_raises_with_context(self):
        for bad_key in ("key", b"key", object(), None):
            with self.subTest(bad=type(bad_key).__name__):
                with self.assertRaises(TypeError):
                    toy_lattice_verify(
                        MESSAGE, self.bound, bad_key, context=CONTEXT_A
                    )

    def test_other_mismatches_return_false_not_raise(self):
        self.assertFalse(
            toy_lattice_verify(
                123, self.bound, self.public_key, context=CONTEXT_A
            )
        )
        self.assertFalse(
            toy_lattice_verify(
                MESSAGE, "not-a-signature", self.public_key, context=CONTEXT_A
            )
        )


class ProofContextTest(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = key_pair()
        self.bound = toy_lattice_sign(
            MESSAGE,
            self.private_key,
            token_bytes=fixed_tokens(TOKEN_BYTES),
            context=CONTEXT_A,
        )
        self.unbound = toy_lattice_sign(
            MESSAGE, self.private_key, token_bytes=fixed_tokens(TOKEN_BYTES)
        )
        self.proof = ToyLatticeProof(self.public_key, self.bound)
        self.legacy_proof = ToyLatticeProof(self.public_key, self.unbound)
        _, self.other_public = toy_lattice_keygen(
            token_bytes=fixed_tokens(b"otherkey")
        )

    def test_verify_matching_context(self):
        self.assertTrue(self.proof.verify(MESSAGE, context=CONTEXT_A))
        self.assertTrue(self.proof.verify(MESSAGE, context="context-a"))

    def test_verify_context_mismatch_is_false(self):
        self.assertFalse(self.proof.verify(MESSAGE))
        self.assertFalse(self.proof.verify(MESSAGE, context=None))
        self.assertFalse(self.proof.verify(MESSAGE, context=b""))
        self.assertFalse(self.proof.verify(MESSAGE, context=CONTEXT_B_BYTES))
        self.assertFalse(self.proof.verify(b"wrong", context=CONTEXT_A))
        # Unbound proof cannot be verified with a context; bound proof cannot be
        # verified without one.
        self.assertFalse(self.legacy_proof.verify(MESSAGE, context=CONTEXT_A))
        self.assertTrue(self.legacy_proof.verify(MESSAGE))
        self.assertFalse(self.proof.verify(MESSAGE))

    def test_verify_bound_matching_context(self):
        self.assertTrue(
            self.proof.verify_bound(
                MESSAGE, public_key=self.public_key, context=CONTEXT_A
            )
        )

    def test_verify_bound_context_mismatch_is_false(self):
        self.assertFalse(
            self.proof.verify_bound(MESSAGE, public_key=self.public_key)
        )
        self.assertFalse(
            self.proof.verify_bound(
                MESSAGE, public_key=self.public_key, context=CONTEXT_B_BYTES
            )
        )
        self.assertFalse(
            self.proof.verify_bound(
                b"wrong", public_key=self.public_key, context=CONTEXT_A
            )
        )

    def test_verify_bound_other_embedded_key_is_false(self):
        # Public key mismatch must fail even when the context matches.
        self.assertFalse(
            self.proof.verify_bound(
                MESSAGE, public_key=self.other_public, context=CONTEXT_A
            )
        )

    def test_proof_context_type_errors(self):
        for bad in BAD_CONTEXTS:
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self.proof.verify(MESSAGE, context=bad)
                with self.assertRaises(TypeError):
                    self.proof.verify_bound(
                        MESSAGE, public_key=self.public_key, context=bad
                    )

    def test_verify_bound_public_key_type_error_with_context(self):
        for bad_key in ("key", b"key", object(), None):
            with self.subTest(bad=type(bad_key).__name__):
                with self.assertRaises(TypeError):
                    self.proof.verify_bound(
                        MESSAGE, public_key=bad_key, context=CONTEXT_A
                    )

    def test_tampered_embedded_fields_fail_under_context(self):
        rogue = object.__new__(ToyLatticeProof)
        object.__setattr__(rogue, "public_key", "not-a-key")
        object.__setattr__(rogue, "signature", "not-a-signature")
        self.assertFalse(rogue.verify(MESSAGE, context=CONTEXT_A))
        self.assertFalse(
            rogue.verify_bound(
                MESSAGE, public_key=self.public_key, context=CONTEXT_A
            )
        )

        rogue2 = object.__new__(ToyLatticeProof)
        object.__setattr__(rogue2, "public_key", self.public_key)
        object.__setattr__(rogue2, "signature", "not-a-signature")
        self.assertFalse(rogue2.verify(MESSAGE, context=CONTEXT_A))
        self.assertFalse(
            rogue2.verify_bound(
                MESSAGE, public_key=self.public_key, context=CONTEXT_A
            )
        )

    def test_serialisation_unchanged_and_context_survives_roundtrip(self):
        # The v1 proof encoding carries no context; the bound signature still
        # verifies after a serialisation roundtrip when the same context is
        # supplied.
        restored = ToyLatticeProof.from_bytes(self.proof.to_bytes())
        self.assertEqual(restored.to_bytes(), self.proof.to_bytes())
        self.assertTrue(restored.verify(MESSAGE, context=CONTEXT_A))
        self.assertFalse(restored.verify(MESSAGE))
        # Legacy proof bytes keep verifying with no context.
        restored_legacy = ToyLatticeProof.from_bytes(self.legacy_proof.to_bytes())
        self.assertTrue(restored_legacy.verify(MESSAGE))
        self.assertFalse(restored_legacy.verify(MESSAGE, context=CONTEXT_A))

    def test_signature_wire_format_unchanged(self):
        # A context-bound signature uses the same 61-byte v1 layout; only the
        # tag contents differ.
        self.assertEqual(
            len(self.bound.to_bytes()), len(self.unbound.to_bytes())
        )
        self.assertEqual(self.bound.to_bytes()[:8], b"PQALSG\0\0")
        restored = ToyLatticeSignature.from_bytes(self.bound.to_bytes())
        self.assertEqual(restored, self.bound)
        _, public_key = key_pair()
        self.assertTrue(
            toy_lattice_verify(
                MESSAGE, restored, public_key, context=CONTEXT_A
            )
        )


if __name__ == "__main__":
    unittest.main()

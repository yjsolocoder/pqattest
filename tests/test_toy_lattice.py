import hashlib
import hmac
import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    ToyLatticeCiphertext,
    ToyLatticePrivateKey,
    ToyLatticePublicKey,
    ToyLatticeSignature,
    toy_lattice_decapsulate,
    toy_lattice_encapsulate,
    toy_lattice_keygen,
    toy_lattice_sign,
    toy_lattice_verify,
)
from pqattest.toy_lattice import _decode_e, _encode_e


def fixed_tokens(value: bytes):
    def token_bytes(size: int) -> bytes:
        assert size == len(value)
        return value

    return token_bytes


def counter_tokens():
    state = {"value": 0}

    def token_bytes(size: int) -> bytes:
        chunk = state["value"].to_bytes(8, "big").rjust(size, b"\x00")
        state["value"] += 1
        return chunk

    return token_bytes


class EncodingTest(unittest.TestCase):
    def test_e_roundtrip(self):
        coeffs = (0, 1, 2, 127, 254, 255, 256, 7)
        encoded = _encode_e(coeffs)
        self.assertEqual(encoded, bytes.fromhex("0000 0001 0002 007f 00fe 00ff 0100 0007".replace(" ", "")))
        self.assertEqual(len(encoded), 16)
        self.assertEqual(_decode_e(encoded), coeffs)

    def test_fields_reject_non_bytes(self):
        for bad in ("0123456789abcdef", bytearray(16), None, [0] * 16):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    ToyLatticePublicKey(bad)
                with self.assertRaises(TypeError):
                    ToyLatticePrivateKey(bad)
        with self.assertRaises(TypeError):
            ToyLatticeCiphertext(b"\x00" * 16, "not bytes")
        with self.assertRaises(TypeError):
            ToyLatticeCiphertext("not bytes", b"\x00" * 32)
        with self.assertRaises(TypeError):
            ToyLatticeCiphertext(b"\x00" * 16, bytearray(32))

    def test_fields_reject_bad_values(self):
        with self.assertRaises(ValueError):
            ToyLatticePublicKey(b"\x00" * 15)  # too short
        with self.assertRaises(ValueError):
            ToyLatticePublicKey(b"\x00" * 17)  # too long
        # coefficient 257 does not fit the 0..256 range
        with self.assertRaises(ValueError):
            ToyLatticePublicKey(b"\x01\x01" + b"\x00" * 14)
        with self.assertRaises(ValueError):
            ToyLatticeCiphertext(b"\x01\x01" + b"\x00" * 14, b"\x00" * 32)

    def test_coefficient_256_allowed(self):
        key = ToyLatticePublicKey(b"\x01\x00" + b"\x00" * 14)
        self.assertEqual(_decode_e(key.t)[0], 256)


class ValueObjectTest(unittest.TestCase):
    def test_frozen(self):
        private_key, public_key = toy_lattice_keygen(token_bytes=fixed_tokens(b"abcdefgh"))
        with self.assertRaises(FrozenInstanceError):
            public_key.t = b"\x00" * 16
        with self.assertRaises(FrozenInstanceError):
            private_key.s = b"\x00" * 16
        ciphertext, _ = toy_lattice_encapsulate(public_key, token_bytes=fixed_tokens(b"r-r-r-r-"))
        with self.assertRaises(FrozenInstanceError):
            ciphertext.u = b"\x00" * 16
        with self.assertRaises(FrozenInstanceError):
            ciphertext.tag = b"\x00" * 32

    def test_positional_construction_and_equality(self):
        a = ToyLatticePublicKey(b"\x00\x01" * 8)
        b = ToyLatticePublicKey(b"\x00\x01" * 8)
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        self.assertIn(a, {b})
        self.assertEqual(ToyLatticePrivateKey(b"\x00\x02" * 8), ToyLatticePrivateKey(b"\x00\x02" * 8))
        self.assertEqual(
            ToyLatticeCiphertext(b"\x00\x03" * 8, b"tag"),
            ToyLatticeCiphertext(b"\x00\x03" * 8, b"tag"),
        )
        self.assertNotEqual(a, ToyLatticePublicKey(b"\x00\x04" * 8))
        self.assertNotEqual(a, ToyLatticePrivateKey(b"\x00\x01" * 8))


class KeygenTest(unittest.TestCase):
    def test_keygen_sets_s_t_equal_to_e_of_x(self):
        x = b"01234567"
        seen = []
        private_key, public_key = toy_lattice_keygen(
            token_bytes=lambda size: seen.append(size) or x
        )
        self.assertEqual(seen, [8])
        self.assertEqual(public_key.t, _encode_e(x))
        self.assertEqual(private_key.s, _encode_e(x))
        self.assertEqual(private_key.s, public_key.t)
        self.assertIsInstance(private_key, ToyLatticePrivateKey)
        self.assertIsInstance(public_key, ToyLatticePublicKey)

    def test_token_length_enforced(self):
        with self.assertRaises(ValueError):
            toy_lattice_keygen(token_bytes=lambda size: b"short")
        with self.assertRaises(ValueError):
            toy_lattice_keygen(token_bytes=lambda size: b"x" * 9)


class EncapsulateTest(unittest.TestCase):
    def test_known_vectors(self):
        t = _encode_e((1, 2, 3, 4, 5, 6, 7, 8))
        r = bytes((8, 7, 6, 5, 4, 3, 2, 1))
        public_key = ToyLatticePublicKey(t)
        ciphertext, shared_key = toy_lattice_encapsulate(
            public_key, token_bytes=fixed_tokens(r)
        )
        self.assertEqual(ciphertext.u, _encode_e(r))
        v = sum((i + 1) * coeff for i, coeff in enumerate((8, 7, 6, 5, 4, 3, 2, 1))) % 257
        expected = hashlib.sha256(b"K" + v.to_bytes(2, "big")).digest()
        self.assertEqual(shared_key, expected)
        self.assertEqual(ciphertext.tag, shared_key)
        self.assertEqual(len(shared_key), 32)

    def test_v_256_encodes_two_bytes(self):
        # dot product 256 * 1 = 256 == v, v2 = b"\x01\x00"
        public_key = ToyLatticePublicKey(b"\x01\x00" + b"\x00" * 14)
        r = b"\x01" + b"\x00" * 7
        ciphertext, shared_key = toy_lattice_encapsulate(
            public_key, token_bytes=fixed_tokens(r)
        )
        self.assertEqual(shared_key, hashlib.sha256(b"K" + b"\x01\x00").digest())
        self.assertEqual(ciphertext.u, _encode_e(r))

    def test_wrong_public_key_type(self):
        for bad in (b"\x00" * 16, None, ToyLatticePrivateKey(b"\x00" * 16), object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    toy_lattice_encapsulate(bad)

    def test_token_length_enforced(self):
        public_key = ToyLatticePublicKey(b"\x00" * 16)
        with self.assertRaises(ValueError):
            toy_lattice_encapsulate(public_key, token_bytes=lambda size: b"short")


class DecapsulateTest(unittest.TestCase):
    def test_roundtrip(self):
        token_bytes = counter_tokens()
        private_key, public_key = toy_lattice_keygen(token_bytes=token_bytes)
        ciphertext, enc_key = toy_lattice_encapsulate(public_key, token_bytes=token_bytes)
        dec_key = toy_lattice_decapsulate(ciphertext, private_key)
        self.assertEqual(dec_key, enc_key)
        self.assertEqual(dec_key, ciphertext.tag)

    def test_decaps_uses_s_dot_u(self):
        s = _encode_e((256, 5, 0, 0, 0, 0, 0, 0))
        r = bytes((1, 2, 0, 0, 0, 0, 0, 0))
        private_key = ToyLatticePrivateKey(s)
        v = (256 * 1 + 5 * 2) % 257  # 11
        key = hashlib.sha256(b"K" + v.to_bytes(2, "big")).digest()
        ciphertext = ToyLatticeCiphertext(_encode_e(r), key)
        self.assertEqual(toy_lattice_decapsulate(ciphertext, private_key), key)

    def test_bad_tag_raises_value_error(self):
        private_key, public_key = toy_lattice_keygen(token_bytes=fixed_tokens(b"abcdefgh"))
        ciphertext, _ = toy_lattice_encapsulate(
            public_key, token_bytes=fixed_tokens(b"r-r-r-r-")
        )
        tampered_tag = ToyLatticeCiphertext(ciphertext.u, b"\x00" * 32)
        with self.assertRaises(ValueError):
            toy_lattice_decapsulate(tampered_tag, private_key)
        tampered_u = ToyLatticeCiphertext(_encode_e(b"XXXXXXXX"), ciphertext.tag)
        with self.assertRaises(ValueError):
            toy_lattice_decapsulate(tampered_u, private_key)
        wrong_length = ToyLatticeCiphertext(ciphertext.u, ciphertext.tag + b"\x00")
        with self.assertRaises(ValueError):
            toy_lattice_decapsulate(wrong_length, private_key)

    def test_wrong_types(self):
        private_key, public_key = toy_lattice_keygen(token_bytes=fixed_tokens(b"abcdefgh"))
        ciphertext, _ = toy_lattice_encapsulate(
            public_key, token_bytes=fixed_tokens(b"r-r-r-r-")
        )
        for bad in (None, b"\x00" * 48, object(), public_key):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    toy_lattice_decapsulate(bad, private_key)
        for bad in (None, b"\x00" * 16, object(), public_key):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    toy_lattice_decapsulate(ciphertext, bad)


class SignatureValueObjectTest(unittest.TestCase):
    def test_positional_construction_and_equality(self):
        a = ToyLatticeSignature(b"\x00\x01" * 8, b"t" * 32)
        b = ToyLatticeSignature(b"\x00\x01" * 8, b"t" * 32)
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        self.assertIn(a, {b})
        self.assertNotEqual(a, ToyLatticeSignature(b"\x00\x02" * 8, b"t" * 32))
        self.assertNotEqual(a, ToyLatticeSignature(b"\x00\x01" * 8, b"u" * 32))
        self.assertNotEqual(a, ToyLatticeCiphertext(b"\x00\x01" * 8, b"t" * 32))

    def test_frozen(self):
        signature = ToyLatticeSignature(b"\x00" * 16, b"\x00" * 32)
        with self.assertRaises(FrozenInstanceError):
            signature.u = b"\x00" * 16
        with self.assertRaises(FrozenInstanceError):
            signature.tag = b"\x00" * 32

    def test_fields_reject_non_bytes(self):
        for bad in ("0123456789abcdef", bytearray(16), None, [0] * 16):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    ToyLatticeSignature(bad, b"\x00" * 32)
        for bad in ("x" * 32, bytearray(32), None, [0] * 32):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    ToyLatticeSignature(b"\x00" * 16, bad)

    def test_fields_reject_bad_values(self):
        with self.assertRaises(ValueError):
            ToyLatticeSignature(b"\x00" * 15, b"\x00" * 32)  # u too short
        with self.assertRaises(ValueError):
            ToyLatticeSignature(b"\x00" * 17, b"\x00" * 32)  # u too long
        with self.assertRaises(ValueError):
            ToyLatticeSignature(b"\x01\x01" + b"\x00" * 14, b"\x00" * 32)  # coeff 257
        for size in (0, 1, 31, 33, 64):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    ToyLatticeSignature(b"\x00" * 16, b"\x00" * size)


class SignTest(unittest.TestCase):
    def test_known_vectors(self):
        s = _encode_e((10, 20, 30, 40, 50, 60, 70, 80))
        private_key = ToyLatticePrivateKey(s)
        r = b"r-r-r-r-"
        message = b"hello"
        signature = toy_lattice_sign(
            message, private_key, token_bytes=fixed_tokens(r)
        )
        self.assertIsInstance(signature, ToyLatticeSignature)
        self.assertEqual(signature.u, _encode_e(r))
        chain = hashlib.sha256(b"S" + signature.u + message).digest()
        expected_tag = hmac.new(chain, b"S" + s, hashlib.sha256).digest()
        self.assertEqual(signature.tag, expected_tag)
        self.assertEqual(len(signature.tag), 32)

    def test_message_types_equivalent(self):
        private_key = ToyLatticePrivateKey(_encode_e((1, 2, 3, 4, 5, 6, 7, 8)))
        text = "héllo—世界"
        signatures = [
            toy_lattice_sign(text, private_key, token_bytes=fixed_tokens(b"r-r-r-r-")),
            toy_lattice_sign(
                text.encode("utf-8"), private_key, token_bytes=fixed_tokens(b"r-r-r-r-")
            ),
            toy_lattice_sign(
                bytearray(text.encode("utf-8")),
                private_key,
                token_bytes=fixed_tokens(b"r-r-r-r-"),
            ),
        ]
        self.assertEqual(signatures[0], signatures[1])
        self.assertEqual(signatures[0], signatures[2])

    def test_random_source_changes_signature_without_touching_key(self):
        s = _encode_e((1, 2, 3, 4, 5, 6, 7, 8))
        private_key = ToyLatticePrivateKey(s)
        first = toy_lattice_sign(b"m", private_key, token_bytes=fixed_tokens(b"aaaaaaaa"))
        second = toy_lattice_sign(b"m", private_key, token_bytes=fixed_tokens(b"bbbbbbbb"))
        self.assertNotEqual(first, second)
        self.assertEqual(private_key.s, s)

    def test_wrong_message_type(self):
        private_key = ToyLatticePrivateKey(b"\x00" * 16)
        for bad in (None, 123, [1, 2, 3], object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    toy_lattice_sign(bad, private_key)

    def test_wrong_private_key_type(self):
        public_key = ToyLatticePublicKey(b"\x00" * 16)
        for bad in (None, b"\x00" * 16, public_key, object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    toy_lattice_sign(b"m", bad)

    def test_token_source_rules(self):
        private_key = ToyLatticePrivateKey(b"\x00" * 16)
        with self.assertRaises(ValueError):
            toy_lattice_sign(b"m", private_key, token_bytes=lambda size: b"short")
        with self.assertRaises(ValueError):
            toy_lattice_sign(b"m", private_key, token_bytes=lambda size: b"x" * 9)
        for bad in (bytearray(8), [0] * 8, memoryview(b"\x00" * 8), None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    toy_lattice_sign(
                        b"m", private_key, token_bytes=lambda size: bad
                    )


class VerifyTest(unittest.TestCase):
    def _pair(self):
        return toy_lattice_keygen(token_bytes=fixed_tokens(b"abcdefgh"))

    def test_original_message_verifies_for_all_message_types(self):
        private_key, public_key = self._pair()
        text = "héllo—世界"
        signature = toy_lattice_sign(text, private_key, token_bytes=fixed_tokens(b"r-r-r-r-"))
        self.assertTrue(toy_lattice_verify(text, signature, public_key))
        self.assertTrue(toy_lattice_verify(text.encode("utf-8"), signature, public_key))
        self.assertTrue(
            toy_lattice_verify(bytearray(text.encode("utf-8")), signature, public_key)
        )

    def test_mismatches_return_false(self):
        private_key, public_key = self._pair()
        _, other_public = toy_lattice_keygen(
            token_bytes=fixed_tokens(bytes(range(1, 9)))
        )
        signature = toy_lattice_sign(
            b"hello", private_key, token_bytes=fixed_tokens(b"r-r-r-r-")
        )
        self.assertFalse(toy_lattice_verify(b"hellp", signature, public_key))
        self.assertFalse(toy_lattice_verify(b"", signature, public_key))
        self.assertFalse(toy_lattice_verify(b"hello", signature, other_public))
        wrong_u = ToyLatticeSignature(_encode_e(b"XXXXXXXX"), signature.tag)
        self.assertFalse(toy_lattice_verify(b"hello", wrong_u, public_key))
        wrong_tag = ToyLatticeSignature(signature.u, b"\x00" * 32)
        self.assertFalse(toy_lattice_verify(b"hello", wrong_tag, public_key))

    def test_bad_message_type_returns_false(self):
        _, public_key = self._pair()
        signature = ToyLatticeSignature(b"\x00" * 16, b"\x00" * 32)
        for bad in (None, 123, [1, 2, 3], object()):
            with self.subTest(bad=bad):
                self.assertFalse(toy_lattice_verify(bad, signature, public_key))

    def test_bad_signature_returns_false(self):
        private_key, public_key = self._pair()
        signature = toy_lattice_sign(
            b"hello", private_key, token_bytes=fixed_tokens(b"r-r-r-r-")
        )
        for bad in (
            None,
            signature.to_bytes(),
            b"\x00" * 61,
            42,
            ToyLatticeCiphertext(signature.u, signature.tag),
            object(),
        ):
            with self.subTest(bad=bad):
                self.assertFalse(toy_lattice_verify(b"hello", bad, public_key))

    def test_bypass_constructed_signature_returns_false(self):
        _, public_key = self._pair()
        for u, tag in (
            ("x" * 16, b"\x00" * 32),
            (b"\x00" * 16, "x" * 32),
            (b"\x00" * 15, b"\x00" * 32),
            (b"\x00" * 16, b"\x00" * 31),
            (None, None),
        ):
            broken = ToyLatticeSignature.__new__(ToyLatticeSignature)
            object.__setattr__(broken, "u", u)
            object.__setattr__(broken, "tag", tag)
            with self.subTest():
                self.assertFalse(toy_lattice_verify(b"hello", broken, public_key))

    def test_wrong_public_key_type_raises(self):
        private_key, public_key = self._pair()
        signature = toy_lattice_sign(
            b"hello", private_key, token_bytes=fixed_tokens(b"r-r-r-r-")
        )
        for bad in (None, b"\x00" * 16, private_key, object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    toy_lattice_verify(b"hello", signature, bad)


class ContextSignTest(unittest.TestCase):
    def _key(self):
        return ToyLatticePrivateKey(_encode_e((1, 2, 3, 4, 5, 6, 7, 8)))

    def test_empty_contexts_match_legacy_signature_byte_for_byte(self):
        private_key = self._key()
        legacy = toy_lattice_sign(
            b"hello", private_key, token_bytes=fixed_tokens(b"r-r-r-r-")
        )
        for empty in (None, b"", bytearray(), ""):
            with self.subTest(empty=repr(empty)):
                signed = toy_lattice_sign(
                    b"hello",
                    private_key,
                    token_bytes=fixed_tokens(b"r-r-r-r-"),
                    context=empty,
                )
                self.assertEqual(signed, legacy)
                self.assertEqual(signed.to_bytes(), legacy.to_bytes())

    def test_context_must_be_keyword(self):
        private_key = self._key()
        with self.assertRaises(TypeError):
            toy_lattice_sign(
                b"hello",
                private_key,
                fixed_tokens(b"r-r-r-r-"),
                b"app/1",
            )

    def test_context_types_equivalent(self):
        private_key = self._key()
        text = "app/世界"
        variants = (text, text.encode("utf-8"), bytearray(text.encode("utf-8")))
        signatures = [
            toy_lattice_sign(
                b"hello",
                private_key,
                token_bytes=fixed_tokens(b"r-r-r-r-"),
                context=context,
            )
            for context in variants
        ]
        for other in signatures[1:]:
            self.assertEqual(signatures[0], other)

    def test_non_empty_context_participates_in_binding(self):
        private_key = self._key()
        unbound = toy_lattice_sign(
            b"hello", private_key, token_bytes=fixed_tokens(b"r-r-r-r-")
        )
        bound = toy_lattice_sign(
            b"hello",
            private_key,
            token_bytes=fixed_tokens(b"r-r-r-r-"),
            context=b"app/1",
        )
        self.assertNotEqual(bound, unbound)
        # The tag, not just the random vector, changes.
        self.assertNotEqual(bound.tag, unbound.tag)

    def test_bound_signature_is_deterministic(self):
        private_key = self._key()
        first = toy_lattice_sign(
            b"hello",
            private_key,
            token_bytes=fixed_tokens(b"r-r-r-r-"),
            context=b"app/1",
        )
        second = toy_lattice_sign(
            b"hello",
            private_key,
            token_bytes=fixed_tokens(b"r-r-r-r-"),
            context="app/1",
        )
        self.assertEqual(first, second)
        self.assertEqual(first.to_bytes(), second.to_bytes())

    def test_bound_known_vectors(self):
        s = _encode_e((10, 20, 30, 40, 50, 60, 70, 80))
        private_key = ToyLatticePrivateKey(s)
        signature = toy_lattice_sign(
            b"hello",
            private_key,
            token_bytes=fixed_tokens(b"r-r-r-r-"),
            context=b"app/1",
        )
        message = b"hello"
        context = b"app/1"
        bound = (
            b"pqattest/toy-lattice/context/v1"
            + signature.u
            + len(context).to_bytes(4, "big")
            + context
            + len(message).to_bytes(4, "big")
            + message
        )
        chain = hashlib.sha256(b"S" + bound).digest()
        expected_tag = hmac.new(chain, b"S" + s, hashlib.sha256).digest()
        self.assertEqual(signature.tag, expected_tag)

    def test_bad_context_type_raises_type_error(self):
        private_key = self._key()
        for bad in (123, 3.5, [b"x"], (b"x",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    toy_lattice_sign(
                        b"hello",
                        private_key,
                        token_bytes=fixed_tokens(b"r-r-r-r-"),
                        context=bad,
                    )


class ContextVerifyTest(unittest.TestCase):
    def _pair(self):
        private_key, public_key = toy_lattice_keygen(
            token_bytes=fixed_tokens(b"abcdefgh")
        )
        return private_key, public_key

    def _bound(self, private_key, message=b"hello", context=b"app/1"):
        return toy_lattice_sign(
            message,
            private_key,
            token_bytes=fixed_tokens(b"r-r-r-r-"),
            context=context,
        )

    def test_matching_context_verifies_for_all_context_types(self):
        private_key, public_key = self._pair()
        text = "app/世界"
        signature = self._bound(private_key, context=text.encode("utf-8"))
        self.assertTrue(
            toy_lattice_verify(b"hello", signature, public_key, context=text)
        )
        self.assertTrue(
            toy_lattice_verify(
                b"hello", signature, public_key, context=text.encode("utf-8")
            )
        )
        self.assertTrue(
            toy_lattice_verify(
                b"hello", signature, public_key, context=bytearray(text.encode("utf-8"))
            )
        )

    def test_empty_context_verifies_legacy_signatures(self):
        private_key, public_key = self._pair()
        legacy = toy_lattice_sign(
            b"hello", private_key, token_bytes=fixed_tokens(b"r-r-r-r-")
        )
        for empty in (None, b"", bytearray(), ""):
            with self.subTest(empty=repr(empty)):
                self.assertTrue(
                    toy_lattice_verify(
                        b"hello", legacy, public_key, context=empty
                    )
                )

    def test_wrong_context_returns_false(self):
        private_key, public_key = self._pair()
        signature = self._bound(private_key)
        self.assertFalse(
            toy_lattice_verify(b"hello", signature, public_key, context=b"app/2")
        )
        # Legacy unbound verification must not accept a context-bound tag.
        self.assertFalse(toy_lattice_verify(b"hello", signature, public_key))
        self.assertFalse(
            toy_lattice_verify(b"hello", signature, public_key, context=b"")
        )

    def test_legacy_signature_rejected_under_non_empty_context(self):
        private_key, public_key = self._pair()
        legacy = toy_lattice_sign(
            b"hello", private_key, token_bytes=fixed_tokens(b"r-r-r-r-")
        )
        self.assertFalse(
            toy_lattice_verify(b"hello", legacy, public_key, context=b"app/1")
        )

    def test_context_does_not_authorise_other_fields(self):
        private_key, public_key = self._pair()
        _, other_public = toy_lattice_keygen(
            token_bytes=fixed_tokens(bytes(range(1, 9)))
        )
        signature = self._bound(private_key)
        # Same context, different message.
        self.assertFalse(
            toy_lattice_verify(b"hellp", signature, public_key, context=b"app/1")
        )
        # Same context, different public key.
        self.assertFalse(
            toy_lattice_verify(
                b"hello", signature, other_public, context=b"app/1"
            )
        )
        # Same context, tampered signature fields.
        wrong_u = ToyLatticeSignature(_encode_e(b"XXXXXXXX"), signature.tag)
        self.assertFalse(
            toy_lattice_verify(b"hello", wrong_u, public_key, context=b"app/1")
        )
        wrong_tag = ToyLatticeSignature(signature.u, b"\x00" * 32)
        self.assertFalse(
            toy_lattice_verify(b"hello", wrong_tag, public_key, context=b"app/1")
        )

    def test_context_must_be_keyword(self):
        _, public_key = self._pair()
        signature = ToyLatticeSignature(b"\x00" * 16, b"\x00" * 32)
        with self.assertRaises(TypeError):
            toy_lattice_verify(b"hello", signature, public_key, b"app/1")

    def test_bad_context_type_raises_type_error(self):
        _, public_key = self._pair()
        signature = ToyLatticeSignature(b"\x00" * 16, b"\x00" * 32)
        for bad in (123, 3.5, [b"x"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    toy_lattice_verify(
                        b"hello", signature, public_key, context=bad
                    )

    def test_bad_message_type_with_good_context_returns_false(self):
        _, public_key = self._pair()
        signature = ToyLatticeSignature(b"\x00" * 16, b"\x00" * 32)
        for bad in (None, 123, [1, 2, 3], object()):
            with self.subTest(bad=bad):
                self.assertFalse(
                    toy_lattice_verify(
                        bad, signature, public_key, context=b"app/1"
                    )
                )

    def test_bad_signature_with_good_context_returns_false(self):
        private_key, public_key = self._pair()
        signature = self._bound(private_key)
        for bad in (
            None,
            signature.to_bytes(),
            42,
            ToyLatticeCiphertext(signature.u, signature.tag),
            object(),
        ):
            with self.subTest(bad=bad):
                self.assertFalse(
                    toy_lattice_verify(
                        b"hello", bad, public_key, context=b"app/1"
                    )
                )


class SignatureSerializationTest(unittest.TestCase):
    def _signature(self):
        private_key, _ = toy_lattice_keygen(token_bytes=fixed_tokens(b"abcdefgh"))
        return toy_lattice_sign(
            b"hello", private_key, token_bytes=fixed_tokens(b"r-r-r-r-")
        )

    def test_wire_layout(self):
        signature = self._signature()
        blob = signature.to_bytes()
        self.assertEqual(len(blob), 61)
        self.assertEqual(blob[:8], b"PQALSG\0\0")
        self.assertEqual(blob[8], 1)
        self.assertEqual(blob[9:25], signature.u)
        self.assertEqual(int.from_bytes(blob[25:29], "big"), 32)
        self.assertEqual(blob[29:], signature.tag)
        # neither message nor key is carried
        self.assertNotIn(b"hello", blob)
        self.assertNotIn(b"abcdefgh", blob)

    def test_deterministic_encoding_and_roundtrip(self):
        signature = self._signature()
        self.assertEqual(signature.to_bytes(), signature.to_bytes())
        _, public_key = toy_lattice_keygen(token_bytes=fixed_tokens(b"abcdefgh"))
        for data in (signature.to_bytes(), bytearray(signature.to_bytes())):
            restored = ToyLatticeSignature.from_bytes(data)
            self.assertEqual(restored, signature)
            self.assertEqual(hash(restored), hash(signature))
            self.assertTrue(toy_lattice_verify(b"hello", restored, public_key))

    def test_to_bytes_rejects_corrupt_fields(self):
        good = self._signature()
        for u, tag in (
            ("x" * 16, good.tag),
            (b"\x00" * 15, good.tag),
            (b"\x01\x01" + b"\x00" * 14, good.tag),
            (good.u, "x" * 32),
            (good.u, b"\x00" * 31),
            (good.u, None),
            (None, None),
        ):
            broken = ToyLatticeSignature.__new__(ToyLatticeSignature)
            object.__setattr__(broken, "u", u)
            object.__setattr__(broken, "tag", tag)
            with self.subTest():
                with self.assertRaises(ValueError):
                    broken.to_bytes()

    def test_from_bytes_rejects_non_bytes(self):
        blob = self._signature().to_bytes()
        for bad in (blob.decode("latin-1"), None, 42, [blob], memoryview(blob)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    ToyLatticeSignature.from_bytes(bad)

    def test_from_bytes_rejects_bad_blobs(self):
        signature = self._signature()
        blob = signature.to_bytes()
        header = b"PQALSG\0\0" + bytes((1,)) + signature.u
        bad_blobs = {
            "bad magic": b"PQALXX\0\0" + blob[8:],
            "ciphertext magic": ToyLatticeCiphertext(signature.u, signature.tag).to_bytes(),
            "unknown version": blob[:8] + bytes((2,)) + blob[9:],
            "cut at magic": blob[:7],
            "cut in header": blob[:28],
            "cut in tag": blob[:60],
            "trailing byte": blob + b"\x00",
            "bad coefficient": blob[:9] + b"\x01\x01" + blob[11:],
            "tag length 31": header + (31).to_bytes(4, "big") + b"\x00" * 31,
            "tag length 33": header + (33).to_bytes(4, "big") + b"\x00" * 33,
            "tag length 0": header + (0).to_bytes(4, "big"),
            "length says 32 but short": header + (32).to_bytes(4, "big") + b"\x00" * 31,
        }
        for label, bad in bad_blobs.items():
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    ToyLatticeSignature.from_bytes(bad)


if __name__ == "__main__":
    unittest.main()

import hashlib
import unittest
from unittest import mock

import pqattest
from pqattest import (
    BITS,
    HASH_BYTES,
    PrivateKey as LamportPrivateKey,
    PublicKey as LamportPublicKey,
    WOTSPrivateKey,
    WOTSPublicKey,
    wots_keygen,
    wots_sign,
    wots_verify,
)


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def reference_digits(message: bytes, w: int):
    """Independent textbook reference: big-endian base-B digits plus checksum."""
    base = 1 << w
    l1 = BITS // w
    integer = int.from_bytes(hashlib.sha256(message).digest(), "big")
    message_digits = [(integer >> (w * (l1 - 1 - i))) & (base - 1) for i in range(l1)]
    checksum = sum(base - 1 - d for d in message_digits)
    l2 = 1
    while base ** l2 <= l1 * (base - 1):
        l2 += 1
    checksum_digits = [(checksum >> (w * (l2 - 1 - i))) & (base - 1) for i in range(l2)]
    return message_digits + checksum_digits, base


def reference_walk(start: bytes, steps: int, w: int) -> bytes:
    value = start
    for _ in range(steps):
        value = hashlib.sha256(b"pqattest/wots/v1" + value).digest()
    return value


class WOTSParamsTest(unittest.TestCase):
    def test_chain_counts(self):
        # w=4: 64 message digits, l2=3 (16^2 <= 960 < 16^3)
        priv4, pub4 = wots_keygen(w=4, token_bytes=counter_tokens())
        self.assertEqual(priv4.w, 4)
        self.assertEqual(pub4.w, 4)
        self.assertEqual(len(priv4.elements), 67)
        self.assertEqual(len(pub4.elements), 67)
        # w=8: 32 message digits, l2=2 (256 <= 8160 < 65536)
        priv8, pub8 = wots_keygen(w=8, token_bytes=counter_tokens())
        self.assertEqual(priv8.w, 8)
        self.assertEqual(pub8.w, 8)
        self.assertEqual(len(priv8.elements), 34)
        self.assertEqual(len(pub8.elements), 34)

    def test_elements_are_fixed_size_bytes_tuples(self):
        for w in (4, 8):
            priv, pub = wots_keygen(w=w, token_bytes=counter_tokens())
            self.assertIsInstance(priv.elements, tuple)
            self.assertIsInstance(pub.elements, tuple)
            for key in (priv, pub):
                for element in key.elements:
                    self.assertIsInstance(element, bytes)
                    self.assertEqual(len(element), HASH_BYTES)

    def test_public_endpoints_are_step_b_minus_1_walks(self):
        for w in (4, 8):
            priv, pub = wots_keygen(w=w, token_bytes=counter_tokens())
            base = 1 << w
            for index, start in enumerate(priv.elements):
                self.assertEqual(reference_walk(start, base - 1, w), pub.elements[index])

    def test_starts_are_distinct(self):
        priv, _ = wots_keygen(w=4, token_bytes=counter_tokens())
        self.assertEqual(len(set(priv.elements)), len(priv.elements))

    def test_default_width_is_four(self):
        priv, pub = wots_keygen(token_bytes=counter_tokens())
        self.assertEqual(priv.w, 4)
        self.assertEqual(len(priv.elements), 67)
        self.assertEqual(pub, WOTSPublicKey(4, pub.elements))


class WOTSSignVerifyTest(unittest.TestCase):
    MESSAGE = "position claim: -73.9857,40.7484"

    def test_honest_signature_verifies_at_both_widths(self):
        message = self.MESSAGE
        for w in (4, 8):
            with self.subTest(w=w):
                priv, pub = wots_keygen(w=w, token_bytes=counter_tokens())
                signature = wots_sign(message, priv)
                self.assertIsInstance(signature, tuple)
                self.assertTrue(wots_verify(message, signature, pub))

    def test_signature_matches_independent_reference(self):
        message = b"position claim"
        for w in (4, 8):
            with self.subTest(w=w):
                priv, _ = wots_keygen(w=w, token_bytes=counter_tokens())
                digits, _ = reference_digits(message, w)
                signature = wots_sign(message, priv)
                self.assertEqual(len(signature), len(digits))
                for index, digit in enumerate(digits):
                    self.assertEqual(
                        signature[index],
                        reference_walk(priv.elements[index], digit, w),
                    )

    def test_message_type_variants_agree(self):
        for message in (b"x", bytearray(b"x"), "x"):
            with self.subTest(message=message):
                priv, pub = wots_keygen(w=4, token_bytes=counter_tokens())
                signature = wots_sign(message, priv)
                self.assertTrue(wots_verify(b"x", signature, pub))
                self.assertEqual(signature, wots_sign("x", priv))

    def test_signature_is_deterministic(self):
        priv, _ = wots_keygen(w=8, token_bytes=counter_tokens())
        self.assertEqual(wots_sign("m", priv), wots_sign("m", priv))

    def test_different_message_fails(self):
        priv, pub = wots_keygen(token_bytes=counter_tokens())
        signature = wots_sign("m", priv)
        self.assertFalse(wots_verify("m!", signature, pub))

    def test_tampered_part_fails(self):
        priv, pub = wots_keygen(w=8, token_bytes=counter_tokens())
        signature = list(wots_sign("m", priv))
        signature[0] = bytes(HASH_BYTES)
        self.assertFalse(wots_verify("m", signature, pub))

    def test_wrong_length_signature_fails(self):
        priv, pub = wots_keygen(w=4, token_bytes=counter_tokens())
        signature = wots_sign("m", priv)
        self.assertFalse(wots_verify("m", signature[:-1], pub))
        self.assertFalse(wots_verify("m", signature + (bytes(HASH_BYTES),), pub))

    def test_wrong_sized_part_fails(self):
        priv, pub = wots_keygen(w=4, token_bytes=counter_tokens())
        signature = list(wots_sign("m", priv))
        signature[-1] = b"too short"
        self.assertFalse(wots_verify("m", signature, pub))

    def test_non_bytes_part_fails_without_raising(self):
        priv, pub = wots_keygen(w=4, token_bytes=counter_tokens())
        signature = list(wots_sign("m", priv))
        signature[0] = 12345
        self.assertFalse(wots_verify("m", signature, pub))

    def test_non_iterable_signature_fails(self):
        _, pub = wots_keygen(token_bytes=counter_tokens())
        self.assertFalse(wots_verify("m", 12345, pub))
        self.assertFalse(wots_verify("m", None, pub))

    def test_cross_key_does_not_verify(self):
        priv, pub = wots_keygen(w=8, token_bytes=counter_tokens())
        other_priv, other_pub = wots_keygen(w=8, token_bytes=counter_tokens(start=999))
        signature = wots_sign("m", other_priv)
        self.assertFalse(wots_verify("m", signature, pub))
        self.assertTrue(wots_verify("m", signature, other_pub))

    def test_tampered_public_element_fails(self):
        priv, pub = wots_keygen(w=4, token_bytes=counter_tokens())
        signature = wots_sign("m", priv)
        bad_elements = list(pub.elements)
        bad_elements[5] = bytes(HASH_BYTES)
        bad_pub = WOTSPublicKey(4, tuple(bad_elements))
        self.assertFalse(wots_verify("m", signature, bad_pub))

    def test_width_mismatch_fails(self):
        priv4, _ = wots_keygen(w=4, token_bytes=counter_tokens())
        _, pub8 = wots_keygen(w=8, token_bytes=counter_tokens())
        signature = wots_sign("m", priv4)
        self.assertFalse(wots_verify("m", signature, pub8))

    def test_accepts_list_and_bytearray_parts(self):
        priv, pub = wots_keygen(w=4, token_bytes=counter_tokens())
        signature = wots_sign("m", priv)
        as_lists = [bytearray(part) for part in signature]
        self.assertTrue(wots_verify("m", as_lists, pub))


class WOTSChecksumLeadingZerosTest(unittest.TestCase):
    def test_all_ones_digest_gives_zero_checksum_with_leading_zeros(self):
        # Every message digit is B-1, so the checksum is 0: all l2 checksum
        # digits are leading zeros and the signature still has fixed length.
        for w, count in ((4, 67), (8, 34)):
            with self.subTest(w=w):
                priv, pub = wots_keygen(w=w, token_bytes=counter_tokens())
                with mock.patch.object(pqattest, "message_digest", return_value=b"\xff" * 32):
                    l1, l2, _ = pqattest._wots_params(w)
                    _, checksum_digits = pqattest._wots_digits("m", w)
                    self.assertEqual(checksum_digits, (0,) * l2)
                    signature = wots_sign("m", priv)
                    self.assertEqual(len(signature), count)
                    self.assertTrue(wots_verify("m", signature, pub))
                    # zero steps on checksum chains -> raw chain starts
                    for index in range(l1, l1 + l2):
                        self.assertEqual(signature[index], priv.elements[index])

    def test_all_zero_digest_gives_maximum_checksum(self):
        # Every message digit is 0, so the checksum is l1*(B-1); it must be
        # packed into exactly l2 digits and still verify end to end.
        for w in (4, 8):
            with self.subTest(w=w):
                priv, pub = wots_keygen(w=w, token_bytes=counter_tokens())
                with mock.patch.object(pqattest, "message_digest", return_value=b"\x00" * 32):
                    l1, l2, base = pqattest._wots_params(w)
                    _, checksum_digits = pqattest._wots_digits("m", w)
                    self.assertEqual(len(checksum_digits), l2)
                    self.assertEqual(
                        sum(d * base ** (l2 - 1 - i) for i, d in enumerate(checksum_digits)),
                        l1 * (base - 1),
                    )
                    signature = wots_sign("m", priv)
                    self.assertTrue(wots_verify("m", signature, pub))


class WOTSKeyObjectTest(unittest.TestCase):
    def test_keys_are_frozen_value_objects(self):
        priv, pub = wots_keygen(token_bytes=counter_tokens())
        self.assertEqual(priv, WOTSPrivateKey(4, priv.elements))
        self.assertEqual(pub, WOTSPublicKey(4, pub.elements))
        self.assertEqual(hash(priv), hash(WOTSPrivateKey(4, priv.elements)))
        for key in (priv, pub):
            with self.assertRaises(AttributeError):
                key.w = 8
            with self.assertRaises(TypeError):
                key.elements[0] = bytes(HASH_BYTES)

    def test_invalid_width_rejected(self):
        for bad in (2, 16, 0, -4, None, "4", 4.0, True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    wots_keygen(w=bad)

    def test_short_token_rejected(self):
        with self.assertRaises(ValueError):
            wots_keygen(w=4, token_bytes=lambda size: b"short")
        with self.assertRaises(ValueError):
            wots_keygen(w=8, token_bytes=lambda size: bytes(HASH_BYTES - 1))

    def test_verify_swallows_malformed_key_parameters(self):
        priv, _ = wots_keygen(w=4, token_bytes=counter_tokens())
        signature = wots_sign("m", priv)
        self.assertFalse(wots_verify("m", signature, WOTSPublicKey(3, ())))
        self.assertFalse(wots_verify("m", signature, WOTSPublicKey(4, ())))
        bad_elements = (bytes(HASH_BYTES),) * 66
        self.assertFalse(wots_verify("m", signature, WOTSPublicKey(4, bad_elements)))
        short_elements = (b"x",) * 67
        self.assertFalse(wots_verify("m", signature, WOTSPublicKey(4, short_elements)))

    def test_sign_with_malformed_key_width_raises_value_error(self):
        forged = WOTSPrivateKey(5, tuple(bytes(HASH_BYTES) for _ in range(67)))
        with self.assertRaises(ValueError):
            wots_sign("m", forged)


class WOSTypeErrorTest(unittest.TestCase):
    def test_sign_requires_wots_private_key(self):
        for bad in (object(), None, 42, "key", LamportPrivateKey(()), WOTSPublicKey(4, ())):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    wots_sign("m", bad)

    def test_verify_requires_wots_public_key(self):
        for bad in (object(), None, 42, "key", LamportPublicKey(()), WOTSPrivateKey(4, ())):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    wots_verify("m", (), bad)


class WOTSWithLamportCoexistenceTest(unittest.TestCase):
    def test_lamport_and_wots_share_the_package(self):
        from pqattest import keygen, sign, verify

        lamport_priv, lamport_pub = keygen(bits=16, token_bytes=counter_tokens())
        lamport_signature = sign("m", lamport_priv)
        self.assertTrue(verify("m", lamport_signature, lamport_pub))

        wots_priv, wots_pub = wots_keygen(w=4, token_bytes=counter_tokens(start=100))
        wots_signature = wots_sign("m", wots_priv)
        self.assertTrue(wots_verify("m", wots_signature, wots_pub))
        # neither signature is accepted by the other construction
        self.assertFalse(wots_verify("m", lamport_signature, wots_pub))
        self.assertNotIsInstance(lamport_priv, WOTSPrivateKey)
        self.assertNotIsInstance(wots_priv, LamportPrivateKey)


if __name__ == "__main__":
    unittest.main()

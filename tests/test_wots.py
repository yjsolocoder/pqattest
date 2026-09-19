import hashlib
import unittest

from pqattest import (
    PrivateKey as LamportPrivateKey,
    PublicKey as LamportPublicKey,
    WOTSPrivateKey,
    WOTSPublicKey,
    wots_keygen,
    wots_sign,
    wots_verify,
)
from pqattest.wots import (
    _chain_walk,
    _checksum_digits,
    _message_digits,
    _params,
    _signing_digits,
)


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


class ParameterTest(unittest.TestCase):
    def test_chain_counts(self):
        # w=4: l1=64, max checksum 960 -> 16**3 > 960, so l2=3
        self.assertEqual(_params(4), (16, 64, 3))
        # w=8: l1=32, max checksum 8160 -> 256**2 > 8160, so l2=2
        self.assertEqual(_params(8), (256, 32, 2))

    def test_default_w_is_4(self):
        private_key, public_key = wots_keygen(token_bytes=counter_tokens())
        self.assertEqual(private_key.w, 4)
        self.assertEqual(public_key.w, 4)

    def test_invalid_w_rejected(self):
        for bad_w in (2, 16, 32, 0, -4, 4.0, None, True, "4"):
            with self.subTest(bad_w=bad_w):
                with self.assertRaises(ValueError):
                    wots_keygen(w=bad_w)

    def test_invalid_w_on_direct_construction(self):
        with self.assertRaises(ValueError):
            WOTSPrivateKey(w=2, elements=(b"\x00" * 32,) * 133)
        with self.assertRaises(ValueError):
            WOTSPublicKey(w=16, elements=(b"\x00" * 32,) * 34)

    def test_token_length_enforced(self):
        with self.assertRaises(ValueError):
            wots_keygen(token_bytes=lambda size: b"short")
        with self.assertRaises(ValueError):
            wots_keygen(w=8, token_bytes=lambda size: b"")


class KeyShapeTest(unittest.TestCase):
    def test_w4_shapes(self):
        private_key, public_key = wots_keygen(w=4, token_bytes=counter_tokens())
        self.assertEqual(len(private_key.elements), 67)
        self.assertEqual(len(public_key.elements), 67)
        self.assertEqual(private_key.length, 67)
        self.assertEqual(public_key.length, 67)
        for element in private_key.elements + public_key.elements:
            self.assertIsInstance(element, bytes)
            self.assertEqual(len(element), 32)

    def test_w8_shapes(self):
        private_key, public_key = wots_keygen(w=8, token_bytes=counter_tokens())
        self.assertEqual(len(private_key.elements), 34)
        self.assertEqual(len(public_key.elements), 34)

    def test_public_endpoints_are_chain_tips(self):
        for w in (4, 8):
            with self.subTest(w=w):
                private_key, public_key = wots_keygen(w=w, token_bytes=counter_tokens())
                b = 1 << w
                for start, endpoint in zip(private_key.elements, public_key.elements):
                    self.assertEqual(_chain_walk(start, b - 1), endpoint)
                    self.assertNotEqual(start, endpoint)

    def test_chain_step_uses_domain_prefix(self):
        x = b"\x01" * 32
        self.assertEqual(
            _chain_walk(x, 1), hashlib.sha256(b"pqattest/wots/v1" + x).digest()
        )

    def test_keys_are_frozen(self):
        private_key, public_key = wots_keygen(token_bytes=counter_tokens())
        with self.assertRaises(AttributeError):
            private_key.w = 8
        with self.assertRaises(AttributeError):
            public_key.elements = ()

    def test_keys_are_value_objects(self):
        first_private, first_public = wots_keygen(w=4, token_bytes=counter_tokens())
        second_private, second_public = wots_keygen(w=4, token_bytes=counter_tokens())
        self.assertEqual(first_private, second_private)
        self.assertEqual(first_public, second_public)

    def test_bad_element_container(self):
        with self.assertRaises(TypeError):
            WOTSPrivateKey(w=4, elements=[b"\x00" * 32] * 67)
        with self.assertRaises(TypeError):
            WOTSPublicKey(w=8, elements=[b"\x00" * 32] * 34)

    def test_bad_element_count_or_size(self):
        with self.assertRaises(ValueError):
            WOTSPrivateKey(w=4, elements=(b"\x00" * 32,) * 66)
        with self.assertRaises(ValueError):
            WOTSPrivateKey(w=8, elements=(b"\x00" * 32,) * 36)
        with self.assertRaises(ValueError):
            WOTSPrivateKey(w=4, elements=(b"short",) + (b"\x00" * 32,) * 66)


class DigitEncodingTest(unittest.TestCase):
    def test_digest_split_is_big_endian(self):
        # w=4: first nibble of the digest
        digest = bytes([0xAB]) + b"\x00" * 31
        digits = _message_digits(digest, 4, 16, 64)
        self.assertEqual(digits[:2], (0xA, 0xB))
        self.assertEqual(set(digits[2:]), {0})

    def test_digest_split_w8(self):
        digest = bytes([0x12, 0x34]) + b"\x00" * 30
        digits = _message_digits(digest, 8, 256, 32)
        self.assertEqual(digits[:2], (0x12, 0x34))
        self.assertEqual(set(digits[2:]), {0})

    def test_checksum_keeps_leading_zeros(self):
        # all digits maximal -> checksum 0, still emitted with fixed width
        self.assertEqual(_checksum_digits([15] * 64, 4, 16, 3), (0, 0, 0))
        self.assertEqual(_checksum_digits([255] * 32, 8, 256, 2), (0, 0))

    def test_checksum_small_value_is_zero_padded(self):
        # exactly one unit of checksum -> value 1
        self.assertEqual(_checksum_digits([14] + [15] * 63, 4, 16, 3), (0, 0, 1))
        self.assertEqual(_checksum_digits([254] + [255] * 31, 8, 256, 2), (0, 1))

    def test_checksum_maximum_fills_all_digits(self):
        # all digits zero -> checksum = l1 * (B - 1)
        self.assertEqual(_checksum_digits([0] * 64, 4, 16, 3), (3, 12, 0))  # 960
        self.assertEqual(_checksum_digits([0] * 32, 8, 256, 2), (31, 224))  # 8160

    def test_signing_digits_append_checksum(self):
        for w in (4, 8):
            with self.subTest(w=w):
                _, l1, l2 = _params(w)
                digits = _signing_digits("abc", w)
                self.assertEqual(len(digits), l1 + l2)
                message_part = digits[:l1]
                self.assertEqual(digits[l1:], _checksum_digits(message_part, w, 1 << w, l2))


class SignVerifyTest(unittest.TestCase):
    def test_honest_signature_round_trips_both_w(self):
        for w in (4, 8):
            with self.subTest(w=w):
                private_key, public_key = wots_keygen(w=w, token_bytes=counter_tokens())
                for message in (b"position claim", bytearray(b"position claim"), "position claim"):
                    signature = wots_sign(message, private_key)
                    self.assertIsInstance(signature, tuple)
                    self.assertEqual(len(signature), public_key.length)
                    self.assertTrue(wots_verify(message, signature, public_key))

    def test_str_and_bytes_agree(self):
        private_key, public_key = wots_keygen(token_bytes=counter_tokens())
        self.assertEqual(wots_sign("abc", private_key), wots_sign(b"abc", private_key))

    def test_signature_is_immutable_tuple(self):
        private_key, _ = wots_keygen(token_bytes=counter_tokens())
        signature = wots_sign("m", private_key)
        self.assertIsInstance(signature, tuple)
        with self.assertRaises(TypeError):
            signature[0] = b"\x00" * 32

    def test_known_answer_construction(self):
        private_key, public_key = wots_keygen(w=4, token_bytes=counter_tokens())
        message = "position claim"
        digits = _signing_digits(message, 4)
        signature = wots_sign(message, private_key)
        for index, digit in enumerate(digits):
            self.assertEqual(signature[index], _chain_walk(private_key.elements[index], digit))
            self.assertEqual(
                _chain_walk(signature[index], 15 - digit), public_key.elements[index]
            )

    def test_step_zero_value_revealed_for_zero_checksum_digit(self):
        # Search for a message whose *trailing* checksum digit is 0; the
        # signature must then reveal the raw chain start (zero remaining
        # steps), exercising leading/trailing zero handling end to end.
        for w, probes in ((4, 200), (8, 2000)):
            with self.subTest(w=w):
                private_key, public_key = wots_keygen(w=w, token_bytes=counter_tokens())
                _, l1, l2 = _params(w)
                message = None
                for i in range(probes):
                    candidate = f"probe-{i}"
                    digits = _signing_digits(candidate, w)
                    if digits[-1] == 0:
                        message = candidate
                        break
                self.assertIsNotNone(message, "could not find a zero checksum digit")
                signature = wots_sign(message, private_key)
                self.assertEqual(signature[l1 + l2 - 1], private_key.elements[l1 + l2 - 1])
                self.assertTrue(wots_verify(message, signature, public_key))

    def test_deterministic_signatures(self):
        private_key, _ = wots_keygen(token_bytes=counter_tokens())
        self.assertEqual(wots_sign("m", private_key), wots_sign("m", private_key))

    def test_different_message_fails(self):
        for w in (4, 8):
            with self.subTest(w=w):
                private_key, public_key = wots_keygen(w=w, token_bytes=counter_tokens())
                signature = wots_sign("position claim", private_key)
                self.assertFalse(wots_verify("position claim!", signature, public_key))

    def test_tampered_element_fails(self):
        for w in (4, 8):
            with self.subTest(w=w):
                private_key, public_key = wots_keygen(w=w, token_bytes=counter_tokens())
                signature = list(wots_sign("m", private_key))
                tampered = bytearray(signature[0])
                tampered[0] ^= 0x01
                signature[0] = bytes(tampered)
                self.assertFalse(wots_verify("m", signature, public_key))

    def test_truncated_and_extended_signatures_fail(self):
        private_key, public_key = wots_keygen(token_bytes=counter_tokens())
        signature = wots_sign("m", private_key)
        self.assertFalse(wots_verify("m", signature[:-1], public_key))
        self.assertFalse(wots_verify("m", signature + (b"\x00" * 32,), public_key))

    def test_undersized_element_fails(self):
        private_key, public_key = wots_keygen(token_bytes=counter_tokens())
        signature = list(wots_sign("m", private_key))
        signature[0] = b"short"
        self.assertFalse(wots_verify("m", signature, public_key))

    def test_non_bytes_element_fails(self):
        private_key, public_key = wots_keygen(token_bytes=counter_tokens())
        signature = list(wots_sign("m", private_key))
        signature[0] = object()
        self.assertFalse(wots_verify("m", signature, public_key))

    def test_non_iterable_signature_fails(self):
        _, public_key = wots_keygen(token_bytes=counter_tokens())
        self.assertFalse(wots_verify("m", object(), public_key))
        self.assertFalse(wots_verify("m", 42, public_key))

    def test_malformed_element_bytes_fails(self):
        private_key, public_key = wots_keygen(token_bytes=counter_tokens())
        signature = list(wots_sign("m", private_key))
        signature[0] = [300]  # bytes([300]) raises ValueError
        self.assertFalse(wots_verify("m", signature, public_key))

    def test_different_keys_do_not_cross_verify(self):
        for w in (4, 8):
            with self.subTest(w=w):
                private_key, public_key = wots_keygen(w=w, token_bytes=counter_tokens())
                other_private, other_public = wots_keygen(
                    w=w, token_bytes=counter_tokens(start=1000)
                )
                signature = wots_sign("m", other_private)
                self.assertFalse(wots_verify("m", signature, public_key))
                self.assertTrue(wots_verify("m", signature, other_public))

    def test_w_mismatch_fails(self):
        private4, _ = wots_keygen(w=4, token_bytes=counter_tokens())
        _, public8 = wots_keygen(w=8, token_bytes=counter_tokens())
        signature = wots_sign("m", private4)
        # 67 w=4 parts cannot match the 34-element w=8 public key
        self.assertFalse(wots_verify("m", signature, public8))

    def test_signature_replayed_as_start_fails(self):
        # An endpoint (step B-1) substituted for a lower-step value is rejected.
        private_key, public_key = wots_keygen(w=4, token_bytes=counter_tokens())
        signature = list(wots_sign("m", private_key))
        signature[0] = public_key.elements[0]
        self.assertFalse(wots_verify("m", signature, public_key))

    def test_stateless_api_has_no_reuse_tracking(self):
        # One-time safety is the caller's responsibility: signing twice with
        # the same key still produces two individually verifying signatures.
        private_key, public_key = wots_keygen(token_bytes=counter_tokens())
        first = wots_sign("one", private_key)
        second = wots_sign("two", private_key)
        self.assertNotEqual(first, second)
        self.assertTrue(wots_verify("one", first, public_key))
        self.assertTrue(wots_verify("two", second, public_key))


class TypeErrorTest(unittest.TestCase):
    def test_sign_requires_wots_private_key(self):
        _, public_key = wots_keygen(token_bytes=counter_tokens())
        for bad_key in (object(), None, "not a key", public_key, LamportPrivateKey(())):
            with self.subTest(bad_key=type(bad_key).__name__):
                with self.assertRaises(TypeError):
                    wots_sign("m", bad_key)

    def test_verify_requires_wots_public_key(self):
        private_key, _ = wots_keygen(token_bytes=counter_tokens())
        signature = wots_sign("m", private_key)
        for bad_key in (object(), None, "not a key", private_key, LamportPublicKey(())):
            with self.subTest(bad_key=type(bad_key).__name__):
                with self.assertRaises(TypeError):
                    wots_verify("m", signature, bad_key)

    def test_bad_message_type_raises(self):
        private_key, public_key = wots_keygen(token_bytes=counter_tokens())
        with self.assertRaises(TypeError):
            wots_sign(123, private_key)
        # Any mismatch other than a wrong key type returns False, including a
        # non-message value paired with an otherwise well-formed signature.
        self.assertFalse(wots_verify(123, (), public_key))
        signature = wots_sign("m", private_key)
        self.assertFalse(wots_verify(123, signature, public_key))


if __name__ == "__main__":
    unittest.main()

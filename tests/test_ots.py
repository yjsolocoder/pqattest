import unittest

from pqattest import (
    BITS,
    HASH_BYTES,
    PrivateKey,
    PublicKey,
    keygen,
    message_bits,
    message_digest,
    public_key_from,
    sign,
    verify,
)


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


class DigestTest(unittest.TestCase):
    def test_str_and_bytes_agree(self):
        self.assertEqual(message_digest("abc"), message_digest(b"abc"))

    def test_digest_length(self):
        self.assertEqual(len(message_digest("abc")), HASH_BYTES)

    def test_unsupported_message_rejected(self):
        with self.assertRaises(TypeError):
            message_digest(123)

    def test_bits_are_binary_and_ordered(self):
        bits = message_bits("abc")
        self.assertEqual(len(bits), BITS)
        self.assertTrue(set(bits) <= {0, 1})

    def test_bits_match_manual_extraction(self):
        digest = message_digest("abc")
        expected = tuple((digest[i >> 3] >> (7 - (i & 7))) & 1 for i in range(8))
        self.assertEqual(message_bits("abc", bits=8), expected)

    def test_bit_count_bounds(self):
        with self.assertRaises(ValueError):
            message_bits("abc", bits=0)
        with self.assertRaises(ValueError):
            message_bits("abc", bits=BITS + 1)


class KeygenTest(unittest.TestCase):
    def test_key_sizes(self):
        private_key, public_key = keygen(bits=16, token_bytes=counter_tokens())
        self.assertEqual(len(private_key.secrets), 32)
        self.assertEqual(len(public_key.digests), 32)
        self.assertEqual(private_key.bits, 16)

    def test_public_key_recomputes(self):
        private_key, public_key = keygen(bits=16, token_bytes=counter_tokens())
        self.assertEqual(public_key_from(private_key), public_key)

    def test_secrets_are_distinct(self):
        private_key, _ = keygen(bits=16, token_bytes=counter_tokens())
        self.assertEqual(len(set(private_key.secrets)), 32)

    def test_public_digests_differ_from_secrets(self):
        private_key, public_key = keygen(bits=8, token_bytes=counter_tokens())
        self.assertTrue(set(public_key.digests).isdisjoint(set(private_key.secrets)))

    def test_bit_count_bounds(self):
        with self.assertRaises(ValueError):
            keygen(bits=0)
        with self.assertRaises(ValueError):
            keygen(bits=BITS + 1)

    def test_token_size_enforced(self):
        with self.assertRaises(ValueError):
            keygen(bits=4, token_bytes=lambda size: b"short")


class SignVerifyTest(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = keygen(bits=32, token_bytes=counter_tokens())
        self.message = "position claim"

    def test_signature_length_matches_bits(self):
        self.assertEqual(len(sign(self.message, self.private_key)), 32)

    def test_honest_signature_verifies(self):
        self.assertTrue(verify(self.message, sign(self.message, self.private_key), self.public_key))

    def test_revealed_secret_matches_the_digest_bit(self):
        signature = sign(self.message, self.private_key)
        for index, bit in enumerate(message_bits(self.message, bits=32)):
            self.assertIn(signature[index], self.private_key.secrets[2 * index + bit : 2 * index + bit + 1])

    def test_different_message_fails(self):
        signature = sign(self.message, self.private_key)
        self.assertFalse(verify(self.message + "!", signature, self.public_key))

    def test_tampered_part_fails(self):
        signature = list(sign(self.message, self.private_key))
        signature[0] = bytes(HASH_BYTES)
        self.assertFalse(verify(self.message, signature, self.public_key))

    def test_truncated_signature_fails(self):
        signature = sign(self.message, self.private_key)
        self.assertFalse(verify(self.message, signature[:-1], self.public_key))

    def test_same_message_signs_identically(self):
        self.assertEqual(sign(self.message, self.private_key), sign(self.message, self.private_key))

    def test_different_keys_do_not_cross_verify(self):
        other_private, other_public = keygen(bits=32, token_bytes=counter_tokens(start=1000))
        signature = sign(self.message, other_private)
        self.assertFalse(verify(self.message, signature, self.public_key))
        self.assertTrue(verify(self.message, signature, other_public))

    def test_default_parameters_work(self):
        private_key, public_key = keygen(token_bytes=counter_tokens())
        signature = sign("x", private_key)
        self.assertEqual(len(signature), BITS)
        self.assertTrue(verify("x", signature, public_key))


class TypeTest(unittest.TestCase):
    def test_sign_requires_private_key(self):
        with self.assertRaises(TypeError):
            sign("m", PublicKey(()))

    def test_verify_requires_public_key(self):
        with self.assertRaises(TypeError):
            verify("m", (), PrivateKey(()))


if __name__ == "__main__":
    unittest.main()

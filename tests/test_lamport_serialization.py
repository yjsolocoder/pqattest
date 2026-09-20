import unittest

import pqattest
from pqattest import (
    PrivateKey,
    PublicKey,
    keygen,
    lamport_signature_from_bytes,
    lamport_signature_to_bytes,
    public_key_from,
    sign,
    verify,
)
from pqattest import (
    _PRIVATE_KEY_MAGIC,
    _PUBLIC_KEY_MAGIC,
    _SIGNATURE_MAGIC,
)


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_keys(bits=8, start=0):
    return keygen(bits=bits, token_bytes=counter_tokens(start))


class PrivateKeyFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for bits in (1, 8, 256):
            with self.subTest(bits=bits):
                private_key, _ = make_keys(bits=bits)
                blob = private_key.to_bytes()
                self.assertEqual(len(blob), 8 + 1 + 2 + 2 + 2 * bits * 32)
                self.assertEqual(blob[:8], _PRIVATE_KEY_MAGIC)
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(int.from_bytes(blob[9:11], "big"), bits)
                self.assertEqual(int.from_bytes(blob[11:13], "big"), 2 * bits)
                self.assertEqual(blob[13:], b"".join(private_key.secrets))

    def test_to_bytes_returns_bytes(self):
        private_key, _ = make_keys()
        self.assertIsInstance(private_key.to_bytes(), bytes)

    def test_encoding_is_deterministic(self):
        private_key, _ = make_keys()
        self.assertEqual(private_key.to_bytes(), private_key.to_bytes())


class PrivateKeyRoundTripTest(unittest.TestCase):
    def test_round_trip(self):
        for bits in (1, 2, 8, 256):
            with self.subTest(bits=bits):
                private_key, public_key = make_keys(bits=bits)
                restored = PrivateKey.from_bytes(private_key.to_bytes())
                self.assertEqual(restored, private_key)
                self.assertEqual(restored.to_bytes(), private_key.to_bytes())
                self.assertEqual(public_key_from(restored), public_key)

    def test_accepts_bytearray(self):
        private_key, _ = make_keys()
        restored = PrivateKey.from_bytes(bytearray(private_key.to_bytes()))
        self.assertEqual(restored, private_key)

    def test_restored_key_still_signs(self):
        private_key, public_key = make_keys()
        restored = PrivateKey.from_bytes(private_key.to_bytes())
        signature = sign("message", restored)
        self.assertTrue(verify("message", signature, public_key))


class PrivateKeyValidationTest(unittest.TestCase):
    def setUp(self):
        self.private_key, _ = make_keys()
        self.blob = self.private_key.to_bytes()

    def test_non_bytes_types_raise_type_error(self):
        for bad in (None, 42, 4.5, "key", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    PrivateKey.from_bytes(bad)

    def test_truncated_and_empty_rejected(self):
        for cut in (0, 7, 12, 13, len(self.blob) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    PrivateKey.from_bytes(self.blob[:cut])

    def test_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            PrivateKey.from_bytes(self.blob + b"\x00")

    def test_bad_magic_rejected(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        with self.assertRaises(ValueError):
            PrivateKey.from_bytes(bytes(bad))

    def test_wrong_container_magic_rejected(self):
        _, public_key = make_keys()
        with self.assertRaises(ValueError):
            PrivateKey.from_bytes(public_key.to_bytes())

    def test_bad_version_rejected(self):
        for version in (0, 2, 255):
            with self.subTest(version=version):
                bad = bytearray(self.blob)
                bad[8] = version
                with self.assertRaises(ValueError):
                    PrivateKey.from_bytes(bytes(bad))

    def test_out_of_range_bits_rejected(self):
        for bad_bits in (0, 257, 65535):
            with self.subTest(bits=bad_bits):
                bad = bytearray(self.blob)
                bad[9:11] = bad_bits.to_bytes(2, "big")
                with self.assertRaises(ValueError):
                    PrivateKey.from_bytes(bytes(bad))

    def test_bad_element_count_rejected(self):
        bits = self.private_key.bits
        for count in (0, bits, 2 * bits - 1, 2 * bits + 1):
            with self.subTest(count=count):
                bad = bytearray(self.blob)
                bad[11:13] = count.to_bytes(2, "big")
                with self.assertRaises(ValueError):
                    PrivateKey.from_bytes(bytes(bad))

    def test_to_bytes_on_foreign_object_raises_type_error(self):
        for bad in (None, 42, "key", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    PrivateKey.to_bytes(bad)

    def test_to_bytes_rejects_corrupted_fields(self):
        with self.assertRaises(TypeError):
            PrivateKey(list(self.private_key.secrets)).to_bytes()
        with self.assertRaises(TypeError):
            PrivateKey(self.private_key.secrets + (bytearray(32),)).to_bytes()
        with self.assertRaises(ValueError):
            PrivateKey(self.private_key.secrets + (b"\x00" * 31,)).to_bytes()
        with self.assertRaises(ValueError):
            PrivateKey(self.private_key.secrets[:3]).to_bytes()  # odd count
        with self.assertRaises(ValueError):
            PrivateKey(()).to_bytes()  # bits would be 0


class PublicKeyFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for bits in (1, 8, 256):
            with self.subTest(bits=bits):
                _, public_key = make_keys(bits=bits)
                blob = public_key.to_bytes()
                self.assertEqual(len(blob), 8 + 1 + 2 + 2 + 2 * bits * 32)
                self.assertEqual(blob[:8], _PUBLIC_KEY_MAGIC)
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(int.from_bytes(blob[9:11], "big"), bits)
                self.assertEqual(int.from_bytes(blob[11:13], "big"), 2 * bits)
                self.assertEqual(blob[13:], b"".join(public_key.digests))

    def test_to_bytes_returns_bytes(self):
        _, public_key = make_keys()
        self.assertIsInstance(public_key.to_bytes(), bytes)

    def test_encoding_is_deterministic(self):
        _, public_key = make_keys()
        self.assertEqual(public_key.to_bytes(), public_key.to_bytes())


class PublicKeyRoundTripTest(unittest.TestCase):
    def test_round_trip(self):
        for bits in (1, 2, 8, 256):
            with self.subTest(bits=bits):
                _, public_key = make_keys(bits=bits)
                restored = PublicKey.from_bytes(public_key.to_bytes())
                self.assertEqual(restored, public_key)
                self.assertEqual(restored.to_bytes(), public_key.to_bytes())

    def test_accepts_bytearray(self):
        _, public_key = make_keys()
        restored = PublicKey.from_bytes(bytearray(public_key.to_bytes()))
        self.assertEqual(restored, public_key)

    def test_restored_key_still_verifies(self):
        private_key, public_key = make_keys()
        restored = PublicKey.from_bytes(public_key.to_bytes())
        signature = sign("message", private_key)
        self.assertTrue(verify("message", signature, restored))


class PublicKeyValidationTest(unittest.TestCase):
    def setUp(self):
        _, self.public_key = make_keys()
        self.blob = self.public_key.to_bytes()

    def test_non_bytes_types_raise_type_error(self):
        for bad in (None, 42, 4.5, "key", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    PublicKey.from_bytes(bad)

    def test_truncated_and_empty_rejected(self):
        for cut in (0, 7, 12, 13, len(self.blob) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    PublicKey.from_bytes(self.blob[:cut])

    def test_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            PublicKey.from_bytes(self.blob + b"\x00")

    def test_bad_magic_rejected(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        with self.assertRaises(ValueError):
            PublicKey.from_bytes(bytes(bad))

    def test_bad_version_rejected(self):
        bad = bytearray(self.blob)
        bad[8] = 2
        with self.assertRaises(ValueError):
            PublicKey.from_bytes(bytes(bad))

    def test_out_of_range_bits_rejected(self):
        bad = bytearray(self.blob)
        bad[9:11] = (0).to_bytes(2, "big")
        with self.assertRaises(ValueError):
            PublicKey.from_bytes(bytes(bad))

    def test_bad_element_count_rejected(self):
        bad = bytearray(self.blob)
        bad[11:13] = (self.public_key.bits).to_bytes(2, "big")  # half of 2*bits
        with self.assertRaises(ValueError):
            PublicKey.from_bytes(bytes(bad))

    def test_to_bytes_on_foreign_object_raises_type_error(self):
        for bad in (None, 42, "key", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    PublicKey.to_bytes(bad)


class SignatureFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for bits in (1, 8, 256):
            with self.subTest(bits=bits):
                private_key, _ = make_keys(bits=bits)
                signature = sign("message", private_key)
                blob = lamport_signature_to_bytes(signature, bits=bits)
                self.assertEqual(len(blob), 8 + 1 + 2 + 2 + bits * 32)
                self.assertEqual(blob[:8], _SIGNATURE_MAGIC)
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(int.from_bytes(blob[9:11], "big"), bits)
                self.assertEqual(int.from_bytes(blob[11:13], "big"), bits)
                self.assertEqual(blob[13:], b"".join(signature))

    def test_to_bytes_returns_bytes(self):
        private_key, _ = make_keys()
        blob = lamport_signature_to_bytes(sign("m", private_key), bits=8)
        self.assertIsInstance(blob, bytes)

    def test_encoding_is_deterministic(self):
        private_key, _ = make_keys()
        signature = sign("m", private_key)
        self.assertEqual(
            lamport_signature_to_bytes(signature, bits=8),
            lamport_signature_to_bytes(signature, bits=8),
        )


class SignatureRoundTripTest(unittest.TestCase):
    def test_round_trip(self):
        for bits in (1, 2, 8, 256):
            with self.subTest(bits=bits):
                private_key, public_key = make_keys(bits=bits)
                signature = sign("message", private_key)
                blob = lamport_signature_to_bytes(signature, bits=bits)
                restored_bits, elements = lamport_signature_from_bytes(blob)
                self.assertEqual(restored_bits, bits)
                self.assertIsInstance(restored_bits, int)
                self.assertEqual(elements, signature)
                self.assertIsInstance(elements, tuple)
                self.assertTrue(all(isinstance(e, bytes) and len(e) == 32 for e in elements))
                self.assertTrue(verify("message", elements, public_key))

    def test_accepts_bytearray(self):
        private_key, _ = make_keys()
        signature = sign("m", private_key)
        blob = lamport_signature_to_bytes(signature, bits=8)
        self.assertEqual(lamport_signature_from_bytes(bytearray(blob)), (8, signature))


class SignatureValidationTest(unittest.TestCase):
    def setUp(self):
        self.private_key, _ = make_keys()
        self.signature = sign("message", self.private_key)
        self.blob = lamport_signature_to_bytes(self.signature, bits=8)

    def test_non_bytes_data_raises_type_error(self):
        for bad in (None, 42, 4.5, "sig", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    lamport_signature_from_bytes(bad)

    def test_bad_signature_container_raises_type_error(self):
        for bad in (None, 42, "sig", [b"\x00" * 32] * 8, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    lamport_signature_to_bytes(bad, bits=8)

    def test_bad_signature_member_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            lamport_signature_to_bytes((b"\x00" * 32,) * 7 + (bytearray(32),), bits=8)
        with self.assertRaises(TypeError):
            lamport_signature_to_bytes((b"\x00" * 32,) * 7 + (None,), bits=8)

    def test_bad_bits_raises_value_error(self):
        for bad_bits in (0, 9, 257, -1, True, False, 4.5, "8", None):
            with self.subTest(bits=bad_bits):
                with self.assertRaises(ValueError):
                    lamport_signature_to_bytes(self.signature, bits=bad_bits)

    def test_bits_is_keyword_only(self):
        with self.assertRaises(TypeError):
            lamport_signature_to_bytes(self.signature, 8)

    def test_element_count_mismatch_raises_value_error(self):
        with self.assertRaises(ValueError):
            lamport_signature_to_bytes(self.signature[:7], bits=8)
        with self.assertRaises(ValueError):
            lamport_signature_to_bytes(self.signature + self.signature[:1], bits=8)

    def test_bad_element_length_raises_value_error(self):
        with self.assertRaises(ValueError):
            lamport_signature_to_bytes((b"\x00" * 32,) * 7 + (b"\x00" * 31,), bits=8)

    def test_truncated_and_empty_rejected(self):
        for cut in (0, 7, 12, 13, len(self.blob) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    lamport_signature_from_bytes(self.blob[:cut])

    def test_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            lamport_signature_from_bytes(self.blob + b"\x00")

    def test_bad_magic_rejected(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        with self.assertRaises(ValueError):
            lamport_signature_from_bytes(bytes(bad))

    def test_bad_version_rejected(self):
        bad = bytearray(self.blob)
        bad[8] = 2
        with self.assertRaises(ValueError):
            lamport_signature_from_bytes(bytes(bad))

    def test_out_of_range_bits_rejected(self):
        for bad_bits in (0, 257):
            with self.subTest(bits=bad_bits):
                bad = bytearray(self.blob)
                bad[9:11] = bad_bits.to_bytes(2, "big")
                with self.assertRaises(ValueError):
                    lamport_signature_from_bytes(bytes(bad))

    def test_bad_element_count_rejected(self):
        for count in (0, 7, 9):
            with self.subTest(count=count):
                bad = bytearray(self.blob)
                bad[11:13] = count.to_bytes(2, "big")
                with self.assertRaises(ValueError):
                    lamport_signature_from_bytes(bytes(bad))


class ExistingBehaviourUnchangedTest(unittest.TestCase):
    def test_positional_construction_frozen_and_equality(self):
        secrets = tuple(bytes([i]) * 32 for i in range(4))
        key = PrivateKey(secrets)
        self.assertEqual(key, PrivateKey(secrets))
        self.assertEqual(key.bits, 2)
        with self.assertRaises(AttributeError):
            key.secrets = ()

    def test_module_all_exports(self):
        self.assertIn("lamport_signature_to_bytes", pqattest.__all__)
        self.assertIn("lamport_signature_from_bytes", pqattest.__all__)


if __name__ == "__main__":
    unittest.main()

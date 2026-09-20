import unittest

from pqattest import (
    BITS,
    PrivateKey,
    PublicKey,
    keygen,
    lamport_signature_from_bytes,
    lamport_signature_to_bytes,
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


def make_keys(bits=16, start=0):
    return keygen(bits=bits, token_bytes=counter_tokens(start))


class KeyFormatTest(unittest.TestCase):
    def test_private_layout_and_length(self):
        for bits in (1, 7, 8, 16, 256):
            with self.subTest(bits=bits):
                private_key, _ = make_keys(bits=bits)
                blob = private_key.to_bytes()
                self.assertEqual(len(blob), 8 + 1 + 2 + 2 + 2 * bits * 32)
                self.assertEqual(blob[:8], b"PQALPRV\0")
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(int.from_bytes(blob[9:11], "big"), bits)
                self.assertEqual(int.from_bytes(blob[11:13], "big"), 2 * bits)
                self.assertEqual(blob[13:], b"".join(private_key.secrets))

    def test_public_layout_and_length(self):
        for bits in (1, 7, 8, 16, 256):
            with self.subTest(bits=bits):
                _, public_key = make_keys(bits=bits)
                blob = public_key.to_bytes()
                self.assertEqual(len(blob), 8 + 1 + 2 + 2 + 2 * bits * 32)
                self.assertEqual(blob[:8], b"PQALPUB\0")
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(int.from_bytes(blob[9:11], "big"), bits)
                self.assertEqual(int.from_bytes(blob[11:13], "big"), 2 * bits)
                self.assertEqual(blob[13:], b"".join(public_key.digests))

    def test_to_bytes_returns_bytes(self):
        private_key, public_key = make_keys()
        self.assertIsInstance(private_key.to_bytes(), bytes)
        self.assertIsInstance(public_key.to_bytes(), bytes)

    def test_encoding_is_deterministic(self):
        private_key, public_key = make_keys()
        self.assertEqual(private_key.to_bytes(), private_key.to_bytes())
        self.assertEqual(public_key.to_bytes(), public_key.to_bytes())


class KeyRoundTripTest(unittest.TestCase):
    def test_round_trip_every_bit_count(self):
        for bits in (1, 2, 7, 8, 9, 32, 128, 256):
            with self.subTest(bits=bits):
                private_key, public_key = make_keys(bits=bits)
                restored_private = PrivateKey.from_bytes(private_key.to_bytes())
                restored_public = PublicKey.from_bytes(public_key.to_bytes())
                self.assertEqual(restored_private, private_key)
                self.assertEqual(restored_public, public_key)
                self.assertEqual(restored_private.bits, bits)
                self.assertEqual(restored_public.bits, bits)
                self.assertEqual(restored_private.to_bytes(), private_key.to_bytes())
                self.assertEqual(restored_public.to_bytes(), public_key.to_bytes())

    def test_restored_private_key_still_signs(self):
        for bits in (1, 8, 256):
            with self.subTest(bits=bits):
                private_key, public_key = make_keys(bits=bits)
                restored = PrivateKey.from_bytes(private_key.to_bytes())
                signature = sign("position claim", restored)
                self.assertTrue(verify("position claim", signature, public_key))
                self.assertEqual(public_key_from(restored), public_key)

    def test_restored_key_is_frozen_and_value_equal(self):
        private_key, public_key = make_keys(bits=16)
        restored_private = PrivateKey.from_bytes(private_key.to_bytes())
        restored_public = PublicKey.from_bytes(public_key.to_bytes())
        self.assertIsInstance(restored_private.secrets, tuple)
        self.assertIsInstance(restored_public.digests, tuple)
        with self.assertRaises(Exception):
            restored_private.secrets = ()
        with self.assertRaises(Exception):
            restored_public.digests = ()

    def test_accepts_bytearray(self):
        private_key, public_key = make_keys()
        self.assertEqual(
            PrivateKey.from_bytes(bytearray(private_key.to_bytes())), private_key
        )
        self.assertEqual(
            PublicKey.from_bytes(bytearray(public_key.to_bytes())), public_key
        )


class KeyValidationTest(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = make_keys()
        self.private_blob = self.private_key.to_bytes()
        self.public_blob = self.public_key.to_bytes()

    def test_non_bytes_types_raise_type_error(self):
        for bad in (None, 42, 4.5, "key", [self.private_blob], (self.private_blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    PrivateKey.from_bytes(bad)
                with self.assertRaises(TypeError):
                    PublicKey.from_bytes(bad)

    def test_truncated_and_empty_rejected(self):
        for blob, from_bytes in (
            (self.private_blob, PrivateKey.from_bytes),
            (self.public_blob, PublicKey.from_bytes),
        ):
            for cut in (0, 7, 12, 13, len(blob) - 1):
                with self.subTest(cut=cut):
                    with self.assertRaises(ValueError):
                        from_bytes(blob[:cut])

    def test_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            PrivateKey.from_bytes(self.private_blob + b"\x00")
        with self.assertRaises(ValueError):
            PublicKey.from_bytes(self.public_blob + b"\x00")

    def test_bad_magic_rejected(self):
        for blob, from_bytes in (
            (self.private_blob, PrivateKey.from_bytes),
            (self.public_blob, PublicKey.from_bytes),
        ):
            bad = bytearray(blob)
            bad[0] ^= 0x01
            with self.assertRaises(ValueError):
                from_bytes(bytes(bad))

    def test_cross_magic_rejected(self):
        with self.assertRaises(ValueError):
            PrivateKey.from_bytes(self.public_blob)
        with self.assertRaises(ValueError):
            PublicKey.from_bytes(self.private_blob)

    def test_signature_magic_rejected(self):
        private_key, _ = make_keys()
        signature = sign("message", private_key)
        blob = lamport_signature_to_bytes(signature, bits=private_key.bits)
        with self.assertRaises(ValueError):
            PrivateKey.from_bytes(blob)
        with self.assertRaises(ValueError):
            PublicKey.from_bytes(blob)

    def test_bad_version_rejected(self):
        for version in (0, 2, 255):
            with self.subTest(version=version):
                bad = bytearray(self.private_blob)
                bad[8] = version
                with self.assertRaises(ValueError):
                    PrivateKey.from_bytes(bytes(bad))
                bad = bytearray(self.public_blob)
                bad[8] = version
                with self.assertRaises(ValueError):
                    PublicKey.from_bytes(bytes(bad))

    def test_bits_out_of_range_rejected(self):
        for bad_bits in (0, 257, 65535):
            with self.subTest(bad_bits=bad_bits):
                for blob, from_bytes in (
                    (self.private_blob, PrivateKey.from_bytes),
                    (self.public_blob, PublicKey.from_bytes),
                ):
                    bad = bytearray(blob)
                    bad[9:11] = bad_bits.to_bytes(2, "big")
                    with self.assertRaises(ValueError):
                        from_bytes(bytes(bad))

    def test_bad_element_count_rejected(self):
        for count in (0, 1, 31, 33, 512):
            with self.subTest(count=count):
                for blob, from_bytes in (
                    (self.private_blob, PrivateKey.from_bytes),
                    (self.public_blob, PublicKey.from_bytes),
                ):
                    bad = bytearray(blob)
                    bad[11:13] = count.to_bytes(2, "big")
                    with self.assertRaises(ValueError):
                        from_bytes(bytes(bad))

    def test_bits_and_count_must_agree(self):
        # A well-formed 8-bit key body tagged as bits=16 (count 16) is rejected.
        _, public_key = make_keys(bits=8)
        bad = bytearray(public_key.to_bytes())
        bad[9:11] = (16).to_bytes(2, "big")
        bad[11:13] = (16).to_bytes(2, "big")
        with self.assertRaises(ValueError):
            PublicKey.from_bytes(bytes(bad))

    def test_to_bytes_on_foreign_object_raises_type_error(self):
        for bad in (None, 42, "key", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    PrivateKey.to_bytes(bad)
                with self.assertRaises(TypeError):
                    PublicKey.to_bytes(bad)

    def test_to_bytes_on_corrupted_fields_raises(self):
        corrupt_container = object.__new__(PrivateKey)
        object.__setattr__(corrupt_container, "secrets", [b"\x00" * 32])
        with self.assertRaises(TypeError):
            corrupt_container.to_bytes()

        corrupt_member = object.__new__(PrivateKey)
        object.__setattr__(corrupt_member, "secrets", (42, b"\x00" * 32))
        with self.assertRaises(TypeError):
            corrupt_member.to_bytes()

        missing = object.__new__(PublicKey)
        with self.assertRaises(TypeError):
            missing.to_bytes()

        odd_count = object.__new__(PrivateKey)
        object.__setattr__(odd_count, "secrets", (b"\x00" * 32,))
        with self.assertRaises(ValueError):
            odd_count.to_bytes()

        wrong_length = object.__new__(PrivateKey)
        object.__setattr__(wrong_length, "secrets", (b"\x00" * 31, b"\x00" * 31))
        with self.assertRaises(ValueError):
            wrong_length.to_bytes()


class SignatureFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for bits in (1, 7, 8, 16, 256):
            with self.subTest(bits=bits):
                private_key, _ = make_keys(bits=bits)
                signature = sign("message", private_key)
                blob = lamport_signature_to_bytes(signature, bits=bits)
                self.assertEqual(len(blob), 8 + 1 + 2 + 2 + bits * 32)
                self.assertEqual(blob[:8], b"PQALSIG\0")
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(int.from_bytes(blob[9:11], "big"), bits)
                self.assertEqual(int.from_bytes(blob[11:13], "big"), bits)
                self.assertEqual(blob[13:], b"".join(signature))

    def test_to_bytes_returns_bytes(self):
        private_key, _ = make_keys()
        signature = sign("m", private_key)
        self.assertIsInstance(lamport_signature_to_bytes(signature, bits=16), bytes)

    def test_encoding_is_deterministic(self):
        private_key, _ = make_keys()
        signature = sign("m", private_key)
        self.assertEqual(
            lamport_signature_to_bytes(signature, bits=16),
            lamport_signature_to_bytes(signature, bits=16),
        )

    def test_bits_is_keyword_only(self):
        private_key, _ = make_keys()
        signature = sign("m", private_key)
        with self.assertRaises(TypeError):
            lamport_signature_to_bytes(signature, 16)


class SignatureRoundTripTest(unittest.TestCase):
    def test_round_trip_every_bit_count_and_still_verifies(self):
        for bits in (1, 2, 7, 8, 9, 32, 128, 256):
            with self.subTest(bits=bits):
                private_key, public_key = make_keys(bits=bits)
                signature = sign("position claim", private_key)
                blob = lamport_signature_to_bytes(signature, bits=bits)
                restored_bits, elements = lamport_signature_from_bytes(blob)
                self.assertEqual(restored_bits, bits)
                self.assertIsInstance(restored_bits, int)
                self.assertEqual(elements, signature)
                self.assertIsInstance(elements, tuple)
                self.assertEqual(len(elements), bits)
                for element in elements:
                    self.assertIsInstance(element, bytes)
                    self.assertEqual(len(element), 32)
                self.assertTrue(verify("position claim", elements, public_key))

    def test_accepts_bytearray(self):
        private_key, _ = make_keys()
        signature = sign("m", private_key)
        blob = lamport_signature_to_bytes(signature, bits=16)
        self.assertEqual(
            lamport_signature_from_bytes(bytearray(blob)), (16, signature)
        )


class SignatureValidationTest(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = make_keys(bits=16)
        self.signature = sign("message", self.private_key)
        self.blob = lamport_signature_to_bytes(self.signature, bits=16)

    def test_non_tuple_signature_raises_type_error(self):
        for bad in (None, 42, 4.5, "sig", list(self.signature), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    lamport_signature_to_bytes(bad, bits=16)

    def test_non_bytes_member_raises_type_error(self):
        for member in (bytearray(b"\x00" * 32), 42, None, object()):
            with self.subTest(bad=type(member).__name__):
                signature = list(self.signature)
                signature[0] = member
                with self.assertRaises(TypeError):
                    lamport_signature_to_bytes(tuple(signature), bits=16)

    def test_bad_bits_raises_value_error(self):
        for bad_bits in (0, -1, 257, 1024, None, True, False, 16.0, "16"):
            with self.subTest(bad_bits=bad_bits):
                with self.assertRaises(ValueError):
                    lamport_signature_to_bytes(self.signature, bits=bad_bits)

    def test_count_mismatch_raises_value_error(self):
        with self.assertRaises(ValueError):
            lamport_signature_to_bytes(self.signature, bits=15)
        with self.assertRaises(ValueError):
            lamport_signature_to_bytes(self.signature, bits=17)
        with self.assertRaises(ValueError):
            lamport_signature_to_bytes(self.signature[:-1], bits=16)
        with self.assertRaises(ValueError):
            lamport_signature_to_bytes(
                self.signature + (b"\x00" * 32,), bits=16
            )
        with self.assertRaises(ValueError):
            lamport_signature_to_bytes((), bits=16)

    def test_bad_member_length_raises_value_error(self):
        for member in (b"\x00" * 31, b"\x00" * 33, b""):
            with self.subTest(length=len(member)):
                signature = list(self.signature)
                signature[5] = member
                with self.assertRaises(ValueError):
                    lamport_signature_to_bytes(tuple(signature), bits=16)

    def test_non_bytes_data_raises_type_error(self):
        for bad in (None, 42, 4.5, "sig", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    lamport_signature_from_bytes(bad)

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

    def test_key_magic_rejected(self):
        with self.assertRaises(ValueError):
            lamport_signature_from_bytes(self.private_key.to_bytes())
        with self.assertRaises(ValueError):
            lamport_signature_from_bytes(self.public_key.to_bytes())

    def test_bad_version_rejected(self):
        for version in (0, 2, 255):
            with self.subTest(version=version):
                bad = bytearray(self.blob)
                bad[8] = version
                with self.assertRaises(ValueError):
                    lamport_signature_from_bytes(bytes(bad))

    def test_bits_out_of_range_rejected(self):
        for bad_bits in (0, 257, 65535):
            with self.subTest(bad_bits=bad_bits):
                bad = bytearray(self.blob)
                bad[9:11] = bad_bits.to_bytes(2, "big")
                with self.assertRaises(ValueError):
                    lamport_signature_from_bytes(bytes(bad))

    def test_bad_element_count_rejected(self):
        for count in (0, 1, 15, 17, 32):
            with self.subTest(count=count):
                bad = bytearray(self.blob)
                bad[11:13] = count.to_bytes(2, "big")
                with self.assertRaises(ValueError):
                    lamport_signature_from_bytes(bytes(bad))

    def test_valid_signature_still_accepted(self):
        # Guard against the corruption tests making the helper too strict.
        bits, elements = lamport_signature_from_bytes(self.blob)
        self.assertEqual(bits, 16)
        self.assertEqual(elements, self.signature)
        self.assertTrue(verify("message", elements, self.public_key))


class DefaultSizeTest(unittest.TestCase):
    def test_default_256_bit_key_codecs(self):
        private_key, public_key = keygen()
        self.assertEqual(private_key.bits, BITS)
        restored_private = PrivateKey.from_bytes(private_key.to_bytes())
        restored_public = PublicKey.from_bytes(public_key.to_bytes())
        self.assertEqual(restored_private, private_key)
        self.assertEqual(restored_public, public_key)
        signature = sign("m", private_key)
        blob = lamport_signature_to_bytes(signature, bits=BITS)
        self.assertEqual(len(blob), 13 + BITS * 32)
        bits, elements = lamport_signature_from_bytes(blob)
        self.assertEqual((bits, elements), (BITS, signature))


if __name__ == "__main__":
    unittest.main()

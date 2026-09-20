import hashlib
import struct
import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    ToyLatticeCiphertext,
    ToyLatticePrivateKey,
    ToyLatticePublicKey,
    toy_lattice_decapsulate,
    toy_lattice_encapsulate,
    toy_lattice_keygen,
)
from pqattest.toy_lattice import (
    _CIPHERTEXT_MAGIC,
    _PRIVATE_KEY_MAGIC,
    _PUBLIC_KEY_MAGIC,
    _decode_e,
    _encode_e,
)


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


class KeySerializationTest(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = toy_lattice_keygen(
            token_bytes=fixed_tokens(b"abcdefgh")
        )

    def test_public_key_layout(self):
        blob = self.public_key.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertEqual(len(blob), 25)
        self.assertEqual(blob[:8], _PUBLIC_KEY_MAGIC)
        self.assertEqual(blob[8], 1)  # version
        self.assertEqual(blob[9:], self.public_key.t)

    def test_private_key_layout(self):
        blob = self.private_key.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertEqual(len(blob), 25)
        self.assertEqual(blob[:8], _PRIVATE_KEY_MAGIC)
        self.assertEqual(blob[8], 1)  # version
        self.assertEqual(blob[9:], self.private_key.s)

    def test_encoding_is_deterministic(self):
        self.assertEqual(
            self.public_key.to_bytes(), self.public_key.to_bytes()
        )
        self.assertEqual(
            self.private_key.to_bytes(), self.private_key.to_bytes()
        )

    def test_round_trip(self):
        for key, cls in (
            (self.public_key, ToyLatticePublicKey),
            (self.private_key, ToyLatticePrivateKey),
        ):
            with self.subTest(cls=cls.__name__):
                blob = key.to_bytes()
                restored = cls.from_bytes(blob)
                self.assertIs(type(restored), cls)
                self.assertEqual(restored, key)
                self.assertEqual(restored.to_bytes(), blob)

    def test_accepts_bytearray(self):
        self.assertEqual(
            ToyLatticePublicKey.from_bytes(bytearray(self.public_key.to_bytes())),
            self.public_key,
        )
        self.assertEqual(
            ToyLatticePrivateKey.from_bytes(bytearray(self.private_key.to_bytes())),
            self.private_key,
        )

    def test_coefficient_256_round_trips_losslessly(self):
        encoded = b"\x01\x00" + b"\x00" * 14
        self.assertEqual(ToyLatticePublicKey.from_bytes(
            ToyLatticePublicKey(encoded).to_bytes()).t, encoded)
        self.assertEqual(ToyLatticePrivateKey.from_bytes(
            ToyLatticePrivateKey(encoded).to_bytes()).s, encoded)

    def test_non_bytes_types_raise_type_error(self):
        blob = self.public_key.to_bytes()
        for bad in (None, 42, 4.5, "key", [blob], (blob,), object(), memoryview(blob)):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    ToyLatticePublicKey.from_bytes(bad)
                with self.assertRaises(TypeError):
                    ToyLatticePrivateKey.from_bytes(bad)

    def test_to_bytes_on_foreign_object_raises_type_error(self):
        for bad in (None, 42, "key", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    ToyLatticePublicKey.to_bytes(bad)
                with self.assertRaises(TypeError):
                    ToyLatticePrivateKey.to_bytes(bad)

    def test_truncated_and_empty_rejected(self):
        for cls, blob in (
            (ToyLatticePublicKey, self.public_key.to_bytes()),
            (ToyLatticePrivateKey, self.private_key.to_bytes()),
        ):
            for cut in (0, 7, 8, 20, 24):
                with self.subTest(cls=cls.__name__, cut=cut):
                    with self.assertRaises(ValueError):
                        cls.from_bytes(blob[:cut])

    def test_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            ToyLatticePublicKey.from_bytes(self.public_key.to_bytes() + b"\x00")
        with self.assertRaises(ValueError):
            ToyLatticePrivateKey.from_bytes(self.private_key.to_bytes() + b"\x00")

    def test_bad_magic_rejected(self):
        for cls, blob in (
            (ToyLatticePublicKey, self.public_key.to_bytes()),
            (ToyLatticePrivateKey, self.private_key.to_bytes()),
        ):
            bad = bytearray(blob)
            bad[0] ^= 0x01
            with self.subTest(cls=cls.__name__):
                with self.assertRaises(ValueError):
                    cls.from_bytes(bytes(bad))

    def test_cross_magic_rejected(self):
        with self.assertRaises(ValueError):
            ToyLatticePublicKey.from_bytes(self.private_key.to_bytes())
        with self.assertRaises(ValueError):
            ToyLatticePrivateKey.from_bytes(self.public_key.to_bytes())

    def test_bad_version_rejected(self):
        for cls, blob in (
            (ToyLatticePublicKey, self.public_key.to_bytes()),
            (ToyLatticePrivateKey, self.private_key.to_bytes()),
        ):
            for version in (0, 2, 255):
                with self.subTest(cls=cls.__name__, version=version):
                    bad = bytearray(blob)
                    bad[8] = version
                    with self.assertRaises(ValueError):
                        cls.from_bytes(bytes(bad))

    def test_illegal_coefficient_rejected(self):
        for cls in (ToyLatticePublicKey, ToyLatticePrivateKey):
            bad = bytearray(cls(b"\x00" * 16).to_bytes())
            bad[9:11] = b"\x01\x01"  # coefficient 257 > 256
            with self.subTest(cls=cls.__name__):
                with self.assertRaises(ValueError):
                    cls.from_bytes(bytes(bad))


class CiphertextSerializationTest(unittest.TestCase):
    def setUp(self):
        _, self.public_key = toy_lattice_keygen(
            token_bytes=fixed_tokens(b"abcdefgh")
        )
        self.ciphertext, self.shared_key = toy_lattice_encapsulate(
            self.public_key, token_bytes=fixed_tokens(b"r-r-r-r-")
        )
        self.blob = self.ciphertext.to_bytes()

    def test_layout(self):
        blob = self.blob
        self.assertIsInstance(blob, bytes)
        self.assertEqual(blob[:8], _CIPHERTEXT_MAGIC)
        self.assertEqual(blob[8], 1)  # version
        self.assertEqual(blob[9:25], self.ciphertext.u)
        self.assertEqual(
            struct.unpack(">I", blob[25:29])[0], len(self.ciphertext.tag)
        )
        self.assertEqual(blob[29:], self.ciphertext.tag)

    def test_encoding_is_deterministic(self):
        self.assertEqual(self.blob, self.ciphertext.to_bytes())

    def test_round_trip(self):
        restored = ToyLatticeCiphertext.from_bytes(self.blob)
        self.assertIs(type(restored), ToyLatticeCiphertext)
        self.assertEqual(restored, self.ciphertext)
        self.assertEqual(restored.to_bytes(), self.blob)

    def test_round_trip_still_decapsulates(self):
        private_key, _ = toy_lattice_keygen(token_bytes=fixed_tokens(b"abcdefgh"))
        restored = ToyLatticeCiphertext.from_bytes(self.blob)
        self.assertEqual(
            toy_lattice_decapsulate(restored, private_key), self.shared_key
        )

    def test_accepts_bytearray(self):
        self.assertEqual(
            ToyLatticeCiphertext.from_bytes(bytearray(self.blob)),
            self.ciphertext,
        )

    def test_empty_tag_round_trips(self):
        ciphertext = ToyLatticeCiphertext(_encode_e(b"12345678"), b"")
        blob = ciphertext.to_bytes()
        self.assertEqual(len(blob), 29)
        self.assertEqual(blob[29:], b"")
        self.assertEqual(ToyLatticeCiphertext.from_bytes(blob), ciphertext)

    def test_arbitrary_tag_round_trips(self):
        for tag in (b"\x00", bytes(range(256)), b"x" * 1000):
            with self.subTest(length=len(tag)):
                ciphertext = ToyLatticeCiphertext(_encode_e(b"12345678"), tag)
                blob = ciphertext.to_bytes()
                restored = ToyLatticeCiphertext.from_bytes(blob)
                self.assertEqual(restored, ciphertext)
                self.assertEqual(restored.tag, tag)
                self.assertEqual(restored.to_bytes(), blob)

    def test_coefficient_256_round_trips_losslessly(self):
        encoded = b"\x01\x00" + b"\x00" * 14
        ciphertext = ToyLatticeCiphertext(encoded, b"tag")
        self.assertEqual(
            ToyLatticeCiphertext.from_bytes(ciphertext.to_bytes()).u, encoded
        )

    def test_decoded_value_remains_frozen(self):
        restored = ToyLatticeCiphertext.from_bytes(self.blob)
        with self.assertRaises(FrozenInstanceError):
            restored.u = b"\x00" * 16
        with self.assertRaises(FrozenInstanceError):
            restored.tag = b""

    def test_non_bytes_types_raise_type_error(self):
        for bad in (None, 42, 4.5, "ct", [self.blob], (self.blob,), object(),
                    memoryview(self.blob)):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    ToyLatticeCiphertext.from_bytes(bad)

    def test_to_bytes_on_foreign_object_raises_type_error(self):
        for bad in (None, 42, "ct", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    ToyLatticeCiphertext.to_bytes(bad)

    def test_truncated_and_empty_rejected(self):
        for cut in range(0, len(self.blob)):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    ToyLatticeCiphertext.from_bytes(self.blob[:cut])

    def test_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            ToyLatticeCiphertext.from_bytes(self.blob + b"\x00")

    def test_bad_magic_rejected(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        with self.assertRaises(ValueError):
            ToyLatticeCiphertext.from_bytes(bytes(bad))

    def test_foreign_magic_rejected(self):
        with self.assertRaises(ValueError):
            ToyLatticeCiphertext.from_bytes(self.public_key.to_bytes())

    def test_bad_version_rejected(self):
        for version in (0, 2, 255):
            with self.subTest(version=version):
                bad = bytearray(self.blob)
                bad[8] = version
                with self.assertRaises(ValueError):
                    ToyLatticeCiphertext.from_bytes(bytes(bad))

    def test_illegal_coefficient_rejected(self):
        bad = bytearray(self.blob)
        bad[9:11] = b"\x01\x01"  # coefficient 257 > 256
        with self.assertRaises(ValueError):
            ToyLatticeCiphertext.from_bytes(bytes(bad))

    def test_tag_length_mismatch_rejected(self):
        real_length = len(self.ciphertext.tag)
        # Declared lengths that disagree with the actual tag body.
        for declared in (0, real_length - 1, real_length + 1):
            with self.subTest(declared=declared):
                bad = bytearray(self.blob)
                bad[25:29] = declared.to_bytes(4, "big")
                with self.assertRaises(ValueError):
                    ToyLatticeCiphertext.from_bytes(bytes(bad))
        # A huge declared length runs straight past the end of the blob.
        bad = bytearray(self.blob[:29])
        bad[25:29] = (2 ** 32 - 1).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            ToyLatticeCiphertext.from_bytes(bytes(bad))


if __name__ == "__main__":
    unittest.main()

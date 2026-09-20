import hashlib
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


def fixed_tokens(value: bytes):
    def token_bytes(size: int) -> bytes:
        return value[:size].ljust(size, b"\x00")

    return token_bytes


SEED = bytes(range(1, 9))  # 01 02 ... 08
ENCODED = b"".join(byte.to_bytes(2, "big") for byte in SEED)
SHARED_V = sum(i * i for i in range(1, 9)) % 257  # 204
SHARED_KEY = hashlib.sha256(b"K" + SHARED_V.to_bytes(2, "big")).digest()


class KeygenTest(unittest.TestCase):
    def test_returns_private_then_public(self):
        private_key, public_key = toy_lattice_keygen(token_bytes=fixed_tokens(SEED))
        self.assertIsInstance(private_key, ToyLatticePrivateKey)
        self.assertIsInstance(public_key, ToyLatticePublicKey)

    def test_s_and_t_are_encoded_seed(self):
        private_key, public_key = toy_lattice_keygen(token_bytes=fixed_tokens(SEED))
        self.assertEqual(private_key.s, ENCODED)
        self.assertEqual(public_key.t, ENCODED)

    def test_token_length_enforced(self):
        with self.assertRaises(ValueError):
            toy_lattice_keygen(token_bytes=lambda size: b"short")
        with self.assertRaises(ValueError):
            toy_lattice_keygen(token_bytes=lambda size: b"")


class RoundTripTest(unittest.TestCase):
    def test_decapsulate_recovers_encapsulated_key(self):
        private_key, public_key = toy_lattice_keygen()
        ciphertext, key = toy_lattice_encapsulate(public_key)
        self.assertEqual(toy_lattice_decapsulate(ciphertext, private_key), key)

    def test_deterministic_vectors(self):
        private_key, public_key = toy_lattice_keygen(token_bytes=fixed_tokens(SEED))
        ciphertext, key = toy_lattice_encapsulate(
            public_key, token_bytes=fixed_tokens(SEED)
        )
        self.assertEqual(ciphertext.u, ENCODED)
        self.assertEqual(ciphertext.tag, SHARED_KEY)
        self.assertEqual(key, SHARED_KEY)
        self.assertEqual(toy_lattice_decapsulate(ciphertext, private_key), SHARED_KEY)

    def test_tampered_tag_rejected(self):
        private_key, public_key = toy_lattice_keygen()
        ciphertext, key = toy_lattice_encapsulate(public_key)
        bad_tag = bytes(b ^ 1 for b in ciphertext.tag)
        tampered = ToyLatticeCiphertext(u=ciphertext.u, tag=bad_tag)
        with self.assertRaises(ValueError):
            toy_lattice_decapsulate(tampered, private_key)

    def test_tampered_u_rejected(self):
        private_key, public_key = toy_lattice_keygen(token_bytes=fixed_tokens(SEED))
        ciphertext, _ = toy_lattice_encapsulate(
            public_key, token_bytes=fixed_tokens(SEED)
        )
        other_u = b"".join(byte.to_bytes(2, "big") for byte in range(9, 17))
        tampered = ToyLatticeCiphertext(u=other_u, tag=ciphertext.tag)
        with self.assertRaises(ValueError):
            toy_lattice_decapsulate(tampered, private_key)

    def test_encapsulate_token_length_enforced(self):
        _, public_key = toy_lattice_keygen()
        with self.assertRaises(ValueError):
            toy_lattice_encapsulate(public_key, token_bytes=lambda size: b"short")


class ValueObjectTest(unittest.TestCase):
    def test_positional_construction_and_equality(self):
        self.assertEqual(ToyLatticePublicKey(ENCODED), ToyLatticePublicKey(t=ENCODED))
        self.assertEqual(ToyLatticePrivateKey(ENCODED), ToyLatticePrivateKey(s=ENCODED))
        self.assertEqual(
            ToyLatticeCiphertext(ENCODED, SHARED_KEY),
            ToyLatticeCiphertext(u=ENCODED, tag=SHARED_KEY),
        )

    def test_inequality(self):
        other = b"\x00" * 16
        self.assertNotEqual(ToyLatticePublicKey(ENCODED), ToyLatticePublicKey(other))
        self.assertNotEqual(ToyLatticePrivateKey(ENCODED), ToyLatticePrivateKey(other))

    def test_frozen(self):
        private_key, public_key = toy_lattice_keygen(token_bytes=fixed_tokens(SEED))
        ciphertext, _ = toy_lattice_encapsulate(
            public_key, token_bytes=fixed_tokens(SEED)
        )
        with self.assertRaises(FrozenInstanceError):
            public_key.t = b"\x00" * 16
        with self.assertRaises(FrozenInstanceError):
            private_key.s = b"\x00" * 16
        with self.assertRaises(FrozenInstanceError):
            ciphertext.u = b"\x00" * 16
        with self.assertRaises(FrozenInstanceError):
            ciphertext.tag = b"\x00" * 32

    def test_coefficient_256_allowed(self):
        encoded = b"\x01\x00" * 8  # 256 == MODULUS - 1
        self.assertEqual(ToyLatticePublicKey(encoded).t, encoded)


class TypeErrorTest(unittest.TestCase):
    def test_field_type_errors(self):
        for value in (bytearray(ENCODED), "x" * 16, 12345, None):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    ToyLatticePublicKey(value)
                with self.assertRaises(TypeError):
                    ToyLatticePrivateKey(value)
                with self.assertRaises(TypeError):
                    ToyLatticeCiphertext(value, SHARED_KEY)
                with self.assertRaises(TypeError):
                    ToyLatticeCiphertext(ENCODED, value)

    def test_argument_type_errors(self):
        private_key, public_key = toy_lattice_keygen()
        ciphertext, _ = toy_lattice_encapsulate(public_key)
        with self.assertRaises(TypeError):
            toy_lattice_encapsulate(private_key)
        with self.assertRaises(TypeError):
            toy_lattice_encapsulate(b"not a key")
        with self.assertRaises(TypeError):
            toy_lattice_decapsulate(public_key, private_key)
        with self.assertRaises(TypeError):
            toy_lattice_decapsulate(ciphertext, public_key)


class ValueErrorTest(unittest.TestCase):
    def test_vector_length_enforced(self):
        for bad in (b"", b"\x00" * 15, b"\x00" * 17):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    ToyLatticePublicKey(bad)
                with self.assertRaises(ValueError):
                    ToyLatticePrivateKey(bad)
                with self.assertRaises(ValueError):
                    ToyLatticeCiphertext(bad, SHARED_KEY)

    def test_coefficient_above_256_rejected(self):
        encoded = b"\x01\x01" + b"\x00" * 14  # first coefficient is 257
        with self.assertRaises(ValueError):
            ToyLatticePublicKey(encoded)
        with self.assertRaises(ValueError):
            ToyLatticePrivateKey(encoded)
        with self.assertRaises(ValueError):
            ToyLatticeCiphertext(encoded, SHARED_KEY)

    def test_tag_length_enforced(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    ToyLatticeCiphertext(ENCODED, bad)


if __name__ == "__main__":
    unittest.main()

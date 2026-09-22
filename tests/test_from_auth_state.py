import unittest
from unittest import mock

from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    auth_state_wrap,
    auth_wrap,
)

KEY = b"shared-secret-key"
UINT64_MAX = 2**64 - 1


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def wrap(checkpoint, generation=0, key=KEY, scheme="merkle"):
    return auth_state_wrap(checkpoint, scheme=scheme, key=key, generation=generation)


class FromAuthStateTest(unittest.TestCase):
    def test_round_trip_returns_signer_and_generation(self):
        signer = make_signer()
        signer.sign("a")
        envelope = wrap(signer.checkpoint(), generation=7)
        restored, generation = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertIsInstance(restored, MerkleSigner)
        self.assertIsInstance(generation, int)
        self.assertEqual(generation, 7)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 1)
        self.assertEqual(restored.remaining, signer.remaining)

    def test_restored_signer_resumes_signing(self):
        signer = make_signer()
        signer.sign("a")
        envelope = wrap(signer.checkpoint(), generation=1)
        restored, _ = MerkleSigner.from_auth_state(envelope, key=KEY)
        signature = restored.sign("b")
        self.assertEqual(signature.index, 1)

    def test_accepts_envelope_from_sign_with_auth_state(self):
        signer = make_signer()
        _, envelope = signer.sign_with_auth_state("m", key=KEY, generation=3)
        restored, generation = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(generation, 3)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 1)

    def test_accepts_bytearray_data_and_key(self):
        signer = make_signer()
        envelope = wrap(signer.checkpoint(), generation=2)
        restored, generation = MerkleSigner.from_auth_state(
            bytearray(envelope), key=bytearray(KEY)
        )
        self.assertEqual(generation, 2)
        self.assertEqual(restored.public_key, signer.public_key)

    def test_min_generation_floor(self):
        signer = make_signer()
        envelope = wrap(signer.checkpoint(), generation=7)
        # Equal and lower floors accept; a higher floor rejects.
        MerkleSigner.from_auth_state(envelope, key=KEY, min_generation=7)
        MerkleSigner.from_auth_state(envelope, key=KEY, min_generation=3)
        MerkleSigner.from_auth_state(envelope, key=KEY, min_generation=0)
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(envelope, key=KEY, min_generation=8)

    def test_max_generation_boundaries(self):
        signer = make_signer()
        envelope = wrap(signer.checkpoint(), generation=UINT64_MAX)
        _, generation = MerkleSigner.from_auth_state(
            envelope, key=KEY, min_generation=UINT64_MAX
        )
        self.assertEqual(generation, UINT64_MAX)

    def test_exhausted_state_restores_exhausted(self):
        signer = make_signer(height=2)  # 4 leaves
        signer.advance_to(4)
        envelope = wrap(signer.checkpoint(), generation=0)
        restored, _ = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("m")

    def test_keyword_only_arguments(self):
        signer = make_signer()
        envelope = wrap(signer.checkpoint(), generation=0)
        with self.assertRaises(TypeError):
            MerkleSigner.from_auth_state(envelope, KEY)
        with self.assertRaises(TypeError):
            MerkleSigner.from_auth_state(envelope, KEY, 0)

    def test_non_bytes_data_raises_type_error(self):
        for bad in (None, 42, "blob", [1], (1,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleSigner.from_auth_state(bad, key=KEY)

    def test_invalid_key_raises(self):
        signer = make_signer()
        envelope = wrap(signer.checkpoint(), generation=0)
        for bad in (None, 42, "secret", ["k"]):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleSigner.from_auth_state(envelope, key=bad)
        for bad in (b"", bytearray()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_auth_state(envelope, key=bad)

    def test_invalid_min_generation_raises(self):
        signer = make_signer()
        envelope = wrap(signer.checkpoint(), generation=0)
        for bad in (True, False, 1.5, "0", [0]):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    MerkleSigner.from_auth_state(envelope, key=KEY, min_generation=bad)
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_auth_state(envelope, key=KEY, min_generation=bad)

    def test_wrong_key_raises_value_error(self):
        signer = make_signer()
        envelope = wrap(signer.checkpoint(), generation=0)
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(envelope, key=b"other-secret")

    def test_tampered_tag_raises_value_error(self):
        signer = make_signer()
        envelope = bytearray(wrap(signer.checkpoint(), generation=0))
        envelope[-1] ^= 0x01
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(bytes(envelope), key=KEY)

    def test_tampered_body_raises_value_error(self):
        signer = make_signer()
        envelope = bytearray(wrap(signer.checkpoint(), generation=0))
        envelope[10] ^= 0x01  # flip a generation byte: the tag no longer matches
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(bytes(envelope), key=KEY)

    def test_truncated_and_trailing_data_raise_value_error(self):
        signer = make_signer()
        envelope = wrap(signer.checkpoint(), generation=0)
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(envelope[:-1], key=KEY)
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(envelope + b"\x00", key=KEY)
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(b"", key=KEY)

    def test_v1_envelope_rejected(self):
        signer = make_signer()
        v1 = auth_wrap(signer.checkpoint(), scheme="merkle", key=KEY)
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(v1, key=KEY)

    def test_non_merkle_scheme_rejected(self):
        # A structurally valid v2 envelope for another scheme must not restore.
        wots_payload = b"PQAWCP\0\0" + b"\x00" * 40
        lamport_payload = b"PQALCP\0\0" + b"\x00" * 40
        for scheme, payload in (("wots", wots_payload), ("lamport", lamport_payload)):
            with self.subTest(scheme=scheme):
                envelope = wrap(payload, generation=0, scheme=scheme)
                with self.assertRaises(ValueError):
                    MerkleSigner.from_auth_state(envelope, key=KEY)

    def test_invalid_checkpoint_payload_raises_value_error(self):
        # Valid HMAC over a Merkle-magic-prefixed but corrupt checkpoint.
        envelope = wrap(b"PQAMSCP\0" + b"\x00" * 64, generation=0)
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(envelope, key=KEY)

    def test_draws_no_randomness(self):
        signer = make_signer()
        envelope = wrap(signer.checkpoint(), generation=0)

        import pqattest.merkle

        def exploding_token_bytes(size):
            raise AssertionError("from_auth_state must not draw randomness")

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            restored, generation = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(generation, 0)
        self.assertEqual(restored.public_key, signer.public_key)


if __name__ == "__main__":
    unittest.main()

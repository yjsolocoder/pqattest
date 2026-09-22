import unittest
from unittest import mock

from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    OneTimeSigner,
    WOTSOneTimeSigner,
    auth_state_wrap,
    auth_state_unwrap,
    auth_wrap,
    keygen,
    merkle_verify,
    wots_keygen,
)
import pqattest.merkle

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret"
UINT64_MAX = 2**64 - 1


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def wrap(signer, *, generation=7, key=KEY):
    return auth_state_wrap(
        signer.checkpoint(), scheme="merkle", key=key, generation=generation
    )


class FromAuthStateBasicTest(unittest.TestCase):
    def test_returns_signer_and_generation(self):
        signer = make_signer()
        envelope = wrap(signer, generation=11)
        restored, generation = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertIsInstance(restored, MerkleSigner)
        self.assertIsInstance(generation, int)
        self.assertNotIsInstance(generation, bool)
        self.assertEqual(generation, 11)

    def test_restores_public_key_and_index(self):
        signer = make_signer(height=3)
        signer.sign("one")
        signer.sign("two")
        expected_index = signer.next_index
        envelope = wrap(signer, generation=5)
        restored, generation = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, expected_index)
        self.assertEqual(generation, 5)

    def test_restored_signer_resumes_signing(self):
        signer = make_signer(height=2)
        signature, envelope = signer.sign_with_auth_state(
            "m0", key=KEY, generation=3
        )
        restored, generation = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(generation, 3)
        next_signature = restored.sign("m1")
        self.assertEqual(next_signature.index, signature.index + 1)
        self.assertTrue(merkle_verify("m0", signature, signer.public_key))
        self.assertTrue(merkle_verify("m1", next_signature, signer.public_key))

    def test_restores_exhausted_state(self):
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        envelope = wrap(signer, generation=9)
        restored, generation = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("three")

    def test_restores_advanced_state(self):
        signer = make_signer(height=3)
        signer.advance_to(5)
        envelope = wrap(signer, generation=2)
        restored, generation = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(restored.next_index, 5)
        self.assertEqual(restored.sign("m").index, 5)

    def test_accepts_bytearray_inputs(self):
        signer = make_signer()
        envelope = wrap(signer, generation=1)
        restored, generation = MerkleSigner.from_auth_state(
            bytearray(envelope), key=bytearray(KEY)
        )
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(generation, 1)

    def test_generation_zero_is_non_negative(self):
        signer = make_signer()
        envelope = wrap(signer, generation=0)
        _, generation = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(generation, 0)
        self.assertGreaterEqual(generation, 0)

    def test_generation_uint64_max_round_trips(self):
        signer = make_signer()
        envelope = wrap(signer, generation=UINT64_MAX)
        _, generation = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(generation, UINT64_MAX)

    def test_no_floor_accepts_lower_generation(self):
        signer = make_signer()
        envelope = wrap(signer, generation=0)
        _, generation = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(generation, 0)

    def test_floor_equal_to_generation_passes(self):
        signer = make_signer()
        envelope = wrap(signer, generation=7)
        restored, generation = MerkleSigner.from_auth_state(
            envelope, key=KEY, min_generation=7
        )
        self.assertEqual(generation, 7)
        self.assertEqual(restored.next_index, 0)

    def test_floor_below_generation_passes(self):
        signer = make_signer()
        envelope = wrap(signer, generation=7)
        _, generation = MerkleSigner.from_auth_state(
            envelope, key=KEY, min_generation=6
        )
        self.assertEqual(generation, 7)

    def test_envelope_is_not_mutated_or_rearranged(self):
        signer = make_signer()
        envelope = wrap(signer, generation=42)
        snapshot = bytes(envelope)
        MerkleSigner.from_auth_state(bytearray(envelope), key=KEY)
        self.assertEqual(envelope, snapshot)
        self.assertEqual(envelope[:8], b"PQAAUTH\0")
        self.assertEqual(envelope[8], 2)
        self.assertEqual(envelope[9], 3)
        self.assertEqual(int.from_bytes(envelope[10:18], "big"), 42)

    def test_draws_no_randomness(self):
        signer = make_signer()
        envelope = wrap(signer, generation=1)

        def exploding_token_bytes(size):
            raise AssertionError("from_auth_state must not draw randomness")

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            restored, _ = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(restored.public_key, signer.public_key)


class FromAuthStateTypesTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.envelope = wrap(self.signer, generation=1)

    def test_keyword_only_arguments(self):
        with self.assertRaises(TypeError):
            MerkleSigner.from_auth_state(self.envelope, KEY)
        with self.assertRaises(TypeError):
            MerkleSigner.from_auth_state(self.envelope, KEY, None)

    def test_non_bytes_data_type_error(self):
        for bad in (None, 42, 4.5, "blob", [self.envelope], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleSigner.from_auth_state(bad, key=KEY)

    def test_non_bytes_key_type_error(self):
        for bad in (None, 42, "secret", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleSigner.from_auth_state(self.envelope, key=bad)

    def test_bad_floor_type_error(self):
        for bad in (1.5, "0", [0], (0,), object()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    MerkleSigner.from_auth_state(
                        self.envelope, key=KEY, min_generation=bad
                    )

    def test_boolean_floor_type_error(self):
        for bad in (True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    MerkleSigner.from_auth_state(
                        self.envelope, key=KEY, min_generation=bad
                    )

    def test_empty_key_value_error(self):
        for bad in (b"", bytearray()):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_auth_state(self.envelope, key=bad)

    def test_floor_out_of_range_value_error(self):
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_auth_state(
                        self.envelope, key=KEY, min_generation=bad
                    )

    def test_types_checked_before_envelope(self):
        # A garbage blob must not mask argument type errors.
        with self.assertRaises(TypeError):
            MerkleSigner.from_auth_state(b"", key=42)
        with self.assertRaises(TypeError):
            MerkleSigner.from_auth_state(object(), key=KEY)
        with self.assertRaises(TypeError):
            MerkleSigner.from_auth_state(b"", key=KEY, min_generation=True)


class FromAuthStateFailureTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer()
        self.envelope = wrap(self.signer, generation=7)

    def test_wrong_key_value_error(self):
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(self.envelope, key=OTHER_KEY)

    def test_tampered_tag_value_error(self):
        forged = bytearray(self.envelope)
        forged[-1] ^= 0x01
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(bytes(forged), key=KEY)

    def test_tampered_payload_value_error(self):
        forged = bytearray(self.envelope)
        # Flip a payload byte (after the 22-byte header) and leave the tag;
        # the HMAC must reject it before the checkpoint is parsed.
        forged[30] ^= 0x01
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(bytes(forged), key=KEY)

    def test_generation_below_floor_value_error(self):
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(
                self.envelope, key=KEY, min_generation=8
            )

    def test_floor_zero_does_not_reject(self):
        restored, generation = MerkleSigner.from_auth_state(
            self.envelope, key=KEY, min_generation=0
        )
        self.assertEqual(generation, 7)
        self.assertEqual(restored.public_key, self.signer.public_key)

    def test_v1_envelope_rejected(self):
        v1 = auth_wrap(self.signer.checkpoint(), scheme="merkle", key=KEY)
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(v1, key=KEY)

    def test_other_scheme_envelope_rejected(self):
        wots = WOTSOneTimeSigner(wots_keygen(w=4)[0])
        envelope = auth_state_wrap(
            wots.checkpoint(), scheme="wots", key=KEY, generation=7
        )
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(envelope, key=KEY)

    def test_lamport_scheme_envelope_rejected(self):
        lamport = OneTimeSigner(keygen(bits=32)[0])
        envelope = auth_state_wrap(
            lamport.checkpoint(), scheme="lamport", key=KEY, generation=7
        )
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(envelope, key=KEY)

    def test_bad_magic_rejected(self):
        bad = bytearray(self.envelope)
        bad[0] ^= 0xFF
        # Re-tag under the key would authenticate a bad-magic body, proving
        # the field check happens after HMAC.
        import hashlib
        import hmac

        body = bytes(bad[:-32])
        bad[-32:] = hmac.new(KEY, body, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(bytes(bad), key=KEY)

    def test_unknown_scheme_identifier_rejected(self):
        import hashlib
        import hmac

        bad = bytearray(self.envelope)
        bad[9] = 99
        body = bytes(bad[:-32])
        bad[-32:] = hmac.new(KEY, body, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(bytes(bad), key=KEY)

    def test_garbage_and_truncated_blobs_value_error(self):
        for bad in (b"", b"\x00", b"PQAAUTH\0", b"\x00" * 54, self.envelope[:-1]):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_auth_state(bad, key=KEY)

    def test_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(self.envelope + b"\x00", key=KEY)

    def test_invalid_checkpoint_payload_value_error(self):
        import hashlib
        import hmac

        # Authentic envelope claiming merkle whose payload is not a merkle
        # checkpoint: HMAC passes, the payload magic check fails before the
        # checkpoint is ever parsed.
        payload = b"PQAMSCP\0" + b"\x00" * 40
        body = (
            b"PQAAUTH\0"
            + bytes((2, 3))
            + (7).to_bytes(8, "big")
            + len(payload).to_bytes(4, "big")
            + payload
        )
        blob = body + hmac.new(KEY, body, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(blob, key=KEY)

    def test_corrupt_merkle_checkpoint_payload_value_error(self):
        import hashlib
        import hmac

        scheme, generation, payload = auth_state_unwrap(
            self.envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(scheme, "merkle")
        tampered = bytearray(payload)
        # Flip a private-key byte past the header/root; the checkpoint's own
        # SHA-256 checksum (or rebuilt root) then fails.
        tampered[-2] ^= 0x01
        body = (
            b"PQAAUTH\0"
            + bytes((2, 3))
            + generation.to_bytes(8, "big")
            + len(tampered).to_bytes(4, "big")
            + bytes(tampered)
        )
        blob = body + hmac.new(KEY, body, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(blob, key=KEY)

    def test_no_instance_on_failure(self):
        # A ValueError never leaves a partially restored signer behind:
        # callers only receive an object via the returned tuple.
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(self.envelope, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            MerkleSigner.from_auth_state(
                self.envelope, key=KEY, min_generation=10**9
            )

    def test_equivalent_to_unwrap_then_from_checkpoint(self):
        signer = make_signer(height=2, w=4)
        signer.sign("x")
        signer.sign("y")
        envelope = wrap(signer, generation=13)

        scheme, generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle", min_generation=13
        )
        reference = MerkleSigner.from_checkpoint(checkpoint)
        restored, restored_generation = MerkleSigner.from_auth_state(
            envelope, key=KEY, min_generation=13
        )
        self.assertEqual((scheme, generation), ("merkle", restored_generation))
        self.assertEqual(restored.public_key, reference.public_key)
        self.assertEqual(restored.next_index, reference.next_index)
        self.assertEqual(restored.remaining, reference.remaining)
        self.assertEqual(restored.checkpoint(), reference.checkpoint())


if __name__ == "__main__":
    unittest.main()

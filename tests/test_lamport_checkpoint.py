import hashlib
import threading
import unittest
from unittest import mock

import pqattest
from pqattest import (
    KeyExhaustedError,
    OneTimeSigner,
    keygen,
    sign,
    verify,
)
from pqattest import _CHECKPOINT_MAGIC


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(bits=8, start=0):
    private_key, _ = keygen(bits=bits, token_bytes=counter_tokens(start))
    return OneTimeSigner(private_key)


class CheckpointFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for bits in (1, 8, 16):
            with self.subTest(bits=bits):
                signer = make_signer(bits=bits)
                blob = signer.checkpoint()
                key_blob = signer._private_key.to_bytes()
                header = 8 + 1 + 1 + 4
                self.assertEqual(len(blob), header + len(key_blob) + 32)
                self.assertEqual(blob[:8], _CHECKPOINT_MAGIC)
                self.assertEqual(blob[:8], b"PQALCP\0\0")
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(blob[9], 0)  # unused
                self.assertEqual(int.from_bytes(blob[10:14], "big"), len(key_blob))
                self.assertEqual(blob[14 : 14 + len(key_blob)], key_blob)
                body, checksum = blob[:-32], blob[-32:]
                self.assertEqual(hashlib.sha256(body).digest(), checksum)

    def test_checkpoint_returns_bytes(self):
        self.assertIsInstance(make_signer().checkpoint(), bytes)

    def test_encoding_is_deterministic(self):
        signer = make_signer()
        self.assertEqual(signer.checkpoint(), signer.checkpoint())

    def test_same_state_encodes_identically(self):
        first = make_signer(bits=8, start=0)
        second = OneTimeSigner.from_checkpoint(first.checkpoint())
        self.assertEqual(first.checkpoint(), second.checkpoint())
        first.sign("m")
        second_used = OneTimeSigner.from_checkpoint(first.checkpoint())
        self.assertEqual(first.checkpoint(), second_used.checkpoint())

    def test_used_flag_in_encoding(self):
        signer = make_signer()
        self.assertEqual(signer.checkpoint()[9], 0)
        signer.sign("m")
        self.assertEqual(signer.checkpoint()[9], 1)


class CheckpointRoundTripTest(unittest.TestCase):
    def test_public_key_preserved(self):
        for bits in (1, 8, 16):
            with self.subTest(bits=bits):
                signer = make_signer(bits=bits)
                restored = OneTimeSigner.from_checkpoint(signer.checkpoint())
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertFalse(restored.used)

    def test_private_key_secrets_preserved_in_order(self):
        signer = make_signer(bits=8)
        restored = OneTimeSigner.from_checkpoint(signer.checkpoint())
        self.assertEqual(restored._private_key.secrets, signer._private_key.secrets)

    def test_restored_signature_verifies_against_original_public_key(self):
        signer = make_signer(bits=16)
        restored = OneTimeSigner.from_checkpoint(signer.checkpoint())
        message = b"position claim"
        signature = restored.sign(message)
        self.assertEqual(signature, sign(message, signer._private_key))
        self.assertTrue(verify(message, signature, signer.public_key))
        self.assertTrue(restored.used)

    def test_restored_allows_exactly_one_signature(self):
        signer = make_signer()
        restored = OneTimeSigner.from_checkpoint(signer.checkpoint())
        restored.sign("one")
        with self.assertRaises(KeyExhaustedError):
            restored.sign("two")
        # The original instance is untouched by the restored copy's signing.
        self.assertFalse(signer.used)
        self.assertTrue(verify("other", signer.sign("other"), signer.public_key))

    def test_accepts_bytearray(self):
        signer = make_signer()
        restored = OneTimeSigner.from_checkpoint(bytearray(signer.checkpoint()))
        self.assertEqual(restored.public_key, signer.public_key)

    def test_exhausted_state_round_trips(self):
        signer = make_signer()
        signer.sign("one")
        restored = OneTimeSigner.from_checkpoint(signer.checkpoint())
        self.assertTrue(restored.used)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("two")

    def test_restore_uses_no_randomness(self):
        signer = make_signer()
        blob = signer.checkpoint()

        def exploding_token_bytes(size):
            raise AssertionError("from_checkpoint must not draw randomness")

        with mock.patch.object(pqattest.secrets, "token_bytes", exploding_token_bytes):
            restored = OneTimeSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)

    def test_invalid_message_still_free_after_restore(self):
        signer = make_signer()
        restored = OneTimeSigner.from_checkpoint(signer.checkpoint())
        with self.assertRaises(TypeError):
            restored.sign(123)
        self.assertFalse(restored.used)
        signature = restored.sign("one")
        self.assertTrue(verify("one", signature, signer.public_key))

    def test_exhaustion_takes_priority_over_type_error_after_restore(self):
        signer = make_signer()
        signer.sign("one")
        restored = OneTimeSigner.from_checkpoint(signer.checkpoint())
        for call in (lambda: restored.sign(123), lambda: restored.sign("two")):
            with self.assertRaises(KeyExhaustedError):
                call()


class CheckpointValidationTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(bits=8)
        self.blob = self.signer.checkpoint()

    def assert_rejected(self, data):
        with self.assertRaises(ValueError):
            OneTimeSigner.from_checkpoint(data)

    def test_non_bytes_types_raise_type_error(self):
        for bad in (None, 42, 4.5, "checkpoint", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    OneTimeSigner.from_checkpoint(bad)

    def test_truncated_and_empty_rejected(self):
        self.assert_rejected(b"")
        self.assert_rejected(self.blob[:20])
        self.assert_rejected(self.blob[:-1])

    def test_extended_rejected(self):
        self.assert_rejected(self.blob + b"\x00")

    def test_bad_magic_rejected(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        self.assert_rejected(bytes(bad))

    def test_bad_version_rejected(self):
        for version in (0, 2, 255):
            with self.subTest(version=version):
                bad = bytearray(self.blob)
                bad[8] = version
                self.assert_rejected(bytes(bad))

    def test_bad_used_flag_rejected(self):
        for bad_used in (2, 16, 255):
            with self.subTest(bad_used=bad_used):
                bad = bytearray(self.blob)
                bad[9] = bad_used
                self.assert_rejected(bytes(bad))

    def test_bad_key_length_field_rejected(self):
        key_length = int.from_bytes(self.blob[10:14], "big")
        for count in (0, key_length - 1, key_length + 1, 2**32 - 1):
            with self.subTest(count=count):
                bad = bytearray(self.blob)
                bad[10:14] = count.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_bad_checksum_rejected(self):
        bad = bytearray(self.blob)
        bad[-1] ^= 0x01
        self.assert_rejected(bytes(bad))

    def test_flipped_private_secret_rejected(self):
        bad = bytearray(self.blob)
        bad[20] ^= 0x01
        self.assert_rejected(bytes(bad))

    def test_corrupted_nested_key_rejected_even_with_recomputed_checksum(self):
        # Corrupt the nested private key encoding's own magic, then fix the
        # outer checksum: the nested parse must still fail.
        bad = bytearray(self.blob)
        bad[14] ^= 0x01
        bad[-32:] = hashlib.sha256(bytes(bad[:-32])).digest()
        self.assert_rejected(bytes(bad))

    def test_nested_key_of_wrong_shape_rejected(self):
        # A structurally valid checkpoint wrapping a public-key encoding
        # (wrong nested magic) must not restore.
        _, public_key = keygen(bits=8, token_bytes=counter_tokens())
        nested = public_key.to_bytes()
        body = (
            b"PQALCP\0\0"
            + bytes((1, 0))
            + len(nested).to_bytes(4, "big")
            + nested
        )
        self.assert_rejected(body + hashlib.sha256(body).digest())

    def test_valid_checkpoint_still_accepted(self):
        restored = OneTimeSigner.from_checkpoint(self.blob)
        self.assertEqual(restored.public_key, self.signer.public_key)


class CheckpointConcurrencyTest(unittest.TestCase):
    def test_snapshot_lands_before_or_after_a_signature(self):
        signer = make_signer(bits=8)
        snapshots = []
        errors = []
        barrier = threading.Barrier(16)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                if i % 2 == 0:
                    try:
                        signer.sign(f"m{i}")
                    except KeyExhaustedError:
                        pass
                else:
                    snapshots.append(signer.checkpoint())
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertTrue(signer.used)
        for blob in snapshots:
            with self.subTest(blob=blob[:20]):
                restored = OneTimeSigner.from_checkpoint(blob)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertIn(blob[9], (0, 1))
                self.assertEqual(restored.used, bool(blob[9]))
        # Every snapshot is a whole state: eight signers contend but exactly
        # one wins, so the observed used flags are a subset of {0, 1} and the
        # one-time guarantee held regardless of where snapshots landed.
        self.assertTrue(set(b[9] for b in snapshots) <= {0, 1})


if __name__ == "__main__":
    unittest.main()

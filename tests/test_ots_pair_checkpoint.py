import hashlib
import threading
import unittest
from unittest import mock

import pqattest
from pqattest import (
    KeyExhaustedError,
    OneTimeSigner,
    WOTSOneTimeSigner,
    keygen,
    ots_pair_checkpoint,
    ots_pair_restore,
    verify,
    wots_keygen,
    wots_verify,
)

MAGIC = b"PQAOPCP\0"
HEADER = 8 + 1 + 4 + 4
CHECKSUM_BYTES = 32


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_lamport(start=0):
    private_key, _ = keygen(token_bytes=counter_tokens(start))
    return OneTimeSigner(private_key)


def make_wots(start=1000, w=4):
    private_key, _ = wots_keygen(w=w, token_bytes=counter_tokens(start))
    return WOTSOneTimeSigner(private_key)


def make_pair(w=4):
    return make_lamport(), make_wots(w=w)


def flip(blob, index, value=None):
    bad = bytearray(blob)
    bad[index] = value if value is not None else bad[index] ^ 0x01
    return bytes(bad)


class PairCheckpointFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for w in (4, 8):
            with self.subTest(w=w):
                lamport, wots = make_pair(w=w)
                lamport_blob = lamport.checkpoint()
                wots_blob = wots.checkpoint()
                blob = ots_pair_checkpoint(lamport, wots)
                expected = HEADER + len(lamport_blob) + len(wots_blob) + CHECKSUM_BYTES
                self.assertEqual(len(blob), expected)
                self.assertEqual(blob[:8], MAGIC)
                self.assertEqual(blob[8], 1)
                lamport_length = int.from_bytes(blob[9:13], "big")
                wots_length = int.from_bytes(blob[13:17], "big")
                self.assertEqual(lamport_length, len(lamport_blob))
                self.assertEqual(wots_length, len(wots_blob))
                lamport_end = HEADER + lamport_length
                wots_end = lamport_end + wots_length
                self.assertEqual(blob[HEADER:lamport_end], lamport_blob)
                self.assertEqual(blob[lamport_end:wots_end], wots_blob)
                body, checksum = blob[:-CHECKSUM_BYTES], blob[-CHECKSUM_BYTES:]
                self.assertEqual(hashlib.sha256(body).digest(), checksum)

    def test_returns_bytes(self):
        lamport, wots = make_pair()
        self.assertIsInstance(ots_pair_checkpoint(lamport, wots), bytes)

    def test_encoding_is_deterministic(self):
        lamport, wots = make_pair()
        self.assertEqual(
            ots_pair_checkpoint(lamport, wots), ots_pair_checkpoint(lamport, wots)
        )

    def test_same_state_encodes_identically(self):
        lamport, wots = make_pair()
        blob = ots_pair_checkpoint(lamport, wots)
        restored_lamport, restored_wots = ots_pair_restore(blob)
        self.assertEqual(ots_pair_checkpoint(restored_lamport, restored_wots), blob)
        lamport.sign("m")
        wots.sign("m")
        blob_used = ots_pair_checkpoint(lamport, wots)
        restored_lamport, restored_wots = ots_pair_restore(blob_used)
        self.assertEqual(ots_pair_checkpoint(restored_lamport, restored_wots), blob_used)

    def test_embedded_segments_are_existing_v1_checkpoints(self):
        lamport, wots = make_pair()
        blob = ots_pair_checkpoint(lamport, wots)
        lamport_length = int.from_bytes(blob[9:13], "big")
        wots_length = int.from_bytes(blob[13:17], "big")
        lamport_end = HEADER + lamport_length
        wots_end = lamport_end + wots_length
        # Each segment parses unchanged through its existing v1 parser.
        lamport_signer = OneTimeSigner.from_checkpoint(blob[HEADER:lamport_end])
        wots_signer = WOTSOneTimeSigner.from_checkpoint(blob[lamport_end:wots_end])
        self.assertEqual(lamport_signer.public_key, lamport.public_key)
        self.assertEqual(wots_signer.public_key, wots.public_key)
        self.assertEqual(len(blob), wots_end + CHECKSUM_BYTES)


class PairCheckpointRoundTripTest(unittest.TestCase):
    def test_public_keys_and_used_flags_preserved(self):
        for w in (4, 8):
            with self.subTest(w=w):
                lamport, wots = make_pair(w=w)
                restored_lamport, restored_wots = ots_pair_restore(
                    ots_pair_checkpoint(lamport, wots)
                )
                self.assertEqual(restored_lamport.public_key, lamport.public_key)
                self.assertEqual(restored_wots.public_key, wots.public_key)
                self.assertFalse(restored_lamport.used)
                self.assertFalse(restored_wots.used)

    def test_order_is_lamport_first_wots_second(self):
        lamport, wots = make_pair()
        result = ots_pair_restore(ots_pair_checkpoint(lamport, wots))
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        restored_lamport, restored_wots = result
        self.assertIsInstance(restored_lamport, OneTimeSigner)
        self.assertIsInstance(restored_wots, WOTSOneTimeSigner)

    def test_restored_unused_pair_allows_exactly_one_signature_each(self):
        lamport, wots = make_pair()
        restored_lamport, restored_wots = ots_pair_restore(
            ots_pair_checkpoint(lamport, wots)
        )
        message = b"position claim"
        lamport_signature = restored_lamport.sign(message)
        wots_signature = restored_wots.sign(message)
        self.assertTrue(verify(message, lamport_signature, lamport.public_key))
        self.assertTrue(wots_verify(message, wots_signature, wots.public_key))
        with self.assertRaises(KeyExhaustedError):
            restored_lamport.sign("two")
        with self.assertRaises(KeyExhaustedError):
            restored_wots.sign("two")

    def test_one_side_used_other_side_unused(self):
        lamport, wots = make_pair()
        lamport.sign("only-lamport")
        restored_lamport, restored_wots = ots_pair_restore(
            ots_pair_checkpoint(lamport, wots)
        )
        self.assertTrue(restored_lamport.used)
        self.assertFalse(restored_wots.used)
        with self.assertRaises(KeyExhaustedError):
            restored_lamport.sign("m")
        signature = restored_wots.sign("m")
        self.assertTrue(wots_verify("m", signature, wots.public_key))

        lamport2, wots2 = make_pair()
        wots2.sign("only-wots")
        restored_lamport2, restored_wots2 = ots_pair_restore(
            ots_pair_checkpoint(lamport2, wots2)
        )
        self.assertFalse(restored_lamport2.used)
        self.assertTrue(restored_wots2.used)
        signature = restored_lamport2.sign("m")
        self.assertTrue(verify("m", signature, lamport2.public_key))
        with self.assertRaises(KeyExhaustedError):
            restored_wots2.sign("m")

    def test_both_sides_used_round_trip(self):
        lamport, wots = make_pair()
        lamport.sign("m")
        wots.sign("m")
        restored_lamport, restored_wots = ots_pair_restore(
            ots_pair_checkpoint(lamport, wots)
        )
        self.assertTrue(restored_lamport.used)
        self.assertTrue(restored_wots.used)
        with self.assertRaises(KeyExhaustedError):
            restored_lamport.sign("n")
        with self.assertRaises(KeyExhaustedError):
            restored_wots.sign("n")

    def test_accepts_bytearray(self):
        lamport, wots = make_pair()
        restored_lamport, restored_wots = ots_pair_restore(
            bytearray(ots_pair_checkpoint(lamport, wots))
        )
        self.assertEqual(restored_lamport.public_key, lamport.public_key)
        self.assertEqual(restored_wots.public_key, wots.public_key)

    def test_restore_uses_no_randomness(self):
        lamport, wots = make_pair()
        blob = ots_pair_checkpoint(lamport, wots)

        def exploding_token_bytes(size):
            raise AssertionError("ots_pair_restore must not draw randomness")

        with mock.patch.object(pqattest.secrets, "token_bytes", exploding_token_bytes):
            restored_lamport, restored_wots = ots_pair_restore(blob)
        self.assertEqual(restored_lamport.public_key, lamport.public_key)
        self.assertEqual(restored_wots.public_key, wots.public_key)

    def test_checkpoint_does_not_mutate_inputs(self):
        lamport, wots = make_pair()
        blob = ots_pair_checkpoint(lamport, wots)
        self.assertFalse(lamport.used)
        self.assertFalse(wots.used)
        # Re-encoding the untouched signers yields the same bytes.
        self.assertEqual(ots_pair_checkpoint(lamport, wots), blob)


class PairCheckpointTypeTest(unittest.TestCase):
    def test_checkpoint_rejects_wrong_argument_types(self):
        lamport, wots = make_pair()
        lamport_private = lamport._private_key
        wots_private = wots._private_key
        wrong_pairs = [
            (wots, lamport),  # reversed order
            (lamport_private, wots),
            (lamport, wots_private),
            ("signer", wots),
            (lamport, "signer"),
            (None, wots),
            (lamport, None),
            (42, wots),
            (lamport, object()),
        ]
        for first, second in wrong_pairs:
            with self.subTest(first=type(first).__name__, second=type(second).__name__):
                with self.assertRaises(TypeError):
                    ots_pair_checkpoint(first, second)

    def test_checkpoint_requires_both_arguments(self):
        lamport, _ = make_pair()
        with self.assertRaises(TypeError):
            ots_pair_checkpoint(lamport)

    def test_restore_rejects_non_bytes_types(self):
        lamport, wots = make_pair()
        blob = ots_pair_checkpoint(lamport, wots)
        for bad in (None, 42, 4.5, "checkpoint", [blob], (blob,), object(), memoryview(blob)):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    ots_pair_restore(bad)


class PairCheckpointValidationTest(unittest.TestCase):
    def setUp(self):
        self.lamport, self.wots = make_pair()
        self.blob = ots_pair_checkpoint(self.lamport, self.wots)
        self.lamport_length = int.from_bytes(self.blob[9:13], "big")
        self.wots_length = int.from_bytes(self.blob[13:17], "big")
        self.lamport_end = HEADER + self.lamport_length
        self.wots_end = self.lamport_end + self.wots_length

    def assert_rejected(self, data):
        with self.assertRaises(ValueError):
            ots_pair_restore(data)

    def test_empty_and_truncated_rejected(self):
        self.assert_rejected(b"")
        self.assert_rejected(self.blob[:HEADER - 1])
        self.assert_rejected(self.blob[:HEADER])
        self.assert_rejected(self.blob[: self.lamport_end])
        self.assert_rejected(self.blob[: self.wots_end])
        self.assert_rejected(self.blob[:-1])

    def test_trailing_data_rejected(self):
        self.assert_rejected(self.blob + b"\x00")
        self.assert_rejected(self.blob + b"extra")

    def test_bad_magic_rejected(self):
        self.assert_rejected(flip(self.blob, 0))
        self.assert_rejected(flip(self.blob, 7))

    def test_unknown_version_rejected(self):
        for version in (0, 2, 255):
            with self.subTest(version=version):
                self.assert_rejected(flip(self.blob, 8, version))

    def test_zero_length_fields_rejected(self):
        bad = bytearray(self.blob)
        bad[9:13] = (0).to_bytes(4, "big")
        self.assert_rejected(bytes(bad))
        bad = bytearray(self.blob)
        bad[13:17] = (0).to_bytes(4, "big")
        self.assert_rejected(bytes(bad))

    def test_length_too_large_rejected(self):
        bad = bytearray(self.blob)
        bad[9:13] = (self.lamport_length + 1).to_bytes(4, "big")
        self.assert_rejected(bytes(bad))
        bad = bytearray(self.blob)
        bad[13:17] = (self.wots_length + 1).to_bytes(4, "big")
        self.assert_rejected(bytes(bad))

    def test_length_too_small_rejected(self):
        bad = bytearray(self.blob)
        bad[9:13] = (self.lamport_length - 1).to_bytes(4, "big")
        self.assert_rejected(bytes(bad))
        bad = bytearray(self.blob)
        bad[13:17] = (self.wots_length - 1).to_bytes(4, "big")
        self.assert_rejected(bytes(bad))

    def test_bad_checksum_rejected(self):
        self.assert_rejected(flip(self.blob, len(self.blob) - 1))

    def test_flipped_lamport_segment_rejected(self):
        # A flip inside the embedded Lamport checkpoint breaks its own v1
        # checksum even though the outer checksum is fixed up.
        bad = bytearray(self.blob)
        bad[HEADER + 10] ^= 0x01
        checksum_input = bytes(bad[:-CHECKSUM_BYTES])
        bad[-CHECKSUM_BYTES:] = hashlib.sha256(checksum_input).digest()
        self.assert_rejected(bytes(bad))

    def test_flipped_wots_segment_rejected(self):
        bad = bytearray(self.blob)
        bad[self.lamport_end + 10] ^= 0x01
        checksum_input = bytes(bad[:-CHECKSUM_BYTES])
        bad[-CHECKSUM_BYTES:] = hashlib.sha256(checksum_input).digest()
        self.assert_rejected(bytes(bad))

    def test_swapped_segments_rejected(self):
        # Present the W-OTS checkpoint where the Lamport one must be; its own
        # v1 parser must fail on the foreign magic.
        lamport_segment = self.blob[HEADER:self.lamport_end]
        wots_segment = self.blob[self.lamport_end:self.wots_end]
        body = (
            MAGIC
            + bytes((1,))
            + len(wots_segment).to_bytes(4, "big")
            + len(lamport_segment).to_bytes(4, "big")
            + wots_segment
            + lamport_segment
        )
        self.assert_rejected(body + hashlib.sha256(body).digest())

    def test_nested_lamport_magic_corrupted_rejected(self):
        bad = bytearray(self.blob)
        bad[HEADER] ^= 0x01
        checksum_input = bytes(bad[:-CHECKSUM_BYTES])
        bad[-CHECKSUM_BYTES:] = hashlib.sha256(checksum_input).digest()
        self.assert_rejected(bytes(bad))

    def test_nested_wots_magic_corrupted_rejected(self):
        bad = bytearray(self.blob)
        bad[self.lamport_end] ^= 0x01
        checksum_input = bytes(bad[:-CHECKSUM_BYTES])
        bad[-CHECKSUM_BYTES:] = hashlib.sha256(checksum_input).digest()
        self.assert_rejected(bytes(bad))

    def test_failure_returns_no_instance_side_effect(self):
        result = None
        try:
            result = ots_pair_restore(flip(self.blob, 0))
        except ValueError:
            pass
        self.assertIsNone(result)

    def test_valid_checkpoint_still_accepted(self):
        restored_lamport, restored_wots = ots_pair_restore(self.blob)
        self.assertEqual(restored_lamport.public_key, self.lamport.public_key)
        self.assertEqual(restored_wots.public_key, self.wots.public_key)


class PairCheckpointConcurrencyTest(unittest.TestCase):
    def test_snapshot_lands_before_or_after_each_signature(self):
        lamport, wots = make_pair()
        snapshots = []
        errors = []
        barrier = threading.Barrier(24)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                if i % 3 == 0:
                    try:
                        lamport.sign(f"l{i}")
                    except KeyExhaustedError:
                        pass
                elif i % 3 == 1:
                    try:
                        wots.sign(f"w{i}")
                    except KeyExhaustedError:
                        pass
                else:
                    snapshots.append(ots_pair_checkpoint(lamport, wots))
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(24)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertTrue(lamport.used)
        self.assertTrue(wots.used)
        for blob in snapshots:
            with self.subTest(blob=blob[:20]):
                restored_lamport, restored_wots = ots_pair_restore(blob)
                self.assertEqual(restored_lamport.public_key, lamport.public_key)
                self.assertEqual(restored_wots.public_key, wots.public_key)
                # Every snapshot is a whole state on each side, never a
                # half-advanced one: the restored used flag must match the
                # used byte embedded in each v1 segment.
                lamport_length = int.from_bytes(blob[9:13], "big")
                self.assertEqual(restored_lamport.used, bool(blob[HEADER + 9]))
                self.assertEqual(
                    restored_wots.used, bool(blob[HEADER + lamport_length + 10])
                )


if __name__ == "__main__":
    unittest.main()

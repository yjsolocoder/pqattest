import hashlib
import threading
import unittest

from pqattest import KeyExhaustedError, MerkleSigner, merkle_verify
from pqattest.merkle import _CHECKPOINT_MAGIC


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


class CheckpointFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for w, chains in ((4, 67), (8, 34)):
            with self.subTest(w=w):
                signer = make_signer(height=2, w=w)
                blob = signer.checkpoint()
                header = 8 + 1 + 1 + 1 + 2 + 4 + 32
                self.assertEqual(len(blob), header + 4 * chains * 32 + 32)
                self.assertEqual(blob[:8], _CHECKPOINT_MAGIC)
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(blob[9], w)
                self.assertEqual(blob[10], 2)  # height
                self.assertEqual(int.from_bytes(blob[11:13], "big"), 0)  # next_index
                self.assertEqual(int.from_bytes(blob[13:17], "big"), 4 * chains)
                self.assertEqual(blob[17:49], signer.public_key.root)
                body, checksum = blob[:-32], blob[-32:]
                self.assertEqual(hashlib.sha256(body).digest(), checksum)

    def test_checkpoint_returns_bytes(self):
        signer = make_signer()
        self.assertIsInstance(signer.checkpoint(), bytes)

    def test_next_index_field_tracks_signatures(self):
        signer = make_signer()
        signer.sign("one")
        signer.sign("two")
        blob = signer.checkpoint()
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)

    def test_v1_format_unchanged_by_advance_to(self):
        signer = make_signer(height=2)
        fresh = signer.checkpoint()
        signer.advance_to(3)
        blob = signer.checkpoint()
        # Same magic, version and total length — only next_index differs.
        self.assertEqual(len(blob), len(fresh))
        self.assertEqual(blob[:8], _CHECKPOINT_MAGIC)
        self.assertEqual(blob[8], 1)  # version
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 3)
        # Everything except the next_index field is byte-identical in the body.
        self.assertEqual(blob[:11], fresh[:11])
        self.assertEqual(blob[13:-32], fresh[13:-32])
        # The trailing checksum changes (it covers next_index) and stays valid.
        self.assertEqual(hashlib.sha256(blob[:-32]).digest(), blob[-32:])

    def test_advanced_state_round_trip(self):
        signer = make_signer(height=3)
        signer.advance_to(5)
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 5)
        self.assertEqual(restored.remaining, 3)
        self.assertEqual(restored.sign("m").index, 5)

    def test_advance_to_exhausted_boundary_round_trips(self):
        signer = make_signer(height=2)
        signer.advance_to(4)
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("m")


class CheckpointRoundTripTest(unittest.TestCase):
    def test_public_key_and_state_preserved(self):
        signer = make_signer(height=3, w=8)
        signer.sign("one")
        signer.sign("two")
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        self.assertEqual(restored.public_key, signer.public_key)
        # Signing resumes at the saved next_index on both instances.
        self.assertEqual(restored.sign("three").index, 2)
        self.assertEqual(signer.sign("three").index, 2)

    def test_restored_signatures_verify(self):
        signer = make_signer(height=3)
        for i in range(3):
            signer.sign(f"m{i}")
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        for i in range(3, 8):
            message = f"m{i}"
            signature = restored.sign(message)
            self.assertEqual(signature.index, i)
            self.assertTrue(merkle_verify(message, signature, signer.public_key))

    def test_fresh_checkpoint_round_trip(self):
        signer = make_signer()
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.sign("m").index, 0)

    def test_accepts_bytearray(self):
        signer = make_signer()
        restored = MerkleSigner.from_checkpoint(bytearray(signer.checkpoint()))
        self.assertEqual(restored.public_key, signer.public_key)

    def test_exhausted_state_round_trip(self):
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        with self.assertRaises(KeyExhaustedError):
            restored.sign("three")

    def test_restore_uses_no_randomness(self):
        signer = make_signer()
        blob = signer.checkpoint()

        def exploding_token_bytes(size):
            raise AssertionError("from_checkpoint must not draw randomness")

        import pqattest.merkle
        from unittest import mock

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertTrue(merkle_verify("m", restored.sign("m"), signer.public_key))

    def test_invalid_message_still_free_after_restore(self):
        signer = make_signer(height=1)
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        with self.assertRaises(TypeError):
            restored.sign(123)
        self.assertEqual(restored.sign("one").index, 0)


class CheckpointValidationTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=2)
        self.blob = self.signer.checkpoint()

    def assert_rejected(self, data):
        with self.assertRaises(ValueError):
            MerkleSigner.from_checkpoint(data)

    def test_non_bytes_types_raise_type_error(self):
        for bad in (None, 42, 4.5, "checkpoint", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleSigner.from_checkpoint(bad)

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
        bad = bytearray(self.blob)
        bad[8] = 2
        self.assert_rejected(bytes(bad))

    def test_bad_w_rejected(self):
        for bad_w in (0, 2, 16, 255):
            with self.subTest(bad_w=bad_w):
                bad = bytearray(self.blob)
                bad[9] = bad_w
                self.assert_rejected(bytes(bad))

    def test_bad_height_rejected(self):
        for bad_height in (0, 9, 255):
            with self.subTest(bad_height=bad_height):
                bad = bytearray(self.blob)
                bad[10] = bad_height
                self.assert_rejected(bytes(bad))

    def test_out_of_range_next_index_rejected(self):
        bad = bytearray(self.blob)
        bad[11:13] = (5).to_bytes(2, "big")  # height 2 -> 4 leaves
        self.assert_rejected(bytes(bad))

    def test_boundary_next_index_accepted(self):
        # next_index == 2 ** height is the exhausted state and must restore.
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        blob = bytearray(signer.checkpoint())
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 2)
        restored = MerkleSigner.from_checkpoint(bytes(blob))
        with self.assertRaises(KeyExhaustedError):
            restored.sign("three")

    def test_bad_element_count_rejected(self):
        for count in (0, 4 * 67 - 1, 4 * 67 + 1, 8 * 67):
            with self.subTest(count=count):
                bad = bytearray(self.blob)
                bad[13:17] = count.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_bad_checksum_rejected(self):
        bad = bytearray(self.blob)
        bad[-1] ^= 0x01
        self.assert_rejected(bytes(bad))

    def test_flipped_private_element_rejected(self):
        # Corrupting a private key breaks the checksum...
        bad = bytearray(self.blob)
        bad[60] ^= 0x01
        self.assert_rejected(bytes(bad))
        # ...and with the checksum recomputed the rebuilt root must not match.
        bad[-32:] = hashlib.sha256(bytes(bad[:-32])).digest()
        self.assert_rejected(bytes(bad))

    def test_forged_root_rejected(self):
        # A root that does not match the private keys fails even with a
        # recomputed checksum.
        bad = bytearray(self.blob)
        bad[17] ^= 0x01
        bad[-32:] = hashlib.sha256(bytes(bad[:-32])).digest()
        self.assert_rejected(bytes(bad))

    def test_valid_checkpoint_still_accepted(self):
        # Guard against the corruption tests making the helper too strict.
        restored = MerkleSigner.from_checkpoint(self.blob)
        self.assertEqual(restored.public_key, self.signer.public_key)


class CheckpointConcurrencyTest(unittest.TestCase):
    def test_snapshot_lands_before_or_after_a_signature(self):
        height = 4
        signer = make_signer(height=height)
        snapshots = []
        errors = []
        barrier = threading.Barrier(1 << height)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                if i % 2 == 0:
                    signer.sign(f"m{i}")
                else:
                    snapshots.append(signer.checkpoint())
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(1 << height)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        for blob in snapshots:
            with self.subTest(blob=blob[:20]):
                restored = MerkleSigner.from_checkpoint(blob)
                self.assertEqual(restored.public_key, signer.public_key)
                # Every snapshot parses and reflects a whole number of
                # completed signatures between 0 and the final count.
                next_index = int.from_bytes(blob[11:13], "big")
                self.assertGreaterEqual(next_index, 0)
                self.assertLessEqual(next_index, (1 << height) // 2)


if __name__ == "__main__":
    unittest.main()

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


def corrupt(data: bytes, offset: int) -> bytes:
    mutated = bytearray(data)
    mutated[offset] ^= 0x01
    return bytes(mutated)


class RoundTripTest(unittest.TestCase):
    def test_public_key_and_cursor_survive(self):
        signer = make_signer(height=3)
        signer.sign("one")
        signer.sign("two")
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        self.assertEqual(restored.public_key, signer.public_key)
        for i in range(2, 8):
            signature = restored.sign(f"m{i}")
            self.assertEqual(signature.index, i)
            self.assertTrue(merkle_verify(f"m{i}", signature, restored.public_key))
        with self.assertRaises(KeyExhaustedError):
            restored.sign("one too many")

    def test_restored_signatures_verify_against_original_key(self):
        signer = make_signer(height=2)
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        for i in range(4):
            message = f"continuity-{i}"
            signature = restored.sign(message)
            self.assertTrue(merkle_verify(message, signature, signer.public_key))

    def test_fresh_checkpoint_continues_at_zero(self):
        signer = make_signer()
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        self.assertEqual(restored.sign("m").index, 0)

    def test_exhausted_checkpoint_stays_exhausted(self):
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        with self.assertRaises(KeyExhaustedError):
            restored.sign("three")

    def test_bytearray_accepted(self):
        signer = make_signer()
        signer.sign("one")
        restored = MerkleSigner.from_checkpoint(bytearray(signer.checkpoint()))
        self.assertEqual(restored.sign("two").index, 1)

    def test_both_w_round_trip(self):
        for w in (4, 8):
            with self.subTest(w=w):
                signer = make_signer(height=2, w=w)
                signer.sign("one")
                restored = MerkleSigner.from_checkpoint(signer.checkpoint())
                self.assertEqual(restored.public_key, signer.public_key)
                signature = restored.sign("two")
                self.assertEqual(signature.index, 1)
                self.assertTrue(merkle_verify("two", signature, signer.public_key))

    def test_restore_draws_no_randomness(self):
        # from_checkpoint takes no token_bytes source at all: restoring and
        # subsequent signing work purely from the checkpoint bytes.
        signer = make_signer()
        data = signer.checkpoint()
        restored = MerkleSigner.from_checkpoint(data)
        signature = restored.sign("m")
        self.assertTrue(merkle_verify("m", signature, restored.public_key))
        again = MerkleSigner.from_checkpoint(data)
        self.assertEqual(again.public_key, restored.public_key)

    def test_invalid_message_after_restore_consumes_no_leaf(self):
        signer = make_signer(height=1)
        restored = MerkleSigner.from_checkpoint(signer.checkpoint())
        with self.assertRaises(TypeError):
            restored.sign(123)
        self.assertEqual(restored.sign("one").index, 0)
        self.assertEqual(restored.sign("two").index, 1)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("three")

    def test_checkpoint_does_not_consume_leaf(self):
        signer = make_signer(height=1)
        signer.checkpoint()
        self.assertEqual(signer.sign("one").index, 0)


class LayoutTest(unittest.TestCase):
    def test_v1_layout(self):
        height, w, chains = 2, 4, 67
        signer = make_signer(height=height, w=w)
        signer.sign("one")
        signer.sign("two")
        data = signer.checkpoint()
        element_count = (1 << height) * chains
        self.assertEqual(len(data), 49 + element_count * 32 + 32)
        self.assertEqual(data[:8], b"PQAMSCP\0")
        self.assertEqual(data[:8], _CHECKPOINT_MAGIC)
        self.assertEqual(data[8], 1)
        self.assertEqual(data[9], w)
        self.assertEqual(data[10], height)
        self.assertEqual(int.from_bytes(data[11:13], "big"), 2)
        self.assertEqual(int.from_bytes(data[13:17], "big"), element_count)
        self.assertEqual(data[17:49], signer.public_key.root)
        self.assertEqual(hashlib.sha256(data[:-32]).digest(), data[-32:])

    def test_element_count_scales_with_height_and_w(self):
        for w, chains in ((4, 67), (8, 34)):
            for height in (1, 3):
                with self.subTest(w=w, height=height):
                    data = make_signer(height=height, w=w).checkpoint()
                    self.assertEqual(
                        len(data), 49 + (1 << height) * chains * 32 + 32
                    )


class RejectionTest(unittest.TestCase):
    def test_non_bytes_types_raise_type_error(self):
        signer = make_signer()
        good = signer.checkpoint()
        for bad in (
            None,
            42,
            4.0,
            "checkpoint",
            good.decode("latin1"),
            list(good),
            tuple(good),
            memoryview(good),
            object(),
        ):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleSigner.from_checkpoint(bad)

    def test_truncated_and_empty(self):
        good = make_signer().checkpoint()
        for bad in (b"", b"PQAMSCP\0", good[:48], good[:80], good[:-1]):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_checkpoint(bad)

    def test_trailing_garbage_rejected(self):
        good = make_signer().checkpoint()
        with self.assertRaises(ValueError):
            MerkleSigner.from_checkpoint(good + b"\x00")

    def test_bad_magic(self):
        good = make_signer().checkpoint()
        with self.assertRaises(ValueError):
            MerkleSigner.from_checkpoint(corrupt(good, 0))
        with self.assertRaises(ValueError):
            MerkleSigner.from_checkpoint(b"PQAMSCP1" + good[8:])

    def test_bad_version(self):
        good = make_signer().checkpoint()
        for version in (0, 2, 255):
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_checkpoint(good[:8] + bytes([version]) + good[9:])

    def test_bad_w(self):
        good = make_signer(w=4).checkpoint()
        for bad_w in (0, 2, 16):
            with self.subTest(bad_w=bad_w):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_checkpoint(good[:9] + bytes([bad_w]) + good[10:])

    def test_bad_height(self):
        good = make_signer(height=2).checkpoint()
        for bad_height in (0, 9, 255):
            with self.subTest(bad_height=bad_height):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_checkpoint(
                        good[:10] + bytes([bad_height]) + good[11:]
                    )

    def test_next_index_out_of_range(self):
        good = make_signer(height=2).checkpoint()  # 4 leaves
        for bad_index in (5, 100, 65535):
            with self.subTest(bad_index=bad_index):
                data = good[:11] + bad_index.to_bytes(2, "big") + good[13:]
                data = data[:-32] + hashlib.sha256(data[:-32]).digest()
                with self.assertRaises(ValueError):
                    MerkleSigner.from_checkpoint(data)

    def test_next_index_at_leaf_count_is_valid_exhausted(self):
        signer = make_signer(height=2)
        good = signer.checkpoint()
        data = good[:11] + (4).to_bytes(2, "big") + good[13:]
        data = data[:-32] + hashlib.sha256(data[:-32]).digest()
        restored = MerkleSigner.from_checkpoint(data)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("m")

    def test_bad_element_count(self):
        good = make_signer(height=2, w=4).checkpoint()  # 268 elements
        for bad_count in (0, 267, 269, 4 * 34):
            with self.subTest(bad_count=bad_count):
                data = good[:13] + bad_count.to_bytes(4, "big") + good[17:]
                data = data[:-32] + hashlib.sha256(data[:-32]).digest()
                with self.assertRaises(ValueError):
                    MerkleSigner.from_checkpoint(data)

    def test_bad_checksum(self):
        good = make_signer().checkpoint()
        with self.assertRaises(ValueError):
            MerkleSigner.from_checkpoint(good[:-1] + bytes([good[-1] ^ 0x01]))

    def test_tampered_private_element_rejected(self):
        good = make_signer().checkpoint()
        with self.assertRaises(ValueError):
            MerkleSigner.from_checkpoint(corrupt(good, 49))
        with self.assertRaises(ValueError):
            MerkleSigner.from_checkpoint(corrupt(good, len(good) - 33))

    def test_tampered_root_rejected(self):
        good = make_signer().checkpoint()
        data = corrupt(good, 17)
        data = data[:-32] + hashlib.sha256(data[:-32]).digest()
        with self.assertRaises(ValueError):
            MerkleSigner.from_checkpoint(data)

    def test_tampered_header_fields_rejected_by_length_or_checksum(self):
        good = make_signer().checkpoint()
        # Flipping any byte anywhere invalidates the checkpoint.
        for offset in (8, 11, 13, 100):
            with self.subTest(offset=offset):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_checkpoint(corrupt(good, offset))


class ConcurrencyTest(unittest.TestCase):
    def test_concurrent_checkpoint_lands_on_signature_boundary(self):
        height = 3
        leaf_count = 1 << height
        signer = make_signer(height=height)
        checkpoints = []
        errors = []
        barrier = threading.Barrier(leaf_count)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                checkpoints.append(signer.checkpoint())
                signer.sign(f"m{i}")
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(leaf_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        # Every snapshot was taken between whole signatures: its cursor equals
        # the number of signatures completed before it, and a restored signer
        # continues exactly from there.
        for data in checkpoints:
            cursor = int.from_bytes(data[11:13], "big")
            self.assertTrue(0 <= cursor <= leaf_count)
            restored = MerkleSigner.from_checkpoint(data)
            self.assertEqual(restored.public_key, signer.public_key)
            if cursor < leaf_count:
                self.assertEqual(restored.sign("after").index, cursor)
            else:
                with self.assertRaises(KeyExhaustedError):
                    restored.sign("after")

    def test_checkpoint_after_each_sign_tracks_cursor(self):
        signer = make_signer(height=2)
        for expected_next in range(1, 5):
            signer.sign(f"m{expected_next}")
            data = signer.checkpoint()
            self.assertEqual(int.from_bytes(data[11:13], "big"), expected_next)
            restored = MerkleSigner.from_checkpoint(data)
            if expected_next < 4:
                self.assertEqual(restored.sign("next").index, expected_next)
            else:
                with self.assertRaises(KeyExhaustedError):
                    restored.sign("next")


if __name__ == "__main__":
    unittest.main()

import threading
import unittest
from unittest import mock

import pqattest.wots
from pqattest import (
    KeyExhaustedError,
    WOTSOneTimeSigner,
    wots_keygen,
    wots_verify,
)


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(w=4, start=0):
    private_key, _ = wots_keygen(w=w, token_bytes=counter_tokens(start))
    return WOTSOneTimeSigner(private_key)


class SignWithCheckpointTest(unittest.TestCase):
    def test_returns_signature_tuple_and_bytes(self):
        signer = make_signer()
        signature, blob = signer.sign_with_checkpoint("m")
        self.assertIsInstance(signature, tuple)
        self.assertTrue(all(isinstance(part, bytes) for part in signature))
        self.assertIsInstance(blob, bytes)

    def test_signature_matches_plain_sign_from_same_state(self):
        signer = make_signer()
        reference = make_signer()
        signature, _ = signer.sign_with_checkpoint("m")
        self.assertEqual(signature, reference.sign("m"))

    def test_checkpoint_matches_post_sign_checkpoint(self):
        signer = make_signer()
        reference = make_signer()
        _, blob = signer.sign_with_checkpoint("m")
        reference.sign("m")
        self.assertEqual(blob, reference.checkpoint())

    def test_checkpoint_matches_later_checkpoint_on_same_signer(self):
        signer = make_signer()
        _, blob = signer.sign_with_checkpoint("m")
        self.assertEqual(blob, signer.checkpoint())

    def test_marks_key_used(self):
        signer = make_signer()
        signer.sign_with_checkpoint("m")
        self.assertTrue(signer.used)
        with self.assertRaises(KeyExhaustedError):
            signer.sign("m")

    def test_signature_verifies_for_both_w(self):
        for w in (4, 8):
            with self.subTest(w=w):
                signer = make_signer(w=w)
                signature, _ = signer.sign_with_checkpoint("m")
                self.assertTrue(wots_verify("m", signature, signer.public_key))

    def test_accepts_bytes_bytearray_and_str(self):
        for message in (b"m", bytearray(b"m"), "m"):
            with self.subTest(message=type(message).__name__):
                signer = make_signer()
                signature, blob = signer.sign_with_checkpoint(message)
                self.assertTrue(wots_verify(b"m", signature, signer.public_key))
                self.assertEqual(blob[10], 1)

    def test_restored_checkpoint_is_exhausted_with_same_public_key(self):
        signer = make_signer()
        signature, blob = signer.sign_with_checkpoint("m")
        self.assertTrue(wots_verify("m", signature, signer.public_key))
        restored = WOTSOneTimeSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertTrue(restored.used)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("other")
        restored_again = WOTSOneTimeSigner.from_checkpoint(bytes(blob))
        self.assertEqual(restored_again.public_key, signer.public_key)
        with self.assertRaises(KeyExhaustedError):
            restored_again.sign_with_checkpoint("other")

    def test_draws_no_randomness(self):
        signer = make_signer()

        def exploding_token_bytes(size):
            raise AssertionError("sign_with_checkpoint must not draw randomness")

        with mock.patch.object(
            pqattest.wots.secrets, "token_bytes", exploding_token_bytes
        ):
            signature, blob = signer.sign_with_checkpoint("m")
        self.assertEqual(len(signature), signer.public_key.length)
        self.assertEqual(blob[10], 1)

    def test_invalid_message_raises_type_error_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, 4.5, [b"m"], (b"m",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_with_checkpoint(bad)
        self.assertFalse(signer.used)
        self.assertEqual(signer.sign_with_checkpoint("m")[0], make_signer().sign("m"))

    def test_used_signer_raises_without_partial_result(self):
        signer = make_signer()
        signer.sign("one")
        before = signer.checkpoint()
        with self.assertRaises(KeyExhaustedError):
            signer.sign_with_checkpoint("two")
        self.assertEqual(signer.checkpoint(), before)

    def test_exhaustion_takes_priority_over_type_error(self):
        signer = make_signer()
        signer.sign_with_checkpoint("one")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_with_checkpoint(123)


class SignWithCheckpointConcurrencyTest(unittest.TestCase):
    def test_linearises_with_sign_and_checkpoint(self):
        signer = make_signer()
        worker_count = 16
        barrier = threading.Barrier(worker_count)
        atomic = []
        plain = []
        snapshots = []
        errors = []

        def worker(i):
            try:
                barrier.wait(timeout=10)
                if i % 3 == 0:
                    try:
                        atomic.append(signer.sign_with_checkpoint(f"m{i}"))
                    except KeyExhaustedError:
                        pass
                elif i % 3 == 1:
                    try:
                        plain.append(signer.sign(f"m{i}"))
                    except KeyExhaustedError:
                        pass
                else:
                    snapshots.append(signer.checkpoint())
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(worker_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])

        self.assertEqual(len(atomic) + len(plain), 1)
        self.assertTrue(signer.used)

        for blob in snapshots:
            restored = WOTSOneTimeSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)
            self.assertEqual(restored.used, bool(blob[10]))
        for _, blob in atomic:
            restored = WOTSOneTimeSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)
            self.assertTrue(restored.used)


if __name__ == "__main__":
    unittest.main()

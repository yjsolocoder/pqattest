import threading
import unittest

from pqattest import (
    KeyExhaustedError,
    OneTimeSigner,
    WOTSOneTimeSigner,
    keygen,
    verify,
    wots_keygen,
    wots_verify,
)


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


class SignOtsWithCheckpointTestMixin:
    def make_signer(self, start=0):
        raise NotImplementedError

    def stateless_verify(self, message, signature, public_key):
        raise NotImplementedError

    def test_returns_signature_tuple_and_bytes(self):
        signer = self.make_signer()
        signature, blob = signer.sign_with_checkpoint("m")
        self.assertIsInstance(signature, tuple)
        self.assertTrue(all(isinstance(part, bytes) for part in signature))
        self.assertIsInstance(blob, bytes)

    def test_signature_matches_plain_sign_from_same_state(self):
        signer = self.make_signer()
        reference = self.make_signer()
        signature, _ = signer.sign_with_checkpoint("m")
        self.assertEqual(signature, reference.sign("m"))

    def test_checkpoint_matches_post_sign_checkpoint(self):
        signer = self.make_signer()
        reference = self.make_signer()
        _, blob = signer.sign_with_checkpoint("m")
        reference.sign("m")
        self.assertEqual(blob, reference.checkpoint())

    def test_checkpoint_restores_used_state_with_same_public_key(self):
        signer = self.make_signer()
        public_key = signer.public_key
        signature, blob = signer.sign_with_checkpoint("m")
        self.assertTrue(self.stateless_verify("m", signature, public_key))
        restored = type(signer).from_checkpoint(blob)
        self.assertEqual(restored.public_key, public_key)
        self.assertTrue(restored.used)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("m")
        with self.assertRaises(KeyExhaustedError):
            restored.sign_with_checkpoint("m")

    def test_marks_signer_used(self):
        signer = self.make_signer()
        signer.sign_with_checkpoint("m")
        self.assertTrue(signer.used)
        with self.assertRaises(KeyExhaustedError):
            signer.sign("m")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_with_checkpoint("m")

    def test_accepts_bytes_bytearray_and_str_message(self):
        for message in (b"m", bytearray(b"m"), "m"):
            with self.subTest(message=type(message).__name__):
                signer = self.make_signer()
                signature, blob = signer.sign_with_checkpoint(message)
                self.assertTrue(
                    self.stateless_verify(b"m", signature, signer.public_key)
                )
                self.assertTrue(type(signer).from_checkpoint(blob).used)

    def test_invalid_message_raises_type_error_without_spending(self):
        signer = self.make_signer()
        for bad in (None, 42, 4.5, [b"m"], (b"m",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_with_checkpoint(bad)
        self.assertFalse(signer.used)
        self.assertTrue(
            self.stateless_verify("m", signer.sign("m"), signer.public_key)
        )

    def test_used_signer_raises_without_partial_result(self):
        signer = self.make_signer()
        signer.sign("earlier")
        before = signer.checkpoint()
        with self.assertRaises(KeyExhaustedError):
            signer.sign_with_checkpoint("m")
        # The state is untouched: a checkpoint now equals one taken before.
        self.assertEqual(signer.checkpoint(), before)

    def test_draws_no_extra_randomness(self):
        signer = self.make_signer()

        def exploding_token_bytes(size):
            raise AssertionError("sign_with_checkpoint must not draw randomness")

        import secrets
        from unittest import mock

        with mock.patch.object(secrets, "token_bytes", exploding_token_bytes):
            signer.sign_with_checkpoint("m")
        self.assertTrue(signer.used)

    def test_concurrent_calls_linearise_with_sign_and_checkpoint(self):
        signer = self.make_signer()
        worker_count = 8
        barrier = threading.Barrier(worker_count)
        results = []
        snapshots = []
        exhausted = []
        errors = []

        def worker(i):
            try:
                barrier.wait(timeout=10)
                if i % 2 == 0:
                    results.append(signer.sign_with_checkpoint(f"m{i}"))
                else:
                    snapshots.append(signer.checkpoint())
            except KeyExhaustedError:
                exhausted.append(i)
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(worker_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 1)
        self.assertTrue(signer.used)
        signature, blob = results[0]
        # The winning pair is internally consistent: the snapshot reflects
        # the state right after its own signature, never part-way through.
        restored = type(signer).from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertTrue(restored.used)
        self.assertEqual(blob, signer.checkpoint())
        for snapshot in snapshots:
            self.assertEqual(
                type(signer).from_checkpoint(snapshot).public_key,
                signer.public_key,
            )


class LamportSignWithCheckpointTest(SignOtsWithCheckpointTestMixin, unittest.TestCase):
    def make_signer(self, start=0):
        return make_lamport(start)

    def stateless_verify(self, message, signature, public_key):
        return verify(message, signature, public_key)


class WotsSignWithCheckpointTest(SignOtsWithCheckpointTestMixin, unittest.TestCase):
    def make_signer(self, start=1000):
        return make_wots(start)

    def stateless_verify(self, message, signature, public_key):
        return wots_verify(message, signature, public_key)


if __name__ == "__main__":
    unittest.main()

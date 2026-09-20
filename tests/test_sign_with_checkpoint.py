import threading
import unittest

from pqattest import KeyExhaustedError, MerkleSignature, MerkleSigner, merkle_verify


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


class SignWithCheckpointTest(unittest.TestCase):
    def test_returns_signature_and_bytes(self):
        signer = make_signer()
        signature, blob = signer.sign_with_checkpoint("m")
        self.assertIsInstance(signature, MerkleSignature)
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

    def test_advances_next_index_by_one(self):
        signer = make_signer()
        signer.sign("skipped")
        before = signer.next_index
        signature, blob = signer.sign_with_checkpoint("m")
        self.assertEqual(signature.index, before)
        self.assertEqual(signer.next_index, before + 1)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), before + 1)

    def test_accepts_bytes_bytearray_and_str(self):
        signer = make_signer(height=2)
        for message in (b"m", bytearray(b"m"), "m"):
            with self.subTest(message=type(message).__name__):
                signature, blob = signer.sign_with_checkpoint(message)
                self.assertTrue(
                    merkle_verify(b"m", signature, signer.public_key)
                )
                restored = MerkleSigner.from_checkpoint(blob)
                self.assertEqual(restored.next_index, signature.index + 1)

    def test_restored_checkpoint_resumes_signing(self):
        signer = make_signer(height=2)
        signature, blob = signer.sign_with_checkpoint("one")
        self.assertTrue(merkle_verify("one", signature, signer.public_key))
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 1)
        # Both instances continue from the same advanced state.
        self.assertEqual(restored.sign("two"), signer.sign("two"))

    def test_draws_no_extra_randomness(self):
        tokens = counter_tokens()
        signer = MerkleSigner(height=2, w=4, token_bytes=tokens)

        def exploding_token_bytes(size):
            raise AssertionError("sign_with_checkpoint must not draw randomness")

        import pqattest.merkle
        from unittest import mock

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            signature, blob = signer.sign_with_checkpoint("m")
        self.assertEqual(signature.index, 0)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 1)

    def test_invalid_message_raises_type_error_without_spending(self):
        signer = make_signer()
        for bad in (None, 42, 4.5, [b"m"], (b"m",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_with_checkpoint(bad)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("m").index, 0)

    def test_exhausted_signer_raises_without_partial_result(self):
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        with self.assertRaises(KeyExhaustedError):
            signer.sign_with_checkpoint("three")
        self.assertEqual(signer.next_index, 2)
        self.assertEqual(signer.remaining, 0)

    def test_failure_returns_no_partial_result(self):
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        try:
            signer.sign_with_checkpoint("three")
        except KeyExhaustedError:
            pass
        # The state is untouched: a checkpoint now equals one taken before.
        self.assertEqual(signer.next_index, 2)


class SignWithCheckpointConcurrencyTest(unittest.TestCase):
    def test_linearises_with_sign_and_checkpoint(self):
        height = 4
        signer = make_signer(height=height)
        results = []
        snapshots = []
        errors = []
        barrier = threading.Barrier(1 << height)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                if i % 3 == 0:
                    message = f"m{i}"
                    signature, blob = signer.sign_with_checkpoint(message)
                    results.append((message, signature, blob))
                elif i % 3 == 1:
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

        # Every leaf index was handed out at most once.
        indices = sorted(signature.index for _, signature, _ in results)
        self.assertEqual(len(indices), len(set(indices)))

        # Each atomic snapshot reflects the state right after its own
        # signature: it parses, its next_index is the signature's + 1, and
        # the signature verifies against its message.
        for message, signature, blob in results:
            with self.subTest(index=signature.index):
                restored = MerkleSigner.from_checkpoint(blob)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertEqual(restored.next_index, signature.index + 1)
                self.assertTrue(
                    merkle_verify(message, signature, signer.public_key)
                )
        for blob in snapshots:
            restored = MerkleSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)


if __name__ == "__main__":
    unittest.main()

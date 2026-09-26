import threading
import unittest
from unittest import mock

from pqattest import (
    KeyExhaustedError,
    OneTimeSigner,
    WOTSOneTimeSigner,
    keygen,
    sign_ots_pair_with_checkpoint,
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


def make_lamport(start=0, bits=8):
    private_key, _ = keygen(bits=bits, token_bytes=counter_tokens(start))
    return OneTimeSigner(private_key)


def make_wots(start=1000, w=4):
    private_key, _ = wots_keygen(w=w, token_bytes=counter_tokens(start))
    return WOTSOneTimeSigner(private_key)


def make_pair():
    return make_lamport(), make_wots()


class SignOtsPairWithCheckpointTest(unittest.TestCase):
    def test_returns_nested_pairs_of_expected_types(self):
        lamport, wots = make_pair()
        signatures, checkpoints = sign_ots_pair_with_checkpoint(lamport, wots, "m")
        lamport_signature, wots_signature = signatures
        lamport_checkpoint, wots_checkpoint = checkpoints
        self.assertIsInstance(lamport_signature, tuple)
        self.assertIsInstance(wots_signature, tuple)
        self.assertTrue(all(isinstance(part, bytes) for part in lamport_signature))
        self.assertTrue(all(isinstance(part, bytes) for part in wots_signature))
        self.assertIsInstance(lamport_checkpoint, bytes)
        self.assertIsInstance(wots_checkpoint, bytes)

    def test_signatures_match_plain_sign_from_same_state(self):
        lamport, wots = make_pair()
        reference_lamport, reference_wots = make_pair()
        (lamport_signature, wots_signature), _ = sign_ots_pair_with_checkpoint(
            lamport, wots, "m"
        )
        self.assertEqual(lamport_signature, reference_lamport.sign("m"))
        self.assertEqual(wots_signature, reference_wots.sign("m"))

    def test_results_match_individual_sign_with_checkpoint_calls(self):
        lamport, wots = make_pair()
        reference_lamport, reference_wots = make_pair()
        signatures, checkpoints = sign_ots_pair_with_checkpoint(lamport, wots, "m")
        expected_lamport = reference_lamport.sign_with_checkpoint("m")
        expected_wots = reference_wots.sign_with_checkpoint("m")
        self.assertEqual(signatures[0], expected_lamport[0])
        self.assertEqual(signatures[1], expected_wots[0])
        self.assertEqual(checkpoints[0], expected_lamport[1])
        self.assertEqual(checkpoints[1], expected_wots[1])

    def test_checkpoints_match_explicit_post_sign_checkpoints(self):
        lamport, wots = make_pair()
        reference_lamport, reference_wots = make_pair()
        _, (lamport_checkpoint, wots_checkpoint) = sign_ots_pair_with_checkpoint(
            lamport, wots, "m"
        )
        reference_lamport.sign("m")
        reference_wots.sign("m")
        self.assertEqual(lamport_checkpoint, reference_lamport.checkpoint())
        self.assertEqual(wots_checkpoint, reference_wots.checkpoint())
        # And with checkpoints taken on the live instances afterwards.
        self.assertEqual(lamport_checkpoint, lamport.checkpoint())
        self.assertEqual(wots_checkpoint, wots.checkpoint())

    def test_signatures_verify_against_public_keys(self):
        lamport, wots = make_pair()
        (lamport_signature, wots_signature), _ = sign_ots_pair_with_checkpoint(
            lamport, wots, "m"
        )
        self.assertTrue(verify("m", lamport_signature, lamport.public_key))
        self.assertTrue(wots_verify("m", wots_signature, wots.public_key))

    def test_restored_checkpoints_are_used_with_same_public_keys(self):
        lamport, wots = make_pair()
        _, (lamport_checkpoint, wots_checkpoint) = sign_ots_pair_with_checkpoint(
            lamport, wots, "m"
        )
        restored_lamport = OneTimeSigner.from_checkpoint(lamport_checkpoint)
        restored_wots = WOTSOneTimeSigner.from_checkpoint(wots_checkpoint)
        self.assertEqual(restored_lamport.public_key, lamport.public_key)
        self.assertEqual(restored_wots.public_key, wots.public_key)
        self.assertTrue(restored_lamport.used)
        self.assertTrue(restored_wots.used)
        with self.assertRaises(KeyExhaustedError):
            restored_lamport.sign("m")
        with self.assertRaises(KeyExhaustedError):
            restored_wots.sign("m")

    def test_marks_both_signers_used(self):
        lamport, wots = make_pair()
        sign_ots_pair_with_checkpoint(lamport, wots, "m")
        self.assertTrue(lamport.used)
        self.assertTrue(wots.used)
        with self.assertRaises(KeyExhaustedError):
            lamport.sign("m")
        with self.assertRaises(KeyExhaustedError):
            wots.sign("m")

    def test_accepts_bytes_bytearray_and_str_message(self):
        for message in (b"m", bytearray(b"m"), "m"):
            with self.subTest(message=type(message).__name__):
                lamport, wots = make_pair()
                (lamport_signature, wots_signature), _ = (
                    sign_ots_pair_with_checkpoint(lamport, wots, message)
                )
                self.assertTrue(verify(b"m", lamport_signature, lamport.public_key))
                self.assertTrue(wots_verify(b"m", wots_signature, wots.public_key))

    def test_wrong_signer_types_raise_type_error(self):
        lamport, wots = make_pair()
        for bad in (None, 42, "s", wots, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_ots_pair_with_checkpoint(bad, wots, "m")
        for bad in (None, 42, "s", lamport, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_ots_pair_with_checkpoint(lamport, bad, "m")
        self.assertFalse(lamport.used)
        self.assertFalse(wots.used)

    def test_swapped_signer_order_raises_type_error(self):
        lamport, wots = make_pair()
        with self.assertRaises(TypeError):
            sign_ots_pair_with_checkpoint(wots, lamport, "m")
        self.assertFalse(lamport.used)
        self.assertFalse(wots.used)

    def test_invalid_message_raises_type_error_without_spending(self):
        lamport, wots = make_pair()
        for bad in (None, 42, 4.5, [b"m"], (b"m",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_ots_pair_with_checkpoint(lamport, wots, bad)
        self.assertFalse(lamport.used)
        self.assertFalse(wots.used)

    def test_used_lamport_raises_without_spending_wots(self):
        lamport, wots = make_pair()
        lamport.sign("earlier")
        with self.assertRaises(KeyExhaustedError):
            sign_ots_pair_with_checkpoint(lamport, wots, "m")
        self.assertFalse(wots.used)
        wots_signature = wots.sign("m")
        self.assertTrue(wots_verify("m", wots_signature, wots.public_key))

    def test_used_wots_raises_without_spending_lamport(self):
        lamport, wots = make_pair()
        wots.sign("earlier")
        with self.assertRaises(KeyExhaustedError):
            sign_ots_pair_with_checkpoint(lamport, wots, "m")
        self.assertFalse(lamport.used)
        lamport_signature = lamport.sign("m")
        self.assertTrue(verify("m", lamport_signature, lamport.public_key))

    def test_both_used_raises_without_partial_result(self):
        lamport, wots = make_pair()
        lamport.sign("earlier")
        wots.sign("earlier")
        lamport_before = lamport.checkpoint()
        wots_before = wots.checkpoint()
        with self.assertRaises(KeyExhaustedError):
            sign_ots_pair_with_checkpoint(lamport, wots, "m")
        self.assertEqual(lamport.checkpoint(), lamport_before)
        self.assertEqual(wots.checkpoint(), wots_before)

    def test_draws_no_randomness(self):
        lamport, wots = make_pair()

        def exploding_token_bytes(size):
            raise AssertionError("sign_ots_pair_with_checkpoint must not draw randomness")

        import secrets

        with mock.patch.object(secrets, "token_bytes", exploding_token_bytes):
            result = sign_ots_pair_with_checkpoint(lamport, wots, "m")
        self.assertTrue(lamport.used)
        self.assertTrue(wots.used)
        signatures, checkpoints = result
        self.assertEqual(len(signatures), 2)
        self.assertEqual(len(checkpoints), 2)


class SignOtsPairWithCheckpointConcurrencyTest(unittest.TestCase):
    def test_at_most_one_pair_call_succeeds(self):
        lamport, wots = make_pair()
        worker_count = 8
        barrier = threading.Barrier(worker_count)
        results = []
        exhausted = []
        errors = []

        def worker(i):
            try:
                barrier.wait(timeout=10)
                message = f"m{i}"
                results.append(
                    (message, sign_ots_pair_with_checkpoint(lamport, wots, message))
                )
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
        self.assertEqual(len(exhausted), worker_count - 1)
        self.assertTrue(lamport.used)
        self.assertTrue(wots.used)
        message, (signatures, checkpoints) = results[0]
        lamport_signature, wots_signature = signatures
        lamport_checkpoint, wots_checkpoint = checkpoints
        self.assertTrue(verify(message, lamport_signature, lamport.public_key))
        self.assertTrue(wots_verify(message, wots_signature, wots.public_key))
        restored_lamport = OneTimeSigner.from_checkpoint(lamport_checkpoint)
        restored_wots = WOTSOneTimeSigner.from_checkpoint(wots_checkpoint)
        self.assertTrue(restored_lamport.used)
        self.assertTrue(restored_wots.used)
        self.assertEqual(restored_lamport.public_key, lamport.public_key)
        self.assertEqual(restored_wots.public_key, wots.public_key)

    def test_linearises_with_single_side_signs_and_checkpoints(self):
        lamport, wots = make_pair()
        worker_count = 12
        barrier = threading.Barrier(worker_count)
        pair_results = []
        errors = []

        def worker(i):
            try:
                barrier.wait(timeout=10)
                if i % 4 == 0:
                    try:
                        pair_results.append(
                            sign_ots_pair_with_checkpoint(lamport, wots, f"m{i}")
                        )
                    except KeyExhaustedError:
                        pass
                elif i % 4 == 1:
                    try:
                        lamport.sign_with_checkpoint(f"m{i}")
                    except KeyExhaustedError:
                        pass
                elif i % 4 == 2:
                    try:
                        wots.sign(f"m{i}")
                    except KeyExhaustedError:
                        pass
                else:
                    lamport.checkpoint()
                    wots.checkpoint()
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(worker_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        # Each one-time key was consumed exactly once across every entry.
        self.assertTrue(lamport.used)
        self.assertTrue(wots.used)
        # If the pair won, its checkpoints restore the used state. If a
        # single-side call won for one side, the pair cannot have won.
        self.assertLessEqual(len(pair_results), 1)
        for _, (lamport_checkpoint, wots_checkpoint) in pair_results:
            self.assertTrue(OneTimeSigner.from_checkpoint(lamport_checkpoint).used)
            self.assertTrue(WOTSOneTimeSigner.from_checkpoint(wots_checkpoint).used)


if __name__ == "__main__":
    unittest.main()

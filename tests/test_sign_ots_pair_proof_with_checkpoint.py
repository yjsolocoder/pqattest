import threading
import unittest

from pqattest import (
    KeyExhaustedError,
    LamportProof,
    OneTimeSigner,
    OtsPairProof,
    WOTSOneTimeSigner,
    WOTSProof,
    keygen,
    sign_ots_pair_proof_with_checkpoint,
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


def make_pair():
    return make_lamport(), make_wots()


class SignOtsPairProofWithCheckpointTest(unittest.TestCase):
    def test_returns_pair_proof_and_checkpoint_pair(self):
        lamport, wots = make_pair()
        pair_proof, checkpoints = sign_ots_pair_proof_with_checkpoint(
            lamport, wots, "m"
        )
        self.assertIsInstance(pair_proof, OtsPairProof)
        self.assertIsInstance(checkpoints, tuple)
        self.assertEqual(len(checkpoints), 2)
        lamport_checkpoint, wots_checkpoint = checkpoints
        self.assertIsInstance(lamport_checkpoint, bytes)
        self.assertIsInstance(wots_checkpoint, bytes)

    def test_proof_members_are_lamport_first_wots_second(self):
        lamport, wots = make_pair()
        pair_proof, _ = sign_ots_pair_proof_with_checkpoint(lamport, wots, "m")
        self.assertIsInstance(pair_proof.lamport, LamportProof)
        self.assertIsInstance(pair_proof.wots, WOTSProof)
        self.assertEqual(pair_proof.lamport.public_key, lamport.public_key)
        self.assertEqual(pair_proof.wots.public_key, wots.public_key)

    def test_signatures_match_plain_sign_from_same_state(self):
        lamport, wots = make_pair()
        reference_lamport, reference_wots = make_pair()
        pair_proof, _ = sign_ots_pair_proof_with_checkpoint(lamport, wots, "m")
        self.assertEqual(pair_proof.lamport.signature, reference_lamport.sign("m"))
        self.assertEqual(pair_proof.wots.signature, reference_wots.sign("m"))

    def test_proof_verifies_for_signed_message(self):
        lamport, wots = make_pair()
        pair_proof, _ = sign_ots_pair_proof_with_checkpoint(lamport, wots, "m")
        self.assertTrue(pair_proof.verify("m"))
        self.assertTrue(pair_proof.verify(b"m"))
        self.assertFalse(pair_proof.verify(b"other"))
        self.assertTrue(verify("m", pair_proof.lamport.signature, lamport.public_key))
        self.assertTrue(
            wots_verify("m", pair_proof.wots.signature, wots.public_key)
        )

    def test_encoding_matches_hand_assembled_pair(self):
        lamport, wots = make_pair()
        reference_lamport, reference_wots = make_pair()
        pair_proof, _ = sign_ots_pair_proof_with_checkpoint(lamport, wots, "m")
        hand_assembled = OtsPairProof(
            lamport=LamportProof(
                public_key=reference_lamport.public_key,
                signature=reference_lamport.sign("m"),
            ),
            wots=WOTSProof(
                public_key=reference_wots.public_key,
                signature=reference_wots.sign("m"),
            ),
        )
        self.assertEqual(pair_proof, hand_assembled)
        self.assertEqual(pair_proof.to_bytes(), hand_assembled.to_bytes())
        restored = OtsPairProof.from_bytes(pair_proof.to_bytes())
        self.assertEqual(restored, pair_proof)
        self.assertTrue(restored.verify("m"))

    def test_checkpoints_match_explicit_post_sign_checkpoints(self):
        lamport, wots = make_pair()
        reference_lamport, reference_wots = make_pair()
        _, (lamport_checkpoint, wots_checkpoint) = (
            sign_ots_pair_proof_with_checkpoint(lamport, wots, "m")
        )
        reference_lamport.sign("m")
        reference_wots.sign("m")
        self.assertEqual(lamport_checkpoint, reference_lamport.checkpoint())
        self.assertEqual(wots_checkpoint, reference_wots.checkpoint())

    def test_checkpoints_restore_used_signers_with_same_public_keys(self):
        lamport, wots = make_pair()
        _, (lamport_checkpoint, wots_checkpoint) = (
            sign_ots_pair_proof_with_checkpoint(lamport, wots, "m")
        )
        restored_lamport = OneTimeSigner.from_checkpoint(lamport_checkpoint)
        self.assertEqual(restored_lamport.public_key, lamport.public_key)
        self.assertTrue(restored_lamport.used)
        with self.assertRaises(KeyExhaustedError):
            restored_lamport.sign("m")
        restored_wots = WOTSOneTimeSigner.from_checkpoint(wots_checkpoint)
        self.assertEqual(restored_wots.public_key, wots.public_key)
        self.assertTrue(restored_wots.used)
        with self.assertRaises(KeyExhaustedError):
            restored_wots.sign("m")

    def test_marks_both_signers_used(self):
        lamport, wots = make_pair()
        sign_ots_pair_proof_with_checkpoint(lamport, wots, "m")
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
                pair_proof, _ = sign_ots_pair_proof_with_checkpoint(
                    lamport, wots, message
                )
                self.assertTrue(pair_proof.verify(b"m"))

    def test_wrong_signer_types_raise_type_error(self):
        lamport, wots = make_pair()
        for bad in (None, 42, "s", wots, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_with_checkpoint(bad, wots, "m")
        for bad in (None, 42, "s", lamport, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_with_checkpoint(lamport, bad, "m")
        self.assertFalse(lamport.used)
        self.assertFalse(wots.used)

    def test_invalid_message_raises_type_error_without_spending(self):
        lamport, wots = make_pair()
        for bad in (None, 42, 4.5, [b"m"], (b"m",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_with_checkpoint(lamport, wots, bad)
        self.assertFalse(lamport.used)
        self.assertFalse(wots.used)

    def test_used_lamport_raises_without_spending_wots(self):
        lamport, wots = make_pair()
        lamport.sign("earlier")
        with self.assertRaises(KeyExhaustedError):
            sign_ots_pair_proof_with_checkpoint(lamport, wots, "m")
        self.assertFalse(wots.used)
        wots_signature = wots.sign("m")
        self.assertTrue(wots_verify("m", wots_signature, wots.public_key))

    def test_used_wots_raises_without_spending_lamport(self):
        lamport, wots = make_pair()
        wots.sign("earlier")
        with self.assertRaises(KeyExhaustedError):
            sign_ots_pair_proof_with_checkpoint(lamport, wots, "m")
        self.assertFalse(lamport.used)
        lamport_signature = lamport.sign("m")
        self.assertTrue(verify("m", lamport_signature, lamport.public_key))

    def test_draws_no_extra_randomness(self):
        lamport, wots = make_pair()

        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_ots_pair_proof_with_checkpoint must not draw randomness"
            )

        import secrets
        from unittest import mock

        with mock.patch.object(secrets, "token_bytes", exploding_token_bytes):
            sign_ots_pair_proof_with_checkpoint(lamport, wots, "m")
        self.assertTrue(lamport.used)
        self.assertTrue(wots.used)


class SignOtsPairProofWithCheckpointConcurrencyTest(unittest.TestCase):
    def test_at_most_one_concurrent_caller_succeeds(self):
        lamport, wots = make_pair()
        worker_count = 8
        barrier = threading.Barrier(worker_count)
        results = []
        exhausted = []
        errors = []

        def worker(i):
            try:
                barrier.wait(timeout=10)
                results.append(
                    sign_ots_pair_proof_with_checkpoint(lamport, wots, f"m{i}")
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
        pair_proof, (lamport_checkpoint, wots_checkpoint) = results[0]
        # The winning pair is internally consistent: both checkpoints carry
        # the used state of the same signing act that produced the proof.
        restored_lamport = OneTimeSigner.from_checkpoint(lamport_checkpoint)
        restored_wots = WOTSOneTimeSigner.from_checkpoint(wots_checkpoint)
        self.assertTrue(restored_lamport.used)
        self.assertTrue(restored_wots.used)
        self.assertEqual(restored_lamport.public_key, lamport.public_key)
        self.assertEqual(restored_wots.public_key, wots.public_key)
        self.assertEqual(lamport_checkpoint, lamport.checkpoint())
        self.assertEqual(wots_checkpoint, wots.checkpoint())
        self.assertEqual(pair_proof.lamport.public_key, lamport.public_key)
        self.assertEqual(pair_proof.wots.public_key, wots.public_key)


if __name__ == "__main__":
    unittest.main()

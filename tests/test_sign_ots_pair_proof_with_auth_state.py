import threading
import unittest

from pqattest import (
    KeyExhaustedError,
    LamportProof,
    OneTimeSigner,
    OtsPairProof,
    WOTSOneTimeSigner,
    WOTSProof,
    auth_state_unwrap,
    auth_state_wrap,
    keygen,
    sign_ots_pair_proof_with_auth_state,
    verify,
    wots_keygen,
    wots_verify,
)

KEY = b"shared-secret-key"
UINT64_MAX = 2**64 - 1


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


class SignOtsPairProofWithAuthStateTest(unittest.TestCase):
    def test_returns_pair_proof_and_envelope_pair(self):
        lamport, wots = make_pair()
        pair_proof, envelopes = sign_ots_pair_proof_with_auth_state(
            lamport, wots, "m", key=KEY, generation=0
        )
        self.assertIsInstance(pair_proof, OtsPairProof)
        self.assertIsInstance(envelopes, tuple)
        self.assertEqual(len(envelopes), 2)
        lamport_envelope, wots_envelope = envelopes
        self.assertIsInstance(lamport_envelope, bytes)
        self.assertIsInstance(wots_envelope, bytes)

    def test_proof_members_are_lamport_first_wots_second(self):
        lamport, wots = make_pair()
        pair_proof, _ = sign_ots_pair_proof_with_auth_state(
            lamport, wots, "m", key=KEY, generation=0
        )
        self.assertIsInstance(pair_proof.lamport, LamportProof)
        self.assertIsInstance(pair_proof.wots, WOTSProof)
        self.assertEqual(pair_proof.lamport.public_key, lamport.public_key)
        self.assertEqual(pair_proof.wots.public_key, wots.public_key)

    def test_signatures_match_plain_sign_from_same_state(self):
        lamport, wots = make_pair()
        reference_lamport, reference_wots = make_pair()
        pair_proof, _ = sign_ots_pair_proof_with_auth_state(
            lamport, wots, "m", key=KEY, generation=3
        )
        self.assertEqual(pair_proof.lamport.signature, reference_lamport.sign("m"))
        self.assertEqual(pair_proof.wots.signature, reference_wots.sign("m"))

    def test_proof_verifies_for_signed_message(self):
        lamport, wots = make_pair()
        pair_proof, _ = sign_ots_pair_proof_with_auth_state(
            lamport, wots, "m", key=KEY, generation=0
        )
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
        pair_proof, _ = sign_ots_pair_proof_with_auth_state(
            lamport, wots, "m", key=KEY, generation=0
        )
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

    def test_envelopes_match_explicit_wrap_of_post_sign_checkpoints(self):
        lamport, wots = make_pair()
        reference_lamport, reference_wots = make_pair()
        generation = 7
        _, (lamport_envelope, wots_envelope) = sign_ots_pair_proof_with_auth_state(
            lamport, wots, "m", key=KEY, generation=generation
        )
        reference_lamport.sign("m")
        reference_wots.sign("m")
        self.assertEqual(
            lamport_envelope,
            auth_state_wrap(
                reference_lamport.checkpoint(),
                scheme="lamport",
                key=KEY,
                generation=generation,
            ),
        )
        self.assertEqual(
            wots_envelope,
            auth_state_wrap(
                reference_wots.checkpoint(),
                scheme="wots",
                key=KEY,
                generation=generation,
            ),
        )

    def test_envelopes_unwrap_to_used_checkpoints(self):
        lamport, wots = make_pair()
        _, (lamport_envelope, wots_envelope) = sign_ots_pair_proof_with_auth_state(
            lamport, wots, "m", key=KEY, generation=42
        )
        scheme, generation, checkpoint = auth_state_unwrap(
            lamport_envelope, key=KEY, expect="lamport"
        )
        self.assertEqual((scheme, generation), ("lamport", 42))
        restored_lamport = OneTimeSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored_lamport.public_key, lamport.public_key)
        self.assertTrue(restored_lamport.used)
        with self.assertRaises(KeyExhaustedError):
            restored_lamport.sign("m")
        scheme, generation, checkpoint = auth_state_unwrap(
            wots_envelope, key=KEY, expect="wots"
        )
        self.assertEqual((scheme, generation), ("wots", 42))
        restored_wots = WOTSOneTimeSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored_wots.public_key, wots.public_key)
        self.assertTrue(restored_wots.used)
        with self.assertRaises(KeyExhaustedError):
            restored_wots.sign("m")

    def test_marks_both_signers_used(self):
        lamport, wots = make_pair()
        sign_ots_pair_proof_with_auth_state(lamport, wots, "m", key=KEY, generation=0)
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
                pair_proof, _ = sign_ots_pair_proof_with_auth_state(
                    lamport, wots, message, key=bytearray(KEY), generation=1
                )
                self.assertTrue(pair_proof.verify(b"m"))

    def test_keyword_only_arguments(self):
        lamport, wots = make_pair()
        with self.assertRaises(TypeError):
            sign_ots_pair_proof_with_auth_state(lamport, wots, "m", KEY, 0)
        self.assertFalse(lamport.used)
        self.assertFalse(wots.used)

    def test_wrong_signer_types_raise_type_error(self):
        lamport, wots = make_pair()
        for bad in (None, 42, "s", wots, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_with_auth_state(
                        bad, wots, "m", key=KEY, generation=0
                    )
        for bad in (None, 42, "s", lamport, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_with_auth_state(
                        lamport, bad, "m", key=KEY, generation=0
                    )
        self.assertFalse(lamport.used)
        self.assertFalse(wots.used)

    def test_invalid_message_raises_type_error_without_spending(self):
        lamport, wots = make_pair()
        for bad in (None, 42, 4.5, [b"m"], (b"m",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_with_auth_state(
                        lamport, wots, bad, key=KEY, generation=0
                    )
        self.assertFalse(lamport.used)
        self.assertFalse(wots.used)

    def test_invalid_key_raises_without_spending(self):
        lamport, wots = make_pair()
        type_errors = (None, 42, "secret", ["k"])
        value_errors = (b"", bytearray())
        for bad in type_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_with_auth_state(
                        lamport, wots, "m", key=bad, generation=0
                    )
        for bad in value_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    sign_ots_pair_proof_with_auth_state(
                        lamport, wots, "m", key=bad, generation=0
                    )
        self.assertFalse(lamport.used)
        self.assertFalse(wots.used)

    def test_invalid_generation_raises_without_spending(self):
        lamport, wots = make_pair()
        type_errors = (None, 1.5, "0", [0], True, False)
        range_errors = (-1, UINT64_MAX + 1)
        for bad in type_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(TypeError):
                    sign_ots_pair_proof_with_auth_state(
                        lamport, wots, "m", key=KEY, generation=bad
                    )
        for bad in range_errors:
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    sign_ots_pair_proof_with_auth_state(
                        lamport, wots, "m", key=KEY, generation=bad
                    )
        self.assertFalse(lamport.used)
        self.assertFalse(wots.used)

    def test_used_lamport_raises_without_spending_wots(self):
        lamport, wots = make_pair()
        lamport.sign("earlier")
        with self.assertRaises(KeyExhaustedError):
            sign_ots_pair_proof_with_auth_state(lamport, wots, "m", key=KEY, generation=0)
        self.assertFalse(wots.used)
        wots_signature = wots.sign("m")
        self.assertTrue(wots_verify("m", wots_signature, wots.public_key))

    def test_used_wots_raises_without_spending_lamport(self):
        lamport, wots = make_pair()
        wots.sign("earlier")
        with self.assertRaises(KeyExhaustedError):
            sign_ots_pair_proof_with_auth_state(lamport, wots, "m", key=KEY, generation=0)
        self.assertFalse(lamport.used)
        lamport_signature = lamport.sign("m")
        self.assertTrue(verify("m", lamport_signature, lamport.public_key))

    def test_draws_no_extra_randomness(self):
        lamport, wots = make_pair()

        def exploding_token_bytes(size):
            raise AssertionError(
                "sign_ots_pair_proof_with_auth_state must not draw randomness"
            )

        import secrets
        from unittest import mock

        with mock.patch.object(secrets, "token_bytes", exploding_token_bytes):
            sign_ots_pair_proof_with_auth_state(lamport, wots, "m", key=KEY, generation=0)
        self.assertTrue(lamport.used)
        self.assertTrue(wots.used)

    def test_deterministic_for_same_initial_state(self):
        first_pair = make_pair()
        second_pair = make_pair()
        first = sign_ots_pair_proof_with_auth_state(
            *first_pair, "m", key=KEY, generation=5
        )
        second = sign_ots_pair_proof_with_auth_state(
            *second_pair, "m", key=KEY, generation=5
        )
        self.assertEqual(first[0], second[0])
        self.assertEqual(first[0].to_bytes(), second[0].to_bytes())
        self.assertEqual(first[1], second[1])


class SignOtsPairProofWithAuthStateConcurrencyTest(unittest.TestCase):
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
                    sign_ots_pair_proof_with_auth_state(
                        lamport, wots, f"m{i}", key=KEY, generation=i
                    )
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
        pair_proof, (lamport_envelope, wots_envelope) = results[0]
        # The winning pair is internally consistent: both envelopes carry the
        # used state of the same signing act that produced the proof.
        _, _, lamport_checkpoint = auth_state_unwrap(lamport_envelope, key=KEY)
        _, _, wots_checkpoint = auth_state_unwrap(wots_envelope, key=KEY)
        restored_lamport = OneTimeSigner.from_checkpoint(lamport_checkpoint)
        restored_wots = WOTSOneTimeSigner.from_checkpoint(wots_checkpoint)
        self.assertTrue(restored_lamport.used)
        self.assertTrue(restored_wots.used)
        self.assertEqual(restored_lamport.public_key, lamport.public_key)
        self.assertEqual(restored_wots.public_key, wots.public_key)
        self.assertEqual(pair_proof.lamport.public_key, lamport.public_key)
        self.assertEqual(pair_proof.wots.public_key, wots.public_key)


if __name__ == "__main__":
    unittest.main()

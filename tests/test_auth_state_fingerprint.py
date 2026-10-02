import hashlib
import hmac
import unittest

from pqattest import (
    MerkleSigner,
    OneTimeSigner,
    WOTSOneTimeSigner,
    auth_state_fingerprint,
    auth_state_unwrap,
    auth_state_wrap,
    auth_unwrap,
    auth_wrap,
    keygen,
    toy_lattice_keygen,
    wots_keygen,
)

KEY = b"shared-secret-key"
STATE_ID_DOMAIN = b"pqattest/auth-state-id/v1"
STATE_ID_BYTES = 32


def checkpoints():
    lamport = OneTimeSigner(keygen(bits=32)[0]).checkpoint()
    wots = WOTSOneTimeSigner(wots_keygen(w=4)[0]).checkpoint()
    merkle = MerkleSigner(height=1, w=4).checkpoint()
    lattice = toy_lattice_keygen()[0].to_bytes()
    return {
        "lamport": lamport,
        "wots": wots,
        "merkle": merkle,
        "lattice": lattice,
    }


def expected_fingerprint(blob, key):
    return hmac.new(key, STATE_ID_DOMAIN + blob[:-32], hashlib.sha256).digest()


class FingerprintLayoutTest(unittest.TestCase):
    def test_matches_documentation_formula_for_every_scheme(self):
        for scheme, checkpoint in checkpoints().items():
            with self.subTest(scheme=scheme):
                blob = auth_state_wrap(
                    checkpoint, scheme=scheme, key=KEY, generation=7
                )
                identity = auth_state_fingerprint(blob, key=KEY)
                self.assertIsInstance(identity, bytes)
                self.assertEqual(len(identity), STATE_ID_BYTES)
                self.assertEqual(identity, expected_fingerprint(blob, KEY))

    def test_deterministic_and_stable_across_calls(self):
        checkpoint = checkpoints()["lamport"]
        blob = auth_state_wrap(
            checkpoint, scheme="lamport", key=KEY, generation=1
        )
        first = auth_state_fingerprint(blob, key=KEY)
        for _ in range(5):
            self.assertEqual(
                auth_state_fingerprint(blob, key=KEY), first
            )

    def test_accepts_bytearray_inputs(self):
        checkpoint = checkpoints()["wots"]
        blob = auth_state_wrap(
            checkpoint, scheme="wots", key=KEY, generation=4
        )
        identity = auth_state_fingerprint(
            bytearray(blob), key=bytearray(KEY)
        )
        self.assertEqual(identity, expected_fingerprint(blob, KEY))

    def test_distinct_payloads_give_distinct_identities(self):
        cps = checkpoints()
        first = OneTimeSigner(keygen(bits=32)[0]).checkpoint()
        second = OneTimeSigner(keygen(bits=32)[0]).checkpoint()
        self.assertNotEqual(first, second)
        id_a = auth_state_fingerprint(
            auth_state_wrap(first, scheme="lamport", key=KEY, generation=3),
            key=KEY,
        )
        id_b = auth_state_fingerprint(
            auth_state_wrap(second, scheme="lamport", key=KEY, generation=3),
            key=KEY,
        )
        self.assertNotEqual(id_a, id_b)
        # Even a one-byte payload change, re-tagged under the same key,
        # changes the identity.
        blob = auth_state_wrap(
            cps["lamport"], scheme="lamport", key=KEY, generation=3
        )
        tampered = bytearray(cps["lamport"])
        tampered[-1] ^= 0x01
        retagged = auth_state_wrap(
            bytes(tampered), scheme="lamport", key=KEY, generation=3
        )
        self.assertNotEqual(
            auth_state_fingerprint(retagged, key=KEY),
            auth_state_fingerprint(blob, key=KEY),
        )

    def test_distinct_generations_give_distinct_identities(self):
        checkpoint = checkpoints()["lamport"]
        identities = {
            generation: auth_state_fingerprint(
                auth_state_wrap(
                    checkpoint,
                    scheme="lamport",
                    key=KEY,
                    generation=generation,
                ),
                key=KEY,
            )
            for generation in (0, 1, 2, 2**64 - 1)
        }
        self.assertEqual(len(identities), 4)

    def test_distinct_schemes_give_distinct_identities(self):
        blob_l = auth_state_wrap(
            checkpoints()["lamport"], scheme="lamport", key=KEY, generation=0
        )
        blob_w = auth_state_wrap(
            checkpoints()["wots"], scheme="wots", key=KEY, generation=0
        )
        self.assertNotEqual(
            auth_state_fingerprint(blob_l, key=KEY),
            auth_state_fingerprint(blob_w, key=KEY),
        )

    def test_distinct_keys_give_distinct_identities(self):
        checkpoint = checkpoints()["lamport"]
        other_key = b"a-different-key"
        # The same authenticated body wrapped under two keys; each
        # fingerprint is only defined after the envelope verifies under its
        # own key, and the two keyed identities must not collide.
        blob_a = auth_state_wrap(
            checkpoint, scheme="lamport", key=KEY, generation=0
        )
        blob_b = auth_state_wrap(
            checkpoint, scheme="lamport", key=other_key, generation=0
        )
        id_a = auth_state_fingerprint(blob_a, key=KEY)
        id_b = auth_state_fingerprint(blob_b, key=other_key)
        self.assertNotEqual(id_a, id_b)
        self.assertEqual(id_a, expected_fingerprint(blob_a, KEY))
        self.assertEqual(id_b, expected_fingerprint(blob_b, other_key))

    def test_identity_differs_from_envelope_tag(self):
        checkpoint = checkpoints()["lamport"]
        blob = auth_state_wrap(
            checkpoint, scheme="lamport", key=KEY, generation=0
        )
        self.assertNotEqual(auth_state_fingerprint(blob, key=KEY), blob[-32:])


class FingerprintRejectsBadInputTest(unittest.TestCase):
    def setUp(self):
        self.checkpoint = checkpoints()["lamport"]
        self.blob = auth_state_wrap(
            self.checkpoint, scheme="lamport", key=KEY, generation=0
        )

    def test_rejects_non_bytes_data(self):
        for bad in (None, 42, 4.5, "blob", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_state_fingerprint(bad, key=KEY)

    def test_rejects_non_bytes_key(self):
        for bad in (None, 42, "key", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_state_fingerprint(self.blob, key=bad)

    def test_rejects_empty_key(self):
        with self.assertRaises(ValueError):
            auth_state_fingerprint(self.blob, key=b"")

    def test_rejects_bad_tag(self):
        bad = bytearray(self.blob)
        bad[-1] ^= 0x01
        with self.assertRaises(ValueError):
            auth_state_fingerprint(bytes(bad), key=KEY)
        with self.assertRaises(ValueError):
            auth_state_fingerprint(self.blob, key=b"a-different-key")

    def test_rejects_v1_envelope(self):
        v1_blob = auth_wrap(self.checkpoint, scheme="lamport", key=KEY)
        with self.assertRaises(ValueError):
            auth_state_fingerprint(v1_blob, key=KEY)

    def test_rejects_truncation_and_trailing_data(self):
        for cut in (0, 21, 31, len(self.blob) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    auth_state_fingerprint(self.blob[:cut], key=KEY)
        with self.assertRaises(ValueError):
            auth_state_fingerprint(self.blob + b"\x00", key=KEY)

    def test_rejects_bad_version_even_re_tagged(self):
        body = bytearray(self.blob[:-32])
        body[8] = 3
        forged = bytes(body) + hmac.new(KEY, bytes(body), hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            auth_state_fingerprint(forged, key=KEY)


class ExpectStateIdRoundTripTest(unittest.TestCase):
    def test_correct_identity_returns_original_content(self):
        for scheme, checkpoint in checkpoints().items():
            with self.subTest(scheme=scheme):
                blob = auth_state_wrap(
                    checkpoint, scheme=scheme, key=KEY, generation=12
                )
                identity = auth_state_fingerprint(blob, key=KEY)
                got_scheme, got_generation, got_payload = auth_state_unwrap(
                    blob,
                    key=KEY,
                    min_generation=0,
                    expect_state_id=identity,
                )
                self.assertEqual(got_scheme, scheme)
                self.assertEqual(got_generation, 12)
                self.assertEqual(got_payload, checkpoint)
                self.assertIsInstance(got_payload, bytes)

    def test_correct_identity_accepted_at_floor_equal_to_generation(self):
        checkpoint = checkpoints()["wots"]
        blob = auth_state_wrap(
            checkpoint, scheme="wots", key=KEY, generation=5
        )
        identity = auth_state_fingerprint(blob, key=KEY)
        self.assertEqual(
            auth_state_unwrap(
                blob, key=KEY, min_generation=5, expect_state_id=identity
            ),
            ("wots", 5, checkpoint),
        )

    def test_identity_accepted_as_bytearray(self):
        checkpoint = checkpoints()["lamport"]
        blob = auth_state_wrap(
            checkpoint, scheme="lamport", key=KEY, generation=9
        )
        identity = auth_state_fingerprint(blob, key=KEY)
        self.assertEqual(
            auth_state_unwrap(
                blob, key=KEY, expect_state_id=bytearray(identity)
            ),
            ("lamport", 9, checkpoint),
        )

    def test_wrong_identity_rejected(self):
        checkpoint = checkpoints()["lamport"]
        blob = auth_state_wrap(
            checkpoint, scheme="lamport", key=KEY, generation=3
        )
        other = auth_state_wrap(
            OneTimeSigner(keygen(bits=32)[0]).checkpoint(),
            scheme="lamport",
            key=KEY,
            generation=3,
        )
        other_identity = auth_state_fingerprint(other, key=KEY)
        # A valid identity, same key and same generation, but a different
        # payload: must be rejected.
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                blob, key=KEY, expect_state_id=other_identity
            )

    def test_wrong_identity_after_payload_generation_scheme_key_change(self):
        cps = checkpoints()
        blob = auth_state_wrap(
            cps["lamport"], scheme="lamport", key=KEY, generation=3
        )
        identity = auth_state_fingerprint(blob, key=KEY)

        # Changed payload.
        tampered = bytearray(cps["lamport"])
        tampered[-1] ^= 0x01
        changed_payload = auth_state_wrap(
            bytes(tampered), scheme="lamport", key=KEY, generation=3
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                changed_payload, key=KEY, expect_state_id=identity
            )

        # Changed generation.
        changed_generation = auth_state_wrap(
            cps["lamport"], scheme="lamport", key=KEY, generation=4
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                changed_generation, key=KEY, expect_state_id=identity
            )

        # Changed scheme (different, valid checkpoint).
        changed_scheme = auth_state_wrap(
            cps["wots"], scheme="wots", key=KEY, generation=3
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                changed_scheme, key=KEY, expect_state_id=identity
            )

        # The saved identity is worthless under another key: a blob wrapped
        # under a different key fails the tag first, and even its identity
        # never matches the old one.
        changed_key = auth_state_wrap(
            cps["lamport"], scheme="lamport", key=b"a-different-key",
            generation=3,
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                changed_key, key=b"a-different-key",
                expect_state_id=identity,
            )
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                changed_key, key=KEY, expect_state_id=identity
            )

    def test_identity_length_errors(self):
        checkpoint = checkpoints()["lamport"]
        blob = auth_state_wrap(
            checkpoint, scheme="lamport", key=KEY, generation=0
        )
        identity = auth_state_fingerprint(blob, key=KEY)
        for bad_length in (0, 1, 31, 33, 64):
            bad = identity[:bad_length] if bad_length < 32 else identity + b"\x00" * (
                bad_length - 32
            )
            with self.subTest(bad_length=bad_length):
                with self.assertRaises(ValueError):
                    auth_state_unwrap(blob, key=KEY, expect_state_id=bad)

    def test_identity_wrong_type(self):
        checkpoint = checkpoints()["lamport"]
        blob = auth_state_wrap(
            checkpoint, scheme="lamport", key=KEY, generation=0
        )
        for bad in (None, 42, "0" * 32, [b"\x00" * 32], (b"\x00" * 32,),
                    object()):
            # None is a legal "omit" value, so exclude it from the failure
            # cases; everything else is a type error before authentication.
            if bad is None:
                continue
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_state_unwrap(blob, key=KEY, expect_state_id=bad)

    def test_identity_mismatch_does_not_trust_any_state(self):
        # Bad tag, v1 envelope, truncation and floor failure all raise even
        # when the supplied identity would be well-formed.
        cps = checkpoints()
        blob = auth_state_wrap(
            cps["lamport"], scheme="lamport", key=KEY, generation=5
        )
        identity = auth_state_fingerprint(blob, key=KEY)

        bad_tag = bytearray(blob)
        bad_tag[-1] ^= 0x01
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                bytes(bad_tag), key=KEY, expect_state_id=identity
            )

        v1_blob = auth_wrap(cps["lamport"], scheme="lamport", key=KEY)
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                v1_blob, key=KEY, expect_state_id=identity
            )

        with self.assertRaises(ValueError):
            auth_state_unwrap(
                blob[:-1], key=KEY, expect_state_id=identity
            )

        with self.assertRaises(ValueError):
            auth_state_unwrap(
                blob + b"\x00", key=KEY, expect_state_id=identity
            )

        with self.assertRaises(ValueError):
            auth_state_unwrap(
                blob, key=KEY, min_generation=6, expect_state_id=identity
            )

    def test_omitting_identity_preserves_legacy_behaviour(self):
        for scheme, checkpoint in checkpoints().items():
            with self.subTest(scheme=scheme):
                blob = auth_state_wrap(
                    checkpoint, scheme=scheme, key=KEY, generation=2
                )
                # Positional/keyword call shapes old callers use.
                self.assertEqual(
                    auth_state_unwrap(blob, key=KEY),
                    auth_state_unwrap(
                        blob, key=KEY, expect_state_id=None
                    ),
                )
                self.assertEqual(
                    auth_state_unwrap(
                        blob, key=KEY, expect=scheme, min_generation=2
                    ),
                    (scheme, 2, checkpoint),
                )

    def test_expect_state_id_with_bytearray_blob(self):
        checkpoint = checkpoints()["merkle"]
        blob = auth_state_wrap(
            checkpoint, scheme="merkle", key=KEY, generation=1
        )
        identity = auth_state_fingerprint(blob, key=KEY)
        self.assertEqual(
            auth_state_unwrap(
                bytearray(blob),
                key=bytearray(KEY),
                expect="merkle",
                expect_state_id=identity,
            ),
            ("merkle", 1, checkpoint),
        )


class RollbackWorkflowTest(unittest.TestCase):
    """Acceptance scenario: persist identity + floor, reject replaced state."""

    def test_saved_identity_and_floor_reject_replaced_same_generation(self):
        cps = checkpoints()
        # The current accepted state.
        current = auth_state_wrap(
            cps["lamport"], scheme="lamport", key=KEY, generation=5
        )
        state_id = auth_state_fingerprint(current, key=KEY)
        floor = 5  # trusted high-water mark

        # An older, valid blob an attacker substitutes at the same
        # generation: valid tag, generation on the floor, different payload.
        old_cp = OneTimeSigner(keygen(bits=32)[0]).checkpoint()
        replaced = auth_state_wrap(
            old_cp, scheme="lamport", key=KEY, generation=5
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                replaced,
                key=KEY,
                min_generation=floor,
                expect_state_id=state_id,
            )

        # The true current state still restores.
        scheme, generation, payload = auth_state_unwrap(
            current,
            key=KEY,
            min_generation=floor,
            expect_state_id=state_id,
        )
        self.assertEqual((scheme, generation, payload),
                         ("lamport", 5, cps["lamport"]))

        # An older generation is caught by the floor alone.
        older = auth_state_wrap(
            old_cp, scheme="lamport", key=KEY, generation=4
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                older,
                key=KEY,
                min_generation=floor,
                expect_state_id=state_id,
            )

    def test_advance_workflow_identity_rotates_with_state(self):
        # Simulate sign -> wrap g+1 -> save (identity, floor=g+1): the old
        # saved identity must no longer authorise the new state, and the new
        # identity authorises exactly the new state.
        signer = OneTimeSigner(keygen(bits=32)[0])
        old_blob = auth_state_wrap(
            signer.checkpoint(), scheme="lamport", key=KEY, generation=0
        )
        old_identity = auth_state_fingerprint(old_blob, key=KEY)

        signature, new_blob = signer.sign_with_auth_state(
            b"message", key=KEY, generation=1
        )
        self.assertTrue(signature)
        new_identity = auth_state_fingerprint(new_blob, key=KEY)
        self.assertNotEqual(old_identity, new_identity)

        # Replaying the new envelope against the stale identity/floor fails.
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                new_blob,
                key=KEY,
                min_generation=0,
                expect_state_id=old_identity,
            )
        # The old envelope against the new floor fails as well.
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                old_blob,
                key=KEY,
                min_generation=1,
                expect_state_id=old_identity,
            )
        # Persisted new identity + floor accept only the new state.
        scheme, generation, payload = auth_state_unwrap(
            new_blob,
            key=KEY,
            min_generation=1,
            expect_state_id=new_identity,
        )
        self.assertEqual(scheme, "lamport")
        self.assertEqual(generation, 1)
        OneTimeSigner.from_checkpoint(payload)


if __name__ == "__main__":
    unittest.main()

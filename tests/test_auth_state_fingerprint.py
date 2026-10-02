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
    merkle_verify,
    toy_lattice_keygen,
    wots_keygen,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret-key"
STATE_ID_DOMAIN = b"pqattest/auth-state-id/v1"
UINT64_MAX = 2**64 - 1


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


def wrap(scheme, checkpoint, *, key=KEY, generation=0):
    return auth_state_wrap(
        checkpoint, scheme=scheme, key=key, generation=generation
    )


def reference_identity(blob, key=KEY):
    """Independent spec formula: HMAC over the pre-tag v2 body."""
    return hmac.new(key, STATE_ID_DOMAIN + blob[:-32], hashlib.sha256).digest()


class FingerprintBasicTest(unittest.TestCase):
    def test_returns_32_bytes(self):
        cps = checkpoints()
        for scheme, checkpoint in cps.items():
            with self.subTest(scheme=scheme):
                blob = wrap(scheme, checkpoint, generation=3)
                state_id = auth_state_fingerprint(blob, key=KEY)
                self.assertIsInstance(state_id, bytes)
                self.assertEqual(len(state_id), 32)

    def test_deterministic_same_envelope_and_key(self):
        for scheme, checkpoint in checkpoints().items():
            with self.subTest(scheme=scheme):
                blob = wrap(scheme, checkpoint, generation=8)
                first = auth_state_fingerprint(blob, key=KEY)
                second = auth_state_fingerprint(blob, key=KEY)
                self.assertEqual(first, second)
                # Re-wrapping deterministically yields identical bytes and
                # therefore an identical identity.
                rewrapped = wrap(scheme, checkpoint, generation=8)
                self.assertEqual(
                    first, auth_state_fingerprint(rewrapped, key=KEY)
                )

    def test_matches_reference_formula(self):
        for scheme, checkpoint in checkpoints().items():
            with self.subTest(scheme=scheme):
                blob = wrap(scheme, checkpoint, generation=12)
                self.assertEqual(
                    auth_state_fingerprint(blob, key=KEY),
                    reference_identity(blob),
                )

    def test_known_answer_vector(self):
        # Fixed inputs pin the domain separator and the body coverage: the
        # identity is over the domain string concatenated with every byte
        # before the tag, including header and generation.
        checkpoint = checkpoints()["lamport"]
        blob = wrap("lamport", checkpoint, generation=4242)
        expected = hmac.new(
            KEY, STATE_ID_DOMAIN + blob[:-32], hashlib.sha256
        ).digest()
        self.assertEqual(auth_state_fingerprint(blob, key=KEY), expected)
        # The identity is neither the envelope tag nor a bare payload HMAC.
        self.assertNotEqual(auth_state_fingerprint(blob, key=KEY), blob[-32:])
        self.assertNotEqual(
            auth_state_fingerprint(blob, key=KEY),
            hmac.new(KEY, checkpoint, hashlib.sha256).digest(),
        )

    def test_accepts_bytearray_inputs(self):
        blob = wrap("wots", checkpoints()["wots"], generation=1)
        from_bytes = auth_state_fingerprint(blob, key=KEY)
        from_arrays = auth_state_fingerprint(
            bytearray(blob), key=bytearray(KEY)
        )
        self.assertEqual(from_bytes, from_arrays)


class FingerprintDistinctnessTest(unittest.TestCase):
    def setUp(self):
        self.cps = checkpoints()

    def test_different_payloads_distinct(self):
        signer_a = MerkleSigner(height=1, w=4)
        signer_b = MerkleSigner(height=1, w=4)
        signer_b.sign(b"m")
        blob_a = wrap("merkle", signer_a.checkpoint(), generation=5)
        blob_b = wrap("merkle", signer_b.checkpoint(), generation=5)
        id_a = auth_state_fingerprint(blob_a, key=KEY)
        id_b = auth_state_fingerprint(blob_b, key=KEY)
        self.assertNotEqual(id_a, id_b)

    def test_different_generations_distinct(self):
        checkpoint = self.cps["lamport"]
        low = wrap("lamport", checkpoint, generation=1)
        high = wrap("lamport", checkpoint, generation=2)
        self.assertNotEqual(
            auth_state_fingerprint(low, key=KEY),
            auth_state_fingerprint(high, key=KEY),
        )

    def test_different_schemes_distinct(self):
        # Same payload bytes can only legitimately carry one scheme's magic,
        # so compare identifiers of two genuinely different checkpoints; a
        # forged re-tag across identifiers must still fail fingerprinting
        # rather than collide.
        id_lamport = auth_state_fingerprint(
            wrap("lamport", self.cps["lamport"], generation=0), key=KEY
        )
        id_wots = auth_state_fingerprint(
            wrap("wots", self.cps["wots"], generation=0), key=KEY
        )
        id_merkle = auth_state_fingerprint(
            wrap("merkle", self.cps["merkle"], generation=0), key=KEY
        )
        self.assertEqual(len({id_lamport, id_wots, id_merkle}), 3)

    def test_different_keys_distinct(self):
        checkpoint = self.cps["lamport"]
        blob_a = wrap("lamport", checkpoint, key=KEY, generation=7)
        blob_b = wrap("lamport", checkpoint, key=OTHER_KEY, generation=7)
        id_a = auth_state_fingerprint(blob_a, key=KEY)
        id_b = auth_state_fingerprint(blob_b, key=OTHER_KEY)
        self.assertNotEqual(id_a, id_b)

    def test_same_generation_replacements_never_share_identity(self):
        # The exact gap the floor cannot close: two valid envelopes at the
        # same generation with different payloads.
        base = MerkleSigner(height=2, w=4)
        base.sign(b"first")
        replaced = MerkleSigner(height=2, w=4)
        replaced.sign(b"first")
        replaced.sign(b"second")
        old_blob = wrap("merkle", base.checkpoint(), generation=3)
        new_blob = wrap("merkle", replaced.checkpoint(), generation=3)
        self.assertNotEqual(
            auth_state_fingerprint(old_blob, key=KEY),
            auth_state_fingerprint(new_blob, key=KEY),
        )


class FingerprintErrorTest(unittest.TestCase):
    def setUp(self):
        self.blob = wrap("lamport", checkpoints()["lamport"], generation=0)

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

    def test_rejects_v1_envelope(self):
        v1_blob = auth_wrap(checkpoints()["lamport"], scheme="lamport", key=KEY)
        self.assertEqual(v1_blob[8], 1)
        with self.assertRaises(ValueError):
            auth_state_fingerprint(v1_blob, key=KEY)

    def test_rejects_bad_tag_and_wrong_key(self):
        tampered = bytearray(self.blob)
        tampered[-1] ^= 0x01
        with self.assertRaises(ValueError):
            auth_state_fingerprint(bytes(tampered), key=KEY)
        with self.assertRaises(ValueError):
            auth_state_fingerprint(self.blob, key=OTHER_KEY)

    def test_rejects_tampered_body(self):
        tampered = bytearray(self.blob)
        tampered[17] ^= 0x01  # generation byte inside the authenticated body
        with self.assertRaises(ValueError):
            auth_state_fingerprint(bytes(tampered), key=KEY)

    def test_rejects_truncation_and_trailing_data(self):
        for cut in (0, 21, 31, 32, len(self.blob) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    auth_state_fingerprint(self.blob[:cut], key=KEY)
        with self.assertRaises(ValueError):
            auth_state_fingerprint(self.blob + b"\x00", key=KEY)

    def test_rejects_bad_magic_and_version(self):
        bad_magic = bytearray(self.blob)
        bad_magic[0] ^= 0x01
        bad_magic[-32:] = hmac.new(
            KEY, bytes(bad_magic[:-32]), hashlib.sha256
        ).digest()
        with self.assertRaises(ValueError):
            auth_state_fingerprint(bytes(bad_magic), key=KEY)

        bad_version = bytearray(self.blob)
        bad_version[8] = 3
        bad_version[-32:] = hmac.new(
            KEY, bytes(bad_version[:-32]), hashlib.sha256
        ).digest()
        with self.assertRaises(ValueError):
            auth_state_fingerprint(bytes(bad_version), key=KEY)

    def test_rejects_unknown_scheme_identifier(self):
        checkpoint = checkpoints()["lamport"]
        body = (
            b"PQAAUTH\0"
            + bytes((2, 9))
            + (0).to_bytes(8, "big")
            + len(checkpoint).to_bytes(4, "big")
            + checkpoint
        )
        forged = body + hmac.new(KEY, body, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            auth_state_fingerprint(forged, key=KEY)

    def test_rejects_payload_magic_mismatch_even_with_valid_tag(self):
        body = (
            b"PQAAUTH\0"
            + bytes((2, 1))  # claims lamport
            + (0).to_bytes(8, "big")
            + (32).to_bytes(4, "big")
            + b"\x00" * 32
        )
        forged = body + hmac.new(KEY, body, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            auth_state_fingerprint(forged, key=KEY)


class ExpectStateIdAcceptTest(unittest.TestCase):
    def test_correct_identity_returns_triple(self):
        for scheme, checkpoint in checkpoints().items():
            with self.subTest(scheme=scheme):
                blob = wrap(scheme, checkpoint, generation=21)
                state_id = auth_state_fingerprint(blob, key=KEY)
                scheme_out, generation, payload = auth_state_unwrap(
                    blob,
                    key=KEY,
                    expect=scheme,
                    min_generation=21,
                    expect_state_id=state_id,
                )
                self.assertEqual(scheme_out, scheme)
                self.assertEqual(generation, 21)
                self.assertEqual(payload, checkpoint)

    def test_identity_accepts_bytearray_of_length_32(self):
        blob = wrap("wots", checkpoints()["wots"], generation=4)
        state_id = auth_state_fingerprint(blob, key=KEY)
        result = auth_state_unwrap(
            blob, key=bytearray(KEY), expect_state_id=bytearray(state_id)
        )
        self.assertEqual(result[1], 4)

    def test_floor_equal_and_below_still_accepted_with_identity(self):
        blob = wrap("lamport", checkpoints()["lamport"], generation=9)
        state_id = auth_state_fingerprint(blob, key=KEY)
        self.assertEqual(
            auth_state_unwrap(
                blob, key=KEY, min_generation=9, expect_state_id=state_id
            )[1],
            9,
        )
        self.assertEqual(
            auth_state_unwrap(
                blob, key=KEY, min_generation=0, expect_state_id=state_id
            )[1],
            9,
        )

    def test_identity_computed_under_reference_formula_accepted(self):
        checkpoint = checkpoints()["merkle"]
        blob = wrap("merkle", checkpoint, generation=1)
        scheme, generation, payload = auth_state_unwrap(
            blob, key=KEY, expect_state_id=reference_identity(blob)
        )
        self.assertEqual((scheme, generation), ("merkle", 1))
        self.assertEqual(payload, checkpoint)


class ExpectStateIdRejectTest(unittest.TestCase):
    def setUp(self):
        self.cps = checkpoints()
        self.blob = wrap("lamport", self.cps["lamport"], generation=5)
        self.state_id = auth_state_fingerprint(self.blob, key=KEY)

    def test_identity_from_other_payload_rejected(self):
        other = wrap("lamport", OneTimeSigner(keygen(bits=32)[0]).checkpoint(),
                     generation=5)
        wrong_id = auth_state_fingerprint(other, key=KEY)
        self.assertNotEqual(wrong_id, self.state_id)
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                self.blob,
                key=KEY,
                min_generation=5,
                expect_state_id=wrong_id,
            )

    def test_identity_from_other_generation_rejected(self):
        other = wrap("lamport", self.cps["lamport"], generation=6)
        wrong_id = auth_state_fingerprint(other, key=KEY)
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                self.blob, key=KEY, expect_state_id=wrong_id
            )

    def test_identity_from_other_scheme_rejected(self):
        other = wrap("wots", self.cps["wots"], generation=5)
        wrong_id = auth_state_fingerprint(other, key=KEY)
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                self.blob, key=KEY, expect_state_id=wrong_id
            )

    def test_identity_under_other_key_rejected(self):
        # An identity is a keyed HMAC: one computed over the same body with
        # the wrong key must not match an unwrap under the real key. It
        # cannot be obtained via auth_state_fingerprint with the wrong key
        # (that fails the envelope tag first), so derive it directly.
        wrong_id = hmac.new(
            OTHER_KEY, STATE_ID_DOMAIN + self.blob[:-32], hashlib.sha256
        ).digest()
        self.assertNotEqual(wrong_id, self.state_id)
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                self.blob, key=KEY, expect_state_id=wrong_id
            )

    def test_random_32_bytes_rejected(self):
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                self.blob, key=KEY, expect_state_id=b"\x00" * 32
            )
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                self.blob, key=KEY, expect_state_id=b"\xff" * 32
            )

    def test_wrong_length_identity_rejected(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33, self.state_id[:-1],
                    self.state_id + b"\x00"):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    auth_state_unwrap(
                        self.blob, key=KEY, expect_state_id=bad
                    )

    def test_wrong_type_identity_rejected(self):
        for bad in (42, "0" * 32, [0] * 32, self.state_id.hex(), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_state_unwrap(
                        self.blob, key=KEY, expect_state_id=bad
                    )

    def test_none_identity_keeps_check_disabled(self):
        # None is the documented "no identity check" sentinel, not a type
        # error, and None must never match even a 32-byte identity value.
        self.assertEqual(
            auth_state_unwrap(self.blob, key=KEY, expect_state_id=None),
            auth_state_unwrap(self.blob, key=KEY),
        )

    def test_floor_still_enforced_when_identity_matches(self):
        # The identity pins this exact generation-5 envelope; a caller that
        # advanced its floor must still reject it on the floor, regardless.
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                self.blob,
                key=KEY,
                min_generation=6,
                expect_state_id=self.state_id,
            )

    def test_expect_still_enforced_with_identity(self):
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                self.blob,
                key=KEY,
                expect="wots",
                expect_state_id=self.state_id,
            )

    def test_bad_tag_rejected_before_identity_can_save_it(self):
        # Even the genuine identity must not authenticate a tampered blob:
        # the tag check runs first and raises.
        tampered = bytearray(self.blob)
        tampered[-1] ^= 0x01
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                bytes(tampered),
                key=KEY,
                expect_state_id=self.state_id,
            )

    def test_v1_envelope_rejected_with_identity(self):
        v1_blob = auth_wrap(self.cps["lamport"], scheme="lamport", key=KEY)
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                v1_blob, key=KEY, expect_state_id=self.state_id
            )


class BackwardCompatibilityTest(unittest.TestCase):
    def test_omitting_expect_state_id_unchanged(self):
        cps = checkpoints()
        for scheme, checkpoint in cps.items():
            with self.subTest(scheme=scheme):
                blob = wrap(scheme, checkpoint, generation=2)
                self.assertEqual(
                    auth_state_unwrap(blob, key=KEY),
                    (scheme, 2, checkpoint),
                )
                self.assertEqual(
                    auth_state_unwrap(
                        blob, key=KEY, expect=scheme, min_generation=2
                    ),
                    (scheme, 2, checkpoint),
                )
                # Explicit None behaves exactly like omission.
                self.assertEqual(
                    auth_state_unwrap(
                        blob,
                        key=KEY,
                        expect=scheme,
                        min_generation=2,
                        expect_state_id=None,
                    ),
                    (scheme, 2, checkpoint),
                )

    def test_existing_failure_semantics_unchanged(self):
        blob = wrap("lamport", checkpoints()["lamport"], generation=0)
        with self.assertRaises(ValueError):
            auth_state_unwrap(blob, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            auth_state_unwrap(blob[:-1], key=KEY)
        with self.assertRaises(ValueError):
            auth_state_unwrap(blob + b"\x00", key=KEY)
        with self.assertRaises(ValueError):
            auth_state_unwrap(blob, key=KEY, min_generation=1)

    def test_v2_bytes_unchanged(self):
        checkpoint = checkpoints()["lamport"]
        blob = wrap("lamport", checkpoint, generation=77)
        self.assertEqual(blob[:8], b"PQAAUTH\0")
        self.assertEqual(blob[8], 2)
        self.assertEqual(blob[9], 1)
        self.assertEqual(int.from_bytes(blob[10:18], "big"), 77)
        self.assertEqual(
            int.from_bytes(blob[18:22], "big"), len(checkpoint)
        )
        self.assertEqual(blob[22 : 22 + len(checkpoint)], checkpoint)
        self.assertEqual(
            hmac.new(KEY, blob[:-32], hashlib.sha256).digest(), blob[-32:]
        )

    def test_v1_wrap_unwrap_still_works(self):
        for scheme, checkpoint in (
            ("lamport", checkpoints()["lamport"]),
            ("wots", checkpoints()["wots"]),
        ):
            with self.subTest(scheme=scheme):
                v1_blob = auth_wrap(checkpoint, scheme=scheme, key=KEY)
                got_scheme, got_payload = auth_unwrap(v1_blob, key=KEY)
                self.assertEqual(got_scheme, scheme)
                self.assertEqual(got_payload, checkpoint)


class SavedIdentityReplayFlowTest(unittest.TestCase):
    """Caller-side stateless flow: fingerprint + floor saved in trusted store.

    Mirrors how the stateless auth-state conversions are composed: unwrap
    with the saved identity/floor, only then restore the signer and run the
    monotonic claim. A replaced same-generation envelope must fail the gate
    so no signer is created, no claim runs and no state advances.
    """

    def make_flow(self):
        claims = []

        def accept(blob, *, key, trusted):
            # The gate: identity and high-water mark must both match before
            # anything expensive or monotonic happens.
            scheme, generation, checkpoint = auth_state_unwrap(
                blob,
                key=key,
                min_generation=trusted["generation"],
                expect_state_id=trusted["state_id"],
            )
            signer = MerkleSigner.from_checkpoint(checkpoint)
            token = (scheme, generation)

            def claim(candidate):
                claims.append(candidate)
                return True

            assert claim(token) is True
            return signer, generation

        return accept, claims

    def test_accepted_state_returns_original_content(self):
        signer = MerkleSigner(height=2, w=4)
        signature = signer.sign(b"m")
        blob = wrap("merkle", signer.checkpoint(), generation=10)
        trusted = {
            "generation": 10,
            "state_id": auth_state_fingerprint(blob, key=KEY),
        }
        accept, claims = self.make_flow()
        restored, generation = accept(blob, key=KEY, trusted=trusted)
        self.assertEqual(generation, 10)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, signer.next_index)
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0], ("merkle", 10))
        # The original signer is untouched by the restore/claim flow.
        self.assertEqual(restored.next_index, 1)
        self.assertTrue(merkle_verify(b"m", signature, signer.public_key))

    def test_replaced_same_generation_state_rejected_without_claim(self):
        signer = MerkleSigner(height=2, w=4)
        signer.sign(b"m")
        accepted_blob = wrap("merkle", signer.checkpoint(), generation=10)
        trusted = {
            "generation": 10,
            "state_id": auth_state_fingerprint(accepted_blob, key=KEY),
        }

        # Attacker-substituted state: a different checkpoint, same
        # generation, correctly wrapped under the shared key.
        other = MerkleSigner(height=2, w=4)
        other.sign(b"attacker")
        other.sign(b"attacker2")
        replaced_blob = wrap(
            "merkle", other.checkpoint(), generation=10
        )

        accept, claims = self.make_flow()
        sentinel = object()
        restored = sentinel
        with self.assertRaises(ValueError):
            restored, _ = accept(replaced_blob, key=KEY, trusted=trusted)
        self.assertIs(restored, sentinel)  # no signer assignment occurred
        self.assertEqual(claims, [])  # claim never invoked

    def test_older_generation_rejected_even_if_identity_saved_style(self):
        signer = MerkleSigner(height=2, w=4)
        signer.sign(b"m")
        new_blob = wrap("merkle", signer.checkpoint(), generation=11)
        trusted = {
            "generation": 11,
            "state_id": auth_state_fingerprint(new_blob, key=KEY),
        }
        old_signer = MerkleSigner(height=2, w=4)
        old_blob = wrap("merkle", old_signer.checkpoint(), generation=10)
        accept, claims = self.make_flow()
        with self.assertRaises(ValueError):
            accept(old_blob, key=KEY, trusted=trusted)
        self.assertEqual(claims, [])

    def test_legacy_caller_without_identity_keeps_old_behavior(self):
        # A caller that never persists an identity keeps using only the
        # floor: the same-generation replacement unwraps successfully,
        # exactly as before this feature existed.
        signer = MerkleSigner(height=2, w=4)
        signer.sign(b"m")
        other = MerkleSigner(height=2, w=4)
        other.sign(b"attacker")
        blob = wrap("merkle", other.checkpoint(), generation=10)
        scheme, generation, payload = auth_state_unwrap(
            blob, key=KEY, min_generation=10
        )
        self.assertEqual((scheme, generation), ("merkle", 10))
        self.assertEqual(payload, other.checkpoint())


if __name__ == "__main__":
    unittest.main()

import hashlib
import hmac
import unittest

from pqattest import (
    MerkleSigner,
    OneTimeSigner,
    WOTSOneTimeSigner,
    auth_state_unwrap,
    auth_state_wrap,
    auth_unwrap,
    auth_wrap,
    keygen,
    wots_keygen,
)

KEY = b"shared-secret-key"
UINT64_MAX = 2**64 - 1
STATE_HEADER = 22  # magic(8) + version(1) + id(1) + generation(8) + length(4)
TAG = 32


def checkpoints():
    lamport = OneTimeSigner(keygen(bits=32)[0]).checkpoint()
    wots = WOTSOneTimeSigner(wots_keygen(w=4)[0]).checkpoint()
    merkle = MerkleSigner(height=1, w=4).checkpoint()
    return {
        "lamport": lamport,
        "wots": wots,
        "merkle": merkle,
    }


class StateWrapLayoutTest(unittest.TestCase):
    IDENTIFIERS = {"lamport": 1, "wots": 2, "merkle": 3}
    PAYLOAD_MAGICS = {
        "lamport": b"PQALCP\0\0",
        "wots": b"PQAWCP\0\0",
        "merkle": b"PQAMSCP\0",
    }

    def test_v2_layout(self):
        for scheme, checkpoint in checkpoints().items():
            for generation in (0, 1, 255, 256, UINT64_MAX):
                with self.subTest(scheme=scheme, generation=generation):
                    blob = auth_state_wrap(
                        checkpoint, scheme=scheme, key=KEY, generation=generation
                    )
                    self.assertIsInstance(blob, bytes)
                    self.assertEqual(blob[:8], b"PQAAUTH\0")
                    self.assertEqual(blob[8], 2)  # version
                    self.assertEqual(blob[9], self.IDENTIFIERS[scheme])
                    self.assertEqual(
                        int.from_bytes(blob[10:18], "big"), generation
                    )
                    payload_length = int.from_bytes(blob[18:22], "big")
                    self.assertEqual(payload_length, len(checkpoint))
                    self.assertEqual(blob[22 : 22 + payload_length], checkpoint)
                    body, tag = blob[:-32], blob[-32:]
                    self.assertEqual(
                        hmac.new(KEY, body, hashlib.sha256).digest(), tag
                    )
                    self.assertEqual(len(blob), 22 + len(checkpoint) + 32)

    def test_payload_keeps_own_checkpoint_magic(self):
        for scheme, checkpoint in checkpoints().items():
            with self.subTest(scheme=scheme):
                blob = auth_state_wrap(
                    checkpoint, scheme=scheme, key=KEY, generation=3
                )
                payload = blob[22 : 22 + len(checkpoint)]
                self.assertEqual(payload[:8], self.PAYLOAD_MAGICS[scheme])

    def test_deterministic(self):
        checkpoint = checkpoints()["lamport"]
        self.assertEqual(
            auth_state_wrap(checkpoint, scheme="lamport", key=KEY, generation=9),
            auth_state_wrap(checkpoint, scheme="lamport", key=KEY, generation=9),
        )

    def test_generation_changes_bytes(self):
        checkpoint = checkpoints()["lamport"]
        low = auth_state_wrap(checkpoint, scheme="lamport", key=KEY, generation=0)
        high = auth_state_wrap(
            checkpoint, scheme="lamport", key=KEY, generation=1
        )
        self.assertNotEqual(low, high)
        # Everything except the generation field and the trailing tag is
        # identical: magic/version/id prefix and length+payload region.
        self.assertEqual(low[:10], high[:10])
        self.assertEqual(low[18:-TAG], high[18:-TAG])
        self.assertEqual(
            low[18:22], len(checkpoint).to_bytes(4, "big")
        )
        self.assertNotEqual(low[-TAG:], high[-TAG:])

    def test_accepts_bytearray_inputs(self):
        checkpoint = bytearray(checkpoints()["wots"])
        blob = auth_state_wrap(
            checkpoint, scheme="wots", key=bytearray(KEY), generation=42
        )
        scheme, generation, payload = auth_state_unwrap(
            bytearray(blob), key=bytearray(KEY)
        )
        self.assertEqual((scheme, generation), ("wots", 42))
        self.assertEqual(payload, bytes(checkpoint))
        self.assertIsInstance(payload, bytes)

    def test_generation_and_key_are_keyword_only(self):
        checkpoint = checkpoints()["lamport"]
        with self.assertRaises(TypeError):
            auth_state_wrap(checkpoint, "lamport", KEY, 5)  # type: ignore[misc]


class StateWrapRoundTripTest(unittest.TestCase):
    def test_round_trip_all_schemes_and_generations(self):
        for scheme, checkpoint in checkpoints().items():
            for generation in (0, 1, 1 << 40, UINT64_MAX):
                with self.subTest(scheme=scheme, generation=generation):
                    blob = auth_state_wrap(
                        checkpoint, scheme=scheme, key=KEY, generation=generation
                    )
                    got_scheme, got_generation, got_payload = auth_state_unwrap(
                        blob, key=KEY
                    )
                    self.assertEqual(got_scheme, scheme)
                    self.assertEqual(got_generation, generation)
                    self.assertIsInstance(got_generation, int)
                    self.assertEqual(got_payload, checkpoint)

    def test_wrapped_checkpoints_restore_signers(self):
        cps = checkpoints()
        _, _, payload = auth_state_unwrap(
            auth_state_wrap(cps["lamport"], scheme="lamport", key=KEY, generation=1),
            key=KEY,
        )
        lamport = OneTimeSigner.from_checkpoint(payload)
        lamport.sign(b"m")

        _, _, payload = auth_state_unwrap(
            auth_state_wrap(cps["wots"], scheme="wots", key=KEY, generation=2),
            key=KEY,
        )
        wots = WOTSOneTimeSigner.from_checkpoint(payload)
        wots.sign(b"m")

        signer = MerkleSigner(height=1, w=4)
        signer.sign(b"m")
        blob = auth_state_wrap(
            signer.checkpoint(), scheme="merkle", key=KEY, generation=3
        )
        _, _, payload = auth_state_unwrap(blob, key=KEY)
        merkle = MerkleSigner.from_checkpoint(payload)
        merkle.sign(b"n")  # resumes at next_index == 1

    def test_expect_matches(self):
        for scheme, checkpoint in checkpoints().items():
            with self.subTest(scheme=scheme):
                blob = auth_state_wrap(
                    checkpoint, scheme=scheme, key=KEY, generation=5
                )
                self.assertEqual(
                    auth_state_unwrap(blob, key=KEY, expect=scheme),
                    (scheme, 5, checkpoint),
                )


class GenerationFloorTest(unittest.TestCase):
    def setUp(self):
        self.checkpoint = checkpoints()["lamport"]
        self.blob = auth_state_wrap(
            self.checkpoint, scheme="lamport", key=KEY, generation=10
        )

    def test_no_floor_by_default(self):
        scheme, generation, payload = auth_state_unwrap(self.blob, key=KEY)
        self.assertEqual((scheme, generation), ("lamport", 10))
        self.assertEqual(payload, self.checkpoint)

    def test_floor_equal_accepted(self):
        self.assertEqual(
            auth_state_unwrap(self.blob, key=KEY, min_generation=10)[1], 10
        )

    def test_floor_below_accepted(self):
        self.assertEqual(
            auth_state_unwrap(self.blob, key=KEY, min_generation=0)[1], 10
        )
        self.assertEqual(
            auth_state_unwrap(self.blob, key=KEY, min_generation=9)[1], 10
        )

    def test_floor_above_rejected(self):
        for floor in (11, 12, UINT64_MAX):
            with self.subTest(floor=floor):
                with self.assertRaises(ValueError):
                    auth_state_unwrap(self.blob, key=KEY, min_generation=floor)

    def test_zero_generation_with_zero_floor_accepted(self):
        blob = auth_state_wrap(
            self.checkpoint, scheme="lamport", key=KEY, generation=0
        )
        self.assertEqual(
            auth_state_unwrap(blob, key=KEY, min_generation=0)[1], 0
        )

    def test_rollback_sequence_detected_with_trusted_floor(self):
        # Simulate a caller persisting the highest accepted generation.
        floor = 0
        new = auth_state_wrap(
            self.checkpoint, scheme="lamport", key=KEY, generation=5
        )
        _, gen, _ = auth_state_unwrap(new, key=KEY, min_generation=floor)
        floor = gen  # caller advances the trusted floor
        old = auth_state_wrap(
            self.checkpoint, scheme="lamport", key=KEY, generation=4
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(old, key=KEY, min_generation=floor)


class StateWrapTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.checkpoint = checkpoints()["lamport"]

    def wrap(self, **kwargs):
        defaults = dict(
            scheme="lamport", key=KEY, generation=1
        )
        defaults.update(kwargs)
        return auth_state_wrap(self.checkpoint, **defaults)

    def test_wrap_rejects_boolean_generation(self):
        for bad in (True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    self.wrap(generation=bad)

    def test_wrap_rejects_non_integer_generation(self):
        for bad in (None, 1.0, 4.5, "1", b"1", [1], (1,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self.wrap(generation=bad)

    def test_wrap_rejects_non_bytes_checkpoint(self):
        for bad in (None, 42, "checkpoint", [self.checkpoint], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_state_wrap(
                        bad, scheme="lamport", key=KEY, generation=1
                    )

    def test_wrap_rejects_non_bytes_key(self):
        for bad in (None, 42, "key", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self.wrap(key=bad)

    def test_wrap_rejects_non_string_scheme(self):
        for bad in (None, 1, 1.0, b"lamport", ("lamport",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self.wrap(scheme=bad)

    def test_unwrap_rejects_non_bytes_data(self):
        blob = self.wrap()
        for bad in (None, 42, 4.5, "blob", [blob], (blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_state_unwrap(bad, key=KEY)

    def test_unwrap_rejects_non_bytes_key(self):
        blob = self.wrap()
        for bad in (None, 42, "key", ["k"]):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_state_unwrap(blob, key=bad)

    def test_unwrap_rejects_non_string_expect(self):
        blob = self.wrap()
        for bad in (1, b"lamport", ("lamport",)):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_state_unwrap(blob, key=KEY, expect=bad)

    def test_unwrap_rejects_boolean_floor(self):
        blob = self.wrap()
        for bad in (True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    auth_state_unwrap(blob, key=KEY, min_generation=bad)

    def test_unwrap_rejects_non_integer_floor(self):
        blob = self.wrap()
        for bad in (1.0, "1", b"1", [1], (1,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_state_unwrap(blob, key=KEY, min_generation=bad)


class StateWrapValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.cps = checkpoints()

    def rewrap(
        self,
        scheme,
        payload,
        key=KEY,
        *,
        identifier=None,
        length=None,
        generation=0,
        version=2,
    ):
        """Build a v2 envelope with a valid HMAC but arbitrary body fields."""
        default_identifier = {"lamport": 1, "wots": 2, "merkle": 3}[scheme]
        identifier = default_identifier if identifier is None else identifier
        claimed_length = len(payload) if length is None else length
        body = (
            b"PQAAUTH\0"
            + bytes((version, identifier))
            + generation.to_bytes(8, "big")
            + claimed_length.to_bytes(4, "big")
            + payload
        )
        return body + hmac.new(key, body, hashlib.sha256).digest()

    def test_generation_out_of_range_rejected(self):
        checkpoint = self.cps["lamport"]
        for bad in (-1, -(2**64), UINT64_MAX + 1, 2**128):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    auth_state_wrap(
                        checkpoint, scheme="lamport", key=KEY, generation=bad
                    )

    def test_floor_out_of_range_rejected(self):
        blob = auth_state_wrap(
            self.cps["lamport"], scheme="lamport", key=KEY, generation=0
        )
        for bad in (-1, UINT64_MAX + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    auth_state_unwrap(blob, key=KEY, min_generation=bad)

    def test_empty_key_rejected(self):
        checkpoint = self.cps["lamport"]
        with self.assertRaises(ValueError):
            auth_state_wrap(
                checkpoint, scheme="lamport", key=b"", generation=0
            )
        blob = auth_state_wrap(
            checkpoint, scheme="lamport", key=KEY, generation=0
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(blob, key=b"")

    def test_unknown_scheme_rejected(self):
        with self.assertRaises(ValueError):
            auth_state_wrap(
                self.cps["lamport"], scheme="Lamport", key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            auth_state_wrap(
                self.cps["lamport"], scheme="", key=KEY, generation=0
            )

    def test_wrap_checks_checkpoint_magic(self):
        with self.assertRaises(ValueError):
            auth_state_wrap(
                self.cps["lamport"], scheme="wots", key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            auth_state_wrap(
                self.cps["merkle"], scheme="lamport", key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            auth_state_wrap(
                b"\x00" * 64, scheme="lamport", key=KEY, generation=0
            )
        with self.assertRaises(ValueError):
            auth_state_wrap(
                b"PQALCP\0", scheme="lamport", key=KEY, generation=0
            )

    def test_bad_envelope_magic(self):
        blob = bytearray(
            auth_state_wrap(
                self.cps["lamport"], scheme="lamport", key=KEY, generation=0
            )
        )
        blob[0] ^= 0x01
        with self.assertRaises(ValueError):
            auth_state_unwrap(bytes(blob), key=KEY)

    def test_v1_envelope_rejected_by_state_unwrap(self):
        v1_blob = auth_wrap(self.cps["lamport"], scheme="lamport", key=KEY)
        self.assertEqual(v1_blob[8], 1)
        with self.assertRaises(ValueError):
            auth_state_unwrap(v1_blob, key=KEY)

    def test_v2_envelope_rejected_by_v1_unwrap(self):
        v2_blob = auth_state_wrap(
            self.cps["lamport"], scheme="lamport", key=KEY, generation=0
        )
        self.assertEqual(v2_blob[8], 2)
        with self.assertRaises(ValueError):
            auth_unwrap(v2_blob, key=KEY)

    def test_bad_version(self):
        for version in (0, 1, 3, 255):
            with self.subTest(version=version):
                forged = self.rewrap(
                    "wots", self.cps["wots"], version=version
                )
                with self.assertRaises(ValueError):
                    auth_state_unwrap(forged, key=KEY)

    def test_unknown_identifier(self):
        body = (
            b"PQAAUTH\0"
            + bytes((2, 9))
            + (0).to_bytes(8, "big")
            + (0).to_bytes(4, "big")
        )
        blob = body + hmac.new(KEY, body, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            auth_state_unwrap(blob, key=KEY)

    def test_truncated_and_empty_rejected(self):
        blob = auth_state_wrap(
            self.cps["lamport"], scheme="lamport", key=KEY, generation=0
        )
        for cut in (0, STATE_HEADER - 1, STATE_HEADER, STATE_HEADER + TAG - 1,
                    len(blob) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    auth_state_unwrap(blob[:cut], key=KEY)
        with self.assertRaises(ValueError):
            auth_state_unwrap(b"", key=KEY)

    def test_trailing_data_rejected(self):
        blob = auth_state_wrap(
            self.cps["lamport"], scheme="lamport", key=KEY, generation=0
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(blob + b"\x00", key=KEY)

    def test_length_field_too_large_rejected(self):
        checkpoint = self.cps["lamport"]
        forged = self.rewrap("lamport", checkpoint, length=len(checkpoint) + 1)
        with self.assertRaises(ValueError):
            auth_state_unwrap(forged, key=KEY)

    def test_length_field_too_small_rejected_as_trailing(self):
        checkpoint = self.cps["lamport"]
        forged = self.rewrap("lamport", checkpoint, length=len(checkpoint) - 1)
        with self.assertRaises(ValueError):
            auth_state_unwrap(forged, key=KEY)

    def test_zero_length_payload_rejected(self):
        forged = self.rewrap("lamport", b"", length=0)
        with self.assertRaises(ValueError):
            auth_state_unwrap(forged, key=KEY)

    def test_wrong_key_and_tampered_tag_rejected(self):
        blob = auth_state_wrap(
            self.cps["lamport"], scheme="lamport", key=KEY, generation=0
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(blob, key=b"a-different-key")
        bad = bytearray(blob)
        bad[-1] ^= 0x01
        with self.assertRaises(ValueError):
            auth_state_unwrap(bytes(bad), key=KEY)

    def test_tampered_generation_breaks_tag(self):
        # The generation is inside the authenticated body: flipping a
        # generation byte invalidates the tag even though a caller-supplied
        # floor is what the attacker is trying to dodge.
        blob = bytearray(
            auth_state_wrap(
                self.cps["lamport"], scheme="lamport", key=KEY, generation=10
            )
        )
        blob[10] ^= 0x01
        with self.assertRaises(ValueError):
            auth_state_unwrap(bytes(blob), key=KEY, min_generation=0)

    def test_tampered_body_rejected(self):
        blob = bytearray(
            auth_state_wrap(
                self.cps["lamport"], scheme="lamport", key=KEY, generation=0
            )
        )
        blob[30] ^= 0x01
        with self.assertRaises(ValueError):
            auth_state_unwrap(bytes(blob), key=KEY)
        # Re-tagged identifier swap still fails the payload magic check.
        forged = bytearray(self.rewrap("wots", self.cps["lamport"]))
        with self.assertRaises(ValueError):
            auth_state_unwrap(bytes(forged), key=KEY)

    def test_payload_magic_checked_after_valid_tag(self):
        forged = self.rewrap("lamport", b"\x00" * 32)
        with self.assertRaises(ValueError):
            auth_state_unwrap(forged, key=KEY)

    def test_expect_mismatch_rejected(self):
        blob = auth_state_wrap(
            self.cps["lamport"], scheme="lamport", key=KEY, generation=0
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(blob, key=KEY, expect="wots")
        with self.assertRaises(ValueError):
            auth_state_unwrap(blob, key=KEY, expect="merkle")

    def test_unknown_expect_rejected_even_for_good_blob(self):
        blob = auth_state_wrap(
            self.cps["lamport"], scheme="lamport", key=KEY, generation=0
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(blob, key=KEY, expect="rsa")

    def test_floor_checked_after_tag_and_scheme(self):
        # A blob below the floor is rejected even when its tag is valid and
        # its scheme matches expect; a tampered blob is rejected regardless
        # of the floor (never silently accepted).
        good = auth_state_wrap(
            self.cps["lamport"], scheme="lamport", key=KEY, generation=1
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                good, key=KEY, expect="lamport", min_generation=2
            )
        bad = bytearray(good)
        bad[-1] ^= 0x01
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                bytes(bad), key=KEY, expect="lamport", min_generation=2
            )

    def test_old_interfaces_unchanged(self):
        OneTimeSigner.from_checkpoint(self.cps["lamport"])
        WOTSOneTimeSigner.from_checkpoint(self.cps["wots"])
        MerkleSigner.from_checkpoint(self.cps["merkle"])
        # v1 layout is byte-for-byte the original 14-byte-header envelope.
        blob = auth_wrap(self.cps["lamport"], scheme="lamport", key=KEY)
        self.assertEqual(blob[:14], b"PQAAUTH\0" + bytes((1, 1))
                         + len(self.cps["lamport"]).to_bytes(4, "big"))
        self.assertEqual(
            auth_unwrap(blob, key=KEY), ("lamport", self.cps["lamport"])
        )


if __name__ == "__main__":
    unittest.main()

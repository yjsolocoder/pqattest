import hashlib
import hmac
import unittest

from pqattest import (
    MerkleSigner,
    OneTimeSigner,
    WOTSOneTimeSigner,
    auth_unwrap,
    auth_wrap,
    keygen,
    wots_keygen,
)

KEY = b"shared-secret-key"


def checkpoints():
    lamport = OneTimeSigner(keygen(bits=32)[0]).checkpoint()
    wots = WOTSOneTimeSigner(wots_keygen(w=4)[0]).checkpoint()
    merkle = MerkleSigner(height=1, w=4).checkpoint()
    return {
        "lamport": lamport,
        "wots": wots,
        "merkle": merkle,
    }


class AuthWrapLayoutTest(unittest.TestCase):
    IDENTIFIERS = {"lamport": 1, "wots": 2, "merkle": 3}
    PAYLOAD_MAGICS = {
        "lamport": b"PQALCP\0\0",
        "wots": b"PQAWCP\0\0",
        "merkle": b"PQAMSCP\0",
    }

    def test_v1_layout(self):
        for scheme, checkpoint in checkpoints().items():
            with self.subTest(scheme=scheme):
                blob = auth_wrap(checkpoint, scheme=scheme, key=KEY)
                self.assertIsInstance(blob, bytes)
                self.assertEqual(blob[:8], b"PQAAUTH\0")
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(blob[9], self.IDENTIFIERS[scheme])
                payload_length = int.from_bytes(blob[10:14], "big")
                self.assertEqual(payload_length, len(checkpoint))
                self.assertEqual(blob[14 : 14 + payload_length], checkpoint)
                body, tag = blob[:-32], blob[-32:]
                self.assertEqual(hmac.new(KEY, body, hashlib.sha256).digest(), tag)
                self.assertEqual(len(blob), 14 + len(checkpoint) + 32)

    def test_payload_keeps_own_checkpoint_magic(self):
        for scheme, checkpoint in checkpoints().items():
            with self.subTest(scheme=scheme):
                blob = auth_wrap(checkpoint, scheme=scheme, key=KEY)
                payload = blob[14 : 14 + len(checkpoint)]
                self.assertEqual(payload[:8], self.PAYLOAD_MAGICS[scheme])

    def test_deterministic(self):
        checkpoint = checkpoints()["lamport"]
        self.assertEqual(
            auth_wrap(checkpoint, scheme="lamport", key=KEY),
            auth_wrap(checkpoint, scheme="lamport", key=KEY),
        )

    def test_accepts_bytearray_inputs(self):
        checkpoint = bytearray(checkpoints()["wots"])
        blob = auth_wrap(checkpoint, scheme="wots", key=bytearray(KEY))
        scheme, payload = auth_unwrap(bytearray(blob), key=bytearray(KEY))
        self.assertEqual(scheme, "wots")
        self.assertEqual(payload, bytes(checkpoint))
        self.assertIsInstance(payload, bytes)


class AuthWrapRoundTripTest(unittest.TestCase):
    def test_round_trip_all_schemes(self):
        for scheme, checkpoint in checkpoints().items():
            with self.subTest(scheme=scheme):
                blob = auth_wrap(checkpoint, scheme=scheme, key=KEY)
                got_scheme, got_payload = auth_unwrap(blob, key=KEY)
                self.assertEqual(got_scheme, scheme)
                self.assertEqual(got_payload, checkpoint)

    def test_wrapped_checkpoints_restore_signers(self):
        cps = checkpoints()
        _, payload = auth_unwrap(
            auth_wrap(cps["lamport"], scheme="lamport", key=KEY), key=KEY
        )
        lamport = OneTimeSigner.from_checkpoint(payload)
        lamport.sign(b"m")  # restored unused signer can sign once

        _, payload = auth_unwrap(
            auth_wrap(cps["wots"], scheme="wots", key=KEY), key=KEY
        )
        wots = WOTSOneTimeSigner.from_checkpoint(payload)
        wots.sign(b"m")

        signer = MerkleSigner(height=1, w=4)
        signer.sign(b"m")
        blob = auth_wrap(signer.checkpoint(), scheme="merkle", key=KEY)
        _, payload = auth_unwrap(blob, key=KEY)
        merkle = MerkleSigner.from_checkpoint(payload)
        merkle.sign(b"n")  # resumes at next_index == 1

    def test_expect_matches(self):
        for scheme, checkpoint in checkpoints().items():
            with self.subTest(scheme=scheme):
                blob = auth_wrap(checkpoint, scheme=scheme, key=KEY)
                self.assertEqual(
                    auth_unwrap(blob, key=KEY, expect=scheme), (scheme, checkpoint)
                )


class AuthWrapTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.checkpoint = checkpoints()["lamport"]

    def test_wrap_rejects_non_bytes_checkpoint(self):
        for bad in (None, 42, "checkpoint", [self.checkpoint], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_wrap(bad, scheme="lamport", key=KEY)

    def test_wrap_rejects_non_bytes_key(self):
        for bad in (None, 42, "key", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_wrap(self.checkpoint, scheme="lamport", key=bad)

    def test_wrap_rejects_non_string_scheme(self):
        for bad in (None, 1, 1.0, b"lamport", ("lamport",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_wrap(self.checkpoint, scheme=bad, key=KEY)

    def test_unwrap_rejects_non_bytes_data(self):
        blob = auth_wrap(self.checkpoint, scheme="lamport", key=KEY)
        for bad in (None, 42, 4.5, "blob", [blob], (blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_unwrap(bad, key=KEY)

    def test_unwrap_rejects_non_bytes_key(self):
        blob = auth_wrap(self.checkpoint, scheme="lamport", key=KEY)
        for bad in (None, 42, "key", ["k"]):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_unwrap(blob, key=bad)

    def test_unwrap_rejects_non_string_expect(self):
        blob = auth_wrap(self.checkpoint, scheme="lamport", key=KEY)
        for bad in (1, b"lamport", ("lamport",)):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_unwrap(blob, key=KEY, expect=bad)


class AuthWrapValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.cps = checkpoints()

    def rewrap(self, scheme, payload, key=KEY, *, identifier=None, length=None):
        """Build an envelope with a valid HMAC but arbitrary body fields."""
        default_identifier = {"lamport": 1, "wots": 2, "merkle": 3}[scheme]
        identifier = default_identifier if identifier is None else identifier
        claimed_length = len(payload) if length is None else length
        body = (
            b"PQAAUTH\0"
            + bytes((1, identifier))
            + claimed_length.to_bytes(4, "big")
            + payload
        )
        return body + hmac.new(key, body, hashlib.sha256).digest()

    def test_empty_key_rejected(self):
        checkpoint = self.cps["lamport"]
        with self.assertRaises(ValueError):
            auth_wrap(checkpoint, scheme="lamport", key=b"")
        blob = auth_wrap(checkpoint, scheme="lamport", key=KEY)
        with self.assertRaises(ValueError):
            auth_unwrap(blob, key=b"")

    def test_unknown_scheme_rejected(self):
        with self.assertRaises(ValueError):
            auth_wrap(self.cps["lamport"], scheme="Lamport", key=KEY)
        with self.assertRaises(ValueError):
            auth_wrap(self.cps["lamport"], scheme="", key=KEY)

    def test_wrap_checks_checkpoint_magic(self):
        # Right bytes, wrong scheme name.
        with self.assertRaises(ValueError):
            auth_wrap(self.cps["lamport"], scheme="wots", key=KEY)
        with self.assertRaises(ValueError):
            auth_wrap(self.cps["merkle"], scheme="lamport", key=KEY)
        # Arbitrary payload without any checkpoint magic.
        with self.assertRaises(ValueError):
            auth_wrap(b"\x00" * 64, scheme="lamport", key=KEY)
        with self.assertRaises(ValueError):
            auth_wrap(b"PQALCP\0", scheme="lamport", key=KEY)  # too short

    def test_bad_envelope_magic(self):
        blob = bytearray(auth_wrap(self.cps["lamport"], scheme="lamport", key=KEY))
        blob[0] ^= 0x01
        with self.assertRaises(ValueError):
            auth_unwrap(bytes(blob), key=KEY)

    def test_bad_version(self):
        blob = bytearray(auth_wrap(self.cps["wots"], scheme="wots", key=KEY))
        blob[8] = 2
        with self.assertRaises(ValueError):
            auth_unwrap(bytes(blob), key=KEY)

    def test_unknown_identifier(self):
        body = (
            b"PQAAUTH\0" + bytes((1, 9)) + (0).to_bytes(4, "big")
        )
        blob = body + hmac.new(KEY, body, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            auth_unwrap(blob, key=KEY)

    def test_truncated_and_empty_rejected(self):
        blob = auth_wrap(self.cps["lamport"], scheme="lamport", key=KEY)
        for cut in (0, 13, 45, len(blob) - 1, len(blob)):
            if cut == len(blob):
                continue
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    auth_unwrap(blob[:cut], key=KEY)
        with self.assertRaises(ValueError):
            auth_unwrap(b"", key=KEY)

    def test_trailing_data_rejected(self):
        blob = auth_wrap(self.cps["lamport"], scheme="lamport", key=KEY)
        with self.assertRaises(ValueError):
            auth_unwrap(blob + b"\x00", key=KEY)

    def test_length_field_too_large_rejected(self):
        checkpoint = self.cps["lamport"]
        forged = self.rewrap("lamport", checkpoint, length=len(checkpoint) + 1)
        with self.assertRaises(ValueError):
            auth_unwrap(forged, key=KEY)

    def test_length_field_too_small_rejected_as_trailing(self):
        # Claim one payload byte fewer: the extra payload byte trails.
        checkpoint = self.cps["lamport"]
        forged = self.rewrap("lamport", checkpoint, length=len(checkpoint) - 1)
        with self.assertRaises(ValueError):
            auth_unwrap(forged, key=KEY)

    def test_zero_length_payload_rejected(self):
        forged = self.rewrap("lamport", b"", length=0)
        with self.assertRaises(ValueError):
            auth_unwrap(forged, key=KEY)

    def test_wrong_key_and_tampered_tag_rejected(self):
        blob = auth_wrap(self.cps["lamport"], scheme="lamport", key=KEY)
        with self.assertRaises(ValueError):
            auth_unwrap(blob, key=b"a-different-key")
        bad = bytearray(blob)
        bad[-1] ^= 0x01
        with self.assertRaises(ValueError):
            auth_unwrap(bytes(bad), key=KEY)

    def test_tampered_body_rejected_even_without_tag_check_help(self):
        # Flipping a body byte invalidates the tag...
        blob = bytearray(auth_wrap(self.cps["lamport"], scheme="lamport", key=KEY))
        blob[20] ^= 0x01
        with self.assertRaises(ValueError):
            auth_unwrap(bytes(blob), key=KEY)
        # ...and an attacker who swaps the identifier, keeps a matching
        # payload length and re-tags still fails the payload magic check.
        forged = bytearray(self.rewrap("wots", self.cps["lamport"]))
        with self.assertRaises(ValueError):
            auth_unwrap(bytes(forged), key=KEY)

    def test_payload_magic_checked_after_valid_tag(self):
        # Valid envelope/tag, arbitrary payload bytes with no checkpoint magic.
        forged = self.rewrap("lamport", b"\x00" * 32)
        with self.assertRaises(ValueError):
            auth_unwrap(forged, key=KEY)

    def test_expect_mismatch_rejected(self):
        blob = auth_wrap(self.cps["lamport"], scheme="lamport", key=KEY)
        with self.assertRaises(ValueError):
            auth_unwrap(blob, key=KEY, expect="wots")
        with self.assertRaises(ValueError):
            auth_unwrap(blob, key=KEY, expect="merkle")

    def test_unknown_expect_rejected_even_for_good_blob(self):
        blob = auth_wrap(self.cps["lamport"], scheme="lamport", key=KEY)
        with self.assertRaises(ValueError):
            auth_unwrap(blob, key=KEY, expect="rsa")

    def test_old_interfaces_unchanged(self):
        # Plaintext checkpoints still parse directly, no envelope required.
        OneTimeSigner.from_checkpoint(self.cps["lamport"])
        WOTSOneTimeSigner.from_checkpoint(self.cps["wots"])
        MerkleSigner.from_checkpoint(self.cps["merkle"])


if __name__ == "__main__":
    unittest.main()

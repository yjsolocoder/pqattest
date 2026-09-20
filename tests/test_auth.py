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


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


KEY = b"unit-test-key"
OTHER_KEY = b"different-key"

# Fixed vector: magic + version 1 + scheme 1 (lamport) + length 21 +
# payload (lamport checkpoint magic + b"payload-bytes") + HMAC-SHA256 tag.
FIXED_BLOB = bytes.fromhex(
    "50514141555448000101000000155051414c435000007061796c6f61642d6279746"
    "573035281643828c56027632823b5b38a289bcb8406684c13ad314c66aae74f0846"
)
FIXED_PAYLOAD = b"PQALCP\0\0" + b"payload-bytes"


def checkpoints():
    lamport = OneTimeSigner(keygen(token_bytes=counter_tokens(1))[0])
    wots = WOTSOneTimeSigner(wots_keygen(token_bytes=counter_tokens(100))[0])
    merkle = MerkleSigner(height=2, w=4, token_bytes=counter_tokens(1000))
    return (
        ("lamport", lamport.checkpoint(), OneTimeSigner.from_checkpoint),
        ("wots", wots.checkpoint(), WOTSOneTimeSigner.from_checkpoint),
        ("merkle", merkle.checkpoint(), MerkleSigner.from_checkpoint),
    )


class AuthWrapFormatTest(unittest.TestCase):
    def test_layout(self):
        blob = auth_wrap(FIXED_PAYLOAD, scheme="lamport", key=KEY)
        self.assertEqual(blob, FIXED_BLOB)
        self.assertEqual(blob[:8], b"PQAAUTH\0")
        self.assertEqual(blob[8], 1)  # version
        self.assertEqual(blob[9], 1)  # scheme identifier
        self.assertEqual(int.from_bytes(blob[10:14], "big"), len(FIXED_PAYLOAD))
        self.assertEqual(blob[14:-32], FIXED_PAYLOAD)
        body = blob[:-32]
        self.assertEqual(blob[-32:], hmac.new(KEY, body, hashlib.sha256).digest())
        self.assertEqual(len(blob), 14 + len(FIXED_PAYLOAD) + 32)

    def test_scheme_identifiers(self):
        for scheme, identifier, magic in (
            ("lamport", 1, b"PQALCP\0\0"),
            ("wots", 2, b"PQAWCP\0\0"),
            ("merkle", 3, b"PQAMSCP\0"),
        ):
            with self.subTest(scheme=scheme):
                payload = magic + b"rest-of-checkpoint"
                blob = auth_wrap(payload, scheme=scheme, key=KEY)
                self.assertEqual(blob[9], identifier)
                self.assertEqual(blob[:8], b"PQAAUTH\0")
                self.assertEqual(blob[8], 1)

    def test_returns_bytes(self):
        self.assertIsInstance(auth_wrap(FIXED_PAYLOAD, scheme="lamport", key=KEY), bytes)

    def test_deterministic(self):
        self.assertEqual(
            auth_wrap(FIXED_PAYLOAD, scheme="lamport", key=KEY),
            auth_wrap(FIXED_PAYLOAD, scheme="lamport", key=KEY),
        )

    def test_accepts_bytearray_inputs(self):
        blob = auth_wrap(bytearray(FIXED_PAYLOAD), scheme="lamport", key=bytearray(KEY))
        self.assertEqual(blob, FIXED_BLOB)

    def test_scheme_and_key_are_keyword_only(self):
        with self.assertRaises(TypeError):
            auth_wrap(FIXED_PAYLOAD, "lamport", KEY)
        with self.assertRaises(TypeError):
            auth_unwrap(FIXED_BLOB, KEY)


class AuthRoundTripTest(unittest.TestCase):
    def test_round_trip_each_scheme(self):
        for scheme, checkpoint, from_checkpoint in checkpoints():
            with self.subTest(scheme=scheme):
                blob = auth_wrap(checkpoint, scheme=scheme, key=KEY)
                name, payload = auth_unwrap(blob, key=KEY)
                self.assertEqual(name, scheme)
                self.assertEqual(payload, checkpoint)
                # The unwrapped payload restores an equivalent signer.
                self.assertEqual(from_checkpoint(payload).public_key,
                                 from_checkpoint(checkpoint).public_key)

    def test_accepts_bytearray_blob(self):
        blob = auth_wrap(FIXED_PAYLOAD, scheme="lamport", key=KEY)
        name, payload = auth_unwrap(bytearray(blob), key=bytearray(KEY))
        self.assertEqual((name, payload), ("lamport", FIXED_PAYLOAD))

    def test_expect_matching(self):
        for scheme, checkpoint, _ in checkpoints():
            with self.subTest(scheme=scheme):
                blob = auth_wrap(checkpoint, scheme=scheme, key=KEY)
                name, payload = auth_unwrap(blob, key=KEY, expect=scheme)
                self.assertEqual(name, scheme)
                self.assertEqual(payload, checkpoint)


class AuthWrapValidationTest(unittest.TestCase):
    def test_checkpoint_type_error(self):
        for bad in (None, 42, 4.5, "checkpoint", [b"x"], (b"x",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_wrap(bad, scheme="lamport", key=KEY)

    def test_key_type_error(self):
        for bad in (None, 42, 4.5, "key", [b"k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_wrap(FIXED_PAYLOAD, scheme="lamport", key=bad)

    def test_empty_key_value_error(self):
        with self.assertRaises(ValueError):
            auth_wrap(FIXED_PAYLOAD, scheme="lamport", key=b"")
        with self.assertRaises(ValueError):
            auth_wrap(FIXED_PAYLOAD, scheme="lamport", key=bytearray())

    def test_scheme_type_error(self):
        for bad in (None, 1, b"lamport", ("lamport",), object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    auth_wrap(FIXED_PAYLOAD, scheme=bad, key=KEY)

    def test_unknown_scheme_value_error(self):
        for bad in ("Lamport", "LAMPORT", "rsa", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    auth_wrap(FIXED_PAYLOAD, scheme=bad, key=KEY)

    def test_scheme_payload_magic_mismatch(self):
        # Each scheme only seals a checkpoint bearing its own magic.
        cases = (
            ("lamport", b"PQAWCP\0\0" + b"x"),
            ("wots", b"PQALCP\0\0" + b"x"),
            ("merkle", b"PQALCP\0\0" + b"x"),
            ("lamport", b"PQAMSCP\0" + b"x"),
        )
        for scheme, payload in cases:
            with self.subTest(scheme=scheme, magic=payload[:8]):
                with self.assertRaises(ValueError):
                    auth_wrap(payload, scheme=scheme, key=KEY)

    def test_payload_without_recognised_magic(self):
        with self.assertRaises(ValueError):
            auth_wrap(b"not a checkpoint at all", scheme="lamport", key=KEY)


class AuthUnwrapValidationTest(unittest.TestCase):
    def setUp(self):
        self.blob = auth_wrap(FIXED_PAYLOAD, scheme="lamport", key=KEY)

    def test_data_type_error(self):
        for bad in (None, 42, 4.5, "data", [self.blob], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_unwrap(bad, key=KEY)

    def test_key_type_error(self):
        for bad in (None, 42, 4.5, "key", [b"k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_unwrap(self.blob, key=bad)

    def test_expect_type_error(self):
        for bad in (1, b"lamport", ("lamport",), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_unwrap(self.blob, key=KEY, expect=bad)

    def test_empty_key_value_error(self):
        with self.assertRaises(ValueError):
            auth_unwrap(self.blob, key=b"")

    def test_expect_mismatch_value_error(self):
        with self.assertRaises(ValueError):
            auth_unwrap(self.blob, key=KEY, expect="wots")
        with self.assertRaises(ValueError):
            auth_unwrap(self.blob, key=KEY, expect="merkle")

    def test_wrong_key_value_error(self):
        with self.assertRaises(ValueError):
            auth_unwrap(self.blob, key=OTHER_KEY)

    def test_empty_and_truncated_rejected(self):
        for size in (0, 8, 13, 14, 45, len(self.blob) - 1):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    auth_unwrap(self.blob[:size], key=KEY)

    def test_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            auth_unwrap(self.blob + b"\x00", key=KEY)

    def test_bad_magic_rejected(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        with self.assertRaises(ValueError):
            auth_unwrap(bytes(bad), key=KEY)

    def test_bad_version_rejected(self):
        bad = bytearray(self.blob)
        bad[8] = 2
        with self.assertRaises(ValueError):
            auth_unwrap(bytes(bad), key=KEY)

    def test_bad_scheme_identifier_rejected(self):
        for identifier in (0, 4, 255):
            with self.subTest(identifier=identifier):
                bad = bytearray(self.blob)
                bad[9] = identifier
                with self.assertRaises(ValueError):
                    auth_unwrap(bytes(bad), key=KEY)

    def test_bad_length_rejected(self):
        # Length larger than the actual payload.
        bad = bytearray(self.blob)
        bad[10:14] = (len(FIXED_PAYLOAD) + 1).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            auth_unwrap(bytes(bad), key=KEY)
        # Length smaller: declared body ends early, trailing bytes rejected.
        bad = bytearray(self.blob)
        bad[10:14] = (len(FIXED_PAYLOAD) - 1).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            auth_unwrap(bytes(bad), key=KEY)

    def test_bad_tag_rejected(self):
        bad = bytearray(self.blob)
        bad[-1] ^= 0x01
        with self.assertRaises(ValueError):
            auth_unwrap(bytes(bad), key=KEY)

    def test_modified_payload_with_recomputed_tag_rejected_by_payload_magic(self):
        # A forger without the key cannot recompute the tag; even someone who
        # has the key but swaps in a foreign-scheme payload is rejected once
        # the tag verifies, because the payload magic is checked afterwards.
        foreign = b"PQAWCP\0\0" + FIXED_PAYLOAD[8:]
        body = b"PQAAUTH\0" + bytes((1, 1)) + len(foreign).to_bytes(4, "big") + foreign
        forged = body + hmac.new(KEY, body, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            auth_unwrap(forged, key=KEY)

    def test_modified_body_invalidates_tag(self):
        for position in range(14):
            with self.subTest(position=position):
                bad = bytearray(self.blob)
                bad[position] ^= 0x01
                with self.assertRaises(ValueError):
                    auth_unwrap(bytes(bad), key=KEY)

    def test_header_tampering_not_accepted_with_fresh_tag(self):
        # Declaring a different scheme id with a fresh keyed tag is caught by
        # the payload-magic cross-check (tag verifies, magic does not).
        payload = FIXED_PAYLOAD
        body = b"PQAAUTH\0" + bytes((1, 2)) + len(payload).to_bytes(4, "big") + payload
        forged = body + hmac.new(KEY, body, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            auth_unwrap(forged, key=KEY)

    def test_valid_blob_still_unwraps(self):
        name, payload = auth_unwrap(self.blob, key=KEY)
        self.assertEqual((name, payload), ("lamport", FIXED_PAYLOAD))


class AuthCrossSchemeTest(unittest.TestCase):
    def test_every_real_checkpoint_seals_and_opens(self):
        for scheme, checkpoint, _ in checkpoints():
            with self.subTest(scheme=scheme):
                blob = auth_wrap(checkpoint, scheme=scheme, key=KEY)
                name, payload = auth_unwrap(blob, key=KEY, expect=scheme)
                self.assertEqual(name, scheme)
                self.assertEqual(payload, checkpoint)

    def test_cross_scheme_expect_checked_after_tag(self):
        # Valid envelope, wrong expect: ValueError, nothing returned.
        blob = auth_wrap(checkpoints()[0][1], scheme="lamport", key=KEY)
        for other in ("wots", "merkle"):
            with self.subTest(other=other):
                with self.assertRaises(ValueError):
                    auth_unwrap(blob, key=KEY, expect=other)


if __name__ == "__main__":
    unittest.main()

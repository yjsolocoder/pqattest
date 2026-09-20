import hashlib
import hmac
import unittest

from pqattest import (
    OneTimeSigner,
    auth_state_unwrap,
    auth_state_wrap,
    keygen,
)

KEY = b"shared-secret-key"


def checkpoint():
    return OneTimeSigner(keygen(bits=32)[0]).checkpoint()


def tagged(body: bytes, key: bytes = KEY) -> bytes:
    """Append a valid HMAC-SHA-256 tag for ``body``."""
    return body + hmac.new(key, body, hashlib.sha256).digest()


class TagFirstOrderingTest(unittest.TestCase):
    def setUp(self):
        self.checkpoint = checkpoint()
        self.blob = auth_state_wrap(
            self.checkpoint, scheme="lamport", key=KEY, generation=7
        )

    def test_shorter_than_tag_rejected(self):
        # No body at all, and even zero body bytes need 32 bytes of tag.
        for size in (0, 1, 21, 22, 31):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    auth_state_unwrap(b"\x00" * size, key=KEY)

    def test_thirty_two_bytes_of_garbage_is_tag_mismatch(self):
        # Enough bytes to split into body + 32-byte tag, but the tag cannot
        # check out: rejection must come from the tag, not from parsing.
        with self.assertRaisesRegex(ValueError, "tag"):
            auth_state_unwrap(b"\x00" * 32, key=KEY)

    def test_bad_tag_rejected_before_header_is_inspected(self):
        # The body claims a nonsense version and would fail parsing; the tag
        # is wrong too. Tag-first ordering means the reported failure is the
        # tag mismatch.
        body = bytearray(self.blob[:-32])
        body[8] = 99  # nonsense version
        bad = bytes(body) + b"\x00" * 32  # deliberately wrong tag
        with self.assertRaisesRegex(ValueError, "tag"):
            auth_state_unwrap(bad, key=KEY)

    def test_wrong_key_is_tag_mismatch_even_for_well_formed_blob(self):
        with self.assertRaisesRegex(ValueError, "tag"):
            auth_state_unwrap(self.blob, key=b"a-different-key")

    def test_valid_tag_but_short_body_rejected_as_truncated(self):
        # A correctly tagged body shorter than the 22-byte v2 header passes
        # authentication, then fails v2 parsing.
        blob = tagged(b"PQAAUTH\0\x02")
        with self.assertRaisesRegex(ValueError, "truncated"):
            auth_state_unwrap(blob, key=KEY)

    def test_valid_tag_but_bad_magic_rejected_after_tag(self):
        body = bytearray(self.blob[:-32])
        body[:8] = b"NOTAUTH!"
        blob = tagged(bytes(body))
        with self.assertRaisesRegex(ValueError, "magic"):
            auth_state_unwrap(blob, key=KEY)

    def test_valid_tag_but_bad_version_rejected_after_tag(self):
        body = bytearray(self.blob[:-32])
        body[8] = 3
        blob = tagged(bytes(body))
        with self.assertRaisesRegex(ValueError, "version"):
            auth_state_unwrap(blob, key=KEY)

    def test_v1_envelope_tag_passes_then_version_fails(self):
        # A v1 envelope uses the same HMAC-over-body tag construction, so its
        # tag validates; the v2 parser must then reject version 1.
        from pqattest import auth_wrap

        v1_blob = auth_wrap(self.checkpoint, scheme="lamport", key=KEY)
        body, tag = v1_blob[:-32], v1_blob[-32:]
        self.assertEqual(
            hmac.new(KEY, body, hashlib.sha256).digest(), tag
        )
        with self.assertRaisesRegex(ValueError, "version"):
            auth_state_unwrap(v1_blob, key=KEY)

    def test_valid_tag_with_length_extension_rejected_as_trailing(self):
        # Extra bytes inside the authenticated body but outside the declared
        # payload length: the tag is valid for the extended body, so parsing
        # must reject the surplus (not the tag).
        body = self.blob[:-32] + b"\x00"
        blob = tagged(body)
        with self.assertRaisesRegex(ValueError, "trailing"):
            auth_state_unwrap(blob, key=KEY)

    def test_payload_magic_and_floor_still_enforced_after_good_tag(self):
        scheme_id = 1  # lamport
        body = (
            b"PQAAUTH\0"
            + bytes((2, scheme_id))
            + (5).to_bytes(8, "big")
            + (32).to_bytes(4, "big")
            + b"\x00" * 32  # payload with no checkpoint magic
        )
        blob = tagged(body)
        # Payload magic fails even though the floor would pass.
        with self.assertRaisesRegex(ValueError, "magic"):
            auth_state_unwrap(blob, key=KEY, min_generation=0)
        # And the floor is still applied last to an otherwise valid blob.
        with self.assertRaisesRegex(ValueError, "minimum|below"):
            auth_state_unwrap(self.blob, key=KEY, min_generation=8)

    def test_valid_blob_still_round_trips(self):
        scheme, generation, payload = auth_state_unwrap(self.blob, key=KEY)
        self.assertEqual((scheme, generation), ("lamport", 7))
        self.assertEqual(payload, self.checkpoint)

    def test_bytearray_input_round_trips(self):
        scheme, generation, payload = auth_state_unwrap(
            bytearray(self.blob), key=bytearray(KEY)
        )
        self.assertEqual((scheme, generation), ("lamport", 7))
        self.assertEqual(payload, self.checkpoint)
        self.assertIsInstance(payload, bytes)


if __name__ == "__main__":
    unittest.main()

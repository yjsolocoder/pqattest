import unittest

from pqattest import (
    WOTSPrivateKey,
    WOTSPublicKey,
    wots_keygen,
    wots_sign,
    wots_signature_from_bytes,
    wots_signature_to_bytes,
    wots_verify,
)
from pqattest.wots import _params


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_keys(w=4, start=0):
    return wots_keygen(w=w, token_bytes=counter_tokens(start))


def chains_for(w):
    _, l1, l2 = _params(w)
    return l1 + l2


class KeyFormatTest(unittest.TestCase):
    def test_private_layout_and_length(self):
        for w in (4, 8):
            with self.subTest(w=w):
                private_key, _ = make_keys(w=w)
                blob = private_key.to_bytes()
                chains = chains_for(w)
                self.assertEqual(len(blob), 8 + 1 + 1 + 2 + chains * 32)
                self.assertEqual(blob[:8], b"PQAWPRV\0")
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(blob[9], w)
                self.assertEqual(int.from_bytes(blob[10:12], "big"), chains)
                self.assertEqual(blob[12:], b"".join(private_key.elements))

    def test_public_layout_and_length(self):
        for w in (4, 8):
            with self.subTest(w=w):
                _, public_key = make_keys(w=w)
                blob = public_key.to_bytes()
                chains = chains_for(w)
                self.assertEqual(len(blob), 8 + 1 + 1 + 2 + chains * 32)
                self.assertEqual(blob[:8], b"PQAWPUB\0")
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(blob[9], w)
                self.assertEqual(int.from_bytes(blob[10:12], "big"), chains)
                self.assertEqual(blob[12:], b"".join(public_key.elements))

    def test_to_bytes_returns_bytes(self):
        private_key, public_key = make_keys()
        self.assertIsInstance(private_key.to_bytes(), bytes)
        self.assertIsInstance(public_key.to_bytes(), bytes)

    def test_encoding_is_deterministic(self):
        private_key, public_key = make_keys()
        self.assertEqual(private_key.to_bytes(), private_key.to_bytes())
        self.assertEqual(public_key.to_bytes(), public_key.to_bytes())


class KeyRoundTripTest(unittest.TestCase):
    def test_round_trip_both_w(self):
        for w in (4, 8):
            with self.subTest(w=w):
                private_key, public_key = make_keys(w=w)
                restored_private = WOTSPrivateKey.from_bytes(private_key.to_bytes())
                restored_public = WOTSPublicKey.from_bytes(public_key.to_bytes())
                self.assertEqual(restored_private, private_key)
                self.assertEqual(restored_public, public_key)
                self.assertEqual(restored_private.to_bytes(), private_key.to_bytes())
                self.assertEqual(restored_public.to_bytes(), public_key.to_bytes())

    def test_restored_private_key_still_signs(self):
        for w in (4, 8):
            with self.subTest(w=w):
                private_key, public_key = make_keys(w=w)
                restored = WOTSPrivateKey.from_bytes(private_key.to_bytes())
                signature = wots_sign("position claim", restored)
                self.assertTrue(wots_verify("position claim", signature, public_key))

    def test_accepts_bytearray(self):
        private_key, public_key = make_keys()
        self.assertEqual(
            WOTSPrivateKey.from_bytes(bytearray(private_key.to_bytes())), private_key
        )
        self.assertEqual(
            WOTSPublicKey.from_bytes(bytearray(public_key.to_bytes())), public_key
        )


class KeyValidationTest(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = make_keys()
        self.private_blob = self.private_key.to_bytes()
        self.public_blob = self.public_key.to_bytes()

    def test_non_bytes_types_raise_type_error(self):
        for bad in (None, 42, 4.5, "key", [self.private_blob], (self.private_blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    WOTSPrivateKey.from_bytes(bad)
                with self.assertRaises(TypeError):
                    WOTSPublicKey.from_bytes(bad)

    def test_truncated_and_empty_rejected(self):
        for cut in (0, 7, 11, 12, len(self.private_blob) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    WOTSPrivateKey.from_bytes(self.private_blob[:cut])
                with self.assertRaises(ValueError):
                    WOTSPublicKey.from_bytes(self.public_blob[:cut])

    def test_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            WOTSPrivateKey.from_bytes(self.private_blob + b"\x00")
        with self.assertRaises(ValueError):
            WOTSPublicKey.from_bytes(self.public_blob + b"\x00")

    def test_bad_magic_rejected(self):
        for blob, from_bytes in (
            (self.private_blob, WOTSPrivateKey.from_bytes),
            (self.public_blob, WOTSPublicKey.from_bytes),
        ):
            bad = bytearray(blob)
            bad[0] ^= 0x01
            with self.assertRaises(ValueError):
                from_bytes(bytes(bad))

    def test_cross_magic_rejected(self):
        with self.assertRaises(ValueError):
            WOTSPrivateKey.from_bytes(self.public_blob)
        with self.assertRaises(ValueError):
            WOTSPublicKey.from_bytes(self.private_blob)

    def test_bad_version_rejected(self):
        for version in (0, 2, 255):
            with self.subTest(version=version):
                bad = bytearray(self.private_blob)
                bad[8] = version
                with self.assertRaises(ValueError):
                    WOTSPrivateKey.from_bytes(bytes(bad))

    def test_bad_w_rejected(self):
        for bad_w in (0, 2, 16, 255):
            with self.subTest(bad_w=bad_w):
                bad = bytearray(self.private_blob)
                bad[9] = bad_w
                with self.assertRaises(ValueError):
                    WOTSPrivateKey.from_bytes(bytes(bad))

    def test_bad_element_count_rejected(self):
        chains = chains_for(self.private_key.w)
        for count in (0, chains - 1, chains + 1, 34):
            with self.subTest(count=count):
                bad = bytearray(self.private_blob)
                bad[10:12] = count.to_bytes(2, "big")
                with self.assertRaises(ValueError):
                    WOTSPrivateKey.from_bytes(bytes(bad))

    def test_to_bytes_on_foreign_object_raises_type_error(self):
        for bad in (None, 42, "key", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    WOTSPrivateKey.to_bytes(bad)
                with self.assertRaises(TypeError):
                    WOTSPublicKey.to_bytes(bad)


class SignatureFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for w in (4, 8):
            with self.subTest(w=w):
                private_key, _ = make_keys(w=w)
                signature = wots_sign("message", private_key)
                blob = wots_signature_to_bytes(signature, w=w)
                chains = chains_for(w)
                self.assertEqual(len(blob), 8 + 1 + 1 + 2 + chains * 32)
                self.assertEqual(blob[:8], b"PQAWSIG\0")
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(blob[9], w)
                self.assertEqual(int.from_bytes(blob[10:12], "big"), chains)
                self.assertEqual(blob[12:], b"".join(signature))

    def test_to_bytes_returns_bytes(self):
        private_key, _ = make_keys()
        signature = wots_sign("m", private_key)
        self.assertIsInstance(wots_signature_to_bytes(signature, w=4), bytes)

    def test_encoding_is_deterministic(self):
        private_key, _ = make_keys()
        signature = wots_sign("m", private_key)
        self.assertEqual(
            wots_signature_to_bytes(signature, w=4),
            wots_signature_to_bytes(signature, w=4),
        )


class SignatureRoundTripTest(unittest.TestCase):
    def test_round_trip_both_w_and_still_verifies(self):
        for w in (4, 8):
            with self.subTest(w=w):
                private_key, public_key = make_keys(w=w)
                signature = wots_sign("position claim", private_key)
                blob = wots_signature_to_bytes(signature, w=w)
                restored_w, elements = wots_signature_from_bytes(blob)
                self.assertEqual(restored_w, w)
                self.assertEqual(elements, signature)
                self.assertIsInstance(elements, tuple)
                for element in elements:
                    self.assertIsInstance(element, bytes)
                self.assertTrue(wots_verify("position claim", elements, public_key))

    def test_accepts_bytearray(self):
        private_key, _ = make_keys()
        signature = wots_sign("m", private_key)
        blob = wots_signature_to_bytes(signature, w=4)
        self.assertEqual(wots_signature_from_bytes(bytearray(blob)), (4, signature))


class SignatureValidationTest(unittest.TestCase):
    def setUp(self):
        self.private_key, _ = make_keys()
        self.signature = wots_sign("message", self.private_key)
        self.blob = wots_signature_to_bytes(self.signature, w=4)

    def test_non_tuple_signature_raises_type_error(self):
        for bad in (None, 42, 4.5, "sig", list(self.signature), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    wots_signature_to_bytes(bad, w=4)

    def test_non_bytes_member_raises_type_error(self):
        for member in (bytearray(b"\x00" * 32), 42, None, object()):
            with self.subTest(bad=type(member).__name__):
                signature = list(self.signature)
                signature[0] = member
                with self.assertRaises(TypeError):
                    wots_signature_to_bytes(tuple(signature), w=4)

    def test_bad_w_raises_value_error(self):
        for bad_w in (0, 2, 16, 255, None, True, 4.0, "4"):
            with self.subTest(bad_w=bad_w):
                with self.assertRaises(ValueError):
                    wots_signature_to_bytes(self.signature, w=bad_w)

    def test_count_mismatch_raises_value_error(self):
        with self.assertRaises(ValueError):
            wots_signature_to_bytes(self.signature, w=8)
        with self.assertRaises(ValueError):
            wots_signature_to_bytes(self.signature[:-1], w=4)
        with self.assertRaises(ValueError):
            wots_signature_to_bytes(self.signature + (b"\x00" * 32,), w=4)
        with self.assertRaises(ValueError):
            wots_signature_to_bytes((), w=4)

    def test_bad_member_length_raises_value_error(self):
        for member in (b"\x00" * 31, b"\x00" * 33, b""):
            with self.subTest(length=len(member)):
                signature = list(self.signature)
                signature[5] = member
                with self.assertRaises(ValueError):
                    wots_signature_to_bytes(tuple(signature), w=4)

    def test_non_bytes_data_raises_type_error(self):
        for bad in (None, 42, 4.5, "sig", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    wots_signature_from_bytes(bad)

    def test_truncated_and_empty_rejected(self):
        for cut in (0, 7, 11, 12, len(self.blob) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError):
                    wots_signature_from_bytes(self.blob[:cut])

    def test_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            wots_signature_from_bytes(self.blob + b"\x00")

    def test_bad_magic_rejected(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        with self.assertRaises(ValueError):
            wots_signature_from_bytes(bytes(bad))

    def test_key_magic_rejected(self):
        private_key, public_key = make_keys()
        with self.assertRaises(ValueError):
            wots_signature_from_bytes(private_key.to_bytes())
        with self.assertRaises(ValueError):
            wots_signature_from_bytes(public_key.to_bytes())

    def test_bad_version_rejected(self):
        for version in (0, 2, 255):
            with self.subTest(version=version):
                bad = bytearray(self.blob)
                bad[8] = version
                with self.assertRaises(ValueError):
                    wots_signature_from_bytes(bytes(bad))

    def test_bad_w_rejected(self):
        for bad_w in (0, 2, 16, 255):
            with self.subTest(bad_w=bad_w):
                bad = bytearray(self.blob)
                bad[9] = bad_w
                with self.assertRaises(ValueError):
                    wots_signature_from_bytes(bytes(bad))

    def test_bad_element_count_rejected(self):
        for count in (0, 34, 66, 68):
            with self.subTest(count=count):
                bad = bytearray(self.blob)
                bad[10:12] = count.to_bytes(2, "big")
                with self.assertRaises(ValueError):
                    wots_signature_from_bytes(bytes(bad))

    def test_valid_signature_still_accepted(self):
        # Guard against the corruption tests making the helper too strict.
        w, elements = wots_signature_from_bytes(self.blob)
        self.assertEqual(w, 4)
        self.assertEqual(elements, self.signature)


if __name__ == "__main__":
    unittest.main()

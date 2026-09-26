import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    MerkleSigner,
    Params,
    merkle_verify,
    profile,
    recommend,
)


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


class ProfileTest(unittest.TestCase):
    def test_lamport(self):
        params = profile("lamport")
        self.assertEqual(
            params,
            Params(
                scheme="lamport",
                w=None,
                height=None,
                capacity=1,
                elements=0,
                sig_bytes=8192,
                path_bytes=0,
                steps=0,
            ),
        )

    def test_lamport_rejects_extra_parameters(self):
        for kwargs in ({"w": 4}, {"height": 2}, {"w": 4, "height": 2}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    profile("lamport", **kwargs)

    def test_wots(self):
        self.assertEqual(
            profile("wots", w=4),
            Params("wots", 4, None, 1, 67, 67 * 32, 0, 67 * 15),
        )
        self.assertEqual(
            profile("wots", w=8),
            Params("wots", 8, None, 1, 34, 34 * 32, 0, 34 * 255),
        )

    def test_wots_rejects_missing_and_extra_parameters(self):
        with self.assertRaises(ValueError):
            profile("wots")
        with self.assertRaises(ValueError):
            profile("wots", w=4, height=2)
        for bad_w in (2, 16, 0, 4.0, True, "4"):
            with self.subTest(bad_w=bad_w):
                with self.assertRaises(ValueError):
                    profile("wots", w=bad_w)

    def test_merkle(self):
        self.assertEqual(
            profile("merkle", w=4, height=4),
            Params("merkle", 4, 4, 16, 67, (67 + 4) * 32, 4 * 32, 67 * 15),
        )
        self.assertEqual(
            profile("merkle", w=8, height=1),
            Params("merkle", 8, 1, 2, 34, (34 + 1) * 32, 32, 34 * 255),
        )

    def test_merkle_rejects_missing_and_invalid_parameters(self):
        with self.assertRaises(ValueError):
            profile("merkle")
        with self.assertRaises(ValueError):
            profile("merkle", w=4)
        with self.assertRaises(ValueError):
            profile("merkle", height=2)
        for bad_height in (0, 9, -1, 2.0, True, "2"):
            with self.subTest(bad_height=bad_height):
                with self.assertRaises(ValueError):
                    profile("merkle", w=4, height=bad_height)

    def test_unknown_scheme_rejected(self):
        for bad_scheme in ("lamport2", "", None, 4):
            with self.subTest(bad_scheme=bad_scheme):
                with self.assertRaises(ValueError):
                    profile(bad_scheme)

    def test_params_frozen(self):
        params = profile("lamport")
        with self.assertRaises(FrozenInstanceError):
            params.scheme = "wots"


class RecommendTest(unittest.TestCase):
    def test_size_prefers_w8(self):
        params = recommend(16)
        self.assertEqual(params, profile("merkle", w=8, height=4))

    def test_speed_prefers_w4(self):
        params = recommend(16, prefer="speed")
        self.assertEqual(params, profile("merkle", w=4, height=4))

    def test_minimal_covering_height(self):
        cases = {1: 1, 2: 1, 3: 2, 4: 2, 5: 3, 16: 4, 17: 5, 255: 8, 256: 8}
        for capacity, height in cases.items():
            with self.subTest(capacity=capacity):
                params = recommend(capacity)
                self.assertEqual(params.height, height)
                self.assertGreaterEqual(params.capacity, capacity)

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend(bad)

    def test_invalid_prefer_rejected(self):
        for bad in ("fast", "SIZE", None, 8):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend(4, prefer=bad)


class MerkleVerifyHardeningTest(unittest.TestCase):
    def setUp(self):
        self.signer = MerkleSigner(height=4, w=4, token_bytes=counter_tokens())
        self.public_key = self.signer.public_key
        self.signature = self.signer.sign(b"message")

    def corrupt(self, obj, **fields):
        for name, value in fields.items():
            object.__setattr__(obj, name, value)
        return obj

    def test_valid_signature_still_verifies(self):
        self.assertTrue(merkle_verify(b"message", self.signature, self.public_key))

    def test_wrong_public_key_type_still_raises(self):
        with self.assertRaises(TypeError):
            merkle_verify(b"message", self.signature, object())

    def test_corrupt_public_key_returns_false(self):
        cases = [
            {"w": 3},
            {"w": "4"},
            {"w": None},
            {"height": 0},
            {"height": 9},
            {"height": 2.0},
            {"root": b"short"},
            {"root": "not-bytes"},
            {"root": None},
        ]
        for fields in cases:
            with self.subTest(fields=fields):
                key = self.corrupt(
                    type(self.public_key)(
                        w=self.public_key.w,
                        height=self.public_key.height,
                        root=self.public_key.root,
                    ),
                    **fields,
                )
                self.assertFalse(merkle_verify(b"message", self.signature, key))

    def test_missing_public_key_field_returns_false(self):
        key = type(self.public_key)(
            w=self.public_key.w,
            height=self.public_key.height,
            root=self.public_key.root,
        )
        object.__delattr__(key, "root")
        self.assertFalse(merkle_verify(b"message", self.signature, key))

    def test_corrupt_signature_returns_false(self):
        fresh = lambda: self.signer.sign(b"message")
        cases = [
            {"index": -1},
            {"index": True},
            {"index": 1.5},
            {"index": "0"},
            {"wots_signature": list(self.signature.wots_signature)},
            {"wots_signature": self.signature.wots_signature + (b"x",)},
            {"wots_signature": (b"short",) * len(self.signature.wots_signature)},
            {"auth_path": list(self.signature.auth_path)},
            {"auth_path": self.signature.auth_path[:-1]},
            {"auth_path": (b"short",) * len(self.signature.auth_path)},
        ]
        for fields in cases:
            with self.subTest(fields=fields):
                signature = self.corrupt(fresh(), **fields)
                self.assertFalse(merkle_verify(b"message", signature, self.public_key))

    def test_missing_signature_field_returns_false(self):
        signature = self.signer.sign(b"message")
        object.__delattr__(signature, "index")
        self.assertFalse(merkle_verify(b"message", signature, self.public_key))


if __name__ == "__main__":
    unittest.main()

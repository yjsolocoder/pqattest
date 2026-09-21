import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    MerkleProof,
    MerkleBatchProof,
    MerkleSigner,
    MerkleStorageProfile,
    auth_state_wrap,
    auth_wrap,
    merkle_storage_profile,
    merkle_transport_profile,
    multiproof_encode,
)


def _chain_count(w):
    return 67 if w == 4 else 34


def _expected_storage(w, height):
    n = _chain_count(w)
    leaf_count = 1 << height
    signature = 16 + 32 * (n + height)
    checkpoint = 81 + 32 * leaf_count * n
    return MerkleStorageProfile(
        w,
        height,
        leaf_count,
        signature,
        signature + 60,
        checkpoint,
        checkpoint + 46,
        checkpoint + 54,
    )


class MerkleStorageProfileTest(unittest.TestCase):
    def test_values_for_both_w_and_every_height(self):
        for w in (4, 8):
            for height in range(1, 9):
                with self.subTest(w=w, height=height):
                    self.assertEqual(
                        merkle_storage_profile(w, height),
                        _expected_storage(w, height),
                    )

    def test_positional_fields_in_order(self):
        profile = merkle_storage_profile(8, 2)
        self.assertEqual(
            (
                profile.w,
                profile.height,
                profile.leaf_count,
                profile.signature_wire_bytes,
                profile.proof_wire_bytes,
                profile.checkpoint_bytes,
                profile.auth_v1_bytes,
                profile.auth_v2_bytes,
            ),
            (8, 2, 4, 16 + 32 * (34 + 2), 16 + 32 * 36 + 60,
             81 + 32 * 4 * 34, 81 + 32 * 4 * 34 + 46, 81 + 32 * 4 * 34 + 54),
        )

    def test_sizes_match_actual_encodings(self):
        for w, height in ((4, 1), (8, 2)):
            with self.subTest(w=w, height=height):
                profile = merkle_storage_profile(w, height)
                signer = MerkleSigner(w=w, height=height)
                signature = signer.sign(b"message")
                self.assertEqual(
                    len(signature.to_bytes(signer.public_key)),
                    profile.signature_wire_bytes,
                )
                proof = MerkleProof(
                    public_key=signer.public_key, signature=signature
                ).to_bytes()
                self.assertEqual(len(proof), profile.proof_wire_bytes)
                checkpoint = signer.checkpoint()
                self.assertEqual(len(checkpoint), profile.checkpoint_bytes)
                self.assertEqual(
                    len(auth_wrap(checkpoint, scheme="merkle", key=b"key")),
                    profile.auth_v1_bytes,
                )
                self.assertEqual(
                    len(
                        auth_state_wrap(
                            checkpoint,
                            scheme="merkle",
                            key=b"key",
                            generation=3,
                        )
                    ),
                    profile.auth_v2_bytes,
                )

    def test_frozen_positional_and_value_equality(self):
        first = merkle_storage_profile(4, 4)
        second = merkle_storage_profile(4, 4)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertIsNot(first, second)
        with self.assertRaises(FrozenInstanceError):
            first.w = 8

    def test_rejects_bad_w(self):
        for bad in (None, "4", 4.0, 2, 16, 0, True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_storage_profile(bad, 4)

    def test_rejects_bad_height(self):
        for bad in (None, "4", 4.0, 0, 9, -1, True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_storage_profile(4, bad)


def _canonical_node_count(indices, height):
    current = set(indices)
    count = 0
    for _ in range(height):
        count += sum(1 for index in current if (index ^ 1) not in current)
        current = {index >> 1 for index in current}
    return count


class MerkleTransportProfileTest(unittest.TestCase):
    def test_single_leaf(self):
        for w, n in ((4, 67), (8, 34)):
            height = 3
            signature = 16 + 32 * (n + height)
            m, batch, multiproof = merkle_transport_profile(w, height, (0,))
            self.assertEqual(m, height)
            self.assertEqual(batch, 58 + 4 + signature)
            self.assertEqual(
                multiproof, 60 + (4 + 32 * n) + 35 * height
            )

    def test_formula_matches_actual_encodings(self):
        w, height = 4, 3
        signer = MerkleSigner(w=w, height=height)
        signatures = signer.sign_batch(tuple(f"m{i}".encode() for i in range(8)))
        cases = (
            (0,),
            (7,),
            (0, 1),
            (2, 3),
            (1, 3, 6),
            (0, 2, 4, 6),
            (0, 1, 2, 3, 4, 5, 6, 7),
        )
        for indices in cases:
            with self.subTest(indices=indices):
                chosen = tuple(signatures[i] for i in indices)
                m, batch, multiproof = merkle_transport_profile(w, height, indices)
                self.assertEqual(m, _canonical_node_count(indices, height))
                self.assertEqual(
                    len(
                        MerkleBatchProof(
                            public_key=signer.public_key, signatures=chosen
                        ).to_bytes()
                    ),
                    batch,
                )
                self.assertEqual(
                    len(multiproof_encode(signer.public_key, chosen)),
                    multiproof,
                )
                k = len(indices)
                signature = 16 + 32 * (67 + height)
                self.assertEqual(batch, 58 + k * (4 + signature))
                self.assertEqual(
                    multiproof, 60 + k * (4 + 32 * 67) + 35 * m
                )

    def test_shared_siblings_are_deduplicated(self):
        # An adjacent pair needs no level-0 sibling; only the two upper
        # levels carry a node, so m = 2 for a height-3 tree.
        m, _, _ = merkle_transport_profile(4, 3, (0, 1))
        self.assertEqual(m, 2)
        # The whole tree carries no nodes at all.
        m, _, multiproof = merkle_transport_profile(8, 2, (0, 1, 2, 3))
        self.assertEqual(m, 0)
        self.assertEqual(multiproof, 60 + 4 * (4 + 32 * 34))

    def test_returns_tuple_of_ints(self):
        result = merkle_transport_profile(8, 5, (1, 4, 9))
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)
        self.assertTrue(all(isinstance(value, int) for value in result))

    def test_rejects_container_type(self):
        for bad in ([0], {0}, b"\x00", "0"):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_transport_profile(4, 4, bad)

    def test_rejects_member_type(self):
        for bad in ((0, "1"), (0, 1.0), (None,)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_transport_profile(4, 4, bad)

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            merkle_transport_profile(4, 4, ())

    def test_rejects_boolean_members(self):
        for bad in ((True,), (False,), (0, True)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_profile(4, 4, bad)

    def test_rejects_out_of_range(self):
        for bad in ((-1,), (16,), (0, 16)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_profile(4, 4, bad)

    def test_rejects_non_increasing(self):
        for bad in ((1, 0), (0, 0), (2, 1, 3), (3, 2, 1)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_profile(4, 4, bad)

    def test_rejects_bad_w_or_height(self):
        with self.assertRaises(ValueError):
            merkle_transport_profile(2, 4, (0,))
        with self.assertRaises(ValueError):
            merkle_transport_profile(4, 9, (0,))
        with self.assertRaises(ValueError):
            merkle_transport_profile(4, 0, (0,))


if __name__ == "__main__":
    unittest.main()

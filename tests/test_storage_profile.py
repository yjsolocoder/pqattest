import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    MerkleBatchProof,
    MerkleProof,
    MerkleSigner,
    MerkleStorageProfile,
    auth_state_wrap,
    auth_wrap,
    merkle_storage_profile,
    merkle_transport_profile,
    multiproof_encode,
)


class MerkleStorageProfileTest(unittest.TestCase):
    def test_field_values_w4(self):
        # n = 67 for w=4
        self.assertEqual(
            merkle_storage_profile(4, 4),
            MerkleStorageProfile(
                w=4,
                height=4,
                leaf_count=16,
                signature_wire_bytes=16 + 32 * (67 + 4),
                proof_wire_bytes=16 + 32 * (67 + 4) + 60,
                checkpoint_bytes=81 + 32 * 16 * 67,
                auth_v1_bytes=81 + 32 * 16 * 67 + 46,
                auth_v2_bytes=81 + 32 * 16 * 67 + 54,
            ),
        )

    def test_field_values_w8_height1(self):
        # n = 34 for w=8, L = 2 for height 1
        self.assertEqual(
            merkle_storage_profile(8, 1),
            MerkleStorageProfile(
                w=8,
                height=1,
                leaf_count=2,
                signature_wire_bytes=16 + 32 * (34 + 1),
                proof_wire_bytes=16 + 32 * (34 + 1) + 60,
                checkpoint_bytes=81 + 32 * 2 * 34,
                auth_v1_bytes=81 + 32 * 2 * 34 + 46,
                auth_v2_bytes=81 + 32 * 2 * 34 + 54,
            ),
        )

    def test_all_valid_combinations(self):
        for w, n in ((4, 67), (8, 34)):
            for height in range(1, 9):
                profile = merkle_storage_profile(w, height)
                leaf_count = 2**height
                signature = 16 + 32 * (n + height)
                checkpoint = 81 + 32 * leaf_count * n
                self.assertEqual(profile.w, w)
                self.assertEqual(profile.height, height)
                self.assertEqual(profile.leaf_count, leaf_count)
                self.assertEqual(profile.signature_wire_bytes, signature)
                self.assertEqual(profile.proof_wire_bytes, signature + 60)
                self.assertEqual(profile.checkpoint_bytes, checkpoint)
                self.assertEqual(profile.auth_v1_bytes, checkpoint + 46)
                self.assertEqual(profile.auth_v2_bytes, checkpoint + 54)

    def test_sizes_match_real_blobs(self):
        for w, height in ((4, 4), (8, 1), (4, 8), (8, 7)):
            with self.subTest(w=w, height=height):
                signer = MerkleSigner(w=w, height=height)
                signature = signer.sign(b"message")
                profile = merkle_storage_profile(w, height)
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
                            checkpoint, scheme="merkle", key=b"key", generation=0
                        )
                    ),
                    profile.auth_v2_bytes,
                )

    def test_invalid_w(self):
        for bad_w in (2, 16, 0, -4, 4.0, True, "4", None):
            with self.subTest(bad_w=bad_w):
                with self.assertRaises(ValueError):
                    merkle_storage_profile(bad_w, 4)

    def test_invalid_height(self):
        for bad_height in (0, 9, -1, 2.0, True, "2", None):
            with self.subTest(bad_height=bad_height):
                with self.assertRaises(ValueError):
                    merkle_storage_profile(4, bad_height)

    def test_frozen_positional_and_value_equality(self):
        first = merkle_storage_profile(4, 3)
        second = merkle_storage_profile(4, 3)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(
            MerkleStorageProfile(4, 3, 8, 100, 160, 200, 246, 254),
            MerkleStorageProfile(
                w=4,
                height=3,
                leaf_count=8,
                signature_wire_bytes=100,
                proof_wire_bytes=160,
                checkpoint_bytes=200,
                auth_v1_bytes=246,
                auth_v2_bytes=254,
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            first.height = 5  # type: ignore[misc]

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        merkle_storage_profile(4, 2)
        self.assertEqual(signer.next_index, 0)


class MerkleTransportProfileTest(unittest.TestCase):
    def test_single_leaf(self):
        # height 3, one leaf: one outside sibling at every level -> m = 3
        self.assertEqual(
            merkle_transport_profile(4, 3, (0,)),
            (
                3,
                58 + 1 * (4 + 16 + 32 * (67 + 3)),
                60 + 1 * (4 + 32 * 67) + 35 * 3,
            ),
        )

    def test_all_leaves_have_no_external_siblings(self):
        node_count, batch_bytes, multi_bytes = merkle_transport_profile(
            8, 3, tuple(range(8))
        )
        self.assertEqual(node_count, 0)
        self.assertEqual(batch_bytes, 58 + 8 * (4 + 16 + 32 * (34 + 3)))
        self.assertEqual(multi_bytes, 60 + 8 * (4 + 32 * 34))

    def test_sizes_match_real_blobs(self):
        for w, height, take in ((4, 4, 3), (8, 1, 2), (4, 8, 3), (8, 7, 1)):
            with self.subTest(w=w, height=height):
                signer = MerkleSigner(w=w, height=height)
                signatures = tuple(signer.sign(b"m%d" % i) for i in range(take))
                indices = tuple(signature.index for signature in signatures)
                node_count, batch_bytes, multi_bytes = merkle_transport_profile(
                    w, height, indices
                )
                batch = MerkleBatchProof(
                    public_key=signer.public_key, signatures=signatures
                ).to_bytes()
                self.assertEqual(len(batch), batch_bytes)
                multi = multiproof_encode(signer.public_key, signatures)
                self.assertEqual(len(multi), multi_bytes)
                # the multiproof carries exactly one 35-byte node per coordinate
                self.assertEqual(
                    node_count, (len(multi) - (60 + take * (4 + 32 * (67 if w == 4 else 34)))) // 35
                )

    def test_node_counts_exhaustive_height_three(self):
        import itertools

        for size in range(1, 9):
            for combo in itertools.combinations(range(8), size):
                with self.subTest(combo=combo):
                    node_count, _, _ = merkle_transport_profile(8, 3, combo)
                    current = set(combo)
                    expected = 0
                    for _ in range(3):
                        expected += sum(
                            1 for index in current if (index ^ 1) not in current
                        )
                        current = {index >> 1 for index in current}
                    self.assertEqual(node_count, expected)

    def test_container_type_error(self):
        for bad_container in ([0, 1], {0, 1}, "ab", None, 7, range(2)):
            with self.subTest(bad_container=bad_container):
                with self.assertRaises(TypeError):
                    merkle_transport_profile(4, 3, bad_container)

    def test_member_type_error(self):
        for bad_member in ((0, "1"), (0, 1.0), (0, None), (0, object())):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(TypeError):
                    merkle_transport_profile(4, 3, bad_member)

    def test_value_errors(self):
        # empty, booleans, out of range, duplicates and non-increasing
        for bad_indices in (
            (),
            (True,),
            (0, False),
            (0, 8),
            (-1, 0),
            (7, 7),
            (2, 1),
            (1, 0, 2),
        ):
            with self.subTest(bad_indices=bad_indices):
                with self.assertRaises(ValueError):
                    merkle_transport_profile(4, 3, bad_indices)

    def test_invalid_w_and_height(self):
        for bad_w, bad_height in ((3, 3), (4, 0), (4, 9), (True, 3)):
            with self.subTest(bad_w=bad_w, bad_height=bad_height):
                with self.assertRaises(ValueError):
                    merkle_transport_profile(bad_w, bad_height, (0,))

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        merkle_transport_profile(4, 2, (0, 1))
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

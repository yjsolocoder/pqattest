import unittest

from pqattest import (
    MerkleSigner,
    MerkleStorageProfile,
    merkle_storage_profile,
    recommend_merkle_deployment,
)


class RecommendMerkleDeploymentTest(unittest.TestCase):
    def test_size_picks_shortest_signature(self):
        # w=8 always has the shortest signature wire; smallest covering height
        self.assertEqual(
            recommend_merkle_deployment(16, (None, None, None, 9000)),
            merkle_storage_profile(8, 4),
        )

    def test_speed_picks_fewest_steps(self):
        # w=4 has 1005 chain steps vs 8670 for w=8
        self.assertEqual(
            recommend_merkle_deployment(16, (None, None, None, 9000), prefer="speed"),
            merkle_storage_profile(4, 4),
        )

    def test_returns_storage_profile_instance(self):
        result = recommend_merkle_deployment(1, (None, 2000, None, None))
        self.assertIsInstance(result, MerkleStorageProfile)
        self.assertEqual(result, merkle_storage_profile(result.w, result.height))

    def test_capacity_forces_height(self):
        # 100 signatures need height 7; size prefer keeps w=8
        self.assertEqual(
            recommend_merkle_deployment(100, (None, None, None, 9000)),
            merkle_storage_profile(8, 7),
        )

    def test_checkpoint_budget_excludes_candidates(self):
        # height-7 checkpoints: w=8 -> 139345 bytes, w=4 -> 274513 bytes;
        # a 200000 limit leaves only w=8 even under speed prefer
        self.assertEqual(
            recommend_merkle_deployment(
                100, (200000, None, None, None), prefer="speed"
            ),
            merkle_storage_profile(8, 7),
        )

    def test_signature_budget_excludes_w4(self):
        # w=4 height-1 signature is 16+32*68 = 2192 bytes; w=8 is 1136
        self.assertEqual(
            recommend_merkle_deployment(2, (None, 2000, None, None), prefer="speed"),
            merkle_storage_profile(8, 1),
        )

    def test_proof_budget_is_checked(self):
        # proof wire = signature wire + 60; w=8 height-1 proof is 1196 bytes
        self.assertEqual(
            recommend_merkle_deployment(2, (None, None, 1200, None)),
            merkle_storage_profile(8, 1),
        )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment(2, (None, None, 1196 - 1, None))

    def test_steps_budget_excludes_w8(self):
        # w=8 needs 8670 steps; a 2000-step budget leaves only w=4
        self.assertEqual(
            recommend_merkle_deployment(4, (None, None, None, 2000)),
            merkle_storage_profile(4, 2),
        )

    def test_exact_limits_are_feasible(self):
        profile = merkle_storage_profile(8, 4)
        budgets = (
            profile.checkpoint_bytes,
            profile.signature_wire_bytes,
            profile.proof_wire_bytes,
            8670,
        )
        self.assertEqual(recommend_merkle_deployment(16, budgets), profile)

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_merkle_deployment(256, (None, 1, None, None))
        with self.assertRaises(ValueError):
            # capacity 256 forces height 8; no checkpoint fits in 1000 bytes
            recommend_merkle_deployment(256, (1000, None, None, None))

    def test_all_capacity_values_have_a_feasible_size_choice(self):
        for capacity in range(1, 257):
            with self.subTest(capacity=capacity):
                result = recommend_merkle_deployment(
                    capacity, (None, None, None, 8670)
                )
                self.assertGreaterEqual(result.leaf_count, capacity)

    def test_non_tuple_budgets_raise_type_error(self):
        for bad in ([None, None, None, 1], {1, 2}, "xxxx", None, 7):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_deployment(4, bad)

    def test_wrong_budget_length_raises_value_error(self):
        for bad in ((), (None,), (None, None, None), (None,) * 5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment(4, bad)

    def test_invalid_budget_members_raise_value_error(self):
        for bad_member in (0, -1, True, False, 1.5, "100", b"x", object()):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment(4, (None, bad_member, None, None))

    def test_all_none_budgets_raise_value_error(self):
        with self.assertRaises(ValueError):
            recommend_merkle_deployment(4, (None, None, None, None))

    def test_invalid_capacity_raises_value_error(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment(bad, (None, None, None, 1))

    def test_invalid_prefer_raises_value_error(self):
        for bad in ("fast", "SIZE", None, 8):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment(4, (None, None, None, 1), prefer=bad)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        recommend_merkle_deployment(4, (None, None, None, 2000))
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

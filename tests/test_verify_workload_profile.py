import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    MerkleVerifyProfile,
    MerkleVerifyWorkloadProfile,
    merkle_verify_profile,
    merkle_verify_workload_profile,
)


class MerkleVerifyWorkloadProfileTest(unittest.TestCase):
    def test_mixed_modes_counts(self):
        # Groups (0, 1, 6) twice (once batch, once multi) plus single (5,).
        profile = merkle_verify_workload_profile(
            4, 3, ((0, 1, 6), (0, 1, 6), (5,)),
            ("batch", "multiproof", "multiproof"),
        )
        self.assertEqual(profile.w, 4)
        self.assertEqual(profile.height, 3)
        self.assertEqual(
            profile.costs,
            (
                ("batch", 3 * 67 * 15, 3, 9, 3 * 67 * 15 + 3 + 9),
                ("multiproof", 3 * 67 * 15, 3, 5, 3 * 67 * 15 + 3 + 5),
                ("multiproof", 67 * 15, 1, 3, 67 * 15 + 1 + 3),
            ),
        )
        # Repeated group is billed separately; total is the grand sum.
        self.assertEqual(
            profile.total,
            (3 * 67 * 15 + 3 + 9) + (3 * 67 * 15 + 3 + 5) + (67 * 15 + 1 + 3),
        )
        self.assertEqual(profile.total, sum(cost[4] for cost in profile.costs))

    def test_w8_chain_steps(self):
        profile = merkle_verify_workload_profile(
            8, 1, ((0,), (1,)), ("batch", "multiproof")
        )
        self.assertEqual(
            profile.costs,
            (
                ("batch", 34 * 255, 1, 1, 34 * 255 + 1 + 1),
                ("multiproof", 34 * 255, 1, 1, 34 * 255 + 1 + 1),
            ),
        )
        self.assertEqual(profile.total, 2 * (34 * 255 + 1 + 1))

    def test_each_group_reuses_single_group_profile(self):
        groups = ((0, 1), (3, 5), (0, 1, 6), (7,))
        modes = ("batch", "multiproof", "multiproof", "batch")
        for w in (4, 8):
            for height in range(1, 9):
                leaf_count = 1 << height
                if any(index >= leaf_count for group in groups for index in group):
                    continue
                profile = merkle_verify_workload_profile(w, height, groups, modes)
                expected_total = 0
                for position, (mode, _wots, leaf, internal, group_total) in enumerate(
                    profile.costs
                ):
                    group = groups[position]
                    single = merkle_verify_profile(w, height, group)
                    self.assertEqual(mode, modes[position])
                    self.assertEqual(_wots, single.wots)
                    self.assertEqual(leaf, single.leaf)
                    if mode == "batch":
                        self.assertEqual(internal, single.batch)
                    else:
                        self.assertEqual(internal, single.multi)
                    self.assertEqual(group_total, single.wots + single.leaf + internal)
                    expected_total += group_total
                self.assertEqual(profile.total, expected_total)

    def test_single_group_all_modes(self):
        batch = merkle_verify_workload_profile(4, 3, ((0, 1, 6),), ("batch",))
        multi = merkle_verify_workload_profile(4, 3, ((0, 1, 6),), ("multiproof",))
        single = merkle_verify_profile(4, 3, (0, 1, 6))
        self.assertEqual(
            batch.costs,
            (("batch", single.wots, single.leaf, single.batch,
              single.wots + single.leaf + single.batch),),
        )
        self.assertEqual(
            multi.costs,
            (("multiproof", single.wots, single.leaf, single.multi,
              single.wots + single.leaf + single.multi),),
        )
        self.assertEqual(batch.total, single.wots + single.leaf + single.batch)
        self.assertEqual(multi.total, single.wots + single.leaf + single.multi)

    def test_all_heights_and_field_types(self):
        for height in range(1, 9):
            last = (1 << height) - 1
            profile = merkle_verify_workload_profile(
                4, height, ((0,), (last,)), ("batch", "multiproof")
            )
            self.assertIsInstance(profile.costs, tuple)
            self.assertEqual(len(profile.costs), 2)
            for cost in profile.costs:
                self.assertIsInstance(cost, tuple)
                self.assertEqual(len(cost), 5)
                self.assertIsInstance(cost[0], str)
                for value in cost[1:]:
                    self.assertIsInstance(value, int)
            self.assertIsInstance(profile.total, int)

    def test_value_object_is_frozen_equal_and_hashable(self):
        first = merkle_verify_workload_profile(
            4, 3, ((0, 1, 6), (5,)), ("batch", "multiproof")
        )
        costs = (
            ("batch", 3 * 67 * 15, 3, 9, 3 * 67 * 15 + 3 + 9),
            ("multiproof", 67 * 15, 1, 3, 67 * 15 + 1 + 3),
        )
        positional = MerkleVerifyWorkloadProfile(
            4, 3, costs, sum(cost[4] for cost in costs)
        )
        keyword = MerkleVerifyWorkloadProfile(
            w=4, height=3, costs=costs, total=sum(cost[4] for cost in costs)
        )
        self.assertEqual(first, positional)
        self.assertEqual(first, keyword)
        self.assertEqual(hash(first), hash(positional))
        self.assertEqual(
            {first, positional, keyword},
            {MerkleVerifyWorkloadProfile(4, 3, costs, sum(c[4] for c in costs))},
        )
        self.assertNotEqual(
            first,
            merkle_verify_workload_profile(
                8, 3, ((0, 1, 6), (5,)), ("batch", "multiproof")
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            first.total = 0

    def test_non_tuple_groups_type_error(self):
        for bad in ([(0,)], {(0,)}, (i for i in ((0,),))):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_verify_workload_profile(4, 3, bad, ("batch",))

    def test_non_tuple_group_member_type_error(self):
        for bad in (([0],), ({0},), ((0,), [1])):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_verify_workload_profile(
                        4, 3, bad, ("batch",) * len(bad)
                    )

    def test_non_tuple_modes_type_error(self):
        for bad in (["batch"], {"batch"}, (m for m in ("batch",))):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_verify_workload_profile(4, 3, ((0,),), bad)

    def test_non_string_mode_type_error(self):
        for bad in (0, None, 1.0, object(), b"batch"):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_verify_workload_profile(
                        4, 3, ((0,), (1,)), ("batch", bad)
                    )

    def test_empty_groups_value_error(self):
        with self.assertRaises(ValueError):
            merkle_verify_workload_profile(4, 3, (), ())

    def test_inner_group_rules_value_error(self):
        # Each group must satisfy the single-group merkle_verify_profile rules.
        cases = [
            ((), ("batch",)),  # empty group
            ((False,), ("batch",)),  # boolean member
            ((0, "1"), ("batch",)),  # non-integer member -> TypeError via reuse
            ((8,), ("batch",)),  # out of range for height 3
            ((-1,), ("batch",)),  # negative
            ((1, 1), ("batch",)),  # duplicate
            ((3, 1), ("batch",)),  # unordered
        ]
        for groups, modes in cases:
            with self.subTest(groups=groups):
                with self.assertRaises((ValueError, TypeError)):
                    merkle_verify_workload_profile(4, 3, groups, modes)

    def test_inner_non_integer_member_is_type_error(self):
        with self.assertRaises(TypeError):
            merkle_verify_workload_profile(
                4, 3, ((0, "1"),), ("batch",)
            )

    def test_modes_length_mismatch_value_error(self):
        for modes in ((), ("batch",), ("batch", "multiproof", "batch")):
            with self.subTest(modes=modes):
                with self.assertRaises(ValueError):
                    merkle_verify_workload_profile(
                        4, 3, ((0,), (1,)), modes
                    )

    def test_unknown_mode_value_error(self):
        for bad in ("multi", "BATCH", "Batch", "", "batch proof"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_verify_workload_profile(
                        4, 3, ((0,), (1,)), ("batch", bad)
                    )

    def test_bad_w_value_error(self):
        for bad in (2, 3, 16, 0, -4, "4", 4.0, None, True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_verify_workload_profile(
                        bad, 3, ((0,),), ("batch",)
                    )

    def test_bad_height_value_error(self):
        for bad in (0, 9, -1, "3", 3.0, None, True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_verify_workload_profile(
                        4, bad, ((0,),), ("batch",)
                    )

    def test_function_is_pure(self):
        groups = ((0, 1, 6), (5,))
        modes = ("batch", "multiproof")
        first = merkle_verify_workload_profile(4, 3, groups, modes)
        second = merkle_verify_workload_profile(4, 3, groups, modes)
        self.assertEqual(first, second)
        # Inputs are untouched.
        self.assertEqual(groups, ((0, 1, 6), (5,)))
        self.assertEqual(modes, ("batch", "multiproof"))

    def test_grand_total_matches_sum_of_single_profiles(self):
        groups = ((0, 1), (3, 5), (6,))
        modes = ("batch", "multiproof", "multiproof")
        profile = merkle_verify_workload_profile(4, 3, groups, modes)
        expected = 0
        for group, mode in zip(groups, modes):
            single = merkle_verify_profile(4, 3, group)
            internal = single.batch if mode == "batch" else single.multi
            expected += single.wots + single.leaf + internal
        self.assertEqual(profile.total, expected)


if __name__ == "__main__":
    unittest.main()

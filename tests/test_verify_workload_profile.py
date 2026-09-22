import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    MerkleVerifyProfile,
    MerkleVerifyWorkloadProfile,
    merkle_verify_profile,
    merkle_verify_workload_profile,
)


class MerkleVerifyWorkloadProfileTest(unittest.TestCase):
    def test_single_group_batch(self):
        profile = merkle_verify_workload_profile(4, 3, ((5,),), ("batch",))
        single = merkle_verify_profile(4, 3, (5,))
        self.assertEqual(
            profile,
            MerkleVerifyWorkloadProfile(
                4,
                3,
                (("batch", single.wots, single.leaf, single.batch,
                  single.wots + single.leaf + single.batch),),
                single.wots + single.leaf + single.batch,
            ),
        )
        self.assertEqual(profile.costs[0][0], "batch")
        self.assertEqual(profile.costs[0][3], single.batch)
        self.assertEqual(profile.costs[0][4], 1005 + 1 + 3)
        self.assertEqual(profile.total, 1005 + 1 + 3)

    def test_single_group_multiproof(self):
        profile = merkle_verify_workload_profile(
            8, 3, ((0, 1, 6),), ("multiproof",)
        )
        single = merkle_verify_profile(8, 3, (0, 1, 6))
        self.assertEqual(
            profile.costs,
            (("multiproof", single.wots, single.leaf, single.multi,
              single.wots + single.leaf + single.multi),),
        )
        # multi for {0, 1, 6} is 5; batch over the same set would be 9.
        self.assertEqual(profile.costs[0][3], 5)
        self.assertEqual(profile.total, 3 * 34 * 255 + 3 + 5)

    def test_mixed_groups_in_group_order(self):
        groups = ((0, 1), (0, 1, 6), (0, 1))
        modes = ("batch", "multiproof", "batch")
        profile = merkle_verify_workload_profile(8, 3, groups, modes)

        singles = [merkle_verify_profile(8, 3, group) for group in groups]
        expected_internals = (
            singles[0].batch,   # 2 * 3 = 6
            singles[1].multi,   # 5
            singles[2].batch,   # 6
        )
        expected_rows = tuple(
            (
                mode,
                single.wots,
                single.leaf,
                internal,
                single.wots + single.leaf + internal,
            )
            for mode, single, internal in zip(modes, singles, expected_internals)
        )
        self.assertEqual(profile.costs, expected_rows)
        self.assertEqual(profile.total, sum(row[4] for row in expected_rows))
        # Spot-check concrete numbers.
        self.assertEqual(
            profile.costs,
            (
                ("batch", 2 * 34 * 255, 2, 6, 2 * 34 * 255 + 2 + 6),
                ("multiproof", 3 * 34 * 255, 3, 5, 3 * 34 * 255 + 3 + 5),
                ("batch", 2 * 34 * 255, 2, 6, 2 * 34 * 255 + 2 + 6),
            ),
        )

    def test_duplicate_groups_billed_separately(self):
        group = (0, 1, 6)
        once = merkle_verify_workload_profile(4, 3, (group,), ("multiproof",))
        twice = merkle_verify_workload_profile(
            4, 3, (group, group), ("multiproof", "multiproof")
        )
        self.assertEqual(len(twice.costs), 2)
        self.assertEqual(twice.costs[0], twice.costs[1])
        self.assertEqual(twice.total, 2 * once.total)
        # Two duplicate rows never collapse into one.
        self.assertEqual(twice.total, 2 * twice.costs[0][4])

    def test_same_group_different_modes_differ_only_in_internal_cost(self):
        batch = merkle_verify_workload_profile(
            4, 3, ((0, 1, 6),), ("batch",)
        )
        multi = merkle_verify_workload_profile(
            4, 3, ((0, 1, 6),), ("multiproof",)
        )
        self.assertEqual(batch.costs[0][1], multi.costs[0][1])
        self.assertEqual(batch.costs[0][2], multi.costs[0][2])
        self.assertEqual(batch.costs[0][3], 9)
        self.assertEqual(multi.costs[0][3], 5)
        self.assertEqual(batch.total - multi.total, 9 - 5)

    def test_echoes_parameters_and_both_w(self):
        for w, per_leaf in ((4, 67 * 15), (8, 34 * 255)):
            profile = merkle_verify_workload_profile(
                w, 4, ((0,), (3, 7)), ("batch", "multiproof")
            )
            self.assertEqual(profile.w, w)
            self.assertEqual(profile.height, 4)
            self.assertEqual(profile.costs[0], ("batch", per_leaf, 1, 4, per_leaf + 1 + 4))
            single = merkle_verify_profile(w, 4, (3, 7))
            self.assertEqual(
                profile.costs[1],
                ("multiproof", 2 * per_leaf, 2, single.multi,
                 2 * per_leaf + 2 + single.multi),
            )

    def test_all_heights_and_single_group_rules_reused(self):
        for height in range(1, 9):
            indices = (0, (1 << height) - 1)
            profile = merkle_verify_workload_profile(
                4, height, (indices,), ("multiproof",)
            )
            single = merkle_verify_profile(4, height, indices)
            self.assertEqual(
                profile.costs,
                (("multiproof", single.wots, single.leaf, single.multi,
                  single.wots + single.leaf + single.multi),),
            )
            self.assertEqual(profile.total, single.wots + single.leaf + single.multi)

    def test_row_field_types(self):
        profile = merkle_verify_workload_profile(
            4, 2, ((0, 2), (1,)), ("batch", "multiproof")
        )
        for row in profile.costs:
            self.assertIsInstance(row, tuple)
            self.assertEqual(len(row), 5)
            self.assertIsInstance(row[0], str)
            for value in row[1:]:
                self.assertIsInstance(value, int)
        self.assertIsInstance(profile.w, int)
        self.assertIsInstance(profile.height, int)
        self.assertIsInstance(profile.total, int)

    def test_value_object_is_frozen_equal_and_hashable(self):
        groups = ((0, 1), (0, 1, 6))
        modes = ("batch", "multiproof")
        first = merkle_verify_workload_profile(8, 3, groups, modes)
        rows = (
            ("batch", 2 * 34 * 255, 2, 6, 2 * 34 * 255 + 2 + 6),
            ("multiproof", 3 * 34 * 255, 3, 5, 3 * 34 * 255 + 3 + 5),
        )
        positional = MerkleVerifyWorkloadProfile(8, 3, rows, sum(row[4] for row in rows))
        keyword = MerkleVerifyWorkloadProfile(
            w=8, height=3, costs=rows, total=sum(row[4] for row in rows)
        )
        self.assertEqual(first, positional)
        self.assertEqual(first, keyword)
        self.assertEqual(hash(first), hash(positional))
        self.assertEqual(
            {first, positional, keyword},
            {MerkleVerifyWorkloadProfile(8, 3, rows, sum(row[4] for row in rows))},
        )
        self.assertNotEqual(
            first,
            merkle_verify_workload_profile(8, 3, groups, ("multiproof", "batch")),
        )
        with self.assertRaises(FrozenInstanceError):
            first.total = 0
        with self.assertRaises(FrozenInstanceError):
            first.costs = ()

    def test_non_tuple_groups_type_error(self):
        for bad in ([(0,)], {(0,)}, (i for i in ((0,),))):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_verify_workload_profile(4, 3, bad, ("batch",))

    def test_non_tuple_modes_type_error(self):
        for bad in (["batch"], {"batch"}, (m for m in ("batch",))):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_verify_workload_profile(4, 3, ((0,),), bad)

    def test_non_tuple_group_member_type_error(self):
        for bad in (((0,), [1]), ((0,), 1), ((b"0",),)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_verify_workload_profile(
                        4, 3, bad, ("batch",) * len(bad)
                    )

    def test_non_string_mode_type_error(self):
        for bad in ((0,), (None,), ("batch", 1)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_verify_workload_profile(
                        4, 3, ((0,),) * len(bad), bad
                    )

    def test_empty_groups_value_error(self):
        with self.assertRaises(ValueError):
            merkle_verify_workload_profile(4, 3, (), ())

    def test_empty_inner_group_value_error(self):
        with self.assertRaises(ValueError):
            merkle_verify_workload_profile(
                4, 3, ((0,), ()), ("batch", "multiproof")
            )

    def test_modes_length_mismatch_value_error(self):
        groups = ((0,), (1,))
        for bad_modes in (("batch",), ("batch", "multiproof", "batch"), ()):
            with self.subTest(bad_modes=bad_modes):
                with self.assertRaises(ValueError):
                    merkle_verify_workload_profile(4, 3, groups, bad_modes)

    def test_unknown_mode_value_error(self):
        for bad in (
            ("multi",),
            ("MULTIPROOF",),
            ("batchproof",),
            ("",),
            ("batch", "multi"),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_verify_workload_profile(
                        4, 3, ((0,),) * len(bad), bad
                    )

    def test_illegal_index_value_error(self):
        # Boolean, out-of-range, duplicate and unordered members follow the
        # single-group rules and must surface as ValueError.
        for bad_groups in (
            ((False,),),
            ((8,),),
            ((-1,),),
            ((1, 1),),
            ((3, 1),),
            ((0,), (8,)),
        ):
            with self.subTest(bad_groups=bad_groups):
                with self.assertRaises(ValueError):
                    merkle_verify_workload_profile(
                        4, 3, bad_groups, ("batch",) * len(bad_groups)
                    )

    def test_non_integer_index_member_type_error(self):
        for bad_groups in (((0, "1"),), ((0, 1.0),), ((0, None),)):
            with self.subTest(bad_groups=bad_groups):
                with self.assertRaises(TypeError):
                    merkle_verify_workload_profile(4, 3, bad_groups, ("batch",))

    def test_bad_w_value_error(self):
        for bad in (2, 3, 16, 0, -4, "4", 4.0, None, True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_verify_workload_profile(bad, 3, ((0,),), ("batch",))

    def test_bad_height_value_error(self):
        for bad in (0, 9, -1, "3", 3.0, None, True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_verify_workload_profile(4, bad, ((0,),), ("batch",))

    def test_function_is_pure(self):
        groups = ((0, 1), (0, 1, 6))
        modes = ("batch", "multiproof")
        first = merkle_verify_workload_profile(4, 3, groups, modes)
        second = merkle_verify_workload_profile(4, 3, groups, modes)
        self.assertEqual(first, second)
        # The input tuples are untouched.
        self.assertEqual(groups, ((0, 1), (0, 1, 6)))
        self.assertEqual(modes, ("batch", "multiproof"))
        # Repeated calls leave no shared mutable state.
        self.assertIsNot(first.costs, second.costs)


if __name__ == "__main__":
    unittest.main()

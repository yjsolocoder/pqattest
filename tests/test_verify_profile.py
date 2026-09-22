import unittest
from dataclasses import FrozenInstanceError

from pqattest import MerkleSigner, MerkleVerifyProfile, merkle_verify_profile, profile


class MerkleVerifyProfileTest(unittest.TestCase):
    def test_single_leaf_w4(self):
        result = merkle_verify_profile(4, 3, (0,))
        self.assertEqual(
            result,
            MerkleVerifyProfile(
                w=4, height=3, k=1, wots=67 * 15, leaf=1, batch=3, multi=3
            ),
        )

    def test_single_leaf_w8(self):
        result = merkle_verify_profile(8, 4, (7,))
        self.assertEqual(
            result,
            MerkleVerifyProfile(
                w=8, height=4, k=1, wots=34 * 255, leaf=1, batch=4, multi=4
            ),
        )

    def test_all_leaves(self):
        # height 3, every leaf: the multi-proof only hashes each internal
        # node once: 4 parents at level 1, 2 at level 2, 1 root -> 7.
        result = merkle_verify_profile(8, 3, tuple(range(8)))
        self.assertEqual(result.k, 8)
        self.assertEqual(result.wots, 8 * 34 * 255)
        self.assertEqual(result.leaf, 8)
        self.assertEqual(result.batch, 8 * 3)
        self.assertEqual(result.multi, 4 + 2 + 1)

    def test_shared_versus_distinct_paths(self):
        # Siblings (0, 1) collapse to one parent at every level:
        # {i>>1} = {0}, then {0}, {0} -> multi = 3.
        shared = merkle_verify_profile(4, 3, (0, 1))
        self.assertEqual((shared.k, shared.leaf, shared.batch), (2, 2, 6))
        self.assertEqual(shared.multi, 3)

        # Cousins (0, 2) stay distinct at level 1:
        # {i>>1} = {0, 1} (2), then {0}, {0} -> multi = 4.
        distinct = merkle_verify_profile(4, 3, (0, 2))
        self.assertEqual((distinct.k, distinct.leaf, distinct.batch), (2, 2, 6))
        self.assertEqual(distinct.multi, 4)

    def test_multi_formula_exhaustive_height_three(self):
        import itertools

        for size in range(1, 9):
            for combo in itertools.combinations(range(8), size):
                with self.subTest(combo=combo):
                    result = merkle_verify_profile(4, 3, combo)
                    expected = sum(
                        len({index >> level for index in combo})
                        for level in range(1, 4)
                    )
                    self.assertEqual(result.multi, expected)
                    self.assertEqual(result.batch, size * 3)

    def test_height_one(self):
        both = merkle_verify_profile(4, 1, (0, 1))
        self.assertEqual(
            both,
            MerkleVerifyProfile(
                w=4, height=1, k=2, wots=2 * 67 * 15, leaf=2, batch=2, multi=1
            ),
        )
        one = merkle_verify_profile(8, 1, (1,))
        self.assertEqual((one.k, one.wots, one.leaf, one.batch, one.multi),
                         (1, 34 * 255, 1, 1, 1))

    def test_wots_matches_profile_steps_per_leaf(self):
        for w, n, chain_end in ((4, 67, 15), (8, 34, 255)):
            for height in (1, 5, 8):
                indices = (0,) if height == 1 else (0, 1, 2 ** (height - 1))
                with self.subTest(w=w, height=height):
                    result = merkle_verify_profile(w, height, indices)
                    steps = profile("wots", w=w).steps
                    self.assertEqual(steps, n * chain_end)
                    self.assertEqual(result.wots, steps * len(indices))
                    # per-leaf counts are never deduplicated along paths
                    self.assertEqual(result.leaf, len(indices))

    def test_fields_echo_parameters_and_are_ints(self):
        result = merkle_verify_profile(8, 7, (3, 11, 70))
        self.assertEqual((result.w, result.height, result.k), (8, 7, 3))
        for value in (
            result.w, result.height, result.k, result.wots,
            result.leaf, result.batch, result.multi,
        ):
            self.assertIsInstance(value, int)
            self.assertNotIsInstance(value, bool)

    def test_frozen_positional_and_value_equality(self):
        first = merkle_verify_profile(4, 3, (0, 1))
        second = merkle_verify_profile(4, 3, (0, 1))
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(
            MerkleVerifyProfile(4, 3, 2, 2010, 2, 6, 3),
            MerkleVerifyProfile(
                w=4, height=3, k=2, wots=2010, leaf=2, batch=6, multi=3
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            first.k = 5  # type: ignore[misc]

    def test_deterministic_and_pure(self):
        signer = MerkleSigner(w=4, height=3)
        before = signer.next_index
        first = merkle_verify_profile(4, 3, (0, 3, 7))
        second = merkle_verify_profile(4, 3, (0, 3, 7))
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, before)

    def test_container_type_error(self):
        for bad_container in ([0, 1], {0, 1}, "ab", None, 7, range(2)):
            with self.subTest(bad_container=bad_container):
                with self.assertRaises(TypeError):
                    merkle_verify_profile(4, 3, bad_container)

    def test_member_type_error(self):
        for bad_member in ((0, "1"), (0, 1.0), (0, None), (0, object())):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(TypeError):
                    merkle_verify_profile(4, 3, bad_member)

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
                    merkle_verify_profile(4, 3, bad_indices)

    def test_invalid_w_and_height(self):
        for bad_w, bad_height in (
            (3, 3),
            (16, 3),
            (4, 0),
            (4, 9),
            (4, -1),
            (True, 3),
            (4, True),
        ):
            with self.subTest(bad_w=bad_w, bad_height=bad_height):
                with self.assertRaises(ValueError):
                    merkle_verify_profile(bad_w, bad_height, (0,))


if __name__ == "__main__":
    unittest.main()

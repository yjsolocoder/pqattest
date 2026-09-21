import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    MerkleBatchProof,
    MerkleSigner,
    MerkleStorageProfile,
    MerkleTransportWorkloadProfile,
    merkle_storage_profile,
    merkle_transport_profile,
    multiproof_encode,
    recommend_merkle_transport_workload,
)

# w=4: n=67, steps=1005; w=8: n=34, steps=8670
_GROUPS = ((0, 1), (2, 3))


def _expected(groups, capacity, budgets, *, prefer="compact"):
    """Brute-force the recommended profile with the documented ranking."""
    limits = budgets
    required = max([capacity] + [group[-1] + 1 for group in groups])
    candidates = []
    for candidate_w in (4, 8):
        for candidate_h in range(1, 9):
            storage = merkle_storage_profile(candidate_w, candidate_h)
            if storage.leaf_count < required:
                continue
            modes, sizes = [], []
            for group in groups:
                _nodes, batch, multi = merkle_transport_profile(candidate_w, candidate_h, group)
                if prefer == "batch":
                    mode, size = "batch", batch
                elif prefer == "multiproof":
                    mode, size = "multiproof", multi
                elif batch < multi:
                    mode, size = "batch", batch
                else:
                    mode, size = "multiproof", multi
                modes.append(mode)
                sizes.append(size)
            total = sum(sizes)
            steps = 1005 if candidate_w == 4 else 8670
            measured = (storage.checkpoint_bytes, max(sizes), total, steps)
            if any(limit is not None and value > limit for value, limit in zip(measured, limits)):
                continue
            candidates.append((storage, tuple(modes), tuple(sizes), total, steps))

    def tail(candidate):
        storage = candidate[0]
        return (storage.checkpoint_bytes, storage.leaf_count, storage.w, storage.height)

    if prefer == "speed":
        candidates.sort(key=lambda c: (c[4], c[3]) + tail(c))
    else:
        candidates.sort(key=lambda c: (c[3],) + tail(c))
    storage, modes, sizes, total, _steps = candidates[0]
    return MerkleTransportWorkloadProfile(storage, modes, sizes, total)


class RecommendMerkleTransportWorkloadTest(unittest.TestCase):
    def test_default_compact_picks_shorter_per_group(self):
        result = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 9000)
        )
        self.assertEqual(result, _expected(_GROUPS, 4, (None, None, None, 9000)))
        self.assertEqual(result.config, merkle_storage_profile(8, 2))
        # S(8,2) = 16 + 32 * 36 = 1168; m = 1 for each adjacent pair
        self.assertEqual(result.modes, ("multiproof", "multiproof"))
        self.assertEqual(result.sizes, (60 + 2 * (4 + 32 * 34) + 35,) * 2)
        self.assertEqual(result.total, sum(result.sizes))

    def test_compact_can_pick_batch(self):
        # a lone leaf high in a height-8 tree carries 8 multiproof nodes,
        # which costs more than the batch frame over one short signature
        groups = ((0,),)
        result = recommend_merkle_transport_workload(
            256, groups, (None, None, None, 10_000_000)
        )
        self.assertEqual(result, _expected(groups, 256, (None, None, None, 10_000_000)))
        self.assertEqual(result.config, merkle_storage_profile(8, 8))
        self.assertEqual(result.modes, ("batch",))
        self.assertEqual(result.sizes, (58 + 1 * (4 + 16 + 32 * (34 + 8)),))
        self.assertEqual(result.total, result.sizes[0])

    def test_batch_and_multiproof_fix_the_mode(self):
        groups = ((0, 1), (0, 1, 2, 3))
        for prefer, mode in (("batch", "batch"), ("multiproof", "multiproof")):
            with self.subTest(prefer=prefer):
                result = recommend_merkle_transport_workload(
                    4, groups, (None, None, None, 9000), prefer=prefer
                )
                self.assertEqual(result, _expected(groups, 4, (None, None, None, 9000), prefer=prefer))
                self.assertEqual(result.config, merkle_storage_profile(8, 2))
                self.assertEqual(result.modes, (mode, mode))
                for group, size in zip(groups, result.sizes):
                    _nodes, batch, multi = merkle_transport_profile(8, 2, group)
                    self.assertEqual(size, batch if mode == "batch" else multi)

    def test_speed_prefers_w4(self):
        result = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 9000), prefer="speed"
        )
        self.assertEqual(result, _expected(_GROUPS, 4, (None, None, None, 9000), prefer="speed"))
        self.assertEqual(result.config, merkle_storage_profile(4, 2))
        self.assertEqual(result.modes, ("multiproof", "multiproof"))
        self.assertEqual(result.sizes, (60 + 2 * (4 + 32 * 67) + 35,) * 2)

    def test_groups_force_height_beyond_capacity(self):
        # capacity 2 needs only height 1, but leaf 3 forces height 2
        groups = ((0, 1, 2, 3),)
        result = recommend_merkle_transport_workload(
            2, groups, (None, None, None, 9000)
        )
        self.assertEqual(result, _expected(groups, 2, (None, None, None, 9000)))
        self.assertEqual(result.config.height, 2)
        self.assertEqual(result.modes, ("multiproof",))
        self.assertEqual(result.sizes, (60 + 4 * (4 + 32 * 34),))

    def test_group_budget_filters_candidates(self):
        groups = ((0, 1, 2, 3),)
        # w=4 h=2 multiproof for the group is 8652 bytes; 4500 leaves only w=8
        result = recommend_merkle_transport_workload(
            4, groups, (None, 4500, None, None), prefer="multiproof"
        )
        self.assertEqual(result, _expected(groups, 4, (None, 4500, None, None), prefer="multiproof"))
        self.assertEqual(result.config, merkle_storage_profile(8, 2))
        self.assertEqual(result.sizes, (60 + 4 * (4 + 32 * 34),))

    def test_group_budget_is_inclusive(self):
        groups = ((0, 1), (2, 3))
        result = recommend_merkle_transport_workload(
            4, groups, (None, None, None, 9000)
        )
        limit = max(result.sizes)
        inclusive = recommend_merkle_transport_workload(
            4, groups, (None, limit, None, None)
        )
        self.assertEqual(inclusive, result)
        with self.assertRaises(ValueError):
            recommend_merkle_transport_workload(4, groups, (None, limit - 1, None, None))

    def test_total_budget_is_inclusive(self):
        groups = ((0, 1), (2, 3))
        result = recommend_merkle_transport_workload(
            4, groups, (None, None, None, 9000)
        )
        inclusive = recommend_merkle_transport_workload(
            4, groups, (None, None, result.total, None)
        )
        self.assertEqual(inclusive, result)
        with self.assertRaises(ValueError):
            recommend_merkle_transport_workload(4, groups, (None, None, result.total - 1, None))

    def test_checkpoint_budget_forces_w8(self):
        # w=4 h=1 checkpoint is 4369 bytes; 3000 leaves only w=8
        result = recommend_merkle_transport_workload(
            1, ((0,),), (3000, None, None, None)
        )
        self.assertEqual(result.config, merkle_storage_profile(8, 1))
        self.assertEqual(result.modes, ("multiproof",))
        self.assertEqual(result.sizes, (60 + 1 * (4 + 32 * 34) + 35,))

    def test_steps_budget_inclusive(self):
        result = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 1005), prefer="speed"
        )
        self.assertEqual(result.config, merkle_storage_profile(4, 2))
        with self.assertRaises(ValueError):
            recommend_merkle_transport_workload(
                4, _GROUPS, (None, None, None, 1004), prefer="speed"
            )

    def test_all_budgets_combined(self):
        groups = ((2, 7), (0, 5))
        budgets = (60000, 5000, 9000, 9000)
        result = recommend_merkle_transport_workload(
            8, groups, budgets, prefer="speed"
        )
        self.assertEqual(result, _expected(groups, 8, budgets, prefer="speed"))
        self.assertEqual(result.config.w, 4)
        self.assertEqual(result.config.height, 3)
        self.assertLessEqual(result.config.checkpoint_bytes, 60000)
        self.assertLessEqual(max(result.sizes), 5000)
        self.assertLessEqual(result.total, 9000)

    def test_sizes_match_transport_profile_for_all_candidates(self):
        workloads = (
            (1, ((0,),)),
            (16, ((3, 5), (0,))),
            (256, (tuple(range(0, 256, 37)), (1, 2))),
        )
        for capacity, groups in workloads:
            for prefer in ("compact", "speed", "batch", "multiproof"):
                with self.subTest(capacity=capacity, groups=groups, prefer=prefer):
                    result = recommend_merkle_transport_workload(
                        capacity, groups, (None, None, None, 10_000_000), prefer=prefer
                    )
                    config = result.config
                    self.assertEqual(
                        config, merkle_storage_profile(config.w, config.height)
                    )
                    self.assertEqual(len(result.modes), len(groups))
                    self.assertEqual(len(result.sizes), len(groups))
                    self.assertEqual(result.total, sum(result.sizes))
                    for group, mode, size in zip(groups, result.modes, result.sizes):
                        _nodes, batch, multi = merkle_transport_profile(
                            config.w, config.height, group
                        )
                        self.assertEqual(size, batch if mode == "batch" else multi)
                        if prefer == "batch":
                            self.assertEqual(mode, "batch")
                        elif prefer == "multiproof":
                            self.assertEqual(mode, "multiproof")
                        else:
                            self.assertEqual(size, min(batch, multi))

    def test_sizes_match_real_blobs(self):
        groups = ((3, 5), (0,))
        result = recommend_merkle_transport_workload(
            16, groups, (None, None, None, 9000)
        )
        signer = MerkleSigner(w=result.config.w, height=result.config.height)
        signatures = tuple(signer.sign(b"m%d" % i) for i in range(6))
        for group, mode, size in zip(groups, result.modes, result.sizes):
            chosen = tuple(signatures[index] for index in group)
            if mode == "batch":
                blob = MerkleBatchProof(
                    public_key=signer.public_key, signatures=chosen
                ).to_bytes()
            else:
                blob = multiproof_encode(signer.public_key, chosen)
            self.assertEqual(len(blob), size)

    def test_no_feasible_candidate_raises(self):
        # checkpoint budget below every candidate
        with self.assertRaises(ValueError):
            recommend_merkle_transport_workload(1, ((0,),), (100, None, None, None))
        # leaf 256 cannot exist in any height-8 tree
        with self.assertRaises(ValueError):
            recommend_merkle_transport_workload(
                1, ((256,),), (None, None, None, None)
            )
        # steps below the w=4 minimum
        with self.assertRaises(ValueError):
            recommend_merkle_transport_workload(
                256, (tuple(range(256)),), (None, None, None, 100)
            )

    def test_groups_must_be_tuple(self):
        for bad in ([(0, 1)], {(0, 1)}, "ab", None, 7, range(1)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_transport_workload(
                        4, bad, (None, None, None, 9000)
                    )

    def test_group_members_must_be_tuples(self):
        for bad in (([0, 1],), ("ab",), (None,), (7,), ((0, 1), [2, 3])):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_transport_workload(
                        4, bad, (None, None, None, 9000)
                    )

    def test_group_value_errors(self):
        for bad in (
            (),
            ((),),
            ((True,),),
            ((0, False),),
            ((0, "1"),),
            ((0, 1.0),),
            ((0, None),),
            ((-1, 0),),
            ((7, 7),),
            ((2, 1),),
            ((1, 0, 2),),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_workload(
                        4, bad, (None, None, None, 9000)
                    )

    def test_budgets_must_be_tuple(self):
        for bad in ([None, None, None, 9000], "budget", None, 7, {1, 2}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_transport_workload(4, _GROUPS, bad)

    def test_budgets_length(self):
        for bad in ((), (None,), (None, None, None), (None,) * 5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_workload(4, _GROUPS, bad)

    def test_budget_members_validated(self):
        for bad_member in (0, -1, True, 1.5, "100"):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_workload(
                        4, _GROUPS, (None, None, bad_member, None)
                    )

    def test_at_least_one_budget_required(self):
        with self.assertRaises(ValueError):
            recommend_merkle_transport_workload(
                4, _GROUPS, (None, None, None, None)
            )

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_workload(
                        bad, ((0,),), (None, None, None, 9000)
                    )

    def test_invalid_prefer_rejected(self):
        for bad in ("fast", "size", "COMPACT", None, 8):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_workload(
                        4, _GROUPS, (None, None, None, 9000), prefer=bad
                    )

    def test_returns_profile_type(self):
        result = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 9000)
        )
        self.assertIsInstance(result, MerkleTransportWorkloadProfile)
        self.assertIsInstance(result.config, MerkleStorageProfile)
        self.assertIsInstance(result.modes, tuple)
        self.assertIsInstance(result.sizes, tuple)
        self.assertTrue(all(isinstance(mode, str) for mode in result.modes))
        self.assertTrue(all(isinstance(size, int) for size in result.sizes))
        self.assertIsInstance(result.total, int)
        self.assertEqual(result.total, sum(result.sizes))

    def test_profile_frozen_positional_equal_hashable(self):
        result = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 9000)
        )
        positional = MerkleTransportWorkloadProfile(
            result.config, result.modes, result.sizes, result.total
        )
        keyword = MerkleTransportWorkloadProfile(
            config=result.config,
            modes=result.modes,
            sizes=result.sizes,
            total=result.total,
        )
        self.assertEqual(result, positional)
        self.assertEqual(positional, keyword)
        self.assertEqual(hash(result), hash(positional))
        self.assertEqual(
            {result, positional, keyword},
            {keyword},
        )
        with self.assertRaises(FrozenInstanceError):
            result.total = 1  # type: ignore[misc]

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        first = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 9000)
        )
        second = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 9000)
        )
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

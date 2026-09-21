import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

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
_GROUPS = ((0,), (2, 3))


def _expected(capacity, groups, budgets, *, prefer="compact"):
    """Brute-force the recommended profile with the documented ranking."""
    required = max([capacity, *(group[-1] + 1 for group in groups)])
    candidates = []
    for candidate_w in (4, 8):
        for candidate_h in range(1, 9):
            storage = merkle_storage_profile(candidate_w, candidate_h)
            if storage.leaf_count < required:
                continue
            if budgets[0] is not None and storage.checkpoint_bytes > budgets[0]:
                continue
            modes = []
            sizes = []
            for group in groups:
                _nodes, batch, multi = merkle_transport_profile(
                    candidate_w, candidate_h, group
                )
                if prefer in ("compact", "speed"):
                    if multi <= batch:
                        mode, size = "multiproof", multi
                    else:
                        mode, size = "batch", batch
                elif prefer == "batch":
                    mode, size = "batch", batch
                else:
                    mode, size = "multiproof", multi
                modes.append(mode)
                sizes.append(size)
            total = sum(sizes)
            steps = 1005 if candidate_w == 4 else 8670
            measured = (storage.checkpoint_bytes, max(sizes), total, steps)
            if any(
                limit is not None and value > limit
                for value, limit in zip(measured, budgets)
            ):
                continue
            candidates.append((storage, tuple(modes), tuple(sizes), total, steps))
    if prefer == "speed":
        candidates.sort(
            key=lambda c: (
                c[4], c[3], c[0].checkpoint_bytes, c[0].leaf_count, c[0].w, c[0].height
            )
        )
    else:
        candidates.sort(
            key=lambda c: (
                c[3], c[0].checkpoint_bytes, c[0].leaf_count, c[0].w, c[0].height
            )
        )
    storage, modes, sizes, total, _steps = candidates[0]
    return MerkleTransportWorkloadProfile(storage, modes, sizes, total)


class RecommendMerkleTransportWorkloadTest(unittest.TestCase):
    def test_default_prefers_compact(self):
        result = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 9000)
        )
        self.assertEqual(result, _expected(4, _GROUPS, (None, None, None, 9000)))
        self.assertEqual(result.config, merkle_storage_profile(8, 2))
        # at h=2 the multi-proof is shorter for every group (a batch only wins
        # for a lone leaf once the auth path reaches five nodes)
        self.assertEqual(result.modes, ("multiproof", "multiproof"))
        single_nodes, single_batch, single_multi = merkle_transport_profile(8, 2, (0,))
        pair_nodes, pair_batch, pair_multi = merkle_transport_profile(8, 2, (2, 3))
        self.assertEqual(result.sizes, (single_multi, pair_multi))
        self.assertEqual(result.total, single_multi + pair_multi)

    def test_compact_mixes_formats_per_group_at_height_eight(self):
        # a lone leaf at h=8 has eight carried nodes, so its batch is shorter;
        # an adjacent pair shares nodes and is shorter as a multi-proof
        groups = ((0,), (0, 1))
        result = recommend_merkle_transport_workload(
            256, groups, (None, None, None, 10_000_000)
        )
        self.assertEqual(result.config, merkle_storage_profile(8, 8))
        self.assertEqual(result.modes, ("batch", "multiproof"))
        for mode, size, group in zip(result.modes, result.sizes, groups):
            _nodes, batch, multi = merkle_transport_profile(8, 8, group)
            self.assertEqual(size, batch if mode == "batch" else multi)
            self.assertEqual(mode, "multiproof" if multi <= batch else "batch")
        self.assertEqual(result.total, sum(result.sizes))

    def test_compact_picks_shorter_format_for_every_group(self):        # an adjacent pair at h=2 is shorter as a multiproof; the chosen size
        # is always the minimum of the two format lengths
        groups = ((2, 3),)
        result = recommend_merkle_transport_workload(
            4, groups, (None, None, None, 9000)
        )
        self.assertEqual(result.modes, ("multiproof",))
        for mode, size, group in zip(result.modes, result.sizes, groups):
            _nodes, batch, multi = merkle_transport_profile(
                result.config.w, result.config.height, group
            )
            self.assertEqual(size, min(batch, multi))
            self.assertEqual(mode, "multiproof" if multi <= batch else "batch")

    def test_compact_equal_lengths_break_towards_multiproof(self):
        # real (w, height, indices) with h <= 8 never tie, so force equal
        # batch and multi-proof wire lengths for one group and check the
        # documented tie-break directly
        real_storage = merkle_storage_profile(8, 1)
        equal = 1000

        def fake_storage(w, height):
            return real_storage

        def fake_transport(w, height, indices):
            return 7, equal, equal

        with patch(
            "pqattest.params.merkle_storage_profile", side_effect=fake_storage
        ), patch(
            "pqattest.params.merkle_transport_profile", side_effect=fake_transport
        ):
            for prefer in ("compact", "speed"):
                with self.subTest(prefer=prefer):
                    result = recommend_merkle_transport_workload(
                        1, ((0,),), (None, None, None, 9000), prefer=prefer
                    )
                    self.assertEqual(result.modes, ("multiproof",))
                    self.assertEqual(result.sizes, (equal,))
                    self.assertEqual(result.total, equal)

    def test_speed_prefers_w4(self):
        result = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 9000), prefer="speed"
        )
        self.assertEqual(
            result,
            _expected(4, _GROUPS, (None, None, None, 9000), prefer="speed"),
        )
        self.assertEqual(result.config, merkle_storage_profile(4, 2))
        single_nodes, single_batch, single_multi = merkle_transport_profile(4, 2, (0,))
        pair_nodes, pair_batch, pair_multi = merkle_transport_profile(4, 2, (2, 3))
        self.assertEqual(result.modes, ("multiproof", "multiproof"))
        self.assertEqual(result.sizes, (single_multi, pair_multi))
        self.assertEqual(result.total, single_multi + pair_multi)

    def test_compact_and_speed_choose_same_modes_but_different_config(self):
        for prefer in ("compact", "speed"):
            with self.subTest(prefer=prefer):
                result = recommend_merkle_transport_workload(
                    4, _GROUPS, (None, None, None, 9000), prefer=prefer
                )
                for mode, size, group in zip(result.modes, result.sizes, _GROUPS):
                    _nodes, batch, multi = merkle_transport_profile(
                        result.config.w, result.config.height, group
                    )
                    self.assertEqual(size, min(batch, multi))
                    self.assertEqual(mode, "multiproof" if multi <= batch else "batch")
        compact = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 9000)
        )
        speed = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 9000), prefer="speed"
        )
        self.assertEqual((compact.config.w, compact.config.height), (8, 2))
        self.assertEqual((speed.config.w, speed.config.height), (4, 2))

    def test_batch_and_multiproof_are_fixed_formats(self):
        batch = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 9000), prefer="batch"
        )
        multi = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 9000), prefer="multiproof"
        )
        self.assertEqual(batch.modes, ("batch", "batch"))
        self.assertEqual(multi.modes, ("multiproof", "multiproof"))
        for result, column in ((batch, 1), (multi, 2)):
            for size, group in zip(result.sizes, _GROUPS):
                expected = merkle_transport_profile(
                    result.config.w, result.config.height, group
                )[column]
                self.assertEqual(size, expected)
        self.assertEqual(batch.total, sum(batch.sizes))
        self.assertEqual(multi.total, sum(multi.sizes))

    def test_groups_force_height_beyond_capacity(self):
        # capacity 2 needs only height 1, but leaf 3 forces height 2
        groups = ((0, 1), (2, 3))
        result = recommend_merkle_transport_workload(
            2, groups, (None, None, None, 9000)
        )
        self.assertEqual(result.config.height, 2)
        self.assertEqual(result, _expected(2, groups, (None, None, None, 9000)))

    def test_per_group_budget_filters_candidates(self):
        groups = ((0, 1, 2),)
        # the chosen multiproof must fit a tight per-group budget; a budget one
        # byte below it leaves no feasible candidate
        result = recommend_merkle_transport_workload(
            4, groups, (None, 5000, None, None)
        )
        self.assertTrue(all(size <= 5000 for size in result.sizes))
        self.assertLess(result.config.height, 8)
        with self.assertRaises(ValueError):
            recommend_merkle_transport_workload(
                4, groups, (None, min(result.sizes) - 1, None, None)
            )

    def test_total_budget_is_inclusive(self):
        result = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 9000)
        )
        exact = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, result.total, 9000)
        )
        self.assertEqual(exact, result)
        with self.assertRaises(ValueError):
            recommend_merkle_transport_workload(
                4, _GROUPS, (None, None, result.total - 1, 9000)
            )

    def test_checkpoint_budget_forces_w8(self):
        # w=4 h=1 checkpoint is 4369 bytes; 3000 leaves only w=8
        result = recommend_merkle_transport_workload(
            1, ((0,),), (3000, None, None, None)
        )
        self.assertEqual(result.config, merkle_storage_profile(8, 1))

    def test_steps_budget_forces_w4_under_speed_and_is_inclusive(self):
        result = recommend_merkle_transport_workload(
            4, _GROUPS, (None, None, None, 1005), prefer="speed"
        )
        self.assertEqual(result.config, merkle_storage_profile(4, 2))
        with self.assertRaises(ValueError):
            recommend_merkle_transport_workload(
                4, _GROUPS, (None, None, None, 1004), prefer="speed"
            )

    def test_all_budgets_combined(self):
        groups = ((2, 7),)
        result = recommend_merkle_transport_workload(
            8, groups, (60000, 5000, 5000, 9000), prefer="speed"
        )
        self.assertEqual(
            result,
            _expected(8, groups, (60000, 5000, 5000, 9000), prefer="speed"),
        )
        config = result.config
        self.assertEqual(config.w, 4)
        self.assertEqual(config.height, 3)
        self.assertLessEqual(config.checkpoint_bytes, 60000)
        self.assertTrue(all(size <= 5000 for size in result.sizes))
        self.assertLessEqual(result.total, 5000)

    def test_fields_match_transport_profile_for_all_candidates(self):
        workloads = (
            (1, ((0,),)),
            (16, ((3, 5), (0, 1, 2))),
            (256, (tuple(range(0, 256, 37)), (255,))),
        )
        for capacity, groups in workloads:
            with self.subTest(capacity=capacity, groups=groups):
                result = recommend_merkle_transport_workload(
                    capacity, groups, (None, None, None, 10_000_000)
                )
                self.assertEqual(result.config, merkle_storage_profile(
                    result.config.w, result.config.height
                ))
                for mode, size, group in zip(result.modes, result.sizes, groups):
                    _nodes, batch, multi = merkle_transport_profile(
                        result.config.w, result.config.height, group
                    )
                    self.assertEqual(size, batch if mode == "batch" else multi)
                self.assertEqual(result.total, sum(result.sizes))
                self.assertEqual(len(result.modes), len(groups))
                self.assertEqual(len(result.sizes), len(groups))

    def test_sizes_match_real_blobs(self):
        groups = ((3, 5), (0, 1, 2))
        result = recommend_merkle_transport_workload(
            16, groups, (None, None, 20000, None)
        )
        signer = MerkleSigner(w=result.config.w, height=result.config.height)
        signatures = tuple(signer.sign(b"m%d" % i) for i in range(6))
        for mode, size, group in zip(result.modes, result.sizes, groups):
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
            recommend_merkle_transport_workload(1, ((256,),), (None, None, None, None))
        # steps below the w=4 minimum
        with self.assertRaises(ValueError):
            recommend_merkle_transport_workload(
                256, (tuple(range(256)),), (None, None, None, 100)
            )
        # total budget below the smallest possible aggregate
        with self.assertRaises(ValueError):
            recommend_merkle_transport_workload(1, ((0,),), (None, None, 10, None))

    def test_groups_must_be_tuple(self):
        for bad in ([(0, 1)], {(0, 1)}, "groups", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_transport_workload(
                        4, bad, (None, None, None, 9000)
                    )

    def test_group_members_must_be_tuples(self):
        for bad in (([0, 1],), ({0, 1},), ((0, 1), "ab"), (None,), (7,)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_transport_workload(
                        4, bad, (None, None, None, 9000)
                    )

    def test_index_members_are_value_errors(self):
        for bad in (((0, "1"),), ((0, 1.0),), ((0, None),), ((0, object()),)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_workload(
                        4, bad, (None, None, None, 9000)
                    )

    def test_index_value_errors(self):
        for bad in (
            (),
            ((),),
            ((True,),),
            ((0, False),),
            ((-1, 0),),
            ((7, 7),),
            ((2, 1),),
            ((1, 0, 2),),
            ((0, 1), ()),
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
            for position in range(4):
                bad_budget = [None, None, None, None]
                bad_budget[position] = bad_member
                with self.subTest(bad_member=bad_member, position=position):
                    with self.assertRaises(ValueError):
                        recommend_merkle_transport_workload(
                            4, _GROUPS, tuple(bad_budget)
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
                        bad, _GROUPS, (None, None, None, 9000)
                    )

    def test_invalid_prefer_rejected(self):
        for bad in ("fast", "size", "COMPACT", "Compact", None, 8):
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
        self.assertIsInstance(result.total, int)
        for mode in result.modes:
            self.assertIsInstance(mode, str)
        for size in result.sizes:
            self.assertIsInstance(size, int)

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
            4, ((0, 1),), (None, None, None, 9000)
        )
        second = recommend_merkle_transport_workload(
            4, ((0, 1),), (None, None, None, 9000)
        )
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

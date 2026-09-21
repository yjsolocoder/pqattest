import inspect
import unittest

from pqattest import (
    MerkleBatchProof,
    MerkleSigner,
    MerkleTransportWorkloadProfile,
    merkle_storage_profile,
    merkle_transport_profile,
    merkle_transport_workload_frontier,
    multiproof_encode,
    profile,
)

# w=4: n=67, steps=1005; w=8: n=34, steps=8670
_GROUPS = ((0,), (2, 3))


def _feasible(capacity, groups, budgets):
    """Brute-force every feasible (storage, modes, sizes, total, steps)."""
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
                if multi <= batch:
                    mode, size = "multiproof", multi
                else:
                    mode, size = "batch", batch
                modes.append(mode)
                sizes.append(size)
            total = sum(sizes)
            steps = profile("merkle", w=candidate_w, height=candidate_h).steps
            measured = (storage.checkpoint_bytes, max(sizes), total, steps)
            if any(
                limit is not None and value > limit
                for value, limit in zip(measured, budgets)
            ):
                continue
            candidates.append((storage, tuple(modes), tuple(sizes), total, steps))
    return candidates


def _expected_frontier(capacity, groups, budgets):
    """Brute-force the documented Pareto frontier and ordering."""
    candidates = _feasible(capacity, groups, budgets)
    survivors = []
    for candidate in candidates:
        storage, _modes, _sizes, total, steps = candidate
        dominated = False
        for other in candidates:
            other_storage, _om, _os, other_total, other_steps = other
            if other is candidate:
                continue
            no_worse = (
                other_storage.checkpoint_bytes <= storage.checkpoint_bytes
                and other_total <= total
                and other_steps <= steps
            )
            strictly_better = (
                other_storage.checkpoint_bytes < storage.checkpoint_bytes
                or other_total < total
                or other_steps < steps
            )
            if no_worse and strictly_better:
                dominated = True
                break
        if not dominated:
            survivors.append(candidate)
    survivors.sort(
        key=lambda c: (
            c[4],
            c[3],
            c[0].checkpoint_bytes,
            c[0].leaf_count,
            c[0].w,
            c[0].height,
        )
    )
    return tuple(
        MerkleTransportWorkloadProfile(storage, modes, sizes, total)
        for storage, modes, sizes, total, _steps in survivors
    )


class MerkleTransportWorkloadFrontierTest(unittest.TestCase):
    def test_matches_brute_force(self):
        workloads = (
            (1, ((0,),), (None, None, None, 10_000_000)),
            (4, _GROUPS, (None, None, None, 9000)),
            (16, ((3, 5), (0, 1, 2)), (None, None, 20000, None)),
            (256, (tuple(range(0, 256, 37)), (255,)), (None, None, None, 10_000_000)),
            (8, ((2, 7),), (60000, 5000, 5000, 9000)),
        )
        for capacity, groups, budgets in workloads:
            with self.subTest(capacity=capacity, groups=groups, budgets=budgets):
                result = merkle_transport_workload_frontier(capacity, groups, budgets)
                self.assertEqual(result, _expected_frontier(capacity, groups, budgets))

    def test_returns_tuple_of_profiles(self):
        result = merkle_transport_workload_frontier(
            4, _GROUPS, (None, None, None, 9000)
        )
        self.assertIsInstance(result, tuple)
        self.assertTrue(result)
        for workload in result:
            self.assertIsInstance(workload, MerkleTransportWorkloadProfile)
            self.assertIsInstance(workload.modes, tuple)
            self.assertIsInstance(workload.sizes, tuple)
            self.assertIsInstance(workload.total, int)
            self.assertEqual(len(workload.modes), len(_GROUPS))
            self.assertEqual(len(workload.sizes), len(_GROUPS))
            self.assertEqual(workload.total, sum(workload.sizes))

    def test_tradeoff_keeps_both_w4_and_w8(self):
        # w=4 spends fewer verifier steps but more bytes; w=8 the reverse, so
        # neither config dominates the other and both are on the frontier.
        result = merkle_transport_workload_frontier(
            4, _GROUPS, (None, None, None, 9000)
        )
        configs = {(p.config.w, p.config.height) for p in result}
        self.assertIn((4, 2), configs)
        self.assertIn((8, 2), configs)
        w4 = next(p for p in result if p.config.w == 4)
        w8 = next(p for p in result if p.config.w == 8)
        self.assertLess(
            profile("merkle", w=4, height=2).steps,
            profile("merkle", w=8, height=2).steps,
        )
        self.assertGreater(w4.total, w8.total)
        self.assertGreater(w4.config.checkpoint_bytes, w8.config.checkpoint_bytes)

    def test_dominated_same_w_configs_are_pruned(self):
        # with only a steps budget, every taller w=4 tree is dominated by the
        # shortest covering w=4 tree (same steps, larger checkpoint and total)
        result = merkle_transport_workload_frontier(
            1, ((0,),), (None, None, None, 1005)
        )
        self.assertEqual([(p.config.w, p.config.height) for p in result], [(4, 1)])
        result8 = merkle_transport_workload_frontier(
            1, ((0,),), (3000, None, None, None)
        )
        self.assertEqual([(p.config.w, p.config.height) for p in result8], [(8, 1)])

    def test_every_result_is_feasible_and_non_dominated(self):
        capacity, groups, budgets = 16, ((3, 5), (0, 1, 2)), (None, 8000, 20000, 9000)
        result = merkle_transport_workload_frontier(capacity, groups, budgets)
        feasible = _feasible(capacity, groups, budgets)
        feasible_profiles = {
            MerkleTransportWorkloadProfile(storage, modes, sizes, total)
            for storage, modes, sizes, total, _steps in feasible
        }
        for workload in result:
            self.assertIn(workload, feasible_profiles)
            self.assertTrue(all(size <= 8000 for size in workload.sizes))
            self.assertLessEqual(workload.total, 20000)
            self.assertLessEqual(
                profile(
                    "merkle", w=workload.config.w, height=workload.config.height
                ).steps,
                9000,
            )
            # no other feasible candidate dominates this result
            for storage, modes, sizes, total, steps in feasible:
                other = MerkleTransportWorkloadProfile(storage, modes, sizes, total)
                if other == workload:
                    continue
                no_worse = (
                    storage.checkpoint_bytes <= workload.config.checkpoint_bytes
                    and total <= workload.total
                    and steps
                    <= profile(
                        "merkle",
                        w=workload.config.w,
                        height=workload.config.height,
                    ).steps
                )
                strictly_better = (
                    storage.checkpoint_bytes < workload.config.checkpoint_bytes
                    or total < workload.total
                    or steps
                    < profile(
                        "merkle",
                        w=workload.config.w,
                        height=workload.config.height,
                    ).steps
                )
                self.assertFalse(no_worse and strictly_better)

    def test_results_sorted_stably_by_steps_total_checkpoint_leaves_w_height(self):
        result = merkle_transport_workload_frontier(
            4, _GROUPS, (None, None, None, 10_000_000)
        )
        keys = [
            (
                profile("merkle", w=p.config.w, height=p.config.height).steps,
                p.total,
                p.config.checkpoint_bytes,
                p.config.leaf_count,
                p.config.w,
                p.config.height,
            )
            for p in result
        ]
        self.assertEqual(keys, sorted(keys))

    def test_results_deduplicated_by_value(self):
        result = merkle_transport_workload_frontier(
            4, _GROUPS, (None, None, None, 10_000_000)
        )
        self.assertEqual(len(result), len(set(result)))

    def test_per_group_shortest_wire_with_multiproof_tie_break(self):
        result = merkle_transport_workload_frontier(
            256, ((0,), (0, 1)), (None, None, None, 10_000_000)
        )
        for workload in result:
            for mode, size, group in zip(workload.modes, workload.sizes, ((0,), (0, 1))):
                _nodes, batch, multi = merkle_transport_profile(
                    workload.config.w, workload.config.height, group
                )
                self.assertEqual(size, min(batch, multi))
                self.assertEqual(mode, "multiproof" if multi <= batch else "batch")

    def test_sizes_match_real_blobs(self):
        groups = ((3, 5), (0, 1, 2))
        result = merkle_transport_workload_frontier(
            16, groups, (None, None, 20000, None)
        )
        for workload in result:
            signer = MerkleSigner(w=workload.config.w, height=workload.config.height)
            signatures = tuple(signer.sign(b"m%d" % i) for i in range(6))
            for mode, size, group in zip(workload.modes, workload.sizes, groups):
                chosen = tuple(signatures[index] for index in group)
                if mode == "batch":
                    blob = MerkleBatchProof(
                        public_key=signer.public_key, signatures=chosen
                    ).to_bytes()
                else:
                    blob = multiproof_encode(signer.public_key, chosen)
                self.assertEqual(len(blob), size)

    def test_groups_force_height_beyond_capacity(self):
        groups = ((0, 1), (2, 3))
        result = merkle_transport_workload_frontier(
            2, groups, (None, None, None, 10_000_000)
        )
        self.assertTrue(result)
        self.assertTrue(all(p.config.height >= 2 for p in result))
        self.assertEqual(
            result, _expected_frontier(2, groups, (None, None, None, 10_000_000))
        )

    def test_checkpoint_budget_forces_w8(self):
        result = merkle_transport_workload_frontier(
            1, ((0,),), (3000, None, None, None)
        )
        self.assertTrue(result)
        self.assertTrue(
            all(p.config.w == 8 and p.config.checkpoint_bytes <= 3000 for p in result)
        )

    def test_budgets_are_inclusive(self):
        result = merkle_transport_workload_frontier(
            4, _GROUPS, (None, None, None, 9000)
        )
        # bounds equal to the largest per-dimension value on the frontier must
        # keep every frontier member (equality is feasibility, not violation)
        exact = merkle_transport_workload_frontier(
            4,
            _GROUPS,
            (
                max(p.config.checkpoint_bytes for p in result),
                max(max(p.sizes) for p in result),
                max(p.total for p in result),
                9000,
            ),
        )
        self.assertEqual(exact, result)
        # one byte tighter on the aggregate prunes at least that profile
        with self.assertRaises(ValueError):
            merkle_transport_workload_frontier(
                4,
                _GROUPS,
                (
                    None,
                    None,
                    min(p.total for p in result) - 1,
                    9000,
                ),
            )

    def test_tighter_budgets_shrink_frontier_monotonically(self):
        wide = merkle_transport_workload_frontier(
            4, _GROUPS, (None, None, None, 10_000_000)
        )
        tight = merkle_transport_workload_frontier(
            4, _GROUPS, (None, None, None, 9000)
        )
        self.assertLessEqual(set(tight), set(wide))

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            merkle_transport_workload_frontier(1, ((0,),), (100, None, None, None))
        with self.assertRaises(ValueError):
            merkle_transport_workload_frontier(
                1, ((256,),), (None, None, None, None)
            )
        with self.assertRaises(ValueError):
            merkle_transport_workload_frontier(
                256, (tuple(range(256)),), (None, None, None, 100)
            )
        with self.assertRaises(ValueError):
            merkle_transport_workload_frontier(
                1, ((0,),), (None, None, 10, None)
            )

    def test_groups_must_be_tuple(self):
        for bad in ([(0, 1)], {(0, 1)}, "groups", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_transport_workload_frontier(
                        4, bad, (None, None, None, 9000)
                    )

    def test_group_members_must_be_tuples(self):
        for bad in (([0, 1],), ({0, 1},), ((0, 1), "ab"), (None,), (7,)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_transport_workload_frontier(
                        4, bad, (None, None, None, 9000)
                    )

    def test_index_members_are_value_errors(self):
        for bad in (((0, "1"),), ((0, 1.0),), ((0, None),), ((0, object()),)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_workload_frontier(
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
                    merkle_transport_workload_frontier(
                        4, bad, (None, None, None, 9000)
                    )

    def test_budgets_must_be_tuple(self):
        for bad in ([None, None, None, 9000], "budget", None, 7, {1, 2}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_transport_workload_frontier(4, _GROUPS, bad)

    def test_budgets_length(self):
        for bad in ((), (None,), (None, None, None), (None,) * 5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_workload_frontier(4, _GROUPS, bad)

    def test_budget_members_validated(self):
        for bad_member in (0, -1, True, 1.5, "100"):
            for position in range(4):
                bad_budget = [None, None, None, None]
                bad_budget[position] = bad_member
                with self.subTest(bad_member=bad_member, position=position):
                    with self.assertRaises(ValueError):
                        merkle_transport_workload_frontier(
                            4, _GROUPS, tuple(bad_budget)
                        )

    def test_at_least_one_budget_required(self):
        with self.assertRaises(ValueError):
            merkle_transport_workload_frontier(4, _GROUPS, (None, None, None, None))

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_workload_frontier(
                        bad, _GROUPS, (None, None, None, 9000)
                    )

    def test_arguments_have_no_defaults(self):
        sig = inspect.signature(merkle_transport_workload_frontier)
        self.assertEqual(
            list(sig.parameters), ["capacity", "groups", "budgets"]
        )
        for parameter in sig.parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        first = merkle_transport_workload_frontier(
            4, ((0, 1),), (None, None, None, 9000)
        )
        second = merkle_transport_workload_frontier(
            4, ((0, 1),), (None, None, None, 9000)
        )
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

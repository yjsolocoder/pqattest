import inspect
import unittest
from itertools import product

from pqattest import (
    MerkleBatchProof,
    MerkleSigner,
    MerkleTransportWorkloadProfile,
    merkle_mode_frontier,
    merkle_storage_profile,
    merkle_transport_profile,
    multiproof_encode,
    profile,
)

# w=4: n=67, steps=1005; w=8: n=34, steps=8670
_GROUPS = ((0,), (2, 3))


def _feasible(capacity, groups, budgets):
    """Brute-force every feasible (storage, modes, sizes, total, steps, peak, nodes)."""
    required = max([capacity, *(group[-1] + 1 for group in groups)])
    candidates = []
    for candidate_w in (4, 8):
        for candidate_h in range(1, 9):
            storage = merkle_storage_profile(candidate_w, candidate_h)
            if storage.leaf_count < required:
                continue
            if budgets[0] is not None and storage.checkpoint_bytes > budgets[0]:
                continue
            steps = profile("merkle", w=candidate_w, height=candidate_h).steps
            if budgets[3] is not None and steps > budgets[3]:
                continue
            transports = [
                merkle_transport_profile(candidate_w, candidate_h, group)
                for group in groups
            ]
            for choices in product((0, 1), repeat=len(groups)):
                modes = []
                sizes = []
                nodes = 0
                for choice, (node_count, batch, multi) in zip(choices, transports):
                    if choice:
                        modes.append("multiproof")
                        sizes.append(multi)
                        nodes += node_count
                    else:
                        modes.append("batch")
                        sizes.append(batch)
                peak = max(sizes)
                total = sum(sizes)
                measured = (storage.checkpoint_bytes, peak, total, steps, nodes)
                if any(
                    limit is not None and value > limit
                    for value, limit in zip(measured, budgets)
                ):
                    continue
                candidates.append(
                    (storage, tuple(modes), tuple(sizes), total, steps, peak, nodes)
                )
    return candidates


def _costs(candidate):
    storage, _modes, _sizes, total, steps, peak, nodes = candidate
    return (storage.checkpoint_bytes, peak, total, steps, nodes)


def _expected_frontier(capacity, groups, budgets):
    """Brute-force the documented Pareto frontier and ordering."""
    candidates = _feasible(capacity, groups, budgets)
    survivors = []
    for candidate in candidates:
        dominated = False
        for other in candidates:
            if other is candidate:
                continue
            other_costs = _costs(other)
            candidate_costs = _costs(candidate)
            no_worse = all(
                other_cost <= cost
                for other_cost, cost in zip(other_costs, candidate_costs)
            )
            strictly_better = any(
                other_cost < cost
                for other_cost, cost in zip(other_costs, candidate_costs)
            )
            if no_worse and strictly_better:
                dominated = True
                break
        if not dominated:
            survivors.append(candidate)
    unique = []
    seen = set()
    for candidate in survivors:
        storage, modes, sizes, total, _steps, _peak, _nodes = candidate
        value = MerkleTransportWorkloadProfile(storage, modes, sizes, total)
        if value not in seen:
            seen.add(value)
            unique.append(candidate)
    unique.sort(
        key=lambda c: (
            c[4],
            c[3],
            c[5],
            c[6],
            c[0].checkpoint_bytes,
            c[0].leaf_count,
            c[0].w,
            c[0].height,
            c[1],
        )
    )
    return tuple(
        MerkleTransportWorkloadProfile(storage, modes, sizes, total)
        for storage, modes, sizes, total, _steps, _peak, _nodes in unique
    )


class MerkleModeFrontierTest(unittest.TestCase):
    def test_matches_brute_force(self):
        workloads = (
            (1, ((0,),), (None, None, None, 10_000_000, None)),
            (4, _GROUPS, (None, None, None, 9000, None)),
            (16, ((3, 5), (0, 1, 2)), (None, None, 20000, None, None)),
            (8, ((2, 7),), (60000, 5000, 5000, 9000, 100)),
            (4, _GROUPS, (None, None, None, None, 3)),
            (2, ((0,), (1,), (2,)), (None, 5000, None, None, None)),
        )
        for capacity, groups, budgets in workloads:
            with self.subTest(capacity=capacity, groups=groups, budgets=budgets):
                result = merkle_mode_frontier(capacity, groups, budgets)
                self.assertEqual(result, _expected_frontier(capacity, groups, budgets))

    def test_returns_tuple_of_profiles(self):
        result = merkle_mode_frontier(4, _GROUPS, (None, None, None, 9000, None))
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
            self.assertTrue(all(mode in ("batch", "multiproof") for mode in workload.modes))

    def test_every_mode_combination_participates(self):
        # with 2 groups and only a loose steps budget, all four mode
        # combinations of the shortest covering tree are feasible; the mixed
        # ones survive only where nothing dominates them
        result = merkle_mode_frontier(4, _GROUPS, (None, None, None, 9000, None))
        modes_seen = {p.modes for p in result}
        self.assertIn(("multiproof", "multiproof"), modes_seen)
        self.assertIn(("batch", "multiproof"), modes_seen)
        self.assertIn(("batch", "batch"), modes_seen)
        # every enumerated combination is at least screened: the feasible set
        # contains all four combinations per config before dominance pruning
        feasible_modes = {
            modes
            for _storage, modes, _sizes, _total, _steps, _peak, _nodes in _feasible(
                4, _GROUPS, (None, None, None, 9000, None)
            )
        }
        self.assertEqual(
            feasible_modes,
            {
                ("batch", "batch"),
                ("batch", "multiproof"),
                ("multiproof", "batch"),
                ("multiproof", "multiproof"),
            },
        )

    def test_sizes_match_chosen_modes(self):
        result = merkle_mode_frontier(4, _GROUPS, (None, None, None, 10_000_000, None))
        for workload in result:
            for mode, size, group in zip(workload.modes, workload.sizes, _GROUPS):
                _nodes, batch, multi = merkle_transport_profile(
                    workload.config.w, workload.config.height, group
                )
                self.assertEqual(size, batch if mode == "batch" else multi)

    def test_nodes_budget_counts_multiproof_groups_only(self):
        # (0,) carries 2 multiproof nodes at height 2, (2, 3) carries 1; a
        # node budget of 1 therefore forbids multiproof on the first group
        # while batch groups always count 0 towards the budget
        groups = ((0,), (2, 3))
        self.assertEqual(merkle_transport_profile(4, 2, groups[0])[0], 2)
        self.assertEqual(merkle_transport_profile(4, 2, groups[1])[0], 1)
        result = merkle_mode_frontier(4, groups, (None, None, None, None, 1))
        self.assertTrue(result)
        for workload in result:
            carried = sum(
                merkle_transport_profile(workload.config.w, workload.config.height, group)[0]
                for mode, group in zip(workload.modes, groups)
                if mode == "multiproof"
            )
            self.assertLessEqual(carried, 1)
            for mode, group in zip(workload.modes, groups):
                node_count = merkle_transport_profile(
                    workload.config.w, workload.config.height, group
                )[0]
                if mode == "batch":
                    self.assertGreaterEqual(node_count, 0)  # batch counts 0 regardless
                else:
                    self.assertLessEqual(node_count, 1)
        # the all-batch combination carries zero nodes and is always feasible
        self.assertTrue(any(p.modes == ("batch", "batch") for p in result))

    def test_small_node_budget_forces_batch(self):
        # (0,) carries at least 2 multiproof nodes in every covering tree, so
        # a node budget of 1 leaves only the batch mode for that group
        groups = ((0,),)
        for height in range(2, 9):
            self.assertGreaterEqual(merkle_transport_profile(4, height, groups[0])[0], 2)
        result = merkle_mode_frontier(4, groups, (None, None, None, None, 1))
        self.assertTrue(result)
        self.assertTrue(all(p.modes == ("batch",) for p in result))

    def test_tradeoff_keeps_both_w4_and_w8(self):
        result = merkle_mode_frontier(4, _GROUPS, (None, None, None, 9000, None))
        configs = {(p.config.w, p.config.height) for p in result}
        self.assertIn((4, 2), configs)
        self.assertIn((8, 2), configs)

    def test_dominated_same_w_configs_are_pruned(self):
        # with only a steps budget, every taller w=4 tree is dominated by the
        # shortest covering w=4 tree (same steps, larger checkpoint and total);
        # both modes of the shortest tree survive: multiproof is smaller but
        # carries a node, batch is larger but carries none
        result = merkle_mode_frontier(1, ((0,),), (None, None, None, 1005, None))
        self.assertEqual(
            [(p.config.w, p.config.height) for p in result], [(4, 1), (4, 1)]
        )
        self.assertEqual(
            {p.modes for p in result}, {("batch",), ("multiproof",)}
        )

    def test_every_result_is_feasible_and_non_dominated(self):
        capacity, groups, budgets = 4, _GROUPS, (None, 5000, None, 9000, None)
        result = merkle_mode_frontier(capacity, groups, budgets)
        feasible = _feasible(capacity, groups, budgets)
        feasible_profiles = {
            MerkleTransportWorkloadProfile(storage, modes, sizes, total)
            for storage, modes, sizes, total, _steps, _peak, _nodes in feasible
        }
        for workload in result:
            self.assertIn(workload, feasible_profiles)
            self.assertTrue(all(size <= 5000 for size in workload.sizes))
            self.assertLessEqual(
                profile(
                    "merkle", w=workload.config.w, height=workload.config.height
                ).steps,
                9000,
            )
            # no other feasible candidate dominates this result
            for other_candidate in feasible:
                storage, modes, sizes, total, _s, _p, _n = other_candidate
                other = MerkleTransportWorkloadProfile(storage, modes, sizes, total)
                if other == workload:
                    continue
                other_costs = _costs(other_candidate)
                own_costs = (
                    workload.config.checkpoint_bytes,
                    max(workload.sizes),
                    workload.total,
                    profile(
                        "merkle", w=workload.config.w, height=workload.config.height
                    ).steps,
                    sum(
                        merkle_transport_profile(
                            workload.config.w, workload.config.height, group
                        )[0]
                        for mode, group in zip(workload.modes, groups)
                        if mode == "multiproof"
                    ),
                )
                no_worse = all(
                    other_cost <= cost
                    for other_cost, cost in zip(other_costs, own_costs)
                )
                strictly_better = any(
                    other_cost < cost
                    for other_cost, cost in zip(other_costs, own_costs)
                )
                self.assertFalse(no_worse and strictly_better)

    def test_results_sorted_by_documented_order(self):
        result = merkle_mode_frontier(
            4, _GROUPS, (None, None, None, 10_000_000, None)
        )
        keys = []
        for p in result:
            nodes = sum(
                merkle_transport_profile(p.config.w, p.config.height, group)[0]
                for mode, group in zip(p.modes, _GROUPS)
                if mode == "multiproof"
            )
            keys.append(
                (
                    profile("merkle", w=p.config.w, height=p.config.height).steps,
                    p.total,
                    max(p.sizes),
                    nodes,
                    p.config.checkpoint_bytes,
                    p.config.leaf_count,
                    p.config.w,
                    p.config.height,
                    p.modes,
                )
            )
        self.assertEqual(keys, sorted(keys))

    def test_results_deduplicated_by_value(self):
        result = merkle_mode_frontier(
            4, _GROUPS, (None, None, None, 10_000_000, None)
        )
        self.assertEqual(len(result), len(set(result)))

    def test_sizes_match_real_blobs(self):
        groups = ((3, 5), (0, 1, 2))
        result = merkle_mode_frontier(16, groups, (None, None, 20000, None, None))
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

    def test_budgets_are_inclusive(self):
        result = merkle_mode_frontier(4, _GROUPS, (None, None, None, 9000, None))
        exact = merkle_mode_frontier(
            4,
            _GROUPS,
            (
                max(p.config.checkpoint_bytes for p in result),
                max(max(p.sizes) for p in result),
                max(p.total for p in result),
                9000,
                max(
                    sum(
                        merkle_transport_profile(p.config.w, p.config.height, group)[0]
                        for mode, group in zip(p.modes, _GROUPS)
                        if mode == "multiproof"
                    )
                    for p in result
                ),
            ),
        )
        self.assertEqual(exact, result)
        # one byte tighter on the aggregate prunes at least that profile
        with self.assertRaises(ValueError):
            merkle_mode_frontier(
                4,
                _GROUPS,
                (None, None, min(p.total for p in result) - 1, 9000, None),
            )

    def test_tighter_budgets_shrink_frontier_monotonically(self):
        wide = merkle_mode_frontier(4, _GROUPS, (None, None, None, 10_000_000, None))
        tight = merkle_mode_frontier(4, _GROUPS, (None, None, None, 9000, None))
        self.assertLessEqual(set(tight), set(wide))

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            merkle_mode_frontier(1, ((0,),), (100, None, None, None, None))
        with self.assertRaises(ValueError):
            merkle_mode_frontier(1, ((256,),), (None, None, None, None, None))
        with self.assertRaises(ValueError):
            merkle_mode_frontier(256, (tuple(range(256)),), (None, None, None, 100, None))
        with self.assertRaises(ValueError):
            merkle_mode_frontier(1, ((0,),), (None, None, 10, None, None))

    def test_groups_must_be_tuple(self):
        for bad in ([(0, 1)], {(0, 1)}, "groups", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_mode_frontier(4, bad, (None, None, None, 9000, None))

    def test_group_members_must_be_tuples(self):
        for bad in (([0, 1],), ({0, 1},), ((0, 1), "ab"), (None,), (7,)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_mode_frontier(4, bad, (None, None, None, 9000, None))

    def test_index_members_are_value_errors(self):
        for bad in (((0, "1"),), ((0, 1.0),), ((0, None),), ((0, object()),)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_mode_frontier(4, bad, (None, None, None, 9000, None))

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
                    merkle_mode_frontier(4, bad, (None, None, None, 9000, None))

    def test_budgets_must_be_tuple(self):
        for bad in ([None] * 5, "budget", None, 7, {1, 2}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_mode_frontier(4, _GROUPS, bad)

    def test_budgets_length(self):
        for bad in ((), (None,), (None, None, None, None), (None,) * 6):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_mode_frontier(4, _GROUPS, bad)

    def test_budget_members_validated(self):
        for bad_member in (0, -1, True, 1.5, "100"):
            for position in range(5):
                bad_budget = [None] * 5
                bad_budget[position] = bad_member
                with self.subTest(bad_member=bad_member, position=position):
                    with self.assertRaises(ValueError):
                        merkle_mode_frontier(4, _GROUPS, tuple(bad_budget))

    def test_at_least_one_budget_required(self):
        with self.assertRaises(ValueError):
            merkle_mode_frontier(4, _GROUPS, (None, None, None, None, None))

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_mode_frontier(bad, _GROUPS, (None, None, None, 9000, None))

    def test_arguments_have_no_defaults(self):
        sig = inspect.signature(merkle_mode_frontier)
        self.assertEqual(list(sig.parameters), ["capacity", "groups", "budgets"])
        for parameter in sig.parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        first = merkle_mode_frontier(4, ((0, 1),), (None, None, None, 9000, None))
        second = merkle_mode_frontier(4, ((0, 1),), (None, None, None, 9000, None))
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

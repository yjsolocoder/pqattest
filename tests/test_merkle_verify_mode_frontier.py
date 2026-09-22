import inspect
import unittest
from itertools import product

from pqattest import (
    MerkleModeCost,
    MerkleSigner,
    MerkleTransportWorkloadProfile,
    MerkleVerifyWorkloadProfile,
    merkle_mode_frontier,
    merkle_storage_profile,
    merkle_transport_profile,
    merkle_verify_mode_frontier,
    merkle_verify_workload_profile,
    profile,
)

# w=4: n=67, steps=1005; w=8: n=34, steps=8670
_GROUPS = ((0,), (2, 3))


def _feasible(capacity, groups, budgets):
    """Brute-force every feasible (storage, modes, sizes, total, steps,
    peak, nodes, hashes, verify)."""
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
                modes = tuple(modes)
                peak = max(sizes)
                total = sum(sizes)
                verify = merkle_verify_workload_profile(
                    candidate_w, candidate_h, groups, modes
                )
                measured = (
                    storage.checkpoint_bytes,
                    peak,
                    total,
                    steps,
                    nodes,
                    verify.total,
                )
                if any(
                    limit is not None and value > limit
                    for value, limit in zip(measured, budgets)
                ):
                    continue
                candidates.append(
                    (
                        storage,
                        modes,
                        tuple(sizes),
                        total,
                        steps,
                        peak,
                        nodes,
                        verify.total,
                        verify,
                    )
                )
    return candidates


def _costs(candidate):
    storage, _modes, _sizes, total, steps, peak, nodes, hashes, _verify = candidate
    return (storage.checkpoint_bytes, peak, total, steps, nodes, hashes)


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
        storage, modes, sizes, total, _steps, _peak, nodes, _hashes, verify = candidate
        value = MerkleModeCost(
            MerkleTransportWorkloadProfile(storage, modes, sizes, total),
            verify,
            nodes,
        )
        if value not in seen:
            seen.add(value)
            unique.append(candidate)
    unique.sort(
        key=lambda c: (
            c[4],
            c[7],
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
        MerkleModeCost(
            MerkleTransportWorkloadProfile(storage, modes, sizes, total),
            verify,
            nodes,
        )
        for storage, modes, sizes, total, _steps, _peak, nodes, _hashes, verify in unique
    )


class MerkleVerifyModeFrontierTest(unittest.TestCase):
    def test_matches_brute_force(self):
        workloads = (
            (1, ((0,),), (None, None, None, 10_000_000, None, None)),
            (4, _GROUPS, (None, None, None, 9000, None, None)),
            (16, ((3, 5), (0, 1, 2)), (None, None, 20000, None, None, None)),
            (8, ((2, 7),), (60000, 5000, 5000, 9000, 100, None)),
            (4, _GROUPS, (None, None, None, None, 3, None)),
            (2, ((0,), (1,), (2,)), (None, 5000, None, None, None, None)),
            (4, _GROUPS, (None, None, None, None, None, 10_000)),
            (4, _GROUPS, (None, None, None, None, None, 3022)),
            (4, _GROUPS, (None, None, None, 9000, None, 4000)),
        )
        for capacity, groups, budgets in workloads:
            with self.subTest(capacity=capacity, groups=groups, budgets=budgets):
                result = merkle_verify_mode_frontier(capacity, groups, budgets)
                self.assertEqual(result, _expected_frontier(capacity, groups, budgets))

    def test_returns_tuple_of_mode_costs(self):
        result = merkle_verify_mode_frontier(
            4, _GROUPS, (None, None, None, 9000, None, None)
        )
        self.assertIsInstance(result, tuple)
        self.assertTrue(result)
        for mode_cost in result:
            self.assertIsInstance(mode_cost, MerkleModeCost)
            self.assertIsInstance(mode_cost.plan, MerkleTransportWorkloadProfile)
            self.assertIsInstance(mode_cost.cost, MerkleVerifyWorkloadProfile)
            self.assertIsInstance(mode_cost.nodes, int)
            self.assertEqual(len(mode_cost.plan.modes), len(_GROUPS))
            self.assertEqual(len(mode_cost.plan.sizes), len(_GROUPS))
            self.assertEqual(mode_cost.plan.total, sum(mode_cost.plan.sizes))
            self.assertEqual(mode_cost.cost.w, mode_cost.plan.config.w)
            self.assertEqual(mode_cost.cost.height, mode_cost.plan.config.height)

    def test_cost_modes_align_with_plan(self):
        result = merkle_verify_mode_frontier(
            4, _GROUPS, (None, None, None, 10_000_000, None, None)
        )
        for mode_cost in result:
            cost_modes = tuple(entry[0] for entry in mode_cost.cost.costs)
            self.assertEqual(cost_modes, mode_cost.plan.modes)
            self.assertEqual(
                mode_cost.cost.total,
                sum(entry[4] for entry in mode_cost.cost.costs),
            )
            expected = merkle_verify_workload_profile(
                mode_cost.plan.config.w,
                mode_cost.plan.config.height,
                _GROUPS,
                mode_cost.plan.modes,
            )
            self.assertEqual(mode_cost.cost, expected)

    def test_nodes_counts_multiproof_groups_only(self):
        result = merkle_verify_mode_frontier(
            4, _GROUPS, (None, None, None, None, 1, None)
        )
        self.assertTrue(result)
        for mode_cost in result:
            carried = sum(
                merkle_transport_profile(
                    mode_cost.plan.config.w, mode_cost.plan.config.height, group
                )[0]
                for mode, group in zip(mode_cost.plan.modes, _GROUPS)
                if mode == "multiproof"
            )
            self.assertEqual(mode_cost.nodes, carried)
            self.assertLessEqual(mode_cost.nodes, 1)

    def test_hashes_budget_is_inclusive_and_filters(self):
        result = merkle_verify_mode_frontier(
            4, _GROUPS, (None, None, None, None, None, 4000)
        )
        self.assertTrue(result)
        for mode_cost in result:
            self.assertLessEqual(mode_cost.cost.total, 4000)
        exact = merkle_verify_mode_frontier(
            4,
            _GROUPS,
            (None, None, None, None, None, max(mc.cost.total for mc in result)),
        )
        self.assertEqual(exact, result)
        with self.assertRaises(ValueError):
            merkle_verify_mode_frontier(
                4,
                _GROUPS,
                (None, None, None, None, None, min(mc.cost.total for mc in result) - 1),
            )

    def test_all_budgets_are_inclusive(self):
        result = merkle_verify_mode_frontier(
            4, _GROUPS, (None, None, None, 9000, None, None)
        )
        exact = merkle_verify_mode_frontier(
            4,
            _GROUPS,
            (
                max(mc.plan.config.checkpoint_bytes for mc in result),
                max(max(mc.plan.sizes) for mc in result),
                max(mc.plan.total for mc in result),
                9000,
                max(mc.nodes for mc in result),
                max(mc.cost.total for mc in result),
            ),
        )
        self.assertEqual(exact, result)

    def test_every_mode_combination_participates(self):
        feasible_modes = {
            modes
            for _storage, modes, _sizes, _total, _steps, _peak, _nodes, _h, _v in _feasible(
                4, _GROUPS, (None, None, None, 9000, None, None)
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

    def test_every_result_is_feasible_and_non_dominated(self):
        capacity, groups, budgets = 4, _GROUPS, (None, 5000, None, 9000, None, None)
        result = merkle_verify_mode_frontier(capacity, groups, budgets)
        feasible = _feasible(capacity, groups, budgets)
        feasible_values = {
            MerkleModeCost(
                MerkleTransportWorkloadProfile(storage, modes, sizes, total),
                verify,
                nodes,
            )
            for storage, modes, sizes, total, _s, _p, nodes, _h, verify in feasible
        }
        for mode_cost in result:
            self.assertIn(mode_cost, feasible_values)
            for other_candidate in feasible:
                (
                    storage,
                    modes,
                    sizes,
                    total,
                    _s,
                    _p,
                    nodes,
                    _h,
                    verify,
                ) = other_candidate
                other = MerkleModeCost(
                    MerkleTransportWorkloadProfile(storage, modes, sizes, total),
                    verify,
                    nodes,
                )
                if other == mode_cost:
                    continue
                no_worse = all(
                    other_cost <= cost
                    for other_cost, cost in zip(_costs(other_candidate), _value_costs(mode_cost, groups))
                )
                strictly_better = any(
                    other_cost < cost
                    for other_cost, cost in zip(_costs(other_candidate), _value_costs(mode_cost, groups))
                )
                self.assertFalse(no_worse and strictly_better)

    def test_results_sorted_by_documented_order(self):
        result = merkle_verify_mode_frontier(
            4, _GROUPS, (None, None, None, 10_000_000, None, None)
        )
        keys = [
            (
                profile("merkle", w=mc.plan.config.w, height=mc.plan.config.height).steps,
                mc.cost.total,
                mc.plan.total,
                max(mc.plan.sizes),
                mc.nodes,
                mc.plan.config.checkpoint_bytes,
                mc.plan.config.leaf_count,
                mc.plan.config.w,
                mc.plan.config.height,
                mc.plan.modes,
            )
            for mc in result
        ]
        self.assertEqual(keys, sorted(keys))

    def test_results_deduplicated_by_value(self):
        result = merkle_verify_mode_frontier(
            4, _GROUPS, (None, None, None, 10_000_000, None, None)
        )
        self.assertEqual(len(result), len(set(result)))

    def test_frozen_positional_equal_hash(self):
        result = merkle_verify_mode_frontier(
            4, _GROUPS, (None, None, None, 9000, None, None)
        )
        mode_cost = result[0]
        rebuilt = MerkleModeCost(mode_cost.plan, mode_cost.cost, mode_cost.nodes)
        self.assertEqual(rebuilt, mode_cost)
        self.assertEqual(hash(rebuilt), hash(mode_cost))
        self.assertIn(mode_cost, {rebuilt})
        with self.assertRaises(Exception):
            mode_cost.nodes = 9  # type: ignore[misc]

    def test_plan_sizes_match_real_blobs(self):
        groups = ((3, 5), (0, 1, 2))
        result = merkle_verify_mode_frontier(
            16, groups, (None, None, 20000, None, None, None)
        )
        for mode_cost in result:
            signer = MerkleSigner(
                w=mode_cost.plan.config.w, height=mode_cost.plan.config.height
            )
            signatures = tuple(signer.sign(b"m%d" % i) for i in range(6))
            for mode, size, group in zip(mode_cost.plan.modes, mode_cost.plan.sizes, groups):
                chosen = tuple(signatures[index] for index in group)
                if mode == "batch":
                    from pqattest import MerkleBatchProof

                    blob = MerkleBatchProof(
                        public_key=signer.public_key, signatures=chosen
                    ).to_bytes()
                else:
                    from pqattest import multiproof_encode

                    blob = multiproof_encode(signer.public_key, chosen)
                self.assertEqual(len(blob), size)

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            merkle_verify_mode_frontier(1, ((0,),), (100, None, None, None, None, None))
        with self.assertRaises(ValueError):
            merkle_verify_mode_frontier(1, ((256,),), (None,) * 6)
        with self.assertRaises(ValueError):
            merkle_verify_mode_frontier(
                256, (tuple(range(256)),), (None, None, None, 100, None, None)
            )
        with self.assertRaises(ValueError):
            merkle_verify_mode_frontier(1, ((0,),), (None, None, 10, None, None, None))
        # W-OTS chain work alone for one leaf at w=8 is 34*255 = 8670 hashes
        with self.assertRaises(ValueError):
            merkle_verify_mode_frontier(
                1, ((0,),), (None, None, None, None, None, 100)
            )

    def test_groups_must_be_tuple(self):
        for bad in ([(0, 1)], {(0, 1)}, "groups", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_verify_mode_frontier(
                        4, bad, (None, None, None, 9000, None, None)
                    )

    def test_group_members_must_be_tuples(self):
        for bad in (([0, 1],), ({0, 1},), ((0, 1), "ab"), (None,), (7,)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_verify_mode_frontier(
                        4, bad, (None, None, None, 9000, None, None)
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
                    merkle_verify_mode_frontier(
                        4, bad, (None, None, None, 9000, None, None)
                    )

    def test_budgets_must_be_tuple(self):
        for bad in ([None] * 6, "budget", None, 7, {1, 2}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_verify_mode_frontier(4, _GROUPS, bad)

    def test_budgets_length(self):
        for bad in ((), (None,), (None,) * 5, (None,) * 7):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_verify_mode_frontier(4, _GROUPS, bad)

    def test_budget_members_validated(self):
        for bad_member in (0, -1, True, 1.5, "100"):
            for position in range(6):
                bad_budget = [None] * 6
                bad_budget[position] = bad_member
                with self.subTest(bad_member=bad_member, position=position):
                    with self.assertRaises(ValueError):
                        merkle_verify_mode_frontier(4, _GROUPS, tuple(bad_budget))

    def test_at_least_one_budget_required(self):
        with self.assertRaises(ValueError):
            merkle_verify_mode_frontier(4, _GROUPS, (None,) * 6)

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_verify_mode_frontier(
                        bad, _GROUPS, (None, None, None, 9000, None, None)
                    )

    def test_arguments_have_no_defaults(self):
        sig = inspect.signature(merkle_verify_mode_frontier)
        self.assertEqual(list(sig.parameters), ["capacity", "groups", "budgets"])
        for parameter in sig.parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        first = merkle_verify_mode_frontier(
            4, ((0, 1),), (None, None, None, 9000, None, None)
        )
        second = merkle_verify_mode_frontier(
            4, ((0, 1),), (None, None, None, 9000, None, None)
        )
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)

    def test_old_mode_frontier_unchanged(self):
        # legacy five-budget interface still behaves exactly as before
        result = merkle_mode_frontier(4, _GROUPS, (None, None, None, 9000, None))
        self.assertTrue(result)
        self.assertIsInstance(result[0], MerkleTransportWorkloadProfile)


def _value_costs(mode_cost, groups):
    nodes = sum(
        merkle_transport_profile(
            mode_cost.plan.config.w, mode_cost.plan.config.height, group
        )[0]
        for mode, group in zip(mode_cost.plan.modes, groups)
        if mode == "multiproof"
    )
    return (
        mode_cost.plan.config.checkpoint_bytes,
        max(mode_cost.plan.sizes),
        mode_cost.plan.total,
        profile(
            "merkle",
            w=mode_cost.plan.config.w,
            height=mode_cost.plan.config.height,
        ).steps,
        nodes,
        mode_cost.cost.total,
    )


if __name__ == "__main__":
    unittest.main()

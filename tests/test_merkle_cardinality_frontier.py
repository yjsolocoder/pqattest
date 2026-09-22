import inspect
import unittest
from itertools import combinations, product

from pqattest import (
    ELEMENT_BYTES,
    MerkleModeCost,
    MerkleSigner,
    MerkleTransportWorkloadProfile,
    MerkleVerifyWorkloadProfile,
    merkle_cardinality_frontier,
    merkle_storage_profile,
    merkle_transport_profile,
    merkle_verify_mode_frontier,
    merkle_verify_workload_profile,
    multiproof_encode,
    profile,
)
from pqattest.wots import _params

_SIZES = (1, 2)


def _worst_group_metrics(w, height, k):
    """Worst (node count, multiproof bytes, internal hashes) over all subsets."""
    leaf_count = 1 << height
    rows = []
    for subset in combinations(range(leaf_count), k):
        node_count, _batch_bytes, multi_bytes = merkle_transport_profile(
            w, height, tuple(subset)
        )
        verify = merkle_verify_workload_profile(
            w, height, (tuple(subset),), ("multiproof",)
        )
        rows.append((node_count, multi_bytes, verify.costs[0][3]))
    return (
        max(row[0] for row in rows),
        max(row[1] for row in rows),
        max(row[2] for row in rows),
    )


def _feasible(capacity, group_sizes, budgets):
    """Brute-force every feasible candidate with worst-case per-group costs."""
    (
        checkpoint_limit,
        group_limit,
        total_limit,
        steps_limit,
        nodes_limit,
        hashes_limit,
    ) = budgets
    candidates = []
    for w in (4, 8):
        for height in range(1, 9):
            storage = merkle_storage_profile(w, height)
            if storage.leaf_count < capacity or any(
                k > storage.leaf_count for k in group_sizes
            ):
                continue
            if checkpoint_limit is not None and storage.checkpoint_bytes > checkpoint_limit:
                continue
            steps = profile("merkle", w=w, height=height).steps
            if steps_limit is not None and steps > steps_limit:
                continue
            worst = []
            for k in group_sizes:
                node_max, multi_bytes_max, internal_max = _worst_group_metrics(w, height, k)
                batch_bytes = merkle_transport_profile(
                    w, height, tuple(range(k))
                )[1]
                batch_verify = merkle_verify_workload_profile(
                    w, height, (tuple(range(k)),), ("batch",)
                )
                worst.append(
                    (
                        batch_bytes,
                        multi_bytes_max,
                        node_max,
                        batch_verify.costs[0],
                        internal_max,
                    )
                )
            for choices in product((0, 1), repeat=len(group_sizes)):
                modes = []
                sizes = []
                nodes = 0
                hashes_total = 0
                cost_rows = []
                for choice, metrics in zip(choices, worst):
                    (
                        batch_bytes,
                        multi_bytes,
                        node_max,
                        batch_row,
                        internal_max,
                    ) = metrics
                    wots, leaf = batch_row[1], batch_row[2]
                    if choice:
                        modes.append("multiproof")
                        sizes.append(multi_bytes)
                        nodes += node_max
                        internal = internal_max
                    else:
                        modes.append("batch")
                        sizes.append(batch_bytes)
                        internal = batch_row[3]
                    group_total = wots + leaf + internal
                    hashes_total += group_total
                    cost_rows.append((modes[-1], wots, leaf, internal, group_total))
                modes = tuple(modes)
                peak = max(sizes)
                total = sum(sizes)
                if group_limit is not None and peak > group_limit:
                    continue
                if total_limit is not None and total > total_limit:
                    continue
                if nodes_limit is not None and nodes > nodes_limit:
                    continue
                if hashes_limit is not None and hashes_total > hashes_limit:
                    continue
                verify = MerkleVerifyWorkloadProfile(
                    w=w, height=height, costs=tuple(cost_rows), total=hashes_total
                )
                candidates.append(
                    (
                        storage,
                        modes,
                        tuple(sizes),
                        total,
                        steps,
                        peak,
                        nodes,
                        hashes_total,
                        verify,
                    )
                )
    return candidates


def _costs(candidate):
    storage, _modes, _sizes, total, steps, peak, nodes, hashes, _verify = candidate
    return (storage.checkpoint_bytes, peak, total, steps, nodes, hashes)


def _expected_frontier(capacity, group_sizes, budgets):
    """Brute-force the documented Pareto frontier and ordering."""
    candidates = _feasible(capacity, group_sizes, budgets)
    survivors = []
    for candidate in candidates:
        dominated = False
        for other in candidates:
            if other is candidate:
                continue
            no_worse = all(
                other_cost <= cost
                for other_cost, cost in zip(_costs(other), _costs(candidate))
            )
            strictly_better = any(
                other_cost < cost
                for other_cost, cost in zip(_costs(other), _costs(candidate))
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


class MerkleCardinalityFrontierTest(unittest.TestCase):
    # small checkpoint caps keep the brute-force subset enumeration in tiny trees
    def test_matches_brute_force(self):
        workloads = (
            (4, (1,), (9000, None, None, None, None, None)),
            (4, (2, 2), (9000, None, None, None, None, None)),
            (4, (1, 3), (9000, None, None, None, None, None)),
            (2, (1, 2), (9000, None, None, None, None, None)),
            (4, (3,), (9000, None, None, None, None, None)),
            (8, (1, 2, 4), (9000, None, None, None, None, None)),
            (4, _SIZES, (9000, None, None, None, 4, None)),
            (4, _SIZES, (None, 3000, None, None, None, None)),
            (4, _SIZES, (9000, None, 7000, None, None, None)),
            (4, _SIZES, (9000, None, None, None, None, 6000)),
        )
        for capacity, group_sizes, budgets in workloads:
            with self.subTest(capacity=capacity, sizes=group_sizes, budgets=budgets):
                result = merkle_cardinality_frontier(capacity, group_sizes, budgets)
                self.assertEqual(
                    result, _expected_frontier(capacity, group_sizes, budgets)
                )

    def test_worst_case_is_an_actual_subset_maximum(self):
        # every quoted multiproof figure must equal a maximum attained by
        # some real same-size index subset of the candidate tree
        result = merkle_cardinality_frontier(
            4, (1, 3), (9000, None, None, None, None, None)
        )
        self.assertTrue(result)
        for mode_cost in result:
            w = mode_cost.plan.config.w
            height = mode_cost.plan.config.height
            for mode, k, size, row in zip(
                mode_cost.plan.modes,
                (1, 3),
                mode_cost.plan.sizes,
                mode_cost.cost.costs,
            ):
                if mode != "multiproof":
                    continue
                node_max, bytes_max, internal_max = _worst_group_metrics(w, height, k)
                self.assertEqual(size, bytes_max)
                self.assertEqual(row[3], internal_max)
        for mode_cost in result:
            w, height = mode_cost.plan.config.w, mode_cost.plan.config.height
            expected = sum(
                _worst_group_metrics(w, height, k)[0]
                for k, mode in zip((1, 3), mode_cost.plan.modes)
                if mode == "multiproof"
            )
            self.assertEqual(mode_cost.nodes, expected)

    def test_closed_form_worst_node_counts(self):
        # internal_max = sum(min(k, 2**j)); m_max = internal_max - (k - 1)
        result = merkle_cardinality_frontier(
            16, (1, 2, 3, 4, 8, 16), (None, None, None, None, None, 10**18)
        )
        self.assertTrue(result)
        for mode_cost in result:
            height = mode_cost.plan.config.height
            leaf_count = 1 << height
            for mode, k, row in zip(
                mode_cost.plan.modes,
                (1, 2, 3, 4, 8, 16),
                mode_cost.cost.costs,
            ):
                if k > leaf_count or mode != "multiproof":
                    continue
                internal_max = sum(min(k, 1 << j) for j in range(height))
                self.assertEqual(row[3], internal_max)

    def test_full_tree_multiproof_carries_no_nodes(self):
        # k == leaf_count: every sibling is derivable, m_max == 0
        result = merkle_cardinality_frontier(
            4, (4,), (None, None, None, None, None, 10**18)
        )
        choice = next(
            mc
            for mc in result
            if mc.plan.config.w == 8
            and mc.plan.config.height == 2
            and mc.plan.modes == ("multiproof",)
        )
        self.assertEqual(choice.nodes, 0)
        self.assertEqual(choice.plan.sizes[0], 60 + 4 * (4 + 32 * 34))
        self.assertEqual(choice.cost.costs[0][3], 3)  # 3 internal merges

    def test_batch_groups_use_fixed_position_free_formulas(self):
        result = merkle_cardinality_frontier(
            4, (2, 3), (9000, None, None, None, None, None)
        )
        all_batch = tuple(
            mc
            for mc in result
            if mc.plan.modes == ("batch", "batch")
        )
        self.assertTrue(all_batch)
        for mode_cost in all_batch:
            w = mode_cost.plan.config.w
            height = mode_cost.plan.config.height
            _b, l1, l2 = _params(w)
            n = l1 + l2
            signature_bytes = 16 + ELEMENT_BYTES * (n + height)
            for k, size in zip((2, 3), mode_cost.plan.sizes):
                self.assertEqual(size, 58 + k * (4 + signature_bytes))
            self.assertEqual(mode_cost.nodes, 0)
            for k, row in zip((2, 3), mode_cost.cost.costs):
                self.assertEqual(row[3], k * height)

    def test_duplicate_groups_are_billed_separately(self):
        single = merkle_cardinality_frontier(
            4, (2,), (9000, None, None, None, None, None)
        )
        doubled = merkle_cardinality_frontier(
            4, (2, 2), (9000, None, None, None, None, None)
        )
        one = next(
            mc
            for mc in single
            if mc.plan.config.w == 8
            and mc.plan.config.height == 2
            and mc.plan.modes == ("multiproof",)
        )
        two = next(
            mc
            for mc in doubled
            if mc.plan.config.w == 8
            and mc.plan.config.height == 2
            and mc.plan.modes == ("multiproof", "multiproof")
        )
        self.assertEqual(two.plan.sizes, (one.plan.sizes[0], one.plan.sizes[0]))
        self.assertEqual(two.plan.total, 2 * one.plan.total)
        self.assertEqual(two.nodes, 2 * one.nodes)
        self.assertEqual(two.cost.total, 2 * one.cost.total)

    def test_returns_tuple_of_mode_costs(self):
        result = merkle_cardinality_frontier(
            4, _SIZES, (None, None, None, 9000, None, None)
        )
        self.assertIsInstance(result, tuple)
        self.assertTrue(result)
        for mode_cost in result:
            self.assertIsInstance(mode_cost, MerkleModeCost)
            self.assertIsInstance(mode_cost.plan, MerkleTransportWorkloadProfile)
            self.assertIsInstance(mode_cost.cost, MerkleVerifyWorkloadProfile)
            self.assertIsInstance(mode_cost.nodes, int)
            self.assertEqual(len(mode_cost.plan.modes), len(_SIZES))
            self.assertEqual(len(mode_cost.plan.sizes), len(_SIZES))
            self.assertEqual(mode_cost.plan.total, sum(mode_cost.plan.sizes))
            self.assertEqual(mode_cost.cost.w, mode_cost.plan.config.w)
            self.assertEqual(mode_cost.cost.height, mode_cost.plan.config.height)
            cost_modes = tuple(entry[0] for entry in mode_cost.cost.costs)
            self.assertEqual(cost_modes, mode_cost.plan.modes)
            self.assertEqual(
                mode_cost.cost.total, sum(entry[4] for entry in mode_cost.cost.costs)
            )

    def test_results_feasible_non_dominated_sorted_unique(self):
        capacity, sizes, budgets = 4, (1, 2), (None, 4000, None, 9000, None, None)
        result = merkle_cardinality_frontier(capacity, sizes, budgets)
        feasible = _feasible(capacity, sizes, budgets)
        feasible_values = {
            MerkleModeCost(
                MerkleTransportWorkloadProfile(storage, modes, mode_sizes, total),
                verify,
                nodes,
            )
            for storage, modes, mode_sizes, total, _s, _p, nodes, _h, verify in feasible
        }
        for mode_cost in result:
            self.assertIn(mode_cost, feasible_values)
            for other in feasible:
                if (
                    MerkleModeCost(
                        MerkleTransportWorkloadProfile(
                            other[0], other[1], other[2], other[3]
                        ),
                        other[8],
                        other[6],
                    )
                    == mode_cost
                ):
                    continue
                no_worse = all(
                    other_cost <= cost
                    for other_cost, cost in zip(_costs(other), _value_costs(mode_cost))
                )
                strictly_better = any(
                    other_cost < cost
                    for other_cost, cost in zip(_costs(other), _value_costs(mode_cost))
                )
                self.assertFalse(no_worse and strictly_better)
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
        self.assertEqual(len(result), len(set(result)))

    def test_all_budgets_are_inclusive(self):
        result = merkle_cardinality_frontier(
            4, _SIZES, (None, None, None, 9000, None, None)
        )
        exact = merkle_cardinality_frontier(
            4,
            _SIZES,
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

    def test_worst_case_bytes_match_real_blobs_at_a_worst_placement(self):
        # a maximally spread subset must actually serialise to the quoted
        # worst-case multiproof length (small trees keep this test fast)
        def spread(height, k):
            if height == 0:
                return (0,)
            if k == 1:
                return (0,)
            left_k = (k + 1) // 2
            right_k = k - left_k
            left = spread(height - 1, left_k) if left_k else ()
            right = (
                tuple(i + (1 << (height - 1)) for i in spread(height - 1, right_k))
                if right_k
                else ()
            )
            return tuple(sorted(left + right))

        result = merkle_cardinality_frontier(
            8, (3,), (9000, None, None, None, None, 10**18)
        )
        for mode_cost in result:
            if mode_cost.plan.modes != ("multiproof",):
                continue
            w, height = mode_cost.plan.config.w, mode_cost.plan.config.height
            if height > 3:
                continue
            signer = MerkleSigner(w=w, height=height)
            indices = spread(height, 3)
            chosen = tuple(signer._signature_at(i, b"m") for i in indices)
            self.assertEqual(
                len(multiproof_encode(signer.public_key, chosen)),
                mode_cost.plan.sizes[0],
            )

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            merkle_cardinality_frontier(1, (1,), (100, None, None, None, None, None))
        with self.assertRaises(ValueError):
            merkle_cardinality_frontier(1, (257,), (None, None, None, None, None, 1))
        with self.assertRaises(ValueError):
            merkle_cardinality_frontier(
                4, (1,), (None, None, None, None, None, 10)
            )
        with self.assertRaises(ValueError):
            merkle_cardinality_frontier(4, (5,), (None, None, 10, None, None, 10**18))

    def test_group_sizes_must_be_tuple(self):
        for bad in ([1], {1}, "sizes", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_cardinality_frontier(4, bad, (None, None, None, 9000, None, None))

    def test_group_sizes_non_empty(self):
        with self.assertRaises(ValueError):
            merkle_cardinality_frontier(4, (), (None, None, None, 9000, None, None))

    def test_group_size_members_typed(self):
        for bad in (1.0, "1", None, [1]):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_cardinality_frontier(
                        4, (bad,), (None, None, None, 9000, None, None)
                    )
        for bad in (True, False, 0, -3):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_cardinality_frontier(
                        4, (bad,), (None, None, None, 9000, None, None)
                    )

    def test_budgets_must_be_tuple(self):
        for bad in ([None] * 6, "budget", None, 7, {1, 2}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_cardinality_frontier(4, _SIZES, bad)

    def test_budgets_length_and_members(self):
        for bad in ((), (None,), (None,) * 5, (None,) * 7):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_cardinality_frontier(4, _SIZES, bad)
        for bad_member in (0, -1, True, 1.5, "100"):
            for position in range(6):
                bad_budget = [None] * 6
                bad_budget[position] = bad_member
                with self.subTest(bad_member=bad_member, position=position):
                    with self.assertRaises(ValueError):
                        merkle_cardinality_frontier(4, _SIZES, tuple(bad_budget))
        with self.assertRaises(ValueError):
            merkle_cardinality_frontier(4, _SIZES, (None,) * 6)

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_cardinality_frontier(
                        bad, _SIZES, (None, None, None, 9000, None, None)
                    )

    def test_boundary_inputs_accepted(self):
        result = merkle_cardinality_frontier(
            256, (256,), (None, None, None, None, None, 10**18)
        )
        self.assertTrue(result)
        self.assertTrue(
            merkle_cardinality_frontier(
                1, (1,), (None, None, None, None, None, 10**18)
            )
        )

    def test_arguments_have_no_defaults(self):
        sig = inspect.signature(merkle_cardinality_frontier)
        self.assertEqual(list(sig.parameters), ["capacity", "group_sizes", "budgets"])
        for parameter in sig.parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        first = merkle_cardinality_frontier(
            4, (1, 2), (None, None, None, 9000, None, None)
        )
        second = merkle_cardinality_frontier(
            4, (1, 2), (None, None, None, 9000, None, None)
        )
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)

    def test_old_joint_frontier_unchanged(self):
        # legacy concrete-index interface still behaves exactly as before
        result = merkle_verify_mode_frontier(
            4, ((0,), (2, 3)), (None, None, None, 9000, None, None)
        )
        self.assertTrue(result)
        self.assertIsInstance(result[0], MerkleModeCost)


def _value_costs(mode_cost):
    return (
        mode_cost.plan.config.checkpoint_bytes,
        max(mode_cost.plan.sizes),
        mode_cost.plan.total,
        profile(
            "merkle", w=mode_cost.plan.config.w, height=mode_cost.plan.config.height
        ).steps,
        mode_cost.nodes,
        mode_cost.cost.total,
    )


if __name__ == "__main__":
    unittest.main()

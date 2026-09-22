import inspect
import unittest
from functools import lru_cache
from itertools import combinations, product
from math import comb

from pqattest import (
    MerkleModeCost,
    MerkleSigner,
    MerkleTransportWorkloadProfile,
    MerkleVerifyWorkloadProfile,
    merkle_cardinality_frontier,
    merkle_storage_profile,
    multiproof_encode,
    profile,
)
from pqattest.merkle import _canonical_multiproof_nodes
from pqattest.params import _worst_multiproof_nodes
from pqattest.wots import _params

# w=4: n=67, steps=1005; w=8: n=34, steps=8670
_SIZES = (1, 2)
_ENUMERATION_LIMIT = 100_000


@lru_cache(maxsize=None)
def _dp_worst_nodes(height, k):
    """Independently written copy of the worst-node recursion."""
    if height == 1:
        return 1 if k == 1 else 0
    best = -1
    upper = min(k, 1 << (height - 1))
    for j in range((k + 1) // 2, upper + 1):
        candidate = 2 * j - k + _dp_worst_nodes(height - 1, j)
        if candidate > best:
            best = candidate
    return best


@lru_cache(maxsize=None)
def _dp_worst_set(height, k):
    """Construct a k-subset attaining the worst carried-node count."""
    if height == 1:
        return (0,) if k == 1 else (0, 1)
    best_j, best_v = None, -1
    upper = min(k, 1 << (height - 1))
    for j in range((k + 1) // 2, upper + 1):
        value = 2 * j - k + _dp_worst_nodes(height - 1, j)
        if value > best_v:
            best_v, best_j = value, j
    parents = _dp_worst_set(height - 1, best_j)
    pair_parents = k - best_j
    indices = []
    for rank, parent in enumerate(parents):
        if rank < pair_parents:
            indices.extend((2 * parent, 2 * parent + 1))
        else:
            indices.append(2 * parent)
    return tuple(sorted(indices))


def _worst_for_group(w, height, k, mode):
    """Exact worst case: real subset enumeration when cheap, DP realization
    otherwise (the realization is cross-checked against enumeration for
    every cheap (height, k) in test_worst_matches_subset_enumeration)."""
    b, l1, l2 = _params(w)
    n = l1 + l2
    leaf_count = 1 << height
    signature_wire_bytes = 16 + 32 * (n + height)
    wots = k * n * (b - 1)
    if mode == "batch":
        return (
            58 + k * (4 + signature_wire_bytes),  # size
            0,  # nodes
            wots,
            k,
            k * height,
        )
    if comb(leaf_count, k) <= _ENUMERATION_LIMIT:
        worst_m = worst_bytes = worst_internal = -1
        for indices in combinations(range(leaf_count), k):
            m = len(_canonical_multiproof_nodes(indices, height))
            wire = 60 + k * (4 + 32 * n) + 35 * m
            internal = sum(len({i >> l for i in indices}) for l in range(1, height + 1))
            worst_m = max(worst_m, m)
            worst_bytes = max(worst_bytes, wire)
            worst_internal = max(worst_internal, internal)
        return worst_bytes, worst_m, wots, k, worst_internal
    worst_m = _dp_worst_nodes(height, k)
    wire = 60 + k * (4 + 32 * n) + 35 * worst_m
    return wire, worst_m, wots, k, k + worst_m - 1


def _feasible(capacity, group_sizes, budgets):
    """Brute-force every feasible (storage, modes, sizes, total, steps,
    peak, nodes, hashes, verify) using per-subset worst cases."""
    required = max([capacity, *group_sizes])
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
            per_group = {
                mode: [
                    _worst_for_group(candidate_w, candidate_h, k, mode)
                    for k in group_sizes
                ]
                for mode in ("batch", "multiproof")
            }
            for choices in product((0, 1), repeat=len(group_sizes)):
                modes = []
                sizes = []
                nodes = 0
                verify_entries = []
                for choice, k in zip(choices, group_sizes):
                    mode = "multiproof" if choice else "batch"
                    size, node_count, wots, leaf, internal = per_group[mode][
                        len(modes)
                    ]
                    modes.append(mode)
                    sizes.append(size)
                    nodes += node_count
                    verify_entries.append(
                        (mode, wots, leaf, internal, wots + leaf + internal)
                    )
                modes = tuple(modes)
                peak = max(sizes)
                total = sum(sizes)
                hashes = sum(entry[4] for entry in verify_entries)
                measured = (
                    storage.checkpoint_bytes,
                    peak,
                    total,
                    steps,
                    nodes,
                    hashes,
                )
                if any(
                    limit is not None and value > limit
                    for value, limit in zip(measured, budgets)
                ):
                    continue
                verify = MerkleVerifyWorkloadProfile(
                    w=candidate_w,
                    height=candidate_h,
                    costs=tuple(verify_entries),
                    total=hashes,
                )
                candidates.append(
                    (storage, modes, tuple(sizes), total, steps, peak, nodes, hashes, verify)
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
            no_worse = all(o <= c for o, c in zip(_costs(other), _costs(candidate)))
            strictly_better = any(o < c for o, c in zip(_costs(other), _costs(candidate)))
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
    def test_matches_brute_force(self):
        # small trees so the subset enumeration in the reference is fast
        workloads = (
            (1, (1,), (None, None, None, 10_000_000, None, None)),
            (4, _SIZES, (None, None, None, 9000, None, None)),
            (4, _SIZES, (None, None, None, None, None, 4000)),
            (8, (1, 2, 3), (None, None, None, 9000, None, None)),
            (2, (2, 2), (None, 5000, None, None, None, None)),
            (4, (3,), (None, None, None, 9000, 3, None)),
            (4, _SIZES, (60000, 5000, 8000, 9000, None, None)),
            (16, (4, 2), (None, None, 30000, None, None, None)),
        )
        for capacity, group_sizes, budgets in workloads:
            with self.subTest(capacity=capacity, group_sizes=group_sizes, budgets=budgets):
                result = merkle_cardinality_frontier(capacity, group_sizes, budgets)
                self.assertEqual(
                    result, _expected_frontier(capacity, group_sizes, budgets)
                )

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
            self.assertEqual(len(mode_cost.cost.costs), len(_SIZES))
            self.assertEqual(mode_cost.cost.total, sum(c[4] for c in mode_cost.cost.costs))

    def test_cost_modes_align_with_plan(self):
        result = merkle_cardinality_frontier(
            4, _SIZES, (None, None, None, 10_000_000, None, None)
        )
        for mode_cost in result:
            cost_modes = tuple(entry[0] for entry in mode_cost.cost.costs)
            self.assertEqual(cost_modes, mode_cost.plan.modes)
            for k, entry in zip(_SIZES, mode_cost.cost.costs):
                _mode, wots, leaf, internal, group_total = entry
                self.assertEqual(leaf, k)
                self.assertEqual(group_total, wots + leaf + internal)

    def test_repeated_group_sizes_billed_separately(self):
        result = merkle_cardinality_frontier(
            4, (2, 2), (None, None, None, 9000, None, None)
        )
        for mode_cost in result:
            self.assertEqual(
                mode_cost.plan.total,
                mode_cost.plan.sizes[0] + mode_cost.plan.sizes[1],
            )
            self.assertEqual(
                mode_cost.nodes,
                sum(
                    _worst_for_group(
                        mode_cost.plan.config.w,
                        mode_cost.plan.config.height,
                        2,
                        mode,
                    )[1]
                    for mode in mode_cost.plan.modes
                ),
            )
            self.assertEqual(
                mode_cost.cost.total,
                sum(entry[4] for entry in mode_cost.cost.costs),
            )
            # identical same-mode groups carry identical costs
            if mode_cost.plan.modes[0] == mode_cost.plan.modes[1]:
                self.assertEqual(
                    mode_cost.plan.sizes[0], mode_cost.plan.sizes[1]
                )

    def test_worst_matches_subset_enumeration(self):
        for height in range(1, 9):
            leaf_count = 1 << height
            for k in range(1, leaf_count + 1):
                if comb(leaf_count, k) > _ENUMERATION_LIMIT:
                    continue
                expected = max(
                    len(_canonical_multiproof_nodes(indices, height))
                    for indices in combinations(range(leaf_count), k)
                )
                self.assertEqual(_worst_multiproof_nodes(height, k), expected)
                # the constructed realising subset attains the same bound and
                # also maximises the internal hash count
                realized = _dp_worst_set(height, k)
                self.assertEqual(
                    len(_canonical_multiproof_nodes(realized, height)), expected
                )
                internal = sum(
                    len({i >> level for i in realized})
                    for level in range(1, height + 1)
                )
                self.assertEqual(internal, k + expected - 1)
        # full tree carries no sibling nodes
        for height in range(1, 9):
            self.assertEqual(_worst_multiproof_nodes(height, 1 << height), 0)
        # one leaf always carries one sibling per level
        for height in range(1, 9):
            self.assertEqual(_worst_multiproof_nodes(height, 1), height)

    def test_worst_sizes_match_real_blobs(self):
        group_sizes = (1, 2, 3)
        result = merkle_cardinality_frontier(
            8, group_sizes, (None, None, None, 9000, None, None)
        )
        for mode_cost in result:
            w = mode_cost.plan.config.w
            height = mode_cost.plan.config.height
            signer = MerkleSigner(w=w, height=height)
            signatures = tuple(signer.sign(b"m%d" % i) for i in range(8))
            for mode, size, k in zip(mode_cost.plan.modes, mode_cost.plan.sizes, group_sizes):
                indices = _dp_worst_set(height, k)
                chosen = tuple(signatures[index] for index in indices)
                if mode == "batch":
                    from pqattest import MerkleBatchProof

                    blob = MerkleBatchProof(
                        public_key=signer.public_key, signatures=chosen
                    ).to_bytes()
                    self.assertEqual(len(blob), size)
                else:
                    blob = multiproof_encode(signer.public_key, chosen)
                    self.assertEqual(len(blob), size)

    def test_hashes_budget_inclusive_and_filters(self):
        result = merkle_cardinality_frontier(
            4, _SIZES, (None, None, None, None, None, 4000)
        )
        self.assertTrue(result)
        for mode_cost in result:
            self.assertLessEqual(mode_cost.cost.total, 4000)
        exact = merkle_cardinality_frontier(
            4,
            _SIZES,
            (None, None, None, None, None, max(mc.cost.total for mc in result)),
        )
        self.assertEqual(exact, result)
        with self.assertRaises(ValueError):
            merkle_cardinality_frontier(
                4,
                _SIZES,
                (None, None, None, None, None, min(mc.cost.total for mc in result) - 1),
            )

    def test_all_budgets_inclusive(self):
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

    def test_every_mode_combination_participates(self):
        feasible_modes = {
            modes
            for _s, modes, _sz, _t, _st, _p, _n, _h, _v in _feasible(
                4, _SIZES, (None, None, None, 9000, None, None)
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

    def test_every_result_feasible_and_non_dominated(self):
        capacity, group_sizes, budgets = 4, _SIZES, (None, 5000, None, 9000, None, None)
        result = merkle_cardinality_frontier(capacity, group_sizes, budgets)
        feasible = _feasible(capacity, group_sizes, budgets)
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
            value_costs = (
                mode_cost.plan.config.checkpoint_bytes,
                max(mode_cost.plan.sizes),
                mode_cost.plan.total,
                profile(
                    "merkle",
                    w=mode_cost.plan.config.w,
                    height=mode_cost.plan.config.height,
                ).steps,
                mode_cost.nodes,
                mode_cost.cost.total,
            )
            for other in feasible:
                if _costs(other) == value_costs:
                    continue
                no_worse = all(o <= c for o, c in zip(_costs(other), value_costs))
                strictly_better = any(o < c for o, c in zip(_costs(other), value_costs))
                self.assertFalse(no_worse and strictly_better)

    def test_results_sorted_by_documented_order(self):
        result = merkle_cardinality_frontier(
            4, _SIZES, (None, None, None, 10_000_000, None, None)
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
        result = merkle_cardinality_frontier(
            4, _SIZES, (None, None, None, 10_000_000, None, None)
        )
        self.assertEqual(len(result), len(set(result)))

    def test_frozen_positional_equal_hash(self):
        result = merkle_cardinality_frontier(
            4, _SIZES, (None, None, None, 9000, None, None)
        )
        mode_cost = result[0]
        rebuilt = MerkleModeCost(mode_cost.plan, mode_cost.cost, mode_cost.nodes)
        self.assertEqual(rebuilt, mode_cost)
        self.assertEqual(hash(rebuilt), hash(mode_cost))
        self.assertIn(mode_cost, {rebuilt})
        with self.assertRaises(Exception):
            mode_cost.nodes = 9  # type: ignore[misc]

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            merkle_cardinality_frontier(1, (1,), (100, None, None, None, None, None))
        # k=256 is coverable at height 8 but 256 leaves' W-OTS work alone is
        # 256*67*15 = 257_280 hashes, so a tight hash budget leaves no plan
        with self.assertRaises(ValueError):
            merkle_cardinality_frontier(
                1, (256,), (None, None, None, None, None, 100_000)
            )
        # group size 257 fits no candidate tree at all
        with self.assertRaises(ValueError):
            merkle_cardinality_frontier(1, (257,), (None, None, None, 9000, None, None))
        with self.assertRaises(ValueError):
            merkle_cardinality_frontier(1, (1,), (None, None, 10, None, None, None))
        with self.assertRaises(ValueError):
            merkle_cardinality_frontier(1, (1,), (None, None, None, None, None, 100))

    def test_group_sizes_must_be_tuple(self):
        for bad in ([1], {1}, "sizes", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_cardinality_frontier(
                        4, bad, (None, None, None, 9000, None, None)
                    )

    def test_group_size_value_errors(self):
        for bad in ((), (0,), (-1,), (True,), (False,), (1, 0), (2, -1)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_cardinality_frontier(4, bad, (None, None, None, 9000, None, None))

    def test_group_size_member_type_errors(self):
        for bad in ((1.5,), ("1",), (2, None), (1.0,)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_cardinality_frontier(4, bad, (None, None, None, 9000, None, None))

    def test_budgets_must_be_tuple(self):
        for bad in ([None] * 6, "budget", None, 7, {1, 2}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_cardinality_frontier(4, _SIZES, bad)

    def test_budgets_length(self):
        for bad in ((), (None,), (None,) * 5, (None,) * 7):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_cardinality_frontier(4, _SIZES, bad)

    def test_budget_members_validated(self):
        for bad_member in (0, -1, True, 1.5, "100"):
            for position in range(6):
                bad_budget = [None] * 6
                bad_budget[position] = bad_member
                with self.subTest(bad_member=bad_member, position=position):
                    with self.assertRaises(ValueError):
                        merkle_cardinality_frontier(4, _SIZES, tuple(bad_budget))

    def test_at_least_one_budget_required(self):
        with self.assertRaises(ValueError):
            merkle_cardinality_frontier(4, _SIZES, (None,) * 6)

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_cardinality_frontier(
                        bad, _SIZES, (None, None, None, 9000, None, None)
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

    def test_old_verify_mode_frontier_unchanged(self):
        result = merkle_cardinality_frontier  # exported
        self.assertTrue(callable(result))
        from pqattest import merkle_verify_mode_frontier

        legacy = merkle_verify_mode_frontier(
            4, ((0,), (2, 3)), (None, None, None, 9000, None, None)
        )
        self.assertTrue(legacy)
        self.assertIsInstance(legacy[0], MerkleModeCost)


if __name__ == "__main__":
    unittest.main()

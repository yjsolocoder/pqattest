import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleModeCost,
    MerkleSigner,
    merkle_verify_mode_frontier,
    profile,
    recommend_merkle_verify_mode_deployment,
)

_GROUPS = ((0, 1), (3, 5))
_BUDGETS = (None, 5000, 12000, None, 8, None)
_PREFERS = ("compact", "verify", "nodes", "speed", "robust")


def _metrics(mode_cost):
    return (
        mode_cost.plan.total,
        max(mode_cost.plan.sizes),
        mode_cost.cost.total,
        mode_cost.nodes,
        profile(
            "merkle", w=mode_cost.plan.config.w, height=mode_cost.plan.config.height
        ).steps,
    )


def _tail(mode_cost):
    config = mode_cost.plan.config
    return (
        config.checkpoint_bytes,
        config.leaf_count,
        config.w,
        config.height,
        mode_cost.plan.modes,
    )


def _expected(capacity, groups, budgets, *, prefer):
    """Rank merkle_verify_mode_frontier's survivors by the documented preference."""
    frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
    if prefer == "robust":
        columns = tuple(
            [_metrics(mode_cost)[i] for mode_cost in frontier] for i in range(5)
        )
        spans = tuple((min(column), max(column)) for column in columns)

        def key(mode_cost):
            normalised = []
            for value, (low, high) in zip(_metrics(mode_cost), spans):
                normalised.append(
                    Fraction(value - low, high - low) if high > low else Fraction(0)
                )
            return (max(normalised), sum(normalised, Fraction(0)), *_tail(mode_cost))

    else:
        def key(mode_cost):
            total, peak, hashes, nodes, steps = _metrics(mode_cost)
            if prefer == "compact":
                order = (total, peak, hashes, nodes, steps)
            elif prefer == "verify":
                order = (hashes, steps, total, peak, nodes)
            elif prefer == "nodes":
                order = (nodes, total, hashes, peak, steps)
            else:  # speed
                order = (steps, hashes, total, peak, nodes)
            return (*order, *_tail(mode_cost))

    return min(frontier, key=key)


class RecommendMerkleVerifyModeDeploymentTest(unittest.TestCase):
    def test_default_prefers_compact(self):
        explicit = recommend_merkle_verify_mode_deployment(
            16, _GROUPS, _BUDGETS, prefer="compact"
        )
        defaulted = recommend_merkle_verify_mode_deployment(16, _GROUPS, _BUDGETS)
        self.assertEqual(defaulted, explicit)
        self.assertEqual(
            defaulted, _expected(16, _GROUPS, _BUDGETS, prefer="compact")
        )

    def test_matches_brute_force_ranking(self):
        workloads = (
            (1, ((0,),), (None, None, None, None, None, 10**18)),
            (16, _GROUPS, _BUDGETS),
            (16, ((1,), (2,), (3,), (4,), (8,)), (None, None, None, None, None, 10**18)),
            (8, ((0,), (1, 2), (4,)), (9000, None, None, None, None, None)),
            (4, ((2,),), (None, 4000, None, None, None, None)),
            (4, ((0,), (1,)), (9000, None, 7000, None, 4, None)),
            (2, ((0,), (1,)), (None, None, None, None, None, 6000)),
            (32, ((0,), (6, 7), (15, 16)), (None, None, None, None, 50, None)),
        )
        for prefer in _PREFERS:
            for capacity, groups, budgets in workloads:
                with self.subTest(
                    prefer=prefer,
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                ):
                    result = recommend_merkle_verify_mode_deployment(
                        capacity, groups, budgets, prefer=prefer
                    )
                    self.assertEqual(
                        result,
                        _expected(capacity, groups, budgets, prefer=prefer),
                    )

    def test_returns_mode_cost_on_the_frontier(self):
        frontier = merkle_verify_mode_frontier(16, _GROUPS, _BUDGETS)
        for prefer in _PREFERS:
            with self.subTest(prefer=prefer):
                result = recommend_merkle_verify_mode_deployment(
                    16, _GROUPS, _BUDGETS, prefer=prefer
                )
                self.assertIsInstance(result, MerkleModeCost)
                self.assertIn(result, frontier)

    def test_compact_minimises_total_then_peak(self):
        frontier = merkle_verify_mode_frontier(16, _GROUPS, _BUDGETS)
        result = recommend_merkle_verify_mode_deployment(16, _GROUPS, _BUDGETS)
        self.assertEqual(result.plan.total, min(mc.plan.total for mc in frontier))
        smallest_total = result.plan.total
        peak_candidates = [
            mc for mc in frontier if mc.plan.total == smallest_total
        ]
        self.assertEqual(
            max(result.plan.sizes),
            min(max(mc.plan.sizes) for mc in peak_candidates),
        )

    def test_verify_minimises_hashes_then_steps(self):
        frontier = merkle_verify_mode_frontier(
            16, ((1,), (2,), (3,), (4,)), (None, None, None, None, None, 10**18)
        )
        result = recommend_merkle_verify_mode_deployment(
            16,
            ((1,), (2,), (3,), (4,)),
            (None, None, None, None, None, 10**18),
            prefer="verify",
        )
        self.assertEqual(
            result.cost.total, min(mc.cost.total for mc in frontier)
        )
        smallest = result.cost.total
        steps_candidates = [mc for mc in frontier if mc.cost.total == smallest]
        steps = lambda mc: profile(
            "merkle", w=mc.plan.config.w, height=mc.plan.config.height
        ).steps
        self.assertEqual(steps(result), min(steps(mc) for mc in steps_candidates))

    def test_nodes_minimises_carried_nodes(self):
        frontier = merkle_verify_mode_frontier(
            8, ((0,), (1, 2), (4,)), (None, None, None, None, None, 10**18)
        )
        result = recommend_merkle_verify_mode_deployment(
            8,
            ((0,), (1, 2), (4,)),
            (None, None, None, None, None, 10**18),
            prefer="nodes",
        )
        self.assertEqual(result.nodes, min(mc.nodes for mc in frontier))

    def test_speed_minimises_steps(self):
        frontier = merkle_verify_mode_frontier(16, _GROUPS, _BUDGETS)
        result = recommend_merkle_verify_mode_deployment(
            16, _GROUPS, _BUDGETS, prefer="speed"
        )
        steps = [
            profile("merkle", w=mc.plan.config.w, height=mc.plan.config.height).steps
            for mc in frontier
        ]
        self.assertEqual(
            profile(
                "merkle", w=result.plan.config.w, height=result.plan.config.height
            ).steps,
            min(steps),
        )

    def test_robust_minimax_normalised_costs_exactly(self):
        capacity, groups = 8, ((0,), (1, 2), (4,))
        budgets = (None, None, None, None, None, 10**18)
        frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
        result = recommend_merkle_verify_mode_deployment(
            capacity, groups, budgets, prefer="robust"
        )
        columns = tuple(
            [_metrics(mc)[i] for mc in frontier] for i in range(5)
        )
        spans = tuple((min(col), max(col)) for col in columns)

        def normalised(mc):
            return tuple(
                Fraction(v - lo, hi - lo) if hi > lo else Fraction(0)
                for v, (lo, hi) in zip(_metrics(mc), spans)
            )

        chosen = normalised(result)
        for mc in frontier:
            other = normalised(mc)
            self.assertLessEqual(
                max(chosen),
                max(other),
            )
        best_max = max(chosen)
        ties = [mc for mc in frontier if max(normalised(mc)) == best_max]
        self.assertEqual(
            sum(chosen, Fraction(0)),
            min(sum(normalised(mc), Fraction(0)) for mc in ties),
        )

    def test_robust_zero_span_dimension_scores_zero(self):
        # a single-member frontier makes every span zero: robust must still
        # pick that unique member without dividing by zero
        budgets = (None, None, 2243, None, None, 2000)
        frontier = merkle_verify_mode_frontier(1, ((0,),), budgets)
        self.assertEqual(len(frontier), 1)
        only = recommend_merkle_verify_mode_deployment(
            1, ((0,),), budgets, prefer="robust"
        )
        self.assertEqual(only, frontier[0])

    def test_different_preferences_can_disagree(self):
        capacity, groups = 8, ((0,), (1, 2), (4,))
        budgets = (None, None, None, None, None, 10**18)
        compact = recommend_merkle_verify_mode_deployment(
            capacity, groups, budgets, prefer="compact"
        )
        speed = recommend_merkle_verify_mode_deployment(
            capacity, groups, budgets, prefer="speed"
        )
        # compact never has more aggregate bytes than speed does, and speed
        # never needs more chain steps than compact does
        self.assertLessEqual(compact.plan.total, speed.plan.total)
        compact_steps = profile(
            "merkle", w=compact.plan.config.w, height=compact.plan.config.height
        ).steps
        speed_steps = profile(
            "merkle", w=speed.plan.config.w, height=speed.plan.config.height
        ).steps
        self.assertLessEqual(speed_steps, compact_steps)

    def test_budgets_are_honoured(self):
        capacity, groups = 16, _GROUPS
        budgets = (None, 3000, 6000, 9000, 5, 10**9)
        for prefer in _PREFERS:
            result = recommend_merkle_verify_mode_deployment(
                capacity, groups, budgets, prefer=prefer
            )
            self.assertTrue(all(size <= 3000 for size in result.plan.sizes))
            self.assertLessEqual(result.plan.total, 6000)
            self.assertLessEqual(
                profile(
                    "merkle",
                    w=result.plan.config.w,
                    height=result.plan.config.height,
                ).steps,
                9000,
            )
            self.assertLessEqual(result.nodes, 5)
            self.assertLessEqual(result.cost.total, 10**9)

    def test_frontier_called_once_no_duplicate_enumeration(self):
        calls = 0
        original = merkle_verify_mode_frontier

        import pqattest.params as params_module

        def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)

        params_module.merkle_verify_mode_frontier = counting
        try:
            for prefer in _PREFERS:
                calls = 0
                recommend_merkle_verify_mode_deployment(
                    16, _GROUPS, _BUDGETS, prefer=prefer
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_verify_mode_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment(
                1, ((0,),), (100, None, None, None, None, None)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment(
                1, ((256,),), (None, None, None, None, None, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment(
                4, ((0,),), (None, None, None, None, None, 10)
            )

    def test_invalid_prefer_raises(self):
        for bad in (
            "size",
            "batch",
            "multiproof",
            "",
            "COMPACT",
            " speed",
            "robustness",
            7,
            None,
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_verify_mode_deployment(
                        16, _GROUPS, _BUDGETS, prefer=bad
                    )

    def test_invalid_arguments_match_frontier(self):
        # capacity / groups / budgets are validated by the frontier
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    recommend_merkle_verify_mode_deployment(
                        bad_capacity, _GROUPS, _BUDGETS
                    )
        for bad_groups in ([(0, 1)], {(0, 1)}, "groups", None, 7, range(2)):
            with self.subTest(bad_groups=bad_groups):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_deployment(
                        16, bad_groups, _BUDGETS
                    )
        for bad_member in ([0, 1], "01", None, 7, {0, 1}):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_deployment(
                        16, ((0, 1), bad_member), _BUDGETS
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment(16, (), _BUDGETS)
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment(16, ((),), _BUDGETS)
        for bad_group in (((1, 0),), ((0, 0),), ((-1,),), ((True,),), ((1.5,),)):
            with self.subTest(bad_group=bad_group):
                with self.assertRaises(ValueError):
                    recommend_merkle_verify_mode_deployment(
                        16, bad_group, _BUDGETS
                    )
        for bad_budgets in ([None] * 6, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_deployment(
                        16, _GROUPS, bad_budgets
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment(
                16, _GROUPS, (None,) * 6
            )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment(
                16, _GROUPS, (None,) * 5
            )

    def test_arguments_validated_like_frontier_before_prefer(self):
        # the capacity/groups/budgets rules belong to the frontier and are
        # screened there, exactly like recommend_merkle_mode_deployment
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment(
                0, (), (None,) * 6, prefer="bogus"
            )
        with self.assertRaises(TypeError):
            recommend_merkle_verify_mode_deployment(
                16, [(0, 1)], _BUDGETS, prefer="bogus"
            )

    def test_first_three_arguments_have_no_defaults(self):
        sig = inspect.signature(recommend_merkle_verify_mode_deployment)
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "groups", "budgets", "prefer"],
        )
        for name in ("capacity", "groups", "budgets"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)
        self.assertEqual(sig.parameters["prefer"].default, "compact")

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        for prefer in _PREFERS:
            first = recommend_merkle_verify_mode_deployment(
                16, _GROUPS, _BUDGETS, prefer=prefer
            )
            second = recommend_merkle_verify_mode_deployment(
                16, _GROUPS, _BUDGETS, prefer=prefer
            )
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

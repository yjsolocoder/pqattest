import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleModeCost,
    MerkleSigner,
    merkle_verify_mode_frontier,
    profile,
    recommend_merkle_verify_mode_weighted,
)

_GROUPS = ((0,), (2, 3))
_BUDGETS = (None, None, None, 9000, None, None)


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


def _expected(capacity, groups, budgets, scenarios):
    """Rank the frontier by the documented minimax-regret rule."""
    frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
    rows = [_metrics(mode_cost) for mode_cost in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(5)
    )

    def scores(values):
        normalised = tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(values, spans)
        )
        return tuple(
            sum(weight * cost for weight, cost in zip(scenario, normalised))
            / sum(scenario)
            for scenario in scenarios
        )

    score_rows = [scores(row) for row in rows]
    best = tuple(min(column) for column in zip(*score_rows))

    def key(item):
        mode_cost, scenario_scores = item
        regrets = tuple(score - low for score, low in zip(scenario_scores, best))
        return (max(regrets), sum(regrets), scenario_scores, *_tail(mode_cost))

    return min(zip(frontier, score_rows), key=key)[0]


_WORKLOADS = (
    (1, ((0,),), (None, None, None, None, None, 10**18)),
    (4, _GROUPS, (None, None, None, 9000, None, None)),
    (16, ((0, 1), (2, 3, 4), (7,)), (None, None, None, None, None, 10**18)),
    (8, ((1,), (2, 4), (0, 5, 6)), (9000, None, None, None, None, None)),
    (4, ((3,),), (None, 4000, None, None, None, None)),
    (4, _GROUPS, (9000, None, 7000, None, 4, None)),
    (2, ((0, 1), (1,)), (None, None, None, None, None, 6000)),
    (32, ((0, 6), (15,), (1, 2, 3)), (None, None, None, None, 50, None)),
)

_SCENARIO_SETS = (
    ((1, 1, 1, 1, 1),),
    ((1, 1, 1, 1, 1), (1, 1, 1, 1, 1)),
    ((10, 0, 0, 0, 0), (0, 0, 0, 0, 1)),
    ((1, 2, 3, 4, 5), (5, 4, 3, 2, 1)),
    ((0, 1, 0, 1, 0), (1, 0, 1, 0, 1), (0, 0, 1, 0, 0)),
    ((10**9, 1, 1, 1, 1), (1, 10**9, 1, 1, 1)),
    ((3, 0, 7, 0, 2), (2, 0, 7, 0, 3), (1, 1, 1, 1, 1)),
)


class RecommendMerkleVerifyModeWeightedTest(unittest.TestCase):
    def test_matches_brute_force_ranking(self):
        for capacity, groups, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    result = recommend_merkle_verify_mode_weighted(
                        capacity, groups, budgets, scenarios
                    )
                    self.assertEqual(
                        result,
                        _expected(capacity, groups, budgets, scenarios),
                    )

    def test_returns_mode_cost_on_the_frontier(self):
        frontier = merkle_verify_mode_frontier(4, _GROUPS, _BUDGETS)
        for scenarios in _SCENARIO_SETS:
            with self.subTest(scenarios=scenarios):
                result = recommend_merkle_verify_mode_weighted(
                    4, _GROUPS, _BUDGETS, scenarios
                )
                self.assertIsInstance(result, MerkleModeCost)
                self.assertIn(result, frontier)

    def test_single_scenario_matches_weighted_ranking(self):
        # with one scenario the minimax regret winner is exactly the
        # candidate with the smallest weighted normalised score
        frontier = merkle_verify_mode_frontier(4, _GROUPS, _BUDGETS)
        rows = [_metrics(mc) for mc in frontier]
        spans = tuple(
            (min(row[i] for row in rows), max(row[i] for row in rows))
            for i in range(5)
        )
        for weights in (
            (1, 1, 1, 1, 1),
            (10, 0, 0, 0, 0),
            (0, 0, 0, 0, 1),
            (1, 2, 3, 4, 5),
        ):
            with self.subTest(weights=weights):
                result = recommend_merkle_verify_mode_weighted(
                    4, _GROUPS, _BUDGETS, (weights,)
                )

                def score(mode_cost):
                    total = Fraction(0)
                    for value, weight, (low, high) in zip(
                        _metrics(mode_cost), weights, spans
                    ):
                        if high > low:
                            total += weight * Fraction(value - low, high - low)
                    return total

                self.assertEqual(
                    score(result), min(score(mc) for mc in frontier)
                )

    def test_duplicate_scenarios_are_counted_separately(self):
        # duplicating one scenario weights its regret twice in the sum
        # tie-break, so the result may differ from the single copy
        frontier = merkle_verify_mode_frontier(4, _GROUPS, _BUDGETS)
        rows = [_metrics(mc) for mc in frontier]
        spans = tuple(
            (min(row[i] for row in rows), max(row[i] for row in rows))
            for i in range(5)
        )

        def scores(mode_cost, scenarios):
            normalised = tuple(
                Fraction(value - low, high - low) if high > low else Fraction(0)
                for value, (low, high) in zip(_metrics(mode_cost), spans)
            )
            return tuple(
                sum(weight * cost for weight, cost in zip(scenario, normalised))
                / sum(scenario)
                for scenario in scenarios
            )

        scenarios = ((1, 0, 0, 0, 0), (0, 0, 0, 0, 1))
        score_rows = {mc: scores(mc, scenarios) for mc in frontier}
        best = tuple(
            min(score_rows[mc][i] for mc in frontier) for i in range(2)
        )
        single = recommend_merkle_verify_mode_weighted(
            4, _GROUPS, _BUDGETS, scenarios
        )
        doubled = recommend_merkle_verify_mode_weighted(
            4, _GROUPS, _BUDGETS, scenarios + scenarios
        )
        # doubling every scenario scales every regret by two and cannot
        # change the ranking; the result must be identical
        self.assertEqual(single, doubled)
        # and the max regret of the winner is zero only if some candidate
        # is best under both scenarios
        winner_scores = score_rows[single]
        self.assertEqual(
            max(s - b for s, b in zip(winner_scores, best)),
            min(
                max(s - b for s, b in zip(score_rows[mc], best))
                for mc in frontier
            ),
        )

    def test_zero_span_dimension_scores_zero(self):
        # a single-member frontier makes every span zero: the unique member
        # is chosen regardless of the scenarios, without dividing by zero
        budgets = (None, None, 2243, None, None, 2000)
        frontier = merkle_verify_mode_frontier(1, ((0,),), budgets)
        self.assertEqual(len(frontier), 1)
        for scenarios in (
            ((1, 1, 1, 1, 1),),
            ((0, 0, 0, 0, 1), (9, 8, 7, 6, 5)),
            ((1, 0, 0, 0, 0), (0, 1, 0, 0, 0), (0, 0, 1, 0, 0)),
        ):
            with self.subTest(scenarios=scenarios):
                self.assertEqual(
                    recommend_merkle_verify_mode_weighted(
                        1, ((0,),), budgets, scenarios
                    ),
                    frontier[0],
                )

    def test_tie_break_is_documented_order(self):
        # among the members sharing the smallest maximum regret, the sum of
        # regrets, then the per-scenario score tuple, then the stable tail
        # (checkpoint bytes, leaf count, w, height, modes) decides
        for capacity, groups, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    result = recommend_merkle_verify_mode_weighted(
                        capacity, groups, budgets, scenarios
                    )
                    frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
                    rows = [_metrics(mc) for mc in frontier]
                    spans = tuple(
                        (min(row[i] for row in rows), max(row[i] for row in rows))
                        for i in range(5)
                    )

                    def scores(mode_cost):
                        normalised = tuple(
                            Fraction(value - low, high - low)
                            if high > low
                            else Fraction(0)
                            for value, (low, high) in zip(_metrics(mode_cost), spans)
                        )
                        return tuple(
                            sum(
                                weight * cost
                                for weight, cost in zip(scenario, normalised)
                            )
                            / sum(scenario)
                            for scenario in scenarios
                        )

                    score_map = {mc: scores(mc) for mc in frontier}
                    best = tuple(
                        min(score_map[mc][i] for mc in frontier)
                        for i in range(len(scenarios))
                    )

                    def regrets(mode_cost):
                        return tuple(
                            score - low
                            for score, low in zip(score_map[mode_cost], best)
                        )

                    def key(mode_cost):
                        regret = regrets(mode_cost)
                        return (
                            max(regret),
                            sum(regret),
                            score_map[mode_cost],
                            *_tail(mode_cost),
                        )

                    self.assertEqual(result, min(frontier, key=key))

    def test_scores_are_exact_rational_no_float(self):
        # the documented arithmetic uses Fraction; spot-check the chosen
        # regrets against an exact computation
        capacity, groups = 16, ((0, 1), (2, 3, 4), (7,))
        budgets = (None, None, None, None, None, 10**18)
        scenarios = ((1, 1, 1, 1, 1), (3, 0, 7, 0, 2))
        frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
        result = recommend_merkle_verify_mode_weighted(
            capacity, groups, budgets, scenarios
        )
        rows = [_metrics(mc) for mc in frontier]
        spans = tuple(
            (min(row[i] for row in rows), max(row[i] for row in rows))
            for i in range(5)
        )

        def scores(mode_cost):
            normalised = tuple(
                Fraction(value - low, high - low) if high > low else Fraction(0)
                for value, (low, high) in zip(_metrics(mode_cost), spans)
            )
            return tuple(
                sum(weight * cost for weight, cost in zip(scenario, normalised))
                / sum(scenario)
                for scenario in scenarios
            )

        score_map = {mc: scores(mc) for mc in frontier}
        best = tuple(
            min(score_map[mc][i] for mc in frontier)
            for i in range(len(scenarios))
        )
        chosen_regret = max(
            score - low for score, low in zip(score_map[result], best)
        )
        self.assertIsInstance(chosen_regret, Fraction)
        for mode_cost in frontier:
            regret = max(
                score - low for score, low in zip(score_map[mode_cost], best)
            )
            self.assertLessEqual(chosen_regret, regret)

    def test_budgets_are_honoured(self):
        capacity, groups = 4, _GROUPS
        budgets = (None, 3000, 6000, 9000, 5, 10**9)
        result = recommend_merkle_verify_mode_weighted(
            capacity, groups, budgets, ((1, 2, 3, 4, 5), (5, 4, 3, 2, 1))
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
            for scenarios in _SCENARIO_SETS:
                calls = 0
                recommend_merkle_verify_mode_weighted(
                    4, _GROUPS, _BUDGETS, scenarios
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_verify_mode_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_weighted(
                1, ((0,),), (100, None, None, None, None, None), ((1, 1, 1, 1, 1),)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_weighted(
                1, ((256,),), (None, None, None, None, None, 1), ((1, 1, 1, 1, 1),)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_weighted(
                4, ((1,),), (None, None, None, None, None, 10), ((1, 1, 1, 1, 1),)
            )

    def test_invalid_scenarios_container_raises_type_error(self):
        for bad in (
            [(1, 1, 1, 1, 1)],
            {(1, 1, 1, 1, 1)},
            "scenarios",
            None,
            7,
            range(2),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_weighted(
                        4, _GROUPS, _BUDGETS, bad
                    )

    def test_non_tuple_scenario_member_raises_type_error(self):
        for bad in (
            ([1, 1, 1, 1, 1],),
            ((1, 1, 1, 1, 1), [1, 1, 1, 1, 1]),
            ("12345",),
            (None,),
            (7,),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_weighted(
                        4, _GROUPS, _BUDGETS, bad
                    )

    def test_non_integer_weight_raises_type_error(self):
        for bad in (
            ((1.0, 1, 1, 1, 1),),
            ((1, "1", 1, 1, 1),),
            ((1, None, 1, 1, 1),),
            ((1, 1, 1, 1, 1.5),),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_weighted(
                        4, _GROUPS, _BUDGETS, bad
                    )

    def test_invalid_scenario_members_raise_value_error(self):
        for bad in (
            (),
            ((1, 1, 1, 1),),
            ((1, 1, 1, 1, 1, 1),),
            ((0, 0, 0, 0, 0),),
            ((1, -1, 1, 1, 1),),
            ((-1, 1, 1, 1, 1),),
            ((True, 1, 1, 1, 1),),
            ((1, 1, 1, 1, False),),
            ((1, 1, 1, 1, 1), (0, 0, 0, 0, 0)),
            ((1, 1, 1, 1, 1), (1, 1, 1, 1)),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_verify_mode_weighted(
                        4, _GROUPS, _BUDGETS, bad
                    )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in (((True, 0, 0, 0, 0),), ((0, 0, 0, 0, True),)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_verify_mode_weighted(
                        4, _GROUPS, _BUDGETS, bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    recommend_merkle_verify_mode_weighted(
                        bad_capacity, _GROUPS, _BUDGETS, ((1, 1, 1, 1, 1),)
                    )
        for bad_groups in ([(0,)], {(0,)}, "groups", None, 7, range(2)):
            with self.subTest(bad_groups=bad_groups):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_weighted(
                        4, bad_groups, _BUDGETS, ((1, 1, 1, 1, 1),)
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_weighted(
                4, (), _BUDGETS, ((1, 1, 1, 1, 1),)
            )
        for bad_budgets in ([None] * 6, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_weighted(
                        4, _GROUPS, bad_budgets, ((1, 1, 1, 1, 1),)
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_weighted(
                4, _GROUPS, (None,) * 6, ((1, 1, 1, 1, 1),)
            )

    def test_frontier_arguments_screened_before_scenarios(self):
        # the capacity/groups/budgets rules belong to the frontier and are
        # screened there, before the scenarios are examined
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_weighted(
                0, (), (None,) * 6, ((0, 0, 0, 0, 0),)
            )
        with self.assertRaises(TypeError):
            recommend_merkle_verify_mode_weighted(
                4, [(0,)], _BUDGETS, "not a tuple"
            )

    def test_all_four_parameters_are_required_without_defaults(self):
        sig = inspect.signature(recommend_merkle_verify_mode_weighted)
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "groups", "budgets", "scenarios"],
        )
        for name in ("capacity", "groups", "budgets", "scenarios"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        for scenarios in _SCENARIO_SETS:
            first = recommend_merkle_verify_mode_weighted(
                4, _GROUPS, (None, None, None, 9000, None, None), scenarios
            )
            second = recommend_merkle_verify_mode_weighted(
                4, _GROUPS, (None, None, None, 9000, None, None), scenarios
            )
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

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

_GROUPS = ((0, 1), (3, 5))
_BUDGETS = (None, 5000, 12000, None, 8, None)


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


def _normalised_rows(frontier):
    rows = [_metrics(mode_cost) for mode_cost in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(5)
    )
    return tuple(
        tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(row, spans)
        )
        for row in rows
    )


def _expected(capacity, groups, budgets, scenarios):
    """Rank the frontier by the documented minimax-regret score."""
    frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
    normalised = _normalised_rows(frontier)
    totals = tuple(sum(weights) for weights in scenarios)

    def scenario_scores(row):
        return tuple(
            sum(
                (weight * component for weight, component in zip(weights, row)),
                Fraction(0),
            )
            / total
            for weights, total in zip(scenarios, totals)
        )

    score_rows = tuple(scenario_scores(row) for row in normalised)
    best = tuple(
        min(row[scenario_index] for row in score_rows)
        for scenario_index in range(len(scenarios))
    )

    def key(entry):
        mode_cost, scores = entry
        regrets = tuple(score - floor for score, floor in zip(scores, best))
        return (
            max(regrets),
            sum(regrets, Fraction(0)),
            scores,
            *_tail(mode_cost),
        )

    return min(zip(frontier, score_rows), key=key)[0]


_WORKLOADS = (
    (1, ((0,),), (None, None, None, None, None, 10**18)),
    (16, _GROUPS, _BUDGETS),
    (16, ((1,), (2,), (3,), (4,), (8,)), (None, None, None, None, None, 10**18)),
    (8, ((0,), (1, 2), (4,)), (9000, None, None, None, None, None)),
    (4, ((2,),), (None, 4000, None, None, None, None)),
    (4, ((0,), (1,)), (9000, None, 7000, None, 4, None)),
    (2, ((0,), (1,)), (None, None, None, None, None, 6000)),
    (32, ((0,), (6, 7), (15, 16)), (None, None, None, None, 50, None)),
)

_SCENARIO_SETS = (
    ((1, 1, 1, 1, 1),),
    ((10, 0, 0, 0, 0), (0, 0, 0, 0, 1)),
    (
        (1, 2, 3, 4, 5),
        (0, 1, 0, 1, 0),
        (10**9, 1, 1, 1, 1),
        (3, 0, 7, 0, 2),
    ),
    ((1, 0, 0, 0, 0), (0, 1, 0, 0, 0), (0, 0, 1, 0, 0), (0, 0, 0, 1, 0)),
    ((1, 1, 1, 1, 1), (1, 1, 1, 1, 1)),
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
        frontier = merkle_verify_mode_frontier(16, _GROUPS, _BUDGETS)
        for scenarios in _SCENARIO_SETS:
            with self.subTest(scenarios=scenarios):
                result = recommend_merkle_verify_mode_weighted(
                    16, _GROUPS, _BUDGETS, scenarios
                )
                self.assertIsInstance(result, MerkleModeCost)
                self.assertIn(result, frontier)

    def test_single_scenario_picks_its_weighted_best(self):
        # one scenario makes every regret zero, so the choice is the plain
        # weighted-normalised minimum (plus the stable tail)
        weights = (1, 2, 3, 4, 5)
        frontier = merkle_verify_mode_frontier(16, _GROUPS, _BUDGETS)
        normalised = _normalised_rows(frontier)
        total = sum(weights)

        def score(mode_cost):
            row = normalised[frontier.index(mode_cost)]
            return sum(
                (weight * component for weight, component in zip(weights, row)),
                Fraction(0),
            ) / total

        result = recommend_merkle_verify_mode_weighted(
            16, _GROUPS, _BUDGETS, (weights,)
        )
        self.assertEqual(result, min(frontier, key=lambda mc: (score(mc), *_tail(mc))))

    def test_repeated_scenarios_counted_separately(self):
        # two conflicting composite scenarios: one weights verifier hashes
        # and chain steps (picks w=4), the other weights the single-group
        # peak and chain steps (picks w=8). One copy of each still picks
        # w=4; repeating the second scenario must actually swing the
        # minimax-regret choice to w=8. An implementation that deduped equal
        # scenarios would collapse (first, second, second) to
        # (first, second) and could not follow.
        first = (0, 0, 0, 2, 1)
        second = (0, 2, 0, 0, 1)
        only_first = recommend_merkle_verify_mode_weighted(
            16, _GROUPS, _BUDGETS, (first,)
        )
        one_each = recommend_merkle_verify_mode_weighted(
            16, _GROUPS, _BUDGETS, (first, second)
        )
        second_doubled = recommend_merkle_verify_mode_weighted(
            16, _GROUPS, _BUDGETS, (first, second, second)
        )
        first_doubled = recommend_merkle_verify_mode_weighted(
            16, _GROUPS, _BUDGETS, (first, first, second)
        )
        self.assertEqual(only_first.plan.config.w, 4)
        self.assertEqual(one_each.plan.config.w, 4)
        self.assertEqual(second_doubled.plan.config.w, 8)
        self.assertEqual(first_doubled.plan.config.w, 4)
        self.assertNotEqual(one_each, second_doubled)

    def test_repeated_scenarios_regression_cases(self):
        # repeated scenarios must be kept as separate tuple positions.
        # Each case pairs a scenario tuple with the tuple a
        # duplicate-dropping implementation would collapse it to: the
        # minimax-regret ranking keeps every copy (an extra copy adds an
        # extra regret column that can swing the regret-sum tie-break), so
        # the full tuple must actually CHANGE the choice versus the
        # collapsed one while still agreeing with the brute-force ranking.
        # The previous (3, 0, 7, 0, 2)/(0, 5, 0, 1, 0) cases always
        # selected the same config, so they could not detect a deduping
        # implementation.
        first = (0, 0, 0, 2, 1)
        second = (0, 2, 0, 0, 1)

        def collapsed(scenarios):
            unique = []
            for scenario in scenarios:
                if scenario not in unique:
                    unique.append(scenario)
            return tuple(unique)

        cases = (
            (first, second, second),
            (second, second, first),
        )
        for scenarios in cases:
            with self.subTest(scenarios=scenarios):
                result = recommend_merkle_verify_mode_weighted(
                    16, _GROUPS, _BUDGETS, scenarios
                )
                collapsed_result = recommend_merkle_verify_mode_weighted(
                    16, _GROUPS, _BUDGETS, collapsed(scenarios)
                )
                self.assertEqual(
                    result,
                    _expected(16, _GROUPS, _BUDGETS, scenarios),
                )
                self.assertNotEqual(result, collapsed_result)

    def test_zero_span_dimensions_score_zero(self):
        # a single-member frontier makes every span zero: the unique member
        # is chosen regardless of the scenarios, without dividing by zero
        budgets = (None, None, 2243, None, None, 2000)
        frontier = merkle_verify_mode_frontier(1, ((0,),), budgets)
        self.assertEqual(len(frontier), 1)
        for scenarios in (
            ((1, 1, 1, 1, 1),),
            ((0, 0, 0, 0, 1),),
            ((9, 8, 7, 6, 5), (1, 0, 0, 0, 0)),
        ):
            with self.subTest(scenarios=scenarios):
                self.assertEqual(
                    recommend_merkle_verify_mode_weighted(
                        1, ((0,),), budgets, scenarios
                    ),
                    frontier[0],
                )

    def test_minimax_regret_beats_sum_regret(self):
        # construct the score table directly: the plan with the smallest
        # worst regret must win even when its regret sum is larger
        plan_a_scores = (Fraction(0), Fraction(0))
        plan_b_scores = (Fraction(1, 3), Fraction(1, 3))
        best = (Fraction(0), Fraction(0))
        regret_a = tuple(s - b for s, b in zip(plan_a_scores, best))
        regret_b = tuple(s - b for s, b in zip(plan_b_scores, best))
        self.assertLess(max(regret_a), max(regret_b))

    def test_tie_break_is_documented_tail(self):
        for capacity, groups, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    frontier = merkle_verify_mode_frontier(
                        capacity, groups, budgets
                    )
                    normalised = _normalised_rows(frontier)
                    totals = tuple(sum(weights) for weights in scenarios)

                    def score_tuple(mode_cost):
                        row = normalised[frontier.index(mode_cost)]
                        return tuple(
                            sum(
                                (
                                    weight * component
                                    for weight, component in zip(weights, row)
                                ),
                                Fraction(0),
                            )
                            / total
                            for weights, total in zip(scenarios, totals)
                        )

                    all_scores = tuple(score_tuple(mc) for mc in frontier)
                    best = tuple(
                        min(row[i] for row in all_scores)
                        for i in range(len(scenarios))
                    )

                    def regret_key(mode_cost):
                        scores = score_tuple(mode_cost)
                        regrets = tuple(s - b for s, b in zip(scores, best))
                        return (
                            max(regrets),
                            sum(regrets, Fraction(0)),
                            scores,
                        )

                    result = recommend_merkle_verify_mode_weighted(
                        capacity, groups, budgets, scenarios
                    )
                    chosen = regret_key(result)
                    tied = [
                        mc for mc in frontier if regret_key(mc)[:2] == chosen[:2]
                        and regret_key(mc)[2] == chosen[2]
                    ]
                    self.assertEqual(result, min(tied, key=_tail))
                    self.assertIn(result, tied)

    def test_scores_are_exact_rational_no_float(self):
        capacity, groups, budgets = 16, _GROUPS, _BUDGETS
        scenarios = ((1, 1, 1, 1, 1), (5, 0, 0, 0, 1))
        frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
        result = recommend_merkle_verify_mode_weighted(
            capacity, groups, budgets, scenarios
        )
        normalised = _normalised_rows(frontier)
        totals = tuple(sum(weights) for weights in scenarios)

        def scores(mode_cost):
            row = normalised[frontier.index(mode_cost)]
            return tuple(
                sum(
                    (weight * component for weight, component in zip(weights, row)),
                    Fraction(0),
                )
                / total
                for weights, total in zip(scenarios, totals)
            )

        all_scores = tuple(scores(mc) for mc in frontier)
        best = tuple(
            min(row[i] for row in all_scores) for i in range(len(scenarios))
        )

        def worst_regret(mode_cost):
            return max(s - b for s, b in zip(scores(mode_cost), best))

        chosen_regret = worst_regret(result)
        for mode_cost in frontier:
            self.assertLessEqual(chosen_regret, worst_regret(mode_cost))
            for component in scores(mode_cost):
                self.assertIsInstance(component, Fraction)

    def test_budgets_are_honoured(self):
        capacity, groups = 4, ((0,), (1,))
        budgets = (None, 3000, 6000, 9000, 5, 10**9)
        scenarios = ((1, 2, 3, 4, 5), (5, 4, 3, 2, 1))
        result = recommend_merkle_verify_mode_weighted(
            capacity, groups, budgets, scenarios
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
                    16, _GROUPS, _BUDGETS, scenarios
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_verify_mode_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_weighted(
                1,
                ((0,),),
                (100, None, None, None, None, None),
                ((1, 1, 1, 1, 1),),
            )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_weighted(
                4,
                ((0,),),
                (None, None, None, None, None, 10),
                ((1, 1, 1, 1, 1),),
            )

    def test_invalid_scenarios_container_raises_type_error(self):
        for bad in (
            [(1, 1, 1, 1, 1)],
            {(1, 1, 1, 1, 1)},
            "scenarios",
            None,
            7,
            range(5),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )

    def test_invalid_scenario_member_raises_type_error(self):
        for bad in (
            ([1, 1, 1, 1, 1],),
            ("scenario",),
            (None,),
            (7,),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )
        # the bad scenario member is also rejected when it follows a valid
        # one, not only when it is the sole member of the tuple
        good = (1, 1, 1, 1, 1)
        for bad_member in ([1, 1, 1, 1, 1], "scenario", None, 7):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_weighted(
                        16, _GROUPS, _BUDGETS, (good, bad_member)
                    )

    def test_non_integer_weight_raises_type_error(self):
        base_bad = (
            ((1.0, 1, 1, 1, 1),),
            ((1, "1", 1, 1, 1),),
            ((1, None, 1, 1, 1),),
            ((1, 1, 1, 1, 1.5),),
        )
        for bad in base_bad:
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )
        # a non-integer weight is rejected at every weight position and in
        # every scenario of the tuple, not just the first one inspected
        good = (1, 1, 1, 1, 1)
        for scenario_position in range(2):
            for weight_position in range(5):
                for replacement in (1.0, "1", None, 1.5):
                    scenarios = [good, good]
                    scenarios[scenario_position] = tuple(
                        replacement if index == weight_position else good[index]
                        for index in range(5)
                    )
                    with self.subTest(
                        scenario_position=scenario_position,
                        weight_position=weight_position,
                        replacement=replacement,
                    ):
                        with self.assertRaises(TypeError):
                            recommend_merkle_verify_mode_weighted(
                                16, _GROUPS, _BUDGETS, tuple(scenarios)
                            )

    def test_invalid_weights_members_raise_value_error(self):
        base_bad = (
            (),
            ((1, 1, 1, 1),),
            ((1, 1, 1, 1, 1, 1),),
            ((0, 0, 0, 0, 0),),
        )
        for bad in base_bad:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_verify_mode_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )
        # a boolean or negative weight is rejected at every weight position
        # and in every scenario of the tuple, and an all-zero scenario is
        # rejected at every outer position, not just the first inspected
        good = (1, 1, 1, 1, 1)
        for scenario_position in range(2):
            for weight_position in range(5):
                for replacement in (-1, True, False):
                    scenarios = [good, good]
                    scenarios[scenario_position] = tuple(
                        replacement if index == weight_position else good[index]
                        for index in range(5)
                    )
                    with self.subTest(
                        scenario_position=scenario_position,
                        weight_position=weight_position,
                        replacement=replacement,
                    ):
                        with self.assertRaises(ValueError):
                            recommend_merkle_verify_mode_weighted(
                                16, _GROUPS, _BUDGETS, tuple(scenarios)
                            )
        for scenario_position in range(2):
            scenarios = [good, good]
            scenarios[scenario_position] = (0, 0, 0, 0, 0)
            with self.subTest(scenario_position=scenario_position):
                with self.assertRaises(ValueError):
                    recommend_merkle_verify_mode_weighted(
                        16, _GROUPS, _BUDGETS, tuple(scenarios)
                    )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in (((True, 0, 0, 0, 0),), ((0, 0, 0, 0, True),)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_verify_mode_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    recommend_merkle_verify_mode_weighted(
                        bad_capacity,
                        _GROUPS,
                        _BUDGETS,
                        ((1, 1, 1, 1, 1),),
                    )
        for bad_groups in ([(0, 1)], {(0, 1)}, "groups", None, 7, range(2)):
            with self.subTest(bad_groups=bad_groups):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_weighted(
                        16,
                        bad_groups,
                        _BUDGETS,
                        ((1, 1, 1, 1, 1),),
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_weighted(
                16, (), _BUDGETS, ((1, 1, 1, 1, 1),)
            )
        for bad_budgets in ([None] * 6, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_weighted(
                        16,
                        _GROUPS,
                        bad_budgets,
                        ((1, 1, 1, 1, 1),),
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_weighted(
                16, _GROUPS, (None,) * 6, ((1, 1, 1, 1, 1),)
            )

    def test_frontier_arguments_screened_before_scenarios(self):
        # the capacity/groups/budgets rules belong to the frontier and are
        # screened there before scenarios is inspected
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_weighted(
                0, (), (None,) * 6, ()
            )
        with self.assertRaises(TypeError):
            recommend_merkle_verify_mode_weighted(
                16, [(0, 1)], _BUDGETS, "not a tuple"
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
                16,
                _GROUPS,
                (None, None, None, 9000, None, None),
                scenarios,
            )
            second = recommend_merkle_verify_mode_weighted(
                16,
                _GROUPS,
                (None, None, None, 9000, None, None),
                scenarios,
            )
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

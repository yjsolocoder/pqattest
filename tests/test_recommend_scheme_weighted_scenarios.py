import inspect
import unittest
from fractions import Fraction

from pqattest import (
    Params,
    recommend_scheme_weighted_scenarios,
    scheme_frontier,
)

_BUDGET_CASES = (
    (None, 10**9),
    (10**9, None),
    (2048, None),
    (None, 1005),
    (None, 8670),
    (2300, 9000),
)

_SCENARIO_SETS = (
    ((1, 1),),
    ((1, 0), (0, 1)),
    ((2, 3), (3, 7), (10**9, 1)),
    ((1, 0), (0, 1), (1, 1)),
    ((1, 1), (1, 1)),
    ((0, 5), (7, 0), (2, 3)),
)


def _metrics(candidate):
    return (candidate.sig_bytes, candidate.steps)


def _tail(candidate, capacity):
    return (
        candidate.capacity - capacity,
        candidate.scheme,
        candidate.w is not None,
        candidate.w,
        candidate.height is not None,
        candidate.height,
    )


def _normalised_rows(frontier):
    rows = [_metrics(candidate) for candidate in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(2)
    )
    return tuple(
        tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(row, spans)
        )
        for row in rows
    )


def _expected(capacity, budgets, scenarios):
    """Rank the scheme frontier by the documented minimax-regret score."""
    frontier = scheme_frontier(capacity, budgets)
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
        candidate, scores = entry
        regrets = tuple(score - floor for score, floor in zip(scores, best))
        return (
            max(regrets),
            sum(regrets, Fraction(0)),
            scores,
            *_tail(candidate, capacity),
        )

    return min(zip(frontier, score_rows), key=key)[0]


class RecommendSchemeWeightedScenariosTest(unittest.TestCase):
    def test_matches_brute_force_ranking(self):
        for capacity in (1, 2, 3, 5, 16, 42, 100, 256):
            for budgets in _BUDGET_CASES:
                for scenarios in _SCENARIO_SETS:
                    with self.subTest(
                        capacity=capacity,
                        budgets=budgets,
                        scenarios=scenarios,
                    ):
                        try:
                            scheme_frontier(capacity, budgets)
                        except ValueError:
                            continue
                        self.assertEqual(
                            recommend_scheme_weighted_scenarios(
                                capacity, budgets, scenarios
                            ),
                            _expected(capacity, budgets, scenarios),
                        )

    def test_returns_params_member_of_the_frontier(self):
        frontier = scheme_frontier(1, (None, 10**9))
        for scenarios in _SCENARIO_SETS:
            with self.subTest(scenarios=scenarios):
                result = recommend_scheme_weighted_scenarios(
                    1, (None, 10**9), scenarios
                )
                self.assertIsInstance(result, Params)
                self.assertIn(result, frontier)

    def test_matches_frontier_member_field_for_field(self):
        for capacity in (1, 2, 16, 256):
            for budgets in _BUDGET_CASES:
                for scenarios in _SCENARIO_SETS:
                    with self.subTest(
                        capacity=capacity,
                        budgets=budgets,
                        scenarios=scenarios,
                    ):
                        try:
                            frontier = scheme_frontier(capacity, budgets)
                        except ValueError:
                            continue
                        result = recommend_scheme_weighted_scenarios(
                            capacity, budgets, scenarios
                        )
                        member = frontier[frontier.index(result)]
                        for field in Params.__dataclass_fields__:
                            self.assertEqual(
                                getattr(result, field), getattr(member, field)
                            )

    def test_single_scenario_picks_its_weighted_best(self):
        # one scenario makes every regret zero, so the choice is the plain
        # weighted-normalised average minimum (plus the stable tail)
        capacity, budgets, weights = 1, (None, 10**9), (2, 3)
        frontier = scheme_frontier(capacity, budgets)
        normalised = _normalised_rows(frontier)
        total = sum(weights)

        def score(candidate):
            row = normalised[frontier.index(candidate)]
            return sum(
                (weight * component for weight, component in zip(weights, row)),
                Fraction(0),
            ) / total

        result = recommend_scheme_weighted_scenarios(
            capacity, budgets, (weights,)
        )
        self.assertEqual(
            result,
            min(frontier, key=lambda c: (score(c), *_tail(c, capacity))),
        )

    def test_each_single_positive_weight_minimises_its_dimension(self):
        frontier = scheme_frontier(1, (None, 10**9))
        for dimension in range(2):
            weights = tuple(1 if i == dimension else 0 for i in range(2))
            with self.subTest(weights=weights):
                result = recommend_scheme_weighted_scenarios(
                    1, (None, 10**9), (weights,)
                )
                self.assertEqual(
                    _metrics(result)[dimension],
                    min(_metrics(candidate)[dimension] for candidate in frontier),
                )

    def test_repeated_scenarios_counted_separately(self):
        # two conflicting single-dimension scenarios: one minimises chain
        # steps (picks merkle w=4), the other minimises the signature size
        # (picks merkle w=8). Repeating the size scenario must actually
        # swing the minimax-regret choice; an implementation that deduped
        # equal scenarios would return the one-each result unchanged.
        capacity, budgets = 2, (None, 10**9)
        steps_only = (0, 1)
        size_only = (1, 0)
        only_steps = recommend_scheme_weighted_scenarios(
            capacity, budgets, (steps_only,)
        )
        one_each = recommend_scheme_weighted_scenarios(
            capacity, budgets, (steps_only, size_only)
        )
        size_doubled = recommend_scheme_weighted_scenarios(
            capacity, budgets, (steps_only, size_only, size_only)
        )
        steps_doubled = recommend_scheme_weighted_scenarios(
            capacity, budgets, (steps_only, steps_only, size_only)
        )
        self.assertEqual((only_steps.scheme, only_steps.w), ("merkle", 4))
        self.assertEqual((one_each.scheme, one_each.w), ("merkle", 4))
        self.assertEqual((size_doubled.scheme, size_doubled.w), ("merkle", 8))
        self.assertEqual((steps_doubled.scheme, steps_doubled.w), ("merkle", 4))
        self.assertNotEqual(one_each, size_doubled)

    def test_repeated_scenarios_regression_cases(self):
        # repeated scenarios must be kept as separate tuple positions:
        # every duplicated tuple must agree with the brute-force ranking
        # (which zips the scenarios position for position), exercising
        # both the max-regret and the regret-sum levels with duplicates
        first = (3, 1)
        second = (0, 5)
        cases = (
            (first, first, second),
            (first, second, second),
            (second, first, first),
            (second, second, first),
            (first, second, first, second),
        )
        for scenarios in cases:
            with self.subTest(scenarios=scenarios):
                result = recommend_scheme_weighted_scenarios(
                    1, (None, 10**9), scenarios
                )
                self.assertEqual(
                    result,
                    _expected(1, (None, 10**9), scenarios),
                )

    def test_zero_span_dimensions_score_zero(self):
        # a single-member frontier makes every span zero: the unique member
        # is chosen regardless of the scenarios, without dividing by zero
        budgets = (None, 1)
        frontier = scheme_frontier(1, budgets)
        self.assertEqual(len(frontier), 1)
        for scenarios in (
            ((1, 1),),
            ((0, 1),),
            ((9, 8), (1, 0)),
        ):
            with self.subTest(scenarios=scenarios):
                self.assertEqual(
                    recommend_scheme_weighted_scenarios(1, budgets, scenarios),
                    frontier[0],
                )

    def test_weight_scales_scenario_scores(self):
        # scaling every weight of a scenario by a constant leaves its
        # normalised score unchanged, hence leaves every regret unchanged
        scenarios = ((1, 2), (3, 0))
        scaled = (
            tuple(7 * weight for weight in scenarios[0]),
            tuple(11 * weight for weight in scenarios[1]),
        )
        self.assertEqual(
            recommend_scheme_weighted_scenarios(1, (None, 10**9), scenarios),
            recommend_scheme_weighted_scenarios(1, (None, 10**9), scaled),
        )

    def test_tie_break_is_documented_tail(self):
        for capacity in (1, 2, 3, 16, 42, 256):
            for budgets in _BUDGET_CASES:
                for scenarios in _SCENARIO_SETS:
                    with self.subTest(
                        capacity=capacity,
                        budgets=budgets,
                        scenarios=scenarios,
                    ):
                        try:
                            frontier = scheme_frontier(capacity, budgets)
                        except ValueError:
                            continue
                        normalised = _normalised_rows(frontier)
                        totals = tuple(sum(weights) for weights in scenarios)

                        def score_tuple(candidate):
                            row = normalised[frontier.index(candidate)]
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

                        all_scores = tuple(score_tuple(c) for c in frontier)
                        best = tuple(
                            min(row[i] for row in all_scores)
                            for i in range(len(scenarios))
                        )

                        def regret_key(candidate):
                            scores = score_tuple(candidate)
                            regrets = tuple(
                                s - b for s, b in zip(scores, best)
                            )
                            return (
                                max(regrets),
                                sum(regrets, Fraction(0)),
                                scores,
                            )

                        result = recommend_scheme_weighted_scenarios(
                            capacity, budgets, scenarios
                        )
                        chosen = regret_key(result)
                        tied = [
                            c for c in frontier if regret_key(c) == chosen
                        ]
                        self.assertEqual(
                            result,
                            min(tied, key=lambda c: _tail(c, capacity)),
                        )
                        self.assertIn(result, tied)

    def test_scores_are_exact_rational_no_float(self):
        scenarios = ((1, 1), (5, 0))
        frontier = scheme_frontier(1, (None, 10**9))
        result = recommend_scheme_weighted_scenarios(
            1, (None, 10**9), scenarios
        )
        normalised = _normalised_rows(frontier)
        totals = tuple(sum(weights) for weights in scenarios)

        def scores(candidate):
            row = normalised[frontier.index(candidate)]
            return tuple(
                sum(
                    (weight * component for weight, component in zip(weights, row)),
                    Fraction(0),
                )
                / total
                for weights, total in zip(scenarios, totals)
            )

        all_scores = tuple(scores(c) for c in frontier)
        best = tuple(
            min(row[i] for row in all_scores) for i in range(len(scenarios))
        )

        def worst_regret(candidate):
            return max(s - b for s, b in zip(scores(candidate), best))

        chosen_regret = worst_regret(result)
        for candidate in frontier:
            self.assertLessEqual(chosen_regret, worst_regret(candidate))
            for component in scores(candidate):
                self.assertIsInstance(component, Fraction)

    def test_budgets_are_honoured(self):
        budgets = (2200, 9000)
        result = recommend_scheme_weighted_scenarios(
            1, budgets, ((1, 1), (3, 2))
        )
        self.assertLessEqual(result.sig_bytes, 2200)
        self.assertLessEqual(result.steps, 9000)

    def test_frontier_called_once_no_duplicate_enumeration(self):
        calls = 0
        original = scheme_frontier

        import pqattest.params as params_module

        def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)

        params_module.scheme_frontier = counting
        try:
            for scenarios in _SCENARIO_SETS:
                calls = 0
                recommend_scheme_weighted_scenarios(
                    1, (None, 10**9), scenarios
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.scheme_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_scheme_weighted_scenarios(1, (100, None), ((1, 1),))
        with self.assertRaises(ValueError):
            recommend_scheme_weighted_scenarios(256, (1200, None), ((1, 1),))
        with self.assertRaises(ValueError):
            recommend_scheme_weighted_scenarios(2, (None, 1004), ((1, 1),))

    def test_invalid_scenarios_container_raises_type_error(self):
        for bad in ([(1, 1)], {(1, 1)}, "scenarios", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_scheme_weighted_scenarios(
                        1, (None, 10**9), bad
                    )

    def test_invalid_scenario_member_raises_type_error(self):
        for bad in (
            ([1, 1],),
            ("scenario",),
            (None,),
            (7,),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_scheme_weighted_scenarios(
                        1, (None, 10**9), bad
                    )
        # the bad scenario member is also rejected when it follows a valid
        # one, not only when it is the sole member of the tuple
        good = (1, 1)
        for bad_member in ([1, 1], "scenario", None, 7):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(TypeError):
                    recommend_scheme_weighted_scenarios(
                        1, (None, 10**9), (good, bad_member)
                    )

    def test_non_integer_weight_raises_type_error(self):
        base_bad = (
            ((1.0, 1),),
            ((1, "1"),),
            ((None, 1),),
            ((1, 1.5),),
        )
        for bad in base_bad:
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_scheme_weighted_scenarios(
                        1, (None, 10**9), bad
                    )
        # a non-integer weight is rejected at every weight position and in
        # every scenario of the tuple, not just the first one inspected
        good = (1, 1)
        for scenario_position in range(2):
            for weight_position in range(2):
                for replacement in (1.0, "1", None, 1.5):
                    scenarios = [good, good]
                    scenarios[scenario_position] = tuple(
                        replacement if index == weight_position else good[index]
                        for index in range(2)
                    )
                    with self.subTest(
                        scenario_position=scenario_position,
                        weight_position=weight_position,
                        replacement=replacement,
                    ):
                        with self.assertRaises(TypeError):
                            recommend_scheme_weighted_scenarios(
                                1, (None, 10**9), tuple(scenarios)
                            )

    def test_invalid_weights_members_raise_value_error(self):
        base_bad = (
            (),
            ((1,),),
            ((1, 1, 1),),
            ((0, 0),),
        )
        for bad in base_bad:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_scheme_weighted_scenarios(
                        1, (None, 10**9), bad
                    )
        # a boolean or negative weight is rejected at every weight position
        # and in every scenario of the tuple, and an all-zero scenario is
        # rejected at every outer position, not just the first inspected
        good = (1, 1)
        for scenario_position in range(2):
            for weight_position in range(2):
                for replacement in (-1, True, False):
                    scenarios = [good, good]
                    scenarios[scenario_position] = tuple(
                        replacement if index == weight_position else good[index]
                        for index in range(2)
                    )
                    with self.subTest(
                        scenario_position=scenario_position,
                        weight_position=weight_position,
                        replacement=replacement,
                    ):
                        with self.assertRaises(ValueError):
                            recommend_scheme_weighted_scenarios(
                                1, (None, 10**9), tuple(scenarios)
                            )
        for scenario_position in range(2):
            scenarios = [good, good]
            scenarios[scenario_position] = (0, 0)
            with self.subTest(scenario_position=scenario_position):
                with self.assertRaises(ValueError):
                    recommend_scheme_weighted_scenarios(
                        1, (None, 10**9), tuple(scenarios)
                    )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in (((True, 0),), ((0, True),)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_scheme_weighted_scenarios(
                        1, (None, 10**9), bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    recommend_scheme_weighted_scenarios(
                        bad_capacity, (None, 10**9), ((1, 1),)
                    )
        for bad_budgets in ([None, 1], "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    recommend_scheme_weighted_scenarios(
                        1, bad_budgets, ((1, 1),)
                    )
        with self.assertRaises(ValueError):
            recommend_scheme_weighted_scenarios(1, (None, None), ((1, 1),))
        with self.assertRaises(ValueError):
            recommend_scheme_weighted_scenarios(1, (None,), ((1, 1),))
        with self.assertRaises(ValueError):
            recommend_scheme_weighted_scenarios(1, (None, 1, None), ((1, 1),))
        for bad_member in (0, -1, True, 1.5, "100"):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    recommend_scheme_weighted_scenarios(
                        1, (None, bad_member), ((1, 1),)
                    )

    def test_frontier_arguments_screened_before_scenarios(self):
        # the capacity/budgets rules belong to the frontier and are
        # screened there before scenarios is inspected
        with self.assertRaises(ValueError):
            recommend_scheme_weighted_scenarios(0, (None, None), ())
        with self.assertRaises(TypeError):
            recommend_scheme_weighted_scenarios(
                1, [None, 1], "not a tuple"
            )

    def test_all_three_parameters_are_required_without_defaults(self):
        sig = inspect.signature(recommend_scheme_weighted_scenarios)
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "budgets", "scenarios"],
        )
        for name in ("capacity", "budgets", "scenarios"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_repeated_calls_are_deterministic(self):
        def exploding_token_bytes(size):
            raise AssertionError("pure parameter analysis must not draw randomness")

        import secrets
        from unittest import mock

        with mock.patch.object(secrets, "token_bytes", exploding_token_bytes):
            for scenarios in _SCENARIO_SETS:
                first = recommend_scheme_weighted_scenarios(
                    1, (None, 10**9), scenarios
                )
                second = recommend_scheme_weighted_scenarios(
                    1, (None, 10**9), scenarios
                )
                self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

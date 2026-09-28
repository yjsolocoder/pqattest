import inspect
import unittest
from fractions import Fraction

from pqattest import (
    Params,
    SchemeScenarioScore,
    explain_scheme_weighted_scenarios,
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

_CAPACITIES = (1, 2, 3, 5, 16, 42, 100, 256)


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


def _expected_rows(capacity, budgets, scenarios):
    """Recompute the documented per-candidate breakdown independently."""
    frontier = scheme_frontier(capacity, budgets)
    rows = [_metrics(candidate) for candidate in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(2)
    )
    totals = tuple(sum(weights) for weights in scenarios)

    entries = []
    for candidate, values in zip(frontier, rows):
        costs = tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(values, spans)
        )
        scores = tuple(
            sum(
                (weight * component for weight, component in zip(weights, costs)),
                Fraction(0),
            )
            / total
            for weights, total in zip(scenarios, totals)
        )
        entries.append((candidate, costs, scores))

    best = tuple(
        min(entry[2][scenario_index] for entry in entries)
        for scenario_index in range(len(scenarios))
    )
    entries = [
        (
            candidate,
            costs,
            scores,
            tuple(score - floor for score, floor in zip(scores, best)),
        )
        for candidate, costs, scores in entries
    ]

    def key(entry):
        candidate, _costs, scores, regrets = entry
        return (
            max(regrets),
            sum(regrets, Fraction(0)),
            scores,
            *_tail(candidate, capacity),
        )

    chosen = min(entries, key=key)[0]
    return tuple(
        SchemeScenarioScore(
            candidate, *costs, scores, regrets, candidate == chosen
        )
        for candidate, costs, scores, regrets in entries
    )


class ExplainSchemeWeightedScenariosTest(unittest.TestCase):
    def test_matches_brute_force_breakdown(self):
        for capacity in _CAPACITIES:
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
                            explain_scheme_weighted_scenarios(
                                capacity, budgets, scenarios
                            ),
                            _expected_rows(capacity, budgets, scenarios),
                        )

    def test_row_order_matches_frontier_member_order(self):
        for capacity, budgets in (
            (1, (None, 10**9)),
            (16, (None, 10**9)),
            (100, (None, 10**9)),
        ):
            frontier = scheme_frontier(capacity, budgets)
            self.assertGreater(len(frontier), 1)
            for scenarios in _SCENARIO_SETS:
                with self.subTest(capacity=capacity, scenarios=scenarios):
                    rows = explain_scheme_weighted_scenarios(
                        capacity, budgets, scenarios
                    )
                    self.assertIsInstance(rows, tuple)
                    self.assertEqual(len(rows), len(frontier))
                    self.assertEqual(
                        tuple(row.params for row in rows),
                        frontier,
                    )

    def test_row_fields_and_types(self):
        scenarios = ((1, 2), (2, 1), (0, 1))
        rows = explain_scheme_weighted_scenarios(
            1, (None, 10**9), scenarios
        )
        for row in rows:
            self.assertIsInstance(row, SchemeScenarioScore)
            self.assertIsInstance(row.params, Params)
            for cost in (row.signature_cost, row.steps_cost):
                self.assertIsInstance(cost, Fraction)
                self.assertGreaterEqual(cost, 0)
                self.assertLessEqual(cost, 1)
            self.assertIsInstance(row.scores, tuple)
            self.assertIsInstance(row.regrets, tuple)
            self.assertEqual(len(row.scores), len(scenarios))
            self.assertEqual(len(row.regrets), len(scenarios))
            for score in row.scores:
                self.assertIsInstance(score, Fraction)
                self.assertGreaterEqual(score, 0)
            for regret in row.regrets:
                self.assertIsInstance(regret, Fraction)
                self.assertGreaterEqual(regret, 0)
            self.assertIsInstance(row.selected, bool)

    def test_regret_is_score_minus_scenario_best(self):
        scenarios = ((1, 0), (0, 1), (2, 2))
        rows = explain_scheme_weighted_scenarios(
            1, (None, 10**9), scenarios
        )
        best = tuple(
            min(row.scores[scenario_index] for row in rows)
            for scenario_index in range(len(scenarios))
        )
        for row in rows:
            self.assertEqual(
                row.regrets,
                tuple(
                    score - floor for score, floor in zip(row.scores, best)
                ),
            )
        # every scenario's best-scoring row has zero regret for it
        for scenario_index in range(len(scenarios)):
            self.assertIn(
                Fraction(0),
                tuple(row.regrets[scenario_index] for row in rows),
            )

    def test_exactly_one_row_selected_and_matches_recommendation(self):
        for capacity in _CAPACITIES:
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
                        rows = explain_scheme_weighted_scenarios(
                            capacity, budgets, scenarios
                        )
                        selected = [row for row in rows if row.selected]
                        self.assertEqual(len(selected), 1)
                        self.assertEqual(
                            selected[0].params,
                            recommend_scheme_weighted_scenarios(
                                capacity, budgets, scenarios
                            ),
                        )

    def test_selected_row_matches_recommendation_field_for_field(self):
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
                        rows = explain_scheme_weighted_scenarios(
                            capacity, budgets, scenarios
                        )
                        chosen = next(row for row in rows if row.selected)
                        result = recommend_scheme_weighted_scenarios(
                            capacity, budgets, scenarios
                        )
                        member = frontier[frontier.index(chosen.params)]
                        for field in Params.__dataclass_fields__:
                            self.assertEqual(
                                getattr(chosen.params, field),
                                getattr(result, field),
                            )
                            self.assertEqual(
                                getattr(chosen.params, field),
                                getattr(member, field),
                            )

    def test_selected_row_has_smallest_worst_regret_with_documented_tail(self):
        for capacity in (1, 2, 3, 16, 42, 256):
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
                        rows = explain_scheme_weighted_scenarios(
                            capacity, budgets, scenarios
                        )

                        def key(row):
                            return (
                                max(row.regrets),
                                sum(row.regrets, Fraction(0)),
                                row.scores,
                            )

                        best = min(key(row) for row in rows)
                        tied = [row for row in rows if key(row) == best]
                        chosen = [row for row in rows if row.selected][0]
                        self.assertIn(chosen, tied)
                        self.assertEqual(
                            chosen.params,
                            min(
                                (row.params for row in tied),
                                key=lambda candidate: _tail(candidate, capacity),
                            ),
                        )

    def test_rows_are_frozen_positional_value_objects(self):
        rows = explain_scheme_weighted_scenarios(
            1, (None, 10**9), ((1, 1), (1, 0))
        )
        row = rows[0]
        clone = SchemeScenarioScore(
            row.params,
            row.signature_cost,
            row.steps_cost,
            row.scores,
            row.regrets,
            row.selected,
        )
        self.assertEqual(clone, row)
        self.assertEqual(hash(clone), hash(row))
        self.assertEqual(
            (
                clone.params,
                clone.signature_cost,
                clone.steps_cost,
                clone.scores,
                clone.regrets,
                clone.selected,
            ),
            (
                row.params,
                row.signature_cost,
                row.steps_cost,
                row.scores,
                row.regrets,
                row.selected,
            ),
        )
        self.assertEqual(
            tuple(SchemeScenarioScore.__dataclass_fields__),
            (
                "params",
                "signature_cost",
                "steps_cost",
                "scores",
                "regrets",
                "selected",
            ),
        )
        with self.assertRaises(Exception):
            row.selected = False

    def test_rows_hash_and_deduplicate_by_value(self):
        rows_a = explain_scheme_weighted_scenarios(
            1, (None, 10**9), ((2, 3), (1, 1))
        )
        rows_b = explain_scheme_weighted_scenarios(
            1, (None, 10**9), ((2, 3), (1, 1))
        )
        self.assertEqual(hash(rows_a[1]), hash(rows_b[1]))
        self.assertEqual(len(set(rows_a)), len(rows_a))

    def test_zero_span_frontier_scores_zero_and_tail_selects(self):
        # a single-member frontier makes every span zero: the unique row
        # scores zero in every scenario and is selected, without dividing
        # by zero
        budgets = (None, 1)
        frontier = scheme_frontier(1, budgets)
        self.assertEqual(len(frontier), 1)
        for scenarios in (
            ((1, 1),),
            ((0, 1),),
            ((9, 8), (1, 0)),
        ):
            with self.subTest(scenarios=scenarios):
                rows = explain_scheme_weighted_scenarios(
                    1, budgets, scenarios
                )
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(row.params, frontier[0])
                self.assertEqual(
                    (row.signature_cost, row.steps_cost),
                    (Fraction(0), Fraction(0)),
                )
                self.assertEqual(
                    row.scores, (Fraction(0),) * len(scenarios)
                )
                self.assertEqual(
                    row.regrets, (Fraction(0),) * len(scenarios)
                )
                self.assertTrue(row.selected)

    def test_each_single_positive_weight_selects_its_dimension_minimum(self):
        # a lone positive weight lights just one dimension: the selected
        # candidate is that dimension's frontier minimum
        frontier = scheme_frontier(1, (None, 10**9))
        for dimension in range(2):
            weights = tuple(1 if i == dimension else 0 for i in range(2))
            with self.subTest(weights=weights):
                rows = explain_scheme_weighted_scenarios(
                    1, (None, 10**9), (weights,)
                )
                chosen = next(row for row in rows if row.selected)
                self.assertEqual(
                    _metrics(chosen.params)[dimension],
                    min(_metrics(candidate)[dimension] for candidate in frontier),
                )

    def test_repeated_scenarios_counted_separately(self):
        # every duplicated scenario tuple must agree with the brute-force
        # ranking, which zips the scenarios position for position
        first = (3, 1)
        second = (0, 5)
        for scenarios in (
            (first, first, second),
            (first, second, second),
            (second, first, first),
            (second, second, first),
            (first, second, first, second),
        ):
            with self.subTest(scenarios=scenarios):
                rows = explain_scheme_weighted_scenarios(
                    1, (None, 10**9), scenarios
                )
                self.assertEqual(
                    rows,
                    _expected_rows(1, (None, 10**9), scenarios),
                )

    def test_scaling_every_scenario_weight_leaves_rows_unchanged(self):
        # scaling every weight of a scenario by a constant leaves that
        # scenario's scores and hence every regret and the selected row
        # unchanged
        scenarios = ((1, 2), (3, 0))
        scaled = (
            tuple(7 * weight for weight in scenarios[0]),
            tuple(11 * weight for weight in scenarios[1]),
        )
        rows_base = explain_scheme_weighted_scenarios(
            1, (None, 10**9), scenarios
        )
        rows_scaled = explain_scheme_weighted_scenarios(
            1, (None, 10**9), scaled
        )
        self.assertEqual(rows_base, rows_scaled)

    def test_scores_are_exact_rational_no_float(self):
        capacity, budgets = 1, (None, 10**9)
        scenarios = ((2, 3), (5, 0))
        frontier = scheme_frontier(capacity, budgets)
        rows = explain_scheme_weighted_scenarios(capacity, budgets, scenarios)
        spans = tuple(
            (
                min(_metrics(candidate)[i] for candidate in frontier),
                max(_metrics(candidate)[i] for candidate in frontier),
            )
            for i in range(2)
        )
        totals = tuple(sum(weights) for weights in scenarios)
        for row in rows:
            for scenario_index, weights in enumerate(scenarios):
                expected = Fraction(0)
                for value, weight, (low, high) in zip(
                    _metrics(row.params), weights, spans
                ):
                    if high > low:
                        expected += weight * Fraction(value - low, high - low)
                expected /= totals[scenario_index]
                self.assertIsInstance(row.scores[scenario_index], Fraction)
                self.assertEqual(row.scores[scenario_index], expected)
            for regret in row.regrets:
                self.assertIsInstance(regret, Fraction)

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
                explain_scheme_weighted_scenarios(
                    1, (None, 10**9), scenarios
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.scheme_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            explain_scheme_weighted_scenarios(
                1, (100, None), ((1, 1),)
            )
        with self.assertRaises(ValueError):
            explain_scheme_weighted_scenarios(
                256, (1200, None), ((1, 1),)
            )
        with self.assertRaises(ValueError):
            explain_scheme_weighted_scenarios(
                2, (None, 1004), ((1, 1),)
            )

    def test_invalid_scenarios_container_raises_type_error(self):
        for bad in ([(1, 1)], {(1, 1)}, "scenarios", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_scheme_weighted_scenarios(
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
                    explain_scheme_weighted_scenarios(
                        1, (None, 10**9), bad
                    )
        good = (1, 1)
        for bad_member in ([1, 1], "scenario", None, 7):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(TypeError):
                    explain_scheme_weighted_scenarios(
                        1, (None, 10**9), (good, bad_member)
                    )

    def test_non_integer_weight_raises_type_error(self):
        for bad in (
            ((1.0, 1),),
            ((1, "1"),),
            ((None, 1),),
            ((1, 1.5),),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_scheme_weighted_scenarios(
                        1, (None, 10**9), bad
                    )
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
                            explain_scheme_weighted_scenarios(
                                1, (None, 10**9), tuple(scenarios)
                            )

    def test_invalid_weights_members_raise_value_error(self):
        for bad in (
            (),
            ((1,),),
            ((1, 1, 1),),
            ((0, 0),),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_scheme_weighted_scenarios(
                        1, (None, 10**9), bad
                    )
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
                            explain_scheme_weighted_scenarios(
                                1, (None, 10**9), tuple(scenarios)
                            )
        for scenario_position in range(2):
            scenarios = [good, good]
            scenarios[scenario_position] = (0, 0)
            with self.subTest(scenario_position=scenario_position):
                with self.assertRaises(ValueError):
                    explain_scheme_weighted_scenarios(
                        1, (None, 10**9), tuple(scenarios)
                    )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in (((True, 0),), ((0, True),)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_scheme_weighted_scenarios(
                        1, (None, 10**9), bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    explain_scheme_weighted_scenarios(
                        bad_capacity, (None, 10**9), ((1, 1),)
                    )
        for bad_budgets in ([None, 1], "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    explain_scheme_weighted_scenarios(
                        1, bad_budgets, ((1, 1),)
                    )
        with self.assertRaises(ValueError):
            explain_scheme_weighted_scenarios(
                1, (None, None), ((1, 1),)
            )
        with self.assertRaises(ValueError):
            explain_scheme_weighted_scenarios(
                1, (None,), ((1, 1),)
            )
        with self.assertRaises(ValueError):
            explain_scheme_weighted_scenarios(
                1, (None, 1, None), ((1, 1),)
            )
        for bad_member in (0, -1, True, 1.5, "100"):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    explain_scheme_weighted_scenarios(
                        1, (None, bad_member), ((1, 1),)
                    )

    def test_frontier_arguments_screened_before_scenarios(self):
        # the capacity/budgets rules belong to the frontier and are
        # screened there before scenarios is inspected
        with self.assertRaises(ValueError):
            explain_scheme_weighted_scenarios(0, (None, None), ())
        with self.assertRaises(TypeError):
            explain_scheme_weighted_scenarios(
                1, [None, 1], "not a tuple"
            )

    def test_all_three_parameters_are_required_without_defaults(self):
        sig = inspect.signature(explain_scheme_weighted_scenarios)
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
                first = explain_scheme_weighted_scenarios(
                    1, (None, 10**9), scenarios
                )
                second = explain_scheme_weighted_scenarios(
                    1, (None, 10**9), scenarios
                )
                self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

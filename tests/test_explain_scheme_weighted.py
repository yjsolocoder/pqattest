import inspect
import unittest
from fractions import Fraction

from pqattest import (
    Params,
    SchemeScore,
    explain_scheme_weighted,
    recommend_scheme_weighted,
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

_WEIGHT_SETS = (
    (1, 1),
    (1, 0),
    (0, 1),
    (2, 3),
    (3, 7),
    (10**9, 1),
    (0, 5),
    (7, 0),
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


def _expected_rows(capacity, budgets, weights):
    """Recompute the documented per-candidate breakdown independently."""
    frontier = scheme_frontier(capacity, budgets)
    rows = [_metrics(candidate) for candidate in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(2)
    )
    total = sum(weights)

    entries = []
    for candidate, values in zip(frontier, rows):
        costs = tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(values, spans)
        )
        score = sum(
            (weight * cost for weight, cost in zip(weights, costs)),
            Fraction(0),
        ) / total
        entries.append((candidate, costs, score))

    chosen = min(
        entries, key=lambda entry: (entry[2], *_tail(entry[0], capacity))
    )[0]
    return tuple(
        SchemeScore(candidate, *costs, score, candidate == chosen)
        for candidate, costs, score in entries
    )


class ExplainSchemeWeightedTest(unittest.TestCase):
    def test_matches_brute_force_breakdown(self):
        for capacity in (1, 2, 3, 5, 16, 42, 100, 256):
            for budgets in _BUDGET_CASES:
                for weights in _WEIGHT_SETS:
                    with self.subTest(
                        capacity=capacity, budgets=budgets, weights=weights
                    ):
                        try:
                            scheme_frontier(capacity, budgets)
                        except ValueError:
                            continue
                        self.assertEqual(
                            explain_scheme_weighted(capacity, budgets, weights),
                            _expected_rows(capacity, budgets, weights),
                        )

    def test_row_order_matches_frontier_member_order(self):
        frontier = scheme_frontier(1, (None, 10**9))
        self.assertGreater(len(frontier), 1)
        for weights in _WEIGHT_SETS:
            with self.subTest(weights=weights):
                rows = explain_scheme_weighted(1, (None, 10**9), weights)
                self.assertIsInstance(rows, tuple)
                self.assertEqual(len(rows), len(frontier))
                self.assertEqual(tuple(row.candidate for row in rows), frontier)

    def test_row_fields_and_types(self):
        rows = explain_scheme_weighted(1, (None, 10**9), (2, 3))
        for row in rows:
            self.assertIsInstance(row, SchemeScore)
            self.assertIsInstance(row.candidate, Params)
            for cost in (row.signature_cost, row.steps_cost, row.score):
                self.assertIsInstance(cost, Fraction)
            for cost in (row.signature_cost, row.steps_cost):
                self.assertGreaterEqual(cost, 0)
                self.assertLessEqual(cost, 1)
            self.assertIsInstance(row.selected, bool)

    def test_exactly_one_row_selected_and_matches_recommendation(self):
        for capacity in (1, 2, 3, 16, 100, 256):
            for budgets in _BUDGET_CASES:
                for weights in _WEIGHT_SETS:
                    with self.subTest(
                        capacity=capacity, budgets=budgets, weights=weights
                    ):
                        try:
                            scheme_frontier(capacity, budgets)
                        except ValueError:
                            continue
                        rows = explain_scheme_weighted(capacity, budgets, weights)
                        selected = [row for row in rows if row.selected]
                        self.assertEqual(len(selected), 1)
                        result = recommend_scheme_weighted(
                            capacity, budgets, weights
                        )
                        self.assertEqual(selected[0].candidate, result)
                        for field in Params.__dataclass_fields__:
                            self.assertEqual(
                                getattr(selected[0].candidate, field),
                                getattr(result, field),
                            )

    def test_selected_row_has_the_smallest_score_with_documented_tail(self):
        for capacity in (1, 2, 3, 16, 42, 256):
            for budgets in _BUDGET_CASES:
                for weights in _WEIGHT_SETS:
                    with self.subTest(
                        capacity=capacity, budgets=budgets, weights=weights
                    ):
                        try:
                            scheme_frontier(capacity, budgets)
                        except ValueError:
                            continue
                        rows = explain_scheme_weighted(capacity, budgets, weights)
                        best = min(row.score for row in rows)
                        tied = [row for row in rows if row.score == best]
                        chosen = [row for row in rows if row.selected][0]
                        self.assertIn(chosen, tied)
                        self.assertEqual(
                            chosen.candidate,
                            min(
                                (row.candidate for row in tied),
                                key=lambda c: _tail(c, capacity),
                            ),
                        )

    def test_each_single_positive_weight_minimises_its_dimension(self):
        # a lone positive weight lights the member minimising that
        # dimension of the whole frontier
        frontier = scheme_frontier(1, (None, 10**9))
        for dimension in range(2):
            weights = tuple(1 if i == dimension else 0 for i in range(2))
            with self.subTest(weights=weights):
                rows = explain_scheme_weighted(1, (None, 10**9), weights)
                chosen = [row for row in rows if row.selected][0]
                self.assertEqual(
                    _metrics(chosen.candidate)[dimension],
                    min(_metrics(candidate)[dimension] for candidate in frontier),
                )
                self.assertEqual(chosen.score, Fraction(0))

    def test_rows_are_frozen_positional_value_objects(self):
        rows = explain_scheme_weighted(1, (None, 10**9), (2, 3))
        row = rows[0]
        clone = SchemeScore(
            row.candidate,
            row.signature_cost,
            row.steps_cost,
            row.score,
            row.selected,
        )
        self.assertEqual(clone, row)
        self.assertEqual(hash(clone), hash(row))
        self.assertEqual(
            (
                clone.candidate,
                clone.signature_cost,
                clone.steps_cost,
                clone.score,
                clone.selected,
            ),
            (
                row.candidate,
                row.signature_cost,
                row.steps_cost,
                row.score,
                row.selected,
            ),
        )
        with self.assertRaises(Exception):
            row.score = Fraction(0)

    def test_zero_span_frontier_scores_zero_and_tail_selects(self):
        # a single-member frontier makes every span zero: the unique row
        # scores zero and is selected, without dividing by zero
        budgets = (None, 1)
        frontier = scheme_frontier(1, budgets)
        self.assertEqual(len(frontier), 1)
        for weights in ((1, 1), (0, 1), (9, 8), (10**12, 0)):
            with self.subTest(weights=weights):
                rows = explain_scheme_weighted(1, budgets, weights)
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(row.candidate, frontier[0])
                self.assertEqual(
                    (row.signature_cost, row.steps_cost, row.score),
                    (Fraction(0),) * 3,
                )
                self.assertTrue(row.selected)

    def test_documented_example_values(self):
        # the fractions shown in the README are computed exactly, no float
        rows = explain_scheme_weighted(1, (None, 10**9), (2, 3))
        self.assertEqual(
            rows,
            (
                SchemeScore(
                    scheme_frontier(1, (None, 10**9))[0],
                    Fraction(1, 1),
                    Fraction(0, 1),
                    Fraction(2, 5),
                    False,
                ),
                SchemeScore(
                    scheme_frontier(1, (None, 10**9))[1],
                    Fraction(11, 74),
                    Fraction(67, 578),
                    Fraction(2759, 21386),
                    True,
                ),
                SchemeScore(
                    scheme_frontier(1, (None, 10**9))[2],
                    Fraction(0, 1),
                    Fraction(1, 1),
                    Fraction(3, 5),
                    False,
                ),
            ),
        )

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
            for weights in _WEIGHT_SETS:
                calls = 0
                explain_scheme_weighted(1, (None, 10**9), weights)
                self.assertEqual(calls, 1)
        finally:
            params_module.scheme_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            explain_scheme_weighted(1, (100, None), (1, 1))
        with self.assertRaises(ValueError):
            explain_scheme_weighted(256, (1200, None), (1, 1))
        with self.assertRaises(ValueError):
            explain_scheme_weighted(2, (None, 1004), (1, 1))

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 1], {1, 2}, "weights", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_scheme_weighted(1, (None, 10**9), bad)

    def test_non_integer_weight_raises_type_error(self):
        for bad in ((1.0, 1), (1, "1"), (None, 1), (1, 1.5)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_scheme_weighted(1, (None, 10**9), bad)

    def test_invalid_weights_members_raise_value_error(self):
        for bad in (
            (),
            (1,),
            (1, 1, 1),
            (0, 0),
            (1, -1),
            (-1, 1),
            (True, 1),
            (1, False),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_scheme_weighted(1, (None, 10**9), bad)

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in ((True, 0), (0, True)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_scheme_weighted(1, (None, 10**9), bad)

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    explain_scheme_weighted(
                        bad_capacity, (None, 10**9), (1, 1)
                    )
        for bad_budgets in ([None, 1], "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    explain_scheme_weighted(1, bad_budgets, (1, 1))
        with self.assertRaises(ValueError):
            explain_scheme_weighted(1, (None, None), (1, 1))
        with self.assertRaises(ValueError):
            explain_scheme_weighted(1, (None,), (1, 1))
        with self.assertRaises(ValueError):
            explain_scheme_weighted(1, (None, 1, None), (1, 1))
        for bad_member in (0, -1, True, 1.5, "100"):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    explain_scheme_weighted(1, (None, bad_member), (1, 1))

    def test_frontier_arguments_screened_before_weights(self):
        # the capacity/budgets rules belong to the frontier and are
        # screened there before weights is inspected
        with self.assertRaises(ValueError):
            explain_scheme_weighted(0, (None, None), (0, 0))
        with self.assertRaises(TypeError):
            explain_scheme_weighted(1, [None, 1], "not a tuple")

    def test_all_three_parameters_are_required_without_defaults(self):
        sig = inspect.signature(explain_scheme_weighted)
        self.assertEqual(list(sig.parameters), ["capacity", "budgets", "weights"])
        for name in ("capacity", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_repeated_calls_are_deterministic(self):
        def exploding_token_bytes(size):
            raise AssertionError("pure parameter analysis must not draw randomness")

        import secrets
        from unittest import mock

        with mock.patch.object(secrets, "token_bytes", exploding_token_bytes):
            for weights in _WEIGHT_SETS:
                first = explain_scheme_weighted(1, (None, 10**9), weights)
                second = explain_scheme_weighted(1, (None, 10**9), weights)
                self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

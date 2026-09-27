import inspect
import unittest
from fractions import Fraction

from pqattest import (
    Params,
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


def _expected(capacity, budgets, weights):
    """Rank the scheme frontier by the documented weighted score."""
    frontier = scheme_frontier(capacity, budgets)
    rows = [_metrics(candidate) for candidate in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(2)
    )
    total = sum(weights)

    def key(item):
        candidate, values = item
        score = Fraction(0)
        for value, weight, (low, high) in zip(values, weights, spans):
            if high > low:
                score += weight * Fraction(value - low, high - low)
        return (score / total, *_tail(candidate, capacity))

    return min(zip(frontier, rows), key=key)[0]


class RecommendSchemeWeightedTest(unittest.TestCase):
    def test_matches_brute_force_ranking(self):
        for capacity in (1, 2, 3, 5, 16, 42, 100, 256):
            for budgets in _BUDGET_CASES:
                for weights in _WEIGHT_SETS:
                    with self.subTest(
                        capacity=capacity, budgets=budgets, weights=weights
                    ):
                        try:
                            frontier = scheme_frontier(capacity, budgets)
                        except ValueError:
                            continue
                        self.assertTrue(frontier)
                        self.assertEqual(
                            recommend_scheme_weighted(capacity, budgets, weights),
                            _expected(capacity, budgets, weights),
                        )

    def test_returns_params_member_of_the_frontier(self):
        frontier = scheme_frontier(1, (None, 10**9))
        for weights in _WEIGHT_SETS:
            with self.subTest(weights=weights):
                result = recommend_scheme_weighted(1, (None, 10**9), weights)
                self.assertIsInstance(result, Params)
                self.assertIn(result, frontier)

    def test_matches_frontier_member_field_for_field(self):
        for capacity in (1, 2, 16, 256):
            for budgets in _BUDGET_CASES:
                for weights in _WEIGHT_SETS:
                    with self.subTest(
                        capacity=capacity, budgets=budgets, weights=weights
                    ):
                        try:
                            frontier = scheme_frontier(capacity, budgets)
                        except ValueError:
                            continue
                        result = recommend_scheme_weighted(
                            capacity, budgets, weights
                        )
                        member = frontier[frontier.index(result)]
                        for field in Params.__dataclass_fields__:
                            self.assertEqual(
                                getattr(result, field), getattr(member, field)
                            )

    def test_each_single_positive_weight_minimises_its_dimension(self):
        # a lone positive weight minimises that (normalised) dimension
        frontier = scheme_frontier(1, (None, 10**9))
        for dimension in range(2):
            weights = tuple(1 if i == dimension else 0 for i in range(2))
            with self.subTest(weights=weights):
                result = recommend_scheme_weighted(1, (None, 10**9), weights)
                self.assertEqual(
                    _metrics(result)[dimension],
                    min(_metrics(candidate)[dimension] for candidate in frontier),
                )

    def test_size_only_weight_picks_shortest_signature(self):
        result = recommend_scheme_weighted(1, (None, 10**9), (1, 0))
        self.assertEqual(result.sig_bytes, 1088)
        self.assertEqual((result.scheme, result.w), ("wots", 8))

    def test_steps_only_weight_picks_lamport(self):
        # lamport has zero hash-chain steps, the global minimum
        result = recommend_scheme_weighted(1, (None, 10**9), (0, 1))
        self.assertEqual(result.scheme, "lamport")
        self.assertEqual(result.steps, 0)

    def test_weighted_sum_is_divided_by_weight_total(self):
        # multiplying every weight by the same factor must not change the
        # ranking because the score divides by the weight total
        for capacity in (1, 2, 16, 100):
            for budgets in _BUDGET_CASES:
                try:
                    scheme_frontier(capacity, budgets)
                except ValueError:
                    continue
                with self.subTest(capacity=capacity, budgets=budgets):
                    base = recommend_scheme_weighted(capacity, budgets, (2, 3))
                    scaled = recommend_scheme_weighted(capacity, budgets, (14, 21))
                    self.assertEqual(base, scaled)

    def test_zero_span_dimensions_score_zero(self):
        # a single-member frontier makes every span zero: the unique member
        # is chosen regardless of the weights, without dividing by zero
        budgets = (None, 1)
        frontier = scheme_frontier(1, budgets)
        self.assertEqual(len(frontier), 1)
        for weights in ((1, 1), (0, 1), (9, 8), (10**12, 0)):
            with self.subTest(weights=weights):
                self.assertEqual(
                    recommend_scheme_weighted(1, budgets, weights),
                    frontier[0],
                )

    def test_tie_break_is_documented_tail(self):
        # among the members sharing the smallest weighted score, the chosen
        # one must be the smallest by spare capacity, scheme name, w and
        # height (missing parameter first)
        for capacity in (1, 2, 3, 16, 42, 256):
            for budgets in _BUDGET_CASES:
                for weights in _WEIGHT_SETS:
                    with self.subTest(
                        capacity=capacity, budgets=budgets, weights=weights
                    ):
                        try:
                            frontier = scheme_frontier(capacity, budgets)
                        except ValueError:
                            continue
                        rows = [_metrics(candidate) for candidate in frontier]
                        spans = tuple(
                            (
                                min(row[i] for row in rows),
                                max(row[i] for row in rows),
                            )
                            for i in range(2)
                        )
                        total = sum(weights)

                        def score(candidate):
                            weighted = Fraction(0)
                            for value, weight, (low, high) in zip(
                                _metrics(candidate), weights, spans
                            ):
                                if high > low:
                                    weighted += weight * Fraction(
                                        value - low, high - low
                                    )
                            return weighted / total

                        result = recommend_scheme_weighted(
                            capacity, budgets, weights
                        )
                        best = score(result)
                        tied = [
                            candidate
                            for candidate in frontier
                            if score(candidate) == best
                        ]
                        self.assertEqual(
                            result,
                            min(tied, key=lambda c: _tail(c, capacity)),
                        )
                        self.assertIn(result, tied)

    def test_scores_are_exact_rational_no_float(self):
        capacity, budgets, weights = 1, (None, 10**9), (2, 3)
        frontier = scheme_frontier(capacity, budgets)
        result = recommend_scheme_weighted(capacity, budgets, weights)
        rows = [_metrics(candidate) for candidate in frontier]
        spans = tuple(
            (min(row[i] for row in rows), max(row[i] for row in rows))
            for i in range(2)
        )
        total = sum(weights)

        def score(candidate):
            weighted = Fraction(0)
            for value, weight, (low, high) in zip(
                _metrics(candidate), weights, spans
            ):
                if high > low:
                    weighted += weight * Fraction(value - low, high - low)
            value = weighted / total
            self.assertIsInstance(value, Fraction)
            return value

        chosen_score = score(result)
        for candidate in frontier:
            self.assertLessEqual(chosen_score, score(candidate))

    def test_budgets_are_honoured(self):
        budgets = (2200, 9000)
        result = recommend_scheme_weighted(1, budgets, (1, 1))
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
            for weights in _WEIGHT_SETS:
                calls = 0
                recommend_scheme_weighted(1, (None, 10**9), weights)
                self.assertEqual(calls, 1)
        finally:
            params_module.scheme_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_scheme_weighted(1, (100, None), (1, 1))
        with self.assertRaises(ValueError):
            recommend_scheme_weighted(256, (1200, None), (1, 1))
        with self.assertRaises(ValueError):
            recommend_scheme_weighted(2, (None, 1004), (1, 1))

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 1], {1, 2}, "weights", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_scheme_weighted(1, (None, 10**9), bad)

    def test_non_integer_weight_raises_type_error(self):
        for bad in ((1.0, 1), (1, "1"), (None, 1), (1, 1.5)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_scheme_weighted(1, (None, 10**9), bad)

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
                    recommend_scheme_weighted(1, (None, 10**9), bad)

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in ((True, 0), (0, True)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_scheme_weighted(1, (None, 10**9), bad)

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    recommend_scheme_weighted(
                        bad_capacity, (None, 10**9), (1, 1)
                    )
        for bad_budgets in ([None, 1], "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    recommend_scheme_weighted(1, bad_budgets, (1, 1))
        with self.assertRaises(ValueError):
            recommend_scheme_weighted(1, (None, None), (1, 1))
        with self.assertRaises(ValueError):
            recommend_scheme_weighted(1, (None,), (1, 1))
        with self.assertRaises(ValueError):
            recommend_scheme_weighted(1, (None, 1, None), (1, 1))
        for bad_member in (0, -1, True, 1.5, "100"):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    recommend_scheme_weighted(1, (None, bad_member), (1, 1))

    def test_frontier_arguments_screened_before_weights(self):
        # the capacity/budgets rules belong to the frontier and are
        # screened there before weights is inspected
        with self.assertRaises(ValueError):
            recommend_scheme_weighted(0, (None, None), (0, 0))
        with self.assertRaises(TypeError):
            recommend_scheme_weighted(1, [None, 1], "not a tuple")

    def test_all_three_parameters_are_required_without_defaults(self):
        sig = inspect.signature(recommend_scheme_weighted)
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "budgets", "weights"],
        )
        for name in ("capacity", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_repeated_calls_are_deterministic(self):
        def exploding_token_bytes(size):
            raise AssertionError("pure parameter analysis must not draw randomness")

        import secrets
        from unittest import mock

        with mock.patch.object(secrets, "token_bytes", exploding_token_bytes):
            for weights in _WEIGHT_SETS:
                first = recommend_scheme_weighted(1, (None, 10**9), weights)
                second = recommend_scheme_weighted(1, (None, 10**9), weights)
                self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

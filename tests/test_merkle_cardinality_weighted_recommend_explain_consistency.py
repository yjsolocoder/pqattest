"""Differential regression: recommend vs explain for weighted cardinality.

These checks do not recompute the ranking from the frontier; they assert the
four public entries agree with *each other* across tie-heavy, duplicate and
big-integer inputs, and that their exception contracts stay distinct.
"""

import unittest
from fractions import Fraction

from pqattest import (
    explain_merkle_cardinality_weighted as explain_one,
    explain_merkle_cardinality_weighted_scenarios as explain_many,
    recommend_merkle_cardinality_weighted as recommend_one,
    recommend_merkle_cardinality_weighted_scenarios as recommend_many,
)

_SIZES = (1, 2)
_BUDGETS = (None, None, None, 9000, None, None)

# workloads chosen to include single-candidate and tiny frontiers
_WORKLOADS = (
    (1, (1,), (None, None, 2243, None, None, 2000)),  # one member
    (4, _SIZES, _BUDGETS),
    (8, (1, 2, 4), (9000, None, None, None, None, None)),
    (2, (1, 2), (None, None, None, None, None, 6000)),
)

_WEIGHT_SETS = (
    (1, 1, 1, 1, 1),
    (10, 0, 0, 0, 0),
    (0, 0, 0, 0, 1),
    (10**40 + 7, 3, 10**80, 0, 1),
    (0, 1, 0, 1, 0),
)

_SCENARIO_SETS = (
    ((1, 1, 1, 1, 1),),
    ((1, 1, 1, 1, 1), (1, 1, 1, 1, 1)),  # exact duplicates, kept twice
    ((0, 0, 0, 2, 1), (0, 2, 0, 0, 1), (0, 2, 0, 0, 1)),
    (
        (10**60, 1, 1, 1, 1),
        (1, 0, 0, 0, 0),
        (1, 0, 0, 0, 0),
        (1, 0, 0, 0, 0),
    ),
    ((1, 2, 3, 4, 5), (5, 4, 3, 2, 1)),
)


class RecommendExplainConsistencyTest(unittest.TestCase):
    def test_single_weight_selected_row_matches_recommendation(self):
        for capacity, sizes, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(capacity=capacity, weights=weights):
                    rows = explain_one(capacity, sizes, budgets, weights)
                    picked = recommend_one(capacity, sizes, budgets, weights)
                    selected = [row for row in rows if row.selected]
                    self.assertEqual(len(selected), 1)
                    self.assertEqual(selected[0].mode_cost, picked)
                    # score field equals weighted sum of the five cost fields
                    for row in rows:
                        recomputed = (
                            sum(
                                w * c
                                for w, c in zip(
                                    weights,
                                    (
                                        row.transport_cost,
                                        row.peak_cost,
                                        row.hashes_cost,
                                        row.nodes_cost,
                                        row.steps_cost,
                                    ),
                                )
                            )
                            / sum(weights)
                        )
                        self.assertEqual(row.score, recomputed)
                        self.assertIsInstance(row.score, Fraction)

    def test_scenarios_selected_row_matches_recommendation(self):
        for capacity, sizes, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(capacity=capacity, scenarios=scenarios):
                    rows = explain_many(capacity, sizes, budgets, scenarios)
                    picked = recommend_many(capacity, sizes, budgets, scenarios)
                    selected = [row for row in rows if row.selected]
                    self.assertEqual(len(selected), 1)
                    self.assertEqual(selected[0].mode_cost, picked)
                    self.assertEqual(len(rows[0].scores), len(scenarios))
                    self.assertEqual(len(rows[0].regrets), len(scenarios))
                    for row in rows:
                        for weights, score in zip(scenarios, row.scores):
                            recomputed = (
                                sum(
                                    w * c
                                    for w, c in zip(
                                        weights,
                                        (
                                            row.transport_cost,
                                            row.peak_cost,
                                            row.hashes_cost,
                                            row.nodes_cost,
                                            row.steps_cost,
                                        ),
                                    )
                                )
                                / sum(weights)
                            )
                            self.assertEqual(score, recomputed)
                        # every regret is the score minus the per-scenario best
                        for index in range(len(scenarios)):
                            best = min(r.scores[index] for r in rows)
                            self.assertEqual(
                                row.regrets[index], row.scores[index] - best
                            )

    def test_single_scenario_matches_single_weight(self):
        # one scenario => all regrets zero; the multi-scenario entry must
        # agree field-for-field with the single-weight entry on that tuple
        for capacity, sizes, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(capacity=capacity, weights=weights):
                    one_rows = explain_one(capacity, sizes, budgets, weights)
                    many_rows = explain_many(
                        capacity, sizes, budgets, (weights,)
                    )
                    self.assertEqual(
                        recommend_many(capacity, sizes, budgets, (weights,)),
                        recommend_one(capacity, sizes, budgets, weights),
                    )
                    best_score = min(row.score for row in one_rows)
                    for one, many in zip(one_rows, many_rows):
                        self.assertEqual(many.mode_cost, one.mode_cost)
                        self.assertEqual(many.scores, (one.score,))
                        self.assertEqual(many.regrets, (one.score - best_score,))
                        self.assertEqual(many.selected, one.selected)

    def test_duplicate_scenarios_swing_minimax_like_repeated_groups(self):
        # both entries must follow the duplicate-sensitive minimax choice
        first = (0, 0, 0, 2, 1)
        second = (0, 2, 0, 0, 1)
        cases = ((first,), (first, second), (first, second, second))
        for scenarios in cases:
            rows = explain_many(4, _SIZES, _BUDGETS, scenarios)
            picked = recommend_many(4, _SIZES, _BUDGETS, scenarios)
            selected = [r for r in rows if r.selected][0]
            self.assertEqual(selected.mode_cost, picked)

    def test_exception_contracts_stay_distinct(self):
        # recommend raises ValueError on a non-integer weight member while
        # explain raises TypeError for the same input
        bad = (1, 1.0, 1, 1, 1)
        with self.assertRaises(ValueError):
            recommend_one(4, _SIZES, _BUDGETS, bad)
        with self.assertRaises(TypeError):
            explain_one(4, _SIZES, _BUDGETS, bad)
        # non-tuple weights: TypeError from both
        for fn in (recommend_one, explain_one):
            with self.assertRaises(TypeError):
                fn(4, _SIZES, _BUDGETS, [1, 1, 1, 1, 1])
        # boolean / negative / all-zero / wrong length: ValueError from both
        for bad in (
            (True, 0, 0, 0, 0),
            (1, -1, 1, 1, 1),
            (0, 0, 0, 0, 0),
            (1, 1, 1, 1),
        ):
            for fn in (recommend_one, explain_one):
                with self.assertRaises(ValueError):
                    fn(4, _SIZES, _BUDGETS, bad)
        # frontier screening precedes weight/scenario screening
        with self.assertRaises(ValueError):
            recommend_one(0, (), _BUDGETS, bad)
        with self.assertRaises(TypeError):
            explain_many(4, [1], _BUDGETS, "not a tuple")
        # scenarios contract shared by both scenario entries
        for fn in (recommend_many, explain_many):
            with self.assertRaises(TypeError):
                fn(4, _SIZES, _BUDGETS, [(1, 1, 1, 1, 1)])
            with self.assertRaises(TypeError):
                fn(4, _SIZES, _BUDGETS, ((1.0, 1, 1, 1, 1),))
            with self.assertRaises(ValueError):
                fn(4, _SIZES, _BUDGETS, ())


if __name__ == "__main__":
    unittest.main()

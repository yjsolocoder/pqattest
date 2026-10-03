"""Regression tests pinning the shared scoring core of the weighted
fixed-position verify-mode deployment ranking.

``recommend_merkle_verify_mode_deployment_weighted`` and
``explain_merkle_verify_mode_deployment_weighted`` share one private cost
extraction / normalisation / tie-break implementation; these tests constrain
that shared semantics through the two public entry points only — real
trade-off frontiers, independently recomputed breakdown numbers, single
lit dimensions, zero spans, genuine score ties and inclusive budget
boundaries.
"""

import unittest
from fractions import Fraction

from pqattest import (
    explain_merkle_verify_mode_deployment_weighted,
    merkle_verify_mode_frontier,
    profile,
    recommend_merkle_verify_mode_deployment_weighted,
)

_GROUPS = ((0, 1), (3, 5))
_BUDGETS = (None, 5000, 12000, None, 8, None)

# workloads whose frontiers hold several members with non-zero cost spans,
# so the weighted score really trades one cost off against another
_TRADEOFF_WORKLOADS = (
    (16, _GROUPS, _BUDGETS),
    (16, ((1,), (2,), (3,), (4,), (8,)), (None, None, None, None, None, 10**18)),
    (4, ((0,), (1,)), (9000, None, 7000, None, 4, None)),
    (32, ((0,), (6, 7), (15, 16)), (None, None, None, None, 50, None)),
)

_WEIGHT_SETS = (
    (1, 1, 1, 1, 1),
    (10, 0, 0, 0, 0),
    (0, 0, 0, 0, 1),
    (1, 2, 3, 4, 5),
    (0, 1, 0, 1, 0),
    (3, 0, 7, 0, 2),
)


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


def _expected_breakdown(capacity, groups, budgets, weights):
    """Recompute the documented normalised costs and scores independently."""
    frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
    rows = [_metrics(mode_cost) for mode_cost in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(5)
    )
    weight_total = sum(weights)
    breakdown = []
    for mode_cost, values in zip(frontier, rows):
        costs = tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(values, spans)
        )
        score = sum(
            (weight * cost for weight, cost in zip(weights, costs)),
            Fraction(0),
        ) / weight_total
        breakdown.append((mode_cost, costs, score))
    return frontier, spans, breakdown


class VerifyModeDeploymentWeightedConsistencyTest(unittest.TestCase):
    def test_frontiers_used_here_have_real_cost_tradeoffs(self):
        # guard the guard: every trade-off workload must keep several
        # members and a non-zero span on at least one cost dimension,
        # otherwise the numeric assertions below would be vacuous
        for capacity, groups, budgets in _TRADEOFF_WORKLOADS:
            with self.subTest(capacity=capacity, groups=groups, budgets=budgets):
                frontier, spans, _ = _expected_breakdown(
                    capacity, groups, budgets, (1, 1, 1, 1, 1)
                )
                self.assertGreater(len(frontier), 1)
                self.assertTrue(any(high > low for low, high in spans))

    def test_breakdown_numbers_and_selection_match_independent_recomputation(self):
        for capacity, groups, budgets in _TRADEOFF_WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    weights=weights,
                ):
                    frontier, _spans, breakdown = _expected_breakdown(
                        capacity, groups, budgets, weights
                    )
                    rows = explain_merkle_verify_mode_deployment_weighted(
                        capacity, groups, budgets, weights
                    )
                    self.assertEqual(len(rows), len(frontier))
                    for row, (mode_cost, costs, score) in zip(rows, breakdown):
                        self.assertEqual(row.mode_cost, mode_cost)
                        self.assertEqual(
                            (
                                row.transport_cost,
                                row.peak_cost,
                                row.hashes_cost,
                                row.nodes_cost,
                                row.steps_cost,
                            ),
                            costs,
                        )
                        self.assertEqual(row.score, score)
                    # exactly one row is selected, it holds the smallest
                    # score and its plan is the recommendation field for field
                    selected = [row for row in rows if row.selected]
                    self.assertEqual(len(selected), 1)
                    self.assertEqual(selected[0].score, min(row.score for row in rows))
                    self.assertEqual(
                        selected[0].mode_cost,
                        recommend_merkle_verify_mode_deployment_weighted(
                            capacity, groups, budgets, weights
                        ),
                    )

    def test_single_positive_weight_minimises_that_dimension(self):
        # lighting exactly one dimension must select the frontier member
        # with the smallest raw cost in that dimension (tail breaks ties),
        # and both entry points must agree on which member that is
        frontier = merkle_verify_mode_frontier(16, _GROUPS, _BUDGETS)
        for dimension in range(5):
            weights = tuple(1 if index == dimension else 0 for index in range(5))
            with self.subTest(dimension=dimension):
                result = recommend_merkle_verify_mode_deployment_weighted(
                    16, _GROUPS, _BUDGETS, weights
                )
                best_value = min(_metrics(mc)[dimension] for mc in frontier)
                tied = [
                    mc for mc in frontier if _metrics(mc)[dimension] == best_value
                ]
                self.assertEqual(result, min(tied, key=_tail))
                rows = explain_merkle_verify_mode_deployment_weighted(
                    16, _GROUPS, _BUDGETS, weights
                )
                selected = [row for row in rows if row.selected]
                self.assertEqual(len(selected), 1)
                self.assertEqual(selected[0].mode_cost, result)
                # the selected member's lit normalised cost is exactly zero
                self.assertEqual(
                    (
                        selected[0].transport_cost,
                        selected[0].peak_cost,
                        selected[0].hashes_cost,
                        selected[0].nodes_cost,
                        selected[0].steps_cost,
                    )[dimension],
                    Fraction(0),
                )
                self.assertEqual(selected[0].score, Fraction(0))

    def test_zero_span_dimension_scores_zero_and_is_ignored(self):
        # this five-member frontier has identical per-signature steps on
        # every member: the steps span is zero, every steps cost must be
        # exactly zero and weighting that dimension must not move the
        # selection
        capacity, groups, budgets = 8, ((0,), (1, 2), (4,)), (
            9000,
            None,
            None,
            None,
            None,
            None,
        )
        frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
        self.assertGreater(len(frontier), 1)
        self.assertEqual(
            len({_metrics(mode_cost)[4] for mode_cost in frontier}), 1
        )
        rows_unweighted = explain_merkle_verify_mode_deployment_weighted(
            capacity, groups, budgets, (1, 1, 1, 1, 0)
        )
        rows_weighted = explain_merkle_verify_mode_deployment_weighted(
            capacity, groups, budgets, (1, 1, 1, 1, 10**6)
        )
        for row in rows_weighted:
            self.assertEqual(row.steps_cost, Fraction(0))
        self.assertEqual(
            [row.mode_cost for row in rows_unweighted if row.selected],
            [row.mode_cost for row in rows_weighted if row.selected],
        )
        self.assertEqual(
            recommend_merkle_verify_mode_deployment_weighted(
                capacity, groups, budgets, (1, 1, 1, 1, 0)
            ),
            recommend_merkle_verify_mode_deployment_weighted(
                capacity, groups, budgets, (1, 1, 1, 1, 10**6)
            ),
        )

    def test_all_zero_span_frontier_scores_zero_and_selects_unique_member(self):
        # a single-member frontier makes every span zero: the unique row
        # scores zero and is selected whatever the weights
        budgets = (None, None, 2243, None, None, 2000)
        frontier = merkle_verify_mode_frontier(1, ((0,),), budgets)
        self.assertEqual(len(frontier), 1)
        for weights in ((1, 1, 1, 1, 1), (0, 0, 0, 0, 1), (9, 8, 7, 6, 5)):
            with self.subTest(weights=weights):
                rows = explain_merkle_verify_mode_deployment_weighted(
                    1, ((0,),), budgets, weights
                )
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(
                    (
                        row.transport_cost,
                        row.peak_cost,
                        row.hashes_cost,
                        row.nodes_cost,
                        row.steps_cost,
                        row.score,
                    ),
                    (Fraction(0),) * 6,
                )
                self.assertTrue(row.selected)
                self.assertEqual(
                    recommend_merkle_verify_mode_deployment_weighted(
                        1, ((0,),), budgets, weights
                    ),
                    frontier[0],
                )

    def test_genuine_score_tie_is_broken_by_documented_tail(self):
        # on this frontier several members share the per-signature step
        # count, so lighting only the steps dimension produces a genuine
        # multi-way score tie: the ascending tail must decide, and both
        # entry points must pick the same member
        weights = (0, 0, 0, 0, 1)
        frontier = merkle_verify_mode_frontier(16, _GROUPS, _BUDGETS)
        rows = explain_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, _BUDGETS, weights
        )
        best = min(row.score for row in rows)
        tied = [row for row in rows if row.score == best]
        self.assertGreater(len(tied), 1)
        expected = min((row.mode_cost for row in tied), key=_tail)
        selected = [row for row in rows if row.selected]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].mode_cost, expected)
        self.assertEqual(
            recommend_merkle_verify_mode_deployment_weighted(
                16, _GROUPS, _BUDGETS, weights
            ),
            expected,
        )
        self.assertIn(expected, frontier)

    def test_total_budget_boundary_is_inclusive(self):
        # a total-transport budget equal to a member's aggregate bytes
        # keeps that member feasible; one byte less removes it, and both
        # entry points agree on the selection at and below the boundary
        capacity, groups = 4, ((0,), (1,))
        wide = merkle_verify_mode_frontier(
            capacity, groups, (None, None, None, None, None, 10**18)
        )
        boundary = sorted({mc.plan.total for mc in wide})[2]
        weights = (1, 2, 3, 4, 5)

        at_budgets = (None, None, boundary, None, None, None)
        at_frontier = merkle_verify_mode_frontier(capacity, groups, at_budgets)
        self.assertTrue(any(mc.plan.total == boundary for mc in at_frontier))
        at_result = recommend_merkle_verify_mode_deployment_weighted(
            capacity, groups, at_budgets, weights
        )
        self.assertLessEqual(at_result.plan.total, boundary)
        at_rows = explain_merkle_verify_mode_deployment_weighted(
            capacity, groups, at_budgets, weights
        )
        at_selected = [row for row in at_rows if row.selected]
        self.assertEqual(len(at_selected), 1)
        self.assertEqual(at_selected[0].mode_cost, at_result)

        below_budgets = (None, None, boundary - 1, None, None, None)
        below_frontier = merkle_verify_mode_frontier(
            capacity, groups, below_budgets
        )
        self.assertTrue(below_frontier)
        self.assertTrue(all(mc.plan.total < boundary for mc in below_frontier))
        below_result = recommend_merkle_verify_mode_deployment_weighted(
            capacity, groups, below_budgets, weights
        )
        self.assertLessEqual(below_result.plan.total, boundary - 1)
        below_rows = explain_merkle_verify_mode_deployment_weighted(
            capacity, groups, below_budgets, weights
        )
        below_selected = [row for row in below_rows if row.selected]
        self.assertEqual(len(below_selected), 1)
        self.assertEqual(below_selected[0].mode_cost, below_result)

    def test_invalid_frontier_arguments_raise_before_invalid_weights(self):
        # capacity/groups/budgets are screened by the frontier before the
        # weights are inspected, so a doubly-invalid call raises the
        # frontier's exception first — through both entry points
        for entry in (
            recommend_merkle_verify_mode_deployment_weighted,
            explain_merkle_verify_mode_deployment_weighted,
        ):
            with self.subTest(entry=entry.__name__):
                with self.assertRaises(ValueError):
                    entry(0, (), (None,) * 6, (0, 0, 0, 0, 0))
                with self.assertRaises(TypeError):
                    entry(16, [(0, 1)], _BUDGETS, "not a tuple")
                with self.assertRaises(TypeError):
                    entry(16, _GROUPS, [None] * 6, [1, 1, 1, 1, 1])
                # an infeasible budget set is reported before the weights
                with self.assertRaises(ValueError):
                    entry(
                        1,
                        ((0,),),
                        (100, None, None, None, None, None),
                        "not a tuple",
                    )

    def test_repeated_calls_return_identical_results(self):
        for capacity, groups, budgets in _TRADEOFF_WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity, groups=groups, budgets=budgets, weights=weights
                ):
                    self.assertEqual(
                        recommend_merkle_verify_mode_deployment_weighted(
                            capacity, groups, budgets, weights
                        ),
                        recommend_merkle_verify_mode_deployment_weighted(
                            capacity, groups, budgets, weights
                        ),
                    )
                    self.assertEqual(
                        explain_merkle_verify_mode_deployment_weighted(
                            capacity, groups, budgets, weights
                        ),
                        explain_merkle_verify_mode_deployment_weighted(
                            capacity, groups, budgets, weights
                        ),
                    )


if __name__ == "__main__":
    unittest.main()

import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleCardinalityScore,
    MerkleModeCost,
    explain_merkle_cardinality_weighted,
    merkle_cardinality_frontier,
    profile,
    recommend_merkle_cardinality_weighted,
)

_SIZES = (1, 2)
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


def _expected_rows(capacity, group_sizes, budgets, weights):
    """Recompute the documented per-candidate breakdown independently."""
    frontier = merkle_cardinality_frontier(capacity, group_sizes, budgets)
    rows = [_metrics(mode_cost) for mode_cost in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(5)
    )
    total = sum(weights)

    entries = []
    for mode_cost, values in zip(frontier, rows):
        costs = tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(values, spans)
        )
        score = sum(
            (weight * cost for weight, cost in zip(weights, costs)),
            Fraction(0),
        ) / total
        entries.append((mode_cost, costs, score))

    chosen = min(entries, key=lambda entry: (entry[2], *_tail(entry[0])))[0]
    return tuple(
        MerkleCardinalityScore(mode_cost, *costs, score, mode_cost == chosen)
        for mode_cost, costs, score in entries
    )


_WORKLOADS = (
    (1, (1,), (None, None, None, None, None, 10**18)),
    (4, _SIZES, _BUDGETS),
    (16, (1, 2, 3, 4, 8), (None, None, None, None, None, 10**18)),
    (8, (1, 2, 4), (9000, None, None, None, None, None)),
    (4, (3,), (None, 4000, None, None, None, None)),
    (4, _SIZES, (9000, None, 7000, None, 4, None)),
    (2, (1, 2), (None, None, None, None, None, 6000)),
    (32, (1, 7, 16), (None, None, None, None, 50, None)),
)

_WEIGHT_SETS = (
    (1, 1, 1, 1, 1),
    (10, 0, 0, 0, 0),
    (0, 0, 0, 0, 1),
    (1, 2, 3, 4, 5),
    (0, 1, 0, 1, 0),
    (10**9, 1, 1, 1, 1),
    (3, 0, 7, 0, 2),
)


class ExplainMerkleCardinalityWeightedTest(unittest.TestCase):
    def test_matches_brute_force_breakdown(self):
        for capacity, group_sizes, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    group_sizes=group_sizes,
                    budgets=budgets,
                    weights=weights,
                ):
                    self.assertEqual(
                        explain_merkle_cardinality_weighted(
                            capacity, group_sizes, budgets, weights
                        ),
                        _expected_rows(capacity, group_sizes, budgets, weights),
                    )

    def test_row_order_matches_frontier_member_order(self):
        frontier = merkle_cardinality_frontier(4, _SIZES, _BUDGETS)
        self.assertGreater(len(frontier), 1)
        for weights in _WEIGHT_SETS:
            with self.subTest(weights=weights):
                rows = explain_merkle_cardinality_weighted(
                    4, _SIZES, _BUDGETS, weights
                )
                self.assertIsInstance(rows, tuple)
                self.assertEqual(len(rows), len(frontier))
                self.assertEqual(
                    tuple(row.mode_cost for row in rows),
                    frontier,
                )

    def test_row_fields_and_types(self):
        rows = explain_merkle_cardinality_weighted(
            4, _SIZES, _BUDGETS, (1, 2, 3, 4, 5)
        )
        for row in rows:
            self.assertIsInstance(row, MerkleCardinalityScore)
            self.assertIsInstance(row.mode_cost, MerkleModeCost)
            for cost in (
                row.transport_cost,
                row.peak_cost,
                row.hashes_cost,
                row.nodes_cost,
                row.steps_cost,
                row.score,
            ):
                self.assertIsInstance(cost, Fraction)
                self.assertGreaterEqual(cost, 0)
            for cost in (
                row.transport_cost,
                row.peak_cost,
                row.hashes_cost,
                row.nodes_cost,
                row.steps_cost,
            ):
                self.assertLessEqual(cost, 1)
            self.assertIsInstance(row.selected, bool)

    def test_exactly_one_row_selected_and_matches_recommendation(self):
        for capacity, group_sizes, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    group_sizes=group_sizes,
                    budgets=budgets,
                    weights=weights,
                ):
                    rows = explain_merkle_cardinality_weighted(
                        capacity, group_sizes, budgets, weights
                    )
                    selected = [row for row in rows if row.selected]
                    self.assertEqual(len(selected), 1)
                    self.assertEqual(
                        selected[0].mode_cost,
                        recommend_merkle_cardinality_weighted(
                            capacity, group_sizes, budgets, weights
                        ),
                    )

    def test_selected_row_has_the_smallest_score_with_documented_tail(self):
        for capacity, group_sizes, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    group_sizes=group_sizes,
                    budgets=budgets,
                    weights=weights,
                ):
                    rows = explain_merkle_cardinality_weighted(
                        capacity, group_sizes, budgets, weights
                    )
                    best = min(row.score for row in rows)
                    tied = [row for row in rows if row.score == best]
                    chosen = [row for row in rows if row.selected][0]
                    self.assertIn(chosen, tied)
                    self.assertEqual(
                        chosen.mode_cost,
                        min((row.mode_cost for row in tied), key=_tail),
                    )

    def test_rows_are_frozen_positional_value_objects(self):
        rows = explain_merkle_cardinality_weighted(
            4, _SIZES, _BUDGETS, (1, 1, 1, 1, 1)
        )
        row = rows[0]
        clone = MerkleCardinalityScore(
            row.mode_cost,
            row.transport_cost,
            row.peak_cost,
            row.hashes_cost,
            row.nodes_cost,
            row.steps_cost,
            row.score,
            row.selected,
        )
        self.assertEqual(clone, row)
        self.assertEqual(hash(clone), hash(row))
        self.assertEqual(
            (
                clone.mode_cost,
                clone.transport_cost,
                clone.peak_cost,
                clone.hashes_cost,
                clone.nodes_cost,
                clone.steps_cost,
                clone.score,
                clone.selected,
            ),
            (
                row.mode_cost,
                row.transport_cost,
                row.peak_cost,
                row.hashes_cost,
                row.nodes_cost,
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
        budgets = (None, None, 2243, 1005, None, None)
        frontier = merkle_cardinality_frontier(1, (1,), budgets)
        self.assertEqual(len(frontier), 1)
        for weights in (
            (1, 1, 1, 1, 1),
            (0, 0, 0, 0, 1),
            (9, 8, 7, 6, 5),
            (10**12, 0, 0, 0, 0),
        ):
            with self.subTest(weights=weights):
                rows = explain_merkle_cardinality_weighted(1, (1,), budgets, weights)
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(row.mode_cost, frontier[0])
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

    def test_frontier_called_once_no_duplicate_enumeration(self):
        calls = 0
        original = merkle_cardinality_frontier

        import pqattest.params as params_module

        def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)

        params_module.merkle_cardinality_frontier = counting
        try:
            for weights in _WEIGHT_SETS:
                calls = 0
                explain_merkle_cardinality_weighted(4, _SIZES, _BUDGETS, weights)
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_cardinality_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            explain_merkle_cardinality_weighted(
                1, (1,), (100, None, None, None, None, None), (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_cardinality_weighted(
                4, (1, 2), (None, None, None, 10, None, None), (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_cardinality_weighted(
                4, (300,), (None,) * 5 + (10**18,), (1, 1, 1, 1, 1)
            )

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 1, 1, 1, 1], {1, 2, 3, 4, 5}, "weights", None, 7, range(5)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_cardinality_weighted(4, _SIZES, _BUDGETS, bad)

    def test_non_integer_weight_raises_type_error(self):
        for bad in (
            (1.0, 1, 1, 1, 1),
            (1, "1", 1, 1, 1),
            (1, None, 1, 1, 1),
            (1, 1, 1, 1, 1.5),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_cardinality_weighted(4, _SIZES, _BUDGETS, bad)

    def test_invalid_weights_members_raise_value_error(self):
        for bad in (
            (),
            (1, 1, 1, 1),
            (1, 1, 1, 1, 1, 1),
            (0, 0, 0, 0, 0),
            (1, -1, 1, 1, 1),
            (-1, 1, 1, 1, 1),
            (True, 1, 1, 1, 1),
            (1, 1, 1, 1, False),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_cardinality_weighted(4, _SIZES, _BUDGETS, bad)

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in ((True, 0, 0, 0, 0), (0, 0, 0, 0, True)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_cardinality_weighted(4, _SIZES, _BUDGETS, bad)

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "4"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    explain_merkle_cardinality_weighted(
                        bad_capacity, _SIZES, _BUDGETS, (1, 1, 1, 1, 1)
                    )
        for bad_sizes in ([1, 2], "sizes", None, 7, {1, 2}):
            with self.subTest(bad_sizes=bad_sizes):
                with self.assertRaises(TypeError):
                    explain_merkle_cardinality_weighted(
                        4, bad_sizes, _BUDGETS, (1, 1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            explain_merkle_cardinality_weighted(
                4, (), _BUDGETS, (1, 1, 1, 1, 1)
            )
        for bad_member in (0, -1, True, False):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    explain_merkle_cardinality_weighted(
                        4, (1, bad_member), _BUDGETS, (1, 1, 1, 1, 1)
                    )
        with self.assertRaises(TypeError):
            explain_merkle_cardinality_weighted(
                4, (1, 1.5), _BUDGETS, (1, 1, 1, 1, 1)
            )
        for bad_budgets in ([None] * 6, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    explain_merkle_cardinality_weighted(
                        4, _SIZES, bad_budgets, (1, 1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            explain_merkle_cardinality_weighted(
                4, _SIZES, (None,) * 6, (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_cardinality_weighted(
                4, _SIZES, (None,) * 5, (1, 1, 1, 1, 1)
            )
        for bad_member in (0, -1, True, 1.5, "100"):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    explain_merkle_cardinality_weighted(
                        4,
                        _SIZES,
                        (None, bad_member, None, None, None, None),
                        (1, 1, 1, 1, 1),
                    )

    def test_frontier_arguments_screened_before_weights(self):
        # the capacity/group_sizes/budgets rules belong to the frontier and
        # are screened there before weights is inspected
        with self.assertRaises(ValueError):
            explain_merkle_cardinality_weighted(
                0, _SIZES, _BUDGETS, (0, 0, 0, 0, 0)
            )
        with self.assertRaises(TypeError):
            explain_merkle_cardinality_weighted(
                4, _SIZES, [None, None, None, 9000, None, None], "not a tuple"
            )

    def test_all_four_parameters_are_required_without_defaults(self):
        sig = inspect.signature(explain_merkle_cardinality_weighted)
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "group_sizes", "budgets", "weights"],
        )
        for name in ("capacity", "group_sizes", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_repeated_calls_are_deterministic(self):
        def exploding_token_bytes(size):
            raise AssertionError("pure parameter analysis must not draw randomness")

        import secrets
        from unittest import mock

        with mock.patch.object(secrets, "token_bytes", exploding_token_bytes):
            for weights in _WEIGHT_SETS:
                first = explain_merkle_cardinality_weighted(4, _SIZES, _BUDGETS, weights)
                second = explain_merkle_cardinality_weighted(4, _SIZES, _BUDGETS, weights)
                self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

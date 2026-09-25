import inspect
import unittest
from dataclasses import fields
from fractions import Fraction

import pqattest
from pqattest import (
    MerkleDeploymentScore,
    MerkleSigner,
    explain_merkle_deployment_weighted,
    merkle_deployment_frontier,
    profile,
    recommend_merkle_deployment_weighted,
)

_BUDGETS = (None, None, None, 9000)


def _metrics(storage):
    return (
        storage.checkpoint_bytes,
        storage.signature_wire_bytes,
        storage.proof_wire_bytes,
        profile("merkle", w=storage.w, height=storage.height).steps,
    )


def _tail(storage):
    return (
        storage.checkpoint_bytes,
        storage.leaf_count,
        storage.w,
        storage.height,
    )


def _normalised_rows(frontier):
    rows = [_metrics(storage) for storage in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(4)
    )
    normalised = tuple(
        tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(row, spans)
        )
        for row in rows
    )
    return normalised, spans


_WORKLOADS = (
    (1, (None, None, None, 10**18)),
    (16, _BUDGETS),
    (8, (9000, None, None, None)),
    (4, (None, 1300, None, None)),
    (2, (None, None, 1400, None)),
    (32, (None, None, None, 9000)),
    (100, (None, None, None, 10**18)),
    (4, (9000, 1300, 1400, 9000)),
)

_WEIGHT_SETS = (
    (1, 1, 1, 1),
    (10, 0, 0, 0),
    (0, 0, 0, 1),
    (1, 2, 3, 4),
    (0, 1, 0, 1),
    (10**9, 1, 1, 1),
    (3, 0, 7, 2),
)


class ExplainMerkleDeploymentWeightedTest(unittest.TestCase):
    def test_exported_from_package_top_level(self):
        self.assertIs(
            pqattest.explain_merkle_deployment_weighted,
            explain_merkle_deployment_weighted,
        )
        self.assertIn("explain_merkle_deployment_weighted", pqattest.__all__)
        self.assertIs(pqattest.MerkleDeploymentScore, MerkleDeploymentScore)
        self.assertIn("MerkleDeploymentScore", pqattest.__all__)

    def test_returns_a_tuple_of_frozen_score_rows(self):
        rows = explain_merkle_deployment_weighted(16, _BUDGETS, (1, 2, 3, 4))
        self.assertIsInstance(rows, tuple)
        for row in rows:
            self.assertIsInstance(row, MerkleDeploymentScore)

    def test_one_row_per_frontier_member_in_frontier_order(self):
        for capacity, budgets in _WORKLOADS:
            with self.subTest(capacity=capacity, budgets=budgets):
                frontier = merkle_deployment_frontier(capacity, budgets)
                rows = explain_merkle_deployment_weighted(
                    capacity, budgets, (1, 2, 3, 4)
                )
                self.assertEqual(len(rows), len(frontier))
                self.assertEqual(tuple(row.config for row in rows), frontier)

    def test_row_field_order_is_config_costs_score_selected(self):
        self.assertEqual(
            [field.name for field in fields(MerkleDeploymentScore)],
            ["config", "costs", "score", "selected"],
        )

    def test_exactly_one_selected_row(self):
        for capacity, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(capacity=capacity, weights=weights):
                    rows = explain_merkle_deployment_weighted(
                        capacity, budgets, weights
                    )
                    selected = [row for row in rows if row.selected]
                    self.assertEqual(len(selected), 1)
                    self.assertTrue(selected[0].selected)
                    self.assertEqual(
                        sum(1 for row in rows if not row.selected),
                        len(rows) - 1,
                    )

    def test_selected_matches_recommend_field_for_field(self):
        for capacity, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(capacity=capacity, weights=weights):
                    rows = explain_merkle_deployment_weighted(
                        capacity, budgets, weights
                    )
                    winner = recommend_merkle_deployment_weighted(
                        capacity, budgets, weights
                    )
                    selected = [row for row in rows if row.selected][0]
                    self.assertEqual(selected.config, winner)

    def test_costs_are_four_exact_fractions(self):
        rows = explain_merkle_deployment_weighted(16, _BUDGETS, (1, 2, 3, 4))
        for row in rows:
            self.assertIsInstance(row.costs, tuple)
            self.assertEqual(len(row.costs), 4)
            for cost in row.costs:
                self.assertIsInstance(cost, Fraction)
            self.assertIsInstance(row.score, Fraction)
            self.assertIsInstance(row.selected, bool)

    def test_normalised_costs_match_whole_frontier_min_max(self):
        for capacity, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(capacity=capacity, weights=weights):
                    frontier = merkle_deployment_frontier(capacity, budgets)
                    rows = explain_merkle_deployment_weighted(
                        capacity, budgets, weights
                    )
                    expected_costs, spans = _normalised_rows(frontier)
                    for row, expected in zip(rows, expected_costs):
                        self.assertEqual(row.costs, expected)
                        for cost, (low, high) in zip(row.costs, spans):
                            if high > low:
                                self.assertGreaterEqual(cost, 0)
                                self.assertLessEqual(cost, 1)
                            else:
                                # a zero span is recorded as zero
                                self.assertEqual(cost, Fraction(0))

    def test_score_is_weighted_sum_divided_by_total(self):
        for capacity, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(capacity=capacity, weights=weights):
                    rows = explain_merkle_deployment_weighted(
                        capacity, budgets, weights
                    )
                    total = sum(weights)
                    for row in rows:
                        expected_score = (
                            sum(
                                (
                                    weight * cost
                                    for weight, cost in zip(weights, row.costs)
                                ),
                                Fraction(0),
                            )
                            / total
                        )
                        self.assertEqual(row.score, expected_score)

    def test_selected_is_minimum_score_with_documented_tie_tail(self):
        for capacity, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(capacity=capacity, weights=weights):
                    rows = explain_merkle_deployment_weighted(
                        capacity, budgets, weights
                    )

                    def rank(row):
                        return (row.score, *_tail(row.config))

                    selected = [row for row in rows if row.selected][0]
                    self.assertEqual(selected, min(rows, key=rank))
                    for row in rows:
                        self.assertLessEqual(selected.score, row.score)

    def test_lone_positive_weight_selects_that_dimensions_minimum(self):
        # a lone positive weight makes the score exactly that dimension's
        # normalised cost, so the selected row minimises that raw dimension
        frontier = merkle_deployment_frontier(16, _BUDGETS)
        for dimension in range(4):
            weights = tuple(1 if i == dimension else 0 for i in range(4))
            with self.subTest(weights=weights):
                rows = explain_merkle_deployment_weighted(16, _BUDGETS, weights)
                selected = [row for row in rows if row.selected][0]
                for row in rows:
                    self.assertEqual(
                        row.score,
                        row.costs[dimension],
                    )
                minimum = min(_metrics(storage)[dimension] for storage in frontier)
                self.assertEqual(_metrics(selected.config)[dimension], minimum)

    def test_zero_span_frontier_rows_score_zero_and_tail_picks_winner(self):
        # a single-member frontier makes every span zero: the unique row
        # carries four zero costs and a zero score and is selected, with
        # the documented tail (not the weights) acting as the decider
        budgets = (None, None, None, 1005)
        frontier = merkle_deployment_frontier(1, budgets)
        self.assertEqual(len(frontier), 1)
        for weights in (
            (1, 1, 1, 1),
            (0, 0, 0, 1),
            (9, 8, 7, 6),
            (10**12, 0, 0, 0),
        ):
            with self.subTest(weights=weights):
                rows = explain_merkle_deployment_weighted(1, budgets, weights)
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(row.costs, (Fraction(0),) * 4)
                self.assertEqual(row.score, Fraction(0))
                self.assertTrue(row.selected)
                self.assertEqual(row.config, frontier[0])

    def test_weight_scaling_leaves_scores_and_selection_unchanged(self):
        # dividing by the weight total makes a common scale irrelevant
        base = explain_merkle_deployment_weighted(16, _BUDGETS, (1, 2, 3, 4))
        scaled = explain_merkle_deployment_weighted(16, _BUDGETS, (7, 14, 21, 28))
        self.assertEqual(
            tuple((row.costs, row.score) for row in base),
            tuple((row.costs, row.score) for row in scaled),
        )
        self.assertEqual(
            tuple(row.selected for row in base),
            tuple(row.selected for row in scaled),
        )

    def test_rows_are_positionally_constructible_equal_and_hashable(self):
        rows = explain_merkle_deployment_weighted(16, _BUDGETS, (1, 2, 3, 4))
        row = rows[0]
        rebuilt = MerkleDeploymentScore(
            row.config,
            row.costs,
            row.score,
            row.selected,
        )
        self.assertEqual(rebuilt, row)
        self.assertEqual(hash(rebuilt), hash(row))
        # the row tuple and a set of its members both hash the frozen rows
        self.assertEqual(len(set(rows)), len(rows))
        self.assertIn(row, {row})
        self.assertEqual(tuple(rows), rows)

    def test_rows_are_frozen(self):
        row = explain_merkle_deployment_weighted(16, _BUDGETS, (1, 2, 3, 4))[0]
        for name, value in (
            ("config", row.config),
            ("costs", row.costs),
            ("score", row.score),
            ("selected", row.selected),
        ):
            with self.subTest(field=name):
                with self.assertRaises(Exception):
                    setattr(row, name, value)

    def test_frontier_called_once_no_duplicate_enumeration(self):
        calls = 0
        original = merkle_deployment_frontier

        import pqattest.params as params_module

        def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)

        params_module.merkle_deployment_frontier = counting
        try:
            for weights in _WEIGHT_SETS:
                calls = 0
                explain_merkle_deployment_weighted(16, _BUDGETS, weights)
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_deployment_frontier = original

    def test_no_feasible_candidate_raises_and_returns_no_rows(self):
        for capacity, budgets in (
            (1, (100, None, None, None)),
            (256, (None, 1000, None, None)),
            (4, (None, None, None, 10)),
        ):
            with self.subTest(capacity=capacity, budgets=budgets):
                with self.assertRaises(ValueError):
                    explain_merkle_deployment_weighted(
                        capacity, budgets, (1, 1, 1, 1)
                    )

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 1, 1, 1], {1, 2, 3, 4}, "weights", None, 7, range(4)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_deployment_weighted(16, _BUDGETS, bad)

    def test_non_integer_weight_raises_type_error(self):
        for bad in (
            (1.0, 1, 1, 1),
            (1, "1", 1, 1),
            (1, None, 1, 1),
            (1, 1, 1, 1.5),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_deployment_weighted(16, _BUDGETS, bad)

    def test_invalid_weights_members_raise_value_error(self):
        for bad in (
            (),
            (1, 1, 1),
            (1, 1, 1, 1, 1),
            (0, 0, 0, 0),
            (1, -1, 1, 1),
            (-1, 1, 1, 1),
            (True, 1, 1, 1),
            (1, 1, 1, False),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_deployment_weighted(16, _BUDGETS, bad)

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in ((True, 0, 0, 0), (0, 0, 0, True)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_deployment_weighted(16, _BUDGETS, bad)

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    explain_merkle_deployment_weighted(
                        bad_capacity, _BUDGETS, (1, 1, 1, 1)
                    )
        for bad_budgets in ([None] * 4, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    explain_merkle_deployment_weighted(
                        16, bad_budgets, (1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            explain_merkle_deployment_weighted(
                16, (None,) * 4, (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_deployment_weighted(
                16, (None,) * 3, (1, 1, 1, 1)
            )
        for bad_member in (0, -1, True, 1.5, "100"):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    explain_merkle_deployment_weighted(
                        16, (None, bad_member, None, None), (1, 1, 1, 1)
                    )

    def test_frontier_arguments_screened_before_weights(self):
        # the capacity/budgets rules belong to the frontier and are
        # screened there before weights is inspected
        with self.assertRaises(ValueError):
            explain_merkle_deployment_weighted(0, (None,) * 4, (0, 0, 0, 0))
        with self.assertRaises(TypeError):
            explain_merkle_deployment_weighted(
                16, [None, None, None, 9000], "not a tuple"
            )

    def test_all_three_parameters_are_required_without_defaults(self):
        sig = inspect.signature(explain_merkle_deployment_weighted)
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "budgets", "weights"],
        )
        for name in ("capacity", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_repeated_calls_are_deterministic_and_state_free(self):
        signer = MerkleSigner(w=4, height=2)
        for weights in _WEIGHT_SETS:
            first = explain_merkle_deployment_weighted(16, _BUDGETS, weights)
            second = explain_merkle_deployment_weighted(16, _BUDGETS, weights)
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)

    def test_budgets_are_honoured_in_every_row(self):
        budgets = (9000, 1300, 1400, 9000)
        rows = explain_merkle_deployment_weighted(4, budgets, (1, 2, 3, 4))
        self.assertTrue(rows)
        for row in rows:
            storage = row.config
            self.assertLessEqual(storage.checkpoint_bytes, 9000)
            self.assertLessEqual(storage.signature_wire_bytes, 1300)
            self.assertLessEqual(storage.proof_wire_bytes, 1400)
            self.assertLessEqual(
                profile("merkle", w=storage.w, height=storage.height).steps,
                9000,
            )


if __name__ == "__main__":
    unittest.main()

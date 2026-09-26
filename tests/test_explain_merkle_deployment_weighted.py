import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleDeploymentScore,
    MerkleStorageProfile,
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


def _expected_rows(capacity, budgets, weights):
    """Recompute the documented per-candidate breakdown independently."""
    frontier = merkle_deployment_frontier(capacity, budgets)
    rows = [_metrics(storage) for storage in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(4)
    )
    total = sum(weights)

    entries = []
    for storage, values in zip(frontier, rows):
        costs = tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(values, spans)
        )
        score = sum(
            (weight * cost for weight, cost in zip(weights, costs)),
            Fraction(0),
        ) / total
        entries.append((storage, costs, score))

    chosen = min(entries, key=lambda entry: (entry[2], *_tail(entry[0])))[0]
    return tuple(
        MerkleDeploymentScore(storage, *costs, score, storage == chosen)
        for storage, costs, score in entries
    )


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
    def test_matches_brute_force_breakdown(self):
        for capacity, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    budgets=budgets,
                    weights=weights,
                ):
                    self.assertEqual(
                        explain_merkle_deployment_weighted(
                            capacity, budgets, weights
                        ),
                        _expected_rows(capacity, budgets, weights),
                    )

    def test_row_order_matches_frontier_member_order(self):
        frontier = merkle_deployment_frontier(16, _BUDGETS)
        self.assertGreater(len(frontier), 1)
        for weights in _WEIGHT_SETS:
            with self.subTest(weights=weights):
                rows = explain_merkle_deployment_weighted(16, _BUDGETS, weights)
                self.assertIsInstance(rows, tuple)
                self.assertEqual(len(rows), len(frontier))
                self.assertEqual(
                    tuple(row.config for row in rows),
                    frontier,
                )

    def test_row_fields_and_types(self):
        rows = explain_merkle_deployment_weighted(16, _BUDGETS, (1, 2, 3, 4))
        for row in rows:
            self.assertIsInstance(row, MerkleDeploymentScore)
            self.assertIsInstance(row.config, MerkleStorageProfile)
            for cost in (
                row.checkpoint_cost,
                row.signature_cost,
                row.proof_cost,
                row.steps_cost,
                row.score,
            ):
                self.assertIsInstance(cost, Fraction)
                self.assertGreaterEqual(cost, 0)
            for cost in (
                row.checkpoint_cost,
                row.signature_cost,
                row.proof_cost,
                row.steps_cost,
            ):
                self.assertLessEqual(cost, 1)
            self.assertIsInstance(row.selected, bool)

    def test_exactly_one_row_selected_and_matches_recommendation(self):
        for capacity, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    budgets=budgets,
                    weights=weights,
                ):
                    rows = explain_merkle_deployment_weighted(
                        capacity, budgets, weights
                    )
                    selected = [row for row in rows if row.selected]
                    self.assertEqual(len(selected), 1)
                    self.assertEqual(
                        selected[0].config,
                        recommend_merkle_deployment_weighted(
                            capacity, budgets, weights
                        ),
                    )

    def test_selected_row_has_the_smallest_score_with_documented_tail(self):
        for capacity, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    budgets=budgets,
                    weights=weights,
                ):
                    rows = explain_merkle_deployment_weighted(
                        capacity, budgets, weights
                    )
                    best = min(row.score for row in rows)
                    tied = [row for row in rows if row.score == best]
                    chosen = [row for row in rows if row.selected][0]
                    self.assertIn(chosen, tied)
                    self.assertEqual(
                        chosen.config,
                        min((row.config for row in tied), key=_tail),
                    )

    def test_rows_are_frozen_positional_value_objects(self):
        rows = explain_merkle_deployment_weighted(16, _BUDGETS, (1, 1, 1, 1))
        row = rows[0]
        clone = MerkleDeploymentScore(
            row.config,
            row.checkpoint_cost,
            row.signature_cost,
            row.proof_cost,
            row.steps_cost,
            row.score,
            row.selected,
        )
        self.assertEqual(clone, row)
        self.assertEqual(hash(clone), hash(row))
        self.assertEqual(
            (
                clone.config,
                clone.checkpoint_cost,
                clone.signature_cost,
                clone.proof_cost,
                clone.steps_cost,
                clone.score,
                clone.selected,
            ),
            (
                row.config,
                row.checkpoint_cost,
                row.signature_cost,
                row.proof_cost,
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
                self.assertEqual(row.config, frontier[0])
                self.assertEqual(
                    (
                        row.checkpoint_cost,
                        row.signature_cost,
                        row.proof_cost,
                        row.steps_cost,
                        row.score,
                    ),
                    (Fraction(0),) * 5,
                )
                self.assertTrue(row.selected)

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

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            explain_merkle_deployment_weighted(
                1, (100, None, None, None), (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_deployment_weighted(
                256, (None, 1000, None, None), (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_deployment_weighted(
                4, (None, None, None, 10), (1, 1, 1, 1)
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
            explain_merkle_deployment_weighted(
                0, (None,) * 4, (0, 0, 0, 0)
            )
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

    def test_repeated_calls_are_deterministic(self):
        def exploding_token_bytes(size):
            raise AssertionError("pure parameter analysis must not draw randomness")

        import secrets
        from unittest import mock

        with mock.patch.object(secrets, "token_bytes", exploding_token_bytes):
            for weights in _WEIGHT_SETS:
                first = explain_merkle_deployment_weighted(16, _BUDGETS, weights)
                second = explain_merkle_deployment_weighted(16, _BUDGETS, weights)
                self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

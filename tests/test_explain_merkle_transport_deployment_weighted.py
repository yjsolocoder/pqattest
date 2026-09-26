import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleTransportDeploymentProfile,
    MerkleTransportDeploymentScore,
    explain_merkle_transport_deployment_weighted,
    merkle_transport_deployment_frontier,
    profile,
    recommend_merkle_transport_deployment_weighted,
)

_INDICES = (1, 2)
_BUDGETS = (None, None, None, 9000)


def _metrics(deployment):
    return (
        deployment.batch,
        deployment.multi,
        deployment.nodes,
        deployment.config.checkpoint_bytes,
        profile(
            "merkle", w=deployment.config.w, height=deployment.config.height
        ).steps,
    )


def _tail(deployment):
    config = deployment.config
    return (
        config.checkpoint_bytes,
        config.leaf_count,
        config.w,
        config.height,
    )


def _expected_rows(capacity, indices, budgets, weights):
    """Recompute the documented per-candidate breakdown independently."""
    frontier = merkle_transport_deployment_frontier(capacity, indices, budgets)
    rows = [_metrics(deployment) for deployment in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(5)
    )
    total = sum(weights)

    entries = []
    for deployment, values in zip(frontier, rows):
        costs = tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(values, spans)
        )
        score = sum(
            (weight * cost for weight, cost in zip(weights, costs)),
            Fraction(0),
        ) / total
        entries.append((deployment, costs, score))

    chosen = min(entries, key=lambda entry: (entry[2], *_tail(entry[0])))[0]
    return tuple(
        MerkleTransportDeploymentScore(
            deployment, *costs, score, deployment == chosen
        )
        for deployment, costs, score in entries
    )


_WORKLOADS = (
    (1, (0,), (None, None, None, 10**6)),
    (4, _INDICES, _BUDGETS),
    (16, (3, 5), (None, None, 8000, None)),
    (8, (0, 1, 6), (9000, None, None, None)),
    (2, (0, 3), (None, 4000, None, None)),
    (32, (1, 7, 16), (None, None, None, 9000)),
    (4, (0, 1, 2, 3), (None, None, None, 10**6)),
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


class ExplainMerkleTransportDeploymentWeightedTest(unittest.TestCase):
    def test_matches_brute_force_breakdown(self):
        for capacity, indices, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    indices=indices,
                    budgets=budgets,
                    weights=weights,
                ):
                    self.assertEqual(
                        explain_merkle_transport_deployment_weighted(
                            capacity, indices, budgets, weights
                        ),
                        _expected_rows(capacity, indices, budgets, weights),
                    )

    def test_row_order_matches_frontier_member_order(self):
        frontier = merkle_transport_deployment_frontier(4, _INDICES, _BUDGETS)
        self.assertGreater(len(frontier), 1)
        for weights in _WEIGHT_SETS:
            with self.subTest(weights=weights):
                rows = explain_merkle_transport_deployment_weighted(
                    4, _INDICES, _BUDGETS, weights
                )
                self.assertIsInstance(rows, tuple)
                self.assertEqual(len(rows), len(frontier))
                self.assertEqual(
                    tuple(row.deployment for row in rows),
                    frontier,
                )

    def test_row_fields_and_types(self):
        rows = explain_merkle_transport_deployment_weighted(
            4, _INDICES, _BUDGETS, (1, 2, 3, 4, 5)
        )
        for row in rows:
            self.assertIsInstance(row, MerkleTransportDeploymentScore)
            self.assertIsInstance(
                row.deployment, MerkleTransportDeploymentProfile
            )
            for cost in (
                row.batch_cost,
                row.multi_cost,
                row.nodes_cost,
                row.checkpoint_cost,
                row.steps_cost,
                row.score,
            ):
                self.assertIsInstance(cost, Fraction)
                self.assertGreaterEqual(cost, 0)
            for cost in (
                row.batch_cost,
                row.multi_cost,
                row.nodes_cost,
                row.checkpoint_cost,
                row.steps_cost,
            ):
                self.assertLessEqual(cost, 1)
            self.assertIsInstance(row.selected, bool)

    def test_exactly_one_row_selected_and_matches_recommendation(self):
        for capacity, indices, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    indices=indices,
                    budgets=budgets,
                    weights=weights,
                ):
                    rows = explain_merkle_transport_deployment_weighted(
                        capacity, indices, budgets, weights
                    )
                    selected = [row for row in rows if row.selected]
                    self.assertEqual(len(selected), 1)
                    self.assertEqual(
                        selected[0].deployment,
                        recommend_merkle_transport_deployment_weighted(
                            capacity, indices, budgets, weights
                        ),
                    )

    def test_selected_row_has_the_smallest_score_with_documented_tail(self):
        for capacity, indices, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    indices=indices,
                    budgets=budgets,
                    weights=weights,
                ):
                    rows = explain_merkle_transport_deployment_weighted(
                        capacity, indices, budgets, weights
                    )
                    best = min(row.score for row in rows)
                    tied = [row for row in rows if row.score == best]
                    chosen = [row for row in rows if row.selected][0]
                    self.assertIn(chosen, tied)
                    self.assertEqual(
                        chosen.deployment,
                        min((row.deployment for row in tied), key=_tail),
                    )

    def test_rows_are_frozen_positional_value_objects(self):
        rows = explain_merkle_transport_deployment_weighted(
            4, _INDICES, _BUDGETS, (1, 1, 1, 1, 1)
        )
        row = rows[0]
        clone = MerkleTransportDeploymentScore(
            row.deployment,
            row.batch_cost,
            row.multi_cost,
            row.nodes_cost,
            row.checkpoint_cost,
            row.steps_cost,
            row.score,
            row.selected,
        )
        self.assertEqual(clone, row)
        self.assertEqual(hash(clone), hash(row))
        self.assertEqual(
            (
                clone.deployment,
                clone.batch_cost,
                clone.multi_cost,
                clone.nodes_cost,
                clone.checkpoint_cost,
                clone.steps_cost,
                clone.score,
                clone.selected,
            ),
            (
                row.deployment,
                row.batch_cost,
                row.multi_cost,
                row.nodes_cost,
                row.checkpoint_cost,
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
        frontier = merkle_transport_deployment_frontier(1, (0,), budgets)
        self.assertEqual(len(frontier), 1)
        for weights in (
            (1, 1, 1, 1, 1),
            (0, 0, 0, 0, 1),
            (9, 8, 7, 6, 5),
            (10**12, 0, 0, 0, 0),
        ):
            with self.subTest(weights=weights):
                rows = explain_merkle_transport_deployment_weighted(
                    1, (0,), budgets, weights
                )
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(row.deployment, frontier[0])
                self.assertEqual(
                    (
                        row.batch_cost,
                        row.multi_cost,
                        row.nodes_cost,
                        row.checkpoint_cost,
                        row.steps_cost,
                        row.score,
                    ),
                    (Fraction(0),) * 6,
                )
                self.assertTrue(row.selected)

    def test_frontier_called_once_no_duplicate_enumeration(self):
        calls = 0
        original = merkle_transport_deployment_frontier

        import pqattest.params as params_module

        def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)

        params_module.merkle_transport_deployment_frontier = counting
        try:
            for weights in _WEIGHT_SETS:
                calls = 0
                explain_merkle_transport_deployment_weighted(
                    4, _INDICES, _BUDGETS, weights
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_transport_deployment_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted(
                1, (0,), (100, None, None, None), (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted(
                1, (255,), (None, None, None, 1), (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted(
                4, (1,), (None, None, None, 10), (1, 1, 1, 1, 1)
            )

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 1, 1, 1, 1], {1, 2, 3, 4, 5}, "weights", None, 7, range(5)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_deployment_weighted(
                        4, _INDICES, _BUDGETS, bad
                    )

    def test_invalid_weights_members_raise_value_error(self):
        bad_bases = (
            (),
            (1, 1, 1, 1),
            (1, 1, 1, 1, 1, 1),
            (0, 0, 0, 0, 0),
        )
        for bad in bad_bases:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_transport_deployment_weighted(
                        4, _INDICES, _BUDGETS, bad
                    )
        # a boolean, negative or non-integer member is rejected at every
        # position, not just the first one the validator inspects
        good = (1, 1, 1, 1, 1)
        for position in range(5):
            for replacement in (-1, True, False, 1.0, "1", None, 1.5):
                bad = tuple(
                    replacement if index == position else good[index]
                    for index in range(5)
                )
                with self.subTest(position=position, replacement=replacement):
                    with self.assertRaises(ValueError):
                        explain_merkle_transport_deployment_weighted(
                            4, _INDICES, _BUDGETS, bad
                        )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in ((True, 0, 0, 0, 0), (0, 0, 0, 0, True)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_transport_deployment_weighted(
                        4, _INDICES, _BUDGETS, bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    explain_merkle_transport_deployment_weighted(
                        bad_capacity, _INDICES, _BUDGETS, (1, 1, 1, 1, 1)
                    )
        for bad_indices in ([1, 2], {1, 2}, "indices", None, 7, range(2)):
            with self.subTest(bad_indices=bad_indices):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_deployment_weighted(
                        4, bad_indices, _BUDGETS, (1, 1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted(
                4, (), _BUDGETS, (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted(
                4, (2, 1), _BUDGETS, (1, 1, 1, 1, 1)
            )
        for bad_budgets in ([None] * 4, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_deployment_weighted(
                        4, _INDICES, bad_budgets, (1, 1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted(
                4, _INDICES, (None,) * 4, (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted(
                4, _INDICES, (None,) * 3, (1, 1, 1, 1, 1)
            )

    def test_frontier_arguments_screened_before_weights(self):
        # the capacity/indices/budgets rules belong to the frontier and are
        # screened there, before the weights are looked at
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted(
                0, (), (None,) * 4, (0, 0, 0, 0, 0)
            )
        with self.assertRaises(TypeError):
            explain_merkle_transport_deployment_weighted(
                4, [1, 2], _BUDGETS, "not a tuple"
            )

    def test_all_four_parameters_are_required_without_defaults(self):
        sig = inspect.signature(explain_merkle_transport_deployment_weighted)
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "indices", "budgets", "weights"],
        )
        for name in ("capacity", "indices", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_repeated_calls_are_deterministic(self):
        def exploding_token_bytes(size):
            raise AssertionError("pure parameter analysis must not draw randomness")

        import secrets
        from unittest import mock

        with mock.patch.object(secrets, "token_bytes", exploding_token_bytes):
            for weights in _WEIGHT_SETS:
                first = explain_merkle_transport_deployment_weighted(
                    4, _INDICES, _BUDGETS, weights
                )
                second = explain_merkle_transport_deployment_weighted(
                    4, _INDICES, _BUDGETS, weights
                )
                self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

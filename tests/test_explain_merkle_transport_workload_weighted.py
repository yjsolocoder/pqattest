import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleSigner,
    MerkleTransportWorkloadProfile,
    MerkleTransportWorkloadScore,
    explain_merkle_transport_workload_weighted,
    merkle_transport_workload_frontier,
    profile,
    recommend_merkle_transport_workload_weighted,
)

_GROUPS = ((0,), (2, 3))
_BUDGETS = (None, None, None, 9000)


def _metrics(workload):
    return (
        workload.config.checkpoint_bytes,
        max(workload.sizes),
        workload.total,
        profile(
            "merkle", w=workload.config.w, height=workload.config.height
        ).steps,
    )


def _tail(workload):
    config = workload.config
    return (
        config.checkpoint_bytes,
        config.leaf_count,
        config.w,
        config.height,
        workload.modes,
    )


def _expected_rows(capacity, groups, budgets, weights):
    """Recompute the documented per-candidate breakdown independently."""
    frontier = merkle_transport_workload_frontier(capacity, groups, budgets)
    rows = [_metrics(workload) for workload in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(4)
    )
    total = sum(weights)

    entries = []
    for workload, values in zip(frontier, rows):
        costs = tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(values, spans)
        )
        score = sum(
            (weight * cost for weight, cost in zip(weights, costs)),
            Fraction(0),
        ) / total
        entries.append((workload, costs, score))

    chosen = min(entries, key=lambda entry: (entry[2], *_tail(entry[0])))[0]
    return tuple(
        MerkleTransportWorkloadScore(
            workload, *costs, score, workload == chosen
        )
        for workload, costs, score in entries
    )


_WORKLOADS = (
    (1, ((0,),), (None, None, None, 10**18)),
    (16, _GROUPS, _BUDGETS),
    (16, ((1,), (2,), (3,), (4,), (8,)), (None, None, None, 10**18)),
    (8, ((0,), (1, 2), (4,)), (9000, None, None, None)),
    (4, ((2,),), (None, 4000, None, None)),
    (4, ((0,), (1,)), (9000, None, 7000, None)),
    (2, ((0,), (1,)), (None, None, None, 6000)),
    (32, ((0,), (6, 7), (15, 16)), (None, None, None, 9000)),
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


class ExplainMerkleTransportWorkloadWeightedTest(unittest.TestCase):
    def test_matches_brute_force_breakdown(self):
        for capacity, groups, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    weights=weights,
                ):
                    self.assertEqual(
                        explain_merkle_transport_workload_weighted(
                            capacity, groups, budgets, weights
                        ),
                        _expected_rows(capacity, groups, budgets, weights),
                    )

    def test_row_order_matches_frontier_member_order(self):
        frontier = merkle_transport_workload_frontier(16, _GROUPS, _BUDGETS)
        self.assertGreater(len(frontier), 1)
        for weights in _WEIGHT_SETS:
            with self.subTest(weights=weights):
                rows = explain_merkle_transport_workload_weighted(
                    16, _GROUPS, _BUDGETS, weights
                )
                self.assertIsInstance(rows, tuple)
                self.assertEqual(len(rows), len(frontier))
                self.assertEqual(
                    tuple(row.workload for row in rows),
                    frontier,
                )

    def test_row_fields_and_types(self):
        rows = explain_merkle_transport_workload_weighted(
            16, _GROUPS, _BUDGETS, (1, 2, 3, 4)
        )
        for row in rows:
            self.assertIsInstance(row, MerkleTransportWorkloadScore)
            self.assertIsInstance(row.workload, MerkleTransportWorkloadProfile)
            for cost in (
                row.checkpoint_cost,
                row.peak_cost,
                row.transport_cost,
                row.steps_cost,
                row.score,
            ):
                self.assertIsInstance(cost, Fraction)
                self.assertGreaterEqual(cost, 0)
            for cost in (
                row.checkpoint_cost,
                row.peak_cost,
                row.transport_cost,
                row.steps_cost,
            ):
                self.assertLessEqual(cost, 1)
            self.assertIsInstance(row.selected, bool)

    def test_exactly_one_row_selected_and_matches_recommendation(self):
        for capacity, groups, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    weights=weights,
                ):
                    rows = explain_merkle_transport_workload_weighted(
                        capacity, groups, budgets, weights
                    )
                    selected = [row for row in rows if row.selected]
                    self.assertEqual(len(selected), 1)
                    self.assertEqual(
                        selected[0].workload,
                        recommend_merkle_transport_workload_weighted(
                            capacity, groups, budgets, weights
                        ),
                    )

    def test_selected_row_has_the_smallest_score_with_documented_tail(self):
        for capacity, groups, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    weights=weights,
                ):
                    rows = explain_merkle_transport_workload_weighted(
                        capacity, groups, budgets, weights
                    )
                    best = min(row.score for row in rows)
                    tied = [row for row in rows if row.score == best]
                    chosen = [row for row in rows if row.selected][0]
                    self.assertIn(chosen, tied)
                    self.assertEqual(
                        chosen.workload,
                        min((row.workload for row in tied), key=_tail),
                    )

    def test_rows_are_frozen_positional_value_objects(self):
        rows = explain_merkle_transport_workload_weighted(
            16, _GROUPS, _BUDGETS, (1, 1, 1, 1)
        )
        row = rows[0]
        clone = MerkleTransportWorkloadScore(
            row.workload,
            row.checkpoint_cost,
            row.peak_cost,
            row.transport_cost,
            row.steps_cost,
            row.score,
            row.selected,
        )
        self.assertEqual(clone, row)
        self.assertEqual(hash(clone), hash(row))
        self.assertEqual(
            (
                clone.workload,
                clone.checkpoint_cost,
                clone.peak_cost,
                clone.transport_cost,
                clone.steps_cost,
                clone.score,
                clone.selected,
            ),
            (
                row.workload,
                row.checkpoint_cost,
                row.peak_cost,
                row.transport_cost,
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
        budgets = (None, 5000, 12000, None)
        groups = ((0, 1), (3, 5), (8, 9, 10))
        frontier = merkle_transport_workload_frontier(16, groups, budgets)
        self.assertEqual(len(frontier), 1)
        for weights in (
            (1, 1, 1, 1),
            (0, 0, 0, 1),
            (9, 8, 7, 6),
            (10**12, 0, 0, 0),
        ):
            with self.subTest(weights=weights):
                rows = explain_merkle_transport_workload_weighted(
                    16, groups, budgets, weights
                )
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(row.workload, frontier[0])
                self.assertEqual(
                    (
                        row.checkpoint_cost,
                        row.peak_cost,
                        row.transport_cost,
                        row.steps_cost,
                        row.score,
                    ),
                    (Fraction(0),) * 5,
                )
                self.assertTrue(row.selected)

    def test_frontier_called_once_no_duplicate_enumeration(self):
        calls = 0
        original = merkle_transport_workload_frontier

        import pqattest.params as params_module

        def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)

        params_module.merkle_transport_workload_frontier = counting
        try:
            for weights in _WEIGHT_SETS:
                calls = 0
                explain_merkle_transport_workload_weighted(
                    16, _GROUPS, _BUDGETS, weights
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_transport_workload_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted(
                1, ((0,),), (100, None, None, None), (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted(
                1, ((255,),), (None, None, None, 1), (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted(
                4, _GROUPS, (None, None, None, 10), (1, 1, 1, 1)
            )

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 1, 1, 1], {1, 2, 3, 4}, "weights", None, 7, range(4)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_workload_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )

    def test_invalid_weights_members_raise_value_error(self):
        bad_bases = (
            (),
            (1, 1, 1),
            (1, 1, 1, 1, 1),
            (0, 0, 0, 0),
        )
        for bad in bad_bases:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_transport_workload_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )
        # a boolean or negative member is rejected at every position, not
        # just the first one the validator inspects
        good = (1, 1, 1, 1)
        for position in range(4):
            for replacement in (-1, True, False):
                bad = tuple(
                    replacement if index == position else good[index]
                    for index in range(4)
                )
                with self.subTest(position=position, replacement=replacement):
                    with self.assertRaises(ValueError):
                        explain_merkle_transport_workload_weighted(
                            16, _GROUPS, _BUDGETS, bad
                        )

    def test_non_integer_weight_members_raise_type_error_at_every_position(self):
        good = (1, 1, 1, 1)
        for position in range(4):
            for replacement in (1.0, "1", None, 1.5):
                bad = tuple(
                    replacement if index == position else good[index]
                    for index in range(4)
                )
                with self.subTest(position=position, replacement=replacement):
                    with self.assertRaises(TypeError):
                        explain_merkle_transport_workload_weighted(
                            16, _GROUPS, _BUDGETS, bad
                        )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in ((True, 0, 0, 0), (0, 0, 0, True)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_transport_workload_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    explain_merkle_transport_workload_weighted(
                        bad_capacity, _GROUPS, _BUDGETS, (1, 1, 1, 1)
                    )
        for bad_groups in ([(0,)], {(0,)}, "groups", None, 7, range(2)):
            with self.subTest(bad_groups=bad_groups):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_workload_weighted(
                        16, bad_groups, _BUDGETS, (1, 1, 1, 1)
                    )
        with self.assertRaises(TypeError):
            explain_merkle_transport_workload_weighted(
                16, ([0],), _BUDGETS, (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted(
                16, (), _BUDGETS, (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted(
                16, ((),), _BUDGETS, (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted(
                16, ((2, 1),), _BUDGETS, (1, 1, 1, 1)
            )
        for bad_budgets in ([None] * 4, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_workload_weighted(
                        16, _GROUPS, bad_budgets, (1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted(
                16, _GROUPS, (None,) * 4, (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted(
                16, _GROUPS, (None,) * 3, (1, 1, 1, 1)
            )

    def test_frontier_arguments_screened_before_weights(self):
        # the capacity/groups/budgets rules belong to the frontier and are
        # screened there, before the weights are looked at
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted(
                0, (), (None,) * 4, (0, 0, 0, 0)
            )
        with self.assertRaises(TypeError):
            explain_merkle_transport_workload_weighted(
                16, [(0,)], _BUDGETS, "not a tuple"
            )

    def test_all_four_parameters_are_required_without_defaults(self):
        sig = inspect.signature(explain_merkle_transport_workload_weighted)
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "groups", "budgets", "weights"],
        )
        for name in ("capacity", "groups", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_repeated_calls_are_deterministic(self):
        signer = MerkleSigner(w=4, height=2)
        for weights in _WEIGHT_SETS:
            first = explain_merkle_transport_workload_weighted(
                16, _GROUPS, _BUDGETS, weights
            )
            second = explain_merkle_transport_workload_weighted(
                16, _GROUPS, _BUDGETS, weights
            )
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

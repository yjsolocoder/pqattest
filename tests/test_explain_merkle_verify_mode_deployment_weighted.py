import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleModeCost,
    MerkleVerifyModeDeploymentScore,
    explain_merkle_verify_mode_deployment_weighted,
    merkle_verify_mode_frontier,
    profile,
    recommend_merkle_verify_mode_deployment_weighted,
)

_GROUPS = ((0, 1), (3, 5))
_BUDGETS = (None, 5000, 12000, None, 8, None)


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


def _expected_rows(capacity, groups, budgets, weights):
    """Recompute the documented per-candidate breakdown independently."""
    frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
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
        MerkleVerifyModeDeploymentScore(mode_cost, *costs, score, mode_cost == chosen)
        for mode_cost, costs, score in entries
    )


_WORKLOADS = (
    (1, ((0,),), (None, None, None, None, None, 10**18)),
    (16, _GROUPS, _BUDGETS),
    (16, ((1,), (2,), (3,), (4,), (8,)), (None, None, None, None, None, 10**18)),
    (8, ((0,), (1, 2), (4,)), (9000, None, None, None, None, None)),
    (4, ((2,),), (None, 4000, None, None, None, None)),
    (4, ((0,), (1,)), (9000, None, 7000, None, 4, None)),
    (2, ((0,), (1,)), (None, None, None, None, None, 6000)),
    (32, ((0,), (6, 7), (15, 16)), (None, None, None, None, 50, None)),
)

_WEIGHT_SETS = (
    (1, 1, 1, 1, 1),
    (10, 0, 0, 0, 0),
    (0, 0, 0, 0, 1),
    (1, 2, 3, 4, 5),
    (0, 1, 0, 1, 0),
    (10**9, 1, 1, 1, 1),
    (3, 0, 7, 0, 2),
    (0, 0, 1, 0, 0),
    (0, 5, 0, 0, 0),
)


class ExplainMerkleVerifyModeDeploymentWeightedTest(unittest.TestCase):
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
                        explain_merkle_verify_mode_deployment_weighted(
                            capacity, groups, budgets, weights
                        ),
                        _expected_rows(capacity, groups, budgets, weights),
                    )

    def test_row_order_matches_frontier_member_order(self):
        frontier = merkle_verify_mode_frontier(16, _GROUPS, _BUDGETS)
        self.assertGreater(len(frontier), 1)
        for weights in _WEIGHT_SETS:
            with self.subTest(weights=weights):
                rows = explain_merkle_verify_mode_deployment_weighted(
                    16, _GROUPS, _BUDGETS, weights
                )
                self.assertIsInstance(rows, tuple)
                self.assertEqual(len(rows), len(frontier))
                self.assertEqual(
                    tuple(row.mode_cost for row in rows),
                    frontier,
                )

    def test_row_fields_and_types(self):
        rows = explain_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, _BUDGETS, (1, 2, 3, 4, 5)
        )
        for row in rows:
            self.assertIsInstance(row, MerkleVerifyModeDeploymentScore)
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
        for capacity, groups, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    weights=weights,
                ):
                    rows = explain_merkle_verify_mode_deployment_weighted(
                        capacity, groups, budgets, weights
                    )
                    selected = [row for row in rows if row.selected]
                    self.assertEqual(len(selected), 1)
                    self.assertEqual(
                        selected[0].mode_cost,
                        recommend_merkle_verify_mode_deployment_weighted(
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
                    rows = explain_merkle_verify_mode_deployment_weighted(
                        capacity, groups, budgets, weights
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
        rows = explain_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, _BUDGETS, (1, 1, 1, 1, 1)
        )
        row = rows[0]
        clone = MerkleVerifyModeDeploymentScore(
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
        budgets = (None, None, 2243, None, None, 2000)
        frontier = merkle_verify_mode_frontier(1, ((0,),), budgets)
        self.assertEqual(len(frontier), 1)
        for weights in (
            (1, 1, 1, 1, 1),
            (0, 0, 0, 0, 1),
            (9, 8, 7, 6, 5),
            (10**12, 0, 0, 0, 0),
        ):
            with self.subTest(weights=weights):
                rows = explain_merkle_verify_mode_deployment_weighted(
                    1, ((0,),), budgets, weights
                )
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
        original = merkle_verify_mode_frontier

        import pqattest.params as params_module

        def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)

        params_module.merkle_verify_mode_frontier = counting
        try:
            for weights in _WEIGHT_SETS:
                calls = 0
                explain_merkle_verify_mode_deployment_weighted(
                    16, _GROUPS, _BUDGETS, weights
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_verify_mode_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            explain_merkle_verify_mode_deployment_weighted(
                1,
                ((0,),),
                (100, None, None, None, None, None),
                (1, 1, 1, 1, 1),
            )
        with self.assertRaises(ValueError):
            explain_merkle_verify_mode_deployment_weighted(
                4,
                ((0,),),
                (None, None, None, None, None, 10),
                (1, 1, 1, 1, 1),
            )

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 1, 1, 1, 1], {1, 2, 3, 4, 5}, "weights", None, 7, range(5)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_verify_mode_deployment_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )

    def test_non_integer_weight_raises_type_error(self):
        for bad in (
            (1.0, 1, 1, 1, 1),
            (1, "1", 1, 1, 1),
            (1, None, 1, 1, 1),
            (1, 1, 1, 1, 1.5),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_verify_mode_deployment_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )

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
                    explain_merkle_verify_mode_deployment_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in ((True, 0, 0, 0, 0), (0, 0, 0, 0, True)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_verify_mode_deployment_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    explain_merkle_verify_mode_deployment_weighted(
                        bad_capacity, _GROUPS, _BUDGETS, (1, 1, 1, 1, 1)
                    )
        for bad_groups in ([(0, 1)], {(0, 1)}, "groups", None, 7, range(2)):
            with self.subTest(bad_groups=bad_groups):
                with self.assertRaises(TypeError):
                    explain_merkle_verify_mode_deployment_weighted(
                        16, bad_groups, _BUDGETS, (1, 1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            explain_merkle_verify_mode_deployment_weighted(
                16, (), _BUDGETS, (1, 1, 1, 1, 1)
            )
        for bad_budgets in ([None] * 6, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    explain_merkle_verify_mode_deployment_weighted(
                        16, _GROUPS, bad_budgets, (1, 1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            explain_merkle_verify_mode_deployment_weighted(
                16, _GROUPS, (None,) * 6, (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            explain_merkle_verify_mode_deployment_weighted(
                16, _GROUPS, (None,) * 5, (1, 1, 1, 1, 1)
            )
        for bad_member in (0, -1, True, 1.5, "100"):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    explain_merkle_verify_mode_deployment_weighted(
                        16,
                        _GROUPS,
                        (None, bad_member, None, None, None, None),
                        (1, 1, 1, 1, 1),
                    )

    def test_frontier_arguments_screened_before_weights(self):
        # the capacity/groups/budgets rules belong to the frontier and are
        # screened there before weights is inspected
        with self.assertRaises(ValueError):
            explain_merkle_verify_mode_deployment_weighted(
                0, (), (None,) * 6, (0, 0, 0, 0, 0)
            )
        with self.assertRaises(TypeError):
            explain_merkle_verify_mode_deployment_weighted(
                16, [(0, 1)], _BUDGETS, "not a tuple"
            )

    def test_all_four_parameters_are_required_without_defaults(self):
        sig = inspect.signature(
            explain_merkle_verify_mode_deployment_weighted
        )
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "groups", "budgets", "weights"],
        )
        for name in ("capacity", "groups", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_repeated_calls_are_deterministic(self):
        def exploding_token_bytes(size):
            raise AssertionError("pure parameter analysis must not draw randomness")

        import secrets
        from unittest import mock

        with mock.patch.object(secrets, "token_bytes", exploding_token_bytes):
            for weights in _WEIGHT_SETS:
                first = explain_merkle_verify_mode_deployment_weighted(
                    16, _GROUPS, _BUDGETS, weights
                )
                second = explain_merkle_verify_mode_deployment_weighted(
                    16, _GROUPS, _BUDGETS, weights
                )
                self.assertEqual(first, second)

    # --- regression tests pinning the refactored shared scoring semantics ---

    # The baseline frontier has six members with genuine trade-offs: w=4
    # plans are transport-heavy but verify-cheap, w=8 plans are the reverse.
    # Tails, per-dimension normalised costs, scores and the selected flag
    # are pinned exactly below, independently of the recommending entry
    # point.
    _TAIL_W4_MM = (34385, 16, 4, 4, ("multiproof", "multiproof"))
    _TAIL_W4_MB = (34385, 16, 4, 4, ("multiproof", "batch"))
    _TAIL_W4_BB = (34385, 16, 4, 4, ("batch", "batch"))
    _TAIL_W8_MM = (17489, 16, 8, 4, ("multiproof", "multiproof"))
    _TAIL_W8_MB = (17489, 16, 8, 4, ("multiproof", "batch"))
    _TAIL_W8_BB = (17489, 16, 8, 4, ("batch", "batch"))

    def test_breakdown_numbers_are_pinned_on_tradeoff_frontier(self):
        rows = explain_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, _BUDGETS, (1, 1, 1, 1, 1)
        )
        pinned = (
            (
                self._TAIL_W4_MM,
                (
                    Fraction(1056, 1129),
                    Fraction(704, 741),
                    Fraction(0, 1),
                    Fraction(1, 1),
                    Fraction(0, 1),
                ),
                Fraction(2413901, 4182945),
                False,
            ),
            (
                self._TAIL_W4_MB,
                (
                    Fraction(4335, 4516),
                    Fraction(1, 1),
                    Fraction(1, 15333),
                    Fraction(3, 8),
                    Fraction(0, 1),
                ),
                Fraction(323366669, 692438280),
                False,
            ),
            (
                self._TAIL_W4_BB,
                (
                    Fraction(1, 1),
                    Fraction(1, 1),
                    Fraction(1, 5111),
                    Fraction(0, 1),
                    Fraction(0, 1),
                ),
                Fraction(10223, 25555),
                True,
            ),
            (
                self._TAIL_W8_MM,
                (
                    Fraction(0, 1),
                    Fraction(0, 1),
                    Fraction(5110, 5111),
                    Fraction(1, 1),
                    Fraction(1, 1),
                ),
                Fraction(15332, 25555),
                False,
            ),
            (
                self._TAIL_W8_MB,
                (
                    Fraction(111, 4516),
                    Fraction(37, 741),
                    Fraction(15331, 15333),
                    Fraction(3, 8),
                    Fraction(1, 1),
                ),
                Fraction(1469906027, 3000565880),
                False,
            ),
            (
                self._TAIL_W8_BB,
                (
                    Fraction(73, 1129),
                    Fraction(37, 741),
                    Fraction(1, 1),
                    Fraction(0, 1),
                    Fraction(1, 1),
                ),
                Fraction(1769044, 4182945),
                False,
            ),
        )
        self.assertEqual(len(rows), len(pinned))
        for row, (expected_tail, expected_costs, expected_score, selected) in zip(
            rows, pinned
        ):
            with self.subTest(expected_tail=expected_tail):
                self.assertEqual(_tail(row.mode_cost), expected_tail)
                self.assertEqual(
                    (
                        row.transport_cost,
                        row.peak_cost,
                        row.hashes_cost,
                        row.nodes_cost,
                        row.steps_cost,
                    ),
                    expected_costs,
                )
                self.assertEqual(row.score, expected_score)
                self.assertIs(row.selected, selected)
        # the selected row equals the recommendation field for field
        selected_rows = [row for row in rows if row.selected]
        self.assertEqual(len(selected_rows), 1)
        self.assertEqual(
            selected_rows[0].mode_cost,
            recommend_merkle_verify_mode_deployment_weighted(
                16, _GROUPS, _BUDGETS, (1, 1, 1, 1, 1)
            ),
        )

    def test_single_positive_weight_rows_pinned(self):
        # hashes-only: exactly the minimum-hashes member must normalise to 0
        # and be selected; every other member must be strictly above it
        rows = explain_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, _BUDGETS, (0, 0, 1, 0, 0)
        )
        details = [
            (
                _tail(row.mode_cost),
                row.hashes_cost,
                row.score,
                row.selected,
            )
            for row in rows
        ]
        self.assertEqual(
            details,
            [
                (self._TAIL_W4_MM, Fraction(0, 1), Fraction(0, 1), True),
                (self._TAIL_W4_MB, Fraction(1, 15333), Fraction(1, 15333), False),
                (self._TAIL_W4_BB, Fraction(1, 5111), Fraction(1, 5111), False),
                (self._TAIL_W8_MM, Fraction(5110, 5111), Fraction(5110, 5111), False),
                (
                    self._TAIL_W8_MB,
                    Fraction(15331, 15333),
                    Fraction(15331, 15333),
                    False,
                ),
                (self._TAIL_W8_BB, Fraction(1, 1), Fraction(1, 1), False),
            ],
        )

    def test_tied_zero_scores_select_by_tail_and_keep_flag_unique(self):
        # nodes-only: both all-batch plans carry zero nodes and tie at score
        # 0; the checkpoint-bytes tail picks the w=8 plan
        rows = explain_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, _BUDGETS, (0, 0, 0, 1, 0)
        )
        zero_score_tails = {
            _tail(row.mode_cost) for row in rows if row.score == 0
        }
        self.assertEqual(zero_score_tails, {self._TAIL_W4_BB, self._TAIL_W8_BB})
        selected = [row for row in rows if row.selected]
        self.assertEqual(len(selected), 1)
        self.assertEqual(_tail(selected[0].mode_cost), self._TAIL_W8_BB)
        self.assertEqual(selected[0].nodes_cost, 0)

        # steps-only: three w=4 plans share the step minimum and tie; the
        # modes tuple lexicographic order picks ("batch", "batch")
        rows = explain_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, _BUDGETS, (0, 0, 0, 0, 1)
        )
        tied = [row for row in rows if row.score == 0]
        self.assertEqual(
            {_tail(row.mode_cost) for row in tied},
            {self._TAIL_W4_MM, self._TAIL_W4_MB, self._TAIL_W4_BB},
        )
        selected = [row for row in rows if row.selected][0]
        self.assertEqual(_tail(selected.mode_cost), self._TAIL_W4_BB)
        self.assertTrue(all(row.steps_cost == 0 for row in tied))

    def test_partial_zero_span_column_is_zero_on_every_row(self):
        # the hashes budget leaves three w=4 members; the steps column is
        # constant (1005), so steps_cost is 0 on every row even though the
        # frontier still trades the other four costs
        budgets = (None, 5000, 12000, None, 8, 5000)
        frontier = merkle_verify_mode_frontier(16, _GROUPS, budgets)
        self.assertEqual(len(frontier), 3)
        rows = explain_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, budgets, (1, 1, 1, 1, 1)
        )
        pinned = (
            (
                self._TAIL_W4_MM,
                (
                    Fraction(0, 1),
                    Fraction(0, 1),
                    Fraction(0, 1),
                    Fraction(1, 1),
                    Fraction(0, 1),
                ),
                Fraction(1, 5),
                True,
            ),
            (
                self._TAIL_W4_MB,
                (
                    Fraction(111, 292),
                    Fraction(1, 1),
                    Fraction(1, 3),
                    Fraction(3, 8),
                    Fraction(0, 1),
                ),
                Fraction(3659, 8760),
                False,
            ),
            (
                self._TAIL_W4_BB,
                (
                    Fraction(1, 1),
                    Fraction(1, 1),
                    Fraction(1, 1),
                    Fraction(0, 1),
                    Fraction(0, 1),
                ),
                Fraction(3, 5),
                False,
            ),
        )
        for row, (expected_tail, expected_costs, expected_score, selected) in zip(
            rows, pinned
        ):
            with self.subTest(expected_tail=expected_tail):
                self.assertEqual(_tail(row.mode_cost), expected_tail)
                self.assertEqual(
                    (
                        row.transport_cost,
                        row.peak_cost,
                        row.hashes_cost,
                        row.nodes_cost,
                        row.steps_cost,
                    ),
                    expected_costs,
                )
                self.assertEqual(row.score, expected_score)
                self.assertIs(row.selected, selected)
        # a steps-only score is 0 for all three, so the tail alone selects
        steps_rows = explain_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, budgets, (0, 0, 0, 0, 1)
        )
        self.assertTrue(all(row.score == 0 for row in steps_rows))
        self.assertEqual(
            _tail(next(row for row in steps_rows if row.selected).mode_cost),
            self._TAIL_W4_BB,
        )

    def test_budget_boundaries_pin_inclusive_single_row_breakdown(self):
        # total-transport boundary: 4768 admits exactly one member, so every
        # span is zero, every cost and the score are 0 and the lone row is
        # selected; 4767 rejects the whole request before any row is built
        rows = explain_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, (None, None, 4768, None, None, None), (3, 1, 4, 1, 5)
        )
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(_tail(row.mode_cost), self._TAIL_W8_MM)
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
        with self.assertRaises(ValueError):
            explain_merkle_verify_mode_deployment_weighted(
                16,
                _GROUPS,
                (None, None, 4767, None, None, None),
                (3, 1, 4, 1, 5),
            )
        # hashes boundary 4034 likewise admits one w=4 member
        rows = explain_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, (None, None, None, None, None, 4034), (1, 1, 1, 1, 1)
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(_tail(rows[0].mode_cost), self._TAIL_W4_MM)
        self.assertEqual(rows[0].score, 0)
        self.assertTrue(rows[0].selected)
        with self.assertRaises(ValueError):
            explain_merkle_verify_mode_deployment_weighted(
                16,
                _GROUPS,
                (None, None, None, None, None, 4033),
                (1, 1, 1, 1, 1),
            )


if __name__ == "__main__":
    unittest.main()

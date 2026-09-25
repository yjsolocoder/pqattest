import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleCardinalityScenarioScore,
    MerkleModeCost,
    MerkleSigner,
    explain_merkle_cardinality_weighted_scenarios,
    merkle_cardinality_frontier,
    profile,
    recommend_merkle_cardinality_weighted_scenarios,
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


def _expected_rows(capacity, group_sizes, budgets, scenarios):
    """Recompute the documented per-candidate breakdown independently."""
    frontier = merkle_cardinality_frontier(capacity, group_sizes, budgets)
    rows = [_metrics(mode_cost) for mode_cost in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(5)
    )
    totals = tuple(sum(weights) for weights in scenarios)

    entries = []
    for mode_cost, values in zip(frontier, rows):
        costs = tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(values, spans)
        )
        scores = tuple(
            sum(
                (weight * component for weight, component in zip(weights, costs)),
                Fraction(0),
            )
            / total
            for weights, total in zip(scenarios, totals)
        )
        entries.append((mode_cost, costs, scores))

    best = tuple(
        min(entry[2][scenario_index] for entry in entries)
        for scenario_index in range(len(scenarios))
    )
    entries = [
        (
            mode_cost,
            costs,
            scores,
            tuple(score - floor for score, floor in zip(scores, best)),
        )
        for mode_cost, costs, scores in entries
    ]

    def key(entry):
        mode_cost, _costs, scores, regrets = entry
        return (
            max(regrets),
            sum(regrets, Fraction(0)),
            scores,
            *_tail(mode_cost),
        )

    chosen = min(entries, key=key)[0]
    return tuple(
        MerkleCardinalityScenarioScore(
            mode_cost, *costs, scores, regrets, mode_cost == chosen
        )
        for mode_cost, costs, scores, regrets in entries
    )


_WORKLOADS = (
    (1, (1,), (None, None, None, None, None, 10**18)),
    (4, _SIZES, (None, None, None, 9000, None, None)),
    (16, (1, 2, 3, 4, 8), (None, None, None, None, None, 10**18)),
    (8, (1, 2, 4), (9000, None, None, None, None, None)),
    (4, (3,), (None, 4000, None, None, None, None)),
    (4, _SIZES, (9000, None, 7000, None, 4, None)),
    (2, (1, 2), (None, None, None, None, None, 6000)),
    (32, (1, 7, 16), (None, None, None, None, 50, None)),
)

_SCENARIO_SETS = (
    ((1, 1, 1, 1, 1),),
    ((10, 0, 0, 0, 0), (0, 0, 0, 0, 1)),
    (
        (1, 2, 3, 4, 5),
        (0, 1, 0, 1, 0),
        (10**9, 1, 1, 1, 1),
        (3, 0, 7, 0, 2),
    ),
    ((1, 0, 0, 0, 0), (0, 1, 0, 0, 0), (0, 0, 1, 0, 0), (0, 0, 0, 1, 0)),
    ((1, 1, 1, 1, 1), (1, 1, 1, 1, 1)),
)


class ExplainMerkleCardinalityWeightedScenariosTest(unittest.TestCase):
    def test_matches_brute_force_breakdown(self):
        for capacity, group_sizes, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    group_sizes=group_sizes,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    self.assertEqual(
                        explain_merkle_cardinality_weighted_scenarios(
                            capacity, group_sizes, budgets, scenarios
                        ),
                        _expected_rows(capacity, group_sizes, budgets, scenarios),
                    )

    def test_row_order_matches_frontier_member_order(self):
        frontier = merkle_cardinality_frontier(4, _SIZES, _BUDGETS)
        self.assertGreater(len(frontier), 1)
        for scenarios in _SCENARIO_SETS:
            with self.subTest(scenarios=scenarios):
                rows = explain_merkle_cardinality_weighted_scenarios(
                    4, _SIZES, _BUDGETS, scenarios
                )
                self.assertIsInstance(rows, tuple)
                self.assertEqual(len(rows), len(frontier))
                self.assertEqual(
                    tuple(row.mode_cost for row in rows),
                    frontier,
                )

    def test_row_fields_and_types(self):
        scenarios = ((1, 2, 3, 4, 5), (5, 4, 3, 2, 1), (0, 0, 1, 0, 0))
        rows = explain_merkle_cardinality_weighted_scenarios(
            4, _SIZES, _BUDGETS, scenarios
        )
        for row in rows:
            self.assertIsInstance(row, MerkleCardinalityScenarioScore)
            self.assertIsInstance(row.mode_cost, MerkleModeCost)
            for cost in (
                row.transport_cost,
                row.peak_cost,
                row.hashes_cost,
                row.nodes_cost,
                row.steps_cost,
            ):
                self.assertIsInstance(cost, Fraction)
                self.assertGreaterEqual(cost, 0)
                self.assertLessEqual(cost, 1)
            self.assertIsInstance(row.scores, tuple)
            self.assertIsInstance(row.regrets, tuple)
            self.assertEqual(len(row.scores), len(scenarios))
            self.assertEqual(len(row.regrets), len(scenarios))
            for score in row.scores:
                self.assertIsInstance(score, Fraction)
                self.assertGreaterEqual(score, 0)
            for regret in row.regrets:
                self.assertIsInstance(regret, Fraction)
                self.assertGreaterEqual(regret, 0)
            self.assertIsInstance(row.selected, bool)

    def test_regret_is_score_minus_scenario_best(self):
        scenarios = ((1, 0, 0, 0, 0), (0, 0, 1, 1, 1), (2, 2, 2, 2, 2))
        rows = explain_merkle_cardinality_weighted_scenarios(
            4, _SIZES, _BUDGETS, scenarios
        )
        best = tuple(
            min(row.scores[scenario_index] for row in rows)
            for scenario_index in range(len(scenarios))
        )
        for row in rows:
            self.assertEqual(
                row.regrets,
                tuple(
                    score - floor for score, floor in zip(row.scores, best)
                ),
            )
        # every scenario's best-scoring row has zero regret for it
        for scenario_index in range(len(scenarios)):
            self.assertIn(
                Fraction(0),
                tuple(row.regrets[scenario_index] for row in rows),
            )

    def test_exactly_one_row_selected_and_matches_recommendation(self):
        for capacity, group_sizes, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    group_sizes=group_sizes,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    rows = explain_merkle_cardinality_weighted_scenarios(
                        capacity, group_sizes, budgets, scenarios
                    )
                    selected = [row for row in rows if row.selected]
                    self.assertEqual(len(selected), 1)
                    self.assertEqual(
                        selected[0].mode_cost,
                        recommend_merkle_cardinality_weighted_scenarios(
                            capacity, group_sizes, budgets, scenarios
                        ),
                    )

    def test_selected_row_has_the_smallest_worst_regret_with_documented_tail(self):
        for capacity, group_sizes, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    group_sizes=group_sizes,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    rows = explain_merkle_cardinality_weighted_scenarios(
                        capacity, group_sizes, budgets, scenarios
                    )

                    def key(row):
                        return (
                            max(row.regrets),
                            sum(row.regrets, Fraction(0)),
                            row.scores,
                        )

                    best = min(key(row) for row in rows)
                    tied = [row for row in rows if key(row) == best]
                    chosen = [row for row in rows if row.selected][0]
                    self.assertIn(chosen, tied)
                    self.assertEqual(
                        chosen.mode_cost,
                        min((row.mode_cost for row in tied), key=_tail),
                    )

    def test_rows_are_frozen_positional_value_objects(self):
        rows = explain_merkle_cardinality_weighted_scenarios(
            4,
            _SIZES,
            _BUDGETS,
            ((1, 2, 3, 4, 5), (3, 0, 7, 0, 2)),
        )
        row = rows[0]
        clone = MerkleCardinalityScenarioScore(
            row.mode_cost,
            row.transport_cost,
            row.peak_cost,
            row.hashes_cost,
            row.nodes_cost,
            row.steps_cost,
            row.scores,
            row.regrets,
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
                clone.scores,
                clone.regrets,
                clone.selected,
            ),
            (
                row.mode_cost,
                row.transport_cost,
                row.peak_cost,
                row.hashes_cost,
                row.nodes_cost,
                row.steps_cost,
                row.scores,
                row.regrets,
                row.selected,
            ),
        )
        with self.assertRaises(Exception):
            row.selected = False

    def test_zero_span_frontier_scores_zero_and_tail_selects(self):
        # a single-member frontier makes every span zero: the unique row
        # scores zero in every scenario and is selected, without dividing
        # by zero
        budgets = (None, None, 2243, None, None, 2000)
        frontier = merkle_cardinality_frontier(1, (1,), budgets)
        self.assertEqual(len(frontier), 1)
        for scenarios in (
            ((1, 1, 1, 1, 1),),
            ((0, 0, 0, 0, 1),),
            ((9, 8, 7, 6, 5), (1, 0, 0, 0, 0)),
        ):
            with self.subTest(scenarios=scenarios):
                rows = explain_merkle_cardinality_weighted_scenarios(
                    1, (1,), budgets, scenarios
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
                    ),
                    (Fraction(0),) * 5,
                )
                self.assertEqual(
                    row.scores, (Fraction(0),) * len(scenarios)
                )
                self.assertEqual(
                    row.regrets, (Fraction(0),) * len(scenarios)
                )
                self.assertTrue(row.selected)

    def test_repeated_scenarios_counted_separately(self):
        # repeated scenarios must be kept as separate tuple positions: the
        # breakdown's regrets zip scenarios position for position, and the
        # selected row follows the swing of the recommendation
        first = (0, 0, 0, 2, 1)
        second = (0, 2, 0, 0, 1)
        one_each = explain_merkle_cardinality_weighted_scenarios(
            4, _SIZES, _BUDGETS, (first, second)
        )
        second_doubled = explain_merkle_cardinality_weighted_scenarios(
            4, _SIZES, _BUDGETS, (first, second, second)
        )
        self.assertEqual(
            [row for row in one_each if row.selected][0].mode_cost.plan.config.w,
            4,
        )
        self.assertEqual(
            [row for row in second_doubled if row.selected][0]
            .mode_cost.plan.config.w,
            8,
        )

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
            for scenarios in _SCENARIO_SETS:
                calls = 0
                explain_merkle_cardinality_weighted_scenarios(
                    4, _SIZES, _BUDGETS, scenarios
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_cardinality_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            explain_merkle_cardinality_weighted_scenarios(
                1,
                (1,),
                (100, None, None, None, None, None),
                ((1, 1, 1, 1, 1),),
            )
        with self.assertRaises(ValueError):
            explain_merkle_cardinality_weighted_scenarios(
                1,
                (257,),
                (None, None, None, None, None, 1),
                ((1, 1, 1, 1, 1),),
            )
        with self.assertRaises(ValueError):
            explain_merkle_cardinality_weighted_scenarios(
                4,
                (1,),
                (None, None, None, None, None, 10),
                ((1, 1, 1, 1, 1),),
            )

    def test_invalid_scenarios_container_raises_type_error(self):
        for bad in (
            [(1, 1, 1, 1, 1)],
            {(1, 1, 1, 1, 1)},
            "scenarios",
            None,
            7,
            range(5),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_cardinality_weighted_scenarios(
                        4, _SIZES, _BUDGETS, bad
                    )

    def test_invalid_scenario_member_raises_type_error(self):
        for bad in (
            ([1, 1, 1, 1, 1],),
            ("scenario",),
            (None,),
            (7,),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_cardinality_weighted_scenarios(
                        4, _SIZES, _BUDGETS, bad
                    )
        good = (1, 1, 1, 1, 1)
        for bad_member in ([1, 1, 1, 1, 1], "scenario", None, 7):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(TypeError):
                    explain_merkle_cardinality_weighted_scenarios(
                        4, _SIZES, _BUDGETS, (good, bad_member)
                    )

    def test_non_integer_weight_raises_type_error(self):
        for bad in (
            ((1.0, 1, 1, 1, 1),),
            ((1, "1", 1, 1, 1),),
            ((1, None, 1, 1, 1),),
            ((1, 1, 1, 1, 1.5),),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_cardinality_weighted_scenarios(
                        4, _SIZES, _BUDGETS, bad
                    )

    def test_invalid_weights_members_raise_value_error(self):
        for bad in (
            (),
            ((1, 1, 1, 1),),
            ((1, 1, 1, 1, 1, 1),),
            ((0, 0, 0, 0, 0),),
            ((1, -1, 1, 1, 1),),
            ((-1, 1, 1, 1, 1),),
            ((True, 1, 1, 1, 1),),
            ((1, 1, 1, 1, False),),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_cardinality_weighted_scenarios(
                        4, _SIZES, _BUDGETS, bad
                    )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in (((True, 0, 0, 0, 0),), ((0, 0, 0, 0, True),)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_cardinality_weighted_scenarios(
                        4, _SIZES, _BUDGETS, bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    explain_merkle_cardinality_weighted_scenarios(
                        bad_capacity,
                        _SIZES,
                        _BUDGETS,
                        ((1, 1, 1, 1, 1),),
                    )
        for bad_sizes in ([1], {1}, "sizes", None, 7, range(2)):
            with self.subTest(bad_sizes=bad_sizes):
                with self.assertRaises(TypeError):
                    explain_merkle_cardinality_weighted_scenarios(
                        4,
                        bad_sizes,
                        _BUDGETS,
                        ((1, 1, 1, 1, 1),),
                    )
        with self.assertRaises(ValueError):
            explain_merkle_cardinality_weighted_scenarios(
                4, (), _BUDGETS, ((1, 1, 1, 1, 1),)
            )
        for bad_budgets in ([None] * 6, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    explain_merkle_cardinality_weighted_scenarios(
                        4,
                        _SIZES,
                        bad_budgets,
                        ((1, 1, 1, 1, 1),),
                    )
        with self.assertRaises(ValueError):
            explain_merkle_cardinality_weighted_scenarios(
                4, _SIZES, (None,) * 6, ((1, 1, 1, 1, 1),)
            )

    def test_frontier_arguments_screened_before_scenarios(self):
        # the capacity/groups/budgets rules belong to the frontier and are
        # screened there before scenarios is inspected
        with self.assertRaises(ValueError):
            explain_merkle_cardinality_weighted_scenarios(
                0, (), (None,) * 6, ()
            )
        with self.assertRaises(TypeError):
            explain_merkle_cardinality_weighted_scenarios(
                4, [1], _BUDGETS, "not a tuple"
            )

    def test_all_four_parameters_are_required_without_defaults(self):
        sig = inspect.signature(
            explain_merkle_cardinality_weighted_scenarios
        )
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "group_sizes", "budgets", "scenarios"],
        )
        for name in ("capacity", "group_sizes", "budgets", "scenarios"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_repeated_calls_are_deterministic(self):
        signer = MerkleSigner(w=4, height=2)
        for scenarios in _SCENARIO_SETS:
            first = explain_merkle_cardinality_weighted_scenarios(
                4, (1, 2), (None, None, None, 9000, None, None), scenarios
            )
            second = explain_merkle_cardinality_weighted_scenarios(
                4, (1, 2), (None, None, None, 9000, None, None), scenarios
            )
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

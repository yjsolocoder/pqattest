import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleSigner,
    MerkleTransportWorkloadProfile,
    MerkleTransportWorkloadScenarioScore,
    explain_merkle_transport_workload_weighted_scenarios,
    merkle_transport_workload_frontier,
    profile,
    recommend_merkle_transport_workload_weighted_scenarios,
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


def _expected_rows(capacity, groups, budgets, scenarios):
    """Recompute the documented per-candidate breakdown independently."""
    frontier = merkle_transport_workload_frontier(capacity, groups, budgets)
    rows = [_metrics(workload) for workload in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(4)
    )
    totals = tuple(sum(weights) for weights in scenarios)

    entries = []
    for workload, values in zip(frontier, rows):
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
        entries.append((workload, costs, scores))

    best = tuple(
        min(entry[2][scenario_index] for entry in entries)
        for scenario_index in range(len(scenarios))
    )
    entries = [
        (
            workload,
            costs,
            scores,
            tuple(score - floor for score, floor in zip(scores, best)),
        )
        for workload, costs, scores in entries
    ]

    def key(entry):
        workload, _costs, scores, regrets = entry
        return (
            max(regrets),
            sum(regrets, Fraction(0)),
            scores,
            *_tail(workload),
        )

    chosen = min(entries, key=key)[0]
    return tuple(
        MerkleTransportWorkloadScenarioScore(
            workload, *costs, scores, regrets, workload == chosen
        )
        for workload, costs, scores, regrets in entries
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

_SCENARIO_SETS = (
    ((1, 1, 1, 1),),
    ((10, 0, 0, 0), (0, 0, 0, 1)),
    (
        (1, 2, 3, 4),
        (0, 1, 0, 1),
        (10**9, 1, 1, 1),
        (3, 0, 7, 2),
    ),
    ((1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0)),
    ((1, 1, 1, 1), (1, 1, 1, 1)),
)


class ExplainMerkleTransportWorkloadWeightedScenariosTest(unittest.TestCase):
    def test_matches_brute_force_breakdown(self):
        for capacity, groups, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    self.assertEqual(
                        explain_merkle_transport_workload_weighted_scenarios(
                            capacity, groups, budgets, scenarios
                        ),
                        _expected_rows(capacity, groups, budgets, scenarios),
                    )

    def test_row_order_matches_frontier_member_order(self):
        frontier = merkle_transport_workload_frontier(16, _GROUPS, _BUDGETS)
        self.assertGreater(len(frontier), 1)
        for scenarios in _SCENARIO_SETS:
            with self.subTest(scenarios=scenarios):
                rows = explain_merkle_transport_workload_weighted_scenarios(
                    16, _GROUPS, _BUDGETS, scenarios
                )
                self.assertIsInstance(rows, tuple)
                self.assertEqual(len(rows), len(frontier))
                self.assertEqual(
                    tuple(row.workload for row in rows),
                    frontier,
                )

    def test_row_fields_and_types(self):
        scenarios = ((1, 2, 3, 4), (4, 3, 2, 1), (0, 0, 1, 0))
        rows = explain_merkle_transport_workload_weighted_scenarios(
            16, _GROUPS, _BUDGETS, scenarios
        )
        for row in rows:
            self.assertIsInstance(row, MerkleTransportWorkloadScenarioScore)
            self.assertIsInstance(row.workload, MerkleTransportWorkloadProfile)
            for cost in (
                row.checkpoint_cost,
                row.peak_cost,
                row.transport_cost,
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
        scenarios = ((1, 0, 0, 0), (0, 1, 1, 1), (2, 2, 2, 2))
        rows = explain_merkle_transport_workload_weighted_scenarios(
            16, _GROUPS, _BUDGETS, scenarios
        )
        best = tuple(
            min(row.scores[scenario_index] for row in rows)
            for scenario_index in range(len(scenarios))
        )
        for row in rows:
            self.assertEqual(
                row.regrets,
                tuple(score - floor for score, floor in zip(row.scores, best)),
            )
        # every scenario's best-scoring row has zero regret for it
        for scenario_index in range(len(scenarios)):
            self.assertIn(
                Fraction(0),
                tuple(row.regrets[scenario_index] for row in rows),
            )

    def test_repeated_scenarios_counted_separately(self):
        # the rows' score and regret tuples keep every scenario position,
        # duplicates included, rather than collapsing equal scenarios
        first = (0, 0, 0, 1)
        second = (0, 0, 1, 0)
        rows = explain_merkle_transport_workload_weighted_scenarios(
            16, _GROUPS, _BUDGETS, (first, second, second)
        )
        for row in rows:
            self.assertEqual(len(row.scores), 3)
            self.assertEqual(len(row.regrets), 3)
            self.assertEqual(row.scores[1], row.scores[2])
            self.assertEqual(row.regrets[1], row.regrets[2])
        self.assertEqual(
            [row for row in rows if row.selected][0].workload,
            recommend_merkle_transport_workload_weighted_scenarios(
                16, _GROUPS, _BUDGETS, (first, second, second)
            ),
        )

    def test_exactly_one_row_selected_and_matches_recommendation(self):
        for capacity, groups, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    rows = explain_merkle_transport_workload_weighted_scenarios(
                        capacity, groups, budgets, scenarios
                    )
                    selected = [row for row in rows if row.selected]
                    self.assertEqual(len(selected), 1)
                    self.assertEqual(
                        selected[0].workload,
                        recommend_merkle_transport_workload_weighted_scenarios(
                            capacity, groups, budgets, scenarios
                        ),
                    )

    def test_selected_row_has_the_smallest_worst_regret_with_documented_tail(self):
        for capacity, groups, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    rows = explain_merkle_transport_workload_weighted_scenarios(
                        capacity, groups, budgets, scenarios
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
                        chosen.workload,
                        min((row.workload for row in tied), key=_tail),
                    )

    def test_rows_are_frozen_positional_value_objects(self):
        rows = explain_merkle_transport_workload_weighted_scenarios(
            16, _GROUPS, _BUDGETS, ((1, 1, 1, 1), (1, 0, 0, 1))
        )
        row = rows[0]
        clone = MerkleTransportWorkloadScenarioScore(
            row.workload,
            row.checkpoint_cost,
            row.peak_cost,
            row.transport_cost,
            row.steps_cost,
            row.scores,
            row.regrets,
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
                clone.scores,
                clone.regrets,
                clone.selected,
            ),
            (
                row.workload,
                row.checkpoint_cost,
                row.peak_cost,
                row.transport_cost,
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
        budgets = (None, 1190, None, None)
        frontier = merkle_transport_workload_frontier(1, ((0,),), budgets)
        self.assertEqual(len(frontier), 1)
        for scenarios in (
            ((1, 1, 1, 1),),
            ((0, 0, 0, 1),),
            ((9, 8, 7, 6), (1, 0, 0, 0)),
        ):
            with self.subTest(scenarios=scenarios):
                rows = explain_merkle_transport_workload_weighted_scenarios(
                    1, ((0,),), budgets, scenarios
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
                    ),
                    (Fraction(0),) * 4,
                )
                self.assertEqual(
                    row.scores, (Fraction(0),) * len(scenarios)
                )
                self.assertEqual(
                    row.regrets, (Fraction(0),) * len(scenarios)
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
            for scenarios in _SCENARIO_SETS:
                calls = 0
                explain_merkle_transport_workload_weighted_scenarios(
                    16, _GROUPS, _BUDGETS, scenarios
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_transport_workload_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted_scenarios(
                1,
                ((0,),),
                (100, None, None, None),
                ((1, 1, 1, 1),),
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted_scenarios(
                4,
                ((0,),),
                (None, None, 10, None),
                ((1, 1, 1, 1),),
            )

    def test_invalid_scenarios_container_raises_type_error(self):
        for bad in (
            [(1, 1, 1, 1)],
            {(1, 1, 1, 1)},
            "scenarios",
            None,
            7,
            range(4),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_workload_weighted_scenarios(
                        16, _GROUPS, _BUDGETS, bad
                    )

    def test_invalid_scenario_member_raises_type_error(self):
        for bad in (
            ([1, 1, 1, 1],),
            ("scenario",),
            (None,),
            (7,),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_workload_weighted_scenarios(
                        16, _GROUPS, _BUDGETS, bad
                    )
        # the bad scenario member is also rejected when it follows a valid
        # one, not only when it is the sole member of the tuple
        good = (1, 1, 1, 1)
        for bad_member in ([1, 1, 1, 1], "scenario", None, 7):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_workload_weighted_scenarios(
                        16, _GROUPS, _BUDGETS, (good, bad_member)
                    )

    def test_non_integer_weight_raises_type_error(self):
        for bad in (
            ((1.0, 1, 1, 1),),
            ((1, "1", 1, 1),),
            ((1, None, 1, 1),),
            ((1, 1, 1, 1.5),),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_workload_weighted_scenarios(
                        16, _GROUPS, _BUDGETS, bad
                    )
        # a non-integer weight is rejected at every weight position and in
        # every scenario of the tuple, not just the first one inspected
        good = (1, 1, 1, 1)
        for scenario_position in range(2):
            for weight_position in range(4):
                for replacement in (1.0, "1", None, 1.5):
                    scenarios = [good, good]
                    scenarios[scenario_position] = tuple(
                        replacement if index == weight_position else good[index]
                        for index in range(4)
                    )
                    with self.subTest(
                        scenario_position=scenario_position,
                        weight_position=weight_position,
                        replacement=replacement,
                    ):
                        with self.assertRaises(TypeError):
                            explain_merkle_transport_workload_weighted_scenarios(
                                16, _GROUPS, _BUDGETS, tuple(scenarios)
                            )

    def test_invalid_weights_members_raise_value_error(self):
        for bad in (
            (),
            ((1, 1, 1),),
            ((1, 1, 1, 1, 1),),
            ((0, 0, 0, 0),),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_transport_workload_weighted_scenarios(
                        16, _GROUPS, _BUDGETS, bad
                    )
        # a boolean or negative weight is rejected at every weight position
        # and in every scenario of the tuple, and an all-zero scenario is
        # rejected at every outer position, not just the first inspected
        good = (1, 1, 1, 1)
        for scenario_position in range(2):
            for weight_position in range(4):
                for replacement in (-1, True, False):
                    scenarios = [good, good]
                    scenarios[scenario_position] = tuple(
                        replacement if index == weight_position else good[index]
                        for index in range(4)
                    )
                    with self.subTest(
                        scenario_position=scenario_position,
                        weight_position=weight_position,
                        replacement=replacement,
                    ):
                        with self.assertRaises(ValueError):
                            explain_merkle_transport_workload_weighted_scenarios(
                                16, _GROUPS, _BUDGETS, tuple(scenarios)
                            )
        for scenario_position in range(2):
            scenarios = [good, good]
            scenarios[scenario_position] = (0, 0, 0, 0)
            with self.subTest(scenario_position=scenario_position):
                with self.assertRaises(ValueError):
                    explain_merkle_transport_workload_weighted_scenarios(
                        16, _GROUPS, _BUDGETS, tuple(scenarios)
                    )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in (((True, 0, 0, 0),), ((0, 0, 0, True),)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_transport_workload_weighted_scenarios(
                        16, _GROUPS, _BUDGETS, bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    explain_merkle_transport_workload_weighted_scenarios(
                        bad_capacity,
                        _GROUPS,
                        _BUDGETS,
                        ((1, 1, 1, 1),),
                    )
        for bad_groups in ([(0, 1)], {(0, 1)}, "groups", None, 7, range(2)):
            with self.subTest(bad_groups=bad_groups):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_workload_weighted_scenarios(
                        16,
                        bad_groups,
                        _BUDGETS,
                        ((1, 1, 1, 1),),
                    )
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted_scenarios(
                16, (), _BUDGETS, ((1, 1, 1, 1),)
            )
        for bad_budgets in ([None] * 4, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_workload_weighted_scenarios(
                        16,
                        _GROUPS,
                        bad_budgets,
                        ((1, 1, 1, 1),),
                    )
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted_scenarios(
                16, _GROUPS, (None,) * 4, ((1, 1, 1, 1),)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted_scenarios(
                16, _GROUPS, (None,) * 3, ((1, 1, 1, 1),)
            )

    def test_frontier_arguments_screened_before_scenarios(self):
        # the capacity/groups/budgets rules belong to the frontier and are
        # screened there before scenarios is inspected
        with self.assertRaises(ValueError):
            explain_merkle_transport_workload_weighted_scenarios(
                0, (), (None,) * 4, ()
            )
        with self.assertRaises(TypeError):
            explain_merkle_transport_workload_weighted_scenarios(
                16, [(0, 1)], _BUDGETS, "not a tuple"
            )

    def test_all_four_parameters_are_required_without_defaults(self):
        sig = inspect.signature(
            explain_merkle_transport_workload_weighted_scenarios
        )
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "groups", "budgets", "scenarios"],
        )
        for name in ("capacity", "groups", "budgets", "scenarios"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_repeated_calls_are_deterministic(self):
        signer = MerkleSigner(w=4, height=2)
        for scenarios in _SCENARIO_SETS:
            first = explain_merkle_transport_workload_weighted_scenarios(
                16,
                _GROUPS,
                (None, None, None, 9000),
                scenarios,
            )
            second = explain_merkle_transport_workload_weighted_scenarios(
                16,
                _GROUPS,
                (None, None, None, 9000),
                scenarios,
            )
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

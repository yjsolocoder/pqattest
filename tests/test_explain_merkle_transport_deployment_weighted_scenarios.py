import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleTransportDeploymentProfile,
    MerkleTransportDeploymentScenarioScore,
    explain_merkle_transport_deployment_weighted_scenarios,
    merkle_transport_deployment_frontier,
    profile,
    recommend_merkle_transport_deployment_weighted_scenarios,
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


def _expected_rows(capacity, indices, budgets, scenarios):
    """Recompute the documented per-candidate breakdown independently."""
    frontier = merkle_transport_deployment_frontier(capacity, indices, budgets)
    rows = [_metrics(deployment) for deployment in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(5)
    )
    totals = tuple(sum(weights) for weights in scenarios)

    entries = []
    for deployment, values in zip(frontier, rows):
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
        entries.append((deployment, costs, scores))

    best = tuple(
        min(entry[2][scenario_index] for entry in entries)
        for scenario_index in range(len(scenarios))
    )
    entries = [
        (
            deployment,
            costs,
            scores,
            tuple(score - floor for score, floor in zip(scores, best)),
        )
        for deployment, costs, scores in entries
    ]

    def key(entry):
        deployment, _costs, scores, regrets = entry
        return (
            max(regrets),
            sum(regrets, Fraction(0)),
            scores,
            *_tail(deployment),
        )

    chosen = min(entries, key=key)[0]
    return tuple(
        MerkleTransportDeploymentScenarioScore(
            deployment, *costs, scores, regrets, deployment == chosen
        )
        for deployment, costs, scores, regrets in entries
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

_SCENARIO_SETS = (
    ((1, 1, 1, 1, 1),),
    ((10, 0, 0, 0, 0), (0, 0, 0, 0, 1)),
    (
        (1, 2, 3, 4, 5),
        (0, 1, 0, 1, 0),
        (10**9, 1, 1, 1, 1),
        (3, 0, 7, 0, 2),
    ),
    ((1, 0, 0, 0, 0), (0, 1, 0, 0, 0), (0, 0, 1, 0, 0), (0, 0, 0, 1, 0), (0, 0, 0, 0, 1)),
    ((1, 1, 1, 1, 1), (1, 1, 1, 1, 1)),
)


class ExplainMerkleTransportDeploymentWeightedScenariosTest(unittest.TestCase):
    def test_matches_brute_force_breakdown(self):
        for capacity, indices, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    indices=indices,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    self.assertEqual(
                        explain_merkle_transport_deployment_weighted_scenarios(
                            capacity, indices, budgets, scenarios
                        ),
                        _expected_rows(capacity, indices, budgets, scenarios),
                    )

    def test_row_order_matches_frontier_member_order(self):
        frontier = merkle_transport_deployment_frontier(4, _INDICES, _BUDGETS)
        self.assertGreater(len(frontier), 1)
        for scenarios in _SCENARIO_SETS:
            with self.subTest(scenarios=scenarios):
                rows = explain_merkle_transport_deployment_weighted_scenarios(
                    4, _INDICES, _BUDGETS, scenarios
                )
                self.assertIsInstance(rows, tuple)
                self.assertEqual(len(rows), len(frontier))
                self.assertEqual(
                    tuple(row.deployment for row in rows),
                    frontier,
                )

    def test_row_fields_and_types(self):
        scenarios = ((1, 2, 3, 4, 5), (5, 4, 3, 2, 1), (0, 0, 1, 0, 0))
        rows = explain_merkle_transport_deployment_weighted_scenarios(
            4, _INDICES, _BUDGETS, scenarios
        )
        for row in rows:
            self.assertIsInstance(row, MerkleTransportDeploymentScenarioScore)
            self.assertIsInstance(
                row.deployment, MerkleTransportDeploymentProfile
            )
            for cost in (
                row.batch_cost,
                row.multi_cost,
                row.nodes_cost,
                row.checkpoint_cost,
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
        scenarios = ((1, 0, 0, 0, 0), (0, 1, 1, 1, 1), (2, 2, 2, 2, 2))
        rows = explain_merkle_transport_deployment_weighted_scenarios(
            4, _INDICES, _BUDGETS, scenarios
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
        for capacity, indices, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    indices=indices,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    rows = explain_merkle_transport_deployment_weighted_scenarios(
                        capacity, indices, budgets, scenarios
                    )
                    selected = [row for row in rows if row.selected]
                    self.assertEqual(len(selected), 1)
                    self.assertEqual(
                        selected[0].deployment,
                        recommend_merkle_transport_deployment_weighted_scenarios(
                            capacity, indices, budgets, scenarios
                        ),
                    )

    def test_selected_row_has_the_smallest_worst_regret_with_documented_tail(self):
        for capacity, indices, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    indices=indices,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    rows = explain_merkle_transport_deployment_weighted_scenarios(
                        capacity, indices, budgets, scenarios
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
                        chosen.deployment,
                        min((row.deployment for row in tied), key=_tail),
                    )

    def test_rows_are_frozen_positional_value_objects(self):
        rows = explain_merkle_transport_deployment_weighted_scenarios(
            4, _INDICES, _BUDGETS, ((1, 1, 1, 1, 1),)
        )
        row = rows[0]
        clone = MerkleTransportDeploymentScenarioScore(
            row.deployment,
            row.batch_cost,
            row.multi_cost,
            row.nodes_cost,
            row.checkpoint_cost,
            row.steps_cost,
            row.scores,
            row.regrets,
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
                clone.scores,
                clone.regrets,
                clone.selected,
            ),
            (
                row.deployment,
                row.batch_cost,
                row.multi_cost,
                row.nodes_cost,
                row.checkpoint_cost,
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
        budgets = (None, None, None, 1005)
        frontier = merkle_transport_deployment_frontier(1, (0,), budgets)
        self.assertEqual(len(frontier), 1)
        for scenarios in (
            ((1, 1, 1, 1, 1),),
            ((0, 0, 0, 0, 1),),
            ((9, 8, 7, 6, 5), (1, 0, 0, 0, 0)),
        ):
            with self.subTest(scenarios=scenarios):
                rows = explain_merkle_transport_deployment_weighted_scenarios(
                    1, (0,), budgets, scenarios
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
            for scenarios in _SCENARIO_SETS:
                calls = 0
                explain_merkle_transport_deployment_weighted_scenarios(
                    4, _INDICES, _BUDGETS, scenarios
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_transport_deployment_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted_scenarios(
                1, (0,), (100, None, None, None), ((1, 1, 1, 1, 1),)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted_scenarios(
                1, (255,), (None, None, None, 1), ((1, 1, 1, 1, 1),)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted_scenarios(
                4, (1,), (None, None, None, 10), ((1, 1, 1, 1, 1),)
            )

    def test_invalid_scenarios_container_raises_type_error(self):
        for bad in (
            [(1, 1, 1, 1, 1)],
            {(1, 1, 1, 1, 1)},
            "scenarios",
            None,
            7,
            range(4),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_deployment_weighted_scenarios(
                        4, _INDICES, _BUDGETS, bad
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
                    explain_merkle_transport_deployment_weighted_scenarios(
                        4, _INDICES, _BUDGETS, bad
                    )
        good = (1, 1, 1, 1, 1)
        for bad_member in ([1, 1, 1, 1, 1], "scenario", None, 7):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_deployment_weighted_scenarios(
                        4, _INDICES, _BUDGETS, (good, bad_member)
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
                    explain_merkle_transport_deployment_weighted_scenarios(
                        4, _INDICES, _BUDGETS, bad
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
                    explain_merkle_transport_deployment_weighted_scenarios(
                        4, _INDICES, _BUDGETS, bad
                    )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in (((True, 0, 0, 0, 0),), ((0, 0, 0, 0, True),)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    explain_merkle_transport_deployment_weighted_scenarios(
                        4, _INDICES, _BUDGETS, bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    explain_merkle_transport_deployment_weighted_scenarios(
                        bad_capacity, _INDICES, _BUDGETS, ((1, 1, 1, 1, 1),)
                    )
        for bad_indices in ([1, 2], {1, 2}, "indices", None, 7, range(2)):
            with self.subTest(bad_indices=bad_indices):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_deployment_weighted_scenarios(
                        4, bad_indices, _BUDGETS, ((1, 1, 1, 1, 1),)
                    )
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted_scenarios(
                4, (), _BUDGETS, ((1, 1, 1, 1, 1),)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted_scenarios(
                4, (2, 1), _BUDGETS, ((1, 1, 1, 1, 1),)
            )
        for bad_budgets in ([None] * 4, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    explain_merkle_transport_deployment_weighted_scenarios(
                        4, _INDICES, bad_budgets, ((1, 1, 1, 1, 1),)
                    )
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted_scenarios(
                4, _INDICES, (None,) * 4, ((1, 1, 1, 1, 1),)
            )
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted_scenarios(
                4, _INDICES, (None,) * 3, ((1, 1, 1, 1, 1),)
            )

    def test_frontier_arguments_screened_before_scenarios(self):
        # the capacity/indices/budgets rules belong to the frontier and are
        # screened there, before the scenarios are looked at
        with self.assertRaises(ValueError):
            explain_merkle_transport_deployment_weighted_scenarios(
                0, (), (None,) * 4, ()
            )
        with self.assertRaises(TypeError):
            explain_merkle_transport_deployment_weighted_scenarios(
                4, [1, 2], _BUDGETS, "not a tuple"
            )

    def test_all_four_parameters_are_required_without_defaults(self):
        sig = inspect.signature(
            explain_merkle_transport_deployment_weighted_scenarios
        )
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "indices", "budgets", "scenarios"],
        )
        for name in ("capacity", "indices", "budgets", "scenarios"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_repeated_calls_are_deterministic(self):
        def exploding_token_bytes(size):
            raise AssertionError("pure parameter analysis must not draw randomness")

        import secrets
        from unittest import mock

        with mock.patch.object(secrets, "token_bytes", exploding_token_bytes):
            for scenarios in _SCENARIO_SETS:
                first = explain_merkle_transport_deployment_weighted_scenarios(
                    4, _INDICES, _BUDGETS, scenarios
                )
                second = explain_merkle_transport_deployment_weighted_scenarios(
                    4, _INDICES, _BUDGETS, scenarios
                )
                self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

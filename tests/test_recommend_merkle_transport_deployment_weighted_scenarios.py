import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleSigner,
    MerkleTransportDeploymentProfile,
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
            "merkle",
            w=deployment.config.w,
            height=deployment.config.height,
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


def _normalised_rows(frontier):
    rows = [_metrics(deployment) for deployment in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(5)
    )
    return tuple(
        tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(row, spans)
        )
        for row in rows
    )


def _expected(capacity, indices, budgets, scenarios):
    """Rank the frontier by the documented minimax-regret score."""
    frontier = merkle_transport_deployment_frontier(capacity, indices, budgets)
    normalised = _normalised_rows(frontier)
    totals = tuple(sum(weights) for weights in scenarios)

    def scenario_scores(row):
        return tuple(
            sum(
                (weight * component for weight, component in zip(weights, row)),
                Fraction(0),
            )
            / total
            for weights, total in zip(scenarios, totals)
        )

    score_rows = tuple(scenario_scores(row) for row in normalised)
    best = tuple(
        min(row[scenario_index] for row in score_rows)
        for scenario_index in range(len(scenarios))
    )

    def key(entry):
        deployment, scores = entry
        regrets = tuple(score - floor for score, floor in zip(scores, best))
        return (
            max(regrets),
            sum(regrets, Fraction(0)),
            scores,
            *_tail(deployment),
        )

    return min(zip(frontier, score_rows), key=key)[0]


_WORKLOADS = (
    (1, (0,), (None, None, None, 10**18)),
    (4, _INDICES, (None, None, None, 9000)),
    (16, (1, 2, 3, 4, 8), (None, None, None, 10**18)),
    (8, (1, 2, 4), (9000, None, None, None)),
    (4, (3,), (None, 4000, None, None)),
    (4, _INDICES, (9000, None, 7000, None)),
    (2, (0, 1), (None, None, None, 6000)),
    (32, (1, 7, 16), (None, None, 10**9, None)),
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


class RecommendMerkleTransportDeploymentWeightedScenariosTest(unittest.TestCase):
    def test_matches_brute_force_ranking(self):
        for capacity, indices, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    indices=indices,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    result = recommend_merkle_transport_deployment_weighted_scenarios(
                        capacity, indices, budgets, scenarios
                    )
                    self.assertEqual(
                        result,
                        _expected(capacity, indices, budgets, scenarios),
                    )

    def test_returns_deployment_profile_on_the_frontier(self):
        frontier = merkle_transport_deployment_frontier(4, _INDICES, _BUDGETS)
        for scenarios in _SCENARIO_SETS:
            with self.subTest(scenarios=scenarios):
                result = recommend_merkle_transport_deployment_weighted_scenarios(
                    4, _INDICES, _BUDGETS, scenarios
                )
                self.assertIsInstance(result, MerkleTransportDeploymentProfile)
                self.assertIn(result, frontier)

    def test_single_scenario_picks_its_weighted_best(self):
        # one scenario makes every regret zero, so the choice is the plain
        # weighted-normalised average minimum (plus the stable tail)
        weights = (1, 2, 3, 4, 5)
        frontier = merkle_transport_deployment_frontier(4, _INDICES, _BUDGETS)
        normalised = _normalised_rows(frontier)
        total = sum(weights)

        def score(deployment):
            row = normalised[frontier.index(deployment)]
            return sum(
                (weight * component for weight, component in zip(weights, row)),
                Fraction(0),
            ) / total

        result = recommend_merkle_transport_deployment_weighted_scenarios(
            4, _INDICES, _BUDGETS, (weights,)
        )
        self.assertEqual(
            result, min(frontier, key=lambda d: (score(d), *_tail(d)))
        )

    def test_repeated_scenarios_counted_separately(self):
        weights = (3, 0, 7, 0, 2)
        once = recommend_merkle_transport_deployment_weighted_scenarios(
            4, _INDICES, _BUDGETS, (weights,)
        )
        twice = recommend_merkle_transport_deployment_weighted_scenarios(
            4, _INDICES, _BUDGETS, (weights, weights)
        )
        thrice = recommend_merkle_transport_deployment_weighted_scenarios(
            4, _INDICES, _BUDGETS, (weights, weights, weights)
        )
        self.assertEqual(once, twice)
        self.assertEqual(once, thrice)

    def test_repeating_one_scenario_can_change_the_choice(self):
        # unlike an inert re-count of a lone scenario, duplicating one of
        # two distinct scenarios weights that scenario's regret and can
        # change the minimax choice; here two copies of the steps-weighted
        # scenario move the choice to that single scenario's own winner
        capacity, indices, budgets = 16, (3, 5), (None, None, 8000, None)
        checkpoint_weights = (1, 0, 0, 0, 0)
        steps_weights = (0, 0, 0, 0, 1)
        distinct = recommend_merkle_transport_deployment_weighted_scenarios(
            capacity, indices, budgets, (checkpoint_weights, steps_weights)
        )
        duplicated = recommend_merkle_transport_deployment_weighted_scenarios(
            capacity,
            indices,
            budgets,
            (checkpoint_weights, steps_weights, steps_weights),
        )
        tripled = recommend_merkle_transport_deployment_weighted_scenarios(
            capacity,
            indices,
            budgets,
            (checkpoint_weights, steps_weights, steps_weights, steps_weights),
        )
        steps_alone = recommend_merkle_transport_deployment_weighted_scenarios(
            capacity, indices, budgets, (steps_weights,)
        )
        self.assertNotEqual(distinct, duplicated)
        self.assertEqual(duplicated, tripled)
        self.assertEqual(duplicated, steps_alone)

    def test_zero_span_dimensions_score_zero(self):
        # a single-member frontier makes every span zero: the unique member
        # is chosen regardless of the scenarios, without dividing by zero
        budgets = (9000, None, None, None)
        frontier = merkle_transport_deployment_frontier(8, (1, 2, 4), budgets)
        self.assertEqual(len(frontier), 1)
        for scenarios in (
            ((1, 1, 1, 1, 1),),
            ((0, 0, 0, 0, 1),),
            ((9, 8, 7, 6, 5), (1, 0, 0, 0, 0)),
        ):
            with self.subTest(scenarios=scenarios):
                self.assertEqual(
                    recommend_merkle_transport_deployment_weighted_scenarios(
                        8, (1, 2, 4), budgets, scenarios
                    ),
                    frontier[0],
                )

    def test_weight_scales_scenario_scores(self):
        # scaling every weight of a scenario by a constant leaves its
        # normalised score unchanged, hence leaves every regret unchanged
        scenarios = ((1, 2, 3, 4, 5), (3, 0, 7, 0, 2))
        scaled = (
            tuple(7 * weight for weight in scenarios[0]),
            tuple(11 * weight for weight in scenarios[1]),
        )
        self.assertEqual(
            recommend_merkle_transport_deployment_weighted_scenarios(
                4, _INDICES, _BUDGETS, scenarios
            ),
            recommend_merkle_transport_deployment_weighted_scenarios(
                4, _INDICES, _BUDGETS, scaled
            ),
        )

    def test_tie_break_is_documented_tail(self):
        for capacity, indices, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    indices=indices,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    frontier = merkle_transport_deployment_frontier(
                        capacity, indices, budgets
                    )
                    normalised = _normalised_rows(frontier)
                    totals = tuple(sum(weights) for weights in scenarios)

                    def score_tuple(deployment):
                        row = normalised[frontier.index(deployment)]
                        return tuple(
                            sum(
                                (
                                    weight * component
                                    for weight, component in zip(weights, row)
                                ),
                                Fraction(0),
                            )
                            / total
                            for weights, total in zip(scenarios, totals)
                        )

                    all_scores = tuple(score_tuple(d) for d in frontier)
                    best = tuple(
                        min(row[i] for row in all_scores)
                        for i in range(len(scenarios))
                    )

                    def regret_key(deployment):
                        scores = score_tuple(deployment)
                        regrets = tuple(s - b for s, b in zip(scores, best))
                        return (
                            max(regrets),
                            sum(regrets, Fraction(0)),
                            scores,
                        )

                    result = recommend_merkle_transport_deployment_weighted_scenarios(
                        capacity, indices, budgets, scenarios
                    )
                    chosen = regret_key(result)
                    tied = [d for d in frontier if regret_key(d) == chosen]
                    self.assertEqual(result, min(tied, key=_tail))
                    self.assertIn(result, tied)

    def test_scores_are_exact_rational_no_float(self):
        capacity, indices = 16, (1, 2, 3)
        budgets = (None, None, None, 10**18)
        scenarios = ((1, 1, 1, 1, 1), (5, 0, 0, 0, 1))
        frontier = merkle_transport_deployment_frontier(capacity, indices, budgets)
        result = recommend_merkle_transport_deployment_weighted_scenarios(
            capacity, indices, budgets, scenarios
        )
        normalised = _normalised_rows(frontier)
        totals = tuple(sum(weights) for weights in scenarios)

        def scores(deployment):
            row = normalised[frontier.index(deployment)]
            return tuple(
                sum(
                    (weight * component for weight, component in zip(weights, row)),
                    Fraction(0),
                )
                / total
                for weights, total in zip(scenarios, totals)
            )

        all_scores = tuple(scores(d) for d in frontier)
        best = tuple(
            min(row[i] for row in all_scores) for i in range(len(scenarios))
        )

        def worst_regret(deployment):
            return max(s - b for s, b in zip(scores(deployment), best))

        chosen_regret = worst_regret(result)
        for deployment in frontier:
            self.assertLessEqual(chosen_regret, worst_regret(deployment))
            for component in scores(deployment):
                self.assertIsInstance(component, Fraction)

    def test_budgets_are_honoured(self):
        capacity, indices = 4, _INDICES
        budgets = (9000, 3000, 7000, 9000)
        result = recommend_merkle_transport_deployment_weighted_scenarios(
            capacity,
            indices,
            budgets,
            ((1, 2, 3, 4, 5), (5, 4, 3, 2, 1)),
        )
        self.assertLessEqual(result.config.checkpoint_bytes, 9000)
        self.assertLessEqual(result.batch, 3000)
        self.assertLessEqual(result.multi, 7000)
        self.assertLessEqual(
            profile(
                "merkle",
                w=result.config.w,
                height=result.config.height,
            ).steps,
            9000,
        )

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
                recommend_merkle_transport_deployment_weighted_scenarios(
                    4, _INDICES, _BUDGETS, scenarios
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_transport_deployment_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted_scenarios(
                1,
                (0,),
                (100, None, None, None),
                ((1, 1, 1, 1, 1),),
            )
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted_scenarios(
                1,
                (0,),
                (None, None, None, 1),
                ((1, 1, 1, 1, 1),),
            )
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted_scenarios(
                4,
                (1,),
                (None, None, None, 10),
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
                    recommend_merkle_transport_deployment_weighted_scenarios(
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
                    recommend_merkle_transport_deployment_weighted_scenarios(
                        4, _INDICES, _BUDGETS, bad
                    )

    def test_non_integer_weight_raises_type_error(self):
        for bad in (
            ((1.0, 1, 1, 1, 1),),
            ((1, "1", 1, 1, 1),),
            ((1, None, 1, 1, 1),),
            ((1, 1, 1.5, 1, 1),),
            ((1, 1, 1, "x", 1),),
            ((1, 1, 1, 1, 1.5),),
            ((1, 1, 1, 1, 1), (1, None, 1, 1, 1)),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_transport_deployment_weighted_scenarios(
                        4, _INDICES, _BUDGETS, bad
                    )

    def test_invalid_weights_members_raise_value_error(self):
        for bad in (
            (),
            ((1, 1, 1, 1),),
            ((1, 1, 1, 1, 1, 1),),
            ((0, 0, 0, 0, 0),),
            ((1, -1, 1, 1, 1),),
            ((1, 1, -1, 1, 1),),
            ((1, 1, 1, -1, 1),),
            ((-1, 1, 1, 1, 1),),
            ((True, 1, 1, 1, 1),),
            ((1, 1, True, 1, 1),),
            ((1, 1, 1, True, 1),),
            ((1, 1, 1, 1, False),),
            ((1, 1, 1, 1, 1), (0, 0, 0, 0, 0)),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_deployment_weighted_scenarios(
                        4, _INDICES, _BUDGETS, bad
                    )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in (
            ((True, 0, 0, 0, 0),),
            ((0, 0, True, 0, 0),),
            ((0, 0, 0, True, 0),),
            ((0, 0, 0, 0, True),),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_deployment_weighted_scenarios(
                        4, _INDICES, _BUDGETS, bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_deployment_weighted_scenarios(
                        bad_capacity,
                        _INDICES,
                        _BUDGETS,
                        ((1, 1, 1, 1, 1),),
                    )
        for bad_indices in ([1], {1}, "indices", None, 7, range(2)):
            with self.subTest(bad_indices=bad_indices):
                with self.assertRaises(TypeError):
                    recommend_merkle_transport_deployment_weighted_scenarios(
                        4,
                        bad_indices,
                        _BUDGETS,
                        ((1, 1, 1, 1, 1),),
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted_scenarios(
                4, (), _BUDGETS, ((1, 1, 1, 1, 1),)
            )
        for bad_budgets in ([None] * 4, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    recommend_merkle_transport_deployment_weighted_scenarios(
                        4,
                        _INDICES,
                        bad_budgets,
                        ((1, 1, 1, 1, 1),),
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted_scenarios(
                4, _INDICES, (None,) * 4, ((1, 1, 1, 1, 1),)
            )

    def test_frontier_arguments_screened_before_scenarios(self):
        # the capacity/indices/budgets rules belong to the frontier and are
        # screened there before scenarios is inspected
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted_scenarios(
                0, (), (None,) * 4, ()
            )
        with self.assertRaises(TypeError):
            recommend_merkle_transport_deployment_weighted_scenarios(
                4, [1], _BUDGETS, "not a tuple"
            )

    def test_all_four_parameters_are_required_without_defaults(self):
        sig = inspect.signature(
            recommend_merkle_transport_deployment_weighted_scenarios
        )
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "indices", "budgets", "scenarios"],
        )
        for name in ("capacity", "indices", "budgets", "scenarios"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        for scenarios in _SCENARIO_SETS:
            first = recommend_merkle_transport_deployment_weighted_scenarios(
                4, (1, 2), (None, None, None, 9000), scenarios
            )
            second = recommend_merkle_transport_deployment_weighted_scenarios(
                4, (1, 2), (None, None, None, 9000), scenarios
            )
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleSigner,
    MerkleStorageProfile,
    merkle_deployment_frontier,
    profile,
    recommend_merkle_deployment_weighted_scenarios,
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
    return tuple(
        tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(row, spans)
        )
        for row in rows
    )


def _expected(capacity, budgets, scenarios):
    """Rank the deployment frontier by the documented minimax-regret score."""
    frontier = merkle_deployment_frontier(capacity, budgets)
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
        storage, scores = entry
        regrets = tuple(score - floor for score, floor in zip(scores, best))
        return (
            max(regrets),
            sum(regrets, Fraction(0)),
            scores,
            *_tail(storage),
        )

    return min(zip(frontier, score_rows), key=key)[0]


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


class RecommendMerkleDeploymentWeightedScenariosTest(unittest.TestCase):
    def test_matches_brute_force_ranking(self):
        for capacity, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    result = recommend_merkle_deployment_weighted_scenarios(
                        capacity, budgets, scenarios
                    )
                    self.assertEqual(
                        result,
                        _expected(capacity, budgets, scenarios),
                    )

    def test_returns_storage_profile_on_the_frontier(self):
        frontier = merkle_deployment_frontier(16, _BUDGETS)
        for scenarios in _SCENARIO_SETS:
            with self.subTest(scenarios=scenarios):
                result = recommend_merkle_deployment_weighted_scenarios(
                    16, _BUDGETS, scenarios
                )
                self.assertIsInstance(result, MerkleStorageProfile)
                self.assertIn(result, frontier)

    def test_single_scenario_picks_its_weighted_best(self):
        # one scenario makes every regret zero, so the choice is the plain
        # weighted-normalised average minimum (plus the stable tail)
        weights = (1, 2, 3, 4)
        frontier = merkle_deployment_frontier(16, _BUDGETS)
        normalised = _normalised_rows(frontier)
        total = sum(weights)

        def score(storage):
            row = normalised[frontier.index(storage)]
            return sum(
                (weight * component for weight, component in zip(weights, row)),
                Fraction(0),
            ) / total

        result = recommend_merkle_deployment_weighted_scenarios(
            16, _BUDGETS, (weights,)
        )
        self.assertEqual(
            result, min(frontier, key=lambda s: (score(s), *_tail(s)))
        )

    def test_each_single_positive_weight_minimises_its_dimension(self):
        frontier = merkle_deployment_frontier(16, _BUDGETS)
        for dimension in range(4):
            weights = tuple(1 if i == dimension else 0 for i in range(4))
            with self.subTest(weights=weights):
                result = recommend_merkle_deployment_weighted_scenarios(
                    16, _BUDGETS, (weights,)
                )
                self.assertEqual(
                    _metrics(result)[dimension],
                    min(_metrics(storage)[dimension] for storage in frontier),
                )

    def test_repeated_scenarios_counted_separately(self):
        # two conflicting single-dimension scenarios: one minimises chain
        # steps (picks w=4), the other minimises the standalone proof wire
        # length (picks w=8). Repeating the second scenario must actually
        # swing the minimax-regret choice; an implementation that deduped
        # equal scenarios would return the (first, second) result unchanged.
        first = (0, 0, 0, 1)
        second = (0, 0, 1, 0)
        only_first = recommend_merkle_deployment_weighted_scenarios(
            16, _BUDGETS, (first,)
        )
        one_each = recommend_merkle_deployment_weighted_scenarios(
            16, _BUDGETS, (first, second)
        )
        second_doubled = recommend_merkle_deployment_weighted_scenarios(
            16, _BUDGETS, (first, second, second)
        )
        first_doubled = recommend_merkle_deployment_weighted_scenarios(
            16, _BUDGETS, (first, first, second)
        )
        self.assertEqual(only_first.w, 4)
        self.assertEqual(one_each.w, 4)
        self.assertEqual(second_doubled.w, 8)
        self.assertEqual(first_doubled.w, 4)
        self.assertNotEqual(one_each, second_doubled)

    def test_repeated_scenarios_regression_cases(self):
        # repeated scenarios must be kept as separate tuple positions.
        # Each case pairs a scenario tuple with the tuple a
        # duplicate-dropping implementation would collapse it to: the
        # minimax-regret ranking keeps every copy (an extra copy adds an
        # extra regret column that can swing the regret-sum tie-break), so
        # the full tuple must actually CHANGE the choice versus the
        # collapsed one while still agreeing with the brute-force ranking.
        # The previous (3, 0, 7, 2)/(0, 5, 0, 1) cases always selected the
        # same config, so they could not detect a deduping implementation.
        first = (0, 0, 0, 1)
        second = (0, 0, 1, 0)

        def collapsed(scenarios):
            unique = []
            for scenario in scenarios:
                if scenario not in unique:
                    unique.append(scenario)
            return tuple(unique)

        cases = (
            (first, second, second),
            (second, first, first),
        )
        for scenarios in cases:
            with self.subTest(scenarios=scenarios):
                result = recommend_merkle_deployment_weighted_scenarios(
                    16, _BUDGETS, scenarios
                )
                collapsed_result = (
                    recommend_merkle_deployment_weighted_scenarios(
                        16, _BUDGETS, collapsed(scenarios)
                    )
                )
                self.assertEqual(result, _expected(16, _BUDGETS, scenarios))
                self.assertNotEqual(result, collapsed_result)

    def test_zero_span_dimensions_score_zero(self):
        # a single-member frontier makes every span zero: the unique member
        # is chosen regardless of the scenarios, without dividing by zero
        budgets = (None, None, None, 1005)
        frontier = merkle_deployment_frontier(1, budgets)
        self.assertEqual(len(frontier), 1)
        for scenarios in (
            ((1, 1, 1, 1),),
            ((0, 0, 0, 1),),
            ((9, 8, 7, 6), (1, 0, 0, 0)),
        ):
            with self.subTest(scenarios=scenarios):
                self.assertEqual(
                    recommend_merkle_deployment_weighted_scenarios(
                        1, budgets, scenarios
                    ),
                    frontier[0],
                )

    def test_weight_scales_scenario_scores(self):
        # scaling every weight of a scenario by a constant leaves its
        # normalised score unchanged, hence leaves every regret unchanged
        scenarios = ((1, 2, 3, 4), (3, 0, 7, 2))
        scaled = (
            tuple(7 * weight for weight in scenarios[0]),
            tuple(11 * weight for weight in scenarios[1]),
        )
        self.assertEqual(
            recommend_merkle_deployment_weighted_scenarios(
                16, _BUDGETS, scenarios
            ),
            recommend_merkle_deployment_weighted_scenarios(
                16, _BUDGETS, scaled
            ),
        )

    def test_tie_break_is_documented_tail(self):
        for capacity, budgets in _WORKLOADS:
            for scenarios in _SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    frontier = merkle_deployment_frontier(capacity, budgets)
                    normalised = _normalised_rows(frontier)
                    totals = tuple(sum(weights) for weights in scenarios)

                    def score_tuple(storage):
                        row = normalised[frontier.index(storage)]
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

                    all_scores = tuple(score_tuple(s) for s in frontier)
                    best = tuple(
                        min(row[i] for row in all_scores)
                        for i in range(len(scenarios))
                    )

                    def regret_key(storage):
                        scores = score_tuple(storage)
                        regrets = tuple(s - b for s, b in zip(scores, best))
                        return (
                            max(regrets),
                            sum(regrets, Fraction(0)),
                            scores,
                        )

                    result = recommend_merkle_deployment_weighted_scenarios(
                        capacity, budgets, scenarios
                    )
                    chosen = regret_key(result)
                    tied = [s for s in frontier if regret_key(s) == chosen]
                    self.assertEqual(result, min(tied, key=_tail))
                    self.assertIn(result, tied)

    def test_scores_are_exact_rational_no_float(self):
        scenarios = ((1, 1, 1, 1), (5, 0, 0, 1))
        frontier = merkle_deployment_frontier(16, _BUDGETS)
        result = recommend_merkle_deployment_weighted_scenarios(
            16, _BUDGETS, scenarios
        )
        normalised = _normalised_rows(frontier)
        totals = tuple(sum(weights) for weights in scenarios)

        def scores(storage):
            row = normalised[frontier.index(storage)]
            return tuple(
                sum(
                    (weight * component for weight, component in zip(weights, row)),
                    Fraction(0),
                )
                / total
                for weights, total in zip(scenarios, totals)
            )

        all_scores = tuple(scores(s) for s in frontier)
        best = tuple(
            min(row[i] for row in all_scores) for i in range(len(scenarios))
        )

        def worst_regret(storage):
            return max(s - b for s, b in zip(scores(storage), best))

        chosen_regret = worst_regret(result)
        for storage in frontier:
            self.assertLessEqual(chosen_regret, worst_regret(storage))
            for component in scores(storage):
                self.assertIsInstance(component, Fraction)

    def test_budgets_are_honoured(self):
        budgets = (9000, 1300, 1400, 9000)
        result = recommend_merkle_deployment_weighted_scenarios(
            4,
            budgets,
            ((1, 2, 3, 4), (4, 3, 2, 1)),
        )
        self.assertLessEqual(result.checkpoint_bytes, 9000)
        self.assertLessEqual(result.signature_wire_bytes, 1300)
        self.assertLessEqual(result.proof_wire_bytes, 1400)
        self.assertLessEqual(
            profile("merkle", w=result.w, height=result.height).steps,
            9000,
        )

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
            for scenarios in _SCENARIO_SETS:
                calls = 0
                recommend_merkle_deployment_weighted_scenarios(
                    16, _BUDGETS, scenarios
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_deployment_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted_scenarios(
                1, (100, None, None, None), ((1, 1, 1, 1),)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted_scenarios(
                256, (None, 1000, None, None), ((1, 1, 1, 1),)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted_scenarios(
                256, (None, None, None, 10), ((1, 1, 1, 1),)
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
                    recommend_merkle_deployment_weighted_scenarios(
                        16, _BUDGETS, bad
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
                    recommend_merkle_deployment_weighted_scenarios(
                        16, _BUDGETS, bad
                    )
        # the bad scenario member is also rejected when it follows a valid
        # one, not only when it is the sole member of the tuple
        good = (1, 1, 1, 1)
        for bad_member in ([1, 1, 1, 1], "scenario", None, 7):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(TypeError):
                    recommend_merkle_deployment_weighted_scenarios(
                        16, _BUDGETS, (good, bad_member)
                    )

    def test_non_integer_weight_raises_type_error(self):
        base_bad = (
            ((1.0, 1, 1, 1),),
            ((1, "1", 1, 1),),
            ((1, None, 1, 1),),
            ((1, 1, 1, 1.5),),
        )
        for bad in base_bad:
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_deployment_weighted_scenarios(
                        16, _BUDGETS, bad
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
                            recommend_merkle_deployment_weighted_scenarios(
                                16, _BUDGETS, tuple(scenarios)
                            )

    def test_invalid_weights_members_raise_value_error(self):
        base_bad = (
            (),
            ((1, 1, 1),),
            ((1, 1, 1, 1, 1),),
            ((0, 0, 0, 0),),
        )
        for bad in base_bad:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment_weighted_scenarios(
                        16, _BUDGETS, bad
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
                            recommend_merkle_deployment_weighted_scenarios(
                                16, _BUDGETS, tuple(scenarios)
                            )
        for scenario_position in range(2):
            scenarios = [good, good]
            scenarios[scenario_position] = (0, 0, 0, 0)
            with self.subTest(scenario_position=scenario_position):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment_weighted_scenarios(
                        16, _BUDGETS, tuple(scenarios)
                    )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in (((True, 0, 0, 0),), ((0, 0, 0, True),)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment_weighted_scenarios(
                        16, _BUDGETS, bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment_weighted_scenarios(
                        bad_capacity,
                        _BUDGETS,
                        ((1, 1, 1, 1),),
                    )
        for bad_budgets in ([None] * 4, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    recommend_merkle_deployment_weighted_scenarios(
                        16,
                        bad_budgets,
                        ((1, 1, 1, 1),),
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted_scenarios(
                16, (None,) * 4, ((1, 1, 1, 1),)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted_scenarios(
                16, (None,) * 3, ((1, 1, 1, 1),)
            )
        for bad_member in (0, -1, True, 1.5, "100"):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment_weighted_scenarios(
                        16,
                        (None, bad_member, None, None),
                        ((1, 1, 1, 1),),
                    )

    def test_frontier_arguments_screened_before_scenarios(self):
        # the capacity/budgets rules belong to the frontier and are
        # screened there before scenarios is inspected
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted_scenarios(
                0, (None,) * 4, ()
            )
        with self.assertRaises(TypeError):
            recommend_merkle_deployment_weighted_scenarios(
                16, [None, None, None, 9000], "not a tuple"
            )

    def test_all_three_parameters_are_required_without_defaults(self):
        sig = inspect.signature(
            recommend_merkle_deployment_weighted_scenarios
        )
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "budgets", "scenarios"],
        )
        for name in ("capacity", "budgets", "scenarios"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        for scenarios in _SCENARIO_SETS:
            first = recommend_merkle_deployment_weighted_scenarios(
                16, _BUDGETS, scenarios
            )
            second = recommend_merkle_deployment_weighted_scenarios(
                16, _BUDGETS, scenarios
            )
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

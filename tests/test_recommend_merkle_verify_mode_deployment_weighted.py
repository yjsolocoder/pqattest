import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleModeCost,
    MerkleSigner,
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


def _expected(capacity, groups, budgets, weights):
    """Rank the frontier by the documented weighted normalised score."""
    frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
    rows = [_metrics(mode_cost) for mode_cost in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(5)
    )
    weight_total = sum(weights)

    def key(item):
        mode_cost, values = item
        score = Fraction(0)
        for value, weight, (low, high) in zip(values, weights, spans):
            if high > low:
                score += weight * Fraction(value - low, high - low)
        score /= weight_total
        return (score, *_tail(mode_cost))

    return min(zip(frontier, rows), key=key)[0]


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


class RecommendMerkleVerifyModeDeploymentWeightedTest(unittest.TestCase):
    def test_matches_brute_force_ranking(self):
        for capacity, groups, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    weights=weights,
                ):
                    result = recommend_merkle_verify_mode_deployment_weighted(
                        capacity, groups, budgets, weights
                    )
                    self.assertEqual(
                        result,
                        _expected(capacity, groups, budgets, weights),
                    )

    def test_returns_mode_cost_on_the_frontier(self):
        frontier = merkle_verify_mode_frontier(16, _GROUPS, _BUDGETS)
        for weights in _WEIGHT_SETS:
            with self.subTest(weights=weights):
                result = recommend_merkle_verify_mode_deployment_weighted(
                    16, _GROUPS, _BUDGETS, weights
                )
                self.assertIsInstance(result, MerkleModeCost)
                self.assertIn(result, frontier)

    def test_single_lit_dimension_minimises_that_dimension(self):
        # lighting only one weight must return the frontier member with the
        # minimum raw cost in that dimension (ties broken by the tail)
        frontier = merkle_verify_mode_frontier(16, _GROUPS, _BUDGETS)
        for dimension in range(5):
            weights = tuple(1 if index == dimension else 0 for index in range(5))
            with self.subTest(dimension=dimension):
                result = recommend_merkle_verify_mode_deployment_weighted(
                    16, _GROUPS, _BUDGETS, weights
                )
                chosen_value = _metrics(result)[dimension]
                self.assertEqual(
                    chosen_value,
                    min(_metrics(mode_cost)[dimension] for mode_cost in frontier),
                )
                tied = [
                    mode_cost
                    for mode_cost in frontier
                    if _metrics(mode_cost)[dimension] == chosen_value
                ]
                self.assertEqual(result, min(tied, key=_tail))

    def test_zero_span_dimension_scores_zero(self):
        # a single-member frontier makes every span zero: the unique member
        # is chosen regardless of the weights, without dividing by zero
        budgets = (None, None, 2243, None, None, 2000)
        frontier = merkle_verify_mode_frontier(1, ((0,),), budgets)
        self.assertEqual(len(frontier), 1)
        for weights in ((1, 1, 1, 1, 1), (0, 0, 0, 0, 1), (9, 8, 7, 6, 5)):
            with self.subTest(weights=weights):
                self.assertEqual(
                    recommend_merkle_verify_mode_deployment_weighted(
                        1, ((0,),), budgets, weights
                    ),
                    frontier[0],
                )

    def test_tie_break_is_documented_tail(self):
        # among the members sharing the smallest weighted score, the chosen
        # one must be the smallest by checkpoint bytes, leaf count, w,
        # height and the modes tuple in lexicographic order
        for capacity, groups, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    weights=weights,
                ):
                    frontier = merkle_verify_mode_frontier(
                        capacity, groups, budgets
                    )
                    rows = [_metrics(mc) for mc in frontier]
                    spans = tuple(
                        (min(row[i] for row in rows), max(row[i] for row in rows))
                        for i in range(5)
                    )
                    weight_total = sum(weights)

                    def score(mode_cost):
                        total = Fraction(0)
                        for value, weight, (low, high) in zip(
                            _metrics(mode_cost), weights, spans
                        ):
                            if high > low:
                                total += weight * Fraction(value - low, high - low)
                        return total / weight_total

                    result = recommend_merkle_verify_mode_deployment_weighted(
                        capacity, groups, budgets, weights
                    )
                    best = score(result)
                    tied = [mc for mc in frontier if score(mc) == best]
                    self.assertEqual(result, min(tied, key=_tail))
                    self.assertIn(result, tied)

    def test_scores_are_exact_rational_no_float(self):
        # the documented arithmetic uses Fraction; the chosen score must be
        # no greater than every other member's exact score
        capacity, groups, budgets = 16, _GROUPS, _BUDGETS
        weights = (1, 1, 1, 1, 1)
        frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
        result = recommend_merkle_verify_mode_deployment_weighted(
            capacity, groups, budgets, weights
        )
        rows = [_metrics(mc) for mc in frontier]
        spans = tuple(
            (min(row[i] for row in rows), max(row[i] for row in rows))
            for i in range(5)
        )
        weight_total = sum(weights)

        def score(mode_cost):
            total = Fraction(0)
            for value, weight, (low, high) in zip(
                _metrics(mode_cost), weights, spans
            ):
                if high > low:
                    total += weight * Fraction(value - low, high - low)
            return total / weight_total

        chosen_score = score(result)
        for mode_cost in frontier:
            self.assertLessEqual(chosen_score, score(mode_cost))
        self.assertIsInstance(chosen_score, Fraction)

    def test_budgets_are_honoured(self):
        capacity, groups = 4, ((0,), (1,))
        budgets = (None, 3000, 6000, 9000, 5, 10**9)
        result = recommend_merkle_verify_mode_deployment_weighted(
            capacity, groups, budgets, (1, 2, 3, 4, 5)
        )
        self.assertTrue(all(size <= 3000 for size in result.plan.sizes))
        self.assertLessEqual(result.plan.total, 6000)
        self.assertLessEqual(
            profile(
                "merkle",
                w=result.plan.config.w,
                height=result.plan.config.height,
            ).steps,
            9000,
        )
        self.assertLessEqual(result.nodes, 5)
        self.assertLessEqual(result.cost.total, 10**9)

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
                recommend_merkle_verify_mode_deployment_weighted(
                    16, _GROUPS, _BUDGETS, weights
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_verify_mode_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment_weighted(
                1,
                ((0,),),
                (100, None, None, None, None, None),
                (1, 1, 1, 1, 1),
            )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment_weighted(
                4,
                ((0,),),
                (None, None, None, None, None, 10),
                (1, 1, 1, 1, 1),
            )

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 1, 1, 1, 1], {1, 2, 3, 4, 5}, "weights", None, 7, range(5)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_deployment_weighted(
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
                    recommend_merkle_verify_mode_deployment_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )
        # a non-integer weight is rejected at every weight position, not
        # just the first one the validator inspects
        good = (1, 1, 1, 1, 1)
        for position in range(5):
            for replacement in (1.0, "1", None, 1.5):
                bad = tuple(
                    replacement if index == position else good[index]
                    for index in range(5)
                )
                with self.subTest(position=position, replacement=replacement):
                    with self.assertRaises(TypeError):
                        recommend_merkle_verify_mode_deployment_weighted(
                            16, _GROUPS, _BUDGETS, bad
                        )

    def test_invalid_weights_members_raise_value_error(self):
        for bad in (
            (),
            (1, 1, 1, 1),
            (1, 1, 1, 1, 1, 1),
            (0, 0, 0, 0, 0),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_verify_mode_deployment_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )
        # a boolean or negative weight is rejected at every position, not
        # just the first one the validator inspects
        good = (1, 1, 1, 1, 1)
        for position in range(5):
            for replacement in (-1, True, False):
                bad = tuple(
                    replacement if index == position else good[index]
                    for index in range(5)
                )
                with self.subTest(position=position, replacement=replacement):
                    with self.assertRaises(ValueError):
                        recommend_merkle_verify_mode_deployment_weighted(
                            16, _GROUPS, _BUDGETS, bad
                        )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in ((True, 0, 0, 0, 0), (0, 0, 0, 0, True)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_verify_mode_deployment_weighted(
                        16, _GROUPS, _BUDGETS, bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    recommend_merkle_verify_mode_deployment_weighted(
                        bad_capacity,
                        _GROUPS,
                        _BUDGETS,
                        (1, 1, 1, 1, 1),
                    )
        for bad_groups in ([(0, 1)], {(0, 1)}, "groups", None, 7, range(2)):
            with self.subTest(bad_groups=bad_groups):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_deployment_weighted(
                        16,
                        bad_groups,
                        _BUDGETS,
                        (1, 1, 1, 1, 1),
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment_weighted(
                16, (), _BUDGETS, (1, 1, 1, 1, 1)
            )
        for bad_budgets in ([None] * 6, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    recommend_merkle_verify_mode_deployment_weighted(
                        16,
                        _GROUPS,
                        bad_budgets,
                        (1, 1, 1, 1, 1),
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment_weighted(
                16, _GROUPS, (None,) * 6, (1, 1, 1, 1, 1)
            )

    def test_frontier_arguments_screened_before_weights(self):
        # the capacity/groups/budgets rules belong to the frontier and are
        # screened there before weights is inspected
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment_weighted(
                0, (), (None,) * 6, (0, 0, 0, 0, 0)
            )
        with self.assertRaises(TypeError):
            recommend_merkle_verify_mode_deployment_weighted(
                16, [(0, 1)], _BUDGETS, "not a tuple"
            )

    def test_all_four_parameters_are_required_without_defaults(self):
        sig = inspect.signature(
            recommend_merkle_verify_mode_deployment_weighted
        )
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "groups", "budgets", "weights"],
        )
        for name in ("capacity", "groups", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        for weights in _WEIGHT_SETS:
            first = recommend_merkle_verify_mode_deployment_weighted(
                16,
                _GROUPS,
                (None, None, None, 9000, None, None),
                weights,
            )
            second = recommend_merkle_verify_mode_deployment_weighted(
                16,
                _GROUPS,
                (None, None, None, 9000, None, None),
                weights,
            )
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)

    # --- regression tests pinning the refactored shared scoring semantics ---

    # The baseline frontier has six members with genuine trade-offs: w=4
    # plans are transport-heavy but verify-cheap, w=8 plans are the reverse,
    # and the two batch/multiproof combinations trade peak transport against
    # carried nodes. The tails below pin each member in frontier order.
    _TAIL_W4_MM = (34385, 16, 4, 4, ("multiproof", "multiproof"))
    _TAIL_W4_MB = (34385, 16, 4, 4, ("multiproof", "batch"))
    _TAIL_W4_BB = (34385, 16, 4, 4, ("batch", "batch"))
    _TAIL_W8_MM = (17489, 16, 8, 4, ("multiproof", "multiproof"))
    _TAIL_W8_MB = (17489, 16, 8, 4, ("multiproof", "batch"))
    _TAIL_W8_BB = (17489, 16, 8, 4, ("batch", "batch"))

    def test_real_cost_tradeoff_frontier_shape(self):
        frontier = merkle_verify_mode_frontier(16, _GROUPS, _BUDGETS)
        tails = [_tail(mode_cost) for mode_cost in frontier]
        self.assertEqual(
            tails,
            [
                self._TAIL_W4_MM,
                self._TAIL_W4_MB,
                self._TAIL_W4_BB,
                self._TAIL_W8_MM,
                self._TAIL_W8_MB,
                self._TAIL_W8_BB,
            ],
        )
        columns = list(zip(*(_metrics(mode_cost) for mode_cost in frontier)))
        # every one of the five weighted costs actually varies on this
        # frontier, so single-dimension weights meet a real minimum
        self.assertTrue(all(min(column) < max(column) for column in columns))
        # the cheapest transport plan is the most expensive hashes plan and
        # vice versa: no member dominates on the weighted dimensions
        cheapest_transport = min(frontier, key=lambda mc: _metrics(mc)[0])
        cheapest_hashes = min(frontier, key=lambda mc: _metrics(mc)[2])
        self.assertNotEqual(cheapest_transport, cheapest_hashes)
        self.assertEqual(_tail(cheapest_transport), self._TAIL_W8_MM)
        self.assertEqual(_tail(cheapest_hashes), self._TAIL_W4_MM)

    def test_single_positive_weight_picks_that_dimensions_minimum(self):
        # one lit dimension on a trade-off frontier: winner, raw minimum and
        # tail tie-break are all pinned rather than inferred from the sibling
        # entry point
        pinned = (
            (0, self._TAIL_W8_MM),  # total transport 4768
            (1, self._TAIL_W8_MM),  # single-group peak 2419
            (2, self._TAIL_W4_MM),  # verifier hashes 4034
            (3, self._TAIL_W8_BB),  # nodes 0, tie broken by checkpoint bytes
            (4, self._TAIL_W4_BB),  # steps 1005, tie broken by modes tuple
        )
        frontier = merkle_verify_mode_frontier(16, _GROUPS, _BUDGETS)
        for dimension, expected_tail in pinned:
            weights = tuple(
                1 if index == dimension else 0 for index in range(5)
            )
            with self.subTest(dimension=dimension):
                result = recommend_merkle_verify_mode_deployment_weighted(
                    16, _GROUPS, _BUDGETS, weights
                )
                values = _metrics(result)
                column = [
                    _metrics(mode_cost)[dimension] for mode_cost in frontier
                ]
                self.assertEqual(values[dimension], min(column))
                self.assertEqual(_tail(result), expected_tail)

    def test_equal_weights_picks_exact_pinned_plan_and_score(self):
        # independent exact-Fraction recomputation pins the actual winner,
        # not just consistency with the explaining entry point
        result = recommend_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, _BUDGETS, (1, 1, 1, 1, 1)
        )
        self.assertEqual(_tail(result), self._TAIL_W4_BB)
        frontier = merkle_verify_mode_frontier(16, _GROUPS, _BUDGETS)
        rows = [_metrics(mode_cost) for mode_cost in frontier]
        spans = tuple(
            (min(row[i] for row in rows), max(row[i] for row in rows))
            for i in range(5)
        )

        def exact_score(mode_cost):
            score = Fraction(0)
            for value, (low, high) in zip(_metrics(mode_cost), spans):
                if high > low:
                    score += Fraction(value - low, high - low)
            return score / 5

        winner_score = exact_score(result)
        self.assertEqual(winner_score, Fraction(10223, 25555))
        for mode_cost in frontier:
            if mode_cost != result:
                self.assertLess(winner_score, exact_score(mode_cost))

    def test_score_ties_are_broken_by_the_documented_tail(self):
        # nodes-only: both all-batch plans carry zero nodes and tie at score
        # 0; the smaller checkpoint bytes (w=8) must win
        nodes_result = recommend_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, _BUDGETS, (0, 0, 0, 1, 0)
        )
        self.assertEqual(_tail(nodes_result), self._TAIL_W8_BB)
        # steps-only: the three w=4 plans share the 1005-step minimum and
        # tie at score 0; checkpoint/leaf/w/height are equal, so the modes
        # tuple lexicographic order picks ("batch", "batch")
        steps_result = recommend_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, _BUDGETS, (0, 0, 0, 0, 1)
        )
        self.assertEqual(_tail(steps_result), self._TAIL_W4_BB)

    def test_partial_zero_span_dimension_is_ignored(self):
        # the hashes budget leaves only the three w=4 members, whose steps
        # column is constant; the steps normalised cost is therefore zero
        # for every row and a steps-only weight falls through to the tail
        budgets = (None, 5000, 12000, None, 8, 5000)
        frontier = merkle_verify_mode_frontier(16, _GROUPS, budgets)
        self.assertEqual(len(frontier), 3)
        steps_values = {_metrics(mode_cost)[4] for mode_cost in frontier}
        self.assertEqual(steps_values, {1005})
        result = recommend_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, budgets, (0, 0, 0, 0, 1)
        )
        self.assertEqual(_tail(result), self._TAIL_W4_BB)

    def test_budget_boundaries_are_inclusive_and_exclusive(self):
        # aggregate-transport boundary: exactly 4768 admits one plan, 4767
        # admits nothing
        result = recommend_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, (None, None, 4768, None, None, None), (1, 1, 1, 1, 1)
        )
        self.assertEqual(_tail(result), self._TAIL_W8_MM)
        self.assertEqual(result.plan.total, 4768)
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment_weighted(
                16, _GROUPS, (None, None, 4767, None, None, None),
                (1, 1, 1, 1, 1),
            )
        # checkpoint boundary: 17489 admits the three w=8 plans, 17488 none
        boundary = recommend_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, (17489, None, None, None, None, None), (1, 1, 1, 1, 1)
        )
        self.assertEqual(_tail(boundary), self._TAIL_W8_MM)
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment_weighted(
                16, _GROUPS, (17488, None, None, None, None, None),
                (1, 1, 1, 1, 1),
            )
        # verifier-hashes boundary: 4034 admits one w=4 plan, 4033 none
        hashes_result = recommend_merkle_verify_mode_deployment_weighted(
            16, _GROUPS, (None, None, None, None, None, 4034),
            (1, 1, 1, 1, 1),
        )
        self.assertEqual(_tail(hashes_result), self._TAIL_W4_MM)
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment_weighted(
                16, _GROUPS, (None, None, None, None, None, 4033),
                (1, 1, 1, 1, 1),
            )

    def test_multiple_invalid_arguments_keep_baseline_precedence(self):
        valid_groups = _GROUPS
        # groups type is screened before capacity, budgets and weights
        with self.assertRaises(TypeError):
            recommend_merkle_verify_mode_deployment_weighted(
                0, [valid_groups], "bad", 7
            )
        # capacity before budgets, even with a non-tuple budgets/weights
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment_weighted(
                0, valid_groups, "bad", 7
            )
        # budgets type before weights type
        with self.assertRaises(TypeError):
            recommend_merkle_verify_mode_deployment_weighted(
                16, valid_groups, "bad", 7
            )
        # an infeasible frontier raises before a non-tuple weights is seen
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment_weighted(
                16, valid_groups, (100, None, None, None, None, None), 7
            )
        # an illegal leaf index is a frontier ValueError screened before
        # the wrong-length weights ValueError
        with self.assertRaises(ValueError):
            recommend_merkle_verify_mode_deployment_weighted(
                16, ((0, 0),), _BUDGETS, ()
            )
        # once the frontier is feasible, the weights TypeError surfaces
        with self.assertRaises(TypeError):
            recommend_merkle_verify_mode_deployment_weighted(
                16, valid_groups, _BUDGETS, 7
            )


if __name__ == "__main__":
    unittest.main()

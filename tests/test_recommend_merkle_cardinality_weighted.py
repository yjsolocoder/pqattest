import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleModeCost,
    MerkleSigner,
    merkle_cardinality_frontier,
    profile,
    recommend_merkle_cardinality_weighted,
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


def _expected(capacity, group_sizes, budgets, weights):
    """Rank the frontier by the documented weighted normalised score."""
    frontier = merkle_cardinality_frontier(capacity, group_sizes, budgets)
    rows = [_metrics(mode_cost) for mode_cost in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(5)
    )

    def key(item):
        mode_cost, values = item
        score = Fraction(0)
        for value, weight, (low, high) in zip(values, weights, spans):
            if high > low:
                score += weight * Fraction(value - low, high - low)
        return (score, *_tail(mode_cost))

    return min(zip(frontier, rows), key=key)[0]


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

_WEIGHT_SETS = (
    (1, 1, 1, 1, 1),
    (10, 0, 0, 0, 0),
    (0, 0, 0, 0, 1),
    (1, 2, 3, 4, 5),
    (0, 1, 0, 1, 0),
    (10**9, 1, 1, 1, 1),
    (3, 0, 7, 0, 2),
)


class RecommendMerkleCardinalityWeightedTest(unittest.TestCase):
    def test_matches_brute_force_ranking(self):
        for capacity, group_sizes, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    group_sizes=group_sizes,
                    budgets=budgets,
                    weights=weights,
                ):
                    result = recommend_merkle_cardinality_weighted(
                        capacity, group_sizes, budgets, weights
                    )
                    self.assertEqual(
                        result,
                        _expected(capacity, group_sizes, budgets, weights),
                    )

    def test_returns_mode_cost_on_the_frontier(self):
        frontier = merkle_cardinality_frontier(4, _SIZES, _BUDGETS)
        for weights in _WEIGHT_SETS:
            with self.subTest(weights=weights):
                result = recommend_merkle_cardinality_weighted(
                    4, _SIZES, _BUDGETS, weights
                )
                self.assertIsInstance(result, MerkleModeCost)
                self.assertIn(result, frontier)

    def test_zero_weight_ignores_dimension(self):
        # only the steps weight is positive: the chosen plan must minimise
        # the (non-normalised, hence normalised) chain steps
        frontier = merkle_cardinality_frontier(4, _SIZES, _BUDGETS)
        steps = lambda mc: profile(
            "merkle", w=mc.plan.config.w, height=mc.plan.config.height
        ).steps
        result = recommend_merkle_cardinality_weighted(
            4, _SIZES, _BUDGETS, (0, 0, 0, 0, 1)
        )
        self.assertEqual(steps(result), min(steps(mc) for mc in frontier))

    def test_zero_span_dimension_scores_zero(self):
        # a single-member frontier makes every span zero: the unique member
        # is chosen regardless of the weights, without dividing by zero
        budgets = (None, None, 2243, None, None, 2000)
        frontier = merkle_cardinality_frontier(1, (1,), budgets)
        self.assertEqual(len(frontier), 1)
        for weights in ((1, 1, 1, 1, 1), (0, 0, 0, 0, 1), (9, 8, 7, 6, 5)):
            with self.subTest(weights=weights):
                self.assertEqual(
                    recommend_merkle_cardinality_weighted(
                        1, (1,), budgets, weights
                    ),
                    frontier[0],
                )

    def test_tie_break_is_documented_tail(self):
        # among the members sharing the smallest weighted score, the chosen
        # one must be the smallest by checkpoint bytes, leaf count, w,
        # height and the modes tuple in lexicographic order
        for capacity, group_sizes, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    group_sizes=group_sizes,
                    budgets=budgets,
                    weights=weights,
                ):
                    frontier = merkle_cardinality_frontier(
                        capacity, group_sizes, budgets
                    )
                    rows = [_metrics(mc) for mc in frontier]
                    spans = tuple(
                        (min(row[i] for row in rows), max(row[i] for row in rows))
                        for i in range(5)
                    )

                    def score(mode_cost):
                        total = Fraction(0)
                        for value, weight, (low, high) in zip(
                            _metrics(mode_cost), weights, spans
                        ):
                            if high > low:
                                total += weight * Fraction(value - low, high - low)
                        return total

                    result = recommend_merkle_cardinality_weighted(
                        capacity, group_sizes, budgets, weights
                    )
                    best = score(result)
                    tied = [mc for mc in frontier if score(mc) == best]
                    self.assertEqual(result, min(tied, key=_tail))
                    self.assertIn(result, tied)

    def test_scores_are_exact_rational_no_float(self):
        # the documented arithmetic uses Fraction; spot-check the chosen
        # score against an exact computation and against a float rounding
        # hazard: unequal exact scores that float arithmetic would collapse
        # must still be ordered correctly
        capacity, sizes, budgets = 16, (1, 2, 3), (None, None, None, None, None, 10**18)
        weights = (1, 1, 1, 1, 1)
        frontier = merkle_cardinality_frontier(capacity, sizes, budgets)
        result = recommend_merkle_cardinality_weighted(
            capacity, sizes, budgets, weights
        )
        rows = [_metrics(mc) for mc in frontier]
        spans = tuple(
            (min(row[i] for row in rows), max(row[i] for row in rows))
            for i in range(5)
        )

        def score(mode_cost):
            total = Fraction(0)
            for value, weight, (low, high) in zip(
                _metrics(mode_cost), weights, spans
            ):
                if high > low:
                    total += weight * Fraction(value - low, high - low)
            return total

        chosen_score = score(result)
        for mode_cost in frontier:
            self.assertLessEqual(chosen_score, score(mode_cost))
        self.assertIsInstance(chosen_score, Fraction)

    def test_budgets_are_honoured(self):
        capacity, sizes = 4, _SIZES
        budgets = (None, 3000, 6000, 9000, 5, 10**9)
        result = recommend_merkle_cardinality_weighted(
            capacity, sizes, budgets, (1, 2, 3, 4, 5)
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
        original = merkle_cardinality_frontier

        import pqattest.params as params_module

        def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)

        params_module.merkle_cardinality_frontier = counting
        try:
            for weights in _WEIGHT_SETS:
                calls = 0
                recommend_merkle_cardinality_weighted(
                    4, _SIZES, _BUDGETS, weights
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_cardinality_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_merkle_cardinality_weighted(
                1, (1,), (100, None, None, None, None, None), (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_cardinality_weighted(
                1, (257,), (None, None, None, None, None, 1), (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_cardinality_weighted(
                4, (1,), (None, None, None, None, None, 10), (1, 1, 1, 1, 1)
            )

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 1, 1, 1, 1], {1, 2, 3, 4, 5}, "weights", None, 7, range(5)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_cardinality_weighted(
                        4, _SIZES, _BUDGETS, bad
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
            (1.0, 1, 1, 1, 1),
            (1, "1", 1, 1, 1),
            (1, None, 1, 1, 1),
            (1, 1, 1, 1, 1.5),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_cardinality_weighted(
                        4, _SIZES, _BUDGETS, bad
                    )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in ((True, 0, 0, 0, 0), (0, 0, 0, 0, True)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_cardinality_weighted(
                        4, _SIZES, _BUDGETS, bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    recommend_merkle_cardinality_weighted(
                        bad_capacity, _SIZES, _BUDGETS, (1, 1, 1, 1, 1)
                    )
        for bad_sizes in ([1], {1}, "sizes", None, 7, range(2)):
            with self.subTest(bad_sizes=bad_sizes):
                with self.assertRaises(TypeError):
                    recommend_merkle_cardinality_weighted(
                        4, bad_sizes, _BUDGETS, (1, 1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_cardinality_weighted(
                4, (), _BUDGETS, (1, 1, 1, 1, 1)
            )
        for bad_budgets in ([None] * 6, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    recommend_merkle_cardinality_weighted(
                        4, _SIZES, bad_budgets, (1, 1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_cardinality_weighted(
                4, _SIZES, (None,) * 6, (1, 1, 1, 1, 1)
            )

    def test_frontier_arguments_screened_before_weights(self):
        # the capacity/groups/budgets rules belong to the frontier and are
        # screened there, exactly like recommend_merkle_cardinality_deployment
        with self.assertRaises(ValueError):
            recommend_merkle_cardinality_weighted(
                0, (), (None,) * 6, (0, 0, 0, 0, 0)
            )
        with self.assertRaises(TypeError):
            recommend_merkle_cardinality_weighted(
                4, [1], _BUDGETS, "not a tuple"
            )

    def test_all_four_parameters_are_required_without_defaults(self):
        sig = inspect.signature(recommend_merkle_cardinality_weighted)
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "group_sizes", "budgets", "weights"],
        )
        for name in ("capacity", "group_sizes", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        for weights in _WEIGHT_SETS:
            first = recommend_merkle_cardinality_weighted(
                4, (1, 2), (None, None, None, 9000, None, None), weights
            )
            second = recommend_merkle_cardinality_weighted(
                4, (1, 2), (None, None, None, 9000, None, None), weights
            )
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

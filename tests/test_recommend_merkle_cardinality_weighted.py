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
_WEIGHTS = (3, 0, 1, 2, 5)


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
    """Rank the frontier by the documented weighted normalized score."""
    frontier = merkle_cardinality_frontier(capacity, group_sizes, budgets)
    columns = tuple(
        [_metrics(mode_cost)[i] for mode_cost in frontier] for i in range(5)
    )
    spans = tuple((min(column), max(column)) for column in columns)

    def key(mode_cost):
        score = Fraction(0)
        for value, weight, (low, high) in zip(_metrics(mode_cost), weights, spans):
            if high > low:
                score += weight * Fraction(value - low, high - low)
        return (score, *_tail(mode_cost))

    return min(frontier, key=key)


class RecommendMerkleCardinalityWeightedTest(unittest.TestCase):
    def test_matches_brute_force_ranking(self):
        workloads = (
            (1, (1,), (None, None, None, None, None, 10**18)),
            (4, _SIZES, (None, None, None, 9000, None, None)),
            (16, (1, 2, 3, 4, 8), (None, None, None, None, None, 10**18)),
            (8, (1, 2, 4), (9000, None, None, None, None, None)),
            (4, (3,), (None, 4000, None, None, None, None)),
            (4, _SIZES, (9000, None, 7000, None, 4, None)),
            (2, (1, 2), (None, None, None, None, None, 6000)),
            (32, (1, 7, 16), (None, None, None, None, 50, None)),
        )
        weight_sets = (
            (1, 1, 1, 1, 1),
            (3, 0, 1, 2, 5),
            (0, 0, 0, 0, 1),
            (10, 0, 0, 0, 0),
            (0, 7, 0, 3, 0),
            (1, 10**6, 1, 1, 1),
        )
        for weights in weight_sets:
            for capacity, group_sizes, budgets in workloads:
                with self.subTest(
                    weights=weights,
                    capacity=capacity,
                    group_sizes=group_sizes,
                    budgets=budgets,
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
        result = recommend_merkle_cardinality_weighted(
            4, _SIZES, _BUDGETS, _WEIGHTS
        )
        self.assertIsInstance(result, MerkleModeCost)
        self.assertIn(result, frontier)

    def test_single_dimension_weight_picks_that_dimension(self):
        frontier = merkle_cardinality_frontier(
            16, (1, 2, 3, 4), (None, None, None, None, None, 10**18)
        )
        result = recommend_merkle_cardinality_weighted(
            16,
            (1, 2, 3, 4),
            (None, None, None, None, None, 10**18),
            (0, 0, 1, 0, 0),
        )
        self.assertEqual(result.cost.total, min(mc.cost.total for mc in frontier))

    def test_weights_only_scale_does_not_change_choice(self):
        budgets = (None, None, None, None, None, 10**18)
        first = recommend_merkle_cardinality_weighted(
            8, (1, 2, 4), budgets, (1, 2, 3, 4, 5)
        )
        second = recommend_merkle_cardinality_weighted(
            8, (1, 2, 4), budgets, (7, 14, 21, 28, 35)
        )
        self.assertEqual(first, second)

    def test_zero_span_dimension_scores_zero(self):
        # a single-member frontier makes every span zero: the only survivor
        # must be picked regardless of the weights, without dividing by zero
        budgets = (None, None, 2243, None, None, 2000)
        frontier = merkle_cardinality_frontier(1, (1,), budgets)
        self.assertEqual(len(frontier), 1)
        result = recommend_merkle_cardinality_weighted(
            1, (1,), budgets, (9, 9, 9, 9, 9)
        )
        self.assertEqual(result, frontier[0])

    def test_tail_tiebreak_is_deterministic(self):
        frontier = merkle_cardinality_frontier(4, _SIZES, _BUDGETS)
        # equal weights on dimensions that span identically leave the tail as
        # the decisive, deterministic ordering
        result = recommend_merkle_cardinality_weighted(
            4, _SIZES, _BUDGETS, (1, 1, 1, 1, 1)
        )
        again = recommend_merkle_cardinality_weighted(
            4, _SIZES, _BUDGETS, (1, 1, 1, 1, 1)
        )
        self.assertEqual(result, again)
        self.assertEqual(result, _expected(4, _SIZES, _BUDGETS, (1, 1, 1, 1, 1)))
        self.assertIn(result, frontier)

    def test_budgets_are_honoured(self):
        budgets = (None, 3000, 6000, 9000, 5, 10**9)
        result = recommend_merkle_cardinality_weighted(
            4, _SIZES, budgets, _WEIGHTS
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
            recommend_merkle_cardinality_weighted(4, _SIZES, _BUDGETS, _WEIGHTS)
            self.assertEqual(calls, 1)
        finally:
            params_module.merkle_cardinality_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_merkle_cardinality_weighted(
                1, (1,), (100, None, None, None, None, None), _WEIGHTS
            )
        with self.assertRaises(ValueError):
            recommend_merkle_cardinality_weighted(
                1, (257,), (None, None, None, None, None, 1), _WEIGHTS
            )

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 0, 0, 0, 0], {1, 2, 3, 4, 5}, "weights", None, 7, range(5)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_cardinality_weighted(4, _SIZES, _BUDGETS, bad)

    def test_invalid_weights_members_raise_value_error(self):
        for bad in (
            (1, 0, 0, 0),
            (1, 0, 0, 0, 0, 0),
            (),
            (0, 0, 0, 0, 0),
            (-1, 0, 0, 0, 0),
            (1, 0, 0, 0, -2),
            (True, 0, 0, 0, 0),
            (0, False, 0, 0, 1),
            (1.0, 0, 0, 0, 0),
            (1, 0, "0", 0, 0),
            (1, 0, None, 0, 0),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_cardinality_weighted(4, _SIZES, _BUDGETS, bad)

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    recommend_merkle_cardinality_weighted(
                        bad_capacity, _SIZES, _BUDGETS, _WEIGHTS
                    )
        for bad_sizes in ([1], {1}, "sizes", None, 7, range(2)):
            with self.subTest(bad_sizes=bad_sizes):
                with self.assertRaises(TypeError):
                    recommend_merkle_cardinality_weighted(
                        4, bad_sizes, _BUDGETS, _WEIGHTS
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_cardinality_weighted(4, (), _BUDGETS, _WEIGHTS)
        for bad_budgets in ([None] * 6, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    recommend_merkle_cardinality_weighted(
                        4, _SIZES, bad_budgets, _WEIGHTS
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_cardinality_weighted(
                4, _SIZES, (None,) * 6, _WEIGHTS
            )

    def test_frontier_arguments_screened_before_weights(self):
        with self.assertRaises(ValueError):
            recommend_merkle_cardinality_weighted(
                0, (), (None,) * 6, (0, 0, 0, 0, 0)
            )
        with self.assertRaises(TypeError):
            recommend_merkle_cardinality_weighted(4, [1], _BUDGETS, "bogus")

    def test_arguments_have_no_defaults(self):
        sig = inspect.signature(recommend_merkle_cardinality_weighted)
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "group_sizes", "budgets", "weights"],
        )
        for name in ("capacity", "group_sizes", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        first = recommend_merkle_cardinality_weighted(
            4, (1, 2), (None, None, None, 9000, None, None), _WEIGHTS
        )
        second = recommend_merkle_cardinality_weighted(
            4, (1, 2), (None, None, None, 9000, None, None), _WEIGHTS
        )
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

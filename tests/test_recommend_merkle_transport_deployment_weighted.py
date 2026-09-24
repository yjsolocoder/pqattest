import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleSigner,
    MerkleTransportDeploymentProfile,
    merkle_transport_deployment_frontier,
    profile,
    recommend_merkle_transport_deployment_weighted,
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


def _expected(capacity, indices, budgets, weights):
    """Rank the frontier by the documented weighted normalised score."""
    frontier = merkle_transport_deployment_frontier(capacity, indices, budgets)
    rows = [_metrics(deployment) for deployment in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(5)
    )

    def key(item):
        deployment, values = item
        score = Fraction(0)
        for value, weight, (low, high) in zip(values, weights, spans):
            if high > low:
                score += weight * Fraction(value - low, high - low)
        return (score, *_tail(deployment))

    return min(zip(frontier, rows), key=key)[0]


_WORKLOADS = (
    (1, (0,), (None, None, None, 10**6)),
    (4, _INDICES, (None, None, None, 9000)),
    (16, (3, 5), (None, None, 8000, None)),
    (8, (0, 1, 6), (9000, None, None, None)),
    (2, (0, 3), (None, 4000, None, None)),
    (32, (1, 7, 16), (None, None, None, 9000)),
    (4, (0, 1, 2, 3), (None, None, None, 10**6)),
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


class RecommendMerkleTransportDeploymentWeightedTest(unittest.TestCase):
    def test_matches_brute_force_ranking(self):
        for capacity, indices, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    indices=indices,
                    budgets=budgets,
                    weights=weights,
                ):
                    result = recommend_merkle_transport_deployment_weighted(
                        capacity, indices, budgets, weights
                    )
                    self.assertEqual(
                        result,
                        _expected(capacity, indices, budgets, weights),
                    )

    def test_returns_deployment_on_the_frontier(self):
        frontier = merkle_transport_deployment_frontier(4, _INDICES, _BUDGETS)
        for weights in _WEIGHT_SETS:
            with self.subTest(weights=weights):
                result = recommend_merkle_transport_deployment_weighted(
                    4, _INDICES, _BUDGETS, weights
                )
                self.assertIsInstance(result, MerkleTransportDeploymentProfile)
                self.assertIn(result, frontier)

    def test_zero_weight_ignores_dimension(self):
        # only the steps weight is positive: the chosen deployment must
        # minimise the (non-normalised, hence normalised) chain steps
        frontier = merkle_transport_deployment_frontier(4, _INDICES, _BUDGETS)
        steps = lambda d: profile(
            "merkle", w=d.config.w, height=d.config.height
        ).steps
        result = recommend_merkle_transport_deployment_weighted(
            4, _INDICES, _BUDGETS, (0, 0, 0, 0, 1)
        )
        self.assertEqual(steps(result), min(steps(d) for d in frontier))

    def test_zero_span_dimension_scores_zero(self):
        # a single-member frontier makes every span zero: the unique member
        # is chosen regardless of the weights, without dividing by zero
        budgets = (None, None, None, 1005)
        frontier = merkle_transport_deployment_frontier(1, (0,), budgets)
        self.assertEqual(len(frontier), 1)
        for weights in ((1, 1, 1, 1, 1), (0, 0, 0, 0, 1), (9, 8, 7, 6, 5)):
            with self.subTest(weights=weights):
                self.assertEqual(
                    recommend_merkle_transport_deployment_weighted(
                        1, (0,), budgets, weights
                    ),
                    frontier[0],
                )

    def test_tie_break_is_documented_tail(self):
        # among the members sharing the smallest weighted score, the chosen
        # one must be the smallest by checkpoint bytes, leaf count, w and
        # height
        for capacity, indices, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    indices=indices,
                    budgets=budgets,
                    weights=weights,
                ):
                    frontier = merkle_transport_deployment_frontier(
                        capacity, indices, budgets
                    )
                    rows = [_metrics(d) for d in frontier]
                    spans = tuple(
                        (min(row[i] for row in rows), max(row[i] for row in rows))
                        for i in range(5)
                    )

                    def score(deployment):
                        total = Fraction(0)
                        for value, weight, (low, high) in zip(
                            _metrics(deployment), weights, spans
                        ):
                            if high > low:
                                total += weight * Fraction(value - low, high - low)
                        return total

                    result = recommend_merkle_transport_deployment_weighted(
                        capacity, indices, budgets, weights
                    )
                    best = score(result)
                    tied = [d for d in frontier if score(d) == best]
                    self.assertEqual(result, min(tied, key=_tail))
                    self.assertIn(result, tied)

    def test_scores_are_exact_rational_no_float(self):
        # the documented arithmetic uses Fraction; spot-check the chosen
        # score against an exact computation over the whole frontier
        capacity, indices, budgets = 16, (3, 5), (None, None, 8000, None)
        weights = (1, 1, 1, 1, 1)
        frontier = merkle_transport_deployment_frontier(capacity, indices, budgets)
        result = recommend_merkle_transport_deployment_weighted(
            capacity, indices, budgets, weights
        )
        rows = [_metrics(d) for d in frontier]
        spans = tuple(
            (min(row[i] for row in rows), max(row[i] for row in rows))
            for i in range(5)
        )

        def score(deployment):
            total = Fraction(0)
            for value, weight, (low, high) in zip(
                _metrics(deployment), weights, spans
            ):
                if high > low:
                    total += weight * Fraction(value - low, high - low)
            return total

        chosen_score = score(result)
        for deployment in frontier:
            self.assertLessEqual(chosen_score, score(deployment))
        self.assertIsInstance(chosen_score, Fraction)

    def test_budgets_are_honoured(self):
        budgets = (9000, 4000, 8000, 9000)
        result = recommend_merkle_transport_deployment_weighted(
            4, _INDICES, budgets, (1, 2, 3, 4, 5)
        )
        self.assertLessEqual(result.config.checkpoint_bytes, 9000)
        self.assertLessEqual(result.batch, 4000)
        self.assertLessEqual(result.multi, 8000)
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
            for weights in _WEIGHT_SETS:
                calls = 0
                recommend_merkle_transport_deployment_weighted(
                    4, _INDICES, _BUDGETS, weights
                )
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_transport_deployment_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted(
                1, (0,), (100, None, None, None), (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted(
                1, (255,), (None, None, None, 1), (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted(
                4, (1,), (None, None, None, 10), (1, 1, 1, 1, 1)
            )

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 1, 1, 1, 1], {1, 2, 3, 4, 5}, "weights", None, 7, range(5)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_transport_deployment_weighted(
                        4, _INDICES, _BUDGETS, bad
                    )

    def test_invalid_weights_members_raise_value_error(self):
        for bad in (
            (),
            (1, 1, 1, 1),
            (1, 1, 1, 1, 1, 1),
            (0, 0, 0, 0, 0),
            (1, -1, 1, 1, 1),
            (-1, 1, 1, 1, 1),
            (1, 1, -1, 1, 1),
            (1, 1, 1, -1, 1),
            (True, 1, 1, 1, 1),
            (1, 1, True, 1, 1),
            (1, 1, 1, True, 1),
            (1, 1, 1, 1, False),
            (1.0, 1, 1, 1, 1),
            (1, "1", 1, 1, 1),
            (1, None, 1, 1, 1),
            (1, 1, 1.5, 1, 1),
            (1, 1, 1, "x", 1),
            (1, 1, 1, 1, 1.5),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_deployment_weighted(
                        4, _INDICES, _BUDGETS, bad
                    )

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in (
            (True, 0, 0, 0, 0),
            (0, 0, True, 0, 0),
            (0, 0, 0, True, 0),
            (0, 0, 0, 0, True),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_deployment_weighted(
                        4, _INDICES, _BUDGETS, bad
                    )

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_deployment_weighted(
                        bad_capacity, _INDICES, _BUDGETS, (1, 1, 1, 1, 1)
                    )
        for bad_indices in ([1, 2], {1, 2}, "indices", None, 7, range(2)):
            with self.subTest(bad_indices=bad_indices):
                with self.assertRaises(TypeError):
                    recommend_merkle_transport_deployment_weighted(
                        4, bad_indices, _BUDGETS, (1, 1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted(
                4, (), _BUDGETS, (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted(
                4, (2, 1), _BUDGETS, (1, 1, 1, 1, 1)
            )
        for bad_budgets in ([None] * 4, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    recommend_merkle_transport_deployment_weighted(
                        4, _INDICES, bad_budgets, (1, 1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted(
                4, _INDICES, (None,) * 4, (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted(
                4, _INDICES, (None,) * 3, (1, 1, 1, 1, 1)
            )

    def test_frontier_arguments_screened_before_weights(self):
        # the capacity/indices/budgets rules belong to the frontier and are
        # screened there, before the weights are looked at
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment_weighted(
                0, (), (None,) * 4, (0, 0, 0, 0, 0)
            )
        with self.assertRaises(TypeError):
            recommend_merkle_transport_deployment_weighted(
                4, [1, 2], _BUDGETS, "not a tuple"
            )

    def test_all_four_parameters_are_required_without_defaults(self):
        sig = inspect.signature(recommend_merkle_transport_deployment_weighted)
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "indices", "budgets", "weights"],
        )
        for name in ("capacity", "indices", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        for weights in _WEIGHT_SETS:
            first = recommend_merkle_transport_deployment_weighted(
                4, (1, 2), (None, None, None, 9000), weights
            )
            second = recommend_merkle_transport_deployment_weighted(
                4, (1, 2), (None, None, None, 9000), weights
            )
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

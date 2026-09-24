import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleSigner,
    MerkleStorageProfile,
    merkle_deployment_frontier,
    profile,
    recommend_merkle_deployment_weighted,
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


def _expected(capacity, budgets, weights):
    """Rank the deployment frontier by the documented weighted score."""
    frontier = merkle_deployment_frontier(capacity, budgets)
    rows = [_metrics(storage) for storage in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(4)
    )
    total = sum(weights)

    def key(item):
        storage, values = item
        score = Fraction(0)
        for value, weight, (low, high) in zip(values, weights, spans):
            if high > low:
                score += weight * Fraction(value - low, high - low)
        return (score / total, *_tail(storage))

    return min(zip(frontier, rows), key=key)[0]


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

_WEIGHT_SETS = (
    (1, 1, 1, 1),
    (10, 0, 0, 0),
    (0, 0, 0, 1),
    (1, 2, 3, 4),
    (0, 1, 0, 1),
    (10**9, 1, 1, 1),
    (3, 0, 7, 2),
)


class RecommendMerkleDeploymentWeightedTest(unittest.TestCase):
    def test_matches_brute_force_ranking(self):
        for capacity, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    budgets=budgets,
                    weights=weights,
                ):
                    result = recommend_merkle_deployment_weighted(
                        capacity, budgets, weights
                    )
                    self.assertEqual(
                        result,
                        _expected(capacity, budgets, weights),
                    )

    def test_returns_storage_profile_on_the_frontier(self):
        frontier = merkle_deployment_frontier(16, _BUDGETS)
        for weights in _WEIGHT_SETS:
            with self.subTest(weights=weights):
                result = recommend_merkle_deployment_weighted(
                    16, _BUDGETS, weights
                )
                self.assertIsInstance(result, MerkleStorageProfile)
                self.assertIn(result, frontier)

    def test_each_single_positive_weight_minimises_its_dimension(self):
        # a lone positive weight minimises that (normalised) dimension
        frontier = merkle_deployment_frontier(16, _BUDGETS)
        for dimension in range(4):
            weights = tuple(1 if i == dimension else 0 for i in range(4))
            with self.subTest(weights=weights):
                result = recommend_merkle_deployment_weighted(
                    16, _BUDGETS, weights
                )
                self.assertEqual(
                    _metrics(result)[dimension],
                    min(_metrics(storage)[dimension] for storage in frontier),
                )

    def test_weighted_sum_is_divided_by_weight_total(self):
        # multiplying every weight by the same factor must not change the
        # ranking because the score divides by the weight total
        for capacity, budgets in _WORKLOADS:
            base = recommend_merkle_deployment_weighted(
                capacity, budgets, (1, 2, 3, 4)
            )
            scaled = recommend_merkle_deployment_weighted(
                capacity, budgets, (7, 14, 21, 28)
            )
            with self.subTest(capacity=capacity, budgets=budgets):
                self.assertEqual(base, scaled)

    def test_zero_span_dimensions_score_zero(self):
        # a single-member frontier makes every span zero: the unique member
        # is chosen regardless of the weights, without dividing by zero
        budgets = (None, None, None, 1005)
        frontier = merkle_deployment_frontier(1, budgets)
        self.assertEqual(len(frontier), 1)
        for weights in (
            (1, 1, 1, 1),
            (0, 0, 0, 1),
            (9, 8, 7, 6),
            (10**12, 0, 0, 0),
        ):
            with self.subTest(weights=weights):
                self.assertEqual(
                    recommend_merkle_deployment_weighted(1, budgets, weights),
                    frontier[0],
                )

    def test_tie_break_is_documented_tail(self):
        # among the members sharing the smallest weighted score, the chosen
        # one must be the smallest by checkpoint bytes, leaf count, w and
        # height
        for capacity, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    budgets=budgets,
                    weights=weights,
                ):
                    frontier = merkle_deployment_frontier(capacity, budgets)
                    rows = [_metrics(storage) for storage in frontier]
                    spans = tuple(
                        (min(row[i] for row in rows), max(row[i] for row in rows))
                        for i in range(4)
                    )
                    total = sum(weights)

                    def score(storage):
                        weighted = Fraction(0)
                        for value, weight, (low, high) in zip(
                            _metrics(storage), weights, spans
                        ):
                            if high > low:
                                weighted += weight * Fraction(value - low, high - low)
                        return weighted / total

                    result = recommend_merkle_deployment_weighted(
                        capacity, budgets, weights
                    )
                    best = score(result)
                    tied = [storage for storage in frontier if score(storage) == best]
                    self.assertEqual(result, min(tied, key=_tail))
                    self.assertIn(result, tied)

    def test_scores_are_exact_rational_no_float(self):
        capacity, budgets = 16, _BUDGETS
        weights = (1, 2, 3, 4)
        frontier = merkle_deployment_frontier(capacity, budgets)
        result = recommend_merkle_deployment_weighted(capacity, budgets, weights)
        rows = [_metrics(storage) for storage in frontier]
        spans = tuple(
            (min(row[i] for row in rows), max(row[i] for row in rows))
            for i in range(4)
        )
        total = sum(weights)

        def score(storage):
            weighted = Fraction(0)
            for value, weight, (low, high) in zip(
                _metrics(storage), weights, spans
            ):
                if high > low:
                    weighted += weight * Fraction(value - low, high - low)
            value = weighted / total
            self.assertIsInstance(value, Fraction)
            return value

        chosen_score = score(result)
        for storage in frontier:
            self.assertLessEqual(chosen_score, score(storage))

    def test_budgets_are_honoured(self):
        budgets = (9000, 1300, 1400, 9000)
        result = recommend_merkle_deployment_weighted(
            4, budgets, (1, 2, 3, 4)
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
            for weights in _WEIGHT_SETS:
                calls = 0
                recommend_merkle_deployment_weighted(16, _BUDGETS, weights)
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_deployment_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted(
                1, (100, None, None, None), (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted(
                256, (None, 1000, None, None), (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted(
                4, (None, None, None, 10), (1, 1, 1, 1)
            )

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 1, 1, 1], {1, 2, 3, 4}, "weights", None, 7, range(4)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_deployment_weighted(16, _BUDGETS, bad)

    def test_non_integer_weight_raises_type_error(self):
        for bad in (
            (1.0, 1, 1, 1),
            (1, "1", 1, 1),
            (1, None, 1, 1),
            (1, 1, 1, 1.5),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_deployment_weighted(16, _BUDGETS, bad)

    def test_invalid_weights_members_raise_value_error(self):
        for bad in (
            (),
            (1, 1, 1),
            (1, 1, 1, 1, 1),
            (0, 0, 0, 0),
            (1, -1, 1, 1),
            (-1, 1, 1, 1),
            (True, 1, 1, 1),
            (1, 1, 1, False),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment_weighted(16, _BUDGETS, bad)

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in ((True, 0, 0, 0), (0, 0, 0, True)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment_weighted(16, _BUDGETS, bad)

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment_weighted(
                        bad_capacity, _BUDGETS, (1, 1, 1, 1)
                    )
        for bad_budgets in ([None] * 4, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    recommend_merkle_deployment_weighted(
                        16, bad_budgets, (1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted(
                16, (None,) * 4, (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted(
                16, (None,) * 3, (1, 1, 1, 1)
            )
        for bad_member in (0, -1, True, 1.5, "100"):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment_weighted(
                        16, (None, bad_member, None, None), (1, 1, 1, 1)
                    )

    def test_frontier_arguments_screened_before_weights(self):
        # the capacity/budgets rules belong to the frontier and are
        # screened there before weights is inspected
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted(
                0, (None,) * 4, (0, 0, 0, 0)
            )
        with self.assertRaises(TypeError):
            recommend_merkle_deployment_weighted(
                16, [None, None, None, 9000], "not a tuple"
            )

    def test_all_three_parameters_are_required_without_defaults(self):
        sig = inspect.signature(recommend_merkle_deployment_weighted)
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "budgets", "weights"],
        )
        for name in ("capacity", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_repeated_calls_are_deterministic(self):
        signer = MerkleSigner(w=4, height=2)
        for weights in _WEIGHT_SETS:
            first = recommend_merkle_deployment_weighted(16, _BUDGETS, weights)
            second = recommend_merkle_deployment_weighted(16, _BUDGETS, weights)
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

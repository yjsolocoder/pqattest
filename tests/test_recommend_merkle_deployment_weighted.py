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
    """Rank the frontier by the documented weighted normalised score."""
    frontier = merkle_deployment_frontier(capacity, budgets)
    rows = [_metrics(storage) for storage in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(4)
    )
    weight_total = sum(weights)

    def key(item):
        storage, values = item
        score = Fraction(0)
        for value, weight, (low, high) in zip(values, weights, spans):
            if high > low:
                score += weight * Fraction(value - low, high - low)
        score /= weight_total
        return (score, *_tail(storage))

    return min(zip(frontier, rows), key=key)[0]


_CASES = (
    (1, (None, None, None, 1005)),
    (4, (None, None, None, 9000)),
    (16, (None, 1300, None, None)),
    (8, (9000, None, None, None)),
    (2, (None, 4000, None, None)),
    (32, (None, None, None, 9000)),
    (4, (None, None, 8000, None)),
)

_WEIGHT_SETS = (
    (1, 1, 1, 1),
    (10, 0, 0, 0),
    (0, 0, 0, 1),
    (1, 2, 3, 4),
    (0, 1, 1, 0),
    (10**9, 1, 1, 1),
    (3, 0, 7, 0),
)


class RecommendMerkleDeploymentWeightedTest(unittest.TestCase):
    def test_matches_brute_force_ranking(self):
        for capacity, budgets in _CASES:
            for weights in _WEIGHT_SETS:
                with self.subTest(capacity=capacity, budgets=budgets, weights=weights):
                    result = recommend_merkle_deployment_weighted(
                        capacity, budgets, weights
                    )
                    self.assertEqual(result, _expected(capacity, budgets, weights))

    def test_returns_member_of_the_frontier(self):
        frontier = merkle_deployment_frontier(4, _BUDGETS)
        for weights in _WEIGHT_SETS:
            with self.subTest(weights=weights):
                result = recommend_merkle_deployment_weighted(4, _BUDGETS, weights)
                self.assertIsInstance(result, MerkleStorageProfile)
                self.assertIn(result, frontier)

    def test_zero_weight_ignores_dimension(self):
        # only the steps weight is positive: the chosen deployment must
        # minimise the (non-normalised, hence normalised) chain steps
        frontier = merkle_deployment_frontier(4, _BUDGETS)
        steps = lambda s: profile("merkle", w=s.w, height=s.height).steps
        result = recommend_merkle_deployment_weighted(
            4, _BUDGETS, (0, 0, 0, 1)
        )
        self.assertEqual(steps(result), min(steps(s) for s in frontier))

    def test_only_checkpoint_weight_minimises_checkpoint(self):
        frontier = merkle_deployment_frontier(16, (None, 1300, None, None))
        result = recommend_merkle_deployment_weighted(
            16, (None, 1300, None, None), (1, 0, 0, 0)
        )
        self.assertEqual(
            result.checkpoint_bytes,
            min(s.checkpoint_bytes for s in frontier),
        )

    def test_zero_span_dimensions_score_zero(self):
        # a single-member frontier makes every span zero: the unique member
        # is chosen regardless of the weights, without dividing by zero
        budgets = (None, None, None, 1005)
        frontier = merkle_deployment_frontier(1, budgets)
        self.assertEqual(len(frontier), 1)
        for weights in ((1, 1, 1, 1), (0, 0, 0, 1), (9, 8, 7, 6)):
            with self.subTest(weights=weights):
                self.assertEqual(
                    recommend_merkle_deployment_weighted(1, budgets, weights),
                    frontier[0],
                )

    def test_tie_break_is_documented_tail(self):
        # among the members sharing the smallest weighted score, the chosen
        # one must be the smallest by checkpoint bytes, leaf count, w and
        # height
        for capacity, budgets in _CASES:
            for weights in _WEIGHT_SETS:
                with self.subTest(capacity=capacity, budgets=budgets, weights=weights):
                    frontier = merkle_deployment_frontier(capacity, budgets)
                    rows = [_metrics(s) for s in frontier]
                    spans = tuple(
                        (min(row[i] for row in rows), max(row[i] for row in rows))
                        for i in range(4)
                    )
                    weight_total = sum(weights)

                    def score(storage):
                        total = Fraction(0)
                        for value, weight, (low, high) in zip(
                            _metrics(storage), weights, spans
                        ):
                            if high > low:
                                total += weight * Fraction(value - low, high - low)
                        return total / weight_total

                    result = recommend_merkle_deployment_weighted(
                        capacity, budgets, weights
                    )
                    best = score(result)
                    tied = [s for s in frontier if score(s) == best]
                    self.assertEqual(result, min(tied, key=_tail))
                    self.assertIn(result, tied)

    def test_scores_are_exact_rational_no_float(self):
        # the documented arithmetic uses Fraction; spot-check the chosen
        # score against an exact computation over the whole frontier
        capacity, budgets, weights = 16, (None, 1300, None, None), (1, 1, 1, 1)
        frontier = merkle_deployment_frontier(capacity, budgets)
        result = recommend_merkle_deployment_weighted(capacity, budgets, weights)
        rows = [_metrics(s) for s in frontier]
        spans = tuple(
            (min(row[i] for row in rows), max(row[i] for row in rows))
            for i in range(4)
        )
        weight_total = sum(weights)

        def score(storage):
            total = Fraction(0)
            for value, weight, (low, high) in zip(
                _metrics(storage), weights, spans
            ):
                if high > low:
                    total += weight * Fraction(value - low, high - low)
            return total / weight_total

        chosen_score = score(result)
        for storage in frontier:
            self.assertLessEqual(chosen_score, score(storage))
        self.assertIsInstance(chosen_score, Fraction)

    def test_weighted_sum_is_divided_by_weight_total(self):
        # unequal weight totals with the same per-dimension ratios must not
        # change the winner, but scaling a subset of weights may; here the
        # division by the total is exercised against the exact score
        capacity, budgets = 4, _BUDGETS
        frontier = merkle_deployment_frontier(capacity, budgets)
        rows = [_metrics(s) for s in frontier]
        spans = tuple(
            (min(row[i] for row in rows), max(row[i] for row in rows))
            for i in range(4)
        )

        def score(storage, weights):
            total = Fraction(0)
            for value, weight, (low, high) in zip(
                _metrics(storage), weights, spans
            ):
                if high > low:
                    total += weight * Fraction(value - low, high - low)
            return total / sum(weights)

        for weights in _WEIGHT_SETS:
            result = recommend_merkle_deployment_weighted(capacity, budgets, weights)
            self.assertEqual(score(result, weights), min(score(s, weights) for s in frontier))

    def test_budgets_are_honoured(self):
        budgets = (9000, 4000, 8000, 9000)
        result = recommend_merkle_deployment_weighted(
            4, budgets, (1, 2, 3, 4)
        )
        self.assertLessEqual(result.checkpoint_bytes, 9000)
        self.assertLessEqual(result.signature_wire_bytes, 4000)
        self.assertLessEqual(result.proof_wire_bytes, 8000)
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
                recommend_merkle_deployment_weighted(4, _BUDGETS, weights)
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
                4, (None, None, None, 10), (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted(
                256, (1000, 1000, 1000, None), (1, 1, 1, 1)
            )

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 1, 1, 1], {1, 2, 3, 4}, "weights", None, 7, range(4)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_deployment_weighted(4, _BUDGETS, bad)

    def test_non_integer_weight_member_raises_type_error(self):
        for bad in (
            (1.0, 1, 1, 1),
            (1, "1", 1, 1),
            (1, None, 1, 1),
            (1, 1, 1, 1.5),
            (1.5, 0, 0, 0),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_deployment_weighted(4, _BUDGETS, bad)

    def test_invalid_weights_members_raise_value_error(self):
        for bad in (
            (),
            (1, 1, 1),
            (1, 1, 1, 1, 1),
            (0, 0, 0, 0),
            (1, -1, 1, 1),
            (-1, 1, 1, 1),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment_weighted(4, _BUDGETS, bad)

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in (
            (True, 1, 1, 1),
            (1, 1, 1, False),
            (True, 0, 0, 0),
            (0, 0, 0, True),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment_weighted(4, _BUDGETS, bad)

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
                        4, bad_budgets, (1, 1, 1, 1)
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted(
                4, (None,) * 4, (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted(
                4, (None,) * 3, (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted(
                4, (0, None, None, None), (1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted(
                4, (True, None, None, None), (1, 1, 1, 1)
            )

    def test_frontier_arguments_screened_before_weights(self):
        # the capacity/budgets rules belong to the frontier and are
        # screened there, before the weights are looked at
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted(
                0, (None,) * 4, (0, 0, 0, 0)
            )
        with self.assertRaises(TypeError):
            recommend_merkle_deployment_weighted(4, [None] * 4, "not a tuple")
        with self.assertRaises(ValueError):
            recommend_merkle_deployment_weighted(
                1, (100, None, None, None), "not a tuple"
            )

    def test_all_three_parameters_are_required_without_defaults(self):
        sig = inspect.signature(recommend_merkle_deployment_weighted)
        self.assertEqual(list(sig.parameters), ["capacity", "budgets", "weights"])
        for name in ("capacity", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_pure_deterministic_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        for weights in _WEIGHT_SETS:
            first = recommend_merkle_deployment_weighted(4, _BUDGETS, weights)
            second = recommend_merkle_deployment_weighted(4, _BUDGETS, weights)
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

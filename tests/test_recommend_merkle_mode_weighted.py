import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleSigner,
    MerkleTransportWorkloadProfile,
    merkle_mode_frontier,
    merkle_transport_profile,
    profile,
    recommend_merkle_mode_weighted,
)

_GROUPS = ((0,), (2, 3))
_BUDGETS = (None, None, None, 9000, None)


def _carried_nodes(workload, groups):
    return sum(
        merkle_transport_profile(workload.config.w, workload.config.height, group)[0]
        for mode, group in zip(workload.modes, groups)
        if mode == "multiproof"
    )


def _metrics(workload, groups):
    return (
        workload.config.checkpoint_bytes,
        max(workload.sizes),
        workload.total,
        profile(
            "merkle", w=workload.config.w, height=workload.config.height
        ).steps,
        _carried_nodes(workload, groups),
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


def _expected(capacity, groups, budgets, weights):
    """Rank the mode frontier by the documented weighted normalised score."""
    frontier = merkle_mode_frontier(capacity, groups, budgets)
    rows = [_metrics(workload, groups) for workload in frontier]
    spans = tuple(
        (min(row[i] for row in rows), max(row[i] for row in rows))
        for i in range(5)
    )
    total = sum(weights)

    def key(item):
        workload, values = item
        score = Fraction(0)
        for value, weight, (low, high) in zip(values, weights, spans):
            if high > low:
                score += weight * Fraction(value - low, high - low)
        return (score / total, *_tail(workload))

    return min(zip(frontier, rows), key=key)[0]


_WORKLOADS = (
    (1, ((0,),), (None, None, None, None, 10**18)),
    (16, _GROUPS, _BUDGETS),
    (16, ((1,), (2,), (3,), (4,), (8,)), (None, None, None, None, 10**18)),
    (8, ((0,), (1, 2), (4,)), (9000, None, None, None, None)),
    (4, ((2,),), (None, 4000, None, None, None)),
    (4, ((0,), (1,)), (9000, None, 7000, None, 4)),
    (2, ((0,), (1,)), (None, None, None, None, 6000)),
    (32, ((0,), (6, 7), (15, 16)), (None, None, None, None, 50)),
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


class RecommendMerkleModeWeightedTest(unittest.TestCase):
    def test_matches_brute_force_ranking(self):
        for capacity, groups, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    weights=weights,
                ):
                    result = recommend_merkle_mode_weighted(
                        capacity, groups, budgets, weights
                    )
                    self.assertEqual(
                        result,
                        _expected(capacity, groups, budgets, weights),
                    )

    def test_returns_profile_on_the_frontier(self):
        frontier = merkle_mode_frontier(16, _GROUPS, _BUDGETS)
        for weights in _WEIGHT_SETS:
            with self.subTest(weights=weights):
                result = recommend_merkle_mode_weighted(
                    16, _GROUPS, _BUDGETS, weights
                )
                self.assertIsInstance(result, MerkleTransportWorkloadProfile)
                self.assertIn(result, frontier)

    def test_zero_weight_ignores_dimension(self):
        # only the steps weight is positive: the chosen plan must minimise
        # the (non-normalised, hence normalised) chain steps
        frontier = merkle_mode_frontier(16, _GROUPS, _BUDGETS)
        steps = lambda w: profile(
            "merkle", w=w.config.w, height=w.config.height
        ).steps
        result = recommend_merkle_mode_weighted(
            16, _GROUPS, _BUDGETS, (0, 0, 0, 1, 0)
        )
        self.assertEqual(steps(result), min(steps(workload) for workload in frontier))

    def test_nodes_weight_uses_multiproof_groups_only(self):
        groups = ((0,), (1, 2), (4,))
        budgets = (9000, None, None, None, None)
        result = recommend_merkle_mode_weighted(
            8, groups, budgets, (0, 0, 0, 0, 1)
        )
        self.assertEqual(
            _carried_nodes(result, groups),
            sum(
                merkle_transport_profile(
                    result.config.w, result.config.height, group
                )[0]
                for mode, group in zip(result.modes, groups)
                if mode == "multiproof"
            ),
        )
        frontier = merkle_mode_frontier(8, groups, budgets)
        self.assertEqual(
            _carried_nodes(result, groups),
            min(_carried_nodes(workload, groups) for workload in frontier),
        )

    def test_zero_span_dimensions_score_zero(self):
        # a single-member frontier makes every span zero: the unique member
        # is chosen regardless of the weights, without dividing by zero
        budgets = (None, 1190, None, None, None)
        frontier = merkle_mode_frontier(1, ((0,),), budgets)
        self.assertEqual(len(frontier), 1)
        for weights in (
            (1, 1, 1, 1, 1),
            (0, 0, 0, 0, 1),
            (9, 8, 7, 6, 5),
        ):
            with self.subTest(weights=weights):
                self.assertEqual(
                    recommend_merkle_mode_weighted(
                        1, ((0,),), budgets, weights
                    ),
                    frontier[0],
                )

    def test_tie_break_is_documented_tail(self):
        # among the members sharing the smallest weighted score, the chosen
        # one must be the smallest by checkpoint bytes, leaf count, w,
        # height and the modes tuple
        for capacity, groups, budgets in _WORKLOADS:
            for weights in _WEIGHT_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    weights=weights,
                ):
                    frontier = merkle_mode_frontier(capacity, groups, budgets)
                    rows = [_metrics(workload, groups) for workload in frontier]
                    spans = tuple(
                        (min(row[i] for row in rows), max(row[i] for row in rows))
                        for i in range(5)
                    )
                    total = sum(weights)

                    def score(workload):
                        weighted = Fraction(0)
                        for value, weight, (low, high) in zip(
                            _metrics(workload, groups), weights, spans
                        ):
                            if high > low:
                                weighted += weight * Fraction(value - low, high - low)
                        return weighted / total

                    result = recommend_merkle_mode_weighted(
                        capacity, groups, budgets, weights
                    )
                    best = score(result)
                    tied = [workload for workload in frontier if score(workload) == best]
                    self.assertEqual(result, min(tied, key=_tail))
                    self.assertIn(result, tied)

    def test_scores_are_exact_rational_no_float(self):
        capacity, groups, budgets = 16, _GROUPS, _BUDGETS
        weights = (1, 2, 3, 4, 5)
        frontier = merkle_mode_frontier(capacity, groups, budgets)
        result = recommend_merkle_mode_weighted(capacity, groups, budgets, weights)
        rows = [_metrics(workload, groups) for workload in frontier]
        spans = tuple(
            (min(row[i] for row in rows), max(row[i] for row in rows))
            for i in range(5)
        )
        total = sum(weights)

        def score(workload):
            weighted = Fraction(0)
            for value, weight, (low, high) in zip(
                _metrics(workload, groups), weights, spans
            ):
                if high > low:
                    weighted += weight * Fraction(value - low, high - low)
            value = weighted / total
            self.assertIsInstance(value, Fraction)
            return value

        chosen_score = score(result)
        for workload in frontier:
            self.assertLessEqual(chosen_score, score(workload))

    def test_budgets_are_honoured(self):
        capacity, groups = 4, ((0,), (1,))
        budgets = (9000, 3000, 6000, 9000, 5)
        result = recommend_merkle_mode_weighted(
            capacity, groups, budgets, (1, 2, 3, 4, 5)
        )
        self.assertLessEqual(result.config.checkpoint_bytes, 9000)
        self.assertTrue(all(size <= 3000 for size in result.sizes))
        self.assertLessEqual(result.total, 6000)
        self.assertLessEqual(
            profile(
                "merkle",
                w=result.config.w,
                height=result.config.height,
            ).steps,
            9000,
        )
        self.assertLessEqual(_carried_nodes(result, groups), 5)

    def test_frontier_called_once_no_duplicate_enumeration(self):
        calls = 0
        original = merkle_mode_frontier

        import pqattest.params as params_module

        def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)

        params_module.merkle_mode_frontier = counting
        try:
            for weights in _WEIGHT_SETS:
                calls = 0
                recommend_merkle_mode_weighted(16, _GROUPS, _BUDGETS, weights)
                self.assertEqual(calls, 1)
        finally:
            params_module.merkle_mode_frontier = original

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_merkle_mode_weighted(
                1,
                ((0,),),
                (100, None, None, None, None),
                (1, 1, 1, 1, 1),
            )
        with self.assertRaises(ValueError):
            recommend_merkle_mode_weighted(
                4,
                ((0,),),
                (None, None, 10, None, None),
                (1, 1, 1, 1, 1),
            )

    def test_invalid_weights_container_raises_type_error(self):
        for bad in ([1, 1, 1, 1, 1], {1, 2, 3, 4, 5}, "weights", None, 7, range(5)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_mode_weighted(16, _GROUPS, _BUDGETS, bad)

    def test_non_integer_weight_raises_type_error(self):
        base_bad = (
            (1.0, 1, 1, 1, 1),
            (1, "1", 1, 1, 1),
            (1, None, 1, 1, 1),
            (1, 1, 1, 1, 1.5),
        )
        for bad in base_bad:
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_mode_weighted(16, _GROUPS, _BUDGETS, bad)
        # a non-integer member is rejected at every position, not just the
        # first one the validator inspects
        good = (1, 1, 1, 1, 1)
        for position in range(5):
            for replacement in (1.0, "1", None, 1.5):
                bad = tuple(
                    replacement if index == position else good[index]
                    for index in range(5)
                )
                with self.subTest(position=position, replacement=replacement):
                    with self.assertRaises(TypeError):
                        recommend_merkle_mode_weighted(16, _GROUPS, _BUDGETS, bad)

    def test_invalid_weights_members_raise_value_error(self):
        base_bad = (
            (),
            (1, 1, 1, 1),
            (1, 1, 1, 1, 1, 1),
            (0, 0, 0, 0, 0),
        )
        for bad in base_bad:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_mode_weighted(16, _GROUPS, _BUDGETS, bad)
        # a boolean or negative member is rejected at every position, not
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
                        recommend_merkle_mode_weighted(16, _GROUPS, _BUDGETS, bad)

    def test_boolean_weights_are_value_error_even_though_int(self):
        for bad in ((True, 0, 0, 0, 0), (0, 0, 0, 0, True)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_mode_weighted(16, _GROUPS, _BUDGETS, bad)

    def test_frontier_arguments_validated_like_frontier(self):
        for bad_capacity in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad_capacity=bad_capacity):
                with self.assertRaises(ValueError):
                    recommend_merkle_mode_weighted(
                        bad_capacity,
                        _GROUPS,
                        _BUDGETS,
                        (1, 1, 1, 1, 1),
                    )
        for bad_groups in ([(0, 1)], {(0, 1)}, "groups", None, 7, range(2)):
            with self.subTest(bad_groups=bad_groups):
                with self.assertRaises(TypeError):
                    recommend_merkle_mode_weighted(
                        16,
                        bad_groups,
                        _BUDGETS,
                        (1, 1, 1, 1, 1),
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_mode_weighted(
                16, (), _BUDGETS, (1, 1, 1, 1, 1)
            )
        for bad_budgets in ([None] * 5, "budget", None, 7, {1, 2}):
            with self.subTest(bad_budgets=bad_budgets):
                with self.assertRaises(TypeError):
                    recommend_merkle_mode_weighted(
                        16,
                        _GROUPS,
                        bad_budgets,
                        (1, 1, 1, 1, 1),
                    )
        with self.assertRaises(ValueError):
            recommend_merkle_mode_weighted(
                16, _GROUPS, (None,) * 5, (1, 1, 1, 1, 1)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_mode_weighted(
                16, _GROUPS, (None,) * 4, (1, 1, 1, 1, 1)
            )

    def test_frontier_arguments_screened_before_weights(self):
        # the capacity/groups/budgets rules belong to the frontier and are
        # screened there before weights is inspected
        with self.assertRaises(ValueError):
            recommend_merkle_mode_weighted(
                0, (), (None,) * 5, (0, 0, 0, 0, 0)
            )
        with self.assertRaises(TypeError):
            recommend_merkle_mode_weighted(
                16, [(0, 1)], _BUDGETS, "not a tuple"
            )

    def test_all_four_parameters_are_required_without_defaults(self):
        sig = inspect.signature(recommend_merkle_mode_weighted)
        self.assertEqual(
            list(sig.parameters),
            ["capacity", "groups", "budgets", "weights"],
        )
        for name in ("capacity", "groups", "budgets", "weights"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        for weights in _WEIGHT_SETS:
            first = recommend_merkle_mode_weighted(
                16,
                _GROUPS,
                (None, None, None, 9000, None),
                weights,
            )
            second = recommend_merkle_mode_weighted(
                16,
                _GROUPS,
                (None, None, None, 9000, None),
                weights,
            )
            self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

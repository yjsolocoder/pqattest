import inspect
import unittest

from pqattest import Params, profile, scheme_frontier


def _all_candidates(capacity):
    """Enumerate every scheme/parameter combination profile() accepts."""
    candidates = []
    if capacity == 1:
        candidates.append(profile("lamport"))
        for w in (4, 8):
            candidates.append(profile("wots", w=w))
    for w in (4, 8):
        for height in range(1, 9):
            candidate = profile("merkle", w=w, height=height)
            if candidate.capacity >= capacity:
                candidates.append(candidate)
    return candidates


def _brute_force(capacity, budgets):
    """Replicate feasible filtering, dominance pruning, dedupe and sorting."""
    signature_limit, steps_limit = budgets
    feasible = []
    for candidate in _all_candidates(capacity):
        if signature_limit is not None and candidate.sig_bytes > signature_limit:
            continue
        if steps_limit is not None and candidate.steps > steps_limit:
            continue
        feasible.append(candidate)
    if not feasible:
        raise ValueError("no feasible candidate")

    def dominates(a, b):
        no_worse = a.sig_bytes <= b.sig_bytes and a.steps <= b.steps
        strictly_better = a.sig_bytes < b.sig_bytes or a.steps < b.steps
        return no_worse and strictly_better

    non_dominated = [
        candidate
        for candidate in feasible
        if not any(dominates(other, candidate) for other in feasible)
    ]

    unique = []
    seen = set()
    for candidate in non_dominated:
        if candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)

    unique.sort(
        key=lambda candidate: (
            candidate.steps,
            candidate.sig_bytes,
            candidate.capacity - capacity,
            candidate.scheme,
            candidate.w is not None,
            candidate.w,
            candidate.height is not None,
            candidate.height,
        )
    )
    return tuple(unique)


_BUDGET_CASES = (
    (None, 10**9),
    (10**9, None),
    (2048, None),
    (2200, None),
    (8191, 1005),
    (None, 1005),
    (None, 1),
    (None, 8670),
    (2300, 9000),
    (1088, 8670),
    (8192, 10**9),
    (1200, None),
    (None, 2000),
)


class SchemeFrontierTest(unittest.TestCase):
    def test_matches_brute_force_for_every_capacity(self):
        for capacity in range(1, 257):
            for budgets in _BUDGET_CASES:
                with self.subTest(capacity=capacity, budgets=budgets):
                    try:
                        expected = _brute_force(capacity, budgets)
                    except ValueError:
                        with self.assertRaises(ValueError):
                            scheme_frontier(capacity, budgets)
                        continue
                    result = scheme_frontier(capacity, budgets)
                    self.assertEqual(result, expected)
                    self.assertIsInstance(result, tuple)
                    self.assertTrue(result)
                    for member in result:
                        self.assertIsInstance(member, Params)
                        self.assertEqual(
                            member,
                            profile(
                                member.scheme, w=member.w, height=member.height
                            ),
                        )

    def test_one_signature_keeps_both_trade_off_ends(self):
        result = scheme_frontier(1, (None, 10**9))
        # speed end: zero chain steps (lamport); size end: shortest signature
        self.assertEqual(result[0], profile("lamport"))
        self.assertEqual(result[-1], profile("wots", w=8))
        schemes = {(member.scheme, member.w) for member in result}
        self.assertIn(("lamport", None), schemes)
        self.assertIn(("wots", 8), schemes)
        # wots w=4 is the intermediate trade-off point
        self.assertIn(profile("wots", w=4), result)
        # every dominating merkle configuration is pruned
        self.assertTrue(all(member.scheme != "merkle" for member in result))

    def test_one_signature_loose_size_budget_same_frontier(self):
        self.assertEqual(
            scheme_frontier(1, (10**9, None)),
            scheme_frontier(1, (None, 10**9)),
        )

    def test_multiple_signatures_exclude_one_time_schemes(self):
        for capacity in (2, 3, 16, 256):
            with self.subTest(capacity=capacity):
                result = scheme_frontier(capacity, (None, 10**9))
                self.assertTrue(
                    all(member.scheme == "merkle" for member in result)
                )
                self.assertTrue(
                    all(member.capacity >= capacity for member in result)
                )

    def test_capacity_two_frontier_has_two_pareto_points(self):
        result = scheme_frontier(2, (None, 10**9))
        self.assertEqual(
            result,
            (
                profile("merkle", w=4, height=1),
                profile("merkle", w=8, height=1),
            ),
        )

    def test_sorted_by_steps_then_size(self):
        result = scheme_frontier(1, (None, 10**9))
        keys = [(member.steps, member.sig_bytes) for member in result]
        self.assertEqual(keys, sorted(keys))
        # strictly ordered Pareto points: as steps rise, size falls
        self.assertEqual(len(keys), len(set(keys)))
        for (s1, b1), (s2, b2) in zip(keys, keys[1:]):
            self.assertLess(s1, s2)
            self.assertGreater(b1, b2)

    def test_dominated_members_absent(self):
        for capacity in range(1, 257):
            result = scheme_frontier(capacity, (None, 10**9))
            for a in result:
                for b in result:
                    if a is b:
                        continue
                    dominated = (
                        a.sig_bytes <= b.sig_bytes
                        and a.steps <= b.steps
                        and (a.sig_bytes < b.sig_bytes or a.steps < b.steps)
                    )
                    self.assertFalse(dominated, (capacity, a, b))

    def test_results_are_deduplicated(self):
        result = scheme_frontier(1, (None, 10**9))
        self.assertEqual(len(result), len(set(result)))

    def test_inclusive_budget_boundary_is_feasible(self):
        result = scheme_frontier(1, (1088, 8670))
        self.assertEqual(result, (profile("wots", w=8),))

    def test_tight_steps_budget_isolates_lamport(self):
        self.assertEqual(scheme_frontier(1, (None, 1)), (profile("lamport"),))

    def test_tight_size_budget_isolates_shortest_signature(self):
        result = scheme_frontier(1, (1088, None))
        self.assertEqual(result, (profile("wots", w=8),))

    def test_budget_filters_frontier_members(self):
        # excluding lamport's 8192-byte signature drops the speed endpoint
        result = scheme_frontier(1, (8000, None))
        self.assertTrue(all(member.sig_bytes <= 8000 for member in result))
        self.assertNotIn(profile("lamport"), result)
        self.assertEqual(result[0], profile("wots", w=4))
        self.assertEqual(result[-1], profile("wots", w=8))

    def test_spare_capacity_breaks_ties_stably(self):
        # a steps-only budget keeps both w choices at every covering height
        # only when no shorter candidate dominates; with both ends loose
        # the minimal covering height wins, so at capacity 3 both points use
        # height 2 (4 leaves), never the height-3 trees
        result = scheme_frontier(3, (None, 10**9))
        self.assertEqual(
            {(member.w, member.height) for member in result}, {(4, 2), (8, 2)}
        )

    def test_no_feasible_candidate_raises_value_error(self):
        with self.assertRaises(ValueError):
            scheme_frontier(1, (100, None))
        with self.assertRaises(ValueError):
            scheme_frontier(256, (1200, None))
        with self.assertRaises(ValueError):
            scheme_frontier(2, (None, 1004))

    def test_invalid_capacity_raises_value_error(self):
        for bad in (0, -1, 257, 10**6, 1.0, True, False, None, "1", 1 + 0j):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    scheme_frontier(bad, (None, 1))

    def test_non_tuple_budgets_raises_type_error(self):
        for bad in ([None, 1], {None, 1}, (lambda: None), None):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    scheme_frontier(1, bad)

    def test_bad_length_budgets_raises_value_error(self):
        for bad in ((), (None,), (None, 1, None)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    scheme_frontier(1, bad)

    def test_bad_budget_members_raise_value_error(self):
        for bad in (
            (None, 0),
            (None, -1),
            (None, True),
            (None, False),
            (None, 1.0),
            (None, "1"),
            (0, None),
            (True, 1),
            (1.0, None),
            ("1", None),
            (None, None),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    scheme_frontier(1, bad)

    def test_validation_order_capacity_then_budgets(self):
        # both illegal: capacity error is reported first
        with self.assertRaises(ValueError):
            scheme_frontier(0, [1])
        # capacity legal, budgets a non-tuple: TypeError
        with self.assertRaises(TypeError):
            scheme_frontier(1, [1])
        with self.assertRaises(ValueError):
            scheme_frontier(1, (None, 0))

    def test_pure_and_deterministic(self):
        first = scheme_frontier(42, (2000, 9000))
        second = scheme_frontier(42, (2000, 9000))
        self.assertEqual(first, second)
        self.assertEqual(
            tuple(
                tuple(getattr(member, field) for field in Params.__dataclass_fields__)
                for member in first
            ),
            tuple(
                tuple(getattr(member, field) for field in Params.__dataclass_fields__)
                for member in second
            ),
        )

    def test_no_default_parameters_and_no_preference(self):
        signature = inspect.signature(scheme_frontier)
        self.assertEqual(list(signature.parameters), ["capacity", "budgets"])
        self.assertEqual(
            signature.parameters["capacity"].default, inspect.Parameter.empty
        )
        self.assertEqual(
            signature.parameters["budgets"].default, inspect.Parameter.empty
        )

    def test_frontier_contains_recommend_scheme_extremes(self):
        from pqattest import recommend_scheme

        # the preference winners are frontier members
        size = recommend_scheme(1, (None, 10**9), prefer="size")
        speed = recommend_scheme(1, (None, 10**9), prefer="speed")
        frontier = scheme_frontier(1, (None, 10**9))
        self.assertIn(size, frontier)
        self.assertIn(speed, frontier)
        self.assertEqual(frontier[-1], size)
        self.assertEqual(frontier[0], speed)


if __name__ == "__main__":
    unittest.main()

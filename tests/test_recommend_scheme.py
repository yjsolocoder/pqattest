import inspect
import unittest

from pqattest import Params, profile, recommend_scheme


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


def _brute_force(capacity, budgets, prefer):
    """Replicate the documented feasible-set filtering and ranking."""
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

    def key(candidate):
        tail = (
            candidate.capacity - capacity,
            candidate.scheme,
            candidate.w is not None,
            candidate.w,
            candidate.height is not None,
            candidate.height,
        )
        if prefer == "speed":
            return (candidate.steps, candidate.sig_bytes) + tail
        return (candidate.sig_bytes, candidate.steps) + tail

    return min(feasible, key=key)


_BUDGET_CASES = (
    (None, 10**9),
    (10**9, None),
    (2048, None),
    (None, 1005),
    (None, 8670),
    (2300, 9000),
)


class RecommendSchemeTest(unittest.TestCase):
    def test_matches_brute_force_for_every_capacity_and_preference(self):
        for capacity in range(1, 257):
            for budgets in _BUDGET_CASES:
                for prefer in ("size", "speed"):
                    with self.subTest(
                        capacity=capacity, budgets=budgets, prefer=prefer
                    ):
                        self.assertEqual(
                            recommend_scheme(capacity, budgets, prefer),
                            _brute_force(capacity, budgets, prefer),
                        )

    def test_returns_params_metrics_object(self):
        result = recommend_scheme(1, (None, 10**9))
        self.assertIsInstance(result, Params)
        self.assertEqual(result, profile("wots", w=8))

    def test_one_signature_size_prefers_wots8(self):
        result = recommend_scheme(1, (None, 10**9))
        self.assertEqual(result.scheme, "wots")
        self.assertEqual(result.w, 8)
        self.assertIsNone(result.height)
        self.assertEqual(result.capacity, 1)
        self.assertEqual(result.sig_bytes, 1088)
        self.assertEqual(result.steps, 8670)

    def test_one_signature_speed_prefers_lamport(self):
        # lamport has zero hash-chain steps, the global minimum
        result = recommend_scheme(1, (None, 10**9), prefer="speed")
        self.assertEqual(result, profile("lamport"))

    def test_one_signature_speed_budget_excludes_lamport(self):
        # a signature-size budget below the 8192-byte lamport signature
        # leaves wots/merkle; speed then picks wots w=4 (1005 steps)
        result = recommend_scheme(1, (8000, None), prefer="speed")
        self.assertEqual(result, profile("wots", w=4))

    def test_signature_size_budget_filters_candidates(self):
        # wots w=8 at 1088 is the shortest candidate of every scheme
        self.assertEqual(recommend_scheme(1, (1088, None)).w, 8)
        # one byte tighter excludes every candidate (1088 is the global
        # minimum signature size)
        with self.assertRaises(ValueError):
            recommend_scheme(1, (1087, None))
        # excluding lamport's 8192-byte signature but keeping both W-OTS
        # choices leaves wots w=8 shortest
        self.assertEqual(recommend_scheme(1, (2200, None)), profile("wots", w=8))

    def test_steps_budget_can_isolate_lamport(self):
        # only lamport has fewer than 1005 hash-chain steps; a tight steps
        # budget selects it even under the size preference
        result = recommend_scheme(1, (None, 1))
        self.assertEqual(result, profile("lamport"))

    def test_steps_budget_excludes_w8_options(self):
        # w=8 chain steps are 8670; a 1005-step budget leaves lamport and
        # the w=4 configurations. Excluding lamport's 8192-byte signature
        # as well makes speed pick wots w=4 (1005 steps)
        result = recommend_scheme(1, (8191, 1005), prefer="speed")
        self.assertEqual(result, profile("wots", w=4))

    def test_multiple_signatures_exclude_one_time_schemes(self):
        for capacity in (2, 3, 16, 256):
            for prefer in ("size", "speed"):
                with self.subTest(capacity=capacity, prefer=prefer):
                    result = recommend_scheme(capacity, (None, 10**9), prefer)
                    self.assertEqual(result.scheme, "merkle")
                    self.assertGreaterEqual(result.capacity, capacity)

    def test_multiple_signatures_pick_minimal_covering_height_per_w(self):
        size = recommend_scheme(5, (None, 10**9))
        self.assertEqual((size.w, size.height), (8, 3))
        speed = recommend_scheme(5, (None, 10**9), prefer="speed")
        self.assertEqual((speed.w, speed.height), (4, 3))

    def test_tail_prefers_smallest_spare_capacity(self):
        # capacity 3 must not take a height-3 tree when a height-2 tree
        # covers it: the spare-capacity tie-break wins over lexicographic w
        result = recommend_scheme(3, (None, 10**9))
        self.assertEqual(result.capacity, 4)
        self.assertEqual(result.height, 2)

    def test_inclusive_budget_boundary_is_feasible(self):
        result = recommend_scheme(1, (1088, 8670))
        self.assertEqual(result, profile("wots", w=8))

    def test_default_preference_is_size(self):
        self.assertEqual(
            recommend_scheme(16, (None, 10**9)),
            recommend_scheme(16, (None, 10**9), prefer="size"),
        )

    def test_no_feasible_candidate_raises_value_error(self):
        with self.assertRaises(ValueError):
            recommend_scheme(1, (100, None))
        with self.assertRaises(ValueError):
            recommend_scheme(256, (1200, None))
        # capacity 2 has no one-time candidates; steps below the w=4 minimum
        # leaves no feasible Merkle configuration either
        with self.assertRaises(ValueError):
            recommend_scheme(2, (None, 1004))

    def test_invalid_capacity_raises_value_error(self):
        for bad in (0, -1, 257, 10**6, 1.0, True, False, None, "1", 1 + 0j):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_scheme(bad, (None, 1))

    def test_non_tuple_budgets_raises_type_error(self):
        for bad in ([None, 1], {None, 1}, (lambda: None)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_scheme(1, bad)

    def test_bad_length_budgets_raises_value_error(self):
        for bad in ((), (None,), (None, 1, None)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_scheme(1, bad)

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
                    recommend_scheme(1, bad)

    def test_invalid_preference_raises_value_error(self):
        for bad in ("fast", "SIZE", "", None, 4):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_scheme(1, (None, 1), prefer=bad)

    def test_validation_order_capacity_budgets_preference(self):
        # all three illegal: capacity error is reported first
        with self.assertRaises(ValueError):
            recommend_scheme(0, [1], prefer="nope")
        # capacity legal, budgets and prefer illegal: budgets first
        with self.assertRaises(TypeError):
            recommend_scheme(1, [1], prefer="nope")
        with self.assertRaises(ValueError):
            recommend_scheme(1, (None, 0), prefer="nope")

    def test_pure_and_deterministic(self):
        first = recommend_scheme(42, (2000, 9000), prefer="speed")
        second = recommend_scheme(42, (2000, 9000), prefer="speed")
        self.assertEqual(first, second)
        self.assertEqual(
            tuple(getattr(first, field) for field in Params.__dataclass_fields__),
            tuple(getattr(second, field) for field in Params.__dataclass_fields__),
        )

    def test_capacity_and_budgets_are_required(self):
        signature = inspect.signature(recommend_scheme)
        self.assertEqual(
            signature.parameters["capacity"].default, inspect.Parameter.empty
        )
        self.assertEqual(
            signature.parameters["budgets"].default, inspect.Parameter.empty
        )

    def test_every_accepted_profile_combination_is_a_candidate(self):
        # at capacity 1 with no restrictive budget every profile()-accepted
        # combination can be isolated as the sole survivor by some budget
        one_time = recommend_scheme(1, (None, 10**9))
        self.assertEqual(one_time, profile("wots", w=8))
        # every merkle configuration is reachable as the exact-capacity pick
        for w in (4, 8):
            for height in range(1, 9):
                capacity = 1 << height
                prefer = "size" if w == 8 else "speed"
                result = recommend_scheme(capacity, (None, 10**9), prefer)
                self.assertEqual(
                    (result.scheme, result.w, result.height),
                    ("merkle", w, height),
                )

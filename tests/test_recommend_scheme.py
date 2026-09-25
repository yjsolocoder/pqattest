import unittest

from pqattest import (
    MerkleSigner,
    Params,
    profile,
    recommend_scheme,
)


def _candidates(capacity):
    """Every candidate Params the selector may consider for ``capacity``."""
    candidates = []
    if capacity == 1:
        candidates.append(profile("lamport"))
        for w in (4, 8):
            candidates.append(profile("wots", w=w))
    for w in (4, 8):
        for height in range(1, 9):
            params = profile("merkle", w=w, height=height)
            if params.capacity >= capacity:
                candidates.append(params)
    return candidates


def _expected(capacity, budgets, prefer):
    """Brute-force selection with the documented ranking rules."""
    signature_limit, steps_limit = budgets
    feasible = [
        params
        for params in _candidates(capacity)
        if (signature_limit is None or params.sig_bytes <= signature_limit)
        and (steps_limit is None or params.steps <= steps_limit)
    ]

    def tail(params):
        return (
            params.capacity - capacity,
            params.scheme,
            (params.w is not None, params.w if params.w is not None else 0),
            (
                params.height is not None,
                params.height if params.height is not None else 0,
            ),
        )

    if prefer == "speed":
        key = lambda params: (params.steps, params.sig_bytes) + tail(params)
    else:
        key = lambda params: (params.sig_bytes, params.steps) + tail(params)
    return min(feasible, key=key)


class RecommendSchemeTest(unittest.TestCase):
    def test_size_picks_shortest_signature(self):
        # wots w=8 has the shortest serialised signature (1088 bytes)
        self.assertEqual(
            recommend_scheme(1, (None, 9000)),
            profile("wots", w=8),
        )

    def test_speed_picks_fewest_steps(self):
        # lamport verifies with no hash-chain steps at all
        self.assertEqual(
            recommend_scheme(1, (None, 9000), prefer="speed"),
            profile("lamport"),
        )

    def test_size_then_steps_order(self):
        # steps budget 2000 excludes every w=8 candidate; size then picks the
        # shortest remaining signature (wots w=4, 2144 bytes), speed the one
        # with zero steps (lamport)
        self.assertEqual(
            recommend_scheme(1, (None, 2000)),
            profile("wots", w=4),
        )
        self.assertEqual(
            recommend_scheme(1, (None, 2000), prefer="speed"),
            profile("lamport"),
        )

    def test_capacity_above_one_leaves_only_merkle(self):
        # one-time schemes sign a single message, so capacity 2 is Merkle-only
        self.assertEqual(
            recommend_scheme(2, (None, 9000)),
            profile("merkle", w=8, height=1),
        )
        self.assertEqual(
            recommend_scheme(2, (None, 9000), prefer="speed"),
            profile("merkle", w=4, height=1),
        )

    def test_capacity_forces_height(self):
        for prefer in ("size", "speed"):
            with self.subTest(prefer=prefer):
                result = recommend_scheme(100, (None, 9000), prefer=prefer)
                self.assertEqual(result.scheme, "merkle")
                self.assertEqual(result.height, 7)
                self.assertEqual(result.w, 8 if prefer == "size" else 4)

    def test_signature_budget_filters_independently(self):
        # a 1300-byte signature budget excludes lamport and every w=4 chain
        self.assertEqual(
            recommend_scheme(16, (1300, None)),
            profile("merkle", w=8, height=4),
        )

    def test_budgets_are_inclusive(self):
        winner = profile("merkle", w=8, height=4)
        exact = (winner.sig_bytes, winner.steps)
        self.assertEqual(recommend_scheme(16, exact), winner)

    def test_matches_brute_force(self):
        cases = (
            (1, (None, 9000)),
            (1, (None, 2000)),
            (1, (1088, None)),
            (2, (None, 9000)),
            (3, (2300, 1005)),
            (16, (1300, None)),
            (16, (1216, 8670)),
            (100, (None, 9000)),
            (256, (8192, 8670)),
        )
        for capacity, budgets in cases:
            for prefer in ("size", "speed"):
                with self.subTest(capacity=capacity, budgets=budgets, prefer=prefer):
                    self.assertEqual(
                        recommend_scheme(capacity, budgets, prefer=prefer),
                        _expected(capacity, budgets, prefer),
                    )

    def test_returns_params(self):
        result = recommend_scheme(4, (None, 9000))
        self.assertIsInstance(result, Params)
        self.assertEqual(
            result, profile(result.scheme, w=result.w, height=result.height)
        )

    def test_no_feasible_candidate_raises(self):
        # no serialised signature fits in 100 bytes
        with self.assertRaises(ValueError):
            recommend_scheme(1, (100, None))
        # capacity 256 needs height 8; a 1000-step budget kills every w
        with self.assertRaises(ValueError):
            recommend_scheme(256, (None, 1000))

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_scheme(bad, (None, 9000))

    def test_budgets_must_be_tuple(self):
        for bad in ([None, 9000], "budget", None, 7, {1, 2}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_scheme(4, bad)

    def test_budgets_length(self):
        for bad in ((), (None,), (None, None, None), (None,) * 4):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_scheme(4, bad)

    def test_budget_members_validated(self):
        for bad_member in (0, -1, True, 1.5, "100"):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    recommend_scheme(4, (None, bad_member))

    def test_at_least_one_budget_required(self):
        with self.assertRaises(ValueError):
            recommend_scheme(4, (None, None))

    def test_invalid_prefer_rejected(self):
        for bad in ("fast", "SIZE", None, 8):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_scheme(4, (None, 9000), prefer=bad)

    def test_capacity_and_budgets_required_without_defaults(self):
        with self.assertRaises(TypeError):
            recommend_scheme()
        with self.assertRaises(TypeError):
            recommend_scheme(4)

    def test_validation_order_capacity_then_budgets_then_prefer(self):
        # an illegal capacity is reported before a non-tuple budgets
        with self.assertRaises(ValueError):
            recommend_scheme(0, [None, 9000], prefer="fast")
        # a non-tuple budgets is reported before an illegal prefer
        with self.assertRaises(TypeError):
            recommend_scheme(4, [None, 9000], prefer="fast")
        # an illegal budgets tuple is reported before an illegal prefer
        with self.assertRaises(ValueError):
            recommend_scheme(4, (None, None), prefer="fast")

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        first = recommend_scheme(2, (None, 9000))
        second = recommend_scheme(2, (None, 9000))
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

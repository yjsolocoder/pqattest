"""Regression for the shared rules behind the weighted verify-mode pair.

These tests pin the public business semantics shared by
``recommend_merkle_verify_mode_weighted`` and
``explain_merkle_verify_mode_weighted`` after both were refactored onto one
decision table:

* the five ranked costs are projected from the *public* frontier
  (``merkle_verify_mode_frontier`` + ``profile``), not from either entry
  under test, so an expected row is an independent recomputation, never a
  copy of the implementation or a mere cross-check that the two entries
  happen to agree with each other;
* costs are min-max normalised over the whole frontier with zero spans
  scoring zero; each scenario score is the weighted normalised sum divided
  by that scenario's weight total; each regret is the score minus the
  scenario's best score — all exact ``Fraction``;
* the order is greatest regret, regret sum, per-scenario score tuple, then
  checkpoint bytes / leaf count / w / height / modes, including fixtures
  where each named level is the one that actually decides;
* the selected row is unique, equals the recommendation field for field and
  the rows keep frontier order;
* validation order (capacity/groups/budgets before scenarios) and exact
  exception types/messages are pinned.
"""
import inspect
import unittest
from fractions import Fraction

from pqattest import (
    MerkleModeCost,
    MerkleVerifyModeScore,
    explain_merkle_verify_mode_weighted,
    merkle_verify_mode_frontier,
    profile,
    recommend_merkle_verify_mode_weighted,
)

GROUPS = ((0, 1), (3, 5))
BUDGETS = (None, 5000, 12000, None, 8, None)

# A workload whose frontier holds members identical across all five ranked
# costs (they differ only in the modes tuple), so a score table of zeros is
# a genuine tail-only decision rather than a single-candidate trivial case.
TAIL_WORKLOAD = (8, ((0,), (1, 2), (4,)), (9000, None, None, None, None, None))
# A workload whose frontier is a single member: every span is zero.
SINGLE_WORKLOAD = (1, ((0,),), (None, None, 2243, None, None, 2000))


def _metrics(mode_cost):
    """The documented five ranked costs, recomputed from public objects."""
    return (
        mode_cost.plan.total,
        max(mode_cost.plan.sizes),
        mode_cost.cost.total,
        mode_cost.nodes,
        profile(
            "merkle",
            w=mode_cost.plan.config.w,
            height=mode_cost.plan.config.height,
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


def _reference_table(capacity, groups, budgets, scenarios):
    """Independently build ``(key, mode_cost, costs, scores, regrets)``.

    Pure re-implementation of the documented pipeline from the public
    frontier and ``profile``; nothing here reads the functions under test.
    """
    frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
    raw = [_metrics(mode_cost) for mode_cost in frontier]
    spans = tuple(
        (min(row[i] for row in raw), max(row[i] for row in raw))
        for i in range(5)
    )
    normalised = tuple(
        tuple(
            Fraction(value - low, high - low) if high > low else Fraction(0)
            for value, (low, high) in zip(row, spans)
        )
        for row in raw
    )
    totals = tuple(sum(weights) for weights in scenarios)
    score_rows = tuple(
        tuple(
            sum((w * c for w, c in zip(weights, row)), Fraction(0)) / total
            for weights, total in zip(scenarios, totals)
        )
        for row in normalised
    )
    best = tuple(
        min(scores[i] for scores in score_rows) for i in range(len(scenarios))
    )
    table = []
    for mode_cost, costs, scores in zip(frontier, normalised, score_rows):
        regrets = tuple(s - b for s, b in zip(scores, best))
        key = (
            max(regrets),
            sum(regrets, Fraction(0)),
            scores,
            *_tail(mode_cost),
        )
        table.append((key, mode_cost, costs, scores, regrets))
    return frontier, table


WORKLOADS = (
    (1, ((0,),), (None, None, None, None, None, 10**18)),
    SINGLE_WORKLOAD,
    (2, ((0,), (1,)), (None, None, None, None, None, 6000)),
    (4, ((2,),), (None, 4000, None, None, None, None)),
    (4, ((0,), (1,)), (9000, None, 7000, None, 4, None)),
    TAIL_WORKLOAD,
    (16, GROUPS, BUDGETS),
    (16, GROUPS, (17489, None, None, None, None, None)),
    (16, ((1,), (2,), (3,), (4,), (8,)), (None, None, None, None, None, 10**18)),
    (32, ((0,), (6, 7), (15, 16)), (None, None, None, None, 50, None)),
    (64, ((0,), (3, 63)), (None, None, None, None, None, 10**18)),
    (256, ((0,), (255,)), (None, None, None, None, None, 10**18)),
)

SCENARIO_SETS = (
    ((1, 1, 1, 1, 1),),
    ((0, 0, 0, 0, 1),),
    ((10, 0, 0, 0, 0), (0, 0, 0, 0, 1)),
    (
        (1, 2, 3, 4, 5),
        (0, 1, 0, 1, 0),
        (10**9, 1, 1, 1, 1),
        (3, 0, 7, 0, 2),
    ),
    ((1, 0, 0, 0, 0), (0, 1, 0, 0, 0), (0, 0, 1, 0, 0), (0, 0, 0, 1, 0)),
    # repeated scenarios: kept as separate positions, in original order
    ((1, 1, 1, 1, 1), (1, 1, 1, 1, 1)),
    ((3, 0, 7, 0, 2), (3, 0, 7, 0, 2), (0, 5, 0, 1, 0)),
    # large integer weights: exact rationals, no float truncation
    ((10**40, 10**30, 0, 1, 0), (1, 0, 10**50, 0, 10**20)),
    ((0, 0, 0, 1, 0), (0, 0, 0, 0, 1)),
)


class SharedVerifyModeRulesTest(unittest.TestCase):
    def _assert_matches_reference(self, capacity, groups, budgets, scenarios):
        frontier, table = _reference_table(
            capacity, groups, budgets, scenarios
        )
        reference_winner = min(table, key=lambda item: item[0])[1]

        recommendation = recommend_merkle_verify_mode_weighted(
            capacity, groups, budgets, scenarios
        )
        rows = explain_merkle_verify_mode_weighted(
            capacity, groups, budgets, scenarios
        )

        # selection follows the independently computed ranking
        self.assertEqual(recommendation, reference_winner)
        self.assertEqual(len(rows), len(frontier))
        self.assertEqual(tuple(row.mode_cost for row in rows), frontier)
        selected = [row for row in rows if row.selected]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].mode_cost, recommendation)

        # every row equals the independent reference, field for field
        self.assertEqual(len(rows), len(table))
        for row, (_key, mode_cost, costs, scores, regrets) in zip(rows, table):
            self.assertIsInstance(row, MerkleVerifyModeScore)
            self.assertEqual(row.mode_cost, mode_cost)
            self.assertEqual(
                (
                    row.transport_cost,
                    row.peak_cost,
                    row.hashes_cost,
                    row.nodes_cost,
                    row.steps_cost,
                ),
                costs,
            )
            self.assertEqual(row.scores, scores)
            self.assertEqual(row.regrets, regrets)
            for value in (*costs, *scores, *regrets):
                self.assertIsInstance(value, Fraction)
            self.assertEqual(
                row.regrets,
                tuple(
                    score - floor
                    for score, floor in zip(
                        row.scores,
                        tuple(
                            min(other.scores[i] for other in rows)
                            for i in range(len(scenarios))
                        ),
                    )
                ),
            )

    def test_grid_matches_independent_reference(self):
        for capacity, groups, budgets in WORKLOADS:
            for scenarios in SCENARIO_SETS:
                with self.subTest(
                    capacity=capacity,
                    groups=groups,
                    budgets=budgets,
                    scenarios=scenarios,
                ):
                    self._assert_matches_reference(
                        capacity, groups, budgets, scenarios
                    )

    def test_normalisation_is_min_max_with_zero_span_zero(self):
        # single-member frontier: all five spans are zero, so every
        # normalised cost, score and regret is exactly zero (no /0)
        capacity, groups, budgets = SINGLE_WORKLOAD
        frontier = merkle_verify_mode_frontier(capacity, groups, budgets)
        self.assertEqual(len(frontier), 1)
        for scenarios in (
            ((1, 1, 1, 1, 1),),
            ((0, 0, 0, 0, 1),),
            ((9, 8, 7, 6, 5), (1, 0, 0, 0, 0)),
        ):
            with self.subTest(scenarios=scenarios):
                (row,) = explain_merkle_verify_mode_weighted(
                    capacity, groups, budgets, scenarios
                )
                self.assertEqual(
                    (
                        row.transport_cost,
                        row.peak_cost,
                        row.hashes_cost,
                        row.nodes_cost,
                        row.steps_cost,
                    ),
                    (Fraction(0),) * 5,
                )
                self.assertEqual(row.scores, (Fraction(0),) * len(scenarios))
                self.assertEqual(row.regrets, (Fraction(0),) * len(scenarios))
                self.assertTrue(row.selected)

    def test_normalised_costs_reach_zero_and_one(self):
        # on a non-degenerate frontier each spanned column independently
        # hits 0 (its minimum) and 1 (its maximum) over the rows
        capacity, groups, budgets = 16, GROUPS, BUDGETS
        rows = explain_merkle_verify_mode_weighted(
            capacity, groups, budgets, ((1, 1, 1, 1, 1),)
        )
        columns = (
            "transport_cost",
            "peak_cost",
            "hashes_cost",
            "nodes_cost",
            "steps_cost",
        )
        raw = [_metrics(row.mode_cost) for row in rows]
        for index, name in enumerate(columns):
            values = [getattr(row, name) for row in rows]
            low, high = min(r[index] for r in raw), max(
                r[index] for r in raw
            )
            if high > low:
                self.assertEqual(min(values), Fraction(0))
                self.assertEqual(max(values), Fraction(1))

    def test_regret_sum_is_the_deciding_level(self):
        # two members tie on greatest regret; the regret sum breaks it, so
        # the all-three tie group is a singleton while the max-regret group
        # is not
        capacity, groups, budgets = TAIL_WORKLOAD
        scenarios = ((0, 0, 0, 1, 0), (1, 0, 0, 0, 2))
        _frontier, table = _reference_table(
            capacity, groups, budgets, scenarios
        )
        winner_key = min(table, key=lambda item: item[0])[0]
        max_tied = [t for t in table if t[0][0] == winner_key[0]]
        sum_tied = [
            t for t in max_tied if t[0][1] == winner_key[1]
        ]
        self.assertGreater(len(max_tied), 1)
        self.assertEqual(len(sum_tied), 1)
        winner = recommend_merkle_verify_mode_weighted(
            capacity, groups, budgets, scenarios
        )
        self.assertEqual(winner.plan.config.w, 8)
        self.assertEqual(winner.plan.modes, ("batch", "batch", "batch"))

    def test_score_tuple_is_the_deciding_level(self):
        # greatest regret AND regret sum both tie across two members; the
        # per-scenario score tuple is the first distinguishing level
        capacity, groups, budgets = TAIL_WORKLOAD
        scenarios = ((0, 0, 0, 1, 0), (0, 0, 1, 0, 2))
        _frontier, table = _reference_table(
            capacity, groups, budgets, scenarios
        )
        winner_key = min(table, key=lambda item: item[0])[0]
        max_tied = [t for t in table if t[0][0] == winner_key[0]]
        sum_tied = [t for t in max_tied if t[0][1] == winner_key[1]]
        score_tied = [t for t in sum_tied if t[0][2] == winner_key[2]]
        self.assertGreater(len(max_tied), 1)
        self.assertGreater(len(sum_tied), 1)
        self.assertEqual(len(score_tied), 1)
        winner = recommend_merkle_verify_mode_weighted(
            capacity, groups, budgets, scenarios
        )
        self.assertEqual(winner.plan.modes, ("batch", "batch", "batch"))

    def test_tail_modes_tuple_is_the_deciding_level(self):
        # five members share identical ranked costs, so every score and
        # regret is 0 and checkpoint/leaf/w/height tie too; only the modes
        # tuple lexicographic order decides
        capacity, groups, budgets = TAIL_WORKLOAD
        scenarios = ((0, 0, 0, 0, 1), (0, 0, 0, 0, 1))
        _frontier, table = _reference_table(
            capacity, groups, budgets, scenarios
        )
        first_key = min(table, key=lambda item: item[0])[0]
        fully_tied = [
            t
            for t in table
            if (t[0][0], t[0][1], t[0][2], *t[0][3:7])
            == (first_key[0], first_key[1], first_key[2], *first_key[3:7])
        ]
        self.assertGreaterEqual(len(fully_tied), 2)
        modes_tied = [t for t in fully_tied if t[0][7] == first_key[7]]
        self.assertEqual(len(modes_tied), 1)
        self.assertEqual(first_key[7], ("batch", "batch", "batch"))
        rows = explain_merkle_verify_mode_weighted(
            capacity, groups, budgets, scenarios
        )
        selected = [row for row in rows if row.selected][0]
        self.assertEqual(
            selected.mode_cost.plan.modes, ("batch", "batch", "batch")
        )
        for row in rows:
            self.assertEqual(row.scores, (Fraction(0), Fraction(0)))
            self.assertEqual(row.regrets, (Fraction(0), Fraction(0)))

    def test_pinned_exact_vectors(self):
        # exact Fraction numerator/denominator vectors lock arithmetic and
        # ordering against any silent semantic drift
        capacity, groups, budgets = 16, GROUPS, BUDGETS
        scenarios = (
            (1, 2, 3, 4, 5),
            (0, 1, 0, 1, 0),
            (3, 0, 7, 0, 2),
        )
        rows = explain_merkle_verify_mode_weighted(
            capacity, groups, budgets, scenarios
        )
        selected = [row for row in rows if row.selected][0]
        self.assertEqual(
            selected.mode_cost.plan.config.w, 4,
        )
        self.assertEqual(selected.mode_cost.plan.config.height, 4)
        self.assertEqual(selected.mode_cost.plan.modes, ("batch", "batch"))
        self.assertEqual(
            (
                selected.transport_cost,
                selected.peak_cost,
                selected.hashes_cost,
                selected.nodes_cost,
                selected.steps_cost,
            ),
            (
                Fraction(1, 1),
                Fraction(1, 1),
                Fraction(1, 5111),
                Fraction(0, 1),
                Fraction(0, 1),
            ),
        )
        self.assertEqual(
            selected.scores,
            (Fraction(5112, 25555), Fraction(1, 2), Fraction(3835, 15333)),
        )
        self.assertEqual(
            selected.regrets,
            (
                Fraction(0, 1),
                Fraction(352, 741),
                Fraction(281803, 17310957),
            ),
        )

    def test_repeated_scenarios_counted_separately_in_order(self):
        first = (0, 0, 0, 1, 1)
        second = (0, 3, 0, 0, 1)
        one_each = recommend_merkle_verify_mode_weighted(
            16, GROUPS, BUDGETS, (first, second)
        )
        second_doubled = recommend_merkle_verify_mode_weighted(
            16, GROUPS, BUDGETS, (first, second, second)
        )
        # repeating the second scenario swings the minimax choice and keeps
        # three score/regret positions in the explanation, not two
        rows_doubled = explain_merkle_verify_mode_weighted(
            16, GROUPS, BUDGETS, (first, second, second)
        )
        self.assertEqual(len(rows_doubled[0].scores), 3)
        self.assertEqual(len(rows_doubled[0].regrets), 3)
        # the duplicate positions are exact equals but distinct positions
        for row in rows_doubled:
            self.assertEqual(row.scores[1], row.scores[2])
            self.assertEqual(row.regrets[1], row.regrets[2])
        self.assertNotEqual(one_each, second_doubled)
        self.assertEqual(second_doubled.plan.config.w, 8)

    def test_large_integer_weights_are_exact(self):
        scenarios = ((10**40, 10**30, 0, 1, 0), (1, 0, 10**50, 0, 10**20))
        rows = explain_merkle_verify_mode_weighted(
            16, GROUPS, BUDGETS, scenarios
        )
        _frontier, table = _reference_table(16, GROUPS, BUDGETS, scenarios)
        for row, (_k, _mc, costs, scores, regrets) in zip(rows, table):
            self.assertEqual(row.scores, scores)
            self.assertEqual(row.regrets, regrets)

    def test_rows_are_frozen_positional_value_and_hashable(self):
        rows = explain_merkle_verify_mode_weighted(
            16, GROUPS, BUDGETS, ((1, 1, 1, 1, 1),)
        )
        row = rows[0]
        clone = MerkleVerifyModeScore(
            row.mode_cost,
            row.transport_cost,
            row.peak_cost,
            row.hashes_cost,
            row.nodes_cost,
            row.steps_cost,
            row.scores,
            row.regrets,
            row.selected,
        )
        self.assertEqual(clone, row)
        self.assertEqual(hash(clone), hash(row))
        self.assertEqual({row, clone}, {row})
        with self.assertRaises(Exception):
            row.selected = False

    def test_frontier_is_the_only_candidate_source_called_once(self):
        import pqattest.params as params_module

        for fn in (
            recommend_merkle_verify_mode_weighted,
            explain_merkle_verify_mode_weighted,
        ):
            calls = 0
            original = params_module.merkle_verify_mode_frontier

            def counting(*args, **kwargs):
                nonlocal calls
                calls += 1
                return original(*args, **kwargs)

            params_module.merkle_verify_mode_frontier = counting
            try:
                fn(16, GROUPS, BUDGETS, ((1, 1, 1, 1, 1),))
                self.assertEqual(calls, 1)
            finally:
                params_module.merkle_verify_mode_frontier = original

    def test_no_partial_rows_when_no_feasible_candidate(self):
        for fn in (
            recommend_merkle_verify_mode_weighted,
            explain_merkle_verify_mode_weighted,
        ):
            with self.assertRaises(ValueError):
                fn(
                    1,
                    ((0,),),
                    (100, None, None, None, None, None),
                    ((1, 1, 1, 1, 1),),
                )
            with self.assertRaises(ValueError):
                fn(
                    4,
                    ((0,),),
                    (None, None, None, None, None, 10),
                    ((1, 1, 1, 1, 1),),
                )

    def test_scenario_validation_types_and_values(self):
        rec = recommend_merkle_verify_mode_weighted
        for bad_container in (
            [(1, 1, 1, 1, 1)],
            {(1, 1, 1, 1, 1)},
            "scenarios",
            None,
            7,
            range(5),
        ):
            with self.subTest(bad_container=bad_container):
                with self.assertRaises(TypeError):
                    rec(16, GROUPS, BUDGETS, bad_container)
        for bad_member in (
            ([1, 1, 1, 1, 1],),
            ("scenario",),
            (None,),
            (7,),
        ):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(TypeError):
                    rec(16, GROUPS, BUDGETS, bad_member)
        for bad_weight in (
            ((1.0, 1, 1, 1, 1),),
            ((1, "1", 1, 1, 1),),
            ((1, None, 1, 1, 1),),
        ):
            with self.subTest(bad_weight=bad_weight):
                with self.assertRaises(TypeError):
                    rec(16, GROUPS, BUDGETS, bad_weight)
        for bad_value in (
            (),
            ((1, 1, 1, 1),),
            ((1, 1, 1, 1, 1, 1),),
            ((0, 0, 0, 0, 0),),
            ((1, -1, 1, 1, 1),),
            ((True, 1, 1, 1, 1),),
            ((1, 1, 1, 1, False),),
            ((1, 1, 1, 1, 1), (0, 0, 0, 0, 0)),
        ):
            with self.subTest(bad_value=bad_value):
                with self.assertRaises(ValueError):
                    rec(16, GROUPS, BUDGETS, bad_value)

    def test_frontier_arguments_screened_before_scenarios(self):
        # capacity/groups/budgets are validated first via the frontier, so
        # the frontier's error wins even when scenarios is also invalid
        with self.assertRaisesRegex(ValueError, "between 1 and"):
            recommend_merkle_verify_mode_weighted(
                0, (), (None,) * 6, ()
            )
        with self.assertRaises(TypeError):
            recommend_merkle_verify_mode_weighted(
                16, [(0, 1)], BUDGETS, "not a tuple"
            )
        # the frontier's own message text is preserved
        with self.assertRaisesRegex(ValueError, "at least one budget"):
            recommend_merkle_verify_mode_weighted(
                16, GROUPS, (None,) * 6, ()
            )

    def test_exception_type_and_message_match_between_entries(self):
        bad = (
            (0, GROUPS, BUDGETS, ((1, 1, 1, 1, 1),)),
            (16, [(0, 1)], BUDGETS, ((1, 1, 1, 1, 1),)),
            (16, GROUPS, (None,) * 6, ((1, 1, 1, 1, 1),)),
            (16, GROUPS, BUDGETS, "x"),
            (16, GROUPS, BUDGETS, ((1, 1, 1, 1),)),
            (16, GROUPS, BUDGETS, ((0, 0, 0, 0, 0),)),
        )
        for args in bad:
            for rec_args, exp_args in ((args, args),):
                with self.assertRaises(Exception) as rec_cm:
                    recommend_merkle_verify_mode_weighted(*rec_args)
                with self.assertRaises(Exception) as exp_cm:
                    explain_merkle_verify_mode_weighted(*exp_args)
                self.assertEqual(
                    type(rec_cm.exception), type(exp_cm.exception)
                )
                self.assertEqual(str(rec_cm.exception), str(exp_cm.exception))

    def test_returns_public_types_and_unchanged_signature(self):
        self.assertIsInstance(
            recommend_merkle_verify_mode_weighted(
                16, GROUPS, BUDGETS, ((1, 1, 1, 1, 1),)
            ),
            MerkleModeCost,
        )
        rows = explain_merkle_verify_mode_weighted(
            16, GROUPS, BUDGETS, ((1, 1, 1, 1, 1),)
        )
        self.assertIsInstance(rows, tuple)
        for fn in (
            recommend_merkle_verify_mode_weighted,
            explain_merkle_verify_mode_weighted,
        ):
            sig = inspect.signature(fn)
            self.assertEqual(
                list(sig.parameters),
                ["capacity", "groups", "budgets", "scenarios"],
            )
            for parameter in sig.parameters.values():
                self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_pure_deterministic_and_draws_no_randomness(self):
        import secrets
        from unittest import mock

        def explode(*_args, **_kwargs):
            raise AssertionError("must not draw randomness")

        with mock.patch.object(secrets, "token_bytes", explode):
            for scenarios in SCENARIO_SETS:
                first = recommend_merkle_verify_mode_weighted(
                    16, GROUPS, BUDGETS, scenarios
                )
                second = recommend_merkle_verify_mode_weighted(
                    16, GROUPS, BUDGETS, scenarios
                )
                self.assertEqual(first, second)
                first_rows = explain_merkle_verify_mode_weighted(
                    16, GROUPS, BUDGETS, scenarios
                )
                second_rows = explain_merkle_verify_mode_weighted(
                    16, GROUPS, BUDGETS, scenarios
                )
                self.assertEqual(first_rows, second_rows)


if __name__ == "__main__":
    unittest.main()

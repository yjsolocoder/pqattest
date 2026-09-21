import inspect
import unittest

from pqattest import (
    MerkleSigner,
    MerkleStorageProfile,
    merkle_deployment_frontier,
    merkle_storage_profile,
    profile,
)

# w=4: n=67, steps=1005; w=8: n=34, steps=8670


def _feasible(capacity, budgets):
    """Brute-force every feasible (storage, steps) pair."""
    candidates = []
    for w in (4, 8):
        for height in range(1, 9):
            storage = merkle_storage_profile(w, height)
            if storage.leaf_count < capacity:
                continue
            steps = profile("merkle", w=w, height=height).steps
            measured = (
                storage.checkpoint_bytes,
                storage.signature_wire_bytes,
                storage.proof_wire_bytes,
                steps,
            )
            if any(
                limit is not None and value > limit
                for value, limit in zip(measured, budgets)
            ):
                continue
            candidates.append((storage, steps))
    return candidates


def _expected_frontier(capacity, budgets):
    """Brute-force the documented Pareto frontier and ordering."""
    candidates = _feasible(capacity, budgets)
    survivors = []
    for candidate in candidates:
        storage, steps = candidate
        dominated = False
        for other in candidates:
            other_storage, other_steps = other
            if other is candidate:
                continue
            no_worse = (
                other_storage.checkpoint_bytes <= storage.checkpoint_bytes
                and other_storage.signature_wire_bytes <= storage.signature_wire_bytes
                and other_storage.proof_wire_bytes <= storage.proof_wire_bytes
                and other_steps <= steps
            )
            strictly_better = (
                other_storage.checkpoint_bytes < storage.checkpoint_bytes
                or other_storage.signature_wire_bytes < storage.signature_wire_bytes
                or other_storage.proof_wire_bytes < storage.proof_wire_bytes
                or other_steps < steps
            )
            if no_worse and strictly_better:
                dominated = True
                break
        if not dominated:
            survivors.append(storage)
    survivors.sort(
        key=lambda s: (
            profile("merkle", w=s.w, height=s.height).steps,
            s.signature_wire_bytes,
            s.proof_wire_bytes,
            s.checkpoint_bytes,
            s.leaf_count,
            s.w,
            s.height,
        )
    )
    return tuple(survivors)


class MerkleDeploymentFrontierTest(unittest.TestCase):
    def test_matches_brute_force(self):
        cases = (
            (1, (None, None, None, 10_000_000)),
            (4, (None, None, None, 9000)),
            (16, (None, 1300, None, None)),
            (100, (None, None, None, 9000)),
            (256, (None, None, None, 10_000_000)),
            (8, (9000, 1300, 1400, 9000)),
            (2, (3000, None, None, None)),
        )
        for capacity, budgets in cases:
            with self.subTest(capacity=capacity, budgets=budgets):
                result = merkle_deployment_frontier(capacity, budgets)
                self.assertEqual(result, _expected_frontier(capacity, budgets))

    def test_returns_tuple_of_storage_profiles(self):
        result = merkle_deployment_frontier(4, (None, None, None, 9000))
        self.assertIsInstance(result, tuple)
        self.assertTrue(result)
        for storage in result:
            self.assertIsInstance(storage, MerkleStorageProfile)
            self.assertEqual(storage, merkle_storage_profile(storage.w, storage.height))

    def test_tradeoff_keeps_both_w4_and_w8(self):
        # w=4 spends fewer verifier steps but has longer wires and bigger
        # checkpoints; w=8 the reverse, so neither config dominates the
        # other and both stay on the frontier.
        result = merkle_deployment_frontier(4, (None, None, None, 9000))
        configs = {(s.w, s.height) for s in result}
        self.assertIn((4, 2), configs)
        self.assertIn((8, 2), configs)
        w4 = next(s for s in result if s.w == 4)
        w8 = next(s for s in result if s.w == 8)
        self.assertLess(
            profile("merkle", w=4, height=2).steps,
            profile("merkle", w=8, height=2).steps,
        )
        self.assertGreater(w4.signature_wire_bytes, w8.signature_wire_bytes)
        self.assertGreater(w4.checkpoint_bytes, w8.checkpoint_bytes)

    def test_dominated_taller_trees_are_pruned(self):
        # with only a steps budget set, every taller w=4 tree is dominated by
        # the shortest covering w=4 tree (same steps, larger wires/checkpoint)
        result = merkle_deployment_frontier(1, (None, None, None, 1005))
        self.assertEqual([(s.w, s.height) for s in result], [(4, 1)])

    def test_checkpoint_budget_forces_w8(self):
        # w=4 checkpoints start at 4369 bytes; 3000 leaves w=8 only
        result = merkle_deployment_frontier(2, (3000, None, None, None))
        self.assertTrue(result)
        self.assertTrue(
            all(s.w == 8 and s.checkpoint_bytes <= 3000 for s in result)
        )

    def test_signature_budget_filters(self):
        # only w=8 fits 1300-byte signatures; minimal covering height is 4
        result = merkle_deployment_frontier(16, (None, 1300, None, None))
        self.assertTrue(result)
        self.assertTrue(all(s.w == 8 and s.height >= 4 for s in result))
        self.assertTrue(all(s.signature_wire_bytes <= 1300 for s in result))

    def test_proof_budget_filters(self):
        result = merkle_deployment_frontier(8, (None, None, 1260, None))
        self.assertTrue(result)
        self.assertTrue(all(s.proof_wire_bytes <= 1260 for s in result))

    def test_every_result_is_feasible_and_non_dominated(self):
        capacity, budgets = 16, (None, 1300, None, 10_000_000)
        result = merkle_deployment_frontier(capacity, budgets)
        feasible = _feasible(capacity, budgets)
        feasible_set = {storage for storage, _steps in feasible}
        for storage in result:
            self.assertIn(storage, feasible_set)
            self.assertLessEqual(storage.signature_wire_bytes, 1300)
            for other, other_steps in feasible:
                if other == storage:
                    continue
                steps = profile("merkle", w=storage.w, height=storage.height).steps
                no_worse = (
                    other.checkpoint_bytes <= storage.checkpoint_bytes
                    and other.signature_wire_bytes <= storage.signature_wire_bytes
                    and other.proof_wire_bytes <= storage.proof_wire_bytes
                    and other_steps <= steps
                )
                strictly_better = (
                    other.checkpoint_bytes < storage.checkpoint_bytes
                    or other.signature_wire_bytes < storage.signature_wire_bytes
                    or other.proof_wire_bytes < storage.proof_wire_bytes
                    or other_steps < steps
                )
                self.assertFalse(no_worse and strictly_better)

    def test_sorted_stably_by_steps_signature_proof_checkpoint_leaves_w_height(self):
        result = merkle_deployment_frontier(
            4, (None, None, None, 10_000_000)
        )
        keys = [
            (
                profile("merkle", w=s.w, height=s.height).steps,
                s.signature_wire_bytes,
                s.proof_wire_bytes,
                s.checkpoint_bytes,
                s.leaf_count,
                s.w,
                s.height,
            )
            for s in result
        ]
        self.assertEqual(keys, sorted(keys))

    def test_deduplicated_by_value(self):
        result = merkle_deployment_frontier(
            4, (None, None, None, 10_000_000)
        )
        self.assertEqual(len(result), len(set(result)))

    def test_budgets_are_inclusive(self):
        result = merkle_deployment_frontier(4, (None, None, None, 9000))
        # bounds equal to the largest per-dimension value on the frontier must
        # keep every frontier member (equality is feasibility, not violation)
        exact = merkle_deployment_frontier(
            4,
            (
                max(s.checkpoint_bytes for s in result),
                max(s.signature_wire_bytes for s in result),
                max(s.proof_wire_bytes for s in result),
                max(profile("merkle", w=s.w, height=s.height).steps for s in result),
            ),
        )
        self.assertEqual(exact, result)
        # one unit tighter on the smallest signature prunes at least it
        with self.assertRaises(ValueError):
            merkle_deployment_frontier(
                4,
                (None, min(s.signature_wire_bytes for s in result) - 1, None, None),
            )

    def test_tighter_budgets_shrink_frontier_monotonically(self):
        wide = merkle_deployment_frontier(4, (None, None, None, 10_000_000))
        tight = merkle_deployment_frontier(4, (None, None, None, 9000))
        self.assertLessEqual(set(tight), set(wide))

    def test_capacity_forces_height(self):
        result = merkle_deployment_frontier(100, (None, None, None, 10_000_000))
        self.assertTrue(result)
        self.assertTrue(all(s.height >= 7 for s in result))

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            merkle_deployment_frontier(1, (100, None, None, None))
        with self.assertRaises(ValueError):
            merkle_deployment_frontier(256, (None, 1000, None, None))
        with self.assertRaises(ValueError):
            merkle_deployment_frontier(256, (None, None, None, 100))

    def test_budgets_must_be_tuple(self):
        for bad in ([None, None, None, 9000], "budget", None, 7, {1, 2}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_deployment_frontier(4, bad)

    def test_budgets_length(self):
        for bad in ((), (None,), (None, None, None), (None,) * 5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_deployment_frontier(4, bad)

    def test_budget_members_validated(self):
        for bad_member in (0, -1, True, 1.5, "100"):
            for position in range(4):
                bad_budget = [None, None, None, None]
                bad_budget[position] = bad_member
                with self.subTest(bad_member=bad_member, position=position):
                    with self.assertRaises(ValueError):
                        merkle_deployment_frontier(4, tuple(bad_budget))

    def test_at_least_one_budget_required(self):
        with self.assertRaises(ValueError):
            merkle_deployment_frontier(4, (None, None, None, None))

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_deployment_frontier(bad, (None, None, None, 9000))

    def test_arguments_have_no_defaults(self):
        sig = inspect.signature(merkle_deployment_frontier)
        self.assertEqual(list(sig.parameters), ["capacity", "budgets"])
        for parameter in sig.parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        first = merkle_deployment_frontier(4, (None, None, None, 9000))
        second = merkle_deployment_frontier(4, (None, None, None, 9000))
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

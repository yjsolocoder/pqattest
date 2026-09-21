import inspect
import unittest

from pqattest import (
    MerkleSigner,
    MerkleStorageProfile,
    merkle_deployment_frontier,
    merkle_storage_profile,
    profile,
)


def _feasible(capacity, budgets):
    """Brute-force every feasible (storage, steps)."""
    candidates = []
    for candidate_w in (4, 8):
        for candidate_h in range(1, 9):
            storage = merkle_storage_profile(candidate_w, candidate_h)
            if storage.leaf_count < capacity:
                continue
            steps = profile("merkle", w=candidate_w, height=candidate_h).steps
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
                and other_storage.signature_wire_bytes
                <= storage.signature_wire_bytes
                and other_storage.proof_wire_bytes <= storage.proof_wire_bytes
                and other_steps <= steps
            )
            strictly_better = (
                other_storage.checkpoint_bytes < storage.checkpoint_bytes
                or other_storage.signature_wire_bytes
                < storage.signature_wire_bytes
                or other_storage.proof_wire_bytes < storage.proof_wire_bytes
                or other_steps < steps
            )
            if no_worse and strictly_better:
                dominated = True
                break
        if not dominated:
            survivors.append(candidate)
    survivors.sort(
        key=lambda c: (
            c[1],
            c[0].signature_wire_bytes,
            c[0].proof_wire_bytes,
            c[0].checkpoint_bytes,
            c[0].leaf_count,
            c[0].w,
            c[0].height,
        )
    )
    return tuple(storage for storage, _steps in survivors)


class MerkleDeploymentFrontierTest(unittest.TestCase):
    def test_matches_brute_force(self):
        workloads = (
            (1, (None, None, None, 10_000_000)),
            (4, (None, None, None, 9000)),
            (16, (60000, 3000, 3100, None)),
            (256, (None, None, None, 10_000_000)),
            (256, (None, None, None, 8670)),
            (1, (3000, None, None, None)),
            (3, (None, None, None, 1005)),
            (100, (None, None, None, 9000)),
            (128, (140000, None, None, None)),
        )
        for capacity, budgets in workloads:
            with self.subTest(capacity=capacity, budgets=budgets):
                result = merkle_deployment_frontier(capacity, budgets)
                self.assertEqual(
                    result, _expected_frontier(capacity, budgets)
                )

    def test_returns_tuple_of_storage_profiles(self):
        result = merkle_deployment_frontier(4, (None, None, None, 9000))
        self.assertIsInstance(result, tuple)
        self.assertTrue(result)
        for storage in result:
            self.assertIsInstance(storage, MerkleStorageProfile)
            self.assertEqual(
                storage, merkle_storage_profile(storage.w, storage.height)
            )

    def test_tradeoff_keeps_both_w4_and_w8(self):
        # w=4 spends fewer verifier steps but has larger signatures/proofs;
        # w=8 the reverse, so neither config dominates the other and both
        # are on the frontier.
        result = merkle_deployment_frontier(4, (None, None, None, 9000))
        configs = {(p.w, p.height) for p in result}
        self.assertIn((4, 2), configs)
        self.assertIn((8, 2), configs)
        w4 = next(p for p in result if p.w == 4)
        w8 = next(p for p in result if p.w == 8)
        self.assertLess(
            profile("merkle", w=4, height=2).steps,
            profile("merkle", w=8, height=2).steps,
        )
        self.assertGreater(w4.signature_wire_bytes, w8.signature_wire_bytes)
        self.assertGreater(w4.proof_wire_bytes, w8.proof_wire_bytes)

    def test_dominated_taller_trees_are_pruned(self):
        # with only a tight steps budget, every taller w=4 tree is dominated
        # by the shortest covering w=4 tree (same steps, larger everything)
        result = merkle_deployment_frontier(
            1, (None, None, None, 1005)
        )
        self.assertEqual([(p.w, p.height) for p in result], [(4, 1)])
        result8 = merkle_deployment_frontier(
            1, (3000, None, None, None)
        )
        self.assertEqual([(p.w, p.height) for p in result8], [(8, 1)])

    def test_every_result_is_feasible_and_non_dominated(self):
        capacity, budgets = 16, (None, 3000, 3100, 10_000_000)
        result = merkle_deployment_frontier(capacity, budgets)
        feasible = _feasible(capacity, budgets)
        for storage in result:
            steps = profile(
                "merkle", w=storage.w, height=storage.height
            ).steps
            self.assertEqual(
                (storage, steps),
                next(
                    candidate
                    for candidate in feasible
                    if candidate[0] == storage
                ),
            )
            self.assertLessEqual(storage.signature_wire_bytes, 3000)
            self.assertLessEqual(storage.proof_wire_bytes, 3100)
            for other_storage, other_steps in feasible:
                if other_storage == storage:
                    continue
                no_worse = (
                    other_storage.checkpoint_bytes
                    <= storage.checkpoint_bytes
                    and other_storage.signature_wire_bytes
                    <= storage.signature_wire_bytes
                    and other_storage.proof_wire_bytes
                    <= storage.proof_wire_bytes
                    and other_steps <= steps
                )
                strictly_better = (
                    other_storage.checkpoint_bytes
                    < storage.checkpoint_bytes
                    or other_storage.signature_wire_bytes
                    < storage.signature_wire_bytes
                    or other_storage.proof_wire_bytes
                    < storage.proof_wire_bytes
                    or other_steps < steps
                )
                self.assertFalse(no_worse and strictly_better)

    def test_results_sorted_stably(self):
        result = merkle_deployment_frontier(
            16, (None, None, None, 10_000_000)
        )
        keys = [
            (
                profile("merkle", w=p.w, height=p.height).steps,
                p.signature_wire_bytes,
                p.proof_wire_bytes,
                p.checkpoint_bytes,
                p.leaf_count,
                p.w,
                p.height,
            )
            for p in result
        ]
        self.assertEqual(keys, sorted(keys))

    def test_results_deduplicated_by_value(self):
        result = merkle_deployment_frontier(
            4, (None, None, None, 10_000_000)
        )
        self.assertEqual(len(result), len(set(result)))

    def test_sizes_match_real_blobs(self):
        result = merkle_deployment_frontier(
            8, (None, None, None, 10_000_000)
        )
        for storage in result:
            signer = MerkleSigner(w=storage.w, height=storage.height)
            signature = signer.sign(b"m")
            signature_blob = signature.to_bytes(signer.public_key)
            self.assertEqual(
                len(signature_blob), storage.signature_wire_bytes
            )
            checkpoint = signer.checkpoint()
            self.assertEqual(len(checkpoint), storage.checkpoint_bytes)

    def test_budgets_are_inclusive(self):
        result = merkle_deployment_frontier(
            4, (None, None, None, 9000)
        )
        exact = merkle_deployment_frontier(
            4,
            (
                max(p.checkpoint_bytes for p in result),
                max(p.signature_wire_bytes for p in result),
                max(p.proof_wire_bytes for p in result),
                9000,
            ),
        )
        self.assertEqual(exact, result)
        # one unit tighter on the signature bound prunes that profile
        with self.assertRaises(ValueError):
            merkle_deployment_frontier(
                4,
                (
                    None,
                    min(p.signature_wire_bytes for p in result) - 1,
                    None,
                    9000,
                ),
            )

    def test_tighter_budgets_shrink_frontier_monotonically(self):
        wide = merkle_deployment_frontier(
            4, (None, None, None, 10_000_000)
        )
        tight = merkle_deployment_frontier(
            4, (None, None, None, 9000)
        )
        self.assertLessEqual(set(tight), set(wide))

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            merkle_deployment_frontier(1, (100, None, None, None))
        with self.assertRaises(ValueError):
            merkle_deployment_frontier(256, (None, None, None, 100))
        with self.assertRaises(ValueError):
            # capacity forces height 8; its proof is longer than 1100 bytes
            merkle_deployment_frontier(256, (None, None, 1100, None))

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
                with self.subTest(
                    bad_member=bad_member, position=position
                ):
                    with self.assertRaises(ValueError):
                        merkle_deployment_frontier(4, tuple(bad_budget))

    def test_at_least_one_budget_required(self):
        with self.assertRaises(ValueError):
            merkle_deployment_frontier(4, (None, None, None, None))

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_deployment_frontier(
                        bad, (None, None, None, 9000)
                    )

    def test_arguments_have_no_defaults(self):
        sig = inspect.signature(merkle_deployment_frontier)
        self.assertEqual(list(sig.parameters), ["capacity", "budgets"])
        for parameter in sig.parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        first = merkle_deployment_frontier(
            4, (None, None, None, 9000)
        )
        second = merkle_deployment_frontier(
            4, (None, None, None, 9000)
        )
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

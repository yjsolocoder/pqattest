import inspect
import unittest

from pqattest import (
    MerkleBatchProof,
    MerkleSigner,
    MerkleStorageProfile,
    MerkleTransportDeploymentProfile,
    merkle_storage_profile,
    merkle_transport_deployment_frontier,
    merkle_transport_profile,
    multiproof_encode,
    profile,
)

_STEPS = {4: 1005, 8: 8670}


def _feasible(capacity, indices, budgets):
    """Brute-force every feasible (storage, nodes, batch, multi, steps)."""
    required = max(capacity, indices[-1] + 1)
    candidates = []
    for candidate_w in (4, 8):
        for candidate_h in range(1, 9):
            storage = merkle_storage_profile(candidate_w, candidate_h)
            if storage.leaf_count < required:
                continue
            nodes, batch, multi = merkle_transport_profile(
                candidate_w, candidate_h, indices
            )
            steps = _STEPS[candidate_w]
            measured = (storage.checkpoint_bytes, batch, multi, steps)
            if any(
                limit is not None and value > limit
                for value, limit in zip(measured, budgets)
            ):
                continue
            candidates.append((storage, nodes, batch, multi, steps))
    return candidates


def _expected_frontier(capacity, indices, budgets):
    """Brute-force the documented Pareto frontier and ordering."""
    candidates = _feasible(capacity, indices, budgets)
    survivors = []
    for candidate in candidates:
        storage, _nodes, batch, multi, steps = candidate
        dominated = False
        for other in candidates:
            if other is candidate:
                continue
            other_storage, _other_nodes, other_batch, other_multi, other_steps = other
            no_worse = (
                other_storage.checkpoint_bytes <= storage.checkpoint_bytes
                and other_batch <= batch
                and other_multi <= multi
                and other_steps <= steps
            )
            strictly_better = (
                other_storage.checkpoint_bytes < storage.checkpoint_bytes
                or other_batch < batch
                or other_multi < multi
                or other_steps < steps
            )
            if no_worse and strictly_better:
                dominated = True
                break
        if not dominated:
            survivors.append(candidate)
    survivors.sort(
        key=lambda c: (
            c[4],
            c[3],
            c[2],
            c[0].checkpoint_bytes,
            c[0].leaf_count,
            c[0].w,
            c[0].height,
        )
    )
    return tuple(
        MerkleTransportDeploymentProfile(storage, nodes, batch, multi)
        for storage, nodes, batch, multi, _steps in survivors
    )


class MerkleTransportDeploymentFrontierTest(unittest.TestCase):
    def test_matches_brute_force(self):
        workloads = (
            (1, (0,), (None, None, None, 10_000_000)),
            (4, (0, 1), (None, None, None, 9000)),
            (16, (3, 5), (60000, 5000, 5000, None)),
            (256, tuple(range(0, 256, 37)), (None, None, None, 10_000_000)),
            (256, tuple(range(256)), (None, None, None, 8670)),
            (1, (0,), (3000, None, None, None)),
            (3, (0, 1, 2), (None, None, None, 1005)),
            (100, (50, 99), (None, None, None, 9000)),
            (128, (0,), (140_000, None, None, None)),
            (2, (0, 1, 2, 3), (None, None, None, 10_000_000)),
            (8, (2, 7), (None, 5000, None, 9000)),
        )
        for capacity, indices, budgets in workloads:
            with self.subTest(capacity=capacity, indices=indices, budgets=budgets):
                result = merkle_transport_deployment_frontier(
                    capacity, indices, budgets
                )
                self.assertEqual(
                    result, _expected_frontier(capacity, indices, budgets)
                )

    def test_returns_tuple_of_deployment_profiles(self):
        result = merkle_transport_deployment_frontier(
            4, (0, 1), (None, None, None, 9000)
        )
        self.assertIsInstance(result, tuple)
        self.assertTrue(result)
        for deployment in result:
            self.assertIsInstance(deployment, MerkleTransportDeploymentProfile)
            self.assertIsInstance(deployment.config, MerkleStorageProfile)
            self.assertEqual(
                deployment.config,
                merkle_storage_profile(deployment.config.w, deployment.config.height),
            )
            nodes, batch, multi = merkle_transport_profile(
                deployment.config.w, deployment.config.height, (0, 1)
            )
            self.assertEqual(
                (deployment.nodes, deployment.batch, deployment.multi),
                (nodes, batch, multi),
            )

    def test_tradeoff_keeps_both_w4_and_w8(self):
        # w=4 spends fewer verifier steps but has larger transports; w=8 the
        # reverse, so neither config dominates the other and both survive.
        result = merkle_transport_deployment_frontier(
            4, (0, 1), (None, None, None, 9000)
        )
        configs = {(p.config.w, p.config.height) for p in result}
        self.assertIn((4, 2), configs)
        self.assertIn((8, 2), configs)
        w4 = next(p for p in result if p.config.w == 4)
        w8 = next(p for p in result if p.config.w == 8)
        self.assertLess(
            profile("merkle", w=4, height=2).steps,
            profile("merkle", w=8, height=2).steps,
        )
        self.assertGreater(w4.batch, w8.batch)
        self.assertGreater(w4.multi, w8.multi)

    def test_dominated_taller_trees_are_pruned(self):
        # with only a tight steps budget, every taller w=4 tree is dominated
        # by the shortest covering w=4 tree (same steps, larger everything)
        result = merkle_transport_deployment_frontier(
            1, (0,), (None, None, None, 1005)
        )
        self.assertEqual(
            [(p.config.w, p.config.height) for p in result], [(4, 1)]
        )
        result8 = merkle_transport_deployment_frontier(
            1, (0,), (3000, None, None, None)
        )
        self.assertEqual(
            [(p.config.w, p.config.height) for p in result8], [(8, 1)]
        )

    def test_every_result_is_feasible_and_non_dominated(self):
        capacity, indices, budgets = 16, (3, 5), (None, 5000, 5000, 10_000_000)
        result = merkle_transport_deployment_frontier(capacity, indices, budgets)
        feasible = _feasible(capacity, indices, budgets)
        for deployment in result:
            steps = profile(
                "merkle", w=deployment.config.w, height=deployment.config.height
            ).steps
            self.assertEqual(
                (
                    deployment.config,
                    deployment.nodes,
                    deployment.batch,
                    deployment.multi,
                    steps,
                ),
                next(
                    candidate
                    for candidate in feasible
                    if MerkleTransportDeploymentProfile(
                        candidate[0], candidate[1], candidate[2], candidate[3]
                    )
                    == deployment
                ),
            )
            self.assertLessEqual(deployment.batch, 5000)
            self.assertLessEqual(deployment.multi, 5000)
            for other_storage, other_nodes, other_batch, other_multi, other_steps in feasible:
                other = MerkleTransportDeploymentProfile(
                    other_storage, other_nodes, other_batch, other_multi
                )
                if other == deployment:
                    continue
                no_worse = (
                    other_storage.checkpoint_bytes
                    <= deployment.config.checkpoint_bytes
                    and other_batch <= deployment.batch
                    and other_multi <= deployment.multi
                    and other_steps <= steps
                )
                strictly_better = (
                    other_storage.checkpoint_bytes
                    < deployment.config.checkpoint_bytes
                    or other_batch < deployment.batch
                    or other_multi < deployment.multi
                    or other_steps < steps
                )
                self.assertFalse(no_worse and strictly_better)

    def test_results_sorted_stably(self):
        result = merkle_transport_deployment_frontier(
            16, (3, 5), (None, None, None, 10_000_000)
        )
        keys = [
            (
                profile(
                    "merkle", w=p.config.w, height=p.config.height
                ).steps,
                p.multi,
                p.batch,
                p.config.checkpoint_bytes,
                p.config.leaf_count,
                p.config.w,
                p.config.height,
            )
            for p in result
        ]
        self.assertEqual(keys, sorted(keys))

    def test_results_deduplicated_by_value(self):
        result = merkle_transport_deployment_frontier(
            4, (0, 1), (None, None, None, 10_000_000)
        )
        self.assertEqual(len(result), len(set(result)))

    def test_indices_force_height_beyond_capacity(self):
        # capacity 2 needs only height 1, but leaf 3 forces height 2
        result = merkle_transport_deployment_frontier(
            2, (0, 1, 2, 3), (None, None, None, 10_000_000)
        )
        self.assertTrue(result)
        for deployment in result:
            self.assertGreaterEqual(deployment.config.height, 2)
            self.assertEqual(
                deployment,
                next(
                    p
                    for p in _expected_frontier(
                        2, (0, 1, 2, 3), (None, None, None, 10_000_000)
                    )
                    if p == deployment
                ),
            )

    def test_sizes_match_real_blobs(self):
        result = merkle_transport_deployment_frontier(
            16, (3, 5), (None, None, None, 10_000_000)
        )
        for deployment in result:
            signer = MerkleSigner(
                w=deployment.config.w, height=deployment.config.height
            )
            signatures = tuple(signer.sign(b"m%d" % i) for i in range(6))
            chosen = (signatures[3], signatures[5])
            batch = MerkleBatchProof(
                public_key=signer.public_key, signatures=chosen
            ).to_bytes()
            multi = multiproof_encode(signer.public_key, chosen)
            self.assertEqual(len(batch), deployment.batch)
            self.assertEqual(len(multi), deployment.multi)

    def test_budgets_are_inclusive(self):
        result = merkle_transport_deployment_frontier(
            4, (0, 1), (None, None, None, 9000)
        )
        exact = merkle_transport_deployment_frontier(
            4,
            (0, 1),
            (
                max(p.config.checkpoint_bytes for p in result),
                max(p.batch for p in result),
                max(p.multi for p in result),
                9000,
            ),
        )
        self.assertEqual(exact, result)
        # one unit tighter on the multi bound prunes the widest profile
        with self.assertRaises(ValueError):
            merkle_transport_deployment_frontier(
                4,
                (0, 1),
                (None, None, min(p.multi for p in result) - 1, 9000),
            )

    def test_tighter_budgets_shrink_frontier_monotonically(self):
        wide = merkle_transport_deployment_frontier(
            4, (0, 1), (None, None, None, 10_000_000)
        )
        tight = merkle_transport_deployment_frontier(
            4, (0, 1), (None, None, None, 9000)
        )
        self.assertLessEqual(set(tight), set(wide))

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            merkle_transport_deployment_frontier(
                1, (0,), (100, None, None, None)
            )
        with self.assertRaises(ValueError):
            merkle_transport_deployment_frontier(
                256, tuple(range(256)), (None, None, None, 100)
            )
        # capacity forces height 8; the full-leaf-set multiproof exceeds 1100
        with self.assertRaises(ValueError):
            merkle_transport_deployment_frontier(
                256, tuple(range(256)), (None, None, 1100, None)
            )

    def test_indices_must_be_tuple(self):
        for bad in ([0, 1], {0, 1}, "ab", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_transport_deployment_frontier(
                        4, bad, (None, None, None, 9000)
                    )

    def test_index_members_are_value_errors(self):
        for bad in ((0, "1"), (0, 1.0), (0, None), (0, object())):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_deployment_frontier(
                        4, bad, (None, None, None, 9000)
                    )

    def test_index_value_errors(self):
        for bad in (
            (),
            (True,),
            (0, False),
            (-1, 0),
            (7, 7),
            (2, 1),
            (1, 0, 2),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_deployment_frontier(
                        4, bad, (None, None, None, 9000)
                    )

    def test_budgets_must_be_tuple(self):
        for bad in ([None, None, None, 9000], "budget", None, 7, {1, 2}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_transport_deployment_frontier(4, (0, 1), bad)

    def test_budgets_length(self):
        for bad in ((), (None,), (None, None, None), (None,) * 5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_deployment_frontier(4, (0, 1), bad)

    def test_budget_members_validated(self):
        for bad_member in (0, -1, True, 1.5, "100"):
            for position in range(4):
                bad_budget = [None, None, None, None]
                bad_budget[position] = bad_member
                with self.subTest(bad_member=bad_member, position=position):
                    with self.assertRaises(ValueError):
                        merkle_transport_deployment_frontier(
                            4, (0, 1), tuple(bad_budget)
                        )

    def test_at_least_one_budget_required(self):
        with self.assertRaises(ValueError):
            merkle_transport_deployment_frontier(
                4, (0, 1), (None, None, None, None)
            )

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_deployment_frontier(
                        bad, (0,), (None, None, None, 9000)
                    )

    def test_arguments_have_no_defaults(self):
        sig = inspect.signature(merkle_transport_deployment_frontier)
        self.assertEqual(list(sig.parameters), ["capacity", "indices", "budgets"])
        for parameter in sig.parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        first = merkle_transport_deployment_frontier(
            4, (0, 1), (None, None, None, 9000)
        )
        second = merkle_transport_deployment_frontier(
            4, (0, 1), (None, None, None, 9000)
        )
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

import inspect
import unittest

from pqattest import (
    MerkleBatchProof,
    MerkleSigner,
    MerkleTransportWorkloadProfile,
    merkle_mode_frontier,
    merkle_storage_profile,
    merkle_transport_profile,
    profile,
    recommend_merkle_mode_deployment,
    multiproof_encode,
)

# w=4: n=67, steps=1005; w=8: n=34, steps=8670
_GROUPS = ((0,), (2, 3))
_BUDGETS = (None, None, None, 9000, None)


def _carried_nodes(workload, groups):
    return sum(
        merkle_transport_profile(workload.config.w, workload.config.height, group)[0]
        for mode, group in zip(workload.modes, groups)
        if mode == "multiproof"
    )


def _expected(capacity, groups, budgets, *, prefer):
    """Rank merkle_mode_frontier's survivors by the documented preference."""
    frontier = merkle_mode_frontier(capacity, groups, budgets)

    def key(workload):
        peak = max(workload.sizes)
        steps = profile(
            "merkle", w=workload.config.w, height=workload.config.height
        ).steps
        nodes = _carried_nodes(workload, groups)
        tail = (
            workload.config.checkpoint_bytes,
            workload.config.leaf_count,
            workload.config.w,
            workload.config.height,
            workload.modes,
        )
        if prefer == "compact":
            return (workload.total, peak, nodes, steps) + tail
        if prefer == "nodes":
            return (nodes, workload.total, peak, steps) + tail
        return (steps, workload.total, peak, nodes) + tail

    return min(frontier, key=key)


class RecommendMerkleModeDeploymentTest(unittest.TestCase):
    def test_default_prefers_compact(self):
        explicit = recommend_merkle_mode_deployment(
            4, _GROUPS, _BUDGETS, prefer="compact"
        )
        defaulted = recommend_merkle_mode_deployment(4, _GROUPS, _BUDGETS)
        self.assertEqual(defaulted, explicit)
        self.assertEqual(
            defaulted, _expected(4, _GROUPS, _BUDGETS, prefer="compact")
        )

    def test_matches_brute_force_ranking(self):
        workloads = (
            (1, ((0,),), (None, None, None, 10_000_000, None)),
            (4, _GROUPS, (None, None, None, 9000, None)),
            (16, ((3, 5), (0, 1, 2)), (None, None, 20000, None, None)),
            (8, ((2, 7),), (60000, 5000, 5000, 9000, 100)),
            (4, _GROUPS, (None, None, None, None, 3)),
            (2, ((0,), (1,), (2,)), (None, 5000, None, None, None)),
        )
        for prefer in ("compact", "nodes", "speed"):
            for capacity, groups, budgets in workloads:
                with self.subTest(
                    prefer=prefer, capacity=capacity, groups=groups, budgets=budgets
                ):
                    result = recommend_merkle_mode_deployment(
                        capacity, groups, budgets, prefer=prefer
                    )
                    self.assertEqual(
                        result, _expected(capacity, groups, budgets, prefer=prefer)
                    )

    def test_returns_workload_profile(self):
        result = recommend_merkle_mode_deployment(4, _GROUPS, _BUDGETS)
        self.assertIsInstance(result, MerkleTransportWorkloadProfile)
        self.assertIsInstance(result.modes, tuple)
        self.assertIsInstance(result.sizes, tuple)
        self.assertEqual(len(result.modes), len(_GROUPS))
        self.assertEqual(len(result.sizes), len(_GROUPS))
        self.assertEqual(result.total, sum(result.sizes))
        self.assertTrue(
            all(mode in ("batch", "multiproof") for mode in result.modes)
        )

    def test_result_is_on_the_frontier(self):
        for prefer in ("compact", "nodes", "speed"):
            frontier = merkle_mode_frontier(4, _GROUPS, _BUDGETS)
            result = recommend_merkle_mode_deployment(
                4, _GROUPS, _BUDGETS, prefer=prefer
            )
            self.assertIn(result, frontier)

    def test_compact_minimises_total_on_frontier(self):
        frontier = merkle_mode_frontier(4, _GROUPS, _BUDGETS)
        result = recommend_merkle_mode_deployment(4, _GROUPS, _BUDGETS)
        self.assertEqual(result.total, min(workload.total for workload in frontier))

    def test_nodes_minimises_carried_nodes(self):
        frontier = merkle_mode_frontier(4, _GROUPS, _BUDGETS)
        result = recommend_merkle_mode_deployment(
            4, _GROUPS, _BUDGETS, prefer="nodes"
        )
        self.assertEqual(
            _carried_nodes(result, _GROUPS),
            min(_carried_nodes(workload, _GROUPS) for workload in frontier),
        )
        # zero carried nodes means every group is carried as a batch proof
        self.assertEqual(_carried_nodes(result, _GROUPS), 0)
        self.assertTrue(all(mode == "batch" for mode in result.modes))

    def test_speed_minimises_steps_on_frontier(self):
        frontier = merkle_mode_frontier(4, _GROUPS, _BUDGETS)
        result = recommend_merkle_mode_deployment(
            4, _GROUPS, _BUDGETS, prefer="speed"
        )
        steps = [
            profile("merkle", w=p.config.w, height=p.config.height).steps
            for p in frontier
        ]
        self.assertEqual(
            profile("merkle", w=result.config.w, height=result.config.height).steps,
            min(steps),
        )

    def test_modes_tuple_breaks_final_tie(self):
        # the all-batch profile ties nothing, but wherever two profiles share
        # every numeric key, lexicographically smaller modes must win
        groups = ((0,), (1,))
        frontier = merkle_mode_frontier(
            4, groups, (None, None, None, 10_000_000, None)
        )
        for prefer in ("compact", "nodes", "speed"):
            result = recommend_merkle_mode_deployment(
                4,
                groups,
                (None, None, None, 10_000_000, None),
                prefer=prefer,
            )

            def key(workload):
                peak = max(workload.sizes)
                steps = profile(
                    "merkle", w=workload.config.w, height=workload.config.height
                ).steps
                nodes = _carried_nodes(workload, groups)
                tail = (
                    workload.config.checkpoint_bytes,
                    workload.config.leaf_count,
                    workload.config.w,
                    workload.config.height,
                    workload.modes,
                )
                if prefer == "compact":
                    return (workload.total, peak, nodes, steps) + tail
                if prefer == "nodes":
                    return (nodes, workload.total, peak, steps) + tail
                return (steps, workload.total, peak, nodes) + tail

            self.assertEqual(result, min(frontier, key=key))

    def test_different_preferences_can_disagree(self):
        compact = recommend_merkle_mode_deployment(4, _GROUPS, _BUDGETS)
        nodes = recommend_merkle_mode_deployment(
            4, _GROUPS, _BUDGETS, prefer="nodes"
        )
        # compact may carry multiproof nodes to shrink bytes; nodes never
        # carries more nodes than compact does
        self.assertLessEqual(
            _carried_nodes(nodes, _GROUPS), _carried_nodes(compact, _GROUPS)
        )
        # compact never has more aggregate bytes than nodes does
        self.assertLessEqual(compact.total, nodes.total)

    def test_sizes_match_chosen_modes(self):
        result = recommend_merkle_mode_deployment(
            4, _GROUPS, (None, None, None, 10_000_000, None)
        )
        for mode, size, group in zip(result.modes, result.sizes, _GROUPS):
            _nodes, batch, multi = merkle_transport_profile(
                result.config.w, result.config.height, group
            )
            self.assertEqual(size, batch if mode == "batch" else multi)

    def test_sizes_match_real_blobs(self):
        groups = ((3, 5), (0, 1, 2))
        result = recommend_merkle_mode_deployment(
            16, groups, (None, None, 20000, None, None)
        )
        signer = MerkleSigner(w=result.config.w, height=result.config.height)
        signatures = tuple(signer.sign(b"m%d" % i) for i in range(6))
        for mode, size, group in zip(result.modes, result.sizes, groups):
            chosen = tuple(signatures[index] for index in group)
            if mode == "batch":
                blob = MerkleBatchProof(
                    public_key=signer.public_key, signatures=chosen
                ).to_bytes()
            else:
                blob = multiproof_encode(signer.public_key, chosen)
            self.assertEqual(len(blob), size)

    def test_budgets_are_honoured(self):
        capacity, groups = 4, _GROUPS
        budgets = (None, 5000, 12000, 9000, 3)
        for prefer in ("compact", "nodes", "speed"):
            result = recommend_merkle_mode_deployment(
                capacity, groups, budgets, prefer=prefer
            )
            self.assertTrue(all(size <= 5000 for size in result.sizes))
            self.assertLessEqual(result.total, 12000)
            self.assertLessEqual(
                profile(
                    "merkle", w=result.config.w, height=result.config.height
                ).steps,
                9000,
            )
            self.assertLessEqual(_carried_nodes(result, groups), 3)

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            recommend_merkle_mode_deployment(
                1, ((0,),), (100, None, None, None, None)
            )
        with self.assertRaises(ValueError):
            recommend_merkle_mode_deployment(
                1, ((0,),), (None, None, 10, None, None)
            )

    def test_invalid_prefer_raises(self):
        for bad in ("size", "batch", "multiproof", "", "COMPACT", " speed", 7, None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_mode_deployment(
                        4, _GROUPS, _BUDGETS, prefer=bad
                    )

    def test_groups_must_be_tuple(self):
        for bad in ([(0, 1)], {(0, 1)}, "groups", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_mode_deployment(4, bad, _BUDGETS)

    def test_group_members_must_be_tuples(self):
        for bad in (([0, 1],), ({0, 1},), ((0, 1), "ab"), (None,), (7,)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_mode_deployment(4, bad, _BUDGETS)

    def test_index_value_errors(self):
        for bad in (
            (),
            ((),),
            ((True,),),
            ((0, False),),
            ((-1, 0),),
            ((7, 7),),
            ((2, 1),),
            ((0, "1"),),
            ((0, 1.0),),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_mode_deployment(4, bad, _BUDGETS)

    def test_budgets_must_be_tuple(self):
        for bad in ([None] * 5, "budget", None, 7, {1, 2}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_mode_deployment(4, _GROUPS, bad)

    def test_budgets_length(self):
        for bad in ((), (None,), (None, None, None, None), (None,) * 6):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_mode_deployment(4, _GROUPS, bad)

    def test_budget_members_validated(self):
        for bad_member in (0, -1, True, 1.5, "100"):
            for position in range(5):
                bad_budget = [None] * 5
                bad_budget[position] = bad_member
                with self.subTest(bad_member=bad_member, position=position):
                    with self.assertRaises(ValueError):
                        recommend_merkle_mode_deployment(
                            4, _GROUPS, tuple(bad_budget)
                        )

    def test_at_least_one_budget_required(self):
        with self.assertRaises(ValueError):
            recommend_merkle_mode_deployment(
                4, _GROUPS, (None, None, None, None, None)
            )

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_mode_deployment(bad, _GROUPS, _BUDGETS)

    def test_first_three_arguments_have_no_defaults(self):
        sig = inspect.signature(recommend_merkle_mode_deployment)
        self.assertEqual(
            list(sig.parameters), ["capacity", "groups", "budgets", "prefer"]
        )
        for name in ("capacity", "groups", "budgets"):
            self.assertIs(sig.parameters[name].default, inspect.Parameter.empty)
        self.assertEqual(sig.parameters["prefer"].default, "compact")

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        first = recommend_merkle_mode_deployment(
            4, ((0, 1),), (None, None, None, 9000, None)
        )
        second = recommend_merkle_mode_deployment(
            4, ((0, 1),), (None, None, None, 9000, None)
        )
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

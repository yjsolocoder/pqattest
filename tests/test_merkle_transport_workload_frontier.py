import inspect
import unittest

from pqattest import (
    MerkleSigner,
    MerkleTransportWorkloadProfile,
    merkle_storage_profile,
    merkle_transport_profile,
    merkle_transport_workload_frontier,
    profile,
)

# w=4: n=67, steps=1005; w=8: n=34, steps=8670
_GROUPS = ((0,), (2, 3))


def _brute_force_frontier(capacity, groups, budgets):
    """Independently enumerate, filter and Pareto-prune the candidates."""
    required = max([capacity, *(group[-1] + 1 for group in groups)])
    feasible = []
    for candidate_w in (4, 8):
        for candidate_h in range(1, 9):
            storage = merkle_storage_profile(candidate_w, candidate_h)
            if storage.leaf_count < required:
                continue
            if budgets[0] is not None and storage.checkpoint_bytes > budgets[0]:
                continue
            modes = []
            sizes = []
            for group in groups:
                _nodes, batch, multi = merkle_transport_profile(
                    candidate_w, candidate_h, group
                )
                if multi <= batch:
                    modes.append("multiproof")
                    sizes.append(multi)
                else:
                    modes.append("batch")
                    sizes.append(batch)
            if budgets[1] is not None and any(size > budgets[1] for size in sizes):
                continue
            total = sum(sizes)
            if budgets[2] is not None and total > budgets[2]:
                continue
            steps = profile("merkle", w=candidate_w, height=candidate_h).steps
            if budgets[3] is not None and steps > budgets[3]:
                continue
            feasible.append(
                MerkleTransportWorkloadProfile(
                    config=storage, modes=tuple(modes), sizes=tuple(sizes), total=total
                )
            )
    survivors = []
    for candidate in feasible:
        steps = profile(
            "merkle", w=candidate.config.w, height=candidate.config.height
        ).steps
        dominated = False
        for other in feasible:
            if other is candidate:
                continue
            other_steps = profile(
                "merkle", w=other.config.w, height=other.config.height
            ).steps
            if (
                other.config.checkpoint_bytes <= candidate.config.checkpoint_bytes
                and other.total <= candidate.total
                and other_steps <= steps
                and (
                    other.config.checkpoint_bytes < candidate.config.checkpoint_bytes
                    or other.total < candidate.total
                    or other_steps < steps
                )
            ):
                dominated = True
                break
        if not dominated:
            survivors.append(candidate)
    survivors.sort(
        key=lambda p: (
            profile("merkle", w=p.config.w, height=p.config.height).steps,
            p.total,
            p.config.checkpoint_bytes,
            p.config.leaf_count,
            p.config.w,
            p.config.height,
        )
    )
    return tuple(survivors)


class MerkleTransportWorkloadFrontierTest(unittest.TestCase):
    def test_signature_has_three_required_parameters(self):
        signature = inspect.signature(merkle_transport_workload_frontier)
        self.assertEqual(
            list(signature.parameters), ["capacity", "groups", "budgets"]
        )
        for parameter in signature.parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_returns_tuple_of_existing_profile_type(self):
        result = merkle_transport_workload_frontier(
            4, _GROUPS, (None, None, None, 9000)
        )
        self.assertIsInstance(result, tuple)
        self.assertTrue(result)
        for member in result:
            self.assertIs(type(member), MerkleTransportWorkloadProfile)

    def test_matches_brute_force_frontier(self):
        cases = [
            (4, _GROUPS, (None, None, None, 9000)),
            (256, ((0,), (0, 1)), (None, None, None, 10_000_000)),
            (16, ((3, 5), (0, 1, 2)), (None, None, 20000, None)),
            (1, ((0,),), (3000, None, None, None)),
            (8, ((2, 7),), (60000, 5000, 5000, 9000)),
        ]
        for capacity, groups, budgets in cases:
            with self.subTest(capacity=capacity, groups=groups, budgets=budgets):
                result = merkle_transport_workload_frontier(
                    capacity, groups, budgets
                )
                self.assertEqual(
                    result, _brute_force_frontier(capacity, groups, budgets)
                )

    def test_steps_budget_splits_frontier_into_w4_and_w8(self):
        # with a steps bound accepting both w values the trade-off survives:
        # w=4 is faster but its transports are larger, w=8 is the reverse
        result = merkle_transport_workload_frontier(
            4, _GROUPS, (None, None, None, 9000)
        )
        configs = {(member.config.w, member.config.height) for member in result}
        self.assertEqual(configs, {(4, 2), (8, 2)})
        w4 = next(member for member in result if member.config.w == 4)
        w8 = next(member for member in result if member.config.w == 8)
        self.assertLess(
            profile("merkle", w=4, height=2).steps,
            profile("merkle", w=8, height=2).steps,
        )
        self.assertGreater(w4.total, w8.total)
        self.assertGreater(
            w4.config.checkpoint_bytes, w8.config.checkpoint_bytes
        )

    def test_steps_budget_keeps_only_w4(self):
        result = merkle_transport_workload_frontier(
            4, _GROUPS, (None, None, None, 1005)
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].config, merkle_storage_profile(4, 2))

    def test_result_is_sorted_and_stable(self):
        result = merkle_transport_workload_frontier(
            16, ((3, 5), (0, 1, 2)), (None, None, None, 10_000_000)
        )
        keys = [
            (
                profile("merkle", w=member.config.w, height=member.config.height).steps,
                member.total,
                member.config.checkpoint_bytes,
                member.config.leaf_count,
                member.config.w,
                member.config.height,
            )
            for member in result
        ]
        self.assertEqual(keys, sorted(keys))
        # repeated calls return value-identical, equal tuples
        again = merkle_transport_workload_frontier(
            16, ((3, 5), (0, 1, 2)), (None, None, None, 10_000_000)
        )
        self.assertEqual(result, again)

    def test_no_surviving_member_dominates_another(self):
        result = merkle_transport_workload_frontier(
            64,
            ((0,), (3, 5), (8, 9, 10)),
            (None, None, None, 10_000_000),
        )
        measured = [
            (
                member.config.checkpoint_bytes,
                member.total,
                profile("merkle", w=member.config.w, height=member.config.height).steps,
            )
            for member in result
        ]
        for i, a in enumerate(measured):
            for j, b in enumerate(measured):
                if i == j:
                    continue
                self.assertFalse(
                    b[0] <= a[0]
                    and b[1] <= a[1]
                    and b[2] <= a[2]
                    and (b[0] < a[0] or b[1] < a[1] or b[2] < a[2]),
                    (a, b),
                )

    def test_every_member_is_feasible(self):
        budgets = (60000, 5000, 12000, 9000)
        groups = ((2, 7), (0, 1))
        result = merkle_transport_workload_frontier(8, groups, budgets)
        self.assertTrue(result)
        for member in result:
            self.assertLessEqual(member.config.checkpoint_bytes, budgets[0])
            self.assertTrue(all(size <= budgets[1] for size in member.sizes))
            self.assertLessEqual(member.total, budgets[2])
            self.assertLessEqual(
                profile(
                    "merkle", w=member.config.w, height=member.config.height
                ).steps,
                budgets[3],
            )
            self.assertGreaterEqual(member.config.leaf_count, 8)

    def test_every_group_takes_shortest_format_with_multiproof_tie_break(self):
        groups = ((0,), (0, 1))
        result = merkle_transport_workload_frontier(
            256, groups, (None, None, None, 10_000_000)
        )
        # a lone leaf at h=8 has eight carried nodes, so its batch is shorter;
        # an adjacent pair shares nodes and is shorter as a multi-proof
        for member in result:
            self.assertEqual(member.config.height, 8)
            for mode, size, group in zip(member.modes, member.sizes, groups):
                _nodes, batch, multi = merkle_transport_profile(
                    member.config.w, member.config.height, group
                )
                self.assertEqual(size, min(batch, multi))
                self.assertEqual(mode, "multiproof" if multi <= batch else "batch")
            self.assertEqual(member.total, sum(member.sizes))

    def test_sizes_match_real_blobs(self):
        groups = ((3, 5), (0, 1, 2))
        result = merkle_transport_workload_frontier(
            16, groups, (None, None, 20000, None)
        )
        for member in result:
            signer = MerkleSigner(w=member.config.w, height=member.config.height)
            signatures = tuple(signer.sign(b"m%d" % i) for i in range(6))
            for mode, size, group in zip(member.modes, member.sizes, groups):
                from pqattest import MerkleBatchProof, multiproof_encode

                chosen = tuple(signatures[index] for index in group)
                if mode == "batch":
                    blob = MerkleBatchProof(
                        public_key=signer.public_key, signatures=chosen
                    ).to_bytes()
                else:
                    blob = multiproof_encode(signer.public_key, chosen)
                self.assertEqual(len(blob), size)

    def test_groups_force_height_beyond_capacity(self):
        # capacity 2 needs only height 1, but leaf 3 forces height 2
        groups = ((0, 1), (2, 3))
        result = merkle_transport_workload_frontier(
            2, groups, (None, None, None, 9000)
        )
        self.assertTrue(all(member.config.height >= 2 for member in result))
        self.assertEqual(
            result, _brute_force_frontier(2, groups, (None, None, None, 9000))
        )

    def test_tight_per_group_budget_prunes_frontier(self):
        groups = ((0, 1, 2),)
        result = merkle_transport_workload_frontier(
            4, groups, (None, 5000, None, None)
        )
        self.assertTrue(result)
        self.assertTrue(all(size <= 5000 for member in result for size in member.sizes))
        self.assertTrue(all(member.config.height < 8 for member in result))
        smallest = min(size for member in result for size in member.sizes)
        with self.assertRaises(ValueError):
            merkle_transport_workload_frontier(
                4, groups, (None, smallest - 1, None, None)
            )

    def test_no_feasible_candidate_raises(self):
        with self.assertRaises(ValueError):
            merkle_transport_workload_frontier(
                1, ((0,),), (100, None, None, None)
            )
        # leaf 256 cannot exist in any height-8 tree
        with self.assertRaises(ValueError):
            merkle_transport_workload_frontier(
                1, ((256,),), (None, None, None, None)
            )
        # steps below the w=4 minimum
        with self.assertRaises(ValueError):
            merkle_transport_workload_frontier(
                256, (tuple(range(256)),), (None, None, None, 100)
            )
        # total budget below the smallest possible aggregate
        with self.assertRaises(ValueError):
            merkle_transport_workload_frontier(
                1, ((0,),), (None, None, 10, None)
            )

    def test_groups_must_be_tuple(self):
        for bad in ([(0, 1)], {(0, 1)}, "groups", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_transport_workload_frontier(
                        4, bad, (None, None, None, 9000)
                    )

    def test_group_members_must_be_tuples(self):
        for bad in (([0, 1],), ({0, 1},), ((0, 1), "ab"), (None,), (7,)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_transport_workload_frontier(
                        4, bad, (None, None, None, 9000)
                    )

    def test_index_members_are_value_errors(self):
        for bad in (((0, "1"),), ((0, 1.0),), ((0, None),), ((0, object()),)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_workload_frontier(
                        4, bad, (None, None, None, 9000)
                    )

    def test_index_value_errors(self):
        for bad in (
            (),
            ((),),
            ((True,),),
            ((0, False),),
            ((-1, 0),),
            ((7, 7),),
            ((2, 1),),
            ((1, 0, 2),),
            ((0, 1), ()),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_workload_frontier(
                        4, bad, (None, None, None, 9000)
                    )

    def test_budgets_must_be_tuple(self):
        for bad in ([None, None, None, 9000], "budget", None, 7, {1, 2}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_transport_workload_frontier(4, _GROUPS, bad)

    def test_budgets_length(self):
        for bad in ((), (None,), (None, None, None), (None,) * 5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_workload_frontier(4, _GROUPS, bad)

    def test_budget_members_validated(self):
        for bad_member in (0, -1, True, 1.5, "100"):
            for position in range(4):
                bad_budget = [None, None, None, None]
                bad_budget[position] = bad_member
                with self.subTest(bad_member=bad_member, position=position):
                    with self.assertRaises(ValueError):
                        merkle_transport_workload_frontier(
                            4, _GROUPS, tuple(bad_budget)
                        )

    def test_at_least_one_budget_required(self):
        with self.assertRaises(ValueError):
            merkle_transport_workload_frontier(
                4, _GROUPS, (None, None, None, None)
            )

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_transport_workload_frontier(
                        bad, _GROUPS, (None, None, None, 9000)
                    )

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        first = merkle_transport_workload_frontier(
            4, ((0, 1),), (None, None, None, 9000)
        )
        second = merkle_transport_workload_frontier(
            4, ((0, 1),), (None, None, None, 9000)
        )
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

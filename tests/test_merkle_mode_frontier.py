import inspect
import itertools
import unittest

from pqattest import (
    MerkleSigner,
    MerkleTransportWorkloadProfile,
    merkle_mode_frontier,
    merkle_storage_profile,
    merkle_transport_profile,
    profile,
)

_GROUPS = ((0,), (2, 3))


def _feasible(capacity, groups, budgets):
    """Brute-force every feasible (storage, modes, sizes, total, peak, steps, nodes)."""
    required = max([capacity, *(group[-1] + 1 for group in groups)])
    candidates = []
    for candidate_w in (4, 8):
        for candidate_h in range(1, 9):
            storage = merkle_storage_profile(candidate_w, candidate_h)
            if storage.leaf_count < required:
                continue
            measured = [
                merkle_transport_profile(candidate_w, candidate_h, group)
                for group in groups
            ]
            steps = profile("merkle", w=candidate_w, height=candidate_h).steps
            for choice in itertools.product(("batch", "multiproof"), repeat=len(groups)):
                modes = tuple(choice)
                sizes = tuple(
                    batch if mode == "batch" else multi
                    for mode, (_, batch, multi) in zip(modes, measured)
                )
                peak = max(sizes)
                total = sum(sizes)
                nodes = sum(
                    node_count
                    for mode, (node_count, _, _) in zip(modes, measured)
                    if mode == "multiproof"
                )
                values = (storage.checkpoint_bytes, peak, total, steps, nodes)
                if any(
                    limit is not None and value > limit
                    for value, limit in zip(values, budgets)
                ):
                    continue
                candidates.append((storage, modes, sizes, total, peak, steps, nodes))
    return candidates


def _expected_frontier(capacity, groups, budgets):
    candidates = _feasible(capacity, groups, budgets)
    survivors = []
    for candidate in candidates:
        storage, _m, _s, total, peak, steps, nodes = candidate
        dominated = False
        for other in candidates:
            o_storage, _om, _os, o_total, o_peak, o_steps, o_nodes = other
            if other is candidate:
                continue
            no_worse = (
                o_storage.checkpoint_bytes <= storage.checkpoint_bytes
                and o_peak <= peak
                and o_total <= total
                and o_steps <= steps
                and o_nodes <= nodes
            )
            strictly_better = (
                o_storage.checkpoint_bytes < storage.checkpoint_bytes
                or o_peak < peak
                or o_total < total
                or o_steps < steps
                or o_nodes < nodes
            )
            if no_worse and strictly_better:
                dominated = True
                break
        if not dominated:
            survivors.append(candidate)
    unique = {}
    for storage, modes, sizes, total, peak, _steps, nodes in survivors:
        workload = MerkleTransportWorkloadProfile(storage, modes, sizes, total)
        unique.setdefault(workload, (peak, nodes))
    ordered = sorted(
        unique.items(),
        key=lambda item: (
            profile("merkle", w=item[0].config.w, height=item[0].config.height).steps,
            item[0].total,
            item[1][0],
            item[1][1],
            item[0].config.checkpoint_bytes,
            item[0].config.leaf_count,
            item[0].config.w,
            item[0].config.height,
            item[0].modes,
        ),
    )
    return tuple(workload for workload, _aux in ordered)


class MerkleModeFrontierTest(unittest.TestCase):
    def test_matches_brute_force(self):
        workloads = (
            (1, ((0,),), (None, None, None, 10_000_000, None)),
            (4, _GROUPS, (None, None, None, 9000, None)),
            (16, ((3, 5), (0, 1, 2)), (None, None, 20000, None, None)),
            (256, (tuple(range(0, 256, 37)), (255,)), (None, None, None, 10_000_000, None)),
            (8, ((2, 7),), (60000, 5000, 5000, 9000, 30)),
            (4, ((0, 1), (2, 3)), (None, None, None, None, 3)),
            (16, ((3, 5), (0, 1, 2)), (None, 8000, 50000, 9000, 10)),
        )
        for capacity, groups, budgets in workloads:
            with self.subTest(capacity=capacity, groups=groups, budgets=budgets):
                result = merkle_mode_frontier(capacity, groups, budgets)
                self.assertEqual(result, _expected_frontier(capacity, groups, budgets))

    def test_enumerates_all_mode_combinations(self):
        groups = ((0,), (2, 3))
        result = merkle_mode_frontier(4, groups, (None, None, None, 10_000_000, None))
        mode_sets = {p.modes for p in result}
        # the all-batch and all-multiproof extremes must both be represented
        self.assertIn(("batch", "batch"), mode_sets)
        self.assertIn(("multiproof", "multiproof"), mode_sets)
        for workload in result:
            self.assertEqual(len(workload.modes), 2)
            self.assertEqual(len(workload.sizes), 2)
            self.assertEqual(workload.total, sum(workload.sizes))
            for mode, size, group in zip(workload.modes, workload.sizes, groups):
                _, batch, multi = merkle_transport_profile(
                    workload.config.w, workload.config.height, group
                )
                self.assertEqual(size, batch if mode == "batch" else multi)

    def test_node_budget_only_counts_multiproof_groups(self):
        groups = ((0,), (2, 3))
        # at height 2 the all-multiproof workload carries 3 nodes, the
        # (batch, multiproof) workload 1 and the all-batch workload 0
        result = merkle_mode_frontier(4, groups, (None, None, None, 10_000_000, 1))
        mode_sets = {p.modes for p in result}
        self.assertNotIn(("multiproof", "multiproof"), mode_sets)
        self.assertNotIn(("multiproof", "batch"), mode_sets)
        self.assertIn(("batch", "batch"), mode_sets)
        self.assertIn(("batch", "multiproof"), mode_sets)
        for workload in result:
            nodes = sum(
                merkle_transport_profile(
                    workload.config.w, workload.config.height, group
                )[0]
                for mode, group in zip(workload.modes, groups)
                if mode == "multiproof"
            )
            self.assertLessEqual(nodes, 1)

    def test_sorting_includes_modes_tie_break(self):
        result = merkle_mode_frontier(
            4, _GROUPS, (None, None, None, 10_000_000, None)
        )
        keys = []
        for workload in result:
            storage = workload.config
            measured = [
                merkle_transport_profile(storage.w, storage.height, group)
                for group in _GROUPS
            ]
            nodes = sum(
                node_count
                for mode, (node_count, _, _) in zip(workload.modes, measured)
                if mode == "multiproof"
            )
            keys.append(
                (
                    profile("merkle", w=storage.w, height=storage.height).steps,
                    workload.total,
                    max(workload.sizes),
                    nodes,
                    storage.checkpoint_bytes,
                    storage.leaf_count,
                    storage.w,
                    storage.height,
                    workload.modes,
                )
            )
        self.assertEqual(keys, sorted(keys))

    def test_deduplicated(self):
        result = merkle_mode_frontier(
            4, _GROUPS, (None, None, None, 10_000_000, None)
        )
        self.assertEqual(len(result), len(set(result)))

    def test_sizes_match_real_blobs(self):
        from pqattest import MerkleBatchProof, multiproof_encode

        groups = ((3, 5), (0, 1, 2))
        result = merkle_mode_frontier(16, groups, (None, None, None, 10_000_000, None))
        for workload in result:
            signer = MerkleSigner(w=workload.config.w, height=workload.config.height)
            signatures = tuple(signer.sign(b"m%d" % i) for i in range(6))
            for mode, size, group in zip(workload.modes, workload.sizes, groups):
                chosen = tuple(signatures[index] for index in group)
                if mode == "batch":
                    blob = MerkleBatchProof(
                        public_key=signer.public_key, signatures=chosen
                    ).to_bytes()
                else:
                    blob = multiproof_encode(signer.public_key, chosen)
                self.assertEqual(len(blob), size)

    def test_no_feasible_raises(self):
        with self.assertRaises(ValueError):
            merkle_mode_frontier(1, ((0,),), (100, None, None, None, None))
        with self.assertRaises(ValueError):
            merkle_mode_frontier(1, ((256,),), (None, None, None, None, None))
        with self.assertRaises(ValueError):
            merkle_mode_frontier(1, ((0,),), (None, None, 10, None, None))
        with self.assertRaises(ValueError):
            merkle_mode_frontier(4, _GROUPS, (None, None, None, 100, None))

    def test_type_errors(self):
        for bad in ([(0, 1)], {(0, 1)}, "x", None, 7):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_mode_frontier(4, bad, (None,) * 4 + (1,))
        for bad in (([0, 1],), ({0, 1},), (None,), (7,)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_mode_frontier(4, bad, (None,) * 4 + (1,))
        for bad in ([None] * 5, "x", None, 7, {1}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_mode_frontier(4, _GROUPS, bad)

    def test_value_errors(self):
        for bad in ((), ((),), ((True,),), ((-1, 0),), ((2, 1),), ((1, 1),)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_mode_frontier(4, bad, (None,) * 4 + (1,))
        for bad in ((), (None,) * 4, (None,) * 6):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_mode_frontier(4, _GROUPS, bad)
        for bad_member in (0, -1, True, 1.5, "1"):
            for position in range(5):
                bad_budget = [None] * 5
                bad_budget[position] = bad_member
                with self.subTest(bad_member=bad_member, position=position):
                    with self.assertRaises(ValueError):
                        merkle_mode_frontier(4, _GROUPS, tuple(bad_budget))
        with self.assertRaises(ValueError):
            merkle_mode_frontier(4, _GROUPS, (None,) * 5)
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_mode_frontier(bad, _GROUPS, (None,) * 4 + (1,))

    def test_no_defaults_and_pure(self):
        sig = inspect.signature(merkle_mode_frontier)
        self.assertEqual(list(sig.parameters), ["capacity", "groups", "budgets"])
        for parameter in sig.parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)
        signer = MerkleSigner(w=4, height=2)
        first = merkle_mode_frontier(4, ((0, 1),), (None, None, None, 9000, None))
        second = merkle_mode_frontier(4, ((0, 1),), (None, None, None, 9000, None))
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

import itertools
import unittest

from pqattest import (
    MerkleSigner,
    merkle_verify_profile,
    multiproof_encode,
    multiproof_merge,
    multiproof_partition,
    multiproof_partition_frontier,
    multiproof_select,
    multiproof_verify_bound,
)
from pqattest.merkle import _multiproof_parse


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=3, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def make_proof(height=3, w=4, count=None, start=0, context=None,
               contexts=None, keep=None):
    signer = make_signer(height=height, w=w, start=start)
    leaf_count = 1 << height
    if count is None and keep is None:
        count = leaf_count
    if keep is not None:
        messages = tuple(f"message-{i}" for i in keep)
        if contexts is not None:
            signatures = signer.sign_selected(
                tuple(keep), messages, contexts=contexts
            )
        elif context is not None:
            signatures = signer.sign_selected(
                tuple(keep), messages, context=context
            )
        else:
            signatures = signer.sign_selected(tuple(keep), messages)
    else:
        messages = tuple(f"message-{i}" for i in range(count))
        if contexts is not None:
            signatures = signer.sign_batch(messages, contexts=contexts)
        elif context is not None:
            signatures = signer.sign_batch(messages, context=context)
        else:
            signatures = signer.sign_batch(messages)
    proof = multiproof_encode(signer.public_key, signatures)
    return signer.public_key, messages, signatures, proof


def packet_costs(public_key, packets):
    """The frontier cost triple of a plan: (count, bytes, hashes)."""
    total_bytes = 0
    total_hashes = 0
    for packet in packets:
        total_bytes += len(packet)
        _, leaves, _ = _multiproof_parse(packet)
        indices = tuple(index for index, _ in leaves)
        profile = merkle_verify_profile(public_key.w, public_key.height, indices)
        total_hashes += profile.wots + profile.leaf + profile.multi
    return (len(packets), total_bytes, total_hashes)


def brute_force_frontier(messages, proof, public_key, max_bytes,
                         max_verify_hashes=None, max_total_verify_hashes=None,
                         max_total_bytes=None, context=None, contexts=None):
    """Exhaustively enumerate every feasible consecutive fragmentation.

    Returns the Pareto frontier of cost triples as a tuple of packet
    tuples, built straight from the original signatures, applying the
    domination and tie-breaking rules of the public entry literally.
    """
    kwargs = {"public_key": public_key}
    if contexts is not None:
        kwargs["contexts"] = contexts
    elif context is not None:
        kwargs["context"] = context
    from pqattest import multiproof_expand

    batch = multiproof_expand(messages, proof, **kwargs)
    signatures = batch.signatures
    n = len(signatures)
    sizes, hashes = {}, {}
    for start in range(n):
        for end in range(start + 1, n + 1):
            fragment = tuple(signatures[start:end])
            sizes[(start, end)] = len(multiproof_encode(public_key, fragment))
            profile = merkle_verify_profile(
                public_key.w,
                public_key.height,
                tuple(signature.index for signature in fragment),
            )
            hashes[(start, end)] = profile.wots + profile.leaf + profile.multi
    plans = {}
    for cuts in range(1, n + 1):
        for inner in itertools.combinations(range(1, n), cuts - 1):
            bounds = (0,) + inner + (n,)
            total_bytes = 0
            total_hashes = 0
            ends = []
            feasible = True
            for start, end in zip(bounds, bounds[1:]):
                size = sizes[(start, end)]
                work = hashes[(start, end)]
                if size > max_bytes:
                    feasible = False
                    break
                if max_verify_hashes is not None and work > max_verify_hashes:
                    feasible = False
                    break
                total_bytes += size
                total_hashes += work
                ends.append(signatures[end - 1].index)
            if not feasible:
                continue
            if max_total_bytes is not None and total_bytes > max_total_bytes:
                continue
            if max_total_verify_hashes is not None and (
                total_hashes > max_total_verify_hashes
            ):
                continue
            key = (cuts, total_bytes, total_hashes)
            ends = tuple(ends)
            if key not in plans or ends < plans[key]:
                plans[key] = ends
    frontier = []
    for key in sorted(plans):
        if any(
            other[0] <= key[0]
            and other[1] <= key[1]
            and other[2] <= key[2]
            and other != key
            for other in plans
        ):
            continue
        frontier.append(plans[key])
    result = []
    for ends in frontier:
        packets = []
        start = 0
        for index in ends:
            stop = next(
                position
                for position, signature in enumerate(signatures)
                if signature.index == index
            ) + 1
            packets.append(
                multiproof_encode(public_key, tuple(signatures[start:stop]))
            )
            start = stop
        result.append(tuple(packets))
    return tuple(result)


class TestFrontierMatchesBruteForce(unittest.TestCase):
    def check(self, messages, proof, public_key, budgets, **kwargs):
        expected = brute_force_frontier(
            messages, proof, public_key, **budgets, **kwargs
        )
        if not expected:
            with self.assertRaises(ValueError):
                multiproof_partition_frontier(
                    messages, proof, public_key=public_key, **budgets, **kwargs
                )
            return None
        result = multiproof_partition_frontier(
            messages, proof, public_key=public_key, **budgets, **kwargs
        )
        self.assertEqual(result, expected)
        return result

    def test_byte_budget_only_all_heights_and_w(self):
        for w in (4, 8):
            for height in range(1, 9):
                keep = tuple(range(min(1 << height, 6)))
                with self.subTest(w=w, height=height):
                    public_key, messages, _, proof = make_proof(
                        w=w, height=height, keep=keep
                    )
                    full = len(proof)
                    for divisor in (1, 2, 3):
                        with self.subTest(divisor=divisor):
                            self.check(
                                messages,
                                proof,
                                public_key,
                                {"max_bytes": max(1, full // divisor)},
                            )

    def test_sparse_leaves(self):
        for w in (4, 8):
            for keep in ((0, 3, 7, 11, 15), (1, 2, 5, 8, 13), (2, 9), (5,)):
                with self.subTest(w=w, keep=keep):
                    public_key, messages, _, proof = make_proof(
                        w=w, height=4, keep=keep
                    )
                    for divisor in (1, 2, 3):
                        with self.subTest(divisor=divisor):
                            self.check(
                                messages,
                                proof,
                                public_key,
                                {"max_bytes": max(1, len(proof) // divisor)},
                            )

    def test_all_budgets_together(self):
        for w in (4, 8):
            with self.subTest(w=w):
                public_key, messages, _, proof = make_proof(
                    w=w, height=4, keep=(0, 3, 7, 11, 15)
                )
                full_hashes = packet_costs(public_key, (bytes(proof),))[2]
                for hash_divisor, total_slack in ((2, 2), (3, 3), (2, 1)):
                    budgets = {
                        "max_bytes": max(1, len(proof) // 2),
                        "max_verify_hashes": max(1, full_hashes // hash_divisor),
                        "max_total_verify_hashes": full_hashes * total_slack,
                        "max_total_bytes": len(proof) * total_slack,
                    }
                    with self.subTest(**budgets):
                        self.check(messages, proof, public_key, budgets)

    def test_each_budget_individually(self):
        public_key, messages, _, proof = make_proof(
            height=4, keep=(0, 3, 7, 11, 15)
        )
        full_hashes = packet_costs(public_key, (bytes(proof),))[2]
        budget_sets = (
            {"max_bytes": len(proof)},
            {"max_bytes": len(proof), "max_verify_hashes": full_hashes // 2},
            {
                "max_bytes": len(proof),
                "max_total_verify_hashes": full_hashes * 2,
            },
            {"max_bytes": len(proof), "max_total_bytes": len(proof) * 2},
        )
        for budgets in budget_sets:
            with self.subTest(budgets=budgets):
                self.check(messages, proof, public_key, budgets)

    def test_shared_context(self):
        for w in (4, 8):
            with self.subTest(w=w):
                public_key, messages, _, proof = make_proof(
                    w=w, height=4, count=6, context="shared-context"
                )
                self.check(
                    messages,
                    proof,
                    public_key,
                    {"max_bytes": max(1, len(proof) // 2)},
                    context="shared-context",
                )

    def test_per_leaf_contexts(self):
        for w in (4, 8):
            contexts = tuple(f"leaf-context-{i}" for i in range(6))
            with self.subTest(w=w):
                public_key, messages, _, proof = make_proof(
                    w=w, height=4, count=6, contexts=contexts
                )
                self.check(
                    messages,
                    proof,
                    public_key,
                    {"max_bytes": max(1, len(proof) // 2)},
                    contexts=contexts,
                )

    def test_full_tree_small_heights(self):
        for w in (4, 8):
            for height in (1, 2, 3):
                with self.subTest(w=w, height=height):
                    public_key, messages, _, proof = make_proof(
                        w=w, height=height
                    )
                    self.check(
                        messages,
                        proof,
                        public_key,
                        {"max_bytes": max(1, len(proof) // 2)},
                    )

    def test_single_leaf(self):
        for w in (4, 8):
            for height in (1, 5, 8):
                with self.subTest(w=w, height=height):
                    public_key, messages, _, proof = make_proof(
                        w=w, height=height, keep=(0,)
                    )
                    result = self.check(
                        messages,
                        proof,
                        public_key,
                        {"max_bytes": len(proof)},
                    )
                    self.assertEqual(result, ((bytes(proof),),))

    def test_repeated_messages_stay_on_separate_leaves(self):
        signer = make_signer(height=3)
        messages = ("same", "same", "same", "other")
        signatures = signer.sign_batch(messages)
        proof = multiproof_encode(signer.public_key, signatures)
        result = multiproof_partition_frontier(
            messages,
            proof,
            public_key=signer.public_key,
            max_bytes=len(proof) // 2,
        )
        for plan in result:
            covered = []
            for packet in plan:
                _, leaves, _ = _multiproof_parse(packet)
                covered.extend(index for index, _ in leaves)
            self.assertEqual(covered, [0, 1, 2, 3])


class TestFrontierShape(unittest.TestCase):
    def test_result_is_sorted_and_non_dominated(self):
        public_key, messages, _, proof = make_proof(
            height=4, keep=(0, 3, 7, 11, 15)
        )
        result = multiproof_partition_frontier(
            messages, proof, public_key=public_key, max_bytes=len(proof)
        )
        self.assertTrue(result)
        costs = [packet_costs(public_key, plan) for plan in result]
        self.assertEqual(costs, sorted(costs))
        self.assertEqual(len(set(costs)), len(costs))
        for position, cost in enumerate(costs):
            for other in costs:
                if other == cost:
                    continue
                dominated = (
                    other[0] <= cost[0]
                    and other[1] <= cost[1]
                    and other[2] <= cost[2]
                )
                self.assertFalse(dominated, (position, cost, other))
        for plan in result:
            self.assertTrue(plan)
            for packet in plan:
                self.assertIsInstance(packet, bytes)

    def test_frontier_has_multiple_plans_when_tradeoffs_exist(self):
        # A fragmentation with one more packet can spend a few more
        # header bytes to buy fewer deduplicated internal-node hashes,
        # so both plans stay non-dominated.
        public_key, messages, _, proof = make_proof(
            height=5, keep=(3, 8, 12, 16, 23, 30)
        )
        result = multiproof_partition_frontier(
            messages, proof, public_key=public_key,
            max_bytes=len(proof) // 2,
        )
        costs = [packet_costs(public_key, plan) for plan in result]
        self.assertEqual(len(result), 2)
        self.assertEqual(costs[0][0], 3)
        self.assertEqual(costs[1][0], 4)
        # The extra packet costs more total bytes but fewer total hashes.
        self.assertGreater(costs[1][1], costs[0][1])
        self.assertLess(costs[1][2], costs[0][2])

    def test_single_packet_plan_is_present_when_source_fits(self):
        for w in (4, 8):
            with self.subTest(w=w):
                public_key, messages, _, proof = make_proof(w=w, height=3)
                result = multiproof_partition_frontier(
                    messages, proof, public_key=public_key, max_bytes=len(proof)
                )
                self.assertEqual(result[0], (bytes(proof),))

    def test_plans_cover_leaves_exactly_once_in_order(self):
        public_key, messages, _, proof = make_proof(
            height=4, keep=(1, 2, 5, 8, 13)
        )
        result = multiproof_partition_frontier(
            messages, proof, public_key=public_key, max_bytes=len(proof) // 2
        )
        for plan in result:
            covered = []
            for packet in plan:
                _, leaves, _ = _multiproof_parse(packet)
                covered.extend(index for index, _ in leaves)
            self.assertEqual(covered, [1, 2, 5, 8, 13])

    def test_each_packet_equals_select_of_same_fragment(self):
        public_key, messages, _, proof = make_proof(
            height=4, keep=(0, 3, 7, 11, 15)
        )
        result = multiproof_partition_frontier(
            messages, proof, public_key=public_key, max_bytes=len(proof) // 2
        )
        for plan in result:
            for packet in plan:
                _, leaves, _ = _multiproof_parse(packet)
                indices = tuple(index for index, _ in leaves)
                expected = multiproof_select(
                    messages, proof, public_key=public_key, indices=indices
                )
                self.assertEqual(packet, expected)

    def test_packets_verify_independently_and_remerge(self):
        contexts = tuple(f"ctx-{i}" for i in range(5))
        public_key, messages, _, proof = make_proof(
            height=4, keep=(0, 3, 7, 11, 15), contexts=contexts
        )
        result = multiproof_partition_frontier(
            messages,
            proof,
            public_key=public_key,
            max_bytes=len(proof) // 2,
            contexts=contexts,
        )
        for plan in result:
            message_groups = []
            context_groups = []
            position = 0
            for packet in plan:
                _, leaves, _ = _multiproof_parse(packet)
                count = len(leaves)
                group_messages = messages[position:position + count]
                group_contexts = contexts[position:position + count]
                self.assertTrue(
                    multiproof_verify_bound(
                        group_messages,
                        packet,
                        public_key=public_key,
                        contexts=group_contexts,
                    )
                )
                message_groups.append(group_messages)
                context_groups.append(group_contexts)
                position += count
            merged = multiproof_merge(
                tuple(message_groups),
                plan,
                public_key=public_key,
                context_groups=tuple(context_groups),
            )
            self.assertEqual(merged, bytes(proof))

    def test_budget_equality_is_allowed(self):
        public_key, messages, _, proof = make_proof(
            height=4, keep=(0, 3, 7, 11, 15)
        )
        result = multiproof_partition_frontier(
            messages, proof, public_key=public_key, max_bytes=len(proof)
        )
        for plan in result:
            count, total_bytes, total_hashes = packet_costs(public_key, plan)
            with self.subTest(cost=(count, total_bytes, total_hashes)):
                exact = multiproof_partition_frontier(
                    messages,
                    proof,
                    public_key=public_key,
                    max_bytes=max(len(packet) for packet in plan),
                    max_verify_hashes=max(
                        packet_costs(public_key, (packet,))[2]
                        for packet in plan
                    ),
                    max_total_verify_hashes=total_hashes,
                    max_total_bytes=total_bytes,
                )
                self.assertIn(plan, exact)

    def test_result_is_deterministic_and_does_not_alias_input(self):
        public_key, messages, _, proof = make_proof(
            height=4, keep=(0, 3, 7, 11, 15)
        )
        mutable = bytearray(proof)
        first = multiproof_partition_frontier(
            messages, mutable, public_key=public_key, max_bytes=len(proof) // 2
        )
        second = multiproof_partition_frontier(
            messages, mutable, public_key=public_key, max_bytes=len(proof) // 2
        )
        self.assertEqual(first, second)
        mutable[:] = b"\x00" * len(mutable)
        self.assertEqual(first, second)
        for plan in first:
            for packet in plan:
                self.assertIsInstance(packet, bytes)

    def test_inputs_are_not_modified(self):
        public_key, messages, _, proof = make_proof(
            height=3, contexts=tuple(f"c-{i}" for i in range(8))
        )
        contexts = tuple(f"c-{i}" for i in range(8))
        messages_before = tuple(messages)
        proof_before = bytes(proof)
        multiproof_partition_frontier(
            messages,
            proof,
            public_key=public_key,
            max_bytes=len(proof) // 2,
            contexts=contexts,
        )
        self.assertEqual(messages, messages_before)
        self.assertEqual(bytes(proof), proof_before)
        self.assertEqual(contexts, tuple(f"c-{i}" for i in range(8)))


class TestFrontierErrors(unittest.TestCase):
    def setUp(self):
        self.public_key, self.messages, _, self.proof = make_proof(height=3)

    def frontier(self, **overrides):
        kwargs = {
            "public_key": self.public_key,
            "max_bytes": len(self.proof),
        }
        kwargs.update(overrides)
        return multiproof_partition_frontier(self.messages, self.proof, **kwargs)

    def test_type_errors(self):
        bad_calls = [
            {"messages": list(self.messages)},
            {"messages": ("ok", 3)},
            {"data": "not-bytes"},
            {"public_key": object()},
            {"max_bytes": "1000"},
            {"max_bytes": 1.5},
            {"max_verify_hashes": "7"},
            {"max_total_verify_hashes": 1.5},
            {"max_total_bytes": b"x"},
            {"context": 3},
            {"contexts": ["a"] * len(self.messages)},
            {"contexts": (object(),) * len(self.messages)},
        ]
        for overrides in bad_calls:
            with self.subTest(overrides=overrides):
                messages = overrides.pop("messages", self.messages)
                data = overrides.pop("data", self.proof)
                kwargs = {"public_key": self.public_key, "max_bytes": len(self.proof)}
                kwargs.update(overrides)
                with self.assertRaises(TypeError):
                    multiproof_partition_frontier(messages, data, **kwargs)

    def test_type_check_precedes_content_check(self):
        # A non-integer budget is a TypeError even when the messages are
        # empty and the proof is malformed (both ValueError cases).
        with self.assertRaises(TypeError):
            multiproof_partition_frontier(
                (), b"junk", public_key=self.public_key, max_bytes="x"
            )
        with self.assertRaises(TypeError):
            multiproof_partition_frontier(
                (), b"junk", public_key=self.public_key, max_bytes=10,
                max_verify_hashes="x",
            )
        with self.assertRaises(TypeError):
            multiproof_partition_frontier(
                (), b"junk", public_key=object(), max_bytes=10
            )

    def test_value_errors(self):
        with self.assertRaises(ValueError):
            self.frontier(max_bytes=True)
        with self.assertRaises(ValueError):
            self.frontier(max_bytes=0)
        with self.assertRaises(ValueError):
            self.frontier(max_bytes=-5)
        with self.assertRaises(ValueError):
            self.frontier(max_verify_hashes=False)
        with self.assertRaises(ValueError):
            self.frontier(max_verify_hashes=0)
        with self.assertRaises(ValueError):
            self.frontier(max_total_verify_hashes=-1)
        with self.assertRaises(ValueError):
            self.frontier(max_total_bytes=0)
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                (), self.proof, public_key=self.public_key,
                max_bytes=len(self.proof),
            )
        with self.assertRaises(ValueError):
            self.frontier(contexts=())
        with self.assertRaises(ValueError):
            self.frontier(context="shared", contexts=(None,) * len(self.messages))
        with self.assertRaises(ValueError):
            self.frontier(contexts=(None,) * (len(self.messages) + 1))
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                self.messages + ("extra",),
                self.proof,
                public_key=self.public_key,
                max_bytes=len(self.proof),
            )
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                self.messages, b"not a proof",
                public_key=self.public_key, max_bytes=len(self.proof),
            )
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                ("wrong",) + self.messages[1:],
                self.proof,
                public_key=self.public_key,
                max_bytes=len(self.proof),
            )

    def test_public_key_mismatch(self):
        other = make_signer(height=3, start=1000)
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                self.messages,
                self.proof,
                public_key=other.public_key,
                max_bytes=len(self.proof),
            )

    def test_context_mismatch(self):
        public_key, messages, _, proof = make_proof(
            height=3, context="right"
        )
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                messages, proof, public_key=public_key,
                max_bytes=len(proof), context="wrong",
            )
        contexts = tuple(f"ctx-{i}" for i in range(len(messages)))
        public_key, messages, _, proof = make_proof(
            height=3, contexts=contexts
        )
        wrong = ("nope",) + contexts[1:]
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                messages, proof, public_key=public_key,
                max_bytes=len(proof), contexts=wrong,
            )

    def test_infeasible_budgets(self):
        # A single leaf's own packet already exceeds the byte budget.
        _, leaves, _ = _multiproof_parse(self.proof)
        one = multiproof_select(
            self.messages, self.proof,
            public_key=self.public_key, indices=(leaves[0][0],),
        )
        with self.assertRaises(ValueError):
            self.frontier(max_bytes=len(one) - 1)
        # The total hash bill can never drop below the one-packet bill's
        # per-leaf W-OTS and leaf contributions; a tiny total is infeasible.
        with self.assertRaises(ValueError):
            self.frontier(max_total_verify_hashes=1)
        with self.assertRaises(ValueError):
            self.frontier(max_total_bytes=len(one) - 1)

    def test_keyword_only_arguments(self):
        with self.assertRaises(TypeError):
            multiproof_partition_frontier(
                self.messages, self.proof, self.public_key, len(self.proof)
            )

    def test_no_prefer_parameter(self):
        with self.assertRaises(TypeError):
            self.frontier(prefer="compact")

    def test_source_fully_verified_even_with_generous_budget(self):
        # Corrupt the last leaf's W-OTS elements: even though the budget
        # admits the source as a single packet, the failure must surface.
        data = bytearray(self.proof)
        data[-1] ^= 0x01
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                self.messages, bytes(data),
                public_key=self.public_key, max_bytes=len(self.proof),
            )


class TestFrontierAgainstPartition(unittest.TestCase):
    def test_verify_winner_is_on_the_frontier(self):
        # The "verify" preference minimises total hashes first, so its
        # cost triple is never dominated and must appear on the frontier.
        for w in (4, 8):
            with self.subTest(w=w):
                public_key, messages, _, proof = make_proof(
                    w=w, height=4, keep=(0, 3, 7, 11, 15)
                )
                budgets = {"max_bytes": max(1, len(proof) // 2)}
                winner = multiproof_partition(
                    messages, proof, public_key=public_key,
                    prefer="verify", **budgets,
                )
                result = multiproof_partition_frontier(
                    messages, proof, public_key=public_key, **budgets
                )
                self.assertIn(winner, result)

    def test_frontier_not_limited_to_prefer_winners(self):
        # The compact winner minimises packet count first, yet a plan
        # with more packets can stay non-dominated by billing fewer
        # verification hashes; the frontier must still list it.
        public_key, messages, _, proof = make_proof(
            height=5, keep=(3, 8, 12, 16, 23, 30)
        )
        budgets = {"max_bytes": len(proof) // 2}
        compact = multiproof_partition(
            messages, proof, public_key=public_key, prefer="compact", **budgets
        )
        result = multiproof_partition_frontier(
            messages, proof, public_key=public_key, **budgets
        )
        self.assertIn(compact, result)
        self.assertTrue(
            any(len(plan) > len(compact) for plan in result),
            [packet_costs(public_key, plan) for plan in result],
        )


if __name__ == "__main__":
    unittest.main()

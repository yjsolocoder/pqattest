import itertools
import unittest

from pqattest import (
    MerkleSigner,
    merkle_verify_profile,
    multiproof_encode,
    multiproof_expand,
    multiproof_merge,
    multiproof_partition,
    multiproof_partition_frontier,
    multiproof_select,
    multiproof_verify,
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


def proof_hashes(public_key, indices):
    """wots + leaf + multi the profile bills an actual leaf-index tuple."""
    profile = merkle_verify_profile(public_key.w, public_key.height, indices)
    return profile.wots + profile.leaf + profile.multi


def scheme_cost(public_key, packets):
    """The frontier cost triple of a returned packet tuple."""
    total_hashes = 0
    ends = ()
    for packet in packets:
        _, leaves, _ = _multiproof_parse(packet)
        indices = tuple(index for index, _ in leaves)
        total_hashes += proof_hashes(public_key, indices)
        ends += (indices[-1],)
    return (
        len(packets),
        sum(len(packet) for packet in packets),
        total_hashes,
        ends,
    )


def context_kwargs(context=None, contexts=None):
    if contexts is not None:
        return {"contexts": contexts}
    if context is not None:
        return {"context": context}
    return {}


def brute_force_frontier(
    messages,
    proof,
    public_key,
    max_bytes,
    max_verify_hashes=None,
    max_total_verify_hashes=None,
    max_total_bytes=None,
    context=None,
    contexts=None,
):
    """Exhaustively gather the non-dominated feasible fragmentations.

    Returns the expected frontier as a tuple of packet tuples, each packet
    built through :func:`multiproof_select`, ordered ascending by the cost
    triple ``(packet count, total bytes, total hashes)``; an empty tuple
    means no fragmentation is feasible.
    """
    kwargs = context_kwargs(context, contexts)
    batch = multiproof_expand(messages, proof, public_key=public_key, **kwargs)
    signatures = batch.signatures
    n = len(signatures)
    sizes, hashes = {}, {}
    for start in range(n):
        for end in range(start + 1, n + 1):
            fragment = tuple(signatures[start:end])
            sizes[(start, end)] = len(
                multiproof_encode(public_key, fragment)
            )
            hashes[(start, end)] = proof_hashes(
                public_key,
                tuple(signature.index for signature in fragment),
            )
    best = {}
    for cuts in range(1, n + 1):
        for inner in itertools.combinations(range(1, n), cuts - 1):
            bounds = (0,) + inner + (n,)
            total_bytes = 0
            total_hashes = 0
            ends = ()
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
                ends += (signatures[end - 1].index,)
            if not feasible:
                continue
            if (max_total_verify_hashes is not None
                    and total_hashes > max_total_verify_hashes):
                continue
            if max_total_bytes is not None and total_bytes > max_total_bytes:
                continue
            cost = (cuts, total_bytes, total_hashes)
            if cost not in best or ends < best[cost][0]:
                best[cost] = (ends, bounds)
    frontier = []
    for cost in sorted(best):
        if any(
            kept[0] <= cost[0]
            and kept[1] <= cost[1]
            and kept[2] <= cost[2]
            for kept in frontier
        ):
            continue
        frontier.append(cost)
    expected = []
    for cost in frontier:
        _, bounds = best[cost]
        expected.append(tuple(
            multiproof_select(
                messages,
                proof,
                public_key=public_key,
                indices=tuple(
                    signature.index
                    for signature in signatures[start:end]
                ),
                **kwargs,
            )
            for start, end in zip(bounds, bounds[1:])
        ))
    return tuple(expected)


class TestFrontierValidation(unittest.TestCase):
    def test_wrong_container_types_raise_type_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        for bad_data in (None, 1, "proof", [proof], (proof,), object()):
            with self.subTest(bad_data=bad_data):
                with self.assertRaises(TypeError):
                    multiproof_partition_frontier(
                        messages, bad_data,
                        public_key=public_key, max_bytes=len(proof),
                    )
        for bad_messages in (None, b"messages", [b"m"], "messages"):
            with self.subTest(bad_messages=bad_messages):
                with self.assertRaises(TypeError):
                    multiproof_partition_frontier(
                        bad_messages, proof,
                        public_key=public_key, max_bytes=len(proof),
                    )
        for bad_message in (None, 1, 1.5, object(), (b"m",)):
            with self.subTest(bad_message=bad_message):
                with self.assertRaises(TypeError):
                    multiproof_partition_frontier(
                        (bad_message,), proof,
                        public_key=public_key, max_bytes=len(proof),
                    )
        for bad_key in (None, b"key", "key", object()):
            with self.subTest(bad_key=bad_key):
                with self.assertRaises(TypeError):
                    multiproof_partition_frontier(
                        messages, proof,
                        public_key=bad_key, max_bytes=len(proof),
                    )

    def test_wrong_budget_types_raise_type_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        for bad in (None, 1.5, "100", b"100", (100,), [100], object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    multiproof_partition_frontier(
                        messages, proof,
                        public_key=public_key, max_bytes=bad,
                    )
        for name in ("max_verify_hashes", "max_total_verify_hashes",
                     "max_total_bytes"):
            for bad in (1.5, "100", b"100", (100,), [100], object()):
                with self.subTest(name=name, bad=bad):
                    with self.assertRaises(TypeError):
                        multiproof_partition_frontier(
                            messages, proof,
                            public_key=public_key, max_bytes=len(proof),
                            **{name: bad},
                        )

    def test_wrong_context_types_raise_type_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        for bad in (1, 1.5, True, object(), (b"x",), [b"x"]):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    multiproof_partition_frontier(
                        messages, proof,
                        public_key=public_key, max_bytes=len(proof),
                        context=bad,
                    )
        for bad in (b"x", "x", 1, [None], object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    multiproof_partition_frontier(
                        messages, proof,
                        public_key=public_key, max_bytes=len(proof),
                        contexts=bad,
                    )
        with self.assertRaises(TypeError):
            multiproof_partition_frontier(
                messages, proof,
                public_key=public_key, max_bytes=len(proof),
                contexts=(None, 1, None, None),
            )

    def test_type_check_precedes_content_check(self):
        public_key, messages, _, proof = make_proof(height=2)
        # Empty messages are a content error, but wrongly typed arguments
        # must still raise TypeError first.
        with self.assertRaises(TypeError):
            multiproof_partition_frontier(
                (), proof, public_key=public_key, max_bytes="100",
            )
        with self.assertRaises(TypeError):
            multiproof_partition_frontier(
                (), proof, public_key=public_key, max_bytes=len(proof),
                max_total_bytes=1.5,
            )
        with self.assertRaises(TypeError):
            multiproof_partition_frontier(
                (), proof, public_key=public_key, max_bytes=len(proof),
                contexts=[None],
            )

    def test_boolean_and_non_positive_budgets_raise_value_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        for bad in (True, False, 0, -1, -100):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    multiproof_partition_frontier(
                        messages, proof,
                        public_key=public_key, max_bytes=bad,
                    )
        for name in ("max_verify_hashes", "max_total_verify_hashes",
                     "max_total_bytes"):
            for bad in (True, False, 0, -1, -100):
                with self.subTest(name=name, bad=bad):
                    with self.assertRaises(ValueError):
                        multiproof_partition_frontier(
                            messages, proof,
                            public_key=public_key, max_bytes=len(proof),
                            **{name: bad},
                        )

    def test_empty_messages_raise_value_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                (), proof, public_key=public_key, max_bytes=len(proof),
            )

    def test_message_count_mismatch_raises_value_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        for wrong in (messages[:-1], messages + (b"extra",)):
            with self.subTest(wrong=len(wrong)):
                with self.assertRaises(ValueError):
                    multiproof_partition_frontier(
                        wrong, proof,
                        public_key=public_key, max_bytes=len(proof),
                    )

    def test_contexts_boundary_errors_raise_value_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                messages, proof,
                public_key=public_key, max_bytes=len(proof), contexts=(),
            )
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                messages, proof,
                public_key=public_key, max_bytes=len(proof),
                contexts=(None,) * (len(messages) - 1),
            )
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                messages, proof,
                public_key=public_key, max_bytes=len(proof),
                context=b"shared",
                contexts=(None,) * len(messages),
            )

    def test_malformed_proof_raises_value_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        for bad in (b"", proof[:10], proof[:-1], proof + b"\x00",
                    b"\x00" + proof[1:]):
            with self.subTest(bad=len(bad)):
                with self.assertRaises(ValueError):
                    multiproof_partition_frontier(
                        messages, bad,
                        public_key=public_key, max_bytes=len(proof),
                    )

    def test_verification_failure_raises_value_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        wrong = list(messages)
        wrong[1] = b"tampered"
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                tuple(wrong), proof,
                public_key=public_key, max_bytes=len(proof),
            )

    def test_single_feasible_scheme_still_verifies_every_leaf(self):
        # One leaf, a generous budget and exactly one feasible
        # fragmentation: a tampered message must still fail.
        public_key, messages, _, proof = make_proof(height=1, count=1)
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                (b"tampered",), proof,
                public_key=public_key, max_bytes=len(proof) + 1000,
            )
        # A tampered dropped leaf's message fails even when the budget
        # only leaves room for one packet per leaf anyway.
        public_key, messages, _, proof = make_proof(height=2)
        single = len(multiproof_select(
            messages, proof, public_key=public_key, indices=(0,),
        ))
        wrong = list(messages)
        wrong[-1] = b"tampered"
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                tuple(wrong), proof,
                public_key=public_key, max_bytes=single,
            )

    def test_public_key_mismatch_raises_value_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        other_key, _, _, _ = make_proof(height=2, start=100)
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                messages, proof,
                public_key=other_key, max_bytes=len(proof),
            )

    def test_context_mismatch_raises_value_error(self):
        public_key, messages, _, proof = make_proof(height=2, context=b"ctx")
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                messages, proof,
                public_key=public_key, max_bytes=len(proof),
            )
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                messages, proof,
                public_key=public_key, max_bytes=len(proof), context=b"other",
            )
        contexts = (None, b"a", None, b"b")
        public_key, messages, _, proof = make_proof(height=2, contexts=contexts)
        wrong_contexts = (None, b"a", None, b"c")
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                messages, proof,
                public_key=public_key, max_bytes=len(proof),
                contexts=wrong_contexts,
            )

    def test_infeasible_budgets_raise_value_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        single = len(multiproof_select(
            messages, proof, public_key=public_key, indices=(0,),
        ))
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                messages, proof,
                public_key=public_key, max_bytes=single - 1,
            )
        single_hashes = proof_hashes(public_key, (0,))
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                messages, proof,
                public_key=public_key, max_bytes=len(proof),
                max_verify_hashes=single_hashes - 1,
            )
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                messages, proof,
                public_key=public_key, max_bytes=len(proof),
                max_total_bytes=len(proof) - 1,
            )
        with self.assertRaises(ValueError):
            multiproof_partition_frontier(
                messages, proof,
                public_key=public_key, max_bytes=len(proof),
                max_total_verify_hashes=proof_hashes(public_key, (0, 1, 2, 3)) - 1,
            )


class TestFrontierAgainstBruteForce(unittest.TestCase):
    def check(self, messages, proof, public_key, max_bytes, context=None,
              contexts=None, **budgets):
        expected = brute_force_frontier(
            messages, proof, public_key, max_bytes,
            context=context, contexts=contexts, **budgets,
        )
        if not expected:
            with self.assertRaises(ValueError):
                multiproof_partition_frontier(
                    messages, proof,
                    public_key=public_key, max_bytes=max_bytes,
                    **context_kwargs(context, contexts), **budgets,
                )
            return ()
        got = multiproof_partition_frontier(
            messages, proof,
            public_key=public_key, max_bytes=max_bytes,
            **context_kwargs(context, contexts), **budgets,
        )
        self.assertEqual(got, expected)
        self.assertTrue(got)
        return got

    def test_height_one(self):
        public_key, messages, _, proof = make_proof(height=1)
        single = len(multiproof_select(
            messages, proof, public_key=public_key, indices=(0,),
        ))
        for max_bytes in (len(proof), single):
            with self.subTest(max_bytes=max_bytes):
                self.check(messages, proof, public_key, max_bytes)

    def test_single_leaf(self):
        public_key, messages, _, proof = make_proof(height=3, count=1)
        got = self.check(messages, proof, public_key, len(proof))
        self.assertEqual(got, ((bytes(proof),),))

    def test_full_trees(self):
        for height, w in ((2, 4), (3, 4), (3, 8), (4, 4)):
            public_key, messages, _, proof = make_proof(height=height, w=w)
            single = len(multiproof_select(
                messages, proof, public_key=public_key, indices=(0,),
            ))
            for max_bytes in (len(proof), single,
                              (single + len(proof)) // 2):
                with self.subTest(height=height, w=w, max_bytes=max_bytes):
                    self.check(messages, proof, public_key, max_bytes)

    def test_sparse_leaves(self):
        cases = (
            (4, 4, (0, 2, 5, 7, 9, 15)),
            (5, 8, (1, 4, 9, 16, 25)),
            (8, 4, (0, 5, 100, 255)),
            (8, 8, (3, 200)),
        )
        for height, w, keep in cases:
            public_key, messages, _, proof = make_proof(
                height=height, w=w, keep=keep,
            )
            single = len(multiproof_select(
                messages, proof, public_key=public_key, indices=(keep[0],),
            ))
            for max_bytes in (len(proof), single,
                              (single + len(proof)) // 2):
                with self.subTest(height=height, w=w, keep=keep,
                                  max_bytes=max_bytes):
                    self.check(messages, proof, public_key, max_bytes)

    def test_shared_context(self):
        public_key, messages, _, proof = make_proof(height=3, context=b"ctx")
        single = len(multiproof_select(
            messages, proof, public_key=public_key, indices=(0,),
            context=b"ctx",
        ))
        for max_bytes in (len(proof), single, (single + len(proof)) // 2):
            with self.subTest(max_bytes=max_bytes):
                self.check(messages, proof, public_key, max_bytes,
                           context=b"ctx")

    def test_per_leaf_contexts(self):
        contexts = (None, b"a", "b", None, b"c", "", b"d", "e")
        public_key, messages, _, proof = make_proof(
            height=3, contexts=contexts,
        )
        single = len(multiproof_select(
            messages, proof, public_key=public_key, indices=(0,),
            contexts=contexts,
        ))
        for max_bytes in (len(proof), single, (single + len(proof)) // 2):
            with self.subTest(max_bytes=max_bytes):
                self.check(messages, proof, public_key, max_bytes,
                           contexts=contexts)

    def test_hash_budget(self):
        public_key, messages, _, proof = make_proof(height=3)
        for max_verify_hashes in (2000, 2500, 4000):
            with self.subTest(max_verify_hashes=max_verify_hashes):
                self.check(
                    messages, proof, public_key, len(proof),
                    max_verify_hashes=max_verify_hashes,
                )

    def test_total_hash_budget(self):
        public_key, messages, _, proof = make_proof(height=3)
        for max_total_verify_hashes in (6000, 9000, 20000):
            with self.subTest(max_total_verify_hashes=max_total_verify_hashes):
                self.check(
                    messages, proof, public_key, len(proof),
                    max_total_verify_hashes=max_total_verify_hashes,
                )

    def test_total_byte_budget(self):
        public_key, messages, _, proof = make_proof(height=3)
        for max_total_bytes in (len(proof), 12000, 20000):
            with self.subTest(max_total_bytes=max_total_bytes):
                self.check(
                    messages, proof, public_key, len(proof),
                    max_total_bytes=max_total_bytes,
                )

    def test_all_budgets_together(self):
        public_key, messages, _, proof = make_proof(height=3, w=8)
        single = len(multiproof_select(
            messages, proof, public_key=public_key, indices=(0,),
        ))
        budget_grid = (
            {"max_verify_hashes": 10000},
            {"max_verify_hashes": 10000, "max_total_verify_hashes": 40000},
            {"max_verify_hashes": 10000, "max_total_bytes": 30000},
            {"max_verify_hashes": 10000,
             "max_total_verify_hashes": 40000, "max_total_bytes": 30000},
            {"max_total_verify_hashes": 25000, "max_total_bytes": 18000},
        )
        for max_bytes in (len(proof), single, (single + len(proof)) // 2):
            for budgets in budget_grid:
                with self.subTest(max_bytes=max_bytes, budgets=budgets):
                    self.check(messages, proof, public_key, max_bytes,
                               **budgets)

    def test_budget_equality_is_allowed(self):
        public_key, messages, _, proof = make_proof(height=3)
        got = multiproof_partition_frontier(
            messages, proof,
            public_key=public_key, max_bytes=len(proof),
            max_verify_hashes=proof_hashes(public_key, (0, 1, 2, 3, 4, 5, 6, 7)),
            max_total_verify_hashes=proof_hashes(
                public_key, (0, 1, 2, 3, 4, 5, 6, 7)
            ),
            max_total_bytes=len(proof),
        )
        self.assertIn((bytes(proof),), got)


class TestFrontierShape(unittest.TestCase):
    def test_explicit_tie_break(self):
        # Height 3, eight leaves, room for the largest three-leaf
        # fragments: the fragmentations {0,1}|{2,3,4}|{5,6,7} (ends
        # (1, 4, 7)) and {0,1,2}|{3,4,5}|{6,7} (ends (2, 5, 7)) tie on all
        # three costs, and only the lexicographically smaller end tuple
        # survives.
        public_key, messages, _, proof = make_proof(height=3)
        max_bytes = len(multiproof_select(
            messages, proof, public_key=public_key, indices=(2, 3, 4),
        ))
        got = multiproof_partition_frontier(
            messages, proof, public_key=public_key, max_bytes=max_bytes,
        )
        survivor = (
            multiproof_select(messages, proof, public_key=public_key,
                              indices=(0, 1)),
            multiproof_select(messages, proof, public_key=public_key,
                              indices=(2, 3, 4)),
            multiproof_select(messages, proof, public_key=public_key,
                              indices=(5, 6, 7)),
        )
        tied = (
            multiproof_select(messages, proof, public_key=public_key,
                              indices=(0, 1, 2)),
            multiproof_select(messages, proof, public_key=public_key,
                              indices=(3, 4, 5)),
            multiproof_select(messages, proof, public_key=public_key,
                              indices=(6, 7)),
        )
        # A genuine tie: identical cost triples, different end tuples.
        self.assertEqual(
            scheme_cost(public_key, survivor)[:3],
            scheme_cost(public_key, tied)[:3],
        )
        self.assertEqual(got, (survivor,))

    def test_explicit_ordering_and_trade_off(self):
        # The same source with slightly less room per packet yields a
        # two-member frontier: the three-packet scheme is cheaper in
        # packet count and bytes, the four-packet scheme is cheaper in
        # verification hashes, and the frontier is ordered ascending by
        # (packet count, total bytes, total hashes).
        public_key, messages, _, proof = make_proof(height=3)
        max_bytes = len(multiproof_select(
            messages, proof, public_key=public_key, indices=(0, 1, 2),
        ))
        got = multiproof_partition_frontier(
            messages, proof, public_key=public_key, max_bytes=max_bytes,
        )
        expected = (
            (
                multiproof_select(messages, proof, public_key=public_key,
                                  indices=(0, 1, 2)),
                multiproof_select(messages, proof, public_key=public_key,
                                  indices=(3, 4)),
                multiproof_select(messages, proof, public_key=public_key,
                                  indices=(5, 6, 7)),
            ),
            (
                multiproof_select(messages, proof, public_key=public_key,
                                  indices=(0, 1)),
                multiproof_select(messages, proof, public_key=public_key,
                                  indices=(2, 3)),
                multiproof_select(messages, proof, public_key=public_key,
                                  indices=(4, 5)),
                multiproof_select(messages, proof, public_key=public_key,
                                  indices=(6, 7)),
            ),
        )
        self.assertEqual(got, expected)
        costs = [scheme_cost(public_key, scheme)[:3] for scheme in got]
        self.assertEqual(costs, sorted(costs))
        self.assertLess(costs[0][0], costs[1][0])
        self.assertLess(costs[0][1], costs[1][1])
        self.assertGreater(costs[0][2], costs[1][2])

    def test_result_is_non_empty_tuples_of_bytes(self):
        public_key, messages, _, proof = make_proof(height=3)
        got = multiproof_partition_frontier(
            messages, proof, public_key=public_key, max_bytes=len(proof),
        )
        self.assertIsInstance(got, tuple)
        self.assertTrue(got)
        for scheme in got:
            self.assertIsInstance(scheme, tuple)
            self.assertTrue(scheme)
            for packet in scheme:
                self.assertIsInstance(packet, bytes)

    def test_costs_are_sorted_and_non_dominated(self):
        public_key, messages, _, proof = make_proof(height=4, count=6)
        single = len(multiproof_select(
            messages, proof, public_key=public_key, indices=(0,),
        ))
        got = multiproof_partition_frontier(
            messages, proof, public_key=public_key,
            max_bytes=(single + len(proof)) // 2,
        )
        costs = [scheme_cost(public_key, scheme)[:3] for scheme in got]
        self.assertEqual(costs, sorted(costs))
        self.assertEqual(len(costs), len(set(costs)))
        for position, cost in enumerate(costs):
            for other in costs[:position]:
                self.assertFalse(
                    other[0] <= cost[0]
                    and other[1] <= cost[1]
                    and other[2] <= cost[2]
                )

    def test_schemes_cover_every_leaf_exactly_once(self):
        public_key, messages, _, proof = make_proof(
            height=4, keep=(0, 2, 5, 7, 9, 15),
        )
        single = len(multiproof_select(
            messages, proof, public_key=public_key, indices=(0,),
        ))
        got = multiproof_partition_frontier(
            messages, proof, public_key=public_key,
            max_bytes=(single + len(proof)) // 2,
        )
        for scheme in got:
            indices = []
            for packet in scheme:
                _, leaves, _ = _multiproof_parse(packet)
                indices.extend(index for index, _ in leaves)
            self.assertEqual(tuple(indices), (0, 2, 5, 7, 9, 15))

    def test_packets_verify_and_merge_restores_source(self):
        public_key, messages, _, proof = make_proof(height=3)
        single = len(multiproof_select(
            messages, proof, public_key=public_key, indices=(0,),
        ))
        got = multiproof_partition_frontier(
            messages, proof, public_key=public_key,
            max_bytes=(single + len(proof)) // 2,
        )
        for scheme in got:
            position = 0
            groups = []
            for packet in scheme:
                _, leaves, _ = _multiproof_parse(packet)
                fragment = messages[position:position + len(leaves)]
                groups.append(fragment)
                self.assertTrue(multiproof_verify(fragment, packet))
                position += len(leaves)
            self.assertEqual(position, len(messages))
            self.assertEqual(
                multiproof_merge(
                    tuple(groups), scheme, public_key=public_key,
                ),
                proof,
            )

    def test_packets_verify_and_merge_with_per_leaf_contexts(self):
        contexts = (None, b"a", "b", None)
        public_key, messages, _, proof = make_proof(
            height=2, contexts=contexts,
        )
        single = len(multiproof_select(
            messages, proof, public_key=public_key, indices=(0,),
            contexts=contexts,
        ))
        got = multiproof_partition_frontier(
            messages, proof, public_key=public_key,
            max_bytes=(single + len(proof)) // 2, contexts=contexts,
        )
        for scheme in got:
            position = 0
            groups = []
            context_groups = []
            for packet in scheme:
                _, leaves, _ = _multiproof_parse(packet)
                count = len(leaves)
                fragment = messages[position:position + count]
                fragment_contexts = contexts[position:position + count]
                groups.append(fragment)
                context_groups.append(fragment_contexts)
                self.assertTrue(multiproof_verify(
                    fragment, packet, contexts=fragment_contexts,
                ))
                position += count
            self.assertEqual(
                multiproof_merge(
                    tuple(groups), scheme,
                    public_key=public_key,
                    context_groups=tuple(context_groups),
                ),
                proof,
            )

    def test_single_packet_scheme_keeps_source_bytes(self):
        public_key, messages, _, proof = make_proof(height=2)
        got = multiproof_partition_frontier(
            messages, proof, public_key=public_key, max_bytes=len(proof),
        )
        self.assertEqual(got[0], (bytes(proof),))

    def test_frontier_contains_both_preference_winners(self):
        # Both ``multiproof_partition`` preference winners appear on the
        # frontier, in frontier (cost-triple) order — here they are two
        # distinct schemes, and the frontier is gathered over every
        # feasible fragmentation rather than from the winners alone (the
        # brute-force comparisons above pin the complete membership).
        public_key, messages, _, proof = make_proof(height=3)
        max_bytes = len(multiproof_select(
            messages, proof, public_key=public_key, indices=(0, 1, 2),
        ))
        got = multiproof_partition_frontier(
            messages, proof, public_key=public_key, max_bytes=max_bytes,
        )
        compact = multiproof_partition(
            messages, proof, public_key=public_key, max_bytes=max_bytes,
        )
        verify = multiproof_partition(
            messages, proof, public_key=public_key, max_bytes=max_bytes,
            prefer="verify",
        )
        self.assertNotEqual(compact, verify)
        self.assertEqual(got, (compact, verify))

    def test_deterministic_and_inputs_untouched(self):
        public_key, messages, _, proof = make_proof(height=3)
        data = bytearray(proof)
        mutable_messages = tuple(bytearray(m.encode()) for m in messages)
        before = bytes(data)
        first = multiproof_partition_frontier(
            mutable_messages, data,
            public_key=public_key, max_bytes=len(proof),
        )
        second = multiproof_partition_frontier(
            mutable_messages, data,
            public_key=public_key, max_bytes=len(proof),
        )
        self.assertEqual(first, second)
        self.assertEqual(bytes(data), before)
        self.assertEqual(
            tuple(bytes(m) for m in mutable_messages),
            tuple(m.encode() for m in messages),
        )
        data[10] ^= 0xFF
        self.assertTrue(
            all(bytes(packet) != data for scheme in first for packet in scheme)
        )

    def test_result_does_not_reference_mutable_input(self):
        public_key, messages, _, proof = make_proof(height=2)
        data = bytearray(proof)
        got = multiproof_partition_frontier(
            messages, data, public_key=public_key, max_bytes=len(proof),
        )
        snapshot = tuple(
            tuple(bytes(packet) for packet in scheme) for scheme in got
        )
        for i in range(len(data)):
            data[i] ^= 0xFF
        self.assertEqual(
            tuple(
                tuple(bytes(packet) for packet in scheme) for scheme in got
            ),
            snapshot,
        )


if __name__ == "__main__":
    unittest.main()

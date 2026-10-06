import itertools
import random
import unittest

from pqattest import (
    MerkleSigner,
    multiproof_encode,
    multiproof_expand,
    multiproof_merge,
    multiproof_partition,
    multiproof_select,
    multiproof_verify,
    multiproof_verify_bound,
)
from pqattest.merkle import _MULTIPROOF_HEADER_BYTES, _multiproof_parse

PUBLIC_KEY_BYTES = 43

unset = object()


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


def packet_key(packets):
    """The optimisation key of a fragmentation: (count, bytes, end indices)."""
    return (
        len(packets),
        sum(len(packet) for packet in packets),
        tuple(_multiproof_parse(packet)[1][-1][0] for packet in packets),
    )


def brute_force_key(messages, proof, public_key, budget, contexts=None):
    """Enumerate every feasible fragmentation and return the minimum key.

    The source is expanded once into standalone signatures (each fragment
    bytes then comes from :func:`multiproof_encode` directly, which is
    byte-identical to :func:`multiproof_select` — that equivalence is
    covered by the dedicated tests), so the enumeration stays cheap.
    """
    batch = multiproof_expand(
        messages, proof, public_key=public_key, contexts=contexts
    )
    signatures = batch.signatures
    n = len(signatures)
    sizes = {}
    for start in range(n):
        for end in range(start + 1, n + 1):
            sizes[(start, end)] = len(
                multiproof_encode(
                    public_key, tuple(signatures[start:end])
                )
            )
    best = None
    for cuts in range(1, n + 1):
        for inner in itertools.combinations(range(1, n), cuts - 1):
            bounds = (0,) + inner + (n,)
            total = 0
            ends = ()
            for start, end in zip(bounds, bounds[1:]):
                size = sizes[(start, end)]
                if size > budget:
                    break
                total += size
                ends += (signatures[end - 1].index,)
            else:
                candidate = (cuts, total, ends)
                if best is None or candidate < best:
                    best = candidate
    return best


class TestMultiproofPartitionBasics(unittest.TestCase):
    def test_source_within_budget_returns_source_unchanged(self):
        for w in (4, 8):
            for height in (1, 2, 3, 8):
                public_key, messages, _, proof = make_proof(w=w, height=height)
                for budget in (len(proof), len(proof) + 1, 10**6):
                    with self.subTest(w=w, height=height, budget=budget):
                        packets = multiproof_partition(
                            messages,
                            proof,
                            public_key=public_key,
                            max_bytes=budget,
                        )
                        self.assertEqual(packets, (proof,))
                        self.assertIsInstance(packets[0], bytes)

    def test_packets_are_nonempty_bytes_in_leaf_order(self):
        public_key, messages, _, proof = make_proof(height=4)
        packets = multiproof_partition(
            messages,
            proof,
            public_key=public_key,
            max_bytes=len(proof) // 3,
        )
        self.assertGreater(len(packets), 1)
        for packet in packets:
            self.assertIsInstance(packet, bytes)
            self.assertGreater(len(packet), 0)

    def test_every_packet_respects_budget_including_equality(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                public_key, messages, _, proof = make_proof(w=w, height=height)
                for divisor in (1, 2, 3, 5):
                    budget = max(1, len(proof) // divisor)
                    with self.subTest(w=w, height=height, budget=budget):
                        try:
                            packets = multiproof_partition(
                                messages,
                                proof,
                                public_key=public_key,
                                max_bytes=budget,
                            )
                        except ValueError:
                            continue
                        for packet in packets:
                            self.assertLessEqual(len(packet), budget)

    def test_packets_cover_source_leaves_exactly_once(self):
        public_key, messages, _, proof = make_proof(height=4)
        packets = multiproof_partition(
            messages,
            proof,
            public_key=public_key,
            max_bytes=len(proof) // 3,
        )
        seen_indices = []
        position = 0
        for packet in packets:
            _, leaves, _ = _multiproof_parse(packet)
            count = len(leaves)
            fragment = messages[position : position + count]
            self.assertTrue(
                multiproof_verify(fragment, packet),
                "a packet does not verify its fragment",
            )
            self.assertTrue(
                multiproof_verify_bound(
                    fragment,
                    packet,
                    public_key=public_key,
                    indices=tuple(index for index, _ in leaves),
                )
            )
            seen_indices.extend(index for index, _ in leaves)
            position += count
        self.assertEqual(position, len(messages))
        source_indices = [index for index, _ in _multiproof_parse(proof)[1]]
        self.assertEqual(seen_indices, source_indices)

    def test_sparse_leaves_continuity_is_in_message_position(self):
        keep = (0, 3, 7, 11, 15)
        public_key, messages, signatures, proof = make_proof(
            height=4, keep=keep
        )
        packets = multiproof_partition(
            messages,
            proof,
            public_key=public_key,
            max_bytes=len(proof) // 2,
        )
        self.assertGreater(len(packets), 1)
        position = 0
        covered = ()
        for packet in packets:
            _, leaves, _ = _multiproof_parse(packet)
            count = len(leaves)
            self.assertTrue(
                multiproof_verify(
                    messages[position : position + count], packet
                )
            )
            covered += tuple(index for index, _ in leaves)
            position += count
        self.assertEqual(covered, keep)
        # A single packet never carries two copies of the same leaf.
        for packet in packets:
            indices = [index for index, _ in _multiproof_parse(packet)[1]]
            self.assertEqual(indices, sorted(set(indices)))

    def test_each_packet_equals_select_of_same_fragment(self):
        for w in (4, 8):
            public_key, messages, _, proof = make_proof(w=w, height=4)
            budget = len(proof) // 3
            packets = multiproof_partition(
                messages, proof, public_key=public_key, max_bytes=budget
            )
            position = 0
            for packet in packets:
                _, leaves, _ = _multiproof_parse(packet)
                count = len(leaves)
                indices = tuple(index for index, _ in leaves)
                expected = multiproof_select(
                    messages,
                    proof,
                    public_key=public_key,
                    indices=indices,
                )
                self.assertEqual(packet, expected)
                position += count

    def test_remerge_restores_source_bytes(self):
        for w in (4, 8):
            for height in (2, 3, 5):
                public_key, messages, _, proof = make_proof(w=w, height=height)
                budget = max(1, len(proof) // 3)
                try:
                    packets = multiproof_partition(
                        messages,
                        proof,
                        public_key=public_key,
                        max_bytes=budget,
                    )
                except ValueError:
                    continue
                groups = []
                position = 0
                for packet in packets:
                    count = len(_multiproof_parse(packet)[1])
                    groups.append(messages[position : position + count])
                    position += count
                merged = multiproof_merge(
                    tuple(groups), packets, public_key=public_key
                )
                self.assertEqual(merged, proof)

    def test_single_leaf_floor_is_infeasible_below_its_size(self):
        public_key, messages, _, proof = make_proof(height=3)
        one = multiproof_select(
            messages, proof, public_key=public_key, indices=(0,)
        )
        with self.assertRaises(ValueError):
            multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=len(one) - 1,
            )
        # The floor itself is feasible.
        packets = multiproof_partition(
            messages,
            proof,
            public_key=public_key,
            max_bytes=len(one),
        )
        self.assertTrue(all(len(packet) == len(one) for packet in packets))
        self.assertEqual(len(packets), len(messages))

    def test_duplicate_messages_are_distinct_leaves(self):
        signer = make_signer(height=2)
        messages = ("same", "same", "other", "same")
        signatures = signer.sign_batch(messages)
        public_key = signer.public_key
        proof = multiproof_encode(public_key, signatures)
        packets = multiproof_partition(
            messages,
            proof,
            public_key=public_key,
            max_bytes=len(proof) // 2,
        )
        total = sum(len(_multiproof_parse(packet)[1]) for packet in packets)
        self.assertEqual(total, 4)
        position = 0
        for packet in packets:
            count = len(_multiproof_parse(packet)[1])
            self.assertTrue(
                multiproof_verify(
                    messages[position : position + count], packet
                )
            )
            position += count

    def test_full_height_range_performance_and_coverage(self):
        for height in (6, 7, 8):
            public_key, messages, _, proof = make_proof(height=height)
            packets = multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=len(proof) // 7,
            )
            position = 0
            covered = []
            for packet in packets:
                leaves = _multiproof_parse(packet)[1]
                fragment = messages[position : position + len(leaves)]
                self.assertTrue(multiproof_verify(fragment, packet))
                covered.extend(index for index, _ in leaves)
                position += len(leaves)
            self.assertEqual(position, 1 << height)
            self.assertEqual(covered, list(range(1 << height)))


class TestMultiproofPartitionOptimality(unittest.TestCase):
    def test_matches_exhaustive_enumeration(self):
        rng = random.Random(143)
        cases = 0
        for height in range(1, 9):
            for w in (4, 8):
                signer = make_signer(height=height, w=w)
                total = 1 << height
                all_messages = tuple(f"m{i}" for i in range(total))
                all_signatures = signer.sign_batch(all_messages)
                # Brute force is exponential in leaf count, so exhaustively
                # enumerate small full trees and sparse subsets (at most 7
                # leaves) of the larger trees.
                if total <= 8:
                    subsets = [tuple(range(total))]
                else:
                    subsets = []
                for size in (1, 2, 3, 5, min(7, total)):
                    if size > total or size == total:
                        continue
                    for _ in range(2):
                        subset = tuple(sorted(rng.sample(range(total), size)))
                        if subset not in subsets:
                            subsets.append(subset)
                for subset in subsets:
                    signatures = tuple(
                        all_signatures[i] for i in subset
                    )
                    proof = multiproof_encode(signer.public_key, signatures)
                    messages = tuple(all_messages[i] for i in subset)
                    one = multiproof_encode(
                        signer.public_key, (signatures[0],)
                    )
                    two = multiproof_encode(
                        signer.public_key,
                        tuple(signatures[: min(2, len(signatures))]),
                    )
                    budgets = {
                        len(proof),
                        len(one),
                        len(two),
                        (len(proof) + len(one)) // 2,
                        len(one) - 1,
                    }
                    for budget in budgets:
                        if budget < 1:
                            continue
                        try:
                            packets = multiproof_partition(
                                messages,
                                proof,
                                public_key=signer.public_key,
                                max_bytes=budget,
                            )
                        except ValueError:
                            packets = None
                        expected = brute_force_key(
                            messages, proof, signer.public_key, budget
                        )
                        self.assertIs(
                            packets is None,
                            expected is None,
                            (height, w, subset, budget),
                        )
                        if packets is not None:
                            self.assertEqual(
                                packet_key(packets),
                                expected,
                                (height, w, subset, budget),
                            )
                            cases += 1
        self.assertGreater(cases, 100)

    def test_fewest_packets_beats_smaller_total(self):
        # With the source's own length as budget the one-packet solution
        # always wins over any multi-packet split even if splitting were
        # somehow cheaper overall.
        public_key, messages, _, proof = make_proof(height=3)
        packets = multiproof_partition(
            messages,
            proof,
            public_key=public_key,
            max_bytes=len(proof),
        )
        self.assertEqual(len(packets), 1)


class TestMultiproofPartitionContexts(unittest.TestCase):
    def make_per_leaf(self, height=3, w=4, keep=None):
        signer = make_signer(height=height, w=w)
        if keep is None:
            keep = tuple(range(1 << height))
        messages = tuple(f"message-{i}" for i in keep)
        contexts = tuple(f"ctx-{i}" for i in keep)
        signatures = signer.sign_selected(tuple(keep), messages, contexts=contexts)
        proof = multiproof_encode(signer.public_key, signatures)
        return signer.public_key, messages, contexts, proof, keep

    def test_shared_context_packets_verify_and_remerge(self):
        public_key, messages, _, proof = make_proof(height=3, context="ctx")
        packets = multiproof_partition(
            messages,
            proof,
            public_key=public_key,
            max_bytes=len(proof) // 2,
            context="ctx",
        )
        position = 0
        groups = []
        for packet in packets:
            count = len(_multiproof_parse(packet)[1])
            fragment = messages[position : position + count]
            self.assertTrue(
                multiproof_verify(fragment, packet, context="ctx")
            )
            self.assertFalse(multiproof_verify(fragment, packet))
            groups.append(fragment)
            position += count
        merged = multiproof_merge(
            tuple(groups), packets, public_key=public_key, context="ctx"
        )
        self.assertEqual(merged, proof)

    def test_per_leaf_contexts_align_positionally(self):
        for w in (4, 8):
            public_key, messages, contexts, proof, keep = (
                self.make_per_leaf(height=4, w=w, keep=(0, 3, 7, 11, 15))
            )
            packets = multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=len(proof) // 2,
                contexts=contexts,
            )
            position = 0
            groups, context_groups = [], []
            covered = ()
            for packet in packets:
                leaves = _multiproof_parse(packet)[1]
                count = len(leaves)
                fragment = messages[position : position + count]
                fragment_contexts = contexts[position : position + count]
                indices = tuple(index for index, _ in leaves)
                self.assertTrue(
                    multiproof_verify(
                        fragment, packet, contexts=fragment_contexts
                    )
                )
                self.assertTrue(
                    multiproof_verify_bound(
                        fragment,
                        packet,
                        public_key=public_key,
                        indices=indices,
                        contexts=fragment_contexts,
                    )
                )
                self.assertFalse(multiproof_verify(fragment, packet))
                groups.append(fragment)
                context_groups.append(fragment_contexts)
                covered += indices
                position += count
            self.assertEqual(covered, keep)
            merged = multiproof_merge(
                tuple(groups),
                packets,
                public_key=public_key,
                context_groups=tuple(context_groups),
            )
            self.assertEqual(merged, proof)

    def test_wrong_source_context_fails(self):
        public_key, messages, _, proof = make_proof(height=3, context="ctx")
        with self.assertRaises(ValueError):
            multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=len(proof),
                context="other",
            )
        with self.assertRaises(ValueError):
            multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=len(proof),
            )

    def test_wrong_per_leaf_context_fails_even_when_one_packet(self):
        public_key, messages, contexts, proof, _ = self.make_per_leaf(height=2)
        bad_contexts = ("other",) + contexts[1:]
        with self.assertRaises(ValueError):
            multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=len(proof),
                contexts=bad_contexts,
            )

    def test_empty_shared_context_combines_with_contexts(self):
        public_key, messages, contexts, proof, _ = self.make_per_leaf(height=2)
        expected = multiproof_partition(
            messages,
            proof,
            public_key=public_key,
            max_bytes=len(proof) // 2,
            contexts=contexts,
        )
        for empty in (None, b"", bytearray(), ""):
            with self.subTest(context=empty):
                packets = multiproof_partition(
                    messages,
                    proof,
                    public_key=public_key,
                    max_bytes=len(proof) // 2,
                    context=empty,
                    contexts=contexts,
                )
                self.assertEqual(packets, expected)


class TestMultiproofPartitionValidation(unittest.TestCase):
    def setUp(self):
        self.public_key, self.messages, _, self.proof = make_proof(height=2)
        self.budget = 10**9

    def partition(self, messages=unset, data=unset, **kwargs):
        if messages is unset:
            messages = self.messages
        if data is unset:
            data = self.proof
        kwargs.setdefault("public_key", self.public_key)
        kwargs.setdefault("max_bytes", self.budget)
        return multiproof_partition(messages, data, **kwargs)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            self.partition(data="not-bytes")
        with self.assertRaises(TypeError):
            self.partition(data=None)
        with self.assertRaises(TypeError):
            self.partition(messages=list(self.messages))
        with self.assertRaises(TypeError):
            self.partition(messages=self.messages[:3] + (1,))
        with self.assertRaises(TypeError):
            self.partition(public_key="key")
        with self.assertRaises(TypeError):
            self.partition(max_bytes=1.5)
        with self.assertRaises(TypeError):
            self.partition(max_bytes="100")
        with self.assertRaises(TypeError):
            self.partition(max_bytes=None)
        with self.assertRaises(TypeError):
            self.partition(context=1)
        with self.assertRaises(TypeError):
            self.partition(contexts=[])
        with self.assertRaises(TypeError):
            self.partition(contexts="ctx")
        with self.assertRaises(TypeError):
            self.partition(contexts=(1,) * len(self.messages))
        with self.assertRaises(TypeError):
            self.partition(contexts=(None, b"a", 2, b"b"))

    def test_type_checks_precede_content_checks(self):
        # Bad data type precedes the non-positive budget.
        with self.assertRaises(TypeError):
            multiproof_partition(
                self.messages,
                123,
                public_key=self.public_key,
                max_bytes=0,
            )
        # Bad contexts member precedes a non-positive budget.
        with self.assertRaises(TypeError):
            multiproof_partition(
                self.messages,
                self.proof,
                public_key=self.public_key,
                max_bytes=0,
                contexts=(1,) * len(self.messages),
            )
        # Bad contexts container precedes malformed data.
        with self.assertRaises(TypeError):
            multiproof_partition(
                self.messages,
                b"",
                public_key=self.public_key,
                max_bytes=self.budget,
                contexts=[],
            )
        # Bad max_bytes type precedes malformed data and empty messages.
        with self.assertRaises(TypeError):
            multiproof_partition(
                (),
                b"",
                public_key=self.public_key,
                max_bytes="0",
            )

    def test_budget_value_errors(self):
        for budget in (True, False, 0, -1, -10**6):
            with self.subTest(budget=budget):
                with self.assertRaises(ValueError):
                    self.partition(max_bytes=budget)

    def test_content_value_errors(self):
        with self.assertRaises(ValueError):
            self.partition(messages=())
        with self.assertRaises(ValueError):
            self.partition(messages=self.messages[:3])
        with self.assertRaises(ValueError):
            self.partition(messages=self.messages + ("extra",))
        with self.assertRaises(ValueError):
            self.partition(data=b"")
        with self.assertRaises(ValueError):
            self.partition(data=self.proof[:-1])
        with self.assertRaises(ValueError):
            self.partition(data=self.proof + b"\x00")
        corrupted = bytearray(self.proof)
        corrupted[8] = 2
        with self.assertRaises(ValueError):
            self.partition(data=bytes(corrupted))
        other = make_signer(height=2, start=1000).public_key
        with self.assertRaises(ValueError):
            self.partition(public_key=other)
        wrong_messages = ("tampered",) + self.messages[1:]
        with self.assertRaises(ValueError):
            self.partition(messages=wrong_messages)

    def test_context_value_errors(self):
        with self.assertRaises(ValueError):
            self.partition(contexts=())
        with self.assertRaises(ValueError):
            self.partition(contexts=(b"a",))
        with self.assertRaises(ValueError):
            self.partition(
                context="ctx",
                contexts=tuple(b"" for _ in self.messages),
            )
        with self.assertRaises(ValueError):
            self.partition(contexts=tuple(b"a" for _ in range(3)))
        with self.assertRaises(ValueError):
            self.partition(
                contexts=tuple(b"a" for _ in range(len(self.messages) + 1))
            )

    def test_corrupted_dropped_leaf_fails_even_one_packet(self):
        public_key, messages, _, proof = make_proof(height=2)
        corrupted = bytearray(proof)
        corrupted[_MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES + 4] ^= 0xFF
        with self.assertRaises(ValueError):
            multiproof_partition(
                messages,
                bytes(corrupted),
                public_key=public_key,
                max_bytes=10**9,
            )

    def test_source_fully_verified_even_when_one_packet_suffices(self):
        # A source within budget is returned byte-identical, but a corrupt
        # within-budget source must still be rejected.
        public_key, messages, _, proof = make_proof(height=2)
        corrupted = bytearray(proof)
        # Flip a byte inside a carried authentication node (after leaves).
        corrupted[-1] ^= 0x01
        with self.assertRaises(ValueError):
            multiproof_partition(
                messages,
                bytes(corrupted),
                public_key=public_key,
                max_bytes=len(proof),
            )


class TestMultiproofPartitionSafety(unittest.TestCase):
    def test_bytearray_data_and_mixed_message_forms(self):
        public_key, messages, signatures, proof = make_proof(height=2)
        mixed = tuple(
            bytearray(message.encode()) if i % 2 else message
            for i, message in enumerate(messages)
        )
        packets = multiproof_partition(
            mixed,
            bytearray(proof),
            public_key=public_key,
            max_bytes=len(proof) // 2,
        )
        position = 0
        for packet in packets:
            count = len(_multiproof_parse(packet)[1])
            self.assertTrue(
                multiproof_verify(mixed[position : position + count], packet)
            )
            position += count
        self.assertEqual(position, len(messages))

    def test_inputs_are_not_modified(self):
        public_key, messages, _, proof = make_proof(height=2)
        data = bytearray(proof)
        multiproof_partition(
            messages, data, public_key=public_key, max_bytes=len(proof) // 2
        )
        self.assertEqual(bytes(data), proof)

    def test_returned_bytes_do_not_reference_mutable_buffer(self):
        public_key, messages, _, proof = make_proof(height=2)
        buffer = bytearray(proof)
        packets = multiproof_partition(
            messages, buffer, public_key=public_key, max_bytes=len(proof) // 2
        )
        snapshot = tuple(bytes(packet) for packet in packets)
        buffer[0] ^= 0xFF
        buffer[-1] ^= 0xFF
        self.assertEqual(packets, snapshot)

    def test_result_is_deterministic(self):
        public_key, messages, _, proof = make_proof(height=4)
        kwargs = dict(public_key=public_key, max_bytes=len(proof) // 3)
        first = multiproof_partition(messages, proof, **kwargs)
        second = multiproof_partition(messages, bytearray(proof), **kwargs)
        self.assertEqual(first, second)

    def test_no_signature_quota_consumed(self):
        signer = make_signer(height=3)
        messages = tuple(f"m{i}" for i in range(8))
        signatures = signer.sign_batch(messages)
        proof = multiproof_encode(signer.public_key, signatures)
        index_before = signer.next_index
        multiproof_partition(
            messages,
            proof,
            public_key=signer.public_key,
            max_bytes=len(proof) // 2,
        )
        self.assertEqual(signer.next_index, index_before)


if __name__ == "__main__":
    unittest.main()

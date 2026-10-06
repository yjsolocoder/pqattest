import unittest

from pqattest import (
    MerkleSigner,
    multiproof_encode,
    multiproof_merge,
    multiproof_partition,
    multiproof_select,
    multiproof_verify,
    multiproof_verify_bound,
)
from pqattest.merkle import _MULTIPROOF_HEADER_BYTES

PUBLIC_KEY_BYTES = 43


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=3, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def make_proof(height=3, w=4, count=None, start=0, context=None):
    signer = make_signer(height=height, w=w, start=start)
    leaf_count = 1 << height
    if count is None:
        count = leaf_count
    messages = tuple(f"message-{i}" for i in range(count))
    signatures = (
        signer.sign_batch(messages, context=context)
        if context is not None
        else signer.sign_batch(messages)
    )
    proof = multiproof_encode(signer.public_key, signatures)
    return signer.public_key, messages, signatures, proof


def segment_size(signatures, public_key, start, end):
    return len(multiproof_encode(public_key, signatures[start:end]))


def packet_leaf_count(packet):
    # The v1 header carries the leaf count as two big-endian bytes at 13:15.
    return int.from_bytes(packet[13:15], "big")


def check_partition(
    case, messages, signatures, proof, public_key, max_bytes, **kwargs
):
    packets = multiproof_partition(
        messages, proof, public_key=public_key, max_bytes=max_bytes, **kwargs
    )
    case.assertIsInstance(packets, tuple)
    case.assertGreater(len(packets), 0)
    # Recover the segments from the packet headers and check that the
    # packets cover every source leaf exactly once, in order.
    segments = []
    position = 0
    for packet in packets:
        case.assertIsInstance(packet, bytes)
        case.assertLessEqual(len(packet), max_bytes)
        count = packet_leaf_count(packet)
        case.assertGreater(count, 0)
        segments.append(tuple(range(position, position + count)))
        position += count
    case.assertEqual(position, len(messages))
    case.assertEqual(
        tuple(index for segment in segments for index in segment),
        tuple(range(len(messages))),
    )
    for segment, packet in zip(segments, packets):
        # Each packet keeps the original public key, indices and W-OTS
        # elements: identical to encoding the segment's signatures.
        case.assertEqual(
            packet,
            multiproof_encode(
                public_key, tuple(signatures[i] for i in segment)
            ),
            "packet bytes differ from the segment's original signatures",
        )
    # And identical to extracting the segment with multiproof_select.
    case.assertEqual(
        packets[0],
        multiproof_select(
            messages, proof, public_key=public_key, indices=segments[0], **kwargs
        ),
    )
    # Every packet verifies on its own with its segment's messages.
    for segment, packet in zip(segments, packets):
        segment_messages = tuple(messages[i] for i in segment)
        segment_kwargs = {}
        if "contexts" in kwargs:
            segment_kwargs["contexts"] = tuple(
                kwargs["contexts"][i] for i in segment
            )
        elif "context" in kwargs:
            segment_kwargs["context"] = kwargs["context"]
        case.assertTrue(
            multiproof_verify(segment_messages, packet, **segment_kwargs)
        )
        case.assertTrue(
            multiproof_verify_bound(
                segment_messages,
                packet,
                public_key=public_key,
                indices=segment,
                **segment_kwargs,
            )
        )
    # Merging the packets restores the source bytes exactly.
    groups = tuple(
        tuple(messages[i] for i in segment) for segment in segments
    )
    merge_kwargs = {}
    if "contexts" in kwargs:
        merge_kwargs["context_groups"] = tuple(
            tuple(kwargs["contexts"][i] for i in segment) for segment in segments
        )
    elif "context" in kwargs:
        merge_kwargs["context"] = kwargs["context"]
    merged = multiproof_merge(groups, packets, public_key=public_key, **merge_kwargs)
    case.assertEqual(merged, proof)
    return packets, segments


class TestMultiproofPartitionFits(unittest.TestCase):
    def test_source_within_budget_returns_source_bytes(self):
        for w in (4, 8):
            for height in (1, 2, 3, 8):
                public_key, messages, _, proof = make_proof(w=w, height=height)
                for budget in (len(proof), len(proof) + 100):
                    with self.subTest(w=w, height=height, budget=budget):
                        packets = multiproof_partition(
                            messages, proof, public_key=public_key, max_bytes=budget
                        )
                        self.assertIsInstance(packets, tuple)
                        self.assertEqual(packets, (proof,))
                        self.assertIsInstance(packets[0], bytes)

    def test_bytearray_source_returns_plain_bytes(self):
        public_key, messages, _, proof = make_proof(height=2)
        packets = multiproof_partition(
            messages,
            bytearray(proof),
            public_key=public_key,
            max_bytes=len(proof),
        )
        self.assertEqual(packets, (proof,))
        self.assertIsInstance(packets[0], bytes)

    def test_single_packet_still_verifies_source(self):
        # The source fits the budget, but tampering must still fail the
        # call: the source is fully authenticated before the shortcut.
        public_key, messages, _, proof = make_proof(height=2)
        corrupted = bytearray(proof)
        corrupted[_MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES + 4] ^= 0xFF
        with self.assertRaises(ValueError):
            multiproof_partition(
                messages,
                bytes(corrupted),
                public_key=public_key,
                max_bytes=len(proof) + 1000,
            )
        wrong = ("tampered",) + messages[1:]
        with self.assertRaises(ValueError):
            multiproof_partition(
                wrong, proof, public_key=public_key, max_bytes=len(proof) + 1000
            )


class TestMultiproofPartitionSplitting(unittest.TestCase):
    def test_each_leaf_its_own_packet(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                public_key, messages, signatures, proof = make_proof(
                    w=w, height=height
                )
                budget = segment_size(signatures, public_key, 0, 1)
                with self.subTest(w=w, height=height):
                    packets, segments = check_partition(
                        self, messages, signatures, proof, public_key, budget
                    )
                    self.assertEqual(
                        tuple(segments), tuple((i,) for i in range(len(messages)))
                    )

    def test_minimal_packet_count_then_total_bytes(self):
        # Height 2, four leaves. A budget fitting three-leaf packets
        # admits three two-packet splits; [0,1]|[2,3] has the smallest
        # total byte count even though [0]|[1,2,3] has the
        # lexicographically smaller last-leaf tuple (0, 3).
        public_key, messages, signatures, proof = make_proof(height=2)
        budget = max(
            segment_size(signatures, public_key, 0, 3),
            segment_size(signatures, public_key, 1, 4),
        )
        self.assertGreater(len(proof), budget)  # the source needs a split
        packets = multiproof_partition(
            messages, proof, public_key=public_key, max_bytes=budget
        )
        self.assertEqual(len(packets), 2)
        self.assertEqual(
            packets,
            (
                multiproof_encode(public_key, signatures[0:2]),
                multiproof_encode(public_key, signatures[2:4]),
            ),
        )

    def test_last_leaf_tuple_breaks_remaining_ties(self):
        # Height 4, sixteen leaves. With this budget the 3-packet splits
        # [0:4]|[4:10]|[10:16] (last leaves (3, 9, 15)) and
        # [0:6]|[6:12]|[12:16] (last leaves (5, 11, 15)) tie on packet
        # count and on total bytes; the lexicographically smaller
        # last-leaf tuple wins.
        public_key, messages, signatures, proof = make_proof(height=4)
        winning = tuple(
            multiproof_encode(public_key, signatures[start:end])
            for start, end in ((0, 4), (4, 10), (10, 16))
        )
        tied = tuple(
            multiproof_encode(public_key, signatures[start:end])
            for start, end in ((0, 6), (6, 12), (12, 16))
        )
        self.assertEqual(
            sum(len(packet) for packet in winning),
            sum(len(packet) for packet in tied),
        )
        budget = max(len(packet) for packet in winning + tied)
        self.assertGreater(len(proof), budget)
        packets = multiproof_partition(
            messages, proof, public_key=public_key, max_bytes=budget
        )
        self.assertEqual(packets, winning)

    def test_varied_budgets_across_heights_and_w(self):
        for w in (4, 8):
            for height in (1, 2, 3, 4, 8):
                public_key, messages, signatures, proof = make_proof(
                    w=w, height=height
                )
                if height <= 4:
                    sizes = sorted(
                        {
                            segment_size(signatures, public_key, start, end)
                            for start in range(len(messages))
                            for end in range(start + 1, len(messages) + 1)
                        }
                    )
                    budgets = {
                        sizes[0],
                        sizes[len(sizes) // 2],
                        sizes[-1] - 1,
                        len(proof) - 1,
                    }
                else:
                    budgets = {
                        segment_size(signatures, public_key, 0, 1),
                        len(proof) - 1,
                    }
                for budget in budgets:
                    with self.subTest(w=w, height=height, budget=budget):
                        check_partition(
                            self, messages, signatures, proof, public_key, budget
                        )

    def test_sparse_source_proof(self):
        public_key, messages, signatures, _ = make_proof(height=4)
        keep = (0, 3, 7, 11, 15)
        sparse_signatures = tuple(signatures[i] for i in keep)
        sparse = multiproof_encode(public_key, sparse_signatures)
        sparse_messages = tuple(messages[i] for i in keep)
        budget = max(
            segment_size(sparse_signatures, public_key, 0, 3),
            segment_size(sparse_signatures, public_key, 3, 5),
        )
        packets = multiproof_partition(
            sparse_messages, sparse, public_key=public_key, max_bytes=budget
        )
        self.assertEqual(
            packets,
            (
                multiproof_encode(public_key, sparse_signatures[0:3]),
                multiproof_encode(public_key, sparse_signatures[3:5]),
            ),
        )
        # The packets keep the actual sparse leaf indices.
        self.assertTrue(
            multiproof_verify_bound(
                sparse_messages[:3],
                packets[0],
                public_key=public_key,
                indices=keep[:3],
            )
        )
        self.assertTrue(
            multiproof_verify_bound(
                sparse_messages[3:],
                packets[1],
                public_key=public_key,
                indices=keep[3:],
            )
        )
        merged = multiproof_merge(
            (sparse_messages[:3], sparse_messages[3:]),
            packets,
            public_key=public_key,
        )
        self.assertEqual(merged, sparse)

    def test_duplicate_messages_are_not_merged(self):
        signer = make_signer(height=2)
        messages = ("same", "same", "other", "same")
        signatures = signer.sign_batch(messages)
        proof = multiproof_encode(signer.public_key, signatures)
        budget = max(
            segment_size(signatures, signer.public_key, 0, 2),
            segment_size(signatures, signer.public_key, 2, 4),
        )
        packets = multiproof_partition(
            messages, proof, public_key=signer.public_key, max_bytes=budget
        )
        self.assertEqual(
            packets,
            (
                multiproof_encode(signer.public_key, signatures[0:2]),
                multiproof_encode(signer.public_key, signatures[2:4]),
            ),
        )
        self.assertTrue(multiproof_verify(("same", "same"), packets[0]))
        self.assertTrue(multiproof_verify(("other", "same"), packets[1]))

    def test_message_member_forms_and_bytearray_data(self):
        public_key, messages, signatures, proof = make_proof(height=2)
        mixed = tuple(
            bytearray(m.encode()) if i % 2 else m for i, m in enumerate(messages)
        )
        budget = max(
            segment_size(signatures, public_key, 0, 2),
            segment_size(signatures, public_key, 2, 4),
        )
        packets = multiproof_partition(
            mixed, bytearray(proof), public_key=public_key, max_bytes=budget
        )
        self.assertEqual(
            packets,
            (
                multiproof_encode(public_key, signatures[0:2]),
                multiproof_encode(public_key, signatures[2:4]),
            ),
        )

    def test_deterministic_and_inputs_not_modified(self):
        public_key, messages, _, proof = make_proof(height=3)
        budget = len(proof) - 1
        data = bytearray(proof)
        first = multiproof_partition(
            messages, data, public_key=public_key, max_bytes=budget
        )
        second = multiproof_partition(
            messages, data, public_key=public_key, max_bytes=budget
        )
        self.assertEqual(first, second)
        self.assertEqual(bytes(data), proof)


class TestMultiproofPartitionContexts(unittest.TestCase):
    def make_per_leaf(self, height=3, w=4):
        signer = make_signer(height=height, w=w)
        leaf_count = 1 << height
        messages = tuple(f"message-{i}" for i in range(leaf_count))
        contexts = tuple(f"ctx-{i}" for i in range(leaf_count))
        signatures = signer.sign_batch(messages, contexts=contexts)
        proof = multiproof_encode(signer.public_key, signatures)
        return signer.public_key, messages, contexts, signatures, proof

    def test_shared_context(self):
        public_key, messages, signatures, proof = make_proof(height=3, context="ctx")
        budget = max(
            segment_size(signatures, public_key, 0, 4),
            segment_size(signatures, public_key, 4, 8),
        )
        packets = multiproof_partition(
            messages, proof, public_key=public_key, max_bytes=budget, context="ctx"
        )
        self.assertEqual(
            packets,
            (
                multiproof_encode(public_key, signatures[0:4]),
                multiproof_encode(public_key, signatures[4:8]),
            ),
        )
        self.assertTrue(
            multiproof_verify(messages[:4], packets[0], context="ctx")
        )
        self.assertTrue(
            multiproof_verify(messages[4:], packets[1], context="ctx")
        )
        self.assertFalse(multiproof_verify(messages[:4], packets[0]))

    def test_shared_context_mismatch_fails(self):
        public_key, messages, _, proof = make_proof(height=2, context="ctx")
        for bad_context in (None, b"", "other", b"ctx\x00"):
            with self.subTest(context=bad_context):
                with self.assertRaises(ValueError):
                    multiproof_partition(
                        messages,
                        proof,
                        public_key=public_key,
                        max_bytes=len(proof),
                        context=bad_context,
                    )

    def test_per_leaf_contexts(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                public_key, messages, contexts, signatures, proof = (
                    self.make_per_leaf(height=height, w=w)
                )
                budgets = {
                    segment_size(signatures, public_key, 0, 1),
                    len(proof) - 1,
                }
                for budget in budgets:
                    with self.subTest(w=w, height=height, budget=budget):
                        packets, segments = check_partition(
                            self,
                            messages,
                            signatures,
                            proof,
                            public_key,
                            budget,
                            contexts=contexts,
                        )
                        # Without the contexts the packets must not verify.
                        for segment, packet in zip(segments, packets):
                            self.assertFalse(
                                multiproof_verify(
                                    tuple(messages[i] for i in segment), packet
                                )
                            )

    def test_per_leaf_context_of_any_leaf_mismatch_fails(self):
        public_key, messages, contexts, _, proof = self.make_per_leaf(height=2)
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
        public_key, messages, contexts, signatures, proof = self.make_per_leaf(
            height=2
        )
        budget = len(proof) - 1
        expected = multiproof_partition(
            messages,
            proof,
            public_key=public_key,
            max_bytes=budget,
            contexts=contexts,
        )
        for empty in (None, b"", bytearray(), ""):
            with self.subTest(context=empty):
                packets = multiproof_partition(
                    messages,
                    proof,
                    public_key=public_key,
                    max_bytes=budget,
                    context=empty,
                    contexts=contexts,
                )
                self.assertEqual(packets, expected)

    def test_contexts_member_form_variants_normalise(self):
        signer = make_signer(height=2)
        messages = ("a", "b", "c", "d")
        contexts = (None, "ctx-1", b"", "ctx-3")
        signatures = signer.sign_batch(messages, contexts=contexts)
        public_key = signer.public_key
        proof = multiproof_encode(public_key, signatures)
        budget = max(
            segment_size(signatures, public_key, 0, 2),
            segment_size(signatures, public_key, 2, 4),
        )
        packets = multiproof_partition(
            messages,
            proof,
            public_key=public_key,
            max_bytes=budget,
            contexts=(None, bytearray(b"ctx-1"), bytearray(), b"ctx-3"),
        )
        self.assertEqual(
            packets,
            (
                multiproof_encode(public_key, signatures[0:2]),
                multiproof_encode(public_key, signatures[2:4]),
            ),
        )
        self.assertTrue(
            multiproof_verify(
                ("c", "d"), packets[1], contexts=(None, "ctx-3")
            )
        )


class TestMultiproofPartitionValidation(unittest.TestCase):
    def setUp(self):
        self.public_key, self.messages, self.signatures, self.proof = make_proof(
            height=2
        )
        self.budget = len(self.proof) - 1

    def partition(self, messages=None, data=None, **kwargs):
        if messages is None:
            messages = self.messages
        if data is None:
            data = self.proof
        kwargs.setdefault("public_key", self.public_key)
        kwargs.setdefault("max_bytes", self.budget)
        return multiproof_partition(messages, data, **kwargs)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            self.partition(data="not-bytes")
        with self.assertRaises(TypeError):
            multiproof_partition(
                self.messages,
                None,
                public_key=self.public_key,
                max_bytes=self.budget,
            )
        with self.assertRaises(TypeError):
            self.partition(messages=list(self.messages))
        with self.assertRaises(TypeError):
            self.partition(messages=self.messages[:3] + (1,))
        with self.assertRaises(TypeError):
            self.partition(public_key="key")
        with self.assertRaises(TypeError):
            self.partition(max_bytes="1000")
        with self.assertRaises(TypeError):
            self.partition(max_bytes=1000.0)
        with self.assertRaises(TypeError):
            self.partition(max_bytes=None)
        with self.assertRaises(TypeError):
            self.partition(context=1)
        with self.assertRaises(TypeError):
            self.partition(contexts=[None] * 4)
        with self.assertRaises(TypeError):
            self.partition(contexts=(1,) * 4)

    def test_type_checks_precede_content_checks(self):
        # Bad max_bytes type with empty messages: TypeError wins.
        with self.assertRaises(TypeError):
            self.partition(messages=(), max_bytes="x")
        # Bad contexts container with a non-positive budget: TypeError wins.
        with self.assertRaises(TypeError):
            self.partition(max_bytes=0, contexts=[])
        # Bad contexts member with malformed source data: TypeError wins.
        with self.assertRaises(TypeError):
            self.partition(data=b"", contexts=(1,) * 4)
        # Bad data type with a boolean budget: TypeError wins.
        with self.assertRaises(TypeError):
            self.partition(data=123, max_bytes=True)

    def test_budget_value_errors(self):
        for bad in (True, False, 0, -1, -1000):
            with self.subTest(max_bytes=bad):
                with self.assertRaises(ValueError):
                    self.partition(max_bytes=bad)

    def test_empty_messages_fails(self):
        with self.assertRaises(ValueError):
            self.partition(messages=())

    def test_contexts_value_errors(self):
        with self.assertRaises(ValueError):
            self.partition(contexts=())
        with self.assertRaises(ValueError):
            self.partition(contexts=(None,) * 3)
        with self.assertRaises(ValueError):
            self.partition(contexts=(None,) * 5)
        with self.assertRaises(ValueError):
            self.partition(context="ctx", contexts=(None,) * 4)

    def test_message_count_mismatch_fails(self):
        for bad_messages in (self.messages[:3], self.messages + ("extra",)):
            with self.subTest(count=len(bad_messages)):
                with self.assertRaises(ValueError):
                    self.partition(messages=bad_messages)

    def test_malformed_source_proof_fails(self):
        for bad in (self.proof[:-1], self.proof + b"\x00", b"", b"\x00" * 32):
            with self.subTest(bad=bad[:12]):
                with self.assertRaises(ValueError):
                    self.partition(data=bad)
        corrupted = bytearray(self.proof)
        corrupted[8] = 2
        with self.assertRaises(ValueError):
            self.partition(data=bytes(corrupted))

    def test_public_key_mismatch_fails(self):
        other = make_signer(height=2, start=1000).public_key
        with self.assertRaises(ValueError):
            self.partition(public_key=other)
        same_root_other_w = type(self.public_key)(
            w=8, height=self.public_key.height, root=self.public_key.root
        )
        with self.assertRaises(ValueError):
            self.partition(public_key=same_root_other_w)

    def test_verification_failure_fails(self):
        corrupted = bytearray(self.proof)
        corrupted[_MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES + 4] ^= 0xFF
        with self.assertRaises(ValueError):
            self.partition(data=bytes(corrupted))
        wrong = ("tampered",) + self.messages[1:]
        with self.assertRaises(ValueError):
            self.partition(messages=wrong)

    def test_infeasible_budget_fails(self):
        smallest = segment_size(self.signatures, self.public_key, 0, 1)
        for budget in (smallest - 1, 1):
            with self.subTest(budget=budget):
                with self.assertRaises(ValueError):
                    self.partition(max_bytes=budget)

    def test_smallest_feasible_budget_splits_into_single_leaves(self):
        # Every single-leaf packet of one tree has the same size, so the
        # smallest feasible budget always admits the all-singletons split.
        smallest = segment_size(self.signatures, self.public_key, 0, 1)
        packets = self.partition(max_bytes=smallest)
        self.assertEqual(len(packets), len(self.messages))
        self.assertTrue(all(len(packet) == smallest for packet in packets))


if __name__ == "__main__":
    unittest.main()

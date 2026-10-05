import unittest

from pqattest import (
    MerkleSigner,
    multiproof_encode,
    multiproof_merge,
    multiproof_select,
    multiproof_verify,
    multiproof_verify_bound,
)
from pqattest.merkle import _MULTIPROOF_HEADER_BYTES, _params

PUBLIC_KEY_BYTES = 43


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=3, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def make_full(height=3, w=4, context=None):
    signer = make_signer(height=height, w=w)
    messages = tuple(f"message-{i}" for i in range(1 << height))
    signatures = (
        signer.sign_batch(messages, context=context)
        if context is not None
        else signer.sign_batch(messages)
    )
    return signer.public_key, messages, signatures


def proof_for(public_key, signatures, indices):
    return multiproof_encode(
        public_key, tuple(signatures[i] for i in indices)
    )


def group_for(messages, indices):
    return tuple(messages[i] for i in indices)


class TestMultiproofMergeEquivalence(unittest.TestCase):
    def test_single_source_returns_source_bytes(self):
        for w in (4, 8):
            for height in (1, 2, 3, 8):
                public_key, messages, signatures = make_full(w=w, height=height)
                for indices in [
                    (0,),
                    ((1 << height) - 1,),
                    tuple(range(1 << height)),
                ]:
                    with self.subTest(w=w, height=height, indices=indices):
                        proof = proof_for(public_key, signatures, indices)
                        merged = multiproof_merge(
                            (group_for(messages, indices),),
                            (proof,),
                            public_key=public_key,
                        )
                        self.assertIsInstance(merged, bytes)
                        self.assertEqual(merged, proof)

    def test_matches_multiproof_encode_of_union(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                public_key, messages, signatures = make_full(w=w, height=height)
                leaf_count = 1 << height
                splits = [
                    ((0,), (leaf_count - 1,)),
                    (
                        tuple(range(0, leaf_count, 2)),
                        tuple(range(1, leaf_count, 2)),
                    ),
                    (
                        tuple(range(leaf_count // 2)),
                        tuple(range(leaf_count // 2, leaf_count)),
                    ),
                ]
                for left, right in splits:
                    with self.subTest(w=w, height=height):
                        proof_left = proof_for(public_key, signatures, left)
                        proof_right = proof_for(public_key, signatures, right)
                        merged = multiproof_merge(
                            (
                                group_for(messages, left),
                                group_for(messages, right),
                            ),
                            (proof_left, proof_right),
                            public_key=public_key,
                        )
                        union = tuple(sorted(set(left) | set(right)))
                        expected = proof_for(public_key, signatures, union)
                        self.assertEqual(merged, expected)

    def test_overlapping_sources(self):
        public_key, messages, signatures = make_full(height=4)
        left = (0, 3, 7, 11)
        right = (3, 7, 11, 15)
        merged = multiproof_merge(
            (group_for(messages, left), group_for(messages, right)),
            (
                proof_for(public_key, signatures, left),
                proof_for(public_key, signatures, right),
            ),
            public_key=public_key,
        )
        union = (0, 3, 7, 11, 15)
        self.assertEqual(merged, proof_for(public_key, signatures, union))
        self.assertTrue(
            multiproof_verify(group_for(messages, union), merged)
        )
        self.assertTrue(
            multiproof_verify_bound(
                group_for(messages, union),
                merged,
                public_key=public_key,
                indices=union,
            )
        )

    def test_sparse_and_single_leaf_sources(self):
        public_key, messages, signatures = make_full(height=5)
        groups = [(0,), (31,), (7, 8, 9), (1, 30)]
        proofs = tuple(
            proof_for(public_key, signatures, indices) for indices in groups
        )
        message_groups = tuple(
            group_for(messages, indices) for indices in groups
        )
        merged = multiproof_merge(
            message_groups, proofs, public_key=public_key
        )
        union = tuple(sorted(set().union(*[set(g) for g in groups])))
        self.assertEqual(merged, proof_for(public_key, signatures, union))

    def test_source_order_is_irrelevant(self):
        public_key, messages, signatures = make_full(height=4)
        groups = [(0, 1, 2), (3, 4, 5), (1, 5, 9, 13), (14, 15)]
        proofs = [
            proof_for(public_key, signatures, indices) for indices in groups
        ]
        message_groups = [group_for(messages, indices) for indices in groups]
        first = multiproof_merge(
            tuple(message_groups), tuple(proofs), public_key=public_key
        )
        order = (3, 1, 0, 2)
        second = multiproof_merge(
            tuple(message_groups[i] for i in order),
            tuple(proofs[i] for i in order),
            public_key=public_key,
        )
        self.assertEqual(first, second)

    def test_duplicate_source_submissions(self):
        public_key, messages, signatures = make_full(height=3)
        left = (0, 2, 3)
        right = (3, 5, 7)
        proof_left = proof_for(public_key, signatures, left)
        proof_right = proof_for(public_key, signatures, right)
        base = multiproof_merge(
            (group_for(messages, left), group_for(messages, right)),
            (proof_left, proof_right),
            public_key=public_key,
        )
        repeated = multiproof_merge(
            (
                group_for(messages, left),
                group_for(messages, left),
                group_for(messages, right),
                group_for(messages, right),
            ),
            (proof_left, proof_left, proof_right, proof_right),
            public_key=public_key,
        )
        self.assertEqual(repeated, base)

    def test_staged_merge_matches_one_shot(self):
        public_key, messages, signatures = make_full(height=4)
        a = (0, 1)
        b = (5, 6)
        c = (13, 14)
        p_a = proof_for(public_key, signatures, a)
        p_b = proof_for(public_key, signatures, b)
        p_c = proof_for(public_key, signatures, c)
        one_shot = multiproof_merge(
            (
                group_for(messages, a),
                group_for(messages, b),
                group_for(messages, c),
            ),
            (p_a, p_b, p_c),
            public_key=public_key,
        )
        first = multiproof_merge(
            (group_for(messages, a), group_for(messages, b)),
            (p_a, p_b),
            public_key=public_key,
        )
        staged = multiproof_merge(
            (
                group_for(messages, sorted(set(a) | set(b))),
                group_for(messages, c),
            ),
            (first, p_c),
            public_key=public_key,
        )
        self.assertEqual(staged, one_shot)

    def test_same_message_at_different_leaves_kept_distinct(self):
        signer = make_signer(height=2)
        messages = ("same", "same", "same", "same")
        signatures = signer.sign_batch(messages)
        p_left = multiproof_encode(
            signer.public_key, (signatures[0], signatures[1])
        )
        p_right = multiproof_encode(
            signer.public_key, (signatures[2], signatures[3])
        )
        merged = multiproof_merge(
            (("same", "same"), ("same", "same")),
            (p_left, p_right),
            public_key=signer.public_key,
        )
        self.assertEqual(
            merged, multiproof_encode(signer.public_key, signatures)
        )
        self.assertTrue(multiproof_verify(messages, merged))

    def test_consistent_overlap_accepts_message_form_variants(self):
        public_key, messages, signatures = make_full(height=3)
        indices = (0, 2, 3)
        proof = proof_for(public_key, signatures, indices)
        as_bytes = tuple(m.encode() for m in group_for(messages, indices))
        as_bytearray = tuple(bytearray(m) for m in as_bytes)
        merged = multiproof_merge(
            (as_bytes, as_bytearray, group_for(messages, indices)),
            (proof, bytearray(proof), proof),
            public_key=public_key,
        )
        self.assertEqual(merged, proof)

    def test_merged_result_supports_select_and_remerge(self):
        public_key, messages, signatures = make_full(height=3)
        left = (0, 2, 3)
        right = (3, 5, 7)
        merged = multiproof_merge(
            (group_for(messages, left), group_for(messages, right)),
            (
                proof_for(public_key, signatures, left),
                proof_for(public_key, signatures, right),
            ),
            public_key=public_key,
        )
        union = (0, 2, 3, 5, 7)
        selected = multiproof_select(
            group_for(messages, union),
            merged,
            public_key=public_key,
            indices=(2, 5),
        )
        self.assertEqual(
            selected,
            multiproof_encode(public_key, (signatures[2], signatures[5])),
        )
        extra = proof_for(public_key, signatures, (1,))
        re_merged = multiproof_merge(
            (group_for(messages, union), (messages[1],)),
            (merged, extra),
            public_key=public_key,
        )
        self.assertEqual(
            re_merged,
            proof_for(public_key, signatures, (0, 1, 2, 3, 5, 7)),
        )

    def test_inputs_are_not_modified(self):
        public_key, messages, signatures = make_full(height=3)
        left = (0, 2, 3)
        right = (3, 5, 7)
        p_left = bytearray(proof_for(public_key, signatures, left))
        p_right = bytearray(proof_for(public_key, signatures, right))
        left_before = bytes(p_left)
        right_before = bytes(p_right)
        multiproof_merge(
            (group_for(messages, left), group_for(messages, right)),
            (p_left, p_right),
            public_key=public_key,
        )
        self.assertEqual(bytes(p_left), left_before)
        self.assertEqual(bytes(p_right), right_before)


class TestMultiproofMergeContext(unittest.TestCase):
    def test_context_binding(self):
        public_key, messages, signatures = make_full(height=3, context="ctx")
        left = (1, 2)
        right = (6,)
        merged = multiproof_merge(
            (group_for(messages, left), group_for(messages, right)),
            (
                proof_for(public_key, signatures, left),
                proof_for(public_key, signatures, right),
            ),
            public_key=public_key,
            context="ctx",
        )
        union = (1, 2, 6)
        self.assertEqual(merged, proof_for(public_key, signatures, union))
        self.assertTrue(
            multiproof_verify(
                group_for(messages, union), merged, context="ctx"
            )
        )

    def test_context_mismatch_raises_value_error(self):
        public_key, messages, signatures = make_full(height=3, context="ctx")
        left = (1, 2)
        right = (6,)
        for bad_context in (None, b"", "", "other", b"ctx\x00"):
            with self.subTest(context=bad_context):
                with self.assertRaises(ValueError):
                    multiproof_merge(
                        (
                            group_for(messages, left),
                            group_for(messages, right),
                        ),
                        (
                            proof_for(public_key, signatures, left),
                            proof_for(public_key, signatures, right),
                        ),
                        public_key=public_key,
                        context=bad_context,
                    )

    def test_bound_proof_fails_under_unexpected_context(self):
        public_key, messages, signatures = make_full(height=3)
        indices = (0, 1)
        proof = proof_for(public_key, signatures, indices)
        with self.assertRaises(ValueError):
            multiproof_merge(
                (group_for(messages, indices),),
                (proof,),
                public_key=public_key,
                context="ctx",
            )


class TestMultiproofMergeSourceAuthentication(unittest.TestCase):
    def setUp(self):
        self.public_key, self.messages, self.signatures = make_full(height=3)
        self.left = (0, 2, 3)
        self.right = (5, 7)
        self.p_left = proof_for(
            self.public_key, self.signatures, self.left
        )
        self.p_right = proof_for(
            self.public_key, self.signatures, self.right
        )

    def merge(self, message_groups=None, proofs=None, **kwargs):
        if message_groups is None:
            message_groups = (
                group_for(self.messages, self.left),
                group_for(self.messages, self.right),
            )
        if proofs is None:
            proofs = (self.p_left, self.p_right)
        kwargs.setdefault("public_key", self.public_key)
        return multiproof_merge(message_groups, proofs, **kwargs)

    def test_wrong_message_at_unselected_leaf_fails(self):
        # Leaf 0 is absent from the second proof; the corrupted message is
        # still in a proof that must authenticate fully.
        tampered = ("tampered",) + self.messages[1:]
        with self.assertRaises(ValueError):
            multiproof_merge(
                (
                    group_for(tampered, self.left),
                    group_for(self.messages, self.right),
                ),
                (self.p_left, self.p_right),
                public_key=self.public_key,
            )

    def test_corrupted_unselected_leaf_elements_fail(self):
        # First leaf's first W-OTS element inside the first proof.
        offset = _MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES + 4
        corrupted = bytearray(self.p_left)
        corrupted[offset] ^= 0xFF
        with self.assertRaises(ValueError):
            self.merge(
                proofs=(bytes(corrupted), self.p_right),
            )

    def test_malformed_source_proof_fails(self):
        for bad in (
            self.p_left[:-1],
            self.p_left + b"\x00",
            b"",
            b"\x00" * 32,
        ):
            with self.subTest(bad=bad[:12]):
                with self.assertRaises(ValueError):
                    multiproof_merge(
                        (
                            group_for(self.messages, self.left),
                            group_for(self.messages, self.right),
                        ),
                        (bad, self.p_right),
                        public_key=self.public_key,
                    )
        wrong_version = bytearray(self.p_left)
        wrong_version[8] = 2
        with self.assertRaises(ValueError):
            self.merge(proofs=(bytes(wrong_version), self.p_right))

    def test_non_canonical_node_order_fails(self):
        b, l1, l2 = _params(self.public_key.w)
        chains = l1 + l2
        # The first proof (three sparse leaves) carries at least two node
        # records of 35 bytes; swap the first two records and require the
        # strict parser to reject them.
        node_section = (
            _MULTIPROOF_HEADER_BYTES
            + PUBLIC_KEY_BYTES
            + len(self.left) * (4 + chains * 32)
        )
        reordered = bytearray(self.p_left)
        first = bytes(reordered[node_section : node_section + 35])
        second = bytes(reordered[node_section + 35 : node_section + 70])
        reordered[node_section : node_section + 35] = second
        reordered[node_section + 35 : node_section + 70] = first
        with self.assertRaises(ValueError):
            self.merge(proofs=(bytes(reordered), self.p_right))

    def test_public_key_mismatch_fails(self):
        other = make_signer(height=3, start=1000).public_key
        with self.assertRaises(ValueError):
            self.merge(public_key=other)
        same_root_other_w = type(self.public_key)(
            w=8,
            height=self.public_key.height,
            root=self.public_key.root,
        )
        with self.assertRaises(ValueError):
            self.merge(public_key=same_root_other_w)

    def test_message_count_mismatch_fails(self):
        groups = (
            group_for(self.messages, self.left),
            group_for(self.messages, self.right),
        )
        with self.assertRaises(ValueError):
            self.merge(message_groups=(groups[0][:2], groups[1]))
        with self.assertRaises(ValueError):
            self.merge(
                message_groups=(groups[0], groups[1] + ("extra",))
            )

    def test_conflicting_overlapping_leaf_message_fails(self):
        overlap = (3, 5)
        p_overlap = proof_for(self.public_key, self.signatures, overlap)
        good = group_for(self.messages, overlap)
        bad = (good[0], "different-message")
        with self.assertRaises(ValueError):
            multiproof_merge(
                (group_for(self.messages, self.left), bad),
                (self.p_left, p_overlap),
                public_key=self.public_key,
            )


def make_full_per_leaf(height=3, w=4):
    signer = make_signer(height=height, w=w)
    count = 1 << height
    messages = tuple(f"message-{i}" for i in range(count))
    contexts = tuple(f"ctx-{i}" for i in range(count))
    signatures = signer.sign_batch(messages, contexts=contexts)
    return signer.public_key, messages, contexts, signatures


class TestMultiproofMergeContextGroups(unittest.TestCase):
    def test_per_leaf_context_merge_matches_encode(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                public_key, messages, contexts, signatures = make_full_per_leaf(
                    height=height, w=w
                )
                leaf_count = 1 << height
                splits = [
                    ((0,), (leaf_count - 1,)),
                    (
                        tuple(range(0, leaf_count, 2)),
                        tuple(range(1, leaf_count, 2)),
                    ),
                    (
                        tuple(range(leaf_count // 2)),
                        tuple(range(leaf_count // 2, leaf_count)),
                    ),
                ]
                for left, right in splits:
                    with self.subTest(w=w, height=height, split=(left, right)):
                        merged = multiproof_merge(
                            (
                                group_for(messages, left),
                                group_for(messages, right),
                            ),
                            (
                                proof_for(public_key, signatures, left),
                                proof_for(public_key, signatures, right),
                            ),
                            public_key=public_key,
                            context_groups=(
                                group_for(contexts, left),
                                group_for(contexts, right),
                            ),
                        )
                        union = tuple(sorted(set(left) | set(right)))
                        self.assertEqual(
                            merged, proof_for(public_key, signatures, union)
                        )
                        self.assertTrue(
                            multiproof_verify_bound(
                                group_for(messages, union),
                                merged,
                                public_key=public_key,
                                indices=union,
                                contexts=group_for(contexts, union),
                            )
                        )

    def test_sparse_height_eight(self):
        for w in (4, 8):
            public_key, messages, contexts, signatures = make_full_per_leaf(
                height=8, w=w
            )
            groups = [(0,), (255,), (100, 101, 200)]
            merged = multiproof_merge(
                tuple(group_for(messages, g) for g in groups),
                tuple(proof_for(public_key, signatures, g) for g in groups),
                public_key=public_key,
                context_groups=tuple(group_for(contexts, g) for g in groups),
            )
            union = (0, 100, 101, 200, 255)
            self.assertEqual(merged, proof_for(public_key, signatures, union))

    def test_single_source_returns_source_bytes(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(height=3)
        for indices in [(0,), (7,), tuple(range(8))]:
            with self.subTest(indices=indices):
                proof = proof_for(public_key, signatures, indices)
                merged = multiproof_merge(
                    (group_for(messages, indices),),
                    (proof,),
                    public_key=public_key,
                    context_groups=(group_for(contexts, indices),),
                )
                self.assertEqual(merged, proof)

    def test_member_form_variants_normalise(self):
        signer = make_signer(height=2)
        messages = ("a", "b", "c", "d")
        contexts = (None, "ctx", b"", "other")
        signatures = signer.sign_batch(messages, contexts=contexts)
        public_key = signer.public_key
        left = (0, 1)
        right = (1, 2, 3)
        merged = multiproof_merge(
            (group_for(messages, left), group_for(messages, right)),
            (
                proof_for(public_key, signatures, left),
                proof_for(public_key, signatures, right),
            ),
            public_key=public_key,
            context_groups=(
                (None, b"ctx"),
                (bytearray(b"ctx"), bytearray(), "other"),
            ),
        )
        union = (0, 1, 2, 3)
        self.assertEqual(merged, proof_for(public_key, signatures, union))
        self.assertTrue(
            multiproof_verify(
                messages,
                merged,
                contexts=(None, "ctx", None, "other"),
            )
        )

    def test_omitted_and_none_keep_shared_context_behaviour(self):
        public_key, messages, signatures = make_full(height=3, context="ctx")
        left = (1, 2)
        right = (6,)
        groups = (group_for(messages, left), group_for(messages, right))
        proofs = (
            proof_for(public_key, signatures, left),
            proof_for(public_key, signatures, right),
        )
        baseline = multiproof_merge(
            groups, proofs, public_key=public_key, context="ctx"
        )
        explicit_none = multiproof_merge(
            groups,
            proofs,
            public_key=public_key,
            context="ctx",
            context_groups=None,
        )
        self.assertEqual(baseline, explicit_none)

    def test_empty_shared_context_combines_with_context_groups(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(height=2)
        indices = (0, 3)
        proof = proof_for(public_key, signatures, indices)
        group = group_for(messages, indices)
        context_group = group_for(contexts, indices)
        expected = multiproof_merge(
            (group,),
            (proof,),
            public_key=public_key,
            context_groups=(context_group,),
        )
        for empty in (None, b"", bytearray(), ""):
            with self.subTest(context=empty):
                self.assertEqual(
                    multiproof_merge(
                        (group,),
                        (proof,),
                        public_key=public_key,
                        context=empty,
                        context_groups=(context_group,),
                    ),
                    expected,
                )

    def test_non_empty_shared_context_conflicts(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(height=2)
        indices = (0, 3)
        proof = proof_for(public_key, signatures, indices)
        for bad_context in ("ctx", b"ctx", bytearray(b"x")):
            with self.subTest(context=bad_context):
                with self.assertRaises(ValueError):
                    multiproof_merge(
                        (group_for(messages, indices),),
                        (proof,),
                        public_key=public_key,
                        context=bad_context,
                        context_groups=(group_for(contexts, indices),),
                    )

    def test_context_groups_type_errors(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(height=2)
        indices = (0, 1)
        proof = proof_for(public_key, signatures, indices)
        group = group_for(messages, indices)
        context_group = group_for(contexts, indices)

        def merge(**kwargs):
            kwargs.setdefault("public_key", public_key)
            return multiproof_merge((group,), (proof,), **kwargs)

        with self.assertRaises(TypeError):
            merge(context_groups=[context_group])
        with self.assertRaises(TypeError):
            merge(context_groups="ctx")
        with self.assertRaises(TypeError):
            merge(context_groups=(list(context_group),))
        with self.assertRaises(TypeError):
            merge(context_groups=("ctx",))
        with self.assertRaises(TypeError):
            merge(context_groups=((1, "ctx-1"),))
        with self.assertRaises(TypeError):
            merge(context_groups=((object(), None),))
        # Type checks precede all content checks.
        with self.assertRaises(TypeError):
            multiproof_merge((), (), public_key=public_key, context_groups=[])
        with self.assertRaises(TypeError):
            multiproof_merge(
                (group,),
                (proof,),
                public_key="not-a-key",
                context_groups=(context_group,),
            )

    def test_context_groups_value_errors(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(height=2)
        left = (0, 1)
        right = (2, 3)
        groups = (group_for(messages, left), group_for(messages, right))
        proofs = (
            proof_for(public_key, signatures, left),
            proof_for(public_key, signatures, right),
        )
        context_groups = (
            group_for(contexts, left),
            group_for(contexts, right),
        )

        def merge(cg):
            return multiproof_merge(
                groups, proofs, public_key=public_key, context_groups=cg
            )

        # Empty outer tuple: group count differs from the proof count.
        with self.assertRaises(ValueError):
            merge(())
        # Group count mismatch.
        with self.assertRaises(ValueError):
            merge(context_groups[:1])
        with self.assertRaises(ValueError):
            merge(context_groups + (("x",),))
        # Empty inner group.
        with self.assertRaises(ValueError):
            merge(((), context_groups[1]))
        # Inner count differs from the message/leaf count.
        with self.assertRaises(ValueError):
            merge((context_groups[0][:1], context_groups[1]))
        with self.assertRaises(ValueError):
            merge((context_groups[0] + ("extra",), context_groups[1]))

    def test_overlapping_leaf_context_conflict_fails(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(height=3)
        left = (0, 2, 3)
        right = (3, 5)
        with self.assertRaises(ValueError):
            multiproof_merge(
                (group_for(messages, left), group_for(messages, right)),
                (
                    proof_for(public_key, signatures, left),
                    proof_for(public_key, signatures, right),
                ),
                public_key=public_key,
                context_groups=(
                    group_for(contexts, left),
                    ("ctx-3-wrong", "ctx-5"),
                ),
            )

    def test_overlapping_leaf_same_context_merges(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(height=3)
        left = (0, 2, 3)
        right = (3, 5)
        merged = multiproof_merge(
            (group_for(messages, left), group_for(messages, right)),
            (
                proof_for(public_key, signatures, left),
                proof_for(public_key, signatures, right),
            ),
            public_key=public_key,
            context_groups=(
                group_for(contexts, left),
                (b"ctx-3", bytearray(b"ctx-5")),
            ),
        )
        union = (0, 2, 3, 5)
        self.assertEqual(merged, proof_for(public_key, signatures, union))

    def test_source_order_duplicates_and_staging(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(height=4)
        groups = [(0, 1, 2), (3, 4, 5), (1, 5, 9, 13), (14, 15)]
        proofs = [
            proof_for(public_key, signatures, indices) for indices in groups
        ]
        message_groups = [group_for(messages, g) for g in groups]
        context_groups = [group_for(contexts, g) for g in groups]
        first = multiproof_merge(
            tuple(message_groups),
            tuple(proofs),
            public_key=public_key,
            context_groups=tuple(context_groups),
        )
        order = (3, 1, 0, 2)
        reordered = multiproof_merge(
            tuple(message_groups[i] for i in order),
            tuple(proofs[i] for i in order),
            public_key=public_key,
            context_groups=tuple(context_groups[i] for i in order),
        )
        self.assertEqual(first, reordered)
        duplicated = multiproof_merge(
            tuple(message_groups[i] for i in (0, 0, 1, 2, 2, 3)),
            tuple(proofs[i] for i in (0, 0, 1, 2, 2, 3)),
            public_key=public_key,
            context_groups=tuple(context_groups[i] for i in (0, 0, 1, 2, 2, 3)),
        )
        self.assertEqual(first, duplicated)
        union_ab = tuple(sorted(set(groups[0]) | set(groups[1])))
        stage_one = multiproof_merge(
            (message_groups[0], message_groups[1]),
            (proofs[0], proofs[1]),
            public_key=public_key,
            context_groups=(context_groups[0], context_groups[1]),
        )
        union_cd = tuple(sorted(set(groups[2]) | set(groups[3])))
        stage_two = multiproof_merge(
            (message_groups[2], message_groups[3]),
            (proofs[2], proofs[3]),
            public_key=public_key,
            context_groups=(context_groups[2], context_groups[3]),
        )
        staged = multiproof_merge(
            (group_for(messages, union_ab), group_for(messages, union_cd)),
            (stage_one, stage_two),
            public_key=public_key,
            context_groups=(
                group_for(contexts, union_ab),
                group_for(contexts, union_cd),
            ),
        )
        self.assertEqual(first, staged)

    def test_merged_result_requires_matching_contexts(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(height=3)
        left = (1, 2)
        right = (6,)
        merged = multiproof_merge(
            (group_for(messages, left), group_for(messages, right)),
            (
                proof_for(public_key, signatures, left),
                proof_for(public_key, signatures, right),
            ),
            public_key=public_key,
            context_groups=(
                group_for(contexts, left),
                group_for(contexts, right),
            ),
        )
        union = (1, 2, 6)
        union_messages = group_for(messages, union)
        self.assertFalse(multiproof_verify(union_messages, merged))
        self.assertFalse(
            multiproof_verify(union_messages, merged, context="ctx-1")
        )
        self.assertFalse(
            multiproof_verify(
                union_messages,
                merged,
                contexts=("ctx-1", "ctx-2", "wrong"),
            )
        )
        self.assertTrue(
            multiproof_verify_bound(
                union_messages,
                merged,
                public_key=public_key,
                indices=union,
                contexts=group_for(contexts, union),
            )
        )

    def test_context_groups_public_key_mismatch_fails(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(height=2)
        other = make_signer(height=2, start=1000).public_key
        indices = (0, 1)
        with self.assertRaises(ValueError):
            multiproof_merge(
                (group_for(messages, indices),),
                (proof_for(public_key, signatures, indices),),
                public_key=other,
                context_groups=(group_for(contexts, indices),),
            )

    def test_context_groups_do_not_leak_into_proof_bytes(self):
        # The merged bytes depend only on the union's original signatures:
        # sources signed with per-leaf contexts and sources signed with the
        # shared context that matches leaf by leaf merge to the same bytes.
        signer = make_signer(height=3)
        messages = tuple(f"message-{i}" for i in range(8))
        contexts = tuple(f"ctx-{i}" for i in range(8))
        per_leaf = signer.sign_batch(messages, contexts=contexts)
        public_key = signer.public_key
        left = (0, 2, 3)
        right = (3, 5, 7)
        merged = multiproof_merge(
            (group_for(messages, left), group_for(messages, right)),
            (
                proof_for(public_key, per_leaf, left),
                proof_for(public_key, per_leaf, right),
            ),
            public_key=public_key,
            context_groups=(
                group_for(contexts, left),
                group_for(contexts, right),
            ),
        )
        union = (0, 2, 3, 5, 7)
        self.assertEqual(merged, proof_for(public_key, per_leaf, union))


class TestMultiproofMergeValidation(unittest.TestCase):
    def setUp(self):
        self.public_key, self.messages, self.signatures = make_full(height=2)
        self.indices = (0, 1)
        self.proof = proof_for(
            self.public_key, self.signatures, self.indices
        )
        self.group = group_for(self.messages, self.indices)

    def merge(self, *args, **kwargs):
        if not args:
            args = ((self.group,), (self.proof,))
        kwargs.setdefault("public_key", self.public_key)
        return multiproof_merge(*args, **kwargs)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            self.merge([self.group], (self.proof,))
        with self.assertRaises(TypeError):
            self.merge((self.group,), [self.proof])
        with self.assertRaises(TypeError):
            self.merge((list(self.group),), (self.proof,))
        with self.assertRaises(TypeError):
            self.merge((self.group[:1] + (1,),), (self.proof,))
        with self.assertRaises(TypeError):
            self.merge((self.group,), (None,))
        with self.assertRaises(TypeError):
            self.merge((self.group,), ("not-bytes",))
        with self.assertRaises(TypeError):
            self.merge(public_key="key")
        with self.assertRaises(TypeError):
            self.merge(context=1)
        with self.assertRaises(TypeError):
            self.merge(context=object())

    def test_type_checks_precede_content_checks(self):
        # Empty containers with bad types still report TypeError.
        with self.assertRaises(TypeError):
            multiproof_merge(
                [], [], public_key=self.public_key
            )
        with self.assertRaises(TypeError):
            multiproof_merge(
                (), (), public_key="not-a-key"
            )

    def test_empty_and_length_value_errors(self):
        with self.assertRaises(ValueError):
            multiproof_merge((), (), public_key=self.public_key)
        with self.assertRaises(ValueError):
            multiproof_merge(
                (self.group,), (), public_key=self.public_key
            )
        with self.assertRaises(ValueError):
            multiproof_merge(
                (), (self.proof,), public_key=self.public_key
            )
        other = proof_for(self.public_key, self.signatures, (2,))
        with self.assertRaises(ValueError):
            multiproof_merge(
                (self.group, self.messages[2:3], self.messages[3:4]),
                (self.proof, other),
                public_key=self.public_key,
            )

    def test_result_is_bytes(self):
        result = self.merge()
        self.assertIsInstance(result, bytes)


if __name__ == "__main__":
    unittest.main()

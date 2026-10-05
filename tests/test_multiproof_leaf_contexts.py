"""Per-leaf ``contexts`` support for ``multiproof_select``/``multiproof_expand``.

The explicit ``contexts`` tuple aligns with *every* leaf of the source
proof in its leaf order (not with the chosen subset), and the whole
source proof — dropped leaves included — is verified under those
contexts before anything is returned.
"""

import unittest

from pqattest import (
    MerkleSigner,
    merkle_verify,
    multiproof_encode,
    multiproof_expand,
    multiproof_merge,
    multiproof_select,
    multiproof_verify,
    multiproof_verify_bound,
)


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=3, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def make_full_per_leaf(height=3, w=4):
    signer = make_signer(height=height, w=w)
    count = 1 << height
    messages = tuple(f"message-{i}" for i in range(count))
    contexts = tuple(f"ctx-{i}" for i in range(count))
    signatures = signer.sign_batch(messages, contexts=contexts)
    return signer.public_key, messages, contexts, signatures


def proof_for(public_key, signatures, indices):
    return multiproof_encode(
        public_key, tuple(signatures[i] for i in indices)
    )


def group_for(values, indices):
    return tuple(values[i] for i in indices)


class TestSelectPerLeafContexts(unittest.TestCase):
    def test_select_all_returns_source_bytes(self):
        for w in (4, 8):
            for height in (1, 2, 3, 8):
                public_key, messages, contexts, signatures = make_full_per_leaf(
                    height=height, w=w
                )
                indices = tuple(range(1 << height))
                proof = proof_for(public_key, signatures, indices)
                selected = multiproof_select(
                    messages,
                    proof,
                    public_key=public_key,
                    indices=indices,
                    contexts=contexts,
                )
                self.assertIsInstance(selected, bytes)
                self.assertEqual(selected, proof)

    def test_subset_matches_encode_and_verifies(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                public_key, messages, contexts, signatures = make_full_per_leaf(
                    height=height, w=w
                )
                leaf_count = 1 << height
                subsets = [(0,), (leaf_count - 1,)]
                if leaf_count > 2:
                    subsets += [
                        (0, leaf_count - 1),
                        tuple(range(0, leaf_count, 2)),
                        tuple(range(1, leaf_count, 2)),
                    ]
                for subset in subsets:
                    with self.subTest(w=w, height=height, subset=subset):
                        proof = proof_for(
                            public_key, signatures, tuple(range(leaf_count))
                        )
                        selected = multiproof_select(
                            messages,
                            proof,
                            public_key=public_key,
                            indices=subset,
                            contexts=contexts,
                        )
                        self.assertEqual(
                            selected,
                            proof_for(public_key, signatures, subset),
                        )
                        self.assertTrue(
                            multiproof_verify(
                                group_for(messages, subset),
                                selected,
                                contexts=group_for(contexts, subset),
                            )
                        )
                        self.assertTrue(
                            multiproof_verify_bound(
                                group_for(messages, subset),
                                selected,
                                public_key=public_key,
                                indices=subset,
                                contexts=group_for(contexts, subset),
                            )
                        )

    def test_contexts_align_with_source_leaves_not_selection(self):
        # A sparse source proof: the contexts tuple follows the source
        # proof's three leaves, and ``indices`` still names tree indices.
        public_key, messages, contexts, signatures = make_full_per_leaf(
            height=4
        )
        keep = (0, 3, 7)
        proof = proof_for(public_key, signatures, keep)
        selected = multiproof_select(
            group_for(messages, keep),
            proof,
            public_key=public_key,
            indices=(3,),
            contexts=group_for(contexts, keep),
        )
        self.assertEqual(
            selected, multiproof_encode(public_key, (signatures[3],))
        )
        self.assertTrue(
            multiproof_verify(
                (messages[3],), selected, contexts=(contexts[3],)
            )
        )

    def test_single_leaf_source(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(
            height=3
        )
        proof = proof_for(public_key, signatures, (5,))
        selected = multiproof_select(
            (messages[5],),
            proof,
            public_key=public_key,
            indices=(5,),
            contexts=(contexts[5],),
        )
        self.assertEqual(selected, proof)

    def test_sparse_height_eight(self):
        for w in (4, 8):
            public_key, messages, contexts, signatures = make_full_per_leaf(
                height=8, w=w
            )
            keep = (0, 100, 101, 200, 255)
            proof = proof_for(public_key, signatures, keep)
            subset = (100, 255)
            selected = multiproof_select(
                group_for(messages, keep),
                proof,
                public_key=public_key,
                indices=subset,
                contexts=group_for(contexts, keep),
            )
            self.assertEqual(
                selected, proof_for(public_key, signatures, subset)
            )

    def test_chained_selection_matches_direct(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(
            height=4
        )
        proof = proof_for(public_key, signatures, tuple(range(16)))
        first_keep = (1, 5, 9, 13)
        first = multiproof_select(
            messages,
            proof,
            public_key=public_key,
            indices=first_keep,
            contexts=contexts,
        )
        second = multiproof_select(
            group_for(messages, first_keep),
            first,
            public_key=public_key,
            indices=(5, 13),
            contexts=group_for(contexts, first_keep),
        )
        direct = multiproof_select(
            messages,
            proof,
            public_key=public_key,
            indices=(5, 13),
            contexts=contexts,
        )
        self.assertEqual(second, direct)
        self.assertEqual(
            second,
            multiproof_encode(public_key, (signatures[5], signatures[13])),
        )

    def test_source_from_merge(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(
            height=3
        )
        left = tuple(range(0, 8, 2))
        right = tuple(range(1, 8, 2))
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
        subset = (1, 4, 7)
        selected = multiproof_select(
            messages,
            merged,
            public_key=public_key,
            indices=subset,
            contexts=contexts,
        )
        self.assertEqual(
            selected, proof_for(public_key, signatures, subset)
        )

    def test_same_message_different_contexts_distinct_leaves(self):
        signer = make_signer(height=2)
        messages = ("same", "same", "other", "same")
        contexts = ("ctx-0", "ctx-1", None, "ctx-3")
        signatures = signer.sign_batch(messages, contexts=contexts)
        proof = multiproof_encode(signer.public_key, signatures)
        selected = multiproof_select(
            messages,
            proof,
            public_key=signer.public_key,
            indices=(0, 1, 3),
            contexts=contexts,
        )
        self.assertEqual(
            selected,
            multiproof_encode(
                signer.public_key,
                (signatures[0], signatures[1], signatures[3]),
            ),
        )
        self.assertTrue(
            multiproof_verify(
                ("same", "same", "same"),
                selected,
                contexts=("ctx-0", "ctx-1", "ctx-3"),
            )
        )
        # Swapping the per-leaf contexts between equal messages fails.
        self.assertFalse(
            multiproof_verify(
                ("same", "same", "same"),
                selected,
                contexts=("ctx-1", "ctx-0", "ctx-3"),
            )
        )

    def test_member_form_variants_normalise(self):
        signer = make_signer(height=2)
        messages = ("a", "b", "c", "d")
        contexts = (None, "ctx", b"", "other")
        signatures = signer.sign_batch(messages, contexts=contexts)
        public_key = signer.public_key
        proof = multiproof_encode(public_key, signatures)
        passed = (bytearray(), bytearray(b"ctx"), "", bytearray(b"other"))
        selected = multiproof_select(
            messages,
            bytearray(proof),
            public_key=public_key,
            indices=(1, 2, 3),
            contexts=passed,
        )
        self.assertEqual(
            selected,
            multiproof_encode(
                public_key, (signatures[1], signatures[2], signatures[3])
            ),
        )
        self.assertTrue(
            multiproof_verify(
                ("b", "c", "d"),
                selected,
                contexts=("ctx", None, "other"),
            )
        )

    def test_none_explicit_matches_shared_context(self):
        signer = make_signer(height=3)
        messages = tuple(f"message-{i}" for i in range(8))
        signatures = signer.sign_batch(messages, context="ctx")
        proof = multiproof_encode(signer.public_key, signatures)
        baseline = multiproof_select(
            messages,
            proof,
            public_key=signer.public_key,
            indices=(1, 6),
            context="ctx",
        )
        explicit_none = multiproof_select(
            messages,
            proof,
            public_key=signer.public_key,
            indices=(1, 6),
            context="ctx",
            contexts=None,
        )
        self.assertEqual(baseline, explicit_none)

    def test_empty_shared_context_combines_with_contexts(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(
            height=2
        )
        proof = proof_for(public_key, signatures, (0, 3))
        kwargs = dict(
            public_key=public_key,
            indices=(0, 3),
            contexts=(contexts[0], contexts[3]),
        )
        expected = multiproof_select(
            (messages[0], messages[3]), proof, **kwargs
        )
        for empty in (None, b"", bytearray(), ""):
            with self.subTest(context=empty):
                self.assertEqual(
                    multiproof_select(
                        (messages[0], messages[3]),
                        proof,
                        context=empty,
                        **kwargs,
                    ),
                    expected,
                )

    def test_wrong_context_on_selected_or_dropped_leaf_fails(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(
            height=2
        )
        proof = proof_for(public_key, signatures, tuple(range(4)))
        # Wrong context on a selected leaf.
        bad_selected = ("wrong", contexts[1], contexts[2], contexts[3])
        with self.assertRaises(ValueError):
            multiproof_select(
                messages,
                proof,
                public_key=public_key,
                indices=(0,),
                contexts=bad_selected,
            )
        # Wrong context on a dropped leaf must not pass either.
        bad_dropped = (contexts[0], "wrong", contexts[2], contexts[3])
        with self.assertRaises(ValueError):
            multiproof_select(
                messages,
                proof,
                public_key=public_key,
                indices=(0,),
                contexts=bad_dropped,
            )
        # A context-less source proof must not accept per-leaf contexts.
        plain_signer = make_signer(height=2)
        plain_messages = tuple(f"m-{i}" for i in range(4))
        plain_signatures = plain_signer.sign_batch(plain_messages)
        plain_proof = multiproof_encode(
            plain_signer.public_key, plain_signatures
        )
        with self.assertRaises(ValueError):
            multiproof_select(
                plain_messages,
                plain_proof,
                public_key=plain_signer.public_key,
                indices=(0,),
                contexts=("ctx", None, None, None),
            )

    def test_context_does_not_leak_into_proof_bytes(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(
            height=2
        )
        proof = proof_for(public_key, signatures, tuple(range(4)))
        selected = multiproof_select(
            messages,
            proof,
            public_key=public_key,
            indices=(0, 2),
            contexts=contexts,
        )
        # The bytes are exactly what context-free multiproof_encode produces
        # from the same signatures — no context field is carried.
        self.assertEqual(
            selected,
            multiproof_encode(public_key, (signatures[0], signatures[2])),
        )

    def test_non_empty_shared_context_conflicts(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(
            height=2
        )
        proof = proof_for(public_key, signatures, tuple(range(4)))
        for bad_context in ("ctx", b"ctx", bytearray(b"x")):
            with self.subTest(context=bad_context):
                with self.assertRaises(ValueError):
                    multiproof_select(
                        messages,
                        proof,
                        public_key=public_key,
                        indices=(0,),
                        context=bad_context,
                        contexts=contexts,
                    )


class TestSelectPerLeafContextsValidation(unittest.TestCase):
    def setUp(self):
        (
            self.public_key,
            self.messages,
            self.contexts,
            signatures,
        ) = make_full_per_leaf(height=2)
        self.signatures = signatures
        self.proof = proof_for(
            self.public_key, signatures, tuple(range(4))
        )

    def select(self, messages=None, contexts=Ellipsis, **kwargs):
        if messages is None:
            messages = self.messages
        kwargs.setdefault("public_key", self.public_key)
        kwargs.setdefault("indices", (0,))
        if contexts is not Ellipsis:
            kwargs["contexts"] = contexts
        return multiproof_select(messages, self.proof, **kwargs)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            self.select(contexts=list(self.contexts))
        with self.assertRaises(TypeError):
            self.select(contexts="ctx")
        with self.assertRaises(TypeError):
            self.select(contexts=b"ctx")
        with self.assertRaises(TypeError):
            self.select(contexts=("ctx", 1))
        with self.assertRaises(TypeError):
            self.select(contexts=(None, object()))
        with self.assertRaises(TypeError):
            self.select(contexts=(True, None, None, None))
        with self.assertRaises(TypeError):
            self.select(contexts=(None, 1.5, None, None))

    def test_type_checks_precede_content_checks(self):
        # Bad contexts member type with an empty selection: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_select(
                self.messages,
                self.proof,
                public_key=self.public_key,
                indices=(),
                contexts=("ctx", 1, None, None),
            )
        # Non-tuple contexts with malformed data: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_select(
                self.messages,
                b"garbage",
                public_key=self.public_key,
                indices=(0,),
                contexts=["ctx"] * 4,
            )
        # Bad contexts member with a count mismatch: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_select(
                self.messages[:2],
                self.proof,
                public_key=self.public_key,
                indices=(0,),
                contexts=(1, 2),
            )
        # Non-empty shared context with a bad contexts member: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_select(
                self.messages,
                self.proof,
                public_key=self.public_key,
                indices=(0,),
                context="ctx",
                contexts=(None, 1, None, None),
            )

    def test_value_errors(self):
        with self.assertRaises(ValueError):
            self.select(contexts=())
        with self.assertRaises(ValueError):
            self.select(contexts=self.contexts[:3])
        with self.assertRaises(ValueError):
            self.select(contexts=self.contexts + ("extra",))
        with self.assertRaises(ValueError):
            self.select(
                context="ctx", contexts=tuple(b"" for _ in self.contexts)
            )

    def test_selection_errors_persist_with_contexts(self):
        for indices in (
            (),
            (True,),
            (0, False),
            (1, 1),
            (2, 1),
            (-1,),
        ):
            with self.subTest(indices=indices):
                with self.assertRaises(ValueError):
                    multiproof_select(
                        self.messages,
                        self.proof,
                        public_key=self.public_key,
                        indices=indices,
                        contexts=self.contexts,
                    )
        # Index absent from a sparse source proof.
        keep = (1, 2)
        sparse = proof_for(self.public_key, self.signatures, keep)
        with self.assertRaises(ValueError):
            multiproof_select(
                group_for(self.messages, keep),
                sparse,
                public_key=self.public_key,
                indices=(0,),
                contexts=group_for(self.contexts, keep),
            )

    def test_malformed_source_and_count_mismatch(self):
        for bad in (self.proof[:-1], self.proof + b"\x00", b""):
            with self.assertRaises(ValueError):
                multiproof_select(
                    self.messages,
                    bad,
                    public_key=self.public_key,
                    indices=(0,),
                    contexts=self.contexts,
                )
        for bad_messages in (self.messages[:3], self.messages + ("x",)):
            with self.assertRaises(ValueError):
                multiproof_select(
                    bad_messages,
                    self.proof,
                    public_key=self.public_key,
                    indices=(0,),
                    contexts=self.contexts,
                )

    def test_inputs_not_modified_and_no_quota_consumed(self):
        signer = make_signer(height=2)
        messages = tuple(f"message-{i}" for i in range(4))
        contexts = tuple(f"ctx-{i}" for i in range(4))
        signatures = signer.sign_batch(messages, contexts=contexts)
        proof = bytearray(multiproof_encode(signer.public_key, signatures))
        proof_snapshot = bytes(proof)
        message_buffers = tuple(
            bytearray(m.encode()) for m in messages
        )
        context_buffers = tuple(bytearray(c.encode()) for c in contexts)
        message_snapshots = tuple(bytes(b) for b in message_buffers)
        context_snapshots = tuple(bytes(b) for b in context_buffers)
        multiproof_select(
            message_buffers,
            proof,
            public_key=signer.public_key,
            indices=(0, 3),
            contexts=context_buffers,
        )
        self.assertEqual(bytes(proof), proof_snapshot)
        for buf, snapshot in zip(message_buffers, message_snapshots):
            self.assertEqual(bytes(buf), snapshot)
        for buf, snapshot in zip(context_buffers, context_snapshots):
            self.assertEqual(bytes(buf), snapshot)
        self.assertEqual(signer.next_index, 4)
        self.assertEqual(signer.remaining, 0)


class TestExpandPerLeafContexts(unittest.TestCase):
    def test_restored_signatures_equal_originals(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5, 8):
                public_key, messages, contexts, signatures = (
                    make_full_per_leaf(height=height, w=w)
                )
                leaf_count = 1 << height
                if height == 8:
                    selections = [(0,), (255,), (0, 100, 101, 200, 255)]
                else:
                    selections = [
                        (0,),
                        (leaf_count - 1,),
                        tuple(range(leaf_count)),
                    ]
                    if leaf_count > 2:
                        selections += [
                            (0, leaf_count - 1),
                            tuple(range(0, leaf_count, 2)),
                        ]
                for indices in selections:
                    with self.subTest(w=w, height=height, indices=indices):
                        proof = proof_for(public_key, signatures, indices)
                        batch = multiproof_expand(
                            group_for(messages, indices),
                            proof,
                            public_key=public_key,
                            contexts=group_for(contexts, indices),
                        )
                        expected = tuple(signatures[i] for i in indices)
                        self.assertEqual(batch.signatures, expected)
                        for position, index in enumerate(indices):
                            self.assertTrue(
                                merkle_verify(
                                    messages[index],
                                    batch.signatures[position],
                                    public_key,
                                    context=contexts[index],
                                )
                            )

    def test_recompression_is_byte_identical(self):
        for w in (4, 8):
            for height in (1, 2, 3, 8):
                public_key, messages, contexts, signatures = (
                    make_full_per_leaf(height=height, w=w)
                )
                leaf_count = 1 << height
                if height == 8:
                    index_sets = [
                        (0,),
                        (255,),
                        (0, 100, 101, 200, 255),
                    ]
                else:
                    index_sets = [
                        (0,),
                        (leaf_count - 1,),
                        tuple(range(0, leaf_count, 3)),
                        tuple(range(leaf_count)),
                    ]
                for indices in index_sets:
                    proof = proof_for(public_key, signatures, indices)
                    with self.subTest(w=w, height=height, indices=len(indices)):
                        batch = multiproof_expand(
                            group_for(messages, indices),
                            proof,
                            public_key=public_key,
                            contexts=group_for(contexts, indices),
                        )
                        self.assertEqual(
                            multiproof_encode(
                                batch.public_key, batch.signatures
                            ),
                            proof,
                        )

    def test_batch_verifies_with_per_leaf_contexts(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(
            height=3
        )
        indices = (1, 4, 6)
        proof = proof_for(public_key, signatures, indices)
        proof_messages = group_for(messages, indices)
        proof_contexts = group_for(contexts, indices)
        batch = multiproof_expand(
            proof_messages,
            proof,
            public_key=public_key,
            contexts=proof_contexts,
        )
        self.assertTrue(
            batch.verify(proof_messages, contexts=proof_contexts)
        )
        self.assertTrue(
            batch.verify_bound(
                proof_messages,
                public_key=public_key,
                indices=indices,
                contexts=proof_contexts,
            )
        )
        # Shared-context and per-leaf-less verification must fail.
        self.assertFalse(batch.verify(proof_messages))
        self.assertFalse(
            batch.verify(proof_messages, contexts=tuple(reversed(proof_contexts)))
        )

    def test_member_form_variants_normalise(self):
        signer = make_signer(height=2)
        messages = ("a", "b", "c", "d")
        contexts = (None, "ctx", b"", "other")
        signatures = signer.sign_batch(messages, contexts=contexts)
        public_key = signer.public_key
        proof = multiproof_encode(public_key, signatures)
        passed = (bytearray(), bytearray(b"ctx"), "", bytearray(b"other"))
        batch = multiproof_expand(
            messages,
            bytearray(proof),
            public_key=public_key,
            contexts=passed,
        )
        self.assertEqual(batch.signatures, signatures)

    def test_source_from_merge(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(
            height=3
        )
        groups = [(0, 2, 4), (1, 3, 5, 7)]
        merged = multiproof_merge(
            tuple(group_for(messages, g) for g in groups),
            tuple(proof_for(public_key, signatures, g) for g in groups),
            public_key=public_key,
            context_groups=tuple(
                group_for(contexts, g) for g in groups
            ),
        )
        union = tuple(sorted(set().union(*groups)))
        batch = multiproof_expand(
            group_for(messages, union),
            merged,
            public_key=public_key,
            contexts=group_for(contexts, union),
        )
        self.assertEqual(
            batch.signatures, tuple(signatures[i] for i in union)
        )
        self.assertEqual(
            multiproof_encode(public_key, batch.signatures), merged
        )

    def test_same_message_different_contexts_preserved(self):
        signer = make_signer(height=2)
        messages = ("same", "same", "other", "same")
        contexts = ("ctx-0", "ctx-1", None, "ctx-3")
        signatures = signer.sign_batch(messages, contexts=contexts)
        proof = multiproof_encode(signer.public_key, signatures)
        batch = multiproof_expand(
            messages,
            proof,
            public_key=signer.public_key,
            contexts=contexts,
        )
        self.assertEqual(batch.signatures, signatures)
        self.assertTrue(batch.verify(messages, contexts=contexts))
        for position, context in enumerate(contexts):
            self.assertTrue(
                merkle_verify(
                    messages[position],
                    batch.signatures[position],
                    signer.public_key,
                    context=context,
                )
            )

    def test_wrong_context_on_any_leaf_fails(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(
            height=2
        )
        proof = proof_for(public_key, signatures, tuple(range(4)))
        for position in range(4):
            bad = list(contexts)
            bad[position] = "wrong"
            with self.subTest(position=position):
                with self.assertRaises(ValueError):
                    multiproof_expand(
                        messages,
                        proof,
                        public_key=public_key,
                        contexts=tuple(bad),
                    )

    def test_none_and_empty_shared_context_equivalence(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(
            height=2
        )
        proof = proof_for(public_key, signatures, (0, 2))
        kwargs = dict(
            public_key=public_key, contexts=(contexts[0], contexts[2])
        )
        expected = multiproof_expand(
            (messages[0], messages[2]), proof, **kwargs
        )
        for empty in (None, b"", bytearray(), ""):
            with self.subTest(context=empty):
                batch = multiproof_expand(
                    (messages[0], messages[2]),
                    proof,
                    context=empty,
                    **kwargs,
                )
                self.assertEqual(batch.signatures, expected.signatures)

    def test_non_empty_shared_context_conflicts(self):
        public_key, messages, contexts, signatures = make_full_per_leaf(
            height=2
        )
        proof = proof_for(public_key, signatures, tuple(range(4)))
        for bad_context in ("ctx", b"ctx", bytearray(b"x")):
            with self.subTest(context=bad_context):
                with self.assertRaises(ValueError):
                    multiproof_expand(
                        messages,
                        proof,
                        public_key=public_key,
                        context=bad_context,
                        contexts=contexts,
                    )


class TestExpandPerLeafContextsValidation(unittest.TestCase):
    def setUp(self):
        (
            self.public_key,
            self.messages,
            self.contexts,
            signatures,
        ) = make_full_per_leaf(height=2)
        self.signatures = signatures
        self.proof = proof_for(self.public_key, signatures, tuple(range(4)))

    def expand(self, messages=Ellipsis, contexts=Ellipsis, **kwargs):
        if messages is Ellipsis:
            messages = self.messages
        kwargs.setdefault("public_key", self.public_key)
        if contexts is not Ellipsis:
            kwargs["contexts"] = contexts
        return multiproof_expand(messages, self.proof, **kwargs)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            self.expand(contexts=list(self.contexts))
        with self.assertRaises(TypeError):
            self.expand(contexts="ctx")
        with self.assertRaises(TypeError):
            self.expand(contexts=b"ctx")
        with self.assertRaises(TypeError):
            self.expand(contexts=("ctx", 1, None, None))
        with self.assertRaises(TypeError):
            self.expand(contexts=(None, object(), None, None))
        with self.assertRaises(TypeError):
            self.expand(contexts=(True, None, None, None))

    def test_type_checks_precede_content_checks(self):
        # Bad contexts member with empty messages: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_expand(
                (),
                self.proof,
                public_key=self.public_key,
                contexts=(1,),
            )
        # Non-tuple contexts with malformed data: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_expand(
                self.messages,
                b"garbage",
                public_key=self.public_key,
                contexts=["ctx"] * 4,
            )
        # Bad member with a count mismatch: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_expand(
                self.messages[:2],
                self.proof,
                public_key=self.public_key,
                contexts=(1, 2),
            )
        # Bad contexts type with a bad public key: either TypeError
        # (both are type violations); assert TypeError deterministically.
        with self.assertRaises(TypeError):
            multiproof_expand(
                self.messages,
                self.proof,
                public_key="key",
                contexts=["ctx"] * 4,
            )

    def test_value_errors(self):
        with self.assertRaises(ValueError):
            self.expand(messages=(), contexts=())
        with self.assertRaises(ValueError):
            self.expand(contexts=())
        with self.assertRaises(ValueError):
            self.expand(contexts=self.contexts[:3])
        with self.assertRaises(ValueError):
            self.expand(contexts=self.contexts + ("extra",))
        with self.assertRaises(ValueError):
            self.expand(
                context="ctx", contexts=tuple(b"" for _ in self.contexts)
            )

    def test_malformed_source_and_mismatch(self):
        for bad in (self.proof[:-1], self.proof + b"\x00", b""):
            with self.assertRaises(ValueError):
                multiproof_expand(
                    self.messages,
                    bad,
                    public_key=self.public_key,
                    contexts=self.contexts,
                )
        for bad_messages in (self.messages[:3], self.messages + ("x",)):
            with self.assertRaises(ValueError):
                multiproof_expand(
                    bad_messages,
                    self.proof,
                    public_key=self.public_key,
                    contexts=self.contexts,
                )
        other = make_signer(height=2, start=1000).public_key
        with self.assertRaises(ValueError):
            multiproof_expand(
                self.messages,
                self.proof,
                public_key=other,
                contexts=self.contexts,
            )

    def test_result_does_not_alias_input_buffers(self):
        signer = make_signer(height=2)
        messages = tuple(f"message-{i}" for i in range(4))
        contexts = tuple(f"ctx-{i}" for i in range(4))
        signatures = signer.sign_batch(messages, contexts=contexts)
        proof = bytearray(multiproof_encode(signer.public_key, signatures))
        batch = multiproof_expand(
            tuple(bytearray(m.encode()) for m in messages),
            bytes(proof),
            public_key=signer.public_key,
            contexts=tuple(bytearray(c.encode()) for c in contexts),
        )
        proof[0] ^= 0xFF
        reencoded = multiproof_encode(batch.public_key, batch.signatures)
        proof[0] ^= 0xFF
        self.assertEqual(reencoded, bytes(proof))
        for signature in batch.signatures:
            for element in signature.wots_signature:
                self.assertIsInstance(element, bytes)
            for node in signature.auth_path:
                self.assertIsInstance(node, bytes)

    def test_no_signing_quota_consumed(self):
        signer = make_signer(height=2)
        messages = tuple(f"message-{i}" for i in range(4))
        contexts = tuple(f"ctx-{i}" for i in range(4))
        signatures = signer.sign_batch(messages, contexts=contexts)
        self.assertEqual(signer.next_index, 4)
        proof = multiproof_encode(signer.public_key, signatures)
        before = signer.checkpoint()
        multiproof_expand(
            messages,
            proof,
            public_key=signer.public_key,
            contexts=contexts,
        )
        self.assertEqual(signer.next_index, 4)
        self.assertEqual(signer.remaining, 0)
        self.assertEqual(signer.checkpoint(), before)


class TestAllHeightsAndWeights(unittest.TestCase):
    """Every tree height, both w values, single/sparse/full/merged proofs."""

    def sweep_cases(self, height):
        full = tuple(range(1 << height))
        if height == 1:
            return [((0,), (0,)), ((1,), (1,)), (full, full)]
        sparse = (0, (1 << height) - 1)
        mid = 1 << (height - 1)
        return [
            ((0,), (0,)),
            (((1 << height) - 1,), ((1 << height) - 1,)),
            (sparse, sparse),
            (full, (0, mid, (1 << height) - 1)),
        ]

    def test_select_and_expand_full_tree(self):
        for w in (4, 8):
            for height in range(1, 9):
                public_key, messages, contexts, signatures = (
                    make_full_per_leaf(height=height, w=w)
                )
                full = tuple(range(1 << height))
                full_proof = proof_for(public_key, signatures, full)
                for keep, subset in self.sweep_cases(height):
                    with self.subTest(
                        w=w, height=height, keep=keep, subset=subset
                    ):
                        source = proof_for(public_key, signatures, keep)
                        selected = multiproof_select(
                            group_for(messages, keep),
                            source,
                            public_key=public_key,
                            indices=subset,
                            contexts=group_for(contexts, keep),
                        )
                        self.assertEqual(
                            selected,
                            proof_for(public_key, signatures, subset),
                        )
                        self.assertTrue(
                            multiproof_verify_bound(
                                group_for(messages, subset),
                                selected,
                                public_key=public_key,
                                indices=subset,
                                contexts=group_for(contexts, subset),
                            )
                        )
                        # The same per-leaf contexts against the full-tree
                        # source must give byte-identical extraction.
                        if keep != full:
                            from_full = multiproof_select(
                                messages,
                                full_proof,
                                public_key=public_key,
                                indices=subset,
                                contexts=contexts,
                            )
                            self.assertEqual(from_full, selected)
                        batch = multiproof_expand(
                            group_for(messages, subset),
                            selected,
                            public_key=public_key,
                            contexts=group_for(contexts, subset),
                        )
                        self.assertEqual(
                            batch.signatures,
                            tuple(signatures[i] for i in subset),
                        )
                        self.assertTrue(
                            batch.verify_bound(
                                group_for(messages, subset),
                                public_key=public_key,
                                indices=subset,
                                contexts=group_for(contexts, subset),
                            )
                        )
                        self.assertEqual(
                            multiproof_encode(public_key, batch.signatures),
                            selected,
                        )

    def test_select_and_expand_merged_source(self):
        for w in (4, 8):
            for height in range(1, 6):
                public_key, messages, contexts, signatures = (
                    make_full_per_leaf(height=height, w=w)
                )
                leaf_count = 1 << height
                left = tuple(range(0, leaf_count, 2))
                right = tuple(range(1, leaf_count, 2))
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
                with self.subTest(w=w, height=height):
                    batch = multiproof_expand(
                        messages,
                        merged,
                        public_key=public_key,
                        contexts=contexts,
                    )
                    self.assertEqual(
                        multiproof_encode(public_key, batch.signatures),
                        merged,
                    )
                    selected = multiproof_select(
                        messages,
                        merged,
                        public_key=public_key,
                        indices=(0, leaf_count - 1),
                        contexts=contexts,
                    )
                    self.assertEqual(
                        selected,
                        proof_for(
                            public_key, signatures, (0, leaf_count - 1)
                        ),
                    )


if __name__ == "__main__":
    unittest.main()

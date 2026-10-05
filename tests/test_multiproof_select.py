import unittest

from pqattest import (
    MerkleSigner,
    multiproof_encode,
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


class TestMultiproofSelectEquivalence(unittest.TestCase):
    def test_select_all_returns_source_bytes(self):
        for w in (4, 8):
            for height in (1, 2, 3, 8):
                public_key, messages, _, proof = make_proof(w=w, height=height)
                selected = multiproof_select(
                    messages,
                    proof,
                    public_key=public_key,
                    indices=tuple(range(1 << height)),
                )
                self.assertIsInstance(selected, bytes)
                self.assertEqual(selected, proof)

    def test_matches_multiproof_encode_of_selected_signatures(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                public_key, messages, signatures, proof = make_proof(
                    w=w, height=height
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
                        selected = multiproof_select(
                            messages, proof, public_key=public_key, indices=subset
                        )
                        expected = multiproof_encode(
                            public_key, tuple(signatures[i] for i in subset)
                        )
                        self.assertEqual(selected, expected)

    def test_select_from_sparse_source_proof(self):
        public_key, messages, signatures, _ = make_proof(height=4)
        keep = (0, 3, 7, 11, 15)
        sparse = multiproof_encode(public_key, tuple(signatures[i] for i in keep))
        sparse_messages = tuple(messages[i] for i in keep)
        for subset in [(0,), (15,), (3, 7, 11), keep]:
            with self.subTest(subset=subset):
                selected = multiproof_select(
                    sparse_messages, sparse, public_key=public_key, indices=subset
                )
                expected = multiproof_encode(
                    public_key, tuple(signatures[i] for i in subset)
                )
                self.assertEqual(selected, expected)

    def test_repeated_selection_matches_direct_selection(self):
        public_key, messages, signatures, proof = make_proof(height=4)
        first = multiproof_select(
            messages, proof, public_key=public_key, indices=(1, 5, 9, 13)
        )
        first_messages = tuple(messages[i] for i in (1, 5, 9, 13))
        second = multiproof_select(
            first_messages, first, public_key=public_key, indices=(5, 13)
        )
        direct = multiproof_select(
            messages, proof, public_key=public_key, indices=(5, 13)
        )
        self.assertEqual(second, direct)
        self.assertEqual(
            second, multiproof_encode(public_key, (signatures[5], signatures[13]))
        )

    def test_selected_proof_verifies_bound(self):
        public_key, messages, _, proof = make_proof(height=3)
        subset = (2, 5)
        selected = multiproof_select(
            messages, proof, public_key=public_key, indices=subset
        )
        selected_messages = tuple(messages[i] for i in subset)
        self.assertTrue(multiproof_verify(selected_messages, selected))
        self.assertTrue(
            multiproof_verify_bound(
                selected_messages,
                selected,
                public_key=public_key,
                indices=subset,
            )
        )

    def test_duplicate_messages_are_not_merged(self):
        signer = make_signer(height=2)
        messages = ("same", "same", "other", "same")
        signatures = signer.sign_batch(messages)
        proof = multiproof_encode(signer.public_key, signatures)
        selected = multiproof_select(
            messages, proof, public_key=signer.public_key, indices=(0, 1, 3)
        )
        self.assertEqual(
            selected,
            multiproof_encode(
                signer.public_key, (signatures[0], signatures[1], signatures[3])
            ),
        )
        self.assertTrue(multiproof_verify(("same", "same", "same"), selected))

    def test_context_binding(self):
        public_key, messages, signatures, proof = make_proof(height=3, context="ctx")
        selected = multiproof_select(
            messages, proof, public_key=public_key, indices=(1, 6), context="ctx"
        )
        self.assertEqual(
            selected, multiproof_encode(public_key, (signatures[1], signatures[6]))
        )
        self.assertTrue(
            multiproof_verify(
                (messages[1], messages[6]), selected, context="ctx"
            )
        )

    def test_context_mismatch_raises_value_error(self):
        public_key, messages, _, proof = make_proof(height=3, context="ctx")
        for bad_context in (None, b"", "other", b"ctx\x00"):
            with self.subTest(context=bad_context):
                with self.assertRaises(ValueError):
                    multiproof_select(
                        messages,
                        proof,
                        public_key=public_key,
                        indices=(1,),
                        context=bad_context,
                    )

    def test_message_member_forms_and_bytearray_data(self):
        public_key, messages, signatures, proof = make_proof(height=2)
        mixed = tuple(
            bytearray(m.encode()) if i % 2 else m for i, m in enumerate(messages)
        )
        selected = multiproof_select(
            mixed, bytearray(proof), public_key=public_key, indices=(1, 2)
        )
        self.assertEqual(
            selected, multiproof_encode(public_key, (signatures[1], signatures[2]))
        )

    def test_inputs_are_not_modified(self):
        public_key, messages, _, proof = make_proof(height=2)
        data = bytearray(proof)
        multiproof_select(messages, data, public_key=public_key, indices=(0,))
        self.assertEqual(bytes(data), proof)


class TestMultiproofSelectSourceAuthentication(unittest.TestCase):
    def test_corrupted_dropped_leaf_signature_fails(self):
        public_key, messages, _, proof = make_proof(height=2)
        # Flip one byte inside the first leaf's W-OTS elements; the
        # selection keeps only the later, untouched leaves.
        corrupted = bytearray(proof)
        corrupted[_MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES + 4] ^= 0xFF
        with self.assertRaises(ValueError):
            multiproof_select(
                messages, bytes(corrupted), public_key=public_key, indices=(2, 3)
            )

    def test_wrong_message_for_dropped_leaf_fails(self):
        public_key, messages, _, proof = make_proof(height=2)
        wrong = ("tampered",) + messages[1:]
        with self.assertRaises(ValueError):
            multiproof_select(
                wrong, proof, public_key=public_key, indices=(2, 3)
            )

    def test_malformed_source_proof_fails(self):
        public_key, messages, _, proof = make_proof(height=2)
        for bad in (proof[:-1], proof + b"\x00", b"", b"\x00" * 32):
            with self.subTest(bad=bad[:12]):
                with self.assertRaises(ValueError):
                    multiproof_select(
                        messages, bad, public_key=public_key, indices=(0,)
                    )
        corrupted = bytearray(proof)
        corrupted[8] = 2
        with self.assertRaises(ValueError):
            multiproof_select(
                messages, bytes(corrupted), public_key=public_key, indices=(0,)
            )

    def test_public_key_mismatch_fails(self):
        public_key, messages, _, proof = make_proof(height=2)
        other = make_signer(height=2, start=1000).public_key
        with self.assertRaises(ValueError):
            multiproof_select(
                messages, proof, public_key=other, indices=(0,)
            )
        same_root_other_w = type(public_key)(
            w=8, height=public_key.height, root=public_key.root
        )
        with self.assertRaises(ValueError):
            multiproof_select(
                messages, proof, public_key=same_root_other_w, indices=(0,)
            )

    def test_message_count_mismatch_fails(self):
        public_key, messages, _, proof = make_proof(height=2)
        for bad_messages in (messages[:3], messages + ("extra",), ()):
            with self.subTest(count=len(bad_messages)):
                with self.assertRaises(ValueError):
                    multiproof_select(
                        bad_messages, proof, public_key=public_key, indices=(0,)
                    )


class TestMultiproofSelectValidation(unittest.TestCase):
    def setUp(self):
        self.public_key, self.messages, _, self.proof = make_proof(height=2)

    def select(self, messages=None, data=None, **kwargs):
        if messages is None:
            messages = self.messages
        if data is None:
            data = self.proof
        kwargs.setdefault("public_key", self.public_key)
        return multiproof_select(messages, data, **kwargs)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            self.select(data="not-bytes")
        with self.assertRaises(TypeError):
            self.select(data=None)
        with self.assertRaises(TypeError):
            self.select(messages=list(self.messages), indices=(0,))
        with self.assertRaises(TypeError):
            self.select(messages=self.messages[:3] + (1,), indices=(0,))
        with self.assertRaises(TypeError):
            self.select(public_key="key", indices=(0,))
        with self.assertRaises(TypeError):
            self.select(indices=[0])
        with self.assertRaises(TypeError):
            self.select(indices=(0, "1"))
        with self.assertRaises(TypeError):
            self.select(indices=(0, None))
        with self.assertRaises(TypeError):
            self.select(indices=(0,), context=1)

    def test_selection_value_errors(self):
        with self.assertRaises(ValueError):
            self.select(indices=())
        with self.assertRaises(ValueError):
            self.select(indices=(True,))
        with self.assertRaises(ValueError):
            self.select(indices=(0, False))
        with self.assertRaises(ValueError):
            self.select(indices=(1, 1))
        with self.assertRaises(ValueError):
            self.select(indices=(2, 1))
        with self.assertRaises(ValueError):
            self.select(indices=(0, 4))
        with self.assertRaises(ValueError):
            self.select(indices=(-1,))

    def test_index_not_in_source_proof_fails(self):
        keep = (1, 2)
        signer = make_signer(height=2)
        signatures = signer.sign_batch(self.messages)
        sparse = multiproof_encode(
            signer.public_key, tuple(signatures[i] for i in keep)
        )
        sparse_messages = tuple(self.messages[i] for i in keep)
        with self.assertRaises(ValueError):
            multiproof_select(
                sparse_messages,
                sparse,
                public_key=signer.public_key,
                indices=(0,),
            )
        with self.assertRaises(ValueError):
            multiproof_select(
                sparse_messages,
                sparse,
                public_key=signer.public_key,
                indices=(1, 3),
            )


class TestMultiproofSelectPerLeafContexts(unittest.TestCase):
    def make_per_leaf(self, height=3, w=4):
        signer = make_signer(height=height, w=w)
        leaf_count = 1 << height
        messages = tuple(f"message-{i}" for i in range(leaf_count))
        contexts = tuple(f"ctx-{i}" for i in range(leaf_count))
        signatures = signer.sign_batch(messages, contexts=contexts)
        proof = multiproof_encode(signer.public_key, signatures)
        return signer.public_key, messages, contexts, signatures, proof

    def test_select_all_returns_source_bytes(self):
        for w in (4, 8):
            for height in (1, 2, 3, 8):
                public_key, messages, contexts, _, proof = self.make_per_leaf(
                    height=height, w=w
                )
                leaf_count = 1 << height
                selected = multiproof_select(
                    messages,
                    proof,
                    public_key=public_key,
                    indices=tuple(range(leaf_count)),
                    contexts=contexts,
                )
                self.assertEqual(selected, proof)

    def test_subset_matches_encode_and_verifies(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                public_key, messages, contexts, signatures, proof = (
                    self.make_per_leaf(height=height, w=w)
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
                        selected = multiproof_select(
                            messages,
                            proof,
                            public_key=public_key,
                            indices=subset,
                            contexts=contexts,
                        )
                        self.assertEqual(
                            selected,
                            multiproof_encode(
                                public_key,
                                tuple(signatures[i] for i in subset),
                            ),
                        )
                        selected_messages = tuple(messages[i] for i in subset)
                        selected_contexts = tuple(contexts[i] for i in subset)
                        self.assertTrue(
                            multiproof_verify(
                                selected_messages,
                                selected,
                                contexts=selected_contexts,
                            )
                        )
                        self.assertTrue(
                            multiproof_verify_bound(
                                selected_messages,
                                selected,
                                public_key=public_key,
                                indices=subset,
                                contexts=selected_contexts,
                            )
                        )
                        # Without the contexts the selected proof must not verify.
                        self.assertFalse(
                            multiproof_verify(selected_messages, selected)
                        )

    def test_contexts_align_with_source_leaves_on_sparse_proof(self):
        height = 4
        signer = make_signer(height=height)
        keep = (0, 3, 7, 11, 15)
        messages = tuple(f"message-{i}" for i in keep)
        contexts = tuple(f"ctx-{i}" for i in keep)
        signatures = signer.sign_selected(keep, messages, contexts=contexts)
        public_key = signer.public_key
        sparse = multiproof_encode(public_key, signatures)
        for subset in [(0,), (15,), (3, 11), keep]:
            with self.subTest(subset=subset):
                positions = tuple(keep.index(i) for i in subset)
                selected = multiproof_select(
                    messages,
                    sparse,
                    public_key=public_key,
                    indices=subset,
                    contexts=contexts,
                )
                self.assertEqual(
                    selected,
                    multiproof_encode(
                        public_key, tuple(signatures[p] for p in positions)
                    ),
                )
                self.assertTrue(
                    multiproof_verify(
                        tuple(messages[p] for p in positions),
                        selected,
                        contexts=tuple(contexts[p] for p in positions),
                    )
                )

    def test_dropped_leaf_wrong_context_fails(self):
        public_key, messages, contexts, _, proof = self.make_per_leaf(height=3)
        # Tamper with the context of a leaf the selection drops.
        for dropped in (0, 2, 7):
            kept = tuple(i for i in range(8) if i != dropped)
            bad_contexts = tuple(
                "other" if i == dropped else contexts[i] for i in range(8)
            )
            with self.subTest(dropped=dropped):
                with self.assertRaises(ValueError):
                    multiproof_select(
                        messages,
                        proof,
                        public_key=public_key,
                        indices=kept,
                        contexts=bad_contexts,
                    )

    def test_dropped_leaf_missing_context_fails(self):
        # A dropped leaf really signed under a context; supplying no
        # context for it must still fail the whole call.
        public_key, messages, contexts, _, proof = self.make_per_leaf(height=2)
        bad_contexts = (None, contexts[1], contexts[2], contexts[3])
        with self.assertRaises(ValueError):
            multiproof_select(
                messages,
                proof,
                public_key=public_key,
                indices=(1, 2, 3),
                contexts=bad_contexts,
            )

    def test_member_form_variants_normalise(self):
        signer = make_signer(height=2)
        messages = ("a", "b", "c", "d")
        contexts = (None, "ctx-1", b"", "ctx-3")
        signatures = signer.sign_batch(messages, contexts=contexts)
        public_key = signer.public_key
        proof = multiproof_encode(public_key, signatures)
        subset = (0, 2, 3)
        selected = multiproof_select(
            messages,
            proof,
            public_key=public_key,
            indices=subset,
            contexts=(None, bytearray(b"ctx-1"), bytearray(), b"ctx-3"),
        )
        self.assertEqual(
            selected,
            multiproof_encode(
                public_key, tuple(signatures[i] for i in subset)
            ),
        )
        self.assertTrue(
            multiproof_verify(
                tuple(messages[i] for i in subset),
                selected,
                contexts=(None, None, "ctx-3"),
            )
        )

    def test_same_message_with_different_contexts_at_different_leaves(self):
        signer = make_signer(height=2)
        messages = ("same", "same", "other", "same")
        contexts = ("one", "two", None, "four")
        signatures = signer.sign_batch(messages, contexts=contexts)
        public_key = signer.public_key
        proof = multiproof_encode(public_key, signatures)
        selected = multiproof_select(
            messages,
            proof,
            public_key=public_key,
            indices=(0, 1, 3),
            contexts=contexts,
        )
        self.assertEqual(
            selected,
            multiproof_encode(
                public_key, (signatures[0], signatures[1], signatures[3])
            ),
        )
        self.assertTrue(
            multiproof_verify(
                ("same", "same", "same"),
                selected,
                contexts=("one", "two", "four"),
            )
        )
        # Swapping the contexts between the equal-message leaves fails.
        self.assertFalse(
            multiproof_verify(
                ("same", "same", "same"),
                selected,
                contexts=("two", "one", "four"),
            )
        )

    def test_consecutive_selection_matches_direct_selection(self):
        public_key, messages, contexts, signatures, proof = (
            self.make_per_leaf(height=4)
        )
        first_subset = (1, 5, 9, 13)
        first = multiproof_select(
            messages,
            proof,
            public_key=public_key,
            indices=first_subset,
            contexts=contexts,
        )
        first_messages = tuple(messages[i] for i in first_subset)
        first_contexts = tuple(contexts[i] for i in first_subset)
        second = multiproof_select(
            first_messages,
            first,
            public_key=public_key,
            indices=(5, 13),
            contexts=first_contexts,
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

    def test_select_after_merge_with_per_leaf_contexts(self):
        from pqattest import multiproof_merge

        public_key, messages, contexts, signatures, _ = (
            self.make_per_leaf(height=4)
        )
        left = (0, 2, 5)
        right = (3, 5, 9, 14)

        def proof_for(indices):
            return multiproof_encode(
                public_key, tuple(signatures[i] for i in indices)
            )

        def group(values, indices):
            return tuple(values[i] for i in indices)

        merged = multiproof_merge(
            (group(messages, left), group(messages, right)),
            (proof_for(left), proof_for(right)),
            public_key=public_key,
            context_groups=(
                group(contexts, left),
                group(contexts, right),
            ),
        )
        union = tuple(sorted(set(left) | set(right)))
        subset = (0, 9, 14)
        selected = multiproof_select(
            group(messages, union),
            merged,
            public_key=public_key,
            indices=subset,
            contexts=group(contexts, union),
        )
        self.assertEqual(
            selected,
            multiproof_encode(
                public_key, tuple(signatures[i] for i in subset)
            ),
        )

    def test_empty_shared_context_combines_with_contexts(self):
        public_key, messages, contexts, _, proof = self.make_per_leaf(height=2)
        expected = multiproof_select(
            messages,
            proof,
            public_key=public_key,
            indices=(0, 3),
            contexts=contexts,
        )
        for empty in (None, b"", bytearray(), ""):
            with self.subTest(context=empty):
                selected = multiproof_select(
                    messages,
                    proof,
                    public_key=public_key,
                    indices=(0, 3),
                    context=empty,
                    contexts=contexts,
                )
                self.assertEqual(selected, expected)

    def test_type_errors(self):
        public_key, messages, contexts, _, proof = self.make_per_leaf(height=2)
        kwargs = dict(public_key=public_key, indices=(0,))

        def call(**extra):
            return multiproof_select(messages, proof, **kwargs, **extra)

        with self.assertRaises(TypeError):
            call(contexts=list(contexts))
        with self.assertRaises(TypeError):
            call(contexts=b"".join(c.encode() for c in contexts))
        with self.assertRaises(TypeError):
            call(contexts="ctx")
        with self.assertRaises(TypeError):
            call(contexts=(1,))
        with self.assertRaises(TypeError):
            call(contexts=(object(),))
        with self.assertRaises(TypeError):
            call(contexts=(contexts[0], None, 2, contexts[3]))

    def test_type_checks_precede_content_checks(self):
        public_key, messages, contexts, _, proof = self.make_per_leaf(height=2)
        # Bad contexts container with an empty selection: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_select(
                messages,
                proof,
                public_key=public_key,
                indices=(),
                contexts=[],
            )
        # Bad contexts member with malformed source data: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_select(
                messages,
                b"",
                public_key=public_key,
                indices=(0,),
                contexts=(1,) * len(messages),
            )
        # Bad contexts member with a conflicting non-empty context.
        with self.assertRaises(TypeError):
            multiproof_select(
                messages,
                proof,
                public_key=public_key,
                indices=(0,),
                context="ctx",
                contexts=(1,) * len(messages),
            )
        # Bad other-argument types still raise TypeError.
        with self.assertRaises(TypeError):
            multiproof_select(
                messages,
                123,
                public_key=public_key,
                indices=(0,),
                contexts=contexts,
            )

    def test_value_errors(self):
        public_key, messages, contexts, _, proof = self.make_per_leaf(height=2)
        kwargs = dict(public_key=public_key)

        def call(indices, **extra):
            return multiproof_select(
                messages, proof, indices=indices, **kwargs, **extra
            )

        # Explicit empty contexts tuple.
        with self.assertRaises(ValueError):
            call((0,), contexts=())
        # Wrong length: too short and too long.
        with self.assertRaises(ValueError):
            call((0,), contexts=contexts[:3])
        with self.assertRaises(ValueError):
            call((0,), contexts=contexts + ("extra",))
        # Combined with a non-empty shared context.
        with self.assertRaises(ValueError):
            call(
                (0,),
                context="ctx",
                contexts=tuple(b"" for _ in messages),
            )
        # Wrong context for a source leaf.
        with self.assertRaises(ValueError):
            call(
                (0,),
                contexts=("other",) + contexts[1:],
            )

    def test_inputs_are_not_modified(self):
        public_key, messages, _, _, proof = self.make_per_leaf(height=2)
        data = bytearray(proof)
        contexts = tuple(
            bytearray(f"ctx-{i}".encode()) for i in range(4)
        )
        snapshots = tuple(bytes(buf) for buf in contexts)
        multiproof_select(
            messages,
            data,
            public_key=public_key,
            indices=(0, 3),
            contexts=contexts,
        )
        self.assertEqual(bytes(data), proof)
        for buf, snapshot in zip(contexts, snapshots):
            self.assertEqual(bytes(buf), snapshot)


if __name__ == "__main__":
    unittest.main()

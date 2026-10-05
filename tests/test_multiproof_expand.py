import unittest

from pqattest import (
    MerkleBatchProof,
    MerkleProof,
    MerklePublicKey,
    MerkleSigner,
    merkle_verify,
    multiproof_encode,
    multiproof_expand,
    multiproof_merge,
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


def expand(public_key, messages, signatures, indices, context=None):
    proof = proof_for(public_key, signatures, indices)
    proof_messages = group_for(messages, indices)
    batch = multiproof_expand(
        proof_messages,
        proof,
        public_key=public_key,
        context=context,
    )
    return proof, batch


class TestMultiproofExpandEquivalence(unittest.TestCase):
    def test_restored_signatures_equal_originals(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5, 8):
                public_key, messages, signatures = make_full(w=w, height=height)
                leaf_count = 1 << height
                selections = [
                    (0,),
                    (leaf_count - 1,),
                    tuple(range(leaf_count)),
                ]
                if leaf_count > 2:
                    selections += [
                        (0, leaf_count - 1),
                        tuple(range(0, leaf_count, 2)),
                        tuple(range(1, leaf_count, 2)),
                    ]
                for indices in selections:
                    with self.subTest(w=w, height=height, indices=indices):
                        _, batch = expand(public_key, messages, signatures, indices)
                        restored = batch.signatures
                        expected = tuple(signatures[i] for i in indices)
                        self.assertEqual(len(restored), len(expected))
                        for got, want in zip(restored, expected):
                            self.assertEqual(got.index, want.index)
                            self.assertEqual(got.wots_signature, want.wots_signature)
                            self.assertEqual(got.auth_path, want.auth_path)
                            self.assertEqual(got, want)

    def test_batch_bytes_equal_direct_wrapping(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                public_key, messages, signatures = make_full(w=w, height=height)
                leaf_count = 1 << height
                for indices in (
                    (0,),
                    (leaf_count - 1,),
                    (0, leaf_count - 1),
                    tuple(range(leaf_count)),
                ):
                    with self.subTest(w=w, height=height, indices=indices):
                        _, batch = expand(public_key, messages, signatures, indices)
                        direct = MerkleBatchProof(
                            public_key=public_key,
                            signatures=tuple(signatures[i] for i in indices),
                        )
                        self.assertEqual(batch.to_bytes(), direct.to_bytes())
                        self.assertEqual(
                            MerkleBatchProof.from_bytes(batch.to_bytes()), batch
                        )

    def test_re_encoding_reproduces_source_bytes(self):
        for w in (4, 8):
            for height in (1, 2, 3, 8):
                public_key, messages, signatures = make_full(w=w, height=height)
                leaf_count = 1 << height
                for indices in (
                    (0,),
                    (leaf_count - 1,),
                    tuple(range(0, leaf_count, 3)),
                    tuple(range(leaf_count)),
                ):
                    with self.subTest(w=w, height=height, indices=indices):
                        proof, batch = expand(
                            public_key, messages, signatures, indices
                        )
                        self.assertEqual(
                            multiproof_encode(batch.public_key, batch.signatures),
                            proof,
                        )

    def test_result_fields(self):
        public_key, messages, signatures = make_full(height=3)
        indices = (1, 4, 6)
        _, batch = expand(public_key, messages, signatures, indices)
        self.assertIsInstance(batch, MerkleBatchProof)
        self.assertEqual(batch.public_key, public_key)
        self.assertEqual(batch.public_key.to_bytes(), public_key.to_bytes())
        self.assertEqual(
            tuple(signature.index for signature in batch.signatures), indices
        )
        for signature in batch.signatures:
            self.assertEqual(len(signature.auth_path), public_key.height)
            self.assertTrue(
                all(isinstance(node, bytes) for node in signature.auth_path)
            )

    def test_single_sparse_and_full_leaves(self):
        for height in (1, 2, 4, 6):
            public_key, messages, signatures = make_full(height=height)
            leaf_count = 1 << height
            cases = [
                (0,),
                (leaf_count - 1,),
                tuple(range(0, leaf_count, max(1, leaf_count // 3))),
                tuple(range(leaf_count)),
            ]
            for indices in cases:
                with self.subTest(height=height, indices=indices):
                    proof, batch = expand(
                        public_key, messages, signatures, indices
                    )
                    self.assertTrue(
                        multiproof_verify(
                            group_for(messages, indices), proof
                        )
                    )
                    self.assertTrue(
                        batch.verify(group_for(messages, indices))
                    )

    def test_duplicate_messages_kept_per_leaf(self):
        signer = make_signer(height=2)
        messages = ("same", "same", "other", "same")
        signatures = signer.sign_batch(messages)
        proof = multiproof_encode(signer.public_key, signatures)
        batch = multiproof_expand(
            messages, proof, public_key=signer.public_key
        )
        self.assertEqual(
            tuple(signature.index for signature in batch.signatures),
            (0, 1, 2, 3),
        )
        self.assertEqual(batch.signatures, signatures)
        self.assertTrue(batch.verify(messages))
        self.assertEqual(
            multiproof_encode(batch.public_key, batch.signatures), proof
        )

    def test_expand_after_select(self):
        public_key, messages, signatures = make_full(height=4)
        keep = (0, 3, 7, 11, 15)
        selected = multiproof_select(
            messages,
            proof_for(public_key, signatures, tuple(range(16))),
            public_key=public_key,
            indices=keep,
        )
        batch = multiproof_expand(
            group_for(messages, keep), selected, public_key=public_key
        )
        self.assertEqual(
            batch.signatures, tuple(signatures[i] for i in keep)
        )
        self.assertEqual(
            multiproof_encode(batch.public_key, batch.signatures), selected
        )

    def test_expand_after_merge(self):
        for w in (4, 8):
            public_key, messages, signatures = make_full(height=4, w=w)
            left = (0, 2, 5)
            right = (3, 5, 9, 14)
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
            )
            union = tuple(sorted(set(left) | set(right)))
            batch = multiproof_expand(
                group_for(messages, union), merged, public_key=public_key
            )
            self.assertEqual(
                batch.signatures, tuple(signatures[i] for i in union)
            )
            self.assertEqual(
                multiproof_encode(batch.public_key, batch.signatures), merged
            )


class TestMultiproofExpandVerification(unittest.TestCase):
    def test_batch_verify_and_verify_bound(self):
        public_key, messages, signatures = make_full(height=3)
        indices = (0, 2, 5, 7)
        proof_messages = group_for(messages, indices)
        _, batch = expand(public_key, messages, signatures, indices)
        self.assertTrue(batch.verify(proof_messages))
        self.assertTrue(
            batch.verify_bound(
                proof_messages, public_key=public_key, indices=indices
            )
        )
        self.assertTrue(
            multiproof_verify_bound(
                proof_messages,
                proof_for(public_key, signatures, indices),
                public_key=public_key,
                indices=indices,
            )
        )

    def test_each_signature_verifies_independently(self):
        public_key, messages, signatures = make_full(height=3)
        indices = (1, 3, 6)
        _, batch = expand(public_key, messages, signatures, indices)
        for position, index in enumerate(indices):
            message = messages[index]
            signature = batch.signatures[position]
            self.assertTrue(
                merkle_verify(message, signature, public_key)
            )
            single = MerkleProof(
                public_key=public_key, signature=signature
            )
            self.assertTrue(single.verify(message))
            self.assertTrue(
                single.verify_bound(
                    message, public_key=public_key, index=index
                )
            )
            self.assertEqual(
                single.to_bytes(),
                MerkleProof(
                    public_key=public_key, signature=signatures[index]
                ).to_bytes(),
            )

    def test_context_binding(self):
        public_key, messages, signatures = make_full(height=3, context="ctx")
        indices = (1, 6)
        proof = proof_for(public_key, signatures, indices)
        proof_messages = group_for(messages, indices)
        batch = multiproof_expand(
            proof_messages, proof, public_key=public_key, context="ctx"
        )
        self.assertEqual(
            batch.signatures, tuple(signatures[i] for i in indices)
        )
        self.assertTrue(batch.verify(proof_messages, context="ctx"))
        for position, index in enumerate(indices):
            self.assertTrue(
                merkle_verify(
                    messages[index],
                    batch.signatures[position],
                    public_key,
                    context="ctx",
                )
            )
        self.assertFalse(batch.verify(proof_messages))
        self.assertEqual(
            multiproof_encode(batch.public_key, batch.signatures), proof
        )

    def test_empty_context_forms_equivalent(self):
        public_key, messages, signatures = make_full(height=2)
        proof = proof_for(public_key, signatures, (0, 2))
        for context in (None, b"", bytearray(), ""):
            with self.subTest(context=context):
                batch = multiproof_expand(
                    (messages[0], messages[2]),
                    proof,
                    public_key=public_key,
                    context=context,
                )
                self.assertEqual(batch.signatures, (signatures[0], signatures[2]))

    def test_context_mismatch_raises_value_error(self):
        public_key, messages, signatures = make_full(height=3, context="ctx")
        proof = proof_for(public_key, signatures, (1, 6))
        proof_messages = (messages[1], messages[6])
        for bad_context in (None, b"", "other", b"ctx\x00"):
            with self.subTest(context=bad_context):
                with self.assertRaises(ValueError):
                    multiproof_expand(
                        proof_messages,
                        proof,
                        public_key=public_key,
                        context=bad_context,
                    )

    def test_wrong_message_raises_value_error(self):
        public_key, messages, signatures = make_full(height=2)
        proof = proof_for(public_key, signatures, tuple(range(4)))
        wrong = ("tampered",) + messages[1:]
        with self.assertRaises(ValueError):
            multiproof_expand(wrong, proof, public_key=public_key)
        swapped = (messages[1], messages[0], messages[2], messages[3])
        with self.assertRaises(ValueError):
            multiproof_expand(swapped, proof, public_key=public_key)

    def test_corrupted_leaf_raises_value_error(self):
        public_key, messages, signatures = make_full(height=2)
        proof = bytearray(
            proof_for(public_key, signatures, tuple(range(4)))
        )
        proof[_MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES + 4] ^= 0xFF
        with self.assertRaises(ValueError):
            multiproof_expand(
                messages, bytes(proof), public_key=public_key
            )

    def test_corrupted_auth_node_raises_value_error(self):
        public_key, messages, signatures = make_full(height=2)
        # Two leaves whose sibling at level 0 is a carried node; flip a
        # byte in that carried node (after all leaf blocks).
        indices = (0, 2)
        proof = bytearray(proof_for(public_key, signatures, indices))
        proof[-1] ^= 0x01
        with self.assertRaises(ValueError):
            multiproof_expand(
                group_for(messages, indices), bytes(proof),
                public_key=public_key,
            )

    def test_malformed_proof_raises_value_error(self):
        public_key, messages, signatures = make_full(height=2)
        proof = proof_for(public_key, signatures, tuple(range(4)))
        for bad in (
            proof[:-1],
            proof + b"\x00",
            b"",
            b"\x00" * 32,
        ):
            with self.subTest(bad=bad[:12]):
                with self.assertRaises(ValueError):
                    multiproof_expand(messages, bad, public_key=public_key)
        corrupted = bytearray(proof)
        corrupted[8] = 2
        with self.assertRaises(ValueError):
            multiproof_expand(
                messages, bytes(corrupted), public_key=public_key
            )
        truncated_header = proof[:_MULTIPROOF_HEADER_BYTES - 1]
        with self.assertRaises(ValueError):
            multiproof_expand(
                messages, truncated_header, public_key=public_key
            )

    def test_public_key_mismatch_raises_value_error(self):
        public_key, messages, signatures = make_full(height=2)
        proof = proof_for(public_key, signatures, (0, 1))
        other = make_signer(height=2, start=1000).public_key
        with self.assertRaises(ValueError):
            multiproof_expand(
                (messages[0], messages[1]), proof, public_key=other
            )
        same_root_other_w = type(public_key)(
            w=8, height=public_key.height, root=public_key.root
        )
        with self.assertRaises(ValueError):
            multiproof_expand(
                (messages[0], messages[1]),
                proof,
                public_key=same_root_other_w,
            )
        same_root_other_height = type(public_key)(
            w=public_key.w, height=3, root=public_key.root
        )
        with self.assertRaises(ValueError):
            multiproof_expand(
                (messages[0], messages[1]),
                proof,
                public_key=same_root_other_height,
            )

    def test_message_count_mismatch_raises_value_error(self):
        public_key, messages, signatures = make_full(height=2)
        proof = proof_for(public_key, signatures, tuple(range(4)))
        for bad_messages in (messages[:3], messages + ("extra",), ()):
            with self.subTest(count=len(bad_messages)):
                with self.assertRaises(ValueError):
                    multiproof_expand(
                        bad_messages, proof, public_key=public_key
                    )


class TestMultiproofExpandValidation(unittest.TestCase):
    def setUp(self):
        self.public_key, self.messages, self.signatures = make_full(height=2)
        self.proof = proof_for(
            self.public_key, self.signatures, tuple(range(4))
        )

    def expand(self, messages=Ellipsis, data=Ellipsis, **kwargs):
        if messages is Ellipsis:
            messages = self.messages
        if data is Ellipsis:
            data = self.proof
        kwargs.setdefault("public_key", self.public_key)
        return multiproof_expand(messages, data, **kwargs)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            self.expand(data="not-bytes")
        with self.assertRaises(TypeError):
            self.expand(data=None)
        with self.assertRaises(TypeError):
            self.expand(data=123)
        with self.assertRaises(TypeError):
            self.expand(messages=list(self.messages))
        with self.assertRaises(TypeError):
            self.expand(messages=self.messages[:3] + (1,))
        with self.assertRaises(TypeError):
            self.expand(messages=(None,))
        with self.assertRaises(TypeError):
            self.expand(public_key="key")
        with self.assertRaises(TypeError):
            self.expand(public_key=None)
        with self.assertRaises(TypeError):
            self.expand(context=1)
        with self.assertRaises(TypeError):
            self.expand(context=1.5)

    def test_type_checks_precede_content_checks(self):
        # Bad data type with an empty message tuple: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_expand(
                (), 123, public_key=self.public_key
            )
        # Bad messages type with malformed data: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_expand(
                ["not", "a", "tuple"], self.proof, public_key=self.public_key
            )
        # Illegal message member with a wrong-count tuple: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_expand(
                (1,), self.proof, public_key=self.public_key
            )
        # Bad public_key type regardless of otherwise-bad content.
        with self.assertRaises(TypeError):
            multiproof_expand((), self.proof, public_key="key")
        # Bad context type even with empty messages: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_expand(
                (), self.proof, public_key=self.public_key, context=4
            )

    def test_empty_messages_value_error(self):
        with self.assertRaises(ValueError):
            self.expand(messages=())

    def test_message_member_forms_and_bytearray_data(self):
        public_key, messages, signatures = make_full(height=2)
        proof = proof_for(public_key, signatures, (1, 2))
        mixed = tuple(
            bytearray(m.encode()) if i % 2 else m for i, m in enumerate(
                (messages[1], messages[2])
            )
        )
        batch = multiproof_expand(
            mixed, bytearray(proof), public_key=public_key
        )
        self.assertEqual(batch.signatures, (signatures[1], signatures[2]))


class TestMultiproofExpandIsolation(unittest.TestCase):
    def test_inputs_are_not_modified(self):
        public_key, messages, signatures = make_full(height=2)
        proof = proof_for(public_key, signatures, (0, 3))
        data = bytearray(proof)
        message_buffers = tuple(
            bytearray(m.encode()) for m in (messages[0], messages[3])
        )
        snapshots = tuple(bytes(buf) for buf in message_buffers)
        multiproof_expand(
            message_buffers, data, public_key=public_key
        )
        self.assertEqual(bytes(data), proof)
        for buf, snapshot in zip(message_buffers, snapshots):
            self.assertEqual(bytes(buf), snapshot)

    def test_result_does_not_alias_input_buffers(self):
        public_key, messages, signatures = make_full(height=2)
        proof = bytearray(
            proof_for(public_key, signatures, (0, 3))
        )
        batch = multiproof_expand(
            (messages[0], messages[3]), bytes(proof),
            public_key=public_key,
        )
        # Mutate the caller's buffer after the call; the frozen result
        # must keep independent copies of every byte it carries.
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
        signatures = signer.sign_batch(messages)
        self.assertEqual(signer.next_index, 4)
        proof = multiproof_encode(signer.public_key, signatures)
        before = signer.checkpoint()
        multiproof_expand(messages, proof, public_key=signer.public_key)
        self.assertEqual(signer.next_index, 4)
        self.assertEqual(signer.remaining, 0)
        self.assertEqual(signer.checkpoint(), before)

    def test_result_is_frozen(self):
        public_key, messages, signatures = make_full(height=2)
        _, batch = expand(public_key, messages, signatures, (0, 1))
        with self.assertRaises(Exception):
            batch.signatures = ()
        with self.assertRaises(Exception):
            batch.public_key = public_key


class TestMultiproofExpandPerLeafContexts(unittest.TestCase):
    def make_per_leaf(self, height=3, w=4):
        signer = make_signer(height=height, w=w)
        leaf_count = 1 << height
        messages = tuple(f"message-{i}" for i in range(leaf_count))
        contexts = tuple(f"ctx-{i}" for i in range(leaf_count))
        signatures = signer.sign_batch(messages, contexts=contexts)
        return signer.public_key, messages, contexts, signatures

    def expand_per_leaf(self, public_key, messages, contexts, signatures, indices):
        proof = proof_for(public_key, signatures, indices)
        proof_messages = group_for(messages, indices)
        proof_contexts = group_for(contexts, indices)
        batch = multiproof_expand(
            proof_messages,
            proof,
            public_key=public_key,
            contexts=proof_contexts,
        )
        return proof, batch

    def test_restored_signatures_equal_originals(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5, 8):
                public_key, messages, contexts, signatures = self.make_per_leaf(
                    height=height, w=w
                )
                leaf_count = 1 << height
                selections = [
                    (0,),
                    (leaf_count - 1,),
                    tuple(range(leaf_count)),
                ]
                if leaf_count > 2:
                    selections += [
                        (0, leaf_count - 1),
                        tuple(range(0, leaf_count, 2)),
                        tuple(range(1, leaf_count, 2)),
                    ]
                for indices in selections:
                    with self.subTest(w=w, height=height, indices=indices):
                        _, batch = self.expand_per_leaf(
                            public_key, messages, contexts, signatures, indices
                        )
                        self.assertEqual(
                            batch.signatures,
                            tuple(signatures[i] for i in indices),
                        )

    def test_batch_verifies_with_per_leaf_contexts(self):
        public_key, messages, contexts, signatures = self.make_per_leaf(height=3)
        indices = (0, 2, 5, 7)
        _, batch = self.expand_per_leaf(
            public_key, messages, contexts, signatures, indices
        )
        proof_messages = group_for(messages, indices)
        proof_contexts = group_for(contexts, indices)
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
        # Without the per-leaf contexts nothing should verify.
        self.assertFalse(batch.verify(proof_messages))

    def test_each_signature_verifies_independently_with_its_context(self):
        public_key, messages, contexts, signatures = self.make_per_leaf(height=3)
        indices = (1, 3, 6)
        proof, batch = self.expand_per_leaf(
            public_key, messages, contexts, signatures, indices
        )
        for position, index in enumerate(indices):
            signature = batch.signatures[position]
            self.assertTrue(
                merkle_verify(
                    messages[index],
                    signature,
                    public_key,
                    context=contexts[index],
                )
            )
            self.assertFalse(
                merkle_verify(messages[index], signature, public_key)
            )
        # Re-compressing reproduces the source byte for byte.
        self.assertEqual(
            multiproof_encode(batch.public_key, batch.signatures), proof
        )

    def test_sparse_single_and_full_leaves_both_w(self):
        for w in (4, 8):
            for height in (1, 2, 4, 6):
                public_key, messages, contexts, signatures = self.make_per_leaf(
                    height=height, w=w
                )
                leaf_count = 1 << height
                cases = [
                    (0,),
                    (leaf_count - 1,),
                    tuple(range(0, leaf_count, max(1, leaf_count // 3))),
                    tuple(range(leaf_count)),
                ]
                for indices in cases:
                    with self.subTest(w=w, height=height, indices=indices):
                        proof, batch = self.expand_per_leaf(
                            public_key, messages, contexts, signatures, indices
                        )
                        proof_messages = group_for(messages, indices)
                        proof_contexts = group_for(contexts, indices)
                        self.assertTrue(
                            multiproof_verify(
                                proof_messages, proof, contexts=proof_contexts
                            )
                        )
                        self.assertTrue(
                            batch.verify(proof_messages, contexts=proof_contexts)
                        )

    def test_member_form_variants_normalise(self):
        signer = make_signer(height=2)
        messages = ("a", "b", "c", "d")
        contexts = (None, "ctx-1", b"", "ctx-3")
        signatures = signer.sign_batch(messages, contexts=contexts)
        public_key = signer.public_key
        proof = proof_for(public_key, signatures, (0, 2, 3))
        batch = multiproof_expand(
            ("a", "c", "d"),
            proof,
            public_key=public_key,
            contexts=(None, bytearray(), b"ctx-3"),
        )
        self.assertEqual(
            batch.signatures,
            (signatures[0], signatures[2], signatures[3]),
        )
        self.assertTrue(
            batch.verify(
                ("a", "c", "d"), contexts=(None, None, "ctx-3")
            )
        )

    def test_same_message_with_different_contexts_at_different_leaves(self):
        signer = make_signer(height=2)
        messages = ("same", "same", "other", "same")
        contexts = ("one", "two", None, "four")
        signatures = signer.sign_batch(messages, contexts=contexts)
        public_key = signer.public_key
        proof = proof_for(public_key, signatures, (0, 1, 3))
        batch = multiproof_expand(
            ("same", "same", "same"),
            proof,
            public_key=public_key,
            contexts=("one", "two", "four"),
        )
        self.assertEqual(
            tuple(signature.index for signature in batch.signatures),
            (0, 1, 3),
        )
        self.assertEqual(
            batch.signatures, (signatures[0], signatures[1], signatures[3])
        )
        self.assertTrue(
            batch.verify(
                ("same", "same", "same"),
                contexts=("one", "two", "four"),
            )
        )

    def test_expand_after_merge_with_per_leaf_contexts(self):
        for w in (4, 8):
            public_key, messages, contexts, signatures = self.make_per_leaf(
                height=4, w=w
            )
            left = (0, 2, 5)
            right = (3, 5, 9, 14)
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
                multiproof_encode(batch.public_key, batch.signatures), merged
            )

    def test_wrong_context_for_any_leaf_raises_value_error(self):
        public_key, messages, contexts, signatures = self.make_per_leaf(height=2)
        indices = (0, 1, 2, 3)
        proof = proof_for(public_key, signatures, indices)
        for tampered in range(4):
            bad_contexts = tuple(
                "other" if i == tampered else contexts[i] for i in indices
            )
            with self.subTest(tampered=tampered):
                with self.assertRaises(ValueError):
                    multiproof_expand(
                        messages,
                        proof,
                        public_key=public_key,
                        contexts=bad_contexts,
                    )

    def test_corrupted_auth_node_with_contexts_raises_value_error(self):
        public_key, messages, contexts, signatures = self.make_per_leaf(height=2)
        indices = (0, 2)
        proof = bytearray(proof_for(public_key, signatures, indices))
        proof[-1] ^= 0x01
        with self.assertRaises(ValueError):
            multiproof_expand(
                group_for(messages, indices),
                bytes(proof),
                public_key=public_key,
                contexts=group_for(contexts, indices),
            )

    def test_empty_shared_context_combines_with_contexts(self):
        public_key, messages, contexts, signatures = self.make_per_leaf(height=2)
        indices = (0, 3)
        proof = proof_for(public_key, signatures, indices)
        group = group_for(messages, indices)
        per_leaf = group_for(contexts, indices)
        expected = multiproof_expand(
            group, proof, public_key=public_key, contexts=per_leaf
        )
        for empty in (None, b"", bytearray(), ""):
            with self.subTest(context=empty):
                batch = multiproof_expand(
                    group,
                    proof,
                    public_key=public_key,
                    context=empty,
                    contexts=per_leaf,
                )
                self.assertEqual(batch.signatures, expected.signatures)

    def test_type_errors(self):
        public_key, messages, contexts, signatures = self.make_per_leaf(height=2)
        proof = proof_for(public_key, signatures, tuple(range(4)))

        def expand(**kwargs):
            return multiproof_expand(
                messages, proof, public_key=public_key, **kwargs
            )

        with self.assertRaises(TypeError):
            expand(contexts=list(contexts))
        with self.assertRaises(TypeError):
            expand(contexts=b"ctx")
        with self.assertRaises(TypeError):
            expand(contexts="ctx")
        with self.assertRaises(TypeError):
            expand(contexts=(1, None, None, None))
        with self.assertRaises(TypeError):
            expand(contexts=(object(),) * 4)

    def test_type_checks_precede_content_checks(self):
        public_key, messages, contexts, signatures = self.make_per_leaf(height=2)
        proof = proof_for(public_key, signatures, tuple(range(4)))
        # Bad contexts member with empty messages: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_expand(
                (),
                proof,
                public_key=public_key,
                contexts=(1,),
            )
        # Bad contexts container with malformed data: TypeError wins.
        with self.assertRaises(TypeError):
            multiproof_expand(
                messages, b"", public_key=public_key, contexts=[]
            )
        # Bad contexts member with a conflicting non-empty context.
        with self.assertRaises(TypeError):
            multiproof_expand(
                messages,
                proof,
                public_key=public_key,
                context="ctx",
                contexts=(1,) * 4,
            )
        # Bad public_key type still wins with bad contexts content.
        with self.assertRaises(TypeError):
            multiproof_expand(
                messages, proof, public_key="key", contexts=contexts
            )

    def test_value_errors(self):
        public_key, messages, contexts, signatures = self.make_per_leaf(height=2)
        proof = proof_for(public_key, signatures, tuple(range(4)))

        def expand(contexts_):
            return multiproof_expand(
                messages, proof, public_key=public_key, contexts=contexts_
            )

        # Explicit empty contexts tuple.
        with self.assertRaises(ValueError):
            expand(())
        # Wrong length.
        with self.assertRaises(ValueError):
            expand(contexts[:3])
        with self.assertRaises(ValueError):
            expand(contexts + ("extra",))
        # Combined with a non-empty shared context.
        with self.assertRaises(ValueError):
            multiproof_expand(
                messages,
                proof,
                public_key=public_key,
                context="ctx",
                contexts=(b"",) * 4,
            )

    def test_result_does_not_alias_context_buffers(self):
        public_key, messages, _, signatures = self.make_per_leaf(height=2)
        proof = bytearray(proof_for(public_key, signatures, (0, 3)))
        contexts = (
            bytearray(b"ctx-0"),
            bytearray(b"ctx-3"),
        )
        batch = multiproof_expand(
            (messages[0], messages[3]),
            bytes(proof),
            public_key=public_key,
            contexts=contexts,
        )
        proof[0] ^= 0xFF
        contexts[0][0] ^= 0xFF
        reencoded = multiproof_encode(batch.public_key, batch.signatures)
        proof[0] ^= 0xFF
        self.assertEqual(reencoded, bytes(proof))

    def test_inputs_are_not_modified(self):
        public_key, messages, _, signatures = self.make_per_leaf(height=2)
        proof = bytearray(proof_for(public_key, signatures, (0, 3)))
        proof_snapshot = bytes(proof)
        contexts = (
            bytearray(b"ctx-0"),
            bytearray(b"ctx-3"),
        )
        snapshots = tuple(bytes(buf) for buf in contexts)
        multiproof_expand(
            (messages[0], messages[3]),
            proof,
            public_key=public_key,
            contexts=contexts,
        )
        self.assertEqual(bytes(proof), proof_snapshot)
        for buf, snapshot in zip(contexts, snapshots):
            self.assertEqual(bytes(buf), snapshot)

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


if __name__ == "__main__":
    unittest.main()

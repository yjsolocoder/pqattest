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


if __name__ == "__main__":
    unittest.main()

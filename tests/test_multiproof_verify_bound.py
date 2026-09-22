import unittest

from pqattest import (
    MerklePublicKey,
    MerkleSigner,
    multiproof_encode,
    multiproof_verify,
    multiproof_verify_bound,
)

ELEMENT_BYTES = 32


def counter_tokens(start=0):
    state = {"value": start}

    def token_bytes(size):
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def make_proof(signer, messages, *, indices=None):
    if indices is None:
        signatures = tuple(signer.sign(message) for message in messages)
    else:
        signatures = tuple(
            signer._signature_at(index, message)
            for index, message in zip(indices, messages)
        )
    return multiproof_encode(signer.public_key, signatures)


class MultiproofVerifyBoundHappyPathTests(unittest.TestCase):
    def test_verifies_consecutive_leaves_with_and_without_indices(self):
        signer = make_signer(height=3)
        messages = (b"claim 0", "claim 1", bytearray(b"claim 2"))
        blob = make_proof(signer, messages)
        self.assertTrue(
            multiproof_verify_bound(messages, blob, public_key=signer.public_key)
        )
        self.assertTrue(
            multiproof_verify_bound(
                messages, blob, public_key=signer.public_key, indices=(0, 1, 2)
            )
        )

    def test_accepts_bytearray_data(self):
        signer = make_signer()
        messages = (b"a", b"b")
        blob = make_proof(signer, messages)
        self.assertTrue(
            multiproof_verify_bound(
                messages, bytearray(blob), public_key=signer.public_key
            )
        )

    def test_returns_plain_bool(self):
        signer = make_signer()
        blob = make_proof(signer, (b"a",))
        result = multiproof_verify_bound(
            (b"a",), blob, public_key=signer.public_key, indices=(0,)
        )
        self.assertIs(result, True)
        self.assertIsInstance(result, bool)

    def test_gapped_leaves(self):
        signer = make_signer(height=3, w=8, start=100)
        signer.advance_to(5)
        messages = ("café", b"later")
        blob = make_proof(signer, messages, indices=(0, 5))
        self.assertTrue(
            multiproof_verify_bound(
                messages, blob, public_key=signer.public_key, indices=(0, 5)
            )
        )
        self.assertTrue(
            multiproof_verify_bound(messages, blob, public_key=signer.public_key)
        )

    def test_single_leaf(self):
        signer = make_signer(height=1)
        signer.advance_to(1)
        messages = (b"only leaf 1",)
        blob = make_proof(signer, messages, indices=(1,))
        self.assertTrue(
            multiproof_verify_bound(
                messages, blob, public_key=signer.public_key, indices=(1,)
            )
        )

    def test_matches_unbound_verification(self):
        signer = make_signer(height=3)
        messages = (b"a", b"b", b"c")
        blob = make_proof(signer, messages)
        self.assertTrue(multiproof_verify(messages, blob))
        self.assertTrue(
            multiproof_verify_bound(messages, blob, public_key=signer.public_key)
        )


class MultiproofVerifyBoundKeyTests(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.messages = (b"a", b"b", b"c")
        self.blob = make_proof(self.signer, self.messages)

    def test_foreign_public_key_returns_false(self):
        other = make_signer(height=3, start=999).public_key
        self.assertFalse(
            multiproof_verify_bound(
                self.messages, self.blob, public_key=other, indices=(0, 1, 2)
            )
        )

    def test_same_shape_foreign_root_returns_false(self):
        wrong_root = MerklePublicKey(
            w=4, height=3, root=bytes(ELEMENT_BYTES)
        )
        self.assertFalse(
            multiproof_verify_bound(
                self.messages, self.blob, public_key=wrong_root
            )
        )

    def test_different_w_returns_false(self):
        other = MerklePublicKey(w=8, height=3, root=self.signer.public_key.root)
        self.assertFalse(
            multiproof_verify_bound(self.messages, self.blob, public_key=other)
        )

    def test_different_height_returns_false(self):
        other = MerklePublicKey(w=4, height=2, root=self.signer.public_key.root)
        self.assertFalse(
            multiproof_verify_bound(self.messages, self.blob, public_key=other)
        )

    def test_public_key_wrong_type_raises_typeerror(self):
        for bad in (b"x", bytearray(b"x"), None, object(), 4, "key"):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    multiproof_verify_bound(
                        self.messages, self.blob, public_key=bad
                    )

    def test_public_key_is_keyword_only(self):
        with self.assertRaises(TypeError):
            multiproof_verify_bound(
                self.messages, self.blob, self.signer.public_key
            )


class MultiproofVerifyBoundIndicesTests(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.messages = (b"a", b"b", b"c")
        self.blob = make_proof(self.signer, self.messages)

    def verify(self, indices):
        return multiproof_verify_bound(
            self.messages,
            self.blob,
            public_key=self.signer.public_key,
            indices=indices,
        )

    def test_wrong_value_returns_false(self):
        self.assertFalse(self.verify((0, 1, 3)))

    def test_permuted_order_returns_false(self):
        self.assertFalse(self.verify((0, 2, 1)))

    def test_duplicate_returns_false(self):
        self.assertFalse(self.verify((1, 1, 2)))

    def test_too_few_returns_false(self):
        self.assertFalse(self.verify((0, 1)))

    def test_too_many_returns_false(self):
        self.assertFalse(self.verify((0, 1, 2, 3)))

    def test_empty_tuple_returns_false(self):
        self.assertFalse(self.verify(()))

    def test_negative_returns_false(self):
        self.assertFalse(self.verify((-1, 1, 2)))

    def test_out_of_tree_range_returns_false(self):
        self.assertFalse(self.verify((0, 1, 8)))

    def test_boolean_member_returns_false_even_when_equal(self):
        # bool is an int subclass and True == 1, but booleans are a value
        # violation and must never pass as leaf indices.
        self.assertFalse(self.verify((0, 1, True)))
        self.assertFalse(self.verify((False, 1, 2)))
        signer = make_signer(height=2)
        signer.advance_to(1)
        messages = (b"only leaf 1",)
        blob = make_proof(signer, messages, indices=(1,))
        self.assertFalse(
            multiproof_verify_bound(
                messages, blob, public_key=signer.public_key, indices=(True,)
            )
        )

    def test_non_tuple_container_raises_typeerror(self):
        for bad in ([0, 1, 2], {0, 1, 2}, "012", range(3), 1):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    multiproof_verify_bound(
                        self.messages,
                        self.blob,
                        public_key=self.signer.public_key,
                        indices=bad,
                    )

    def test_non_integer_member_raises_typeerror(self):
        for bad in ((0, 1, 2.0), (0, "1", 2), (0, 1, None), (0, 1, b"2")):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    self.verify(bad)


_UNSET = object()


class MultiproofVerifyBoundGenericFailureTests(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.messages = (b"a", b"b", b"c")
        self.blob = make_proof(self.signer, self.messages)

    def bound(self, messages=_UNSET, data=_UNSET, **kwargs):
        kwargs.setdefault("public_key", self.signer.public_key)
        if messages is _UNSET:
            messages = self.messages
        if data is _UNSET:
            data = self.blob
        return multiproof_verify_bound(messages, data, **kwargs)

    def test_bad_message_returns_false(self):
        self.assertFalse(self.bound(messages=(b"a", b"b", b"other")))

    def test_empty_messages_returns_false(self):
        self.assertFalse(self.bound(messages=()))

    def test_illegal_message_member_returns_false(self):
        self.assertFalse(self.bound(messages=(b"a", b"b", 3)))
        self.assertFalse(self.bound(messages=(b"a", b"b", None)))

    def test_messages_not_tuple_returns_false(self):
        self.assertFalse(self.bound(messages=[b"a", b"b", b"c"]))

    def test_messages_count_mismatch_returns_false(self):
        self.assertFalse(self.bound(messages=(b"a", b"b")))

    def test_data_wrong_type_returns_false(self):
        self.assertFalse(self.bound(data=[self.blob]))
        self.assertFalse(self.bound(data=None))
        self.assertFalse(self.bound(data=123))

    def test_truncated_data_returns_false(self):
        self.assertFalse(self.bound(data=self.blob[:-1]))

    def test_garbage_data_returns_false(self):
        self.assertFalse(self.bound(data=b"\x00" * 100))

    def test_corrupted_node_returns_false(self):
        bad = bytearray(self.blob)
        bad[-1] ^= 0xFF
        self.assertFalse(self.bound(data=bytes(bad)))


if __name__ == "__main__":
    unittest.main()

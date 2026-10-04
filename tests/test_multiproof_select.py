import itertools
import unittest

from pqattest import (
    MerklePublicKey,
    MerkleSignature,
    MerkleSigner,
    multiproof_encode,
    multiproof_select,
    multiproof_verify,
    multiproof_verify_bound,
)
from pqattest.merkle import (
    _MULTIPROOF_HEADER_BYTES,
    _MULTIPROOF_NODE_BYTES,
    ELEMENT_BYTES,
)

PUBLIC_KEY_BYTES = 43
CHAINS = {4: 67, 8: 34}


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def sign_all(signer, messages, *, context=None):
    return tuple(signer.sign(message, context=context) for message in messages)


class MultiproofSelectIdentityTest(unittest.TestCase):
    def test_every_subset_of_small_trees_matches_encoder(self):
        for w in (4, 8):
            for height in (1, 2, 3):
                signer = make_signer(height=height, w=w)
                leaf_count = 1 << height
                messages = tuple(f"m{i}" for i in range(leaf_count))
                signatures = sign_all(signer, messages)
                # Partial source proofs (not all leaves present) as well.
                for source_size in range(1, leaf_count + 1):
                    source = signatures[:source_size]
                    source_messages = messages[:source_size]
                    blob = multiproof_encode(signer.public_key, source)
                    positions = range(source_size)
                    for size in range(1, source_size + 1):
                        for combo in itertools.combinations(positions, size):
                            selected_indices = tuple(source[i].index for i in combo)
                            selected_messages = tuple(
                                source_messages[i] for i in combo
                            )
                            with self.subTest(
                                w=w, height=height,
                                source=source_size, combo=combo,
                            ):
                                result = multiproof_select(
                                    source_messages,
                                    blob,
                                    public_key=signer.public_key,
                                    indices=selected_indices,
                                )
                                expected = multiproof_encode(
                                    signer.public_key,
                                    tuple(source[i] for i in combo),
                                )
                                self.assertEqual(result, expected)
                                self.assertTrue(
                                    multiproof_verify(selected_messages, result)
                                )
                                self.assertTrue(
                                    multiproof_verify_bound(
                                        selected_messages,
                                        result,
                                        public_key=signer.public_key,
                                        indices=selected_indices,
                                    )
                                )

    def test_all_legal_heights_and_both_w(self):
        for w in (4, 8):
            for height in (1, 4, 8):
                signer = make_signer(height=height, w=w)
                messages = tuple(f"m{i}" for i in range(min(5, 1 << height)))
                signatures = sign_all(signer, messages)
                blob = multiproof_encode(signer.public_key, signatures)
                indices = tuple(signature.index for signature in signatures)
                result = multiproof_select(
                    messages, blob, public_key=signer.public_key, indices=indices
                )
                self.assertEqual(result, blob)
                sparse = tuple(signature.index for signature in signatures[::2])
                sparse_messages = messages[::2]
                sparse_result = multiproof_select(
                    messages,
                    blob,
                    public_key=signer.public_key,
                    indices=sparse,
                )
                self.assertTrue(
                    multiproof_verify(sparse_messages, sparse_result)
                )

    def test_selecting_all_leaves_keeps_bytes_unchanged(self):
        signer = make_signer(height=3)
        messages = tuple(f"m{i}" for i in range(8))
        signatures = sign_all(signer, messages)
        blob = multiproof_encode(signer.public_key, signatures)
        indices = tuple(signature.index for signature in signatures)
        self.assertEqual(
            multiproof_select(
                messages, blob, public_key=signer.public_key, indices=indices
            ),
            blob,
        )

    def test_single_leaf_selection_is_independent_single_proof(self):
        signer = make_signer(height=4)
        messages = tuple(f"m{i}" for i in range(16))
        signatures = sign_all(signer, messages)
        blob = multiproof_encode(signer.public_key, signatures)
        result = multiproof_select(
            messages, blob, public_key=signer.public_key, indices=(7,)
        )
        self.assertEqual(
            result, multiproof_encode(signer.public_key, (signatures[7],))
        )
        self.assertTrue(multiproof_verify(("m7",), result))
        self.assertFalse(multiproof_verify(("m8",), result))

    def test_sparse_selection_from_full_tree(self):
        signer = make_signer(height=4, w=8)
        messages = tuple(f"m{i}" for i in range(16))
        signatures = sign_all(signer, messages)
        full = multiproof_encode(signer.public_key, signatures)
        # The full proof carries no sibling nodes; extraction must rebuild
        # every authentication node from the authenticated leaves.
        self.assertEqual(int.from_bytes(full[15:17], "big"), 0)
        chosen = (1, 3, 14)
        result = multiproof_select(
            messages,
            full,
            public_key=signer.public_key,
            indices=chosen,
        )
        expected = multiproof_encode(
            signer.public_key, tuple(signatures[i] for i in chosen)
        )
        self.assertEqual(result, expected)
        self.assertTrue(
            multiproof_verify(tuple(messages[i] for i in chosen), result)
        )

    def test_double_extraction_equals_direct_extraction(self):
        signer = make_signer(height=3)
        messages = tuple(f"m{i}" for i in range(8))
        signatures = sign_all(signer, messages)
        blob = multiproof_encode(signer.public_key, signatures)
        first_indices = (0, 2, 5)
        first_messages = tuple(messages[i] for i in first_indices)
        middle = multiproof_select(
            messages,
            blob,
            public_key=signer.public_key,
            indices=first_indices,
        )
        final_index = (5,)
        twice = multiproof_select(
            first_messages,
            middle,
            public_key=signer.public_key,
            indices=final_index,
        )
        direct = multiproof_select(
            messages,
            blob,
            public_key=signer.public_key,
            indices=final_index,
        )
        self.assertEqual(twice, direct)
        self.assertEqual(
            direct, multiproof_encode(signer.public_key, (signatures[5],))
        )

    def test_non_consecutive_double_extraction(self):
        signer = make_signer(height=4)
        messages = tuple(f"m{i}" for i in range(16))
        signatures = sign_all(signer, messages)
        blob = multiproof_encode(signer.public_key, signatures)
        first = multiproof_select(
            messages,
            blob,
            public_key=signer.public_key,
            indices=(1, 6, 9, 15),
        )
        second = multiproof_select(
            ("m1", "m6", "m9", "m15"),
            first,
            public_key=signer.public_key,
            indices=(6, 15),
        )
        direct = multiproof_select(
            messages,
            blob,
            public_key=signer.public_key,
            indices=(6, 15),
        )
        self.assertEqual(second, direct)
        self.assertEqual(
            direct,
            multiproof_encode(signer.public_key, (signatures[6], signatures[15])),
        )

    def test_duplicate_messages_handled_per_leaf(self):
        signer = make_signer(height=3)
        messages = (b"same", b"same", b"other", b"same")
        signatures = sign_all(signer, messages)
        blob = multiproof_encode(signer.public_key, signatures)
        result = multiproof_select(
            messages,
            blob,
            public_key=signer.public_key,
            indices=(0, 3),
        )
        self.assertTrue(
            multiproof_verify((b"same", b"same"), result)
        )
        self.assertTrue(
            multiproof_verify_bound(
                (b"same", b"same"),
                result,
                public_key=signer.public_key,
                indices=(0, 3),
            )
        )
        self.assertEqual(
            result,
            multiproof_encode(signer.public_key, (signatures[0], signatures[3])),
        )

    def test_bytearray_data_accepted(self):
        signer = make_signer(height=2)
        messages = ("a", "b", "c")
        signatures = sign_all(signer, messages)
        blob = multiproof_encode(signer.public_key, signatures)
        result = multiproof_select(
            messages,
            bytearray(blob),
            public_key=signer.public_key,
            indices=(0, 2),
        )
        self.assertEqual(
            result, multiproof_encode(signer.public_key, (signatures[0], signatures[2]))
        )

    def test_return_type_is_bytes(self):
        signer = make_signer(height=2)
        signatures = sign_all(signer, ("a", "b"))
        blob = multiproof_encode(signer.public_key, signatures)
        result = multiproof_select(
            ("a", "b"), blob, public_key=signer.public_key, indices=(1,)
        )
        self.assertIsInstance(result, bytes)

    def test_result_is_verified_without_original_signatures(self):
        # The caller only holds proof bytes, messages and the public key.
        signer = make_signer(height=3, w=8)
        messages = tuple(f"m{i}" for i in range(8))
        signatures = sign_all(signer, messages)
        blob = multiproof_encode(signer.public_key, signatures)
        key_bytes = signer.public_key.to_bytes()
        public_key = MerklePublicKey.from_bytes(key_bytes)
        chosen = (2, 4)
        result = multiproof_select(
            messages, blob, public_key=public_key, indices=chosen
        )
        self.assertTrue(
            multiproof_verify(tuple(messages[i] for i in chosen), result)
        )


class MultiproofSelectContextTest(unittest.TestCase):
    def test_context_bound_selection(self):
        signer = make_signer(height=2, w=8)
        messages = ("a", "b", "c")
        signatures = sign_all(signer, messages, context="ctx")
        blob = multiproof_encode(signer.public_key, signatures)
        result = multiproof_select(
            messages,
            blob,
            public_key=signer.public_key,
            indices=(0, 2),
            context="ctx",
        )
        self.assertEqual(
            result,
            multiproof_encode(signer.public_key, (signatures[0], signatures[2])),
        )
        self.assertTrue(
            multiproof_verify(("a", "c"), result, context="ctx")
        )
        self.assertFalse(multiproof_verify(("a", "c"), result))

    def test_empty_context_equivalents(self):
        signer = make_signer(height=2)
        messages = ("a", "b", "c")
        signatures = sign_all(signer, messages)
        blob = multiproof_encode(signer.public_key, signatures)
        baseline = multiproof_select(
            messages, blob, public_key=signer.public_key, indices=(1,)
        )
        for context in (None, b"", bytearray(), ""):
            with self.subTest(context=repr(context)):
                self.assertEqual(
                    multiproof_select(
                        messages,
                        blob,
                        public_key=signer.public_key,
                        indices=(1,),
                        context=context,
                    ),
                    baseline,
                )

    def test_wrong_context_rejected(self):
        signer = make_signer(height=2)
        messages = ("a", "b", "c")
        signatures = sign_all(signer, messages, context="ctx")
        blob = multiproof_encode(signer.public_key, signatures)
        with self.assertRaises(ValueError):
            multiproof_select(
                messages,
                blob,
                public_key=signer.public_key,
                indices=(0,),
            )
        with self.assertRaises(ValueError):
            multiproof_select(
                messages,
                blob,
                public_key=signer.public_key,
                indices=(0,),
                context="other",
            )

    def test_bad_context_type_raises_type_error(self):
        signer = make_signer(height=2)
        signatures = sign_all(signer, ("a", "b"))
        blob = multiproof_encode(signer.public_key, signatures)
        with self.assertRaises(TypeError):
            multiproof_select(
                ("a", "b"),
                blob,
                public_key=signer.public_key,
                indices=(0,),
                context=42,
            )


class MultiproofSelectWholeProofAuthenticationTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=2)
        self.messages = ("a", "b", "c")
        self.signatures = sign_all(self.signer, self.messages)
        self.blob = multiproof_encode(self.signer.public_key, self.signatures)
        self.key_end = _MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES
        self.leaf_block = 4 + CHAINS[4] * ELEMENT_BYTES

    def test_wrong_message_for_deleted_leaf_rejected(self):
        # Keep leaf 0 only; the wrong message belongs to deleted leaf 2.
        with self.assertRaises(ValueError):
            multiproof_select(
                ("a", "b", "WRONG"),
                self.blob,
                public_key=self.signer.public_key,
                indices=(0,),
            )

    def test_corrupted_signature_of_deleted_leaf_rejected(self):
        bad = bytearray(self.blob)
        # First W-OTS element of the third leaf block (leaf index 2).
        bad[self.key_end + 2 * self.leaf_block + 4] ^= 0x01
        with self.assertRaises(ValueError):
            multiproof_select(
                self.messages,
                bytes(bad),
                public_key=self.signer.public_key,
                indices=(0,),
            )

    def test_corrupted_signature_of_kept_leaf_rejected(self):
        bad = bytearray(self.blob)
        bad[self.key_end + 4] ^= 0x01
        with self.assertRaises(ValueError):
            multiproof_select(
                self.messages,
                bytes(bad),
                public_key=self.signer.public_key,
                indices=(0,),
            )

    def test_corrupted_carried_node_rejected_even_when_unneeded_by_selection(self):
        # A 4-leaf tree source over leaves {0,1,2}: the level-1 sibling of
        # subtree {0,1} is node (1,3), needed by the merge but not directly
        # by a single-leaf selection's canonical set after rebuilds.
        signer = make_signer(height=3)
        messages = tuple(f"m{i}" for i in range(3))
        signatures = sign_all(signer, messages)
        blob = bytearray(multiproof_encode(signer.public_key, signatures))
        node_count = int.from_bytes(blob[15:17], "big")
        self.assertGreater(node_count, 0)
        # Tamper the last node's hash byte.
        blob[-1] ^= 0x01
        with self.assertRaises(ValueError):
            multiproof_select(
                messages,
                bytes(blob),
                public_key=signer.public_key,
                indices=(0,),
            )

    def test_public_key_mismatch_rejected(self):
        other = make_signer(height=2, start=9999)
        other.sign("warmup")
        with self.assertRaises(ValueError):
            multiproof_select(
                self.messages,
                self.blob,
                public_key=other.public_key,
                indices=(0,),
            )

    def test_equal_value_public_key_instance_accepted(self):
        same_key = MerklePublicKey.from_bytes(self.signer.public_key.to_bytes())
        self.assertIsNot(same_key, self.signer.public_key)
        result = multiproof_select(
            self.messages,
            self.blob,
            public_key=same_key,
            indices=(0, 2),
        )
        self.assertEqual(
            result,
            multiproof_encode(
                self.signer.public_key, (self.signatures[0], self.signatures[2])
            ),
        )

    def test_mixed_signer_proof_rejected(self):
        # A structurally compatible leaf from a second signer passes the
        # parse (no shared coordinate to conflict) but must fail the
        # whole-proof root authentication.
        signer_a = make_signer(height=2, start=0)
        signer_b = make_signer(height=2, start=5000)
        foreign = signer_b.sign("a")
        blob = multiproof_encode(signer_a.public_key, (foreign,))
        with self.assertRaises(ValueError):
            multiproof_select(
                ("a",),
                blob,
                public_key=signer_a.public_key,
                indices=(0,),
            )


class MultiproofSelectTypeErrorTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=2)
        self.messages = ("a", "b", "c")
        self.signatures = sign_all(self.signer, self.messages)
        self.blob = multiproof_encode(self.signer.public_key, self.signatures)

    def _select(self, messages, data, *, public_key="UNSET", indices=(0,), context=None):
        return multiproof_select(
            messages,
            data,
            public_key=self.signer.public_key if public_key == "UNSET" else public_key,
            indices=indices,
            context=context,
        )

    def test_bad_data_types(self):
        for bad in (None, 42, 4.5, "data", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self._select(self.messages, bad)

    def test_bad_messages_container(self):
        for bad in (None, 42, b"abc", ["a", "b", "c"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self._select(bad, self.blob)

    def test_bad_message_members(self):
        for bad in (None, 42, 4.5, [1], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self._select(("a", bad, "c"), self.blob)

    def test_bad_public_key_type(self):
        for bad in (None, 42, "key", b"raw", self.signatures, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self._select(self.messages, self.blob, public_key=bad)

    def test_bad_indices_container(self):
        for bad in (None, 42, [0], (i for i in (0,)), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self._select(self.messages, self.blob, indices=bad)

    def test_non_integer_index_members(self):
        for bad in ((1.0,), ("0",), (b"0",), (None,), (object(),)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    self._select(self.messages, self.blob, indices=bad)


class MultiproofSelectValueErrorTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.messages = tuple(f"m{i}" for i in range(4))
        self.signatures = sign_all(self.signer, self.messages)
        self.blob = multiproof_encode(self.signer.public_key, self.signatures)

    def _select(self, indices, *, messages=None):
        return multiproof_select(
            self.messages if messages is None else messages,
            self.blob,
            public_key=self.signer.public_key,
            indices=indices,
        )

    def test_empty_selection(self):
        with self.assertRaises(ValueError):
            self._select(())

    def test_boolean_indices(self):
        for bad in ((True,), (False,), (0, True), (True, 2)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._select(bad)

    def test_duplicate_and_unordered_indices(self):
        for bad in ((0, 0), (2, 1), (0, 2, 2), (3, 2, 1)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._select(bad)

    def test_index_absent_from_source_proof(self):
        # The source covers leaves 0..3 of an 8-leaf tree.
        for bad in ((4,), (7,), (0, 4), (-1,)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self._select(bad)

    def test_message_count_mismatch(self):
        with self.assertRaises(ValueError):
            self._select((0,), messages=("m0",))
        with self.assertRaises(ValueError):
            multiproof_select(
                self.messages + ("m4",),
                self.blob,
                public_key=self.signer.public_key,
                indices=(0,),
            )

    def test_malformed_source_proofs(self):
        bad_magic = bytearray(self.blob)
        bad_magic[0] ^= 0x01
        bad_version = bytearray(self.blob)
        bad_version[8] = 2
        for bad in (
            self.blob[:-1],
            self.blob + b"\x00",
            b"X" * len(self.blob),
            self.blob[:8],
            bytes(bad_magic),
            bytes(bad_version),
        ):
            with self.subTest(bad=bad[:8]):
                with self.assertRaises(ValueError):
                    multiproof_select(
                        self.messages,
                        bad,
                        public_key=self.signer.public_key,
                        indices=(0,),
                    )

    def test_wrong_messages_rejected(self):
        with self.assertRaises(ValueError):
            multiproof_select(
                ("m0", "m1", "m2", "other"),
                self.blob,
                public_key=self.signer.public_key,
                indices=(0, 1, 2, 3),
            )

    def test_foreign_proof_under_expected_key_rejected(self):
        foreign = make_signer(height=3, start=7777)
        foreign_sigs = sign_all(foreign, self.messages)
        foreign_blob = multiproof_encode(foreign.public_key, foreign_sigs)
        with self.assertRaises(ValueError):
            multiproof_select(
                self.messages,
                foreign_blob,
                public_key=self.signer.public_key,
                indices=(0,),
            )

    def test_other_w_key_rejected(self):
        other = make_signer(height=3, w=8, start=1234)
        other_sigs = sign_all(other, self.messages)
        other_blob = multiproof_encode(other.public_key, other_sigs)
        with self.assertRaises(ValueError):
            multiproof_select(
                self.messages,
                other_blob,
                public_key=self.signer.public_key,
                indices=(0,),
            )


class MultiproofSelectPurityTest(unittest.TestCase):
    def test_inputs_not_modified_and_deterministic(self):
        signer = make_signer(height=3)
        messages = tuple(f"m{i}" for i in range(8))
        signatures = sign_all(signer, messages)
        blob = multiproof_encode(signer.public_key, signatures)
        blob_before = bytes(blob)
        indices = (1, 4)
        first = multiproof_select(
            messages, blob, public_key=signer.public_key, indices=indices
        )
        second = multiproof_select(
            messages, blob, public_key=signer.public_key, indices=indices
        )
        self.assertEqual(first, second)
        self.assertEqual(blob, blob_before)
        # No signer state is touched by extraction.
        self.assertEqual(signer.next_index, 8)

    def test_messages_tuple_members_keep_type(self):
        signer = make_signer(height=2)
        messages = ("str", b"bytes", bytearray(b"array"))
        signatures = sign_all(signer, messages)
        blob = multiproof_encode(signer.public_key, signatures)
        result = multiproof_select(
            messages, blob, public_key=signer.public_key, indices=(0, 2)
        )
        self.assertTrue(multiproof_verify(("str", bytearray(b"array")), result))


if __name__ == "__main__":
    unittest.main()

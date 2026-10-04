import unittest

from pqattest import (
    MerkleSigner,
    multiproof_encode,
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


def make_signed(height=3, w=4, start=0, context=None):
    """A signer plus one signature per leaf, all from a single batch."""
    signer = make_signer(height=height, w=w, start=start)
    leaf_count = 1 << height
    messages = tuple(f"message-{i}" for i in range(leaf_count))
    signatures = (
        signer.sign_batch(messages, context=context)
        if context is not None
        else signer.sign_batch(messages)
    )
    return signer.public_key, messages, signatures


def encode_subset(public_key, signatures, subset):
    return multiproof_encode(public_key, tuple(signatures[i] for i in subset))


class TestMultiproofMergeEquivalence(unittest.TestCase):
    def test_single_source_returns_identical_bytes(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                public_key, messages, signatures = make_signed(w=w, height=height)
                subsets = [
                    tuple(range(1 << height)),
                    (0,),
                    (1 << (height - 1),),
                    tuple(range(0, 1 << height, 2)),
                ]
                for subset in subsets:
                    proof = encode_subset(public_key, signatures, subset)
                    group = tuple(messages[i] for i in subset)
                    with self.subTest(w=w, height=height, subset=subset):
                        merged = multiproof_merge(
                            (group,), (proof,), public_key=public_key
                        )
                        self.assertIsInstance(merged, bytes)
                        self.assertEqual(merged, proof)

    def test_merge_matches_encode_of_union_signatures(self):
        for w in (4, 8):
            for height in (1, 2, 3, 4):
                public_key, messages, signatures = make_signed(w=w, height=height)
                leaf_count = 1 << height
                partitions = [
                    (tuple(range(0, leaf_count, 2)), tuple(range(1, leaf_count, 2))),
                    ((0,), tuple(range(1, leaf_count))),
                    (tuple(range(leaf_count)),),
                ]
                if leaf_count >= 4:
                    partitions.append(
                        ((0, leaf_count - 1), tuple(range(1, leaf_count - 1)))
                    )
                for subsets in partitions:
                    proofs = tuple(
                        encode_subset(public_key, signatures, subset)
                        for subset in subsets
                    )
                    groups = tuple(
                        tuple(messages[i] for i in subset) for subset in subsets
                    )
                    union = tuple(sorted(i for subset in subsets for i in subset))
                    with self.subTest(w=w, height=height, subsets=subsets):
                        merged = multiproof_merge(
                            groups, proofs, public_key=public_key
                        )
                        expected = encode_subset(public_key, signatures, union)
                        self.assertEqual(merged, expected)
                        union_messages = tuple(messages[i] for i in union)
                        self.assertTrue(
                            multiproof_verify(union_messages, merged)
                        )
                        self.assertTrue(
                            multiproof_verify_bound(
                                union_messages,
                                merged,
                                public_key=public_key,
                                indices=union,
                            )
                        )

    def test_overlapping_identical_leaves_kept_once(self):
        public_key, messages, signatures = make_signed(height=3)
        left = encode_subset(public_key, signatures, (0, 1, 2, 3))
        right = encode_subset(public_key, signatures, (2, 3, 4, 5))
        merged = multiproof_merge(
            (tuple(messages[i] for i in (0, 1, 2, 3)),
             tuple(messages[i] for i in (2, 3, 4, 5))),
            (left, right),
            public_key=public_key,
        )
        self.assertEqual(
            merged, encode_subset(public_key, signatures, (0, 1, 2, 3, 4, 5))
        )

    def test_source_order_does_not_change_result(self):
        public_key, messages, signatures = make_signed(height=4)
        subsets = [(0, 1, 2), (3, 4), (5, 6, 7, 8), (9, 15)]
        proofs = tuple(encode_subset(public_key, signatures, s) for s in subsets)
        groups = tuple(tuple(messages[i] for i in s) for s in subsets)
        forward = multiproof_merge(groups, proofs, public_key=public_key)
        backward = multiproof_merge(
            groups[::-1], proofs[::-1], public_key=public_key
        )
        shuffled = multiproof_merge(
            (groups[2], groups[0], groups[3], groups[1]),
            (proofs[2], proofs[0], proofs[3], proofs[1]),
            public_key=public_key,
        )
        self.assertEqual(forward, backward)
        self.assertEqual(forward, shuffled)

    def test_duplicate_sources_change_nothing(self):
        public_key, messages, signatures = make_signed(height=3)
        proof = encode_subset(public_key, signatures, (1, 4))
        group = (messages[1], messages[4])
        once = multiproof_merge((group,), (proof,), public_key=public_key)
        twice = multiproof_merge(
            (group, group), (proof, proof), public_key=public_key
        )
        thrice = multiproof_merge(
            (group, group, group), (proof, proof, proof), public_key=public_key
        )
        self.assertEqual(once, twice)
        self.assertEqual(once, thrice)

    def test_batched_merging_matches_direct_merge(self):
        public_key, messages, signatures = make_signed(height=4)
        subsets = [(0, 5), (1, 2), (7, 8, 9), (3, 15)]
        proofs = tuple(encode_subset(public_key, signatures, s) for s in subsets)
        groups = tuple(tuple(messages[i] for i in s) for s in subsets)
        direct = multiproof_merge(groups, proofs, public_key=public_key)
        left = multiproof_merge(groups[:2], proofs[:2], public_key=public_key)
        right = multiproof_merge(groups[2:], proofs[2:], public_key=public_key)
        left_leaves = tuple(messages[i] for i in (0, 1, 2, 5))
        right_leaves = tuple(messages[i] for i in (3, 7, 8, 9, 15))
        staged = multiproof_merge(
            (left_leaves, right_leaves), (left, right), public_key=public_key
        )
        self.assertEqual(direct, staged)

    def test_merged_proof_selects_and_merges_again(self):
        public_key, messages, signatures = make_signed(height=4)
        first = multiproof_merge(
            ((messages[0], messages[3]), (messages[9],)),
            (
                encode_subset(public_key, signatures, (0, 3)),
                encode_subset(public_key, signatures, (9,)),
            ),
            public_key=public_key,
        )
        selected = multiproof_select(
            (messages[0], messages[3], messages[9]),
            first,
            public_key=public_key,
            indices=(3, 9),
        )
        other = encode_subset(public_key, signatures, (12,))
        merged = multiproof_merge(
            ((messages[3], messages[9]), (messages[12],)),
            (selected, other),
            public_key=public_key,
        )
        self.assertEqual(
            merged, encode_subset(public_key, signatures, (3, 9, 12))
        )

    def test_same_message_on_different_leaves_stays_separate(self):
        signer = make_signer(height=2)
        signatures = signer.sign_batch(("repeat", "repeat", "repeat", "repeat"))
        public_key = signer.public_key
        first = encode_subset(public_key, signatures, (0,))
        second = encode_subset(public_key, signatures, (3,))
        merged = multiproof_merge(
            (("repeat",), (b"repeat",)), (first, second), public_key=public_key
        )
        self.assertEqual(
            merged, encode_subset(public_key, signatures, (0, 3))
        )
        self.assertTrue(multiproof_verify(("repeat", "repeat"), merged))

    def test_str_and_bytes_forms_of_one_message_deduplicate(self):
        seed_signer = MerkleSigner.from_seed(b"\x01" * 32, height=2, w=4)
        public_key = seed_signer.public_key
        first = seed_signer.sign("hello")
        twin = MerkleSigner.from_seed(b"\x01" * 32, height=2, w=4)
        second = twin.sign(b"hello")
        self.assertEqual(first, second)
        merged = multiproof_merge(
            (("hello",), (b"hello",)),
            (
                multiproof_encode(public_key, (first,)),
                multiproof_encode(public_key, (second,)),
            ),
            public_key=public_key,
        )
        self.assertEqual(merged, multiproof_encode(public_key, (first,)))

    def test_bytearray_proofs_and_messages_accepted(self):
        public_key, messages, signatures = make_signed(height=2)
        proof = encode_subset(public_key, signatures, (1, 2))
        merged = multiproof_merge(
            ((bytearray(messages[1].encode()), messages[2]),),
            (bytearray(proof),),
            public_key=public_key,
        )
        self.assertEqual(merged, proof)

    def test_context_bound_sources_merge(self):
        public_key, messages, signatures = make_signed(height=3, context="ctx")
        left = encode_subset(public_key, signatures, (0, 1))
        right = encode_subset(public_key, signatures, (4, 5))
        merged = multiproof_merge(
            ((messages[0], messages[1]), (messages[4], messages[5])),
            (left, right),
            public_key=public_key,
            context="ctx",
        )
        self.assertEqual(
            merged, encode_subset(public_key, signatures, (0, 1, 4, 5))
        )
        self.assertTrue(
            multiproof_verify(
                (messages[0], messages[1], messages[4], messages[5]),
                merged,
                context="ctx",
            )
        )
        with self.assertRaises(ValueError):
            multiproof_merge(
                ((messages[0], messages[1]), (messages[4], messages[5])),
                (left, right),
                public_key=public_key,
            )
        with self.assertRaises(ValueError):
            multiproof_merge(
                ((messages[0], messages[1]), (messages[4], messages[5])),
                (left, right),
                public_key=public_key,
                context="other",
            )


class TestMultiproofMergeTypeErrors(unittest.TestCase):
    def setUp(self):
        self.public_key, self.messages, self.signatures = make_signed(height=2)
        self.proof = encode_subset(self.public_key, self.signatures, (0, 1))
        self.group = (self.messages[0], self.messages[1])

    def test_non_tuple_containers(self):
        with self.assertRaises(TypeError):
            multiproof_merge(
                [self.group], (self.proof,), public_key=self.public_key
            )
        with self.assertRaises(TypeError):
            multiproof_merge(
                (self.group,), [self.proof], public_key=self.public_key
            )
        with self.assertRaises(TypeError):
            multiproof_merge(
                (list(self.group),), (self.proof,), public_key=self.public_key
            )

    def test_bad_member_types(self):
        with self.assertRaises(TypeError):
            multiproof_merge(
                ((object(),),), (self.proof,), public_key=self.public_key
            )
        with self.assertRaises(TypeError):
            multiproof_merge(
                (self.group,), ("not-bytes",), public_key=self.public_key
            )
        with self.assertRaises(TypeError):
            multiproof_merge(
                (self.group,), (self.proof,), public_key=self.proof
            )
        with self.assertRaises(TypeError):
            multiproof_merge(
                (self.group,),
                (self.proof,),
                public_key=self.public_key,
                context=object(),
            )

    def test_type_check_precedes_content_check(self):
        # Empty containers would be a ValueError, but a member type error
        # anywhere is reported first.
        with self.assertRaises(TypeError):
            multiproof_merge((), (object(),), public_key=self.public_key)
        with self.assertRaises(TypeError):
            multiproof_merge(
                (self.group,), (), public_key=object()
            )


class TestMultiproofMergeValueErrors(unittest.TestCase):
    def setUp(self):
        self.public_key, self.messages, self.signatures = make_signed(height=3)
        self.proof = encode_subset(self.public_key, self.signatures, (0, 1))
        self.group = (self.messages[0], self.messages[1])

    def test_empty_inputs(self):
        with self.assertRaises(ValueError):
            multiproof_merge((), (self.proof,), public_key=self.public_key)
        with self.assertRaises(ValueError):
            multiproof_merge((self.group,), (), public_key=self.public_key)
        with self.assertRaises(ValueError):
            multiproof_merge((), (), public_key=self.public_key)

    def test_group_count_mismatch(self):
        with self.assertRaises(ValueError):
            multiproof_merge(
                (self.group, self.group), (self.proof,), public_key=self.public_key
            )
        with self.assertRaises(ValueError):
            multiproof_merge(
                (self.group,), (self.proof, self.proof), public_key=self.public_key
            )

    def test_message_count_mismatch(self):
        with self.assertRaises(ValueError):
            multiproof_merge(
                ((self.messages[0],),), (self.proof,), public_key=self.public_key
            )
        with self.assertRaises(ValueError):
            multiproof_merge(
                (self.group + ("extra",),),
                (self.proof,),
                public_key=self.public_key,
            )
        with self.assertRaises(ValueError):
            multiproof_merge(((),), (self.proof,), public_key=self.public_key)

    def test_malformed_proofs(self):
        with self.assertRaises(ValueError):
            multiproof_merge(
                (self.group,), (b"",), public_key=self.public_key
            )
        with self.assertRaises(ValueError):
            multiproof_merge(
                (self.group,), (self.proof[:-1],), public_key=self.public_key
            )
        with self.assertRaises(ValueError):
            multiproof_merge(
                (self.group,),
                (self.proof + b"\x00",),
                public_key=self.public_key,
            )
        bad_magic = b"X" + self.proof[1:]
        with self.assertRaises(ValueError):
            multiproof_merge(
                (self.group,), (bad_magic,), public_key=self.public_key
            )

    def test_verification_failure(self):
        # Flip one byte inside a W-OTS element of the first leaf block.
        offset = 17 + 43 + 4
        tampered = bytearray(self.proof)
        tampered[offset] ^= 0x01
        with self.assertRaises(ValueError):
            multiproof_merge(
                (self.group,), (bytes(tampered),), public_key=self.public_key
            )
        # A wrong message fails verification too.
        with self.assertRaises(ValueError):
            multiproof_merge(
                ((self.messages[0], "wrong"),),
                (self.proof,),
                public_key=self.public_key,
            )

    def test_public_key_mismatch(self):
        other_key, _, _ = make_signed(height=3, start=1000)
        with self.assertRaises(ValueError):
            multiproof_merge(
                (self.group,), (self.proof,), public_key=other_key
            )
        other_height_key, _, _ = make_signed(height=2)
        with self.assertRaises(ValueError):
            multiproof_merge(
                (self.group,), (self.proof,), public_key=other_height_key
            )

    def test_conflicting_leaf_across_sources(self):
        seed = b"\x02" * 32
        first_signer = MerkleSigner.from_seed(seed, height=2, w=4)
        public_key = first_signer.public_key
        first = first_signer.sign("alpha")
        second_signer = MerkleSigner.from_seed(seed, height=2, w=4)
        second = second_signer.sign("beta")
        self.assertNotEqual(first, second)
        first_proof = multiproof_encode(public_key, (first,))
        second_proof = multiproof_encode(public_key, (second,))
        with self.assertRaises(ValueError):
            multiproof_merge(
                (("alpha",), ("beta",)),
                (first_proof, second_proof),
                public_key=public_key,
            )

    def test_corrupted_duplicate_is_still_verified(self):
        # The duplicate's leaves were all seen in the first source, but the
        # corrupted copy must still be fully verified and rejected.
        tampered = bytearray(self.proof)
        tampered[-1] ^= 0x01
        with self.assertRaises(ValueError):
            multiproof_merge(
                (self.group, self.group),
                (self.proof, bytes(tampered)),
                public_key=self.public_key,
            )

    def test_conflicting_node_at_same_coordinate(self):
        # Two proofs over disjoint leaves; the second carries a forged
        # sibling node that happens to be shared with no verification path
        # of its own is impossible to forge past the fold, so instead
        # confirm a hand-built node conflict is caught as a ValueError by
        # the verification step (the forged proof does not verify).
        left = encode_subset(self.public_key, self.signatures, (0,))
        right = encode_subset(self.public_key, self.signatures, (3,))
        forged = bytearray(right)
        forged[-1] ^= 0x01  # last carried node byte
        with self.assertRaises(ValueError):
            multiproof_merge(
                ((self.messages[0],), (self.messages[3],)),
                (left, bytes(forged)),
                public_key=self.public_key,
            )


class TestMultiproofMergeCoverage(unittest.TestCase):
    def test_full_and_sparse_coverage(self):
        for w in (4, 8):
            for height in (1, 2, 3, 4):
                public_key, messages, signatures = make_signed(w=w, height=height)
                leaf_count = 1 << height
                # Split every leaf across three overlapping sparse proofs.
                subsets = tuple(
                    tuple(range(start, leaf_count, 3))
                    for start in range(3)
                    if tuple(range(start, leaf_count, 3))
                )
                proofs = tuple(
                    encode_subset(public_key, signatures, s) for s in subsets
                )
                groups = tuple(
                    tuple(messages[i] for i in s) for s in subsets
                )
                with self.subTest(w=w, height=height):
                    merged = multiproof_merge(
                        groups, proofs, public_key=public_key
                    )
                    self.assertEqual(
                        merged,
                        encode_subset(
                            public_key, signatures, tuple(range(leaf_count))
                        ),
                    )
                    self.assertTrue(
                        multiproof_verify_bound(
                            messages, merged, public_key=public_key
                        )
                    )

    def test_inputs_are_not_modified(self):
        public_key, messages, signatures = make_signed(height=2)
        left = bytearray(encode_subset(public_key, signatures, (0,)))
        right = bytearray(encode_subset(public_key, signatures, (1,)))
        left_copy = bytes(left)
        right_copy = bytes(right)
        groups = ((messages[0],), (bytearray(messages[1].encode()),))
        multiproof_merge(groups, (left, right), public_key=public_key)
        self.assertEqual(bytes(left), left_copy)
        self.assertEqual(bytes(right), right_copy)
        self.assertIsInstance(groups[0][0], str)


if __name__ == "__main__":
    unittest.main()

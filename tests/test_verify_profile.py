import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    MerkleBatchProof,
    MerkleSigner,
    MerkleVerifyProfile,
    merkle_verify_profile,
    multiproof_encode,
    multiproof_verify,
)
import pqattest.merkle as merkle_module


class MerkleVerifyProfileTest(unittest.TestCase):
    def test_single_leaf_w4(self):
        # One leaf: both encodings climb the whole path, so batch == multi.
        profile = merkle_verify_profile(4, 3, (5,))
        self.assertEqual(
            profile,
            MerkleVerifyProfile(
                w=4, height=3, k=1, wots=67 * 15, leaf=1, batch=3, multi=3
            ),
        )
        self.assertEqual(profile.wots, 1005)
        # multi = |{5>>1}| + |{5>>2}| + |{5>>3}| = 1 + 1 + 1.
        self.assertEqual(
            profile.multi,
            sum(len({5 >> level}) for level in range(1, 4)),
        )

    def test_single_leaf_w8(self):
        profile = merkle_verify_profile(8, 1, (0,))
        self.assertEqual(
            profile,
            MerkleVerifyProfile(
                w=8, height=1, k=1, wots=34 * 255, leaf=1, batch=1, multi=1
            ),
        )
        self.assertEqual(profile.wots, 8670)

    def test_full_tree_dedup_savings(self):
        # All 8 leaves of a height-3 tree: multi merges 4 + 2 + 1 = 7 nodes,
        # while the batch repeats every full path for 8 * 3 = 24 hashes.
        profile = merkle_verify_profile(4, 3, tuple(range(8)))
        self.assertEqual(profile.k, 8)
        self.assertEqual(profile.wots, 8 * 67 * 15)
        self.assertEqual(profile.leaf, 8)
        self.assertEqual(profile.batch, 24)
        self.assertEqual(profile.multi, 4 + 2 + 1)

    def test_partial_set_parent_counts(self):
        # Leaves {0, 1, 6} of a height-3 tree:
        # level 1 parents {0, 3} -> 2; level 2 parents {0, 1} -> 2;
        # level 3 parent {0} -> 1; total 5.
        profile = merkle_verify_profile(8, 3, (0, 1, 6))
        self.assertEqual(profile.k, 3)
        self.assertEqual(profile.wots, 3 * 34 * 255)
        self.assertEqual(profile.leaf, 3)
        self.assertEqual(profile.batch, 9)
        self.assertEqual(profile.multi, 5)

    def test_pair_sharing_one_parent(self):
        # Leaves {0, 2} of a height-2 tree:
        # level 1 parents {0, 1} -> 2; level 2 parent {0} -> 1.
        profile = merkle_verify_profile(4, 2, (0, 2))
        self.assertEqual((profile.batch, profile.multi), (4, 3))

    def test_echoes_parameters_and_all_heights(self):
        for w, per_leaf in ((4, 67 * 15), (8, 34 * 255)):
            for height in range(1, 9):
                indices = (0, (1 << height) - 1)
                profile = merkle_verify_profile(w, height, indices)
                self.assertEqual(profile.w, w)
                self.assertEqual(profile.height, height)
                self.assertEqual(profile.k, 2)
                self.assertEqual(profile.wots, 2 * per_leaf)
                self.assertEqual(profile.leaf, 2)
                self.assertEqual(profile.batch, 2 * height)
                expected_multi = sum(
                    len({index >> level for index in indices})
                    for level in range(1, height + 1)
                )
                self.assertEqual(profile.multi, expected_multi)

    def test_multi_never_exceeds_batch(self):
        for height in range(1, 9):
            leaf_count = 1 << height
            for k in range(1, leaf_count + 1):
                indices = tuple(range(0, leaf_count, leaf_count // k))[:k]
                profile = merkle_verify_profile(4, height, indices)
                self.assertLessEqual(profile.multi, profile.batch)

    def test_value_object_is_frozen_equal_and_hashable(self):
        first = merkle_verify_profile(4, 3, (0, 1, 6))
        # Positional construction in the documented seven-field order.
        positional = MerkleVerifyProfile(4, 3, 3, 3 * 67 * 15, 3, 9, 5)
        keyword = MerkleVerifyProfile(
            w=4, height=3, k=3, wots=3 * 67 * 15, leaf=3, batch=9, multi=5
        )
        self.assertEqual(first, positional)
        self.assertEqual(first, keyword)
        self.assertEqual(hash(first), hash(positional))
        self.assertEqual(
            {first, positional, keyword},
            {MerkleVerifyProfile(4, 3, 3, 3 * 67 * 15, 3, 9, 5)},
        )
        self.assertNotEqual(
            first, merkle_verify_profile(8, 3, (0, 1, 6))
        )
        self.assertIsInstance(first.w, int)
        for field in ("height", "k", "wots", "leaf", "batch", "multi"):
            self.assertIsInstance(getattr(first, field), int)
        with self.assertRaises(FrozenInstanceError):
            first.multi = 4

    def test_non_tuple_indices_type_error(self):
        for bad in ([0, 1], {0, 1}, (i for i in (0, 1))):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_verify_profile(4, 3, bad)

    def test_non_integer_member_type_error(self):
        for bad in ((0, "1"), (0, 1.0), (0, None), (0, object())):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    merkle_verify_profile(4, 3, bad)

    def test_empty_indices_value_error(self):
        with self.assertRaises(ValueError):
            merkle_verify_profile(4, 3, ())

    def test_boolean_member_value_error(self):
        for bad in ((False,), (True,), (0, False), (0, True)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_verify_profile(4, 3, bad)

    def test_out_of_range_indices_value_error(self):
        for bad in ((-1,), (8,), (0, 8), (7, 9)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_verify_profile(4, 3, bad)

    def test_duplicate_or_unordered_value_error(self):
        for bad in ((1, 1), (0, 0), (3, 1), (5, 4, 6)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_verify_profile(4, 3, bad)

    def test_bad_w_value_error(self):
        for bad in (2, 3, 16, 0, -4, "4", 4.0, None, True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_verify_profile(bad, 3, (0,))

    def test_bad_height_value_error(self):
        for bad in (0, 9, -1, "3", 3.0, None, True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    merkle_verify_profile(4, bad, (0,))

    def test_function_is_pure(self):
        indices = (0, 1, 6)
        first = merkle_verify_profile(4, 3, indices)
        second = merkle_verify_profile(4, 3, indices)
        self.assertEqual(first, second)
        # The input tuple is untouched.
        self.assertEqual(indices, (0, 1, 6))


class MerkleVerifyProfileHashCountTest(unittest.TestCase):
    """Cross-check the profile against instrumented real verification."""

    def setUp(self):
        self.signer = MerkleSigner(w=4, height=3)
        messages = tuple(f"message-{index}".encode() for index in range(7))
        self.signatures = self.signer.sign_batch(messages)
        self.messages = messages
        self.original_node_hash = merkle_module._node_hash
        self.original_leaf_hash = merkle_module._leaf_hash
        self.original_chain_walk = merkle_module._chain_walk

    def tearDown(self):
        merkle_module._node_hash = self.original_node_hash
        merkle_module._leaf_hash = self.original_leaf_hash
        merkle_module._chain_walk = self.original_chain_walk

    def _instrument(self):
        counts = {"node": 0, "leaf": 0, "chain": 0}
        original_node_hash = self.original_node_hash
        original_leaf_hash = self.original_leaf_hash
        original_chain_walk = self.original_chain_walk

        def counting_node_hash(left, right):
            counts["node"] += 1
            return original_node_hash(left, right)

        def counting_leaf_hash(w, elements):
            counts["leaf"] += 1
            return original_leaf_hash(w, elements)

        def counting_chain_walk(element, steps):
            counts["chain"] += steps
            return original_chain_walk(element, steps)

        merkle_module._node_hash = counting_node_hash
        merkle_module._leaf_hash = counting_leaf_hash
        merkle_module._chain_walk = counting_chain_walk
        return counts

    def test_multiproof_hash_counts_match_profile(self):
        selected = (0, 1, 6)
        signatures = tuple(self.signatures[index] for index in selected)
        selected_messages = tuple(self.messages[index] for index in selected)
        proof = multiproof_encode(self.signer.public_key, signatures)
        profile = merkle_verify_profile(4, 3, selected)

        counts = self._instrument()
        self.assertTrue(multiproof_verify(selected_messages, proof))
        self.assertEqual(counts["node"], profile.multi)
        self.assertEqual(counts["leaf"], profile.leaf)
        self.assertLessEqual(counts["chain"], profile.wots)

    def test_batch_hash_counts_match_profile(self):
        selected = (0, 1, 6)
        signatures = tuple(self.signatures[index] for index in selected)
        selected_messages = tuple(self.messages[index] for index in selected)
        batch = MerkleBatchProof(
            public_key=self.signer.public_key, signatures=signatures
        )
        profile = merkle_verify_profile(4, 3, selected)

        counts = self._instrument()
        self.assertTrue(batch.verify(selected_messages))
        self.assertEqual(counts["node"], profile.batch)
        self.assertEqual(counts["leaf"], profile.leaf)
        self.assertLessEqual(counts["chain"], profile.wots)

    def test_full_tree_counts(self):
        signer = MerkleSigner(w=8, height=3)
        messages = tuple(f"m-{index}".encode() for index in range(8))
        signatures = signer.sign_batch(messages)
        proof = multiproof_encode(signer.public_key, signatures)
        indices = tuple(range(8))
        profile = merkle_verify_profile(8, 3, indices)

        counts = self._instrument()
        self.assertTrue(multiproof_verify(messages, proof))
        self.assertEqual(counts["node"], profile.multi)
        self.assertEqual(counts["node"], 7)
        self.assertEqual(counts["leaf"], 8)
        self.assertLessEqual(counts["chain"], profile.wots)


if __name__ == "__main__":
    unittest.main()

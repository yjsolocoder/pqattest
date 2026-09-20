import itertools
import unittest

from pqattest import (
    MerklePublicKey,
    MerkleSignature,
    MerkleSigner,
    merkle_verify,
    multiproof_encode,
    multiproof_verify,
)
from pqattest.merkle import (
    _MULTIPROOF_HEADER_BYTES,
    _MULTIPROOF_NODE_BYTES,
)

ELEMENT_BYTES = 32
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


def sign_all(signer, messages):
    return tuple(signer.sign(message) for message in messages)


def canonical_coordinates(indices, height):
    """Independent reference implementation of the canonical node rule."""
    current = set(indices)
    result = set()
    for level in range(height):
        for index in current:
            sibling = index ^ 1
            if sibling not in current:
                result.add((level, sibling))
        current = {index >> 1 for index in current}
    return result


def parse_blob(blob):
    """Split a multiproof blob into leaves and nodes for assertions."""
    key_length = int.from_bytes(blob[9:13], "big")
    leaf_count = int.from_bytes(blob[13:15], "big")
    node_count = int.from_bytes(blob[15:17], "big")
    offset = _MULTIPROOF_HEADER_BYTES
    public_key = MerklePublicKey.from_bytes(blob[offset : offset + key_length])
    offset += key_length
    leaves = []
    for _ in range(leaf_count):
        index = int.from_bytes(blob[offset : offset + 2], "big")
        count = int.from_bytes(blob[offset + 2 : offset + 4], "big")
        offset += 4
        elements = tuple(
            blob[offset + i * ELEMENT_BYTES : offset + (i + 1) * ELEMENT_BYTES]
            for i in range(count)
        )
        offset += count * ELEMENT_BYTES
        leaves.append((index, count, elements))
    nodes = []
    for _ in range(node_count):
        level = blob[offset]
        node_index = int.from_bytes(blob[offset + 1 : offset + 3], "big")
        node = blob[offset + 3 : offset + _MULTIPROOF_NODE_BYTES]
        offset += _MULTIPROOF_NODE_BYTES
        nodes.append((level, node_index, node))
    assert offset == len(blob)
    return public_key, leaves, nodes


class MultiproofFormatTest(unittest.TestCase):
    def test_layout_header(self):
        signer = make_signer(height=3, w=4)
        signatures = sign_all(signer, ("a", "b", "c"))
        blob = multiproof_encode(signer.public_key, signatures)
        self.assertIsInstance(blob, bytes)
        self.assertEqual(blob[:8], b"PQAMMUL\0")
        self.assertEqual(blob[8], 1)
        self.assertEqual(int.from_bytes(blob[9:13], "big"), PUBLIC_KEY_BYTES)
        self.assertEqual(int.from_bytes(blob[13:15], "big"), 3)
        self.assertEqual(
            blob[_MULTIPROOF_HEADER_BYTES : _MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES],
            signer.public_key.to_bytes(),
        )

    def test_total_length_formula(self):
        for w in (4, 8):
            for height in (1, 2, 4, 8):
                signer = make_signer(height=height, w=w)
                signatures = sign_all(signer, tuple(f"m{i}" for i in range(height + 1)))
                blob = multiproof_encode(signer.public_key, signatures)
                node_count = int.from_bytes(blob[15:17], "big")
                expected = (
                    _MULTIPROOF_HEADER_BYTES
                    + PUBLIC_KEY_BYTES
                    + len(signatures) * (4 + CHAINS[w] * ELEMENT_BYTES)
                    + node_count * _MULTIPROOF_NODE_BYTES
                )
                self.assertEqual(len(blob), expected, (w, height))

    def test_leaf_blocks_ascending_with_original_elements(self):
        signer = make_signer(height=3, w=8)
        messages = ("a", "b", "c")
        signatures = sign_all(signer, messages)
        blob = multiproof_encode(signer.public_key, signatures)
        _, leaves, _ = parse_blob(blob)
        self.assertEqual([leaf[0] for leaf in leaves], [0, 1, 2])
        for (index, count, elements), signature in zip(leaves, signatures):
            self.assertEqual(count, len(signature.wots_signature))
            self.assertEqual(elements, signature.wots_signature)

    def test_node_blocks_sorted_and_match_tree(self):
        height = 4
        signer = make_signer(height=height, w=4)
        messages = ("a", "b", "d", "e")
        signatures = sign_all(signer, messages)
        indices = tuple(signature.index for signature in signatures)
        blob = multiproof_encode(signer.public_key, signatures)
        _, _, nodes = parse_blob(blob)
        coordinates = [(level, index) for level, index, _ in nodes]
        self.assertEqual(coordinates, sorted(coordinates))
        self.assertEqual(
            set(coordinates), canonical_coordinates(indices, height)
        )
        for level, index, value in nodes:
            self.assertEqual(value, signer._layers[level][index])

    def test_deterministic(self):
        signer = make_signer(height=3)
        signatures = sign_all(signer, ("a", "b", "c"))
        self.assertEqual(
            multiproof_encode(signer.public_key, signatures),
            multiproof_encode(signer.public_key, signatures),
        )

    def test_dedup_saves_duplicated_path_nodes(self):
        from pqattest import MerkleBatchProof

        height = 4
        signer = make_signer(height=height)
        signatures = sign_all(signer, tuple(f"m{i}" for i in range(1 << height)))
        blob = multiproof_encode(signer.public_key, signatures)
        # Every leaf present: every sibling is derivable, so zero nodes ship.
        self.assertEqual(int.from_bytes(blob[15:17], "big"), 0)
        # The equivalent batch proof repeats a height-long path per leaf;
        # the multiproof must be strictly smaller.
        batch_blob = MerkleBatchProof(
            public_key=signer.public_key, signatures=signatures
        ).to_bytes()
        self.assertLess(len(blob), len(batch_blob))

    def test_single_leaf_carries_full_path(self):
        signer = make_signer(height=4)
        signature = signer.sign("a")
        blob = multiproof_encode(signer.public_key, (signature,))
        self.assertEqual(int.from_bytes(blob[15:17], "big"), 4)
        _, _, nodes = parse_blob(blob)
        self.assertEqual(
            [(level, index) for level, index, _ in nodes],
            [(level, (signature.index >> level) ^ 1) for level in range(4)],
        )


class MultiproofEncodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.signatures = sign_all(self.signer, ("a", "b"))

    def test_bad_public_key_type_raises_type_error(self):
        for bad in (None, 42, "key", b"raw", self.signatures, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    multiproof_encode(bad, self.signatures)

    def test_bad_signatures_container_raises_type_error(self):
        for bad in (None, 42, "sigs", [self.signatures[0]], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    multiproof_encode(self.signer.public_key, bad)

    def test_bad_signature_member_raises_type_error(self):
        for bad in (None, 42, "sig", b"raw", self.signer.public_key, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    multiproof_encode(
                        self.signer.public_key, (self.signatures[0], bad)
                    )

    def test_empty_signatures_raise_value_error(self):
        with self.assertRaises(ValueError):
            multiproof_encode(self.signer.public_key, ())

    def test_non_increasing_indices_raise_value_error(self):
        first, second, third = sign_all(
            make_signer(height=3), ("a", "b", "c")
        )
        for bad in ((second, first), (first, first), (first, third, second)):
            with self.subTest(indices=tuple(s.index for s in bad)):
                with self.assertRaises(ValueError):
                    multiproof_encode(self.signer.public_key, bad)

    def test_parameter_mismatch_raises_value_error(self):
        own = make_signer(height=3, w=4)
        signature = own.sign("m")
        for other in (
            make_signer(height=3, w=8, start=1000),
            make_signer(height=4, w=4, start=2000),
        ):
            with self.subTest(other=other.public_key):
                with self.assertRaises(ValueError):
                    multiproof_encode(other.public_key, (signature,))

    def test_index_out_of_range_raises_value_error(self):
        signer = make_signer(height=1)
        good = signer.sign("m")
        out_of_range = MerkleSignature(
            index=2,
            wots_signature=good.wots_signature,
            auth_path=(b"\x11" * ELEMENT_BYTES,),
        )
        with self.assertRaises(ValueError):
            multiproof_encode(signer.public_key, (out_of_range,))

    def test_wrong_element_and_path_counts_raise_value_error(self):
        signature = self.signatures[0]
        bad_elements = MerkleSignature(
            index=signature.index,
            wots_signature=signature.wots_signature[:-1],
            auth_path=signature.auth_path,
        )
        with self.assertRaises(ValueError):
            multiproof_encode(self.signer.public_key, (bad_elements,))
        bad_path = MerkleSignature(
            index=signature.index,
            wots_signature=signature.wots_signature,
            auth_path=signature.auth_path[:-1],
        )
        with self.assertRaises(ValueError):
            multiproof_encode(self.signer.public_key, (bad_path,))

    def test_malformed_element_length_raises_value_error(self):
        signature = self.signatures[0]
        broken_elements = list(signature.wots_signature)
        broken_elements[0] = b"\x00" * (ELEMENT_BYTES - 1)
        # Bypass the frozen constructor, which would reject this itself.
        bad = object.__new__(MerkleSignature)
        object.__setattr__(bad, "index", signature.index)
        object.__setattr__(bad, "wots_signature", tuple(broken_elements))
        object.__setattr__(bad, "auth_path", signature.auth_path)
        with self.assertRaises(ValueError):
            multiproof_encode(self.signer.public_key, (bad,))

    def test_conflicting_auth_nodes_raise_value_error(self):
        # Leaves 0 and 1 share every external coordinate above level 0; take
        # one signature from each of two independent signers so the shared
        # nodes disagree.
        signer_a = make_signer(height=2, start=0)
        signer_b = make_signer(height=2, start=5000)
        first = signer_a.sign("a")    # leaf 0
        signer_b.sign("warm-up")      # spend leaf 0 on the second signer
        second = signer_b.sign("b")   # leaf 1, structurally compatible
        with self.assertRaises(ValueError):
            multiproof_encode(signer_a.public_key, (first, second))

    def test_foreign_signature_alone_encodes_but_fails_verification(self):
        signer_a = make_signer(start=0)
        signer_b = make_signer(start=9000)
        foreign = signer_a.sign("m")
        # No shared coordinate, so the encoder cannot detect the mix; the
        # cryptographic check at verification does.
        blob = multiproof_encode(signer_b.public_key, (foreign,))
        self.assertFalse(multiproof_verify(("m",), blob))


class MultiproofVerifySuccessTest(unittest.TestCase):
    def test_every_subset_of_small_trees(self):
        for w in (4, 8):
            for height in (1, 2, 3):
                signer = make_signer(height=height, w=w)
                leaf_count = 1 << height
                messages = tuple(f"m{i}" for i in range(leaf_count))
                signatures = sign_all(signer, messages)
                for size in range(1, leaf_count + 1):
                    for combo in itertools.combinations(range(leaf_count), size):
                        chosen = tuple(signatures[i] for i in combo)
                        chosen_messages = tuple(messages[i] for i in combo)
                        blob = multiproof_encode(signer.public_key, chosen)
                        self.assertTrue(
                            multiproof_verify(chosen_messages, blob),
                            (w, height, combo),
                        )

    def test_large_tree_selected_subsets(self):
        for w in (4, 8):
            signer = make_signer(height=4, w=w)
            leaf_count = 16
            messages = tuple(f"m{i}" for i in range(leaf_count))
            signatures = sign_all(signer, messages)
            combos = (
                (0,), (15,), (0, 15), (0, 1, 2, 3), (4, 9, 14),
                (0, 1, 14, 15), tuple(range(leaf_count)),
            )
            for combo in combos:
                chosen = tuple(signatures[i] for i in combo)
                chosen_messages = tuple(messages[i] for i in combo)
                blob = multiproof_encode(signer.public_key, chosen)
                self.assertTrue(
                    multiproof_verify(chosen_messages, blob), (w, combo)
                )
                self.assertTrue(
                    all(
                        merkle_verify(message, signature, signer.public_key)
                        for message, signature in zip(chosen_messages, chosen)
                    )
                )

    def test_message_types_and_bytearray_data(self):
        signer = make_signer(height=2)
        messages = ("str", b"bytes", bytearray(b"array"), "fourth")
        signatures = sign_all(signer, messages)
        blob = multiproof_encode(signer.public_key, signatures)
        self.assertTrue(multiproof_verify(messages, bytearray(blob)))
        self.assertTrue(multiproof_verify(tuple(messages), blob))

    def test_odd_indexed_and_sparse_leaves(self):
        signer = make_signer(height=4, w=8)
        all_signatures = sign_all(signer, tuple(f"m{i}" for i in range(16)))
        for combo in ((1,), (15,), (3, 7, 11), (0, 15), (2, 3, 14, 15)):
            chosen = tuple(all_signatures[i] for i in combo)
            messages = tuple(f"m{i}" for i in combo)
            blob = multiproof_encode(signer.public_key, chosen)
            self.assertTrue(multiproof_verify(messages, blob), combo)


class MultiproofVerifyFailureTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3)
        self.messages = ("a", "b", "c")
        self.signatures = sign_all(self.signer, self.messages)
        self.blob = multiproof_encode(self.signer.public_key, self.signatures)

    def test_bad_data_types_are_false(self):
        for bad in (None, 42, 4.5, "data", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(multiproof_verify(self.messages, bad))

    def test_bad_messages_types_are_false(self):
        for bad in (None, 42, 4.5, "abc", b"abc", list(self.messages), object()):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(multiproof_verify(bad, self.blob))

    def test_count_mismatch_is_false(self):
        self.assertFalse(multiproof_verify((), self.blob))
        self.assertFalse(multiproof_verify(self.messages[:-1], self.blob))
        self.assertFalse(multiproof_verify(self.messages + ("d",), self.blob))

    def test_illegal_message_member_is_false(self):
        for bad in (None, 42, 4.5, [1], object()):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(
                    multiproof_verify(("a", bad, "c"), self.blob)
                )

    def test_wrong_and_swapped_messages_are_false(self):
        self.assertFalse(multiproof_verify(("a", "b", "C"), self.blob))
        self.assertFalse(multiproof_verify(("b", "a", "c"), self.blob))

    def test_tampered_wots_element_is_false(self):
        broken = list(self.signatures[1].wots_signature)
        broken[0] = bytes(ELEMENT_BYTES)
        tampered_signature = MerkleSignature(
            index=self.signatures[1].index,
            wots_signature=tuple(broken),
            auth_path=self.signatures[1].auth_path,
        )
        blob = multiproof_encode(
            self.signer.public_key, (self.signatures[0], tampered_signature)
        )
        self.assertFalse(multiproof_verify(("a", "b"), blob))

    def test_tampered_node_byte_is_false(self):
        bad = bytearray(self.blob)
        bad[-1] ^= 0x01
        self.assertFalse(multiproof_verify(self.messages, bytes(bad)))


class MultiproofBlobValidationTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=3, w=4)
        self.messages = ("a", "b", "c")
        self.signatures = sign_all(self.signer, self.messages)
        self.blob = multiproof_encode(self.signer.public_key, self.signatures)
        self.node_count = int.from_bytes(self.blob[15:17], "big")

    def assert_invalid(self, blob):
        self.assertFalse(multiproof_verify(self.messages, bytes(blob)))

    def test_truncation_at_boundaries(self):
        key_end = _MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES
        leaf_block = 4 + 67 * ELEMENT_BYTES
        cuts = {
            0, 8, 9, 13, 15, 16, _MULTIPROOF_HEADER_BYTES,
            key_end, key_end + 1,
            key_end + leaf_block, key_end + 2 * leaf_block + 7,
            len(self.blob) - 1,
        }
        for cut in cuts:
            with self.subTest(cut=cut):
                self.assert_invalid(self.blob[:cut])

    def test_trailing_data(self):
        self.assert_invalid(self.blob + b"\x00")
        self.assert_invalid(self.blob + b"tail")

    def test_bad_magic(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        self.assert_invalid(bad)

    def test_bad_version(self):
        for version in (0, 2, 255):
            bad = bytearray(self.blob)
            bad[8] = version
            self.assert_invalid(bad)

    def test_zero_key_length_and_out_of_bounds(self):
        for length in (0, len(self.blob), 0xFFFFFFFF):
            bad = bytearray(self.blob)
            bad[9:13] = length.to_bytes(4, "big")
            self.assert_invalid(bad)

    def test_zero_leaf_count(self):
        bad = bytearray(self.blob)
        bad[13:15] = (0).to_bytes(2, "big")
        self.assert_invalid(bad)

    def test_leaf_count_exceeding_payload(self):
        bad = bytearray(self.blob)
        bad[13:15] = (4).to_bytes(2, "big")
        self.assert_invalid(bad)

    def test_node_count_too_large(self):
        bad = bytearray(self.blob)
        bad[15:17] = (self.node_count + 1).to_bytes(2, "big")
        self.assert_invalid(bad)

    def test_node_count_too_small_leaves_trailing_data(self):
        bad = bytearray(self.blob)
        bad[15:17] = (self.node_count - 1).to_bytes(2, "big")
        self.assert_invalid(bad)

    def test_nested_public_key_corrupted(self):
        for delta in (8, 9, 10):
            bad = bytearray(self.blob)
            bad[_MULTIPROOF_HEADER_BYTES + delta] ^= 0x01
            self.assert_invalid(bad)

    def test_leaf_index_out_of_range(self):
        offset = _MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES
        bad = bytearray(self.blob)
        bad[offset : offset + 2] = (1 << self.signer.public_key.height).to_bytes(
            2, "big"
        )
        self.assert_invalid(bad)

    def test_leaf_blocks_unordered_and_duplicate(self):
        first = _MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES
        block = 4 + 67 * ELEMENT_BYTES
        second = first + block
        bad = bytearray(self.blob)
        bad[first : first + 2], bad[second : second + 2] = (
            bad[second : second + 2],
            bad[first : first + 2],
        )
        self.assert_invalid(bad)
        duplicate = bytearray(self.blob)
        duplicate[second : second + 2] = duplicate[first : first + 2]
        self.assert_invalid(duplicate)

    def test_leaf_element_count_mismatch(self):
        offset = _MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES + 2
        bad = bytearray(self.blob)
        bad[offset : offset + 2] = (66).to_bytes(2, "big")
        self.assert_invalid(bad)

    def _node_section_start(self):
        key_end = _MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES
        return key_end + 3 * (4 + 67 * ELEMENT_BYTES)

    def test_node_level_out_of_range(self):
        start = self._node_section_start()
        bad = bytearray(self.blob)
        bad[start] = self.signer.public_key.height
        self.assert_invalid(bad)

    def test_nodes_duplicate(self):
        start = self._node_section_start()
        bad = bytearray(self.blob)
        second = start + _MULTIPROOF_NODE_BYTES
        bad[second : second + 3] = bad[start : start + 3]
        self.assert_invalid(bad)

    def test_nodes_unordered(self):
        start = self._node_section_start()
        bad = bytearray(self.blob)
        first_block = bytes(bad[start : start + _MULTIPROOF_NODE_BYTES])
        second_block = bytes(
            bad[start + _MULTIPROOF_NODE_BYTES : start + 2 * _MULTIPROOF_NODE_BYTES]
        )
        bad[start : start + 2 * _MULTIPROOF_NODE_BYTES] = (
            second_block + first_block
        )
        self.assert_invalid(bad)

    def test_non_canonical_node_coordinate(self):
        start = self._node_section_start()
        last = start + (self.node_count - 1) * _MULTIPROOF_NODE_BYTES
        bad = bytearray(self.blob)
        # A coordinate that the leaf set never needs.
        bad[last + 1 : last + 3] = (0x00FD).to_bytes(2, "big")
        self.assert_invalid(bad)

    def test_derivable_coordinate_is_non_canonical(self):
        signer = make_signer(height=3)
        signature = signer.sign("a")
        blob = bytearray(multiproof_encode(signer.public_key, (signature,)))
        # Single leaf 0 needs (0,1),(1,1),(2,1); (0,0) is the leaf itself and
        # must never appear as a proof node.
        start = _MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES + 4 + 67 * ELEMENT_BYTES
        blob[start + 1 : start + 3] = (0).to_bytes(2, "big")
        self.assertFalse(multiproof_verify(("a",), bytes(blob)))


if __name__ == "__main__":
    unittest.main()

import unittest

from pqattest import (
    MerkleSignature,
    MerkleSigner,
    merkle_verify,
    multiproof_encode,
    multiproof_verify,
)
from pqattest.merkle import (
    _LEAF_RECORD_BYTES,
    _MULTIPROOF_HEADER_BYTES,
    _NODE_RECORD_BYTES,
    _canonical_proof_nodes,
    ELEMENT_BYTES,
)


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=3, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def make_multiproof(height=3, w=4, start=0, messages=("m0", "m1", "m3")):
    signer = make_signer(height=height, w=w, start=start)
    signatures = tuple(signer.sign(message) for message in messages)
    blob = multiproof_encode(signer.public_key, signatures)
    return signer, signatures, blob


def multiproof_envelope(
    key_blob: bytes,
    leaves: tuple[tuple[int, int, bytes], ...],
    nodes: tuple[tuple[int, int, bytes], ...],
) -> bytes:
    parts = [
        b"PQAMMUL\0",
        bytes((1,)),
        len(key_blob).to_bytes(4, "big"),
        len(leaves).to_bytes(2, "big"),
        len(nodes).to_bytes(2, "big"),
        key_blob,
    ]
    for index, element_count, elements in leaves:
        parts.append(index.to_bytes(2, "big"))
        parts.append(element_count.to_bytes(2, "big"))
        parts.append(elements)
    for level, node_index, node_value in nodes:
        parts.append(bytes((level,)))
        parts.append(node_index.to_bytes(2, "big"))
        parts.append(node_value)
    return b"".join(parts)


def leaf_records(signer, signatures):
    chains = len(signatures[0].wots_signature)
    return tuple(
        (
            signature.index,
            chains,
            b"".join(signature.wots_signature),
        )
        for signature in signatures
    )


def canonical_node_records(signer, signatures):
    indices = tuple(signature.index for signature in signatures)
    coordinates = _canonical_proof_nodes(signer.public_key.height, indices)
    values = {}
    for signature in signatures:
        for level, node in enumerate(signature.auth_path):
            values[(level, (signature.index >> level) ^ 1)] = node
    return tuple((level, index, values[(level, index)]) for level, index in coordinates)


class CanonicalNodesTest(unittest.TestCase):
    def test_single_leaf_is_full_auth_path(self):
        for height in (1, 2, 5, 8):
            with self.subTest(height=height):
                self.assertEqual(
                    _canonical_proof_nodes(height, (0,)),
                    tuple((level, 1) for level in range(height)),
                )

    def test_all_leaves_need_no_nodes(self):
        self.assertEqual(_canonical_proof_nodes(3, (0, 1, 2, 3, 4, 5, 6, 7)), ())

    def test_adjacent_pair_dedups_level_zero(self):
        # Leaves 0 and 1 authenticate each other at level 0.
        self.assertEqual(
            _canonical_proof_nodes(3, (0, 1)),
            ((1, 1), (2, 1)),
        )

    def test_mixed_set(self):
        self.assertEqual(
            _canonical_proof_nodes(3, (0, 1, 3)),
            ((0, 2), (2, 1)),
        )

    def test_sorted_by_level_then_index(self):
        nodes = _canonical_proof_nodes(4, (0, 3, 5))
        self.assertEqual(nodes, tuple(sorted(nodes)))

    def test_every_signature_path_is_covered(self):
        for height in (1, 2, 3, 6):
            indices = tuple(i for i in range(1 << height) if i % 3 != 1)
            nodes = set(_canonical_proof_nodes(height, indices))
            current = set(indices)
            for level in range(height):
                for index in current:
                    sibling = index ^ 1
                    if sibling not in current:
                        self.assertIn((level, sibling), nodes)
                current = {index >> 1 for index in current}


class MultiproofEncodeTest(unittest.TestCase):
    def test_returns_bytes_and_deterministic(self):
        _, _, blob = make_multiproof()
        self.assertIsInstance(blob, bytes)
        signer, signatures, _ = make_multiproof()
        self.assertEqual(
            blob,
            multiproof_encode(signer.public_key, signatures),
        )

    def test_layout(self):
        signer, signatures, blob = make_multiproof()
        self.assertEqual(blob[:8], b"PQAMMUL\0")
        self.assertEqual(blob[8], 1)
        key_blob = signer.public_key.to_bytes()
        self.assertEqual(int.from_bytes(blob[9:13], "big"), len(key_blob))
        self.assertEqual(int.from_bytes(blob[13:15], "big"), len(signatures))
        nodes = canonical_node_records(signer, signatures)
        self.assertEqual(int.from_bytes(blob[15:17], "big"), len(nodes))

        offset = _MULTIPROOF_HEADER_BYTES
        self.assertEqual(blob[offset : offset + len(key_blob)], key_blob)
        offset += len(key_blob)
        for index, element_count, elements in leaf_records(signer, signatures):
            self.assertEqual(int.from_bytes(blob[offset : offset + 2], "big"), index)
            self.assertEqual(
                int.from_bytes(blob[offset + 2 : offset + 4], "big"), element_count
            )
            offset += _LEAF_RECORD_BYTES
            self.assertEqual(blob[offset : offset + len(elements)], elements)
            offset += len(elements)
        for level, node_index, node_value in nodes:
            self.assertEqual(blob[offset], level)
            self.assertEqual(
                int.from_bytes(blob[offset + 1 : offset + 3], "big"), node_index
            )
            self.assertEqual(
                blob[offset + 3 : offset + _NODE_RECORD_BYTES], node_value
            )
            offset += _NODE_RECORD_BYTES
        self.assertEqual(offset, len(blob))

    def test_length_formula(self):
        for w in (4, 8):
            for height in (1, 2, 3, 8):
                with self.subTest(w=w, height=height):
                    signer, signatures, blob = make_multiproof(
                        w=w,
                        height=height,
                        messages=tuple(f"m{i}" for i in range(min(5, 1 << height))),
                    )
                    chains = len(signatures[0].wots_signature)
                    node_count = len(
                        _canonical_proof_nodes(
                            height, tuple(s.index for s in signatures)
                        )
                    )
                    expected = (
                        _MULTIPROOF_HEADER_BYTES
                        + len(signer.public_key.to_bytes())
                        + len(signatures)
                        * (_LEAF_RECORD_BYTES + chains * ELEMENT_BYTES)
                        + node_count * _NODE_RECORD_BYTES
                    )
                    self.assertEqual(len(blob), expected)

    def test_all_leaves_have_zero_nodes(self):
        signer = make_signer(height=2)
        messages = ("a", "b", "c", "d")
        signatures = signer.sign_batch(messages)
        blob = multiproof_encode(signer.public_key, signatures)
        self.assertEqual(int.from_bytes(blob[15:17], "big"), 0)
        self.assertTrue(multiproof_verify(messages, blob))

    def test_nodes_are_deduplicated_against_batch(self):
        signer = make_signer(height=4)
        messages = tuple(f"m{i}" for i in range(8))
        signatures = signer.sign_batch(messages)
        blob = multiproof_encode(signer.public_key, signatures)
        node_count = int.from_bytes(blob[15:17], "big")
        # Eight consecutive leaves share every level-1+ sibling with a
        # co-signed leaf, so only level-0 boundary nodes remain at most.
        self.assertLessEqual(node_count, 2)

    def test_wrong_key_type_raises_type_error(self):
        _, signatures, _ = make_multiproof()
        for bad in (None, 42, "key", b"raw", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    multiproof_encode(bad, signatures)

    def test_wrong_signature_container_or_member_raises_type_error(self):
        signer = make_signer()
        signature = signer.sign("a")
        for bad in (None, 42, "sigs", b"raw", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    multiproof_encode(signer.public_key, bad)
        with self.assertRaises(TypeError):
            multiproof_encode(signer.public_key, [signature])
        for bad_member in (None, 42, "sig", signer.public_key, b"raw", object()):
            with self.subTest(bad=type(bad_member).__name__):
                with self.assertRaises(TypeError):
                    multiproof_encode(signer.public_key, (signature, bad_member))

    def test_empty_signatures_raise_value_error(self):
        signer = make_signer()
        with self.assertRaises(ValueError):
            multiproof_encode(signer.public_key, ())

    def test_non_increasing_indices_raise_value_error(self):
        signer = make_signer(height=2)
        first = signer.sign("a")
        second = signer.sign("b")
        third = signer.sign("c")
        for bad in ((second, first), (first, first), (first, third, second)):
            with self.subTest(indices=tuple(s.index for s in bad)):
                with self.assertRaises(ValueError):
                    multiproof_encode(signer.public_key, bad)

    def test_parameter_mismatch_raises_value_error(self):
        own = make_signer(w=4, height=2)
        for other in (
            make_signer(w=8, height=2, start=1000),
            make_signer(w=4, height=3, start=2000),
        ):
            with self.subTest(other=other.public_key):
                with self.assertRaises(ValueError):
                    multiproof_encode(other.public_key, (own.sign("m"),))

    def test_conflicting_auth_nodes_raise_value_error(self):
        signer = make_signer(height=3)
        s2 = signer.sign("m2")
        foreign = make_signer(height=3, start=9000)
        foreign_path = foreign.sign("x").auth_path
        # Index 0 signature whose level-1/2 auth nodes disagree with leaf 1's.
        tampered = MerkleSignature(
            index=0, wots_signature=s2.wots_signature, auth_path=foreign_path
        )
        good = signer.sign("m1")
        with self.assertRaises(ValueError):
            multiproof_encode(signer.public_key, (tampered, good))


class MultiproofVerifyRoundTripTest(unittest.TestCase):
    def test_round_trip_all_w_and_heights(self):
        for w in (4, 8):
            for height in (1, 2, 5, 8):
                with self.subTest(w=w, height=height):
                    messages = ("hi0", "hi2", b"bytes", bytearray(b"arr"))
                    messages = messages[: min(4, 1 << height)]
                    signer, signatures, blob = make_multiproof(
                        w=w, height=height, messages=messages
                    )
                    self.assertTrue(multiproof_verify(messages, blob))

    def test_accepts_bytearray(self):
        _, _, blob = make_multiproof()
        messages = ("m0", "m1", "m3")
        self.assertTrue(multiproof_verify(messages, bytearray(blob)))

    def test_matches_per_signature_merkle_verify(self):
        signer = make_signer(height=4, w=8)
        messages = tuple(f"message {i}" for i in range(6))
        signatures = signer.sign_batch(messages)
        blob = multiproof_encode(signer.public_key, signatures)
        self.assertTrue(multiproof_verify(messages, blob))
        for message, signature in zip(messages, signatures):
            self.assertTrue(merkle_verify(message, signature, signer.public_key))

    def test_standalone_transport(self):
        signer = make_signer(height=4)
        messages = (b"claim 0", b"claim 2", b"claim 5")
        signatures = (
            signer.sign(messages[0]),
            signer.sign(messages[1]),
            signer.sign(messages[2]),
        )
        blob = multiproof_encode(signer.public_key, signatures)
        self.assertTrue(multiproof_verify(messages, blob))
        self.assertFalse(multiproof_verify((b"claim 0", b"claim 2", b"other"), blob))

    def test_single_leaf(self):
        signer = make_signer(height=1)
        signature = signer.sign("only")
        blob = multiproof_encode(signer.public_key, (signature,))
        self.assertTrue(multiproof_verify(("only",), blob))


class MultiproofVerifyFailureTest(unittest.TestCase):
    def setUp(self):
        self.messages = ("m0", "m1", "m3")
        self.signer, self.signatures, self.blob = make_multiproof(
            messages=self.messages
        )

    def test_non_bytes_data_is_false(self):
        for bad in (None, 42, 4.5, "proof", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(multiproof_verify(self.messages, bad))

    def test_non_tuple_messages_is_false(self):
        for bad in (None, 42, 4.5, "m0m1", b"m0m1", list(self.messages), object()):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(multiproof_verify(bad, self.blob))

    def test_count_mismatch_is_false(self):
        self.assertFalse(multiproof_verify((), self.blob))
        self.assertFalse(multiproof_verify(self.messages[:-1], self.blob))
        self.assertFalse(multiproof_verify(self.messages + ("extra",), self.blob))

    def test_illegal_message_member_is_false(self):
        for bad_member in (None, 42, 4.5, [1, 2], object()):
            with self.subTest(bad=type(bad_member).__name__):
                self.assertFalse(
                    multiproof_verify(
                        ("m0", bad_member, "m3"), self.blob
                    )
                )

    def test_wrong_or_swapped_messages_fail(self):
        self.assertFalse(multiproof_verify(("m1", "m0", "m3"), self.blob))
        self.assertFalse(multiproof_verify(("x", "m1", "m3"), self.blob))

    def test_bad_magic(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        self.assertFalse(multiproof_verify(self.messages, bytes(bad)))

    def test_bad_version(self):
        for version in (0, 2, 255):
            bad = bytearray(self.blob)
            bad[8] = version
            self.assertFalse(multiproof_verify(self.messages, bytes(bad)))

    def test_zero_counts_fail(self):
        for field in (slice(9, 13), slice(13, 15)):
            bad = bytearray(self.blob)
            bad[field] = (0).to_bytes(4 if field == slice(9, 13) else 2, "big")
            self.assertFalse(multiproof_verify(self.messages, bytes(bad)))

    def test_truncation_and_trailing_fail(self):
        for cut in (0, 8, 9, 13, 15, 16, _MULTIPROOF_HEADER_BYTES, len(self.blob) - 1):
            with self.subTest(cut=cut):
                self.assertFalse(multiproof_verify(self.messages, self.blob[:cut]))
        self.assertFalse(multiproof_verify(self.messages, self.blob + b"\x00"))
        self.assertFalse(multiproof_verify(self.messages, self.blob + b"tail"))

    def test_key_length_out_of_bounds_fails(self):
        payload = len(self.blob) - _MULTIPROOF_HEADER_BYTES
        for length in (payload + 1, payload + 100, 0xFFFFFFFF):
            bad = bytearray(self.blob)
            bad[9:13] = length.to_bytes(4, "big")
            self.assertFalse(multiproof_verify(self.messages, bytes(bad)))

    def test_leaf_count_mismatch_fails(self):
        count = int.from_bytes(self.blob[13:15], "big")
        for value in (count - 1, count + 1):
            bad = bytearray(self.blob)
            bad[13:15] = value.to_bytes(2, "big")
            self.assertFalse(multiproof_verify(self.messages, bytes(bad)))

    def test_node_count_mismatch_fails(self):
        count = int.from_bytes(self.blob[15:17], "big")
        for value in (max(count - 1, 0), count + 1):
            bad = bytearray(self.blob)
            bad[15:17] = value.to_bytes(2, "big")
            self.assertFalse(multiproof_verify(self.messages, bytes(bad)))

    def test_duplicate_and_unordered_leaf_indices_fail(self):
        leaves = leaf_records(self.signer, self.signatures)
        nodes = canonical_node_records(self.signer, self.signatures)
        key_blob = self.signer.public_key.to_bytes()
        duplicated = (leaves[0], leaves[0])
        self.assertFalse(
            multiproof_verify(
                ("a", "b"),
                multiproof_envelope(
                    key_blob,
                    duplicated,
                    (),
                ),
            )
        )
        reordered = (leaves[1], leaves[0], leaves[2])
        self.assertFalse(
            multiproof_verify(
                self.messages,
                multiproof_envelope(key_blob, reordered, nodes),
            )
        )

    def test_index_out_of_tree_range_fails(self):
        leaves = leaf_records(self.signer, self.signatures)
        bad_leaves = ((self.signer.public_key.leaf_count, leaves[0][1], leaves[0][2]),)
        self.assertFalse(
            multiproof_verify(
                ("m",),
                multiproof_envelope(self.signer.public_key.to_bytes(), bad_leaves, ()),
            )
        )

    def test_wrong_element_count_fails(self):
        leaves = list(leaf_records(self.signer, self.signatures))
        index, count, elements = leaves[0]
        leaves[0] = (index, count + 1, elements)
        self.assertFalse(
            multiproof_verify(
                self.messages,
                multiproof_envelope(
                    self.signer.public_key.to_bytes(),
                    tuple(leaves),
                    canonical_node_records(self.signer, self.signatures),
                ),
            )
        )

    def test_extra_node_fails(self):
        nodes = list(canonical_node_records(self.signer, self.signatures))
        extra = (0, 5, b"\x01" * ELEMENT_BYTES)
        # Kept out of canonical order's way: insert a coordinate not required.
        self.assertFalse(
            multiproof_verify(
                self.messages,
                multiproof_envelope(
                    self.signer.public_key.to_bytes(),
                    leaf_records(self.signer, self.signatures),
                    tuple(sorted(nodes + [extra])),
                ),
            )
        )

    def test_missing_node_fails(self):
        nodes = canonical_node_records(self.signer, self.signatures)
        self.assertFalse(
            multiproof_verify(
                self.messages,
                multiproof_envelope(
                    self.signer.public_key.to_bytes(),
                    leaf_records(self.signer, self.signatures),
                    nodes[:-1],
                ),
            )
        )

    def test_reordered_nodes_fail(self):
        nodes = list(canonical_node_records(self.signer, self.signatures))
        if len(nodes) < 2:
            self.skipTest("need at least two nodes")
        reordered = tuple(nodes[1:] + nodes[:1])
        self.assertFalse(
            multiproof_verify(
                self.messages,
                multiproof_envelope(
                    self.signer.public_key.to_bytes(),
                    leaf_records(self.signer, self.signatures),
                    reordered,
                ),
            )
        )

    def test_node_level_out_of_range_fails(self):
        nodes = list(canonical_node_records(self.signer, self.signatures))
        level, index, value = nodes[0]
        nodes[0] = (self.signer.public_key.height, index, value)
        blob = multiproof_envelope(
            self.signer.public_key.to_bytes(),
            leaf_records(self.signer, self.signatures),
            tuple(nodes),
        )
        self.assertFalse(multiproof_verify(self.messages, blob))

    def test_node_index_out_of_range_fails(self):
        nodes = list(canonical_node_records(self.signer, self.signatures))
        level, index, value = nodes[0]
        nodes[0] = (level, 1 << (self.signer.public_key.height - level), value)
        blob = multiproof_envelope(
            self.signer.public_key.to_bytes(),
            leaf_records(self.signer, self.signatures),
            tuple(nodes),
        )
        self.assertFalse(multiproof_verify(self.messages, blob))

    def test_tampered_node_hash_fails(self):
        bad = bytearray(self.blob)
        bad[-1] ^= 0x01
        self.assertFalse(multiproof_verify(self.messages, bytes(bad)))

    def test_tampered_leaf_element_fails(self):
        bad = bytearray(self.blob)
        bad[_MULTIPROOF_HEADER_BYTES + 43 + _LEAF_RECORD_BYTES] ^= 0x01
        self.assertFalse(multiproof_verify(self.messages, bytes(bad)))

    def test_tampered_embedded_key_fails(self):
        for delta in (8, 9, 10):  # magic/version/w inside the nested key
            bad = bytearray(self.blob)
            bad[_MULTIPROOF_HEADER_BYTES + delta] ^= 0x01
            self.assertFalse(multiproof_verify(self.messages, bytes(bad)))


if __name__ == "__main__":
    unittest.main()

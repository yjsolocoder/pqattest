"""Fixed-byte compatibility regression tests for the Merkle multiproof v1 format.

These tests pin the on-wire v1 multiproof encoding (``multiproof_encode``,
magic ``b"PQAMMUL\\0"``, version 1) to checked-in golden bytes under
``tests/fixtures/multiproof_compat`` (see that directory's README). The
golden samples were produced once from documented, public, deterministic
inputs and are only ever read here: they are never regenerated through the
encoder under test, and verification runs against the frozen files
directly rather than against a freshly re-encoded copy, so a future change
that alters the established format even while the in-tree encoder and
verifier move together is still caught.

Coverage for each of ``w=4`` and ``w=8``, tree height 3 (eight leaves):

* ``single`` — one sparse leaf, index 5, no context; the lone leaf carries
  its complete height-long authentication path (three external nodes);
* ``sparse`` — leaves ``(0, 1, 4)`` signed under the non-empty context
  ``b"compat-multiproof-context"``; the sibling pair 0/1 and the shared
  upper path exercise node deduplication (three canonical nodes instead
  of separate full paths);
* ``all`` — all eight leaves, no context; every sibling is derivable, so
  the proof ships zero external nodes.

For every sample the tests pin:

* encoder byte-for-byte equality with the frozen file, over signatures
  produced through the public ``MerkleSigner`` entries from the documented
  deterministic key input;
* direct ``multiproof_verify`` of the frozen bytes (bytes and bytearray
  alike), without re-encoding, including all context variants;
* ``multiproof_verify_bound`` against the expected key and leaf set, an
  equal-value second public-key instance, and rejection of other keys or
  different leaf sets;
* the rejection boundaries: reordered/changed messages, modified
  signature elements or authentication nodes, a broken canonical node
  order, truncation and trailing bytes;
* the documented type behaviour: bad context or bound-argument types
  raise ``TypeError``, while boolean indices return ``False``.

Nothing here changes any public entry or signature algorithm; only the
standard library is used.
"""

import os
import unittest

from pqattest import (
    MerklePublicKey,
    MerkleSigner,
    multiproof_encode,
    multiproof_verify,
    multiproof_verify_bound,
)
from pqattest.merkle import (
    _MULTIPROOF_HEADER_BYTES,
    _MULTIPROOF_NODE_BYTES,
)

FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "fixtures", "multiproof_compat"
)

# Documented sample parameters (see fixtures/multiproof_compat/README.md).
HEIGHT = 3
CONTEXT = b"compat-multiproof-context"

SINGLE_INDICES = (5,)
SINGLE_MESSAGES = (b"compat-multiproof-single",)
SINGLE_CONTEXT = None

SPARSE_INDICES = (0, 1, 4)
SPARSE_MESSAGES = (
    b"compat-multiproof-sparse-00",
    b"compat-multiproof-sparse-01",
    b"compat-multiproof-sparse-04",
)
SPARSE_CONTEXT = CONTEXT

ALL_INDICES = tuple(range(8))
ALL_MESSAGES = tuple(f"compat-multiproof-all-{i:02d}".encode() for i in range(8))
ALL_CONTEXT = None

SAMPLES = ("single", "sparse", "all")

# Documented v1 multiproof layout constants.
PUBLIC_KEY_BYTES = 43
ELEMENT_BYTES = 32


def counter_tokens(start: int = 0):
    """Deterministic, public key input shared by the frozen samples.

    The Nth call returns N as 8-byte big-endian zero-padded to 32 bytes,
    consumed in leaf then chain order; same rule as the merkle_compat
    fixtures. These are public, non-secret test values.
    """
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def fixture(w: int, name: str) -> bytes:
    with open(os.path.join(FIXTURE_DIR, f"w{w}", f"{name}.bin"), "rb") as handle:
        return handle.read()


def sample_spec(name: str):
    """Return ``(indices, messages, context)`` for a named sample."""
    if name == "single":
        return SINGLE_INDICES, SINGLE_MESSAGES, SINGLE_CONTEXT
    if name == "sparse":
        return SPARSE_INDICES, SPARSE_MESSAGES, SPARSE_CONTEXT
    return ALL_INDICES, ALL_MESSAGES, ALL_CONTEXT


def build_signatures(w: int, name: str):
    """Reproduce the sample signatures through public ``MerkleSigner`` entries.

    Used only by the encode-side regression: the verifier-side tests take
    the frozen files untouched. A fresh signer over the documented
    deterministic key input is built per sample.
    """
    indices, messages, context = sample_spec(name)
    signer = MerkleSigner(height=HEIGHT, w=w, token_bytes=counter_tokens())
    if name == "all":
        signatures = signer.sign_batch(messages, context=context)
    else:
        signatures = signer.sign_selected(
            indices, messages, context=context
        )
    return signer, signatures


def parse_layout(blob: bytes) -> dict:
    """Split a frozen multiproof into documented v1 offsets without verifying.

    Returns the embedded public key and the byte ranges of the leaf blocks
    and canonical node blocks, so tamper tests can target specific
    documented regions. This only reads the frozen bytes; it never invokes
    the encoder.
    """
    key_length = int.from_bytes(blob[9:13], "big")
    leaf_count = int.from_bytes(blob[13:15], "big")
    node_count = int.from_bytes(blob[15:17], "big")
    public_key = MerklePublicKey.from_bytes(
        blob[_MULTIPROOF_HEADER_BYTES : _MULTIPROOF_HEADER_BYTES + key_length]
    )
    offset = _MULTIPROOF_HEADER_BYTES + key_length
    leaves = []
    for _ in range(leaf_count):
        start = offset
        index = int.from_bytes(blob[offset : offset + 2], "big")
        count = int.from_bytes(blob[offset + 2 : offset + 4], "big")
        data_start = offset + 4
        end = data_start + count * ELEMENT_BYTES
        leaves.append(
            {
                "index": index,
                "count": count,
                "start": start,
                "data_start": data_start,
                "end": end,
            }
        )
        offset = end
    node_start = offset
    nodes = [
        {
            "start": node_start + i * _MULTIPROOF_NODE_BYTES,
            "level": blob[node_start + i * _MULTIPROOF_NODE_BYTES],
            "index": int.from_bytes(
                blob[
                    node_start
                    + i * _MULTIPROOF_NODE_BYTES
                    + 1 : node_start
                    + i * _MULTIPROOF_NODE_BYTES
                    + 3
                ],
                "big",
            ),
        }
        for i in range(node_count)
    ]
    end = node_start + node_count * _MULTIPROOF_NODE_BYTES
    assert end == len(blob)
    return {
        "public_key": public_key,
        "key_length": key_length,
        "leaf_count": leaf_count,
        "node_count": node_count,
        "leaves": leaves,
        "node_start": node_start,
        "nodes": nodes,
    }


class MultiproofCompatEncodeTest(unittest.TestCase):
    def test_encoder_output_is_byte_for_byte_the_frozen_sample(self):
        for w in (4, 8):
            for name in SAMPLES:
                with self.subTest(w=w, sample=name):
                    frozen = fixture(w, name)
                    signer, signatures = build_signatures(w, name)
                    # The current encoder over the documented inputs must
                    # reproduce the frozen v1 bytes exactly.
                    encoded = multiproof_encode(signer.public_key, signatures)
                    self.assertEqual(encoded, frozen)
                    self.assertIsInstance(encoded, bytes)

    def test_frozen_header_and_shape_match_documented_layout(self):
        expected_nodes = {
            "single": [(0, 4), (1, 3), (2, 0)],
            "sparse": [(0, 5), (1, 1), (1, 3)],
            "all": [],
        }
        for w in (4, 8):
            for name in SAMPLES:
                with self.subTest(w=w, sample=name):
                    blob = fixture(w, name)
                    self.assertEqual(blob[:8], b"PQAMMUL\0")
                    self.assertEqual(blob[8], 1)
                    self.assertEqual(
                        int.from_bytes(blob[9:13], "big"), PUBLIC_KEY_BYTES
                    )
                    layout = parse_layout(blob)
                    indices, _, _ = sample_spec(name)
                    self.assertEqual(layout["public_key"].w, w)
                    self.assertEqual(layout["public_key"].height, HEIGHT)
                    self.assertEqual(
                        [leaf["index"] for leaf in layout["leaves"]],
                        list(indices),
                    )
                    coordinates = [
                        (node["level"], node["index"]) for node in layout["nodes"]
                    ]
                    self.assertEqual(coordinates, expected_nodes[name])


class MultiproofCompatVerifyTest(unittest.TestCase):
    def test_frozen_bytes_verify_directly_without_re_encoding(self):
        for w in (4, 8):
            for name in SAMPLES:
                indices, messages, context = sample_spec(name)
                with self.subTest(w=w, sample=name):
                    blob = fixture(w, name)
                    # Hand the frozen file straight to the verifier; it must
                    # never be rebuilt through multiproof_encode first.
                    self.assertTrue(
                        multiproof_verify(
                            messages, blob, context=context
                        )
                    )
                    self.assertTrue(
                        multiproof_verify(
                            messages, bytearray(blob), context=context
                        )
                    )

    def test_bytes_and_bytearray_agree_on_valid_and_tampered_inputs(self):
        for w in (4, 8):
            for name in SAMPLES:
                indices, messages, context = sample_spec(name)
                with self.subTest(w=w, sample=name):
                    blob = fixture(w, name)
                    tampered = bytearray(blob)
                    tampered[-1] ^= 0x01
                    for data in (blob, bytes(tampered)):
                        as_bytes = multiproof_verify(
                            messages, bytes(data), context=context
                        )
                        as_array = multiproof_verify(
                            messages, bytearray(data), context=context
                        )
                        self.assertEqual(as_bytes, as_array)
                    self.assertTrue(
                        multiproof_verify(messages, blob, context=context)
                    )
                    self.assertFalse(
                        multiproof_verify(
                            messages, bytes(tampered), context=context
                        )
                    )


class MultiproofCompatBoundTest(unittest.TestCase):
    def test_bound_to_expected_key_and_equal_value_instance(self):
        for w in (4, 8):
            for name in SAMPLES:
                indices, messages, context = sample_spec(name)
                with self.subTest(w=w, sample=name):
                    blob = fixture(w, name)
                    public_key = parse_layout(blob)["public_key"]
                    # An independently constructed, equal-value instance.
                    equal_value_key = MerklePublicKey(
                        w=public_key.w,
                        height=public_key.height,
                        root=public_key.root,
                    )
                    self.assertIsNot(equal_value_key, public_key)
                    self.assertEqual(equal_value_key, public_key)
                    for key in (public_key, equal_value_key):
                        self.assertTrue(
                            multiproof_verify_bound(
                                messages,
                                blob,
                                public_key=key,
                                indices=indices,
                                context=context,
                            )
                        )
                        # indices=None imposes no leaf-set constraint.
                        self.assertTrue(
                            multiproof_verify_bound(
                                messages,
                                blob,
                                public_key=key,
                                context=context,
                            )
                        )

    def test_other_public_key_is_rejected(self):
        for w in (4, 8):
            other_w = 8 if w == 4 else 4
            for name in SAMPLES:
                indices, messages, context = sample_spec(name)
                with self.subTest(w=w, sample=name):
                    blob = fixture(w, name)
                    own_key = parse_layout(blob)["public_key"]
                    # Same w/height, unrelated root.
                    wrong_root = MerklePublicKey(
                        w=w, height=HEIGHT, root=b"\x00" * ELEMENT_BYTES
                    )
                    # The other parameter set's frozen key (different root).
                    other_key = parse_layout(fixture(other_w, name))["public_key"]
                    for wrong_key in (wrong_root, other_key):
                        self.assertFalse(
                            multiproof_verify_bound(
                                messages,
                                blob,
                                public_key=wrong_key,
                                indices=indices,
                                context=context,
                            )
                        )
                    self.assertTrue(
                        multiproof_verify_bound(
                            messages,
                            blob,
                            public_key=own_key,
                            indices=indices,
                            context=context,
                        )
                    )

    def test_different_leaf_sets_are_rejected(self):
        alternative_sets = {
            "single": ((4,), (0,), (5, 6)),
            "sparse": ((0, 1, 5), (0, 4, 1), (1, 4, 5), (0, 1), (0, 1, 4, 5)),
            "all": (
                tuple(range(1, 8)) + (8,),  # strictly increasing but out of range
                (0, 1, 2, 3, 4, 5, 7, 6),   # reordered/duplicate-free but unsorted
                tuple(range(7)),            # wrong count
                (0, 1, 2, 3, 4, 5, 6, 9),   # one out-of-range index
            ),
        }
        for w in (4, 8):
            for name in SAMPLES:
                indices, messages, context = sample_spec(name)
                blob = fixture(w, name)
                public_key = parse_layout(blob)["public_key"]
                for wrong_indices in alternative_sets[name]:
                    with self.subTest(
                        w=w, sample=name, wrong=wrong_indices
                    ):
                        self.assertFalse(
                            multiproof_verify_bound(
                                messages,
                                blob,
                                public_key=public_key,
                                indices=wrong_indices,
                                context=context,
                            )
                        )

    def test_bound_bad_public_key_type_raises_type_error(self):
        for w in (4, 8):
            for name in SAMPLES:
                indices, messages, context = sample_spec(name)
                blob = fixture(w, name)
                for bad in (None, 42, "key", b"raw", object()):
                    with self.subTest(w=w, sample=name, bad=type(bad).__name__):
                        with self.assertRaises(TypeError):
                            multiproof_verify_bound(
                                messages,
                                blob,
                                public_key=bad,
                                indices=indices,
                                context=context,
                            )

    def test_bound_bad_indices_type_raises_type_error(self):
        for w in (4, 8):
            for name in SAMPLES:
                indices, messages, context = sample_spec(name)
                blob = fixture(w, name)
                public_key = parse_layout(blob)["public_key"]
                # A non-tuple container, and tuples with a non-integer member.
                bad_sets = [
                    list(indices),
                    tuple(range(len(indices) - 1)) + (1.0,),
                    tuple(range(len(indices) - 1)) + (None,),
                    tuple(range(len(indices) - 1)) + ("5",),
                ]
                for bad in bad_sets:
                    with self.subTest(w=w, sample=name, bad=repr(bad)):
                        with self.assertRaises(TypeError):
                            multiproof_verify_bound(
                                messages,
                                blob,
                                public_key=public_key,
                                indices=bad,
                                context=context,
                            )

    def test_boolean_indices_return_false(self):
        boolean_sets = {
            "single": ((True,), (False,)),
            "sparse": ((False, 1, 4), (0, True, 4), (0, 1, True)),
            "all": tuple(
                [
                    tuple(True if j == i else j for j in range(8))
                    for i in range(8)
                ]
            ),
        }
        for w in (4, 8):
            for name in SAMPLES:
                indices, messages, context = sample_spec(name)
                blob = fixture(w, name)
                public_key = parse_layout(blob)["public_key"]
                for bad in boolean_sets[name]:
                    with self.subTest(w=w, sample=name, bad=repr(bad)):
                        self.assertFalse(
                            multiproof_verify_bound(
                                messages,
                                blob,
                                public_key=public_key,
                                indices=bad,
                                context=context,
                            )
                        )


class MultiproofCompatContextTest(unittest.TestCase):
    def test_no_context_samples_verify_when_context_omitted_none_or_empty(self):
        for w in (4, 8):
            for name in ("single", "all"):
                indices, messages, _ = sample_spec(name)
                blob = fixture(w, name)
                public_key = parse_layout(blob)["public_key"]
                for supplied in (
                    lambda: multiproof_verify(messages, blob),
                    lambda: multiproof_verify(messages, blob, context=None),
                    lambda: multiproof_verify(messages, blob, context=b""),
                    lambda: multiproof_verify(
                        messages, blob, context=bytearray(b"")
                    ),
                    lambda: multiproof_verify(messages, blob, context=""),
                ):
                    with self.subTest(w=w, sample=name):
                        self.assertTrue(supplied())
                # Supplying a non-empty context breaks the unbound samples.
                self.assertFalse(
                    multiproof_verify(messages, blob, context=CONTEXT)
                )
                self.assertFalse(
                    multiproof_verify_bound(
                        messages,
                        blob,
                        public_key=public_key,
                        indices=indices,
                        context=CONTEXT,
                    )
                )

    def test_context_sample_verifies_only_with_the_same_context(self):
        equivalents = (CONTEXT, bytearray(CONTEXT), CONTEXT.decode("ascii"))
        for w in (4, 8):
            blob = fixture(w, "sparse")
            public_key = parse_layout(blob)["public_key"]
            for context in equivalents:
                with self.subTest(w=w, context=type(context).__name__):
                    self.assertTrue(
                        multiproof_verify(
                            SPARSE_MESSAGES, blob, context=context
                        )
                    )
                    self.assertTrue(
                        multiproof_verify_bound(
                            SPARSE_MESSAGES,
                            blob,
                            public_key=public_key,
                            indices=SPARSE_INDICES,
                            context=context,
                        )
                    )
            # Omitted, None and empty all mean "no context" and must fail.
            for absent in (
                    lambda: multiproof_verify(SPARSE_MESSAGES, blob),
                    lambda: multiproof_verify(
                        SPARSE_MESSAGES, blob, context=None
                    ),
                    lambda: multiproof_verify(
                        SPARSE_MESSAGES, blob, context=b""
                    ),
                    lambda: multiproof_verify(
                        SPARSE_MESSAGES, blob, context=""
                    ),
            ):
                self.assertFalse(absent())
            # A different non-empty context fails.
            self.assertFalse(
                multiproof_verify(
                    SPARSE_MESSAGES, blob, context=b"compat-multiproof-other"
                )
            )

    def test_bad_context_type_raises_type_error(self):
        for w in (4, 8):
            for name in SAMPLES:
                indices, messages, _ = sample_spec(name)
                blob = fixture(w, name)
                public_key = parse_layout(blob)["public_key"]
                for bad in (42, 4.5, [CONTEXT], object()):
                    with self.subTest(w=w, sample=name, bad=type(bad).__name__):
                        with self.assertRaises(TypeError):
                            multiproof_verify(messages, blob, context=bad)
                        with self.assertRaises(TypeError):
                            multiproof_verify_bound(
                                messages,
                                blob,
                                public_key=public_key,
                                indices=indices,
                                context=bad,
                            )


class MultiproofCompatRejectionTest(unittest.TestCase):
    def test_reordered_or_changed_messages_are_false(self):
        swapped = {
            "single": (b"compat-multiproof-single-changed",),
            "sparse": (
                SPARSE_MESSAGES[1],
                SPARSE_MESSAGES[0],
                SPARSE_MESSAGES[2],
            ),
            "all": (
                ALL_MESSAGES[1],
                ALL_MESSAGES[0],
                *ALL_MESSAGES[2:],
            ),
        }
        for w in (4, 8):
            for name in SAMPLES:
                _, messages, context = sample_spec(name)
                blob = fixture(w, name)
                with self.subTest(w=w, sample=name, kind="reordered_or_changed"):
                    self.assertFalse(
                        multiproof_verify(
                            swapped[name], blob, context=context
                        )
                    )
                    self.assertTrue(
                        multiproof_verify(
                            messages, blob, context=context
                        )
                    )

    def test_modified_signature_element_is_false(self):
        for w in (4, 8):
            for name in SAMPLES:
                _, messages, context = sample_spec(name)
                blob = fixture(w, name)
                layout = parse_layout(blob)
                target = layout["leaves"][0]["data_start"]
                bad = bytearray(blob)
                bad[target] ^= 0x01
                with self.subTest(w=w, sample=name):
                    self.assertFalse(
                        multiproof_verify(
                            messages, bytes(bad), context=context
                        )
                    )
                    self.assertFalse(
                        multiproof_verify(
                            messages, bytearray(bad), context=context
                        )
                    )

    def test_modified_authentication_node_is_false(self):
        for w in (4, 8):
            for name in ("single", "sparse"):
                _, messages, context = sample_spec(name)
                blob = fixture(w, name)
                layout = parse_layout(blob)
                # Flip a byte inside the first carried node's 32-byte hash.
                target = layout["nodes"][0]["start"] + 3
                bad = bytearray(blob)
                bad[target] ^= 0x01
                with self.subTest(w=w, sample=name):
                    self.assertFalse(
                        multiproof_verify(
                            messages, bytes(bad), context=context
                        )
                    )

    def test_broken_canonical_node_order_is_false(self):
        for w in (4, 8):
            for name in ("single", "sparse"):
                _, messages, context = sample_spec(name)
                blob = fixture(w, name)
                layout = parse_layout(blob)
                # Swap the first two canonical node blocks; the coordinates
                # then arrive out of (level, index) order.
                first = layout["nodes"][0]["start"]
                second = layout["nodes"][1]["start"]
                bad = bytearray(blob)
                bad[first : first + _MULTIPROOF_NODE_BYTES] = blob[
                    second : second + _MULTIPROOF_NODE_BYTES
                ]
                bad[second : second + _MULTIPROOF_NODE_BYTES] = blob[
                    first : first + _MULTIPROOF_NODE_BYTES
                ]
                with self.subTest(w=w, sample=name, kind="swapped_nodes"):
                    self.assertFalse(
                        multiproof_verify(
                            messages, bytes(bad), context=context
                        )
                    )
                # Duplicate the first node's coordinate: the carried set no
                # longer equals the canonical set and ordering is violated.
                duplicate = bytearray(blob)
                duplicate[
                    second : second + 3
                ] = duplicate[first : first + 3]
                with self.subTest(w=w, sample=name, kind="duplicate_node"):
                    self.assertFalse(
                        multiproof_verify(
                            messages, bytes(duplicate), context=context
                        )
                    )

    def test_truncation_is_false(self):
        for w in (4, 8):
            for name in SAMPLES:
                _, messages, context = sample_spec(name)
                blob = fixture(w, name)
                for cut in (0, 8, _MULTIPROOF_HEADER_BYTES, len(blob) - 1):
                    with self.subTest(w=w, sample=name, cut=cut):
                        self.assertFalse(
                            multiproof_verify(
                                messages, blob[:cut], context=context
                            )
                        )
                        self.assertEqual(
                            multiproof_verify(
                                messages, blob[:cut], context=context
                            ),
                            multiproof_verify(
                                messages,
                                bytearray(blob[:cut]),
                                context=context,
                            ),
                        )

    def test_trailing_bytes_are_false(self):
        for w in (4, 8):
            for name in SAMPLES:
                _, messages, context = sample_spec(name)
                blob = fixture(w, name)
                for suffix in (b"\x00", b"tail"):
                    with self.subTest(w=w, sample=name, suffix=suffix):
                        extended = blob + suffix
                        self.assertFalse(
                            multiproof_verify(
                                messages, extended, context=context
                            )
                        )
                        self.assertEqual(
                            multiproof_verify(
                                messages, extended, context=context
                            ),
                            multiproof_verify(
                                messages,
                                bytearray(extended),
                                context=context,
                            ),
                        )


if __name__ == "__main__":
    unittest.main()

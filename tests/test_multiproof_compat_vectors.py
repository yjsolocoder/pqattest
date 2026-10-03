"""Fixed-byte compatibility regression tests for the multiproof v1 format.

These tests pin the on-disk v1 encoding of :func:`multiproof_encode` to
checked-in golden bytes (see ``tests/fixtures/multiproof_compat/README.md``).
The golden samples were produced once from documented deterministic inputs
and are only ever read here: they are never regenerated through the encoder
under test, and the assertions are byte-for-byte comparisons against the
samples rather than length checks or same-version generate-then-verify
round trips. Feeding the frozen bytes straight to ``multiproof_verify``
must succeed, so a future change that alters the v1 byte meaning on either
the encoding or the verification side alone is caught even when both sides
are changed together.

Coverage for each of ``w=4`` and ``w=8`` (tree height 2, four leaves), all
from public, non-secret deterministic inputs:

* ``single_leaf`` — indices ``(0,)``, no context: the full authentication
  path (exactly ``height`` sibling nodes);
* ``sparse_leaves`` — indices ``(0, 1)``, no context: the shared level-1
  sibling is deduplicated to a single proof node;
* ``all_leaves`` — indices ``(0, 1, 2, 3)``, no context: every sibling is
  derivable, so zero external nodes are carried;
* ``context_leaf`` — indices ``(0,)`` under the non-empty context
  ``b"multiproof-compat-context"``.

Each sample is re-produced through the public ``MerkleSigner.sign`` /
``multiproof_encode`` entries and compared byte for byte; the frozen bytes
are also verified directly, bound via ``multiproof_verify_bound`` to the
expected key and leaf set, and exercised against the documented rejection
boundaries (swapped message order, tampered signature elements or nodes,
non-canonical node order, truncation, trailing data, ``bytes`` vs
``bytearray`` equivalence, context rules and ``verify_bound`` type rules).
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

HEIGHT = 2
LEAF_COUNT = 1 << HEIGHT
ELEMENT_BYTES = 32
PUBLIC_KEY_BYTES = 43
CHAINS = {4: 67, 8: 34}

# Public, non-secret sample inputs (see fixtures README). The Nth message
# is signed on leaf index N-1 by a fresh signer per sample.
MESSAGES = (
    b"multiproof-compat-message-zero",
    b"multiproof-compat-message-one",
    b"multiproof-compat-message-two",
    b"multiproof-compat-message-three",
)
CONTEXT = b"multiproof-compat-context"
# A fixed context no sample was ever signed under.
CONTEXT_OTHER = b"multiproof-compat-context-other"

# name -> (leaf indices, signing context, expected deduplicated node count)
SAMPLES = {
    "single_leaf": ((0,), None, 2),
    "sparse_leaves": ((0, 1), None, 1),
    "all_leaves": ((0, 1, 2, 3), None, 0),
    "context_leaf": ((0,), CONTEXT, 2),
}


def counter_tokens(start: int = 0):
    """Deterministic key input shared by the frozen samples.

    The Nth call returns N as 8-byte big-endian zero-padded to 32 bytes, so
    every W-OTS chain start of every leaf is a public, repeatable value.
    """
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(w: int, start: int = 0) -> MerkleSigner:
    return MerkleSigner(height=HEIGHT, w=w, token_bytes=counter_tokens(start))


def fixture(w: int, name: str) -> bytes:
    with open(os.path.join(FIXTURE_DIR, f"w{w}", name + ".bin"), "rb") as handle:
        return handle.read()


def sample_messages(name: str) -> tuple:
    indices, _, _ = SAMPLES[name]
    return MESSAGES[: len(indices)]


def sample_signatures(w: int, name: str):
    """Reproduce the sample through the public signing entry points."""
    indices, context, _ = SAMPLES[name]
    signer = make_signer(w)
    messages = MESSAGES[: len(indices)]
    signatures = tuple(
        signer.sign(message, context=context) for message in messages
    )
    return signer, messages, signatures


def leaf_block_bytes(w: int) -> int:
    return 4 + CHAINS[w] * ELEMENT_BYTES


def node_section_offset(w: int, leaf_count: int) -> int:
    return (
        _MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES + leaf_count * leaf_block_bytes(w)
    )


class MultiproofCompatEncodeTest(unittest.TestCase):
    def test_frozen_samples_reencode_byte_for_byte(self):
        for w in (4, 8):
            for name in SAMPLES:
                with self.subTest(w=w, sample=name):
                    signer, _, signatures = sample_signatures(w, name)
                    indices, _, _ = SAMPLES[name]
                    self.assertEqual(
                        tuple(signature.index for signature in signatures),
                        indices,
                    )
                    encoded = multiproof_encode(signer.public_key, signatures)
                    self.assertIsInstance(encoded, bytes)
                    self.assertEqual(encoded, fixture(w, name))

    def test_frozen_samples_verify_directly(self):
        # The frozen bytes go straight to the verifier; they are not
        # re-encoded by the current encoder first.
        for w in (4, 8):
            for name, (_, context, _) in SAMPLES.items():
                with self.subTest(w=w, sample=name):
                    blob = fixture(w, name)
                    self.assertTrue(
                        multiproof_verify(
                            sample_messages(name), blob, context=context
                        )
                    )
                    self.assertTrue(
                        multiproof_verify(
                            sample_messages(name), bytearray(blob), context=context
                        )
                    )

    def test_frozen_headers_pin_layout_and_node_counts(self):
        for w in (4, 8):
            for name, (indices, _, node_count) in SAMPLES.items():
                with self.subTest(w=w, sample=name):
                    blob = fixture(w, name)
                    self.assertEqual(blob[:8], b"PQAMMUL\0")
                    self.assertEqual(blob[8], 1)
                    self.assertEqual(
                        int.from_bytes(blob[9:13], "big"), PUBLIC_KEY_BYTES
                    )
                    self.assertEqual(
                        int.from_bytes(blob[13:15], "big"), len(indices)
                    )
                    # The structural point of each sample: full path,
                    # deduplicated shared node, zero external nodes.
                    self.assertEqual(
                        int.from_bytes(blob[15:17], "big"), node_count
                    )
                    expected_length = (
                        _MULTIPROOF_HEADER_BYTES
                        + PUBLIC_KEY_BYTES
                        + len(indices) * leaf_block_bytes(w)
                        + node_count * _MULTIPROOF_NODE_BYTES
                    )
                    self.assertEqual(len(blob), expected_length)
                    # The embedded key is the deterministic public key.
                    key_start = _MULTIPROOF_HEADER_BYTES
                    key_end = key_start + PUBLIC_KEY_BYTES
                    self.assertEqual(
                        MerklePublicKey.from_bytes(blob[key_start:key_end]),
                        make_signer(w).public_key,
                    )

    def test_context_binds_into_the_frozen_bytes(self):
        # Same key, leaf and message with and without the context must
        # produce different frozen proofs.
        for w in (4, 8):
            with self.subTest(w=w):
                self.assertNotEqual(
                    fixture(w, "single_leaf"), fixture(w, "context_leaf")
                )


class MultiproofCompatBoundTest(unittest.TestCase):
    def test_bound_to_expected_key_and_indices(self):
        for w in (4, 8):
            for name, (indices, context, _) in SAMPLES.items():
                with self.subTest(w=w, sample=name):
                    blob = fixture(w, name)
                    messages = sample_messages(name)
                    public_key = make_signer(w).public_key
                    self.assertTrue(
                        multiproof_verify_bound(
                            messages,
                            blob,
                            public_key=public_key,
                            indices=indices,
                            context=context,
                        )
                    )
                    # An independent, value-equal key instance binds too.
                    equal_key = MerklePublicKey.from_bytes(public_key.to_bytes())
                    self.assertEqual(equal_key, public_key)
                    self.assertTrue(
                        multiproof_verify_bound(
                            messages,
                            blob,
                            public_key=equal_key,
                            indices=indices,
                            context=context,
                        )
                    )

    def test_other_public_keys_do_not_bind(self):
        for w in (4, 8):
            other_w = 8 if w == 4 else 4
            other_keys = (
                make_signer(w, start=100_000).public_key,  # same w, other root
                make_signer(other_w).public_key,           # other w
            )
            for name, (indices, context, _) in SAMPLES.items():
                blob = fixture(w, name)
                messages = sample_messages(name)
                for other in other_keys:
                    with self.subTest(w=w, sample=name, other_w=other.w):
                        self.assertFalse(
                            multiproof_verify_bound(
                                messages,
                                blob,
                                public_key=other,
                                indices=indices,
                                context=context,
                            )
                        )

    def test_other_leaf_sets_do_not_bind(self):
        wrong_indices = {
            "single_leaf": [(1,), (), (0, 1)],
            "sparse_leaves": [(0, 2), (1, 0), (0,), (0, 1, 2)],
            "all_leaves": [(0, 1, 2), (0, 1, 2, 2), (1, 2, 3, 4)],
            "context_leaf": [(1,), (), (0, 1)],
        }
        for w in (4, 8):
            public_key = make_signer(w).public_key
            for name, (indices, context, _) in SAMPLES.items():
                blob = fixture(w, name)
                messages = sample_messages(name)
                for bad in wrong_indices[name]:
                    with self.subTest(w=w, sample=name, indices=bad):
                        self.assertFalse(
                            multiproof_verify_bound(
                                messages,
                                blob,
                                public_key=public_key,
                                indices=bad,
                                context=context,
                            )
                        )
                    # The genuine proof still binds, guarding against a
                    # verifier that rejects everything.
                    self.assertTrue(
                        multiproof_verify_bound(
                            messages,
                            blob,
                            public_key=public_key,
                            indices=indices,
                            context=context,
                        )
                    )


class MultiproofCompatRejectionTest(unittest.TestCase):
    def test_swapped_message_order_is_false(self):
        for w in (4, 8):
            for name in ("sparse_leaves", "all_leaves"):
                with self.subTest(w=w, sample=name):
                    messages = sample_messages(name)
                    swapped = (messages[1], messages[0]) + messages[2:]
                    self.assertFalse(
                        multiproof_verify(swapped, fixture(w, name))
                    )

    def test_tampered_wots_element_is_false(self):
        element_offset = _MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES + 4
        for w in (4, 8):
            for name, (_, context, _) in SAMPLES.items():
                with self.subTest(w=w, sample=name):
                    blob = bytearray(fixture(w, name))
                    blob[element_offset] ^= 0x01
                    self.assertFalse(
                        multiproof_verify(
                            sample_messages(name), bytes(blob), context=context
                        )
                    )

    def test_tampered_auth_node_is_false(self):
        for w in (4, 8):
            # single_leaf carries the full path; flip a byte inside the
            # last node block of the frozen proof.
            with self.subTest(w=w):
                blob = bytearray(fixture(w, "single_leaf"))
                blob[-1] ^= 0x01
                self.assertFalse(
                    multiproof_verify(sample_messages("single_leaf"), bytes(blob))
                )

    def test_non_canonical_node_order_is_false(self):
        for w in (4, 8):
            with self.subTest(w=w):
                blob = bytearray(fixture(w, "single_leaf"))
                start = node_section_offset(w, 1)
                first = bytes(blob[start : start + _MULTIPROOF_NODE_BYTES])
                second = bytes(
                    blob[start + _MULTIPROOF_NODE_BYTES : start + 2 * _MULTIPROOF_NODE_BYTES]
                )
                blob[start : start + 2 * _MULTIPROOF_NODE_BYTES] = second + first
                self.assertFalse(
                    multiproof_verify(sample_messages("single_leaf"), bytes(blob))
                )

    def test_truncation_is_false(self):
        for w in (4, 8):
            for name, (_, context, _) in SAMPLES.items():
                blob = fixture(w, name)
                cuts = {
                    0,
                    8,
                    _MULTIPROOF_HEADER_BYTES,
                    _MULTIPROOF_HEADER_BYTES + PUBLIC_KEY_BYTES,
                    node_section_offset(w, len(sample_messages(name))),
                    len(blob) - 1,
                }
                # all_leaves carries zero nodes, so its node-section offset
                # is the full length — not a truncation.
                cuts.discard(len(blob))
                for cut in sorted(cuts):
                    with self.subTest(w=w, sample=name, cut=cut):
                        self.assertFalse(
                            multiproof_verify(
                                sample_messages(name),
                                blob[:cut],
                                context=context,
                            )
                        )

    def test_trailing_bytes_are_false(self):
        for w in (4, 8):
            for name, (_, context, _) in SAMPLES.items():
                blob = fixture(w, name)
                for suffix in (b"\x00", b"tail"):
                    with self.subTest(w=w, sample=name, suffix=suffix):
                        self.assertFalse(
                            multiproof_verify(
                                sample_messages(name),
                                blob + suffix,
                                context=context,
                            )
                        )

    def test_bytes_and_bytearray_verify_identically(self):
        for w in (4, 8):
            for name, (_, context, _) in SAMPLES.items():
                with self.subTest(w=w, sample=name):
                    blob = fixture(w, name)
                    messages = sample_messages(name)
                    self.assertEqual(
                        multiproof_verify(messages, blob, context=context),
                        multiproof_verify(
                            messages, bytearray(blob), context=context
                        ),
                    )
                    tampered = bytearray(blob)
                    tampered[-1] ^= 0x01
                    self.assertEqual(
                        multiproof_verify(
                            messages, bytes(tampered), context=context
                        ),
                        multiproof_verify(messages, tampered, context=context),
                    )
                    self.assertFalse(
                        multiproof_verify(messages, tampered, context=context)
                    )


class MultiproofCompatContextTest(unittest.TestCase):
    def test_context_free_samples_accept_absent_none_and_empty(self):
        for w in (4, 8):
            for name in ("single_leaf", "sparse_leaves", "all_leaves"):
                blob = fixture(w, name)
                messages = sample_messages(name)
                for context in (None, b"", "", bytearray()):
                    with self.subTest(w=w, sample=name, context=repr(context)):
                        self.assertTrue(
                            multiproof_verify(messages, blob, context=context)
                        )
                with self.subTest(w=w, sample=name, context="omitted"):
                    self.assertTrue(multiproof_verify(messages, blob))

    def test_context_sample_requires_the_same_context(self):
        for w in (4, 8):
            blob = fixture(w, "context_leaf")
            messages = sample_messages("context_leaf")
            for good in (CONTEXT, bytearray(CONTEXT), CONTEXT.decode("utf-8")):
                with self.subTest(w=w, context=repr(good)):
                    self.assertTrue(
                        multiproof_verify(messages, blob, context=good)
                    )
            for bad in (None, b"", "", bytearray(), CONTEXT_OTHER, "other"):
                with self.subTest(w=w, context=repr(bad)):
                    self.assertFalse(
                        multiproof_verify(messages, blob, context=bad)
                    )
            with self.subTest(w=w, context="omitted"):
                self.assertFalse(multiproof_verify(messages, blob))

    def test_bound_verification_follows_the_same_context_rules(self):
        for w in (4, 8):
            public_key = make_signer(w).public_key
            blob = fixture(w, "context_leaf")
            messages = sample_messages("context_leaf")
            self.assertTrue(
                multiproof_verify_bound(
                    messages,
                    blob,
                    public_key=public_key,
                    indices=(0,),
                    context=CONTEXT,
                )
            )
            self.assertFalse(
                multiproof_verify_bound(
                    messages, blob, public_key=public_key, indices=(0,)
                )
            )
            self.assertFalse(
                multiproof_verify_bound(
                    messages,
                    blob,
                    public_key=public_key,
                    indices=(0,),
                    context=CONTEXT_OTHER,
                )
            )

    def test_wrong_context_type_raises_type_error(self):
        for w in (4, 8):
            blob = fixture(w, "single_leaf")
            messages = sample_messages("single_leaf")
            public_key = make_signer(w).public_key
            for bad in (42, 4.5, object(), [b"x"], (b"x",)):
                with self.subTest(w=w, bad=type(bad).__name__):
                    with self.assertRaises(TypeError):
                        multiproof_verify(messages, blob, context=bad)
                    with self.assertRaises(TypeError):
                        multiproof_verify_bound(
                            messages,
                            blob,
                            public_key=public_key,
                            indices=(0,),
                            context=bad,
                        )


class MultiproofCompatBoundTypeTest(unittest.TestCase):
    def setUp(self):
        self.w = 4
        self.blob = fixture(self.w, "single_leaf")
        self.messages = sample_messages("single_leaf")
        self.public_key = make_signer(self.w).public_key

    def bound(self, **overrides):
        kwargs = {
            "public_key": self.public_key,
            "indices": (0,),
        }
        kwargs.update(overrides)
        return multiproof_verify_bound(self.messages, self.blob, **kwargs)

    def test_wrong_public_key_type_raises_type_error(self):
        for bad in (None, 42, "key", b"raw", self.blob, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self.bound(public_key=bad)

    def test_non_tuple_indices_raise_type_error(self):
        for bad in ([0], "0", 0, {0}, frozenset({0})):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    self.bound(indices=bad)

    def test_non_integer_index_member_raises_type_error(self):
        for bad in (("0",), (None,), (1.5,), (b"\x00",)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    self.bound(indices=bad)

    def test_boolean_index_returns_false_not_error(self):
        # False == 0 matches the proof's leaf index numerically, but a
        # boolean member is rejected by value, not by type error.
        self.assertFalse(self.bound(indices=(False,)))
        self.assertFalse(self.bound(indices=(True,)))
        self.assertTrue(self.bound(indices=(0,)))


if __name__ == "__main__":
    unittest.main()

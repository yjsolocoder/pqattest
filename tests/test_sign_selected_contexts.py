"""Per-message context binding (``contexts=``) for the explicit leaf-set
entries ``MerkleSigner.sign_selected`` /
``sign_selected_with_checkpoint`` / ``sign_selected_with_auth_state``.

Covers positional per-leaf contexts, equivalence with advancing to each
chosen leaf and single-signing with that leaf's context (and with
``sign_batch`` contexts on a consecutive selection), independent
verification, the checkpoint/auth-state variants returning the same
post-signing state, batch-proof and multiproof verification, the fixed
validation order (types, then structure, then key/generation, then
exhaustion, then the index range), all-or-nothing state rules, w=4 and
w=8, every supported tree height, restored signers, determinism without
randomness and concurrency.
"""

import threading
import unittest
from unittest import mock

import pqattest.merkle
from pqattest import (
    KeyExhaustedError,
    MerkleBatchProof,
    MerkleSigner,
    auth_state_unwrap,
    merkle_verify,
    multiproof_encode,
    multiproof_verify,
    multiproof_verify_bound,
)

SEED = bytes(range(32))
KEY = b"shared-secret-key"

INDICES = (1, 4, 6)
MESSAGES = ("same", b"same", bytearray(b"other"))
# The first two leaves sign the same message under different contexts; the
# third slot is the "no context" case (None and an empty str below).
CONTEXTS = (b"ctx-a", "ctx-b/ü", None)
CONTEXTS_BYTES = (b"ctx-a", "ctx-b/ü".encode("utf-8"), None)

BAD_CONTEXTS = (1, 1.5, ["ctx"], {"ctx": 1}, object())


def make_signer(seed: bytes = SEED, height: int = 3, w: int = 4) -> MerkleSigner:
    return MerkleSigner.from_seed(seed, height=height, w=w)


def sequential_selected(indices, messages, contexts, height=3, w=4):
    """Reference: advance to each chosen leaf, then single-sign in turn."""
    signer = make_signer(height=height, w=w)
    signatures = []
    for index, message, context in zip(indices, messages, contexts):
        signer.advance_to(index)
        signatures.append(signer.sign(message, context=context))
    return tuple(signatures)


class SignSelectedContextsBasicTest(unittest.TestCase):
    def test_matches_advance_then_sequential_single_signing(self):
        for w in (4, 8):
            with self.subTest(w=w):
                signer = make_signer(w=w)
                signatures = signer.sign_selected(
                    INDICES, MESSAGES, contexts=CONTEXTS
                )
                self.assertEqual(
                    signatures,
                    sequential_selected(INDICES, MESSAGES, CONTEXTS, w=w),
                )
                self.assertEqual(signer.next_index, INDICES[-1] + 1)

    def test_consecutive_selection_matches_sign_batch_contexts(self):
        messages = ("a", b"b", bytearray(b"c"), "d")
        contexts = (b"c0", None, "c2", "")
        for w in (4, 8):
            with self.subTest(w=w):
                selected = make_signer(w=w).sign_selected(
                    (0, 1, 2, 3), messages, contexts=contexts
                )
                batched = make_signer(w=w).sign_batch(messages, contexts=contexts)
                self.assertEqual(selected, batched)

    def test_same_message_on_different_leaves_binds_different_contexts(self):
        signatures = make_signer().sign_selected(
            (0, 1), ("m", "m"), contexts=(b"x", b"y")
        )
        public_key = make_signer().public_key
        self.assertTrue(
            merkle_verify("m", signatures[0], public_key, context=b"x")
        )
        self.assertTrue(
            merkle_verify("m", signatures[1], public_key, context=b"y")
        )
        # The contexts are not interchangeable.
        self.assertFalse(
            merkle_verify("m", signatures[0], public_key, context=b"y")
        )
        self.assertFalse(
            merkle_verify("m", signatures[1], public_key, context=b"x")
        )
        self.assertFalse(
            merkle_verify("m", signatures[0], public_key)
        )

    def test_each_signature_verifies_independently_and_wrong_context_fails(self):
        signer = make_signer()
        signatures = signer.sign_selected(
            INDICES, MESSAGES, contexts=CONTEXTS
        )
        for message, context, signature in zip(
            MESSAGES, CONTEXTS_BYTES, signatures
        ):
            self.assertTrue(
                merkle_verify(
                    message, signature, signer.public_key, context=context
                )
            )
        # A slot's context verifies no other slot; no context is required for
        # the unbound third slot.
        self.assertFalse(
            merkle_verify(
                MESSAGES[0],
                signatures[0],
                signer.public_key,
                context=CONTEXTS_BYTES[1],
            )
        )
        self.assertFalse(
            merkle_verify(MESSAGES[0], signatures[0], signer.public_key)
        )
        self.assertTrue(
            merkle_verify(MESSAGES[2], signatures[2], signer.public_key)
        )
        # A tampered message still fails.
        self.assertFalse(
            merkle_verify(
                b"not same", signatures[0], signer.public_key, context=b"ctx-a"
            )
        )

    def test_none_contexts_is_legacy_identical(self):
        signer = make_signer()
        legacy = make_signer().sign_selected(INDICES, MESSAGES, context=b"sh")
        self.assertEqual(
            signer.sign_selected(
                INDICES, MESSAGES, context=b"sh", contexts=None
            ),
            legacy,
        )
        self.assertEqual(
            make_signer().sign_selected(INDICES, MESSAGES),
            make_signer().sign_selected(INDICES, MESSAGES, contexts=None),
        )

    def test_all_empty_members_equal_unbound_selection(self):
        indices = (0, 2, 4)
        bound = make_signer().sign_selected(
            indices, MESSAGES, contexts=(None, b"", "")
        )
        plain = make_signer().sign_selected(indices, MESSAGES)
        self.assertEqual(bound, plain)

    def test_gaps_are_voided_and_state_advances_to_last_index_plus_one(self):
        signer = make_signer()
        signatures = signer.sign_selected(
            INDICES, MESSAGES, contexts=CONTEXTS
        )
        self.assertEqual([s.index for s in signatures], list(INDICES))
        self.assertEqual(signer.next_index, 7)
        with self.assertRaises(ValueError):
            signer.sign_selected((2,), ("late",), contexts=(None,))
        self.assertEqual(signer.sign("next").index, 7)


class SignSelectedContextsVariantTest(unittest.TestCase):
    def test_checkpoint_variant_matches_signatures_and_state(self):
        signatures, checkpoint = make_signer().sign_selected_with_checkpoint(
            INDICES, MESSAGES, contexts=CONTEXTS
        )
        self.assertEqual(
            signatures,
            make_signer().sign_selected(INDICES, MESSAGES, contexts=CONTEXTS),
        )
        reference = make_signer()
        reference.sign_selected(INDICES, MESSAGES)
        # Contexts never enter the checkpoint: the bytes describe the same
        # advanced state as the unbound selection.
        self.assertEqual(checkpoint, reference.checkpoint())
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, make_signer().public_key)
        self.assertEqual(restored.next_index, 7)
        follow_up = restored.sign("after", context=b"ctx-z")
        self.assertEqual(follow_up.index, 7)
        self.assertTrue(
            merkle_verify(
                "after", follow_up, restored.public_key, context=b"ctx-z"
            )
        )

    def test_auth_state_variant_matches_wrapped_checkpoint(self):
        generation = 11
        signatures, envelope = (
            make_signer().sign_selected_with_auth_state(
                INDICES,
                MESSAGES,
                key=KEY,
                generation=generation,
                contexts=CONTEXTS,
            )
        )
        self.assertEqual(
            signatures,
            make_signer().sign_selected(INDICES, MESSAGES, contexts=CONTEXTS),
        )
        reference = make_signer()
        reference.sign_selected(INDICES, MESSAGES)
        expected_checkpoint = reference.checkpoint()
        scheme, got_generation, checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(scheme, "merkle")
        self.assertEqual(got_generation, generation)
        self.assertEqual(checkpoint, expected_checkpoint)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.next_index, 7)
        for message, context, signature in zip(
            MESSAGES, CONTEXTS_BYTES, signatures
        ):
            self.assertTrue(
                merkle_verify(
                    message, signature, restored.public_key, context=context
                )
            )

    def test_checkpoint_and_auth_state_variants_share_post_state(self):
        signatures, checkpoint = make_signer().sign_selected_with_checkpoint(
            INDICES, MESSAGES, contexts=CONTEXTS
        )
        signatures2, envelope = (
            make_signer().sign_selected_with_auth_state(
                INDICES,
                MESSAGES,
                key=KEY,
                generation=3,
                contexts=CONTEXTS,
            )
        )
        _, _, wrapped_checkpoint = auth_state_unwrap(
            envelope, key=KEY, expect="merkle"
        )
        self.assertEqual(signatures, signatures2)
        self.assertEqual(checkpoint, wrapped_checkpoint)

    def test_contexts_do_not_change_wire_formats(self):
        signer = make_signer()
        signatures = signer.sign_selected(
            INDICES, MESSAGES, contexts=CONTEXTS
        )
        # Signatures keep the existing v1 codec and contexts stay out of the
        # encoded bytes.
        for signature in signatures:
            self.assertEqual(
                type(signature).from_bytes(
                    signature.to_bytes(signer.public_key), signer.public_key
                ),
                signature,
            )
        batch = MerkleBatchProof(signer.public_key, signatures)
        parsed = MerkleBatchProof.from_bytes(batch.to_bytes())
        self.assertEqual(parsed, batch)
        self.assertTrue(parsed.verify(MESSAGES, contexts=CONTEXTS))


class SignSelectedContextsProofTest(unittest.TestCase):
    def _proved(self):
        signer = make_signer()
        signatures = signer.sign_selected(
            INDICES, MESSAGES, contexts=CONTEXTS
        )
        return signer, signatures

    def test_batch_proof_verifies_with_contexts(self):
        signer, signatures = self._proved()
        batch = MerkleBatchProof(signer.public_key, signatures)
        self.assertTrue(batch.verify(MESSAGES, contexts=CONTEXTS))
        wrong = (CONTEXTS[0], b"other", CONTEXTS[2])
        self.assertFalse(batch.verify(MESSAGES, contexts=wrong))
        self.assertFalse(batch.verify(MESSAGES, contexts=(None,) * 3))
        self.assertFalse(batch.verify(MESSAGES))
        self.assertTrue(
            batch.verify_bound(
                MESSAGES,
                public_key=signer.public_key,
                indices=INDICES,
                contexts=CONTEXTS,
            )
        )
        self.assertFalse(
            batch.verify_bound(
                MESSAGES,
                public_key=signer.public_key,
                indices=(0, 4, 6),
                contexts=CONTEXTS,
            )
        )
        self.assertFalse(
            batch.verify_bound(
                MESSAGES,
                public_key=signer.public_key,
                indices=INDICES,
                contexts=(b"ctx-a", b"other", None),
            )
        )

    def test_multiproof_verifies_with_contexts(self):
        signer, signatures = self._proved()
        proof = multiproof_encode(signer.public_key, signatures)
        self.assertTrue(multiproof_verify(MESSAGES, proof, contexts=CONTEXTS))
        self.assertTrue(
            multiproof_verify_bound(
                MESSAGES,
                proof,
                public_key=signer.public_key,
                indices=INDICES,
                contexts=CONTEXTS,
            )
        )
        self.assertFalse(
            multiproof_verify(
                MESSAGES, proof, contexts=(b"ctx-a", b"other", None)
            )
        )
        self.assertFalse(multiproof_verify(MESSAGES, proof))
        self.assertFalse(
            multiproof_verify_bound(
                MESSAGES,
                proof,
                public_key=signer.public_key,
                indices=(1, 4, 5),
                contexts=CONTEXTS,
            )
        )

    def test_multiproof_bytes_independent_of_contexts(self):
        signer, signatures = self._proved()
        self.assertEqual(
            multiproof_encode(signer.public_key, signatures),
            multiproof_encode(
                make_signer().public_key,
                sequential_selected(INDICES, MESSAGES, CONTEXTS),
            ),
        )


class SignSelectedContextsValidationTest(unittest.TestCase):
    def test_container_type_errors(self):
        signer = make_signer()
        for entry in (
            lambda c: signer.sign_selected(
                (0, 1), ("a", "b"), contexts=c
            ),
            lambda c: signer.sign_selected_with_checkpoint(
                (0, 1), ("a", "b"), contexts=c
            ),
            lambda c: signer.sign_selected_with_auth_state(
                (0, 1), ("a", "b"), key=KEY, generation=0, contexts=c
            ),
        ):
            for bad in ([b"a", None], "ctx", 42, b"ctx", {0: None}):
                with self.subTest(bad=type(bad).__name__):
                    with self.assertRaises(TypeError):
                        entry(bad)

    def test_member_type_errors(self):
        signer = make_signer()
        for bad in BAD_CONTEXTS:
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    signer.sign_selected(
                        (0, 1, 2),
                        ("a", "b", "c"),
                        contexts=(b"a", bad, None),
                    )
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_checkpoint(
                        (0, 1, 2),
                        ("a", "b", "c"),
                        contexts=(b"a", bad, None),
                    )
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_auth_state(
                        (0, 1, 2),
                        ("a", "b", "c"),
                        key=KEY,
                        generation=0,
                        contexts=(b"a", bad, None),
                    )

    def test_index_and_message_type_errors_still_raise(self):
        signer = make_signer()
        with self.assertRaises(TypeError):
            signer.sign_selected("01", ("a", "b"), contexts=(None, None))
        with self.assertRaises(TypeError):
            signer.sign_selected(
                (0, 1), ["a", "b"], contexts=(None, None)
            )
        with self.assertRaises(TypeError):
            signer.sign_selected(
                (0, 1), ("a", 2), contexts=(None, None)
            )

    def test_empty_selection_raises_value_error_even_with_contexts(self):
        signer = make_signer()
        with self.assertRaises(ValueError):
            signer.sign_selected((), (), contexts=())
        with self.assertRaises(ValueError):
            signer.sign_selected((), ("a",), contexts=(None,))
        with self.assertRaises(ValueError):
            signer.sign_selected((0,), (), contexts=())

    def test_length_mismatch_raises_value_error(self):
        signer = make_signer()
        for contexts in ((), (b"a",), (b"a", b"b", None, b"d")):
            with self.subTest(count=len(contexts)):
                with self.assertRaises(ValueError):
                    signer.sign_selected(
                        (0, 1, 2),
                        ("a", "b", "c"),
                        contexts=contexts,
                    )
                with self.assertRaises(ValueError):
                    signer.sign_selected_with_checkpoint(
                        (0, 1, 2),
                        ("a", "b", "c"),
                        contexts=contexts,
                    )

    def test_boolean_duplicate_and_unordered_indices_raise_value_error(self):
        signer = make_signer()
        for indices in ((True, 1), (0, False), (1, 1), (2, 1), (3, 2, 1)):
            messages = tuple("m" for _ in indices)
            contexts = tuple(None for _ in indices)
            with self.subTest(indices=indices):
                with self.assertRaises(ValueError):
                    signer.sign_selected(
                        indices, messages, contexts=contexts
                    )

    def test_shared_context_conflict_raises_value_error(self):
        signer = make_signer()
        for context in (b"shared", "shared", bytearray(b"shared")):
            with self.subTest(context=repr(context)):
                with self.assertRaises(ValueError):
                    signer.sign_selected(
                        (0, 1),
                        ("a", "b"),
                        context=context,
                        contexts=(None, None),
                    )
                with self.assertRaises(ValueError):
                    signer.sign_selected_with_checkpoint(
                        (0, 1),
                        ("a", "b"),
                        context=context,
                        contexts=(None, None),
                    )
                with self.assertRaises(ValueError):
                    signer.sign_selected_with_auth_state(
                        (0, 1),
                        ("a", "b"),
                        key=KEY,
                        generation=0,
                        context=context,
                        contexts=(None, None),
                    )
        # An empty shared context is "no context" and does not conflict.
        self.assertEqual(
            make_signer().sign_selected(
                (0, 1), ("a", "b"), context=b"", contexts=(b"x", None)
            ),
            sequential_selected((0, 1), ("a", "b"), (b"x", None)),
        )

    def test_type_errors_precede_structure_and_conflict(self):
        signer = make_signer()
        # A bad contexts member wins over emptiness, length and conflict.
        with self.assertRaises(TypeError):
            signer.sign_selected((), (), contexts=(42,))
        with self.assertRaises(TypeError):
            signer.sign_selected(
                (0, 1),
                ("a", "b"),
                context=b"shared",
                contexts=(42, None),
            )
        # A bad message member wins over the conflict rule.
        with self.assertRaises(TypeError):
            signer.sign_selected(
                (0, 1),
                ("a", 42),
                context=b"shared",
                contexts=(None, None),
            )

    def test_structure_errors_precede_key_and_generation(self):
        signer = make_signer()
        # Structural problems beat even invalid key/generation inputs.
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (), (), key=b"", generation=-1, contexts=()
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0, 1),
                ("a",),
                key=b"",
                generation=0,
                contexts=(None, None),
            )
        # Type problems of the selection beat key/generation types too.
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                (0, 1),
                ("a", "b"),
                key=42,
                generation="0",
                contexts=[None, None],
            )

    def test_auth_state_key_generation_checks_follow_structure(self):
        signer = make_signer(height=2)
        for bad_key in (None, 42, "secret", ["k"], b"", bytearray()):
            with self.subTest(bad=type(bad_key).__name__):
                with self.assertRaises((TypeError, ValueError)):
                    signer.sign_selected_with_auth_state(
                        (0, 1),
                        ("a", "b"),
                        key=bad_key,
                        generation=0,
                        contexts=(None, None),
                    )
        for bad_generation in (None, 1.5, "0", [0], True, False):
            with self.subTest(bad=repr(bad_generation)):
                with self.assertRaises(TypeError):
                    signer.sign_selected_with_auth_state(
                        (0,),
                        ("a",),
                        key=KEY,
                        generation=bad_generation,
                        contexts=(None,),
                    )
        for bad_generation in (-1, 2**64):
            with self.subTest(bad=repr(bad_generation)):
                with self.assertRaises(ValueError):
                    signer.sign_selected_with_auth_state(
                        (0,),
                        ("a",),
                        key=KEY,
                        generation=bad_generation,
                        contexts=(None,),
                    )

    def test_exhaustion_checked_after_inputs(self):
        signer = make_signer(height=1)
        signer.advance_to(2)
        # Input errors still win on an exhausted signer.
        with self.assertRaises(TypeError):
            signer.sign_selected((0,), (123,), contexts=(None,))
        with self.assertRaises(TypeError):
            signer.sign_selected(
                (0,), ("a",), contexts=(b"a", 1)
            )
        with self.assertRaises(ValueError):
            signer.sign_selected((), (), contexts=())
        with self.assertRaises(ValueError):
            signer.sign_selected(
                (0,), ("a",), context=b"sh", contexts=(None,)
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0,), ("a",), key=b"", generation=0, contexts=(None,)
            )
        # A structurally valid request reports exhaustion, not a range error.
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected((0,), ("late",), contexts=(None,))
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected_with_checkpoint(
                (0,), ("late",), contexts=(None,)
            )
        with self.assertRaises(KeyExhaustedError):
            signer.sign_selected_with_auth_state(
                (0,), ("late",), key=KEY, generation=0, contexts=(None,)
            )

    def test_range_error_on_fresh_signer_never_exhaustion(self):
        signer = make_signer(height=1)
        with self.assertRaises(ValueError):
            signer.sign_selected((2,), ("x",), contexts=(None,))
        with self.assertRaises(ValueError):
            signer.sign_selected((-1,), ("x",), contexts=(b"c",))
        self.assertEqual(signer.next_index, 0)
        # An index below the current next leaf after some progress.
        progressed = make_signer(height=3)
        progressed.sign_batch(("a", "b"))  # next_index == 2, leaves remain
        with self.assertRaises(ValueError):
            progressed.sign_selected(
                (0, 2), ("old", "new"), contexts=(None, b"c")
            )
        self.assertEqual(progressed.next_index, 2)

    def test_failures_consume_no_leaf(self):
        signer = make_signer()
        failing = (
            lambda: signer.sign_selected(
                (0, 1), ("a",), contexts=(None, None)
            ),
            lambda: signer.sign_selected(
                (0, 1), ("a", "b"), contexts=(b"a", 1)
            ),
            lambda: signer.sign_selected(
                (0, 1),
                ("a", "b"),
                context=b"shared",
                contexts=(None, None),
            ),
            lambda: signer.sign_selected_with_checkpoint(
                (1, 1), ("a", "b"), contexts=(None, None)
            ),
            lambda: signer.sign_selected_with_auth_state(
                (0, 1),
                ("a", "b"),
                key=KEY,
                generation=2**64,
                contexts=(None, None),
            ),
        )
        for call in failing:
            with self.assertRaises((TypeError, ValueError)):
                call()
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign("first").index, 0)


class SignSelectedContextsCoverageTest(unittest.TestCase):
    def test_all_supported_heights_and_both_w(self):
        for height in range(1, 9):
            for w in (4, 8):
                with self.subTest(height=height, w=w):
                    signer = make_signer(height=height, w=w)
                    leaf_count = 1 << height
                    indices = tuple(range(0, leaf_count, max(1, leaf_count // 3)))
                    messages = tuple(f"m{i}" for i in indices)
                    contexts = tuple(
                        None if i % 2 else f"ctx-{i}" for i in indices
                    )
                    signatures = signer.sign_selected(
                        indices, messages, contexts=contexts
                    )
                    self.assertEqual(
                        signatures,
                        sequential_selected(
                            indices, messages, contexts, height=height, w=w
                        ),
                    )
                    self.assertEqual(signer.next_index, indices[-1] + 1)
                    proof = multiproof_encode(signer.public_key, signatures)
                    self.assertTrue(
                        multiproof_verify(
                            messages, proof, contexts=contexts
                        )
                    )

    def test_works_after_checkpoint_restore(self):
        signer = make_signer()
        _, blob = signer.sign_selected_with_checkpoint(
            (0, 2), ("a", "b"), contexts=(b"c0", None)
        )
        restored = MerkleSigner.from_checkpoint(blob)
        signatures = restored.sign_selected(
            (3, 5), ("c", "d"), contexts=("c3", b"c5")
        )
        self.assertEqual([s.index for s in signatures], [3, 5])
        self.assertTrue(
            merkle_verify("c", signatures[0], restored.public_key, context="c3")
        )
        self.assertTrue(
            merkle_verify(
                "d", signatures[1], restored.public_key, context=b"c5"
            )
        )

    def test_works_after_seed_checkpoint_restore(self):
        signer = make_signer()
        signer.sign_selected((1,), ("a",), contexts=(b"c1",))
        restored = MerkleSigner.from_seed_checkpoint(
            signer.seed_checkpoint()
        )
        self.assertEqual(restored.next_index, 2)
        signatures = restored.sign_selected(
            (2, 4), ("b", "c"), contexts=(None, "c4")
        )
        self.assertTrue(
            merkle_verify("c", signatures[1], restored.public_key, context="c4")
        )
        self.assertTrue(merkle_verify("b", signatures[0], restored.public_key))

    def test_deterministic_value_for_value(self):
        first = make_signer()
        second = make_signer()
        self.assertEqual(
            first.sign_selected(
                (0, 4, 7), ("a", "b", "c"), contexts=(b"x", None, "z")
            ),
            second.sign_selected(
                (0, 4, 7), ("a", "b", "c"), contexts=(b"x", None, "z")
            ),
        )

    def test_draws_no_randomness(self):
        signer = make_signer()

        def exploding_token_bytes(size):
            raise AssertionError("sign_selected contexts must not draw randomness")

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            signatures = signer.sign_selected(
                (0, 2, 5),
                ("a", "b", "c"),
                contexts=(b"x", None, "z"),
            )
            signer.sign_selected_with_checkpoint(
                (6,), ("d",), contexts=(b"w",)
            )
            signer.sign_selected_with_auth_state(
                (7,), ("e",), key=KEY, generation=1, contexts=(None,)
            )
        self.assertEqual([s.index for s in signatures], [0, 2, 5])
        self.assertEqual(signer.next_index, 8)

    def test_keyword_only_contexts(self):
        signer = make_signer()
        with self.assertRaises(TypeError):
            signer.sign_selected((0,), ("m",), None, (None,))
        with self.assertRaises(TypeError):
            signer.sign_selected_with_checkpoint(
                (0,), ("m",), None, (None,)
            )
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                (0,), ("m",), KEY, 0, None, (None,)
            )


class SignSelectedContextsConcurrencyTest(unittest.TestCase):
    def test_concurrent_context_selections_never_share_a_leaf(self):
        height = 4
        signer = make_signer(height=height)
        leaf_count = 1 << height
        picked = []
        errors = []
        list_lock = threading.Lock()
        barrier = threading.Barrier(4)

        def worker(offset):
            try:
                indices = tuple(range(offset, leaf_count, 4))
                messages = tuple(f"w{offset}-{i}" for i in indices)
                contexts = tuple(
                    None if i % 2 else f"ctx-{offset}-{i}" for i in indices
                )
                barrier.wait(timeout=10)
                signatures = signer.sign_selected(
                    indices, messages, contexts=contexts
                )
                with list_lock:
                    picked.extend(s.index for s in signatures)
            except Exception as exc:  # pragma: no cover - failure path
                with list_lock:
                    errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(i,)) for i in range(4)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertGreaterEqual(len(errors), 3)
        winner_picked = sorted(picked)
        self.assertEqual(winner_picked, sorted(set(winner_picked)))
        self.assertEqual(signer.next_index, max(winner_picked) + 1)

    def test_mixed_with_plain_signing_and_checkpoints(self):
        height = 3
        signer = make_signer(height=height)
        results = []
        errors = []
        result_lock = threading.Lock()
        barrier = threading.Barrier(3)

        def plain():
            try:
                barrier.wait(timeout=10)
                for _ in range(1 << height):
                    results.append(signer.sign("p").index)
            except KeyExhaustedError:
                pass
            except Exception as exc:  # pragma: no cover - failure path
                with result_lock:
                    errors.append(exc)

        def selected():
            try:
                barrier.wait(timeout=10)
                signer.sign_selected(
                    (0, 2, 4, 6),
                    tuple("sxyzwvut"[:4]),
                    contexts=(b"c0", None, "c2", b""),
                )
            except (ValueError, KeyExhaustedError):
                pass  # Lost the race: indices already spent or tree used.
            except Exception as exc:  # pragma: no cover - failure path
                with result_lock:
                    errors.append(exc)

        def checkpointer():
            try:
                barrier.wait(timeout=10)
                signer.sign_selected_with_checkpoint(
                    (1, 3), ("q", "r"), contexts=(None, b"cr")
                )
            except (ValueError, KeyExhaustedError):
                pass
            except Exception as exc:  # pragma: no cover - failure path
                with result_lock:
                    errors.append(exc)

        threads = [
            threading.Thread(target=plain),
            threading.Thread(target=selected),
            threading.Thread(target=checkpointer),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(results, sorted(set(results)))
        self.assertEqual(signer.remaining, 0)


if __name__ == "__main__":
    unittest.main()

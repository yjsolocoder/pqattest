"""Per-message context binding (``contexts=``) for the explicit-leaf entries.

Covers ``MerkleSigner.sign_selected`` /
``sign_selected_with_checkpoint`` / ``sign_selected_with_auth_state``:
positional per-leaf contexts on explicitly chosen (possibly gapped)
leaves, equivalence with sequential single-sign calls advancing through
the gaps and with ``sign_batch`` on a consecutive selection,
single-signature and batch/multiproof verification with the matching
contexts, the snapshot and auth-state artifacts, restoration, the fixed
validation order (types, then structure, then key/generation, then
exhaustion and range), all-or-nothing state rules, every tree height
with w=4 and w=8, determinism and concurrency. Omitting ``contexts``
keeps the legacy shared-``context`` behaviour byte-for-byte.
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
    auth_state_wrap,
    merkle_verify,
    multiproof_encode,
    multiproof_verify,
    multiproof_verify_bound,
)

SEED = bytes(range(32))
KEY = b"shared-secret-key"
INDICES = (0, 2, 5)
MESSAGES = (b"same", b"same", "gamma")
CONTEXTS = (b"ctx-a", "ctx-b/ü", None)  # None == no context for that slot
CONTEXTS_BYTES = (b"ctx-a", "ctx-b/ü".encode("utf-8"), None)

BAD_CONTEXTS = (1, 1.5, ["ctx"], {"ctx": 1}, object())


def make_signer(seed: bytes = SEED, height: int = 3, w: int = 4) -> MerkleSigner:
    return MerkleSigner.from_seed(seed, height=height, w=w)


def sequential_selected(signer, indices, messages, contexts):
    """Reference: advance to each chosen leaf and single-sign with its context."""
    signatures = []
    for index, message, context in zip(indices, messages, contexts):
        signer.advance_to(index)
        signatures.append(signer.sign(message, context=context))
    return tuple(signatures)


class SignSelectedContextsTest(unittest.TestCase):
    def test_binds_contexts_positionally_to_chosen_leaves(self):
        signer = make_signer()
        signatures = signer.sign_selected(INDICES, MESSAGES, contexts=CONTEXTS)
        self.assertEqual([s.index for s in signatures], list(INDICES))
        self.assertEqual(signer.next_index, INDICES[-1] + 1)
        # Skipped leaves 1, 3 and 4 are voided.
        self.assertEqual(signer.remaining, 8 - 6)
        for message, context, signature in zip(
            MESSAGES, CONTEXTS_BYTES, signatures
        ):
            self.assertTrue(
                merkle_verify(
                    message, signature, signer.public_key, context=context
                )
            )
            # The wrong context never verifies.
            self.assertFalse(
                merkle_verify(
                    message, signature, signer.public_key, context=b"other"
                )
            )
        # The None slot is an ordinary unbound signature.
        self.assertTrue(
            merkle_verify(MESSAGES[2], signatures[2], signer.public_key)
        )
        # A bound slot does not verify unbound.
        self.assertFalse(
            merkle_verify(MESSAGES[0], signatures[0], signer.public_key)
        )

    def test_same_message_on_different_leaves_takes_different_contexts(self):
        signer = make_signer()
        messages = (b"dup", b"dup")
        signatures = signer.sign_selected(
            (1, 4), messages, contexts=(b"one", b"two")
        )
        self.assertTrue(
            merkle_verify(b"dup", signatures[0], signer.public_key, context=b"one")
        )
        self.assertTrue(
            merkle_verify(b"dup", signatures[1], signer.public_key, context=b"two")
        )
        self.assertFalse(
            merkle_verify(b"dup", signatures[0], signer.public_key, context=b"two")
        )
        self.assertFalse(
            merkle_verify(b"dup", signatures[1], signer.public_key, context=b"one")
        )
        self.assertNotEqual(signatures[0], signatures[1])

    def test_matches_sequential_single_signing_through_the_gaps(self):
        for w in (4, 8):
            with self.subTest(w=w):
                atomic = make_signer(w=w).sign_selected(
                    INDICES, MESSAGES, contexts=CONTEXTS
                )
                sequential = sequential_selected(
                    make_signer(w=w), INDICES, MESSAGES, CONTEXTS
                )
                self.assertEqual(atomic, sequential)

    def test_consecutive_selection_matches_per_message_batch(self):
        for w in (4, 8):
            with self.subTest(w=w):
                signer = make_signer(w=w)
                signer.sign_batch((b"warm", b"up"))
                selected = signer.sign_selected(
                    (2, 3, 4), MESSAGES, contexts=CONTEXTS
                )
                other = make_signer(w=w)
                other.sign_batch((b"warm", b"up"))
                batched = other.sign_batch(MESSAGES, contexts=CONTEXTS)
                self.assertEqual(selected, batched)

    def test_none_and_empty_contexts_keep_legacy_output(self):
        plain = make_signer().sign_selected(INDICES, MESSAGES)
        self.assertEqual(
            make_signer().sign_selected(INDICES, MESSAGES, contexts=None), plain
        )
        self.assertEqual(
            make_signer().sign_selected(
                INDICES, MESSAGES, contexts=(None, None, None)
            ),
            plain,
        )
        self.assertEqual(
            make_signer().sign_selected(
                INDICES, MESSAGES, contexts=(b"", "", bytearray())
            ),
            plain,
        )
        shared = make_signer().sign_selected(INDICES, MESSAGES, context=b"shared")
        self.assertEqual(
            make_signer().sign_selected(
                INDICES, MESSAGES, context=b"shared", contexts=None
            ),
            shared,
        )

    def test_empty_shared_context_does_not_conflict(self):
        signatures = make_signer().sign_selected(
            INDICES, MESSAGES, context=b"", contexts=CONTEXTS
        )
        self.assertEqual(
            signatures,
            make_signer().sign_selected(INDICES, MESSAGES, contexts=CONTEXTS),
        )

    def test_contexts_are_keyword_only(self):
        signer = make_signer(height=2)
        with self.assertRaises(TypeError):
            signer.sign_selected((0, 1), (b"a", b"b"), None, (None, None))
        with self.assertRaises(TypeError):
            signer.sign_selected_with_checkpoint(
                (0, 1), (b"a", b"b"), None, (None, None)
            )

    def test_deterministic_value_for_value(self):
        first = make_signer()
        second = make_signer()
        self.assertEqual(
            first.sign_selected(INDICES, MESSAGES, contexts=CONTEXTS),
            second.sign_selected(INDICES, MESSAGES, contexts=CONTEXTS),
        )

    def test_draws_no_randomness(self):
        signer = make_signer()

        def exploding_token_bytes(size):
            raise AssertionError("per-message selected signing draws no randomness")

        with mock.patch.object(
            pqattest.merkle.secrets, "token_bytes", exploding_token_bytes
        ):
            signatures = signer.sign_selected(
                INDICES, MESSAGES, contexts=CONTEXTS
            )
        self.assertEqual([s.index for s in signatures], list(INDICES))


class SignSelectedContextsProofTest(unittest.TestCase):
    def test_batch_proof_verifies_with_contexts(self):
        signer = make_signer()
        signatures = signer.sign_selected(INDICES, MESSAGES, contexts=CONTEXTS)
        batch = MerkleBatchProof(signer.public_key, signatures)
        self.assertTrue(batch.verify(MESSAGES, contexts=CONTEXTS))
        wrong = (CONTEXTS[0], b"other", CONTEXTS[2])
        self.assertFalse(batch.verify(MESSAGES, contexts=wrong))
        self.assertFalse(batch.verify(MESSAGES))
        self.assertTrue(
            batch.verify_bound(
                MESSAGES,
                public_key=signer.public_key,
                indices=INDICES,
                contexts=CONTEXTS,
            )
        )
        # Wire format carries no contexts: it round-trips unchanged.
        parsed = MerkleBatchProof.from_bytes(batch.to_bytes())
        self.assertEqual(parsed, batch)
        self.assertTrue(parsed.verify(MESSAGES, contexts=CONTEXTS))

    def test_multiproof_verifies_with_contexts_and_binds_selection(self):
        signer = make_signer()
        signatures = signer.sign_selected(INDICES, MESSAGES, contexts=CONTEXTS)
        proof = multiproof_encode(signer.public_key, signatures)
        self.assertTrue(multiproof_verify(MESSAGES, proof, contexts=CONTEXTS))
        wrong = (CONTEXTS[0], b"other", CONTEXTS[2])
        self.assertFalse(multiproof_verify(MESSAGES, proof, contexts=wrong))
        self.assertFalse(multiproof_verify(MESSAGES, proof))
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
            multiproof_verify_bound(
                MESSAGES,
                proof,
                public_key=signer.public_key,
                indices=(0, 2, 4),
                contexts=CONTEXTS,
            )
        )


class SignSelectedContextsCheckpointTest(unittest.TestCase):
    def test_checkpoint_variant_matches_and_resumes(self):
        signer = make_signer()
        signatures, checkpoint = signer.sign_selected_with_checkpoint(
            INDICES, MESSAGES, contexts=CONTEXTS
        )
        self.assertEqual(
            signatures,
            make_signer().sign_selected(INDICES, MESSAGES, contexts=CONTEXTS),
        )
        self.assertEqual(signer.next_index, 6)
        restored = MerkleSigner.from_checkpoint(checkpoint)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 6)
        # Gaps stay voided after restore.
        with self.assertRaises(ValueError):
            restored.sign_selected((1,), (b"old",), contexts=(b"c",))
        follow_up = restored.sign(b"follow", context=b"ctx-d")
        self.assertEqual(follow_up.index, 6)
        self.assertTrue(
            merkle_verify(
                b"follow", follow_up, signer.public_key, context=b"ctx-d"
            )
        )

    def test_checkpoint_bytes_ignore_contexts(self):
        _, with_contexts = make_signer().sign_selected_with_checkpoint(
            INDICES, MESSAGES, contexts=CONTEXTS
        )
        _, plain = make_signer().sign_selected_with_checkpoint(INDICES, MESSAGES)
        self.assertEqual(with_contexts, plain)

    def test_seed_checkpoint_restores_context_signer(self):
        signer = make_signer()
        signatures, _ = signer.sign_selected_with_checkpoint(
            INDICES, MESSAGES, contexts=CONTEXTS
        )
        blob = signer.seed_checkpoint()
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 6)
        more = restored.sign_selected(
            (6, 7), (b"n1", b"n2"), contexts=("z", None)
        )
        self.assertEqual([s.index for s in more], [6, 7])
        self.assertTrue(
            merkle_verify(b"n1", more[0], signer.public_key, context="z")
        )
        self.assertTrue(merkle_verify(b"n2", more[1], signer.public_key))
        for message, context, signature in zip(
            MESSAGES, CONTEXTS_BYTES, signatures
        ):
            self.assertTrue(
                merkle_verify(
                    message, signature, signer.public_key, context=context
                )
            )


class SignSelectedContextsAuthStateTest(unittest.TestCase):
    def test_auth_variant_matches_and_envelope_wraps_checkpoint(self):
        signer = make_signer()
        signatures, envelope = signer.sign_selected_with_auth_state(
            INDICES, MESSAGES, key=KEY, generation=7, contexts=CONTEXTS
        )
        self.assertEqual(
            signatures,
            make_signer().sign_selected(INDICES, MESSAGES, contexts=CONTEXTS),
        )
        _, plain_checkpoint = make_signer().sign_selected_with_checkpoint(
            INDICES, MESSAGES
        )
        expected = auth_state_wrap(
            plain_checkpoint,
            scheme="merkle",
            key=KEY,
            generation=7,
        )
        self.assertEqual(envelope, expected)

    def test_from_auth_state_resumes_at_last_index_plus_one(self):
        signer = make_signer()
        signatures, envelope = signer.sign_selected_with_auth_state(
            INDICES, MESSAGES, key=KEY, generation=42, contexts=CONTEXTS
        )
        restored, generation = MerkleSigner.from_auth_state(
            envelope, key=KEY, min_generation=42
        )
        self.assertEqual(generation, 42)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 6)
        follow_up = restored.sign(b"follow", context=b"ctx-d")
        self.assertEqual(follow_up.index, 6)
        for message, context, signature in zip(
            MESSAGES, CONTEXTS_BYTES, signatures
        ):
            self.assertTrue(
                merkle_verify(
                    message, signature, signer.public_key, context=context
                )
            )


class SignSelectedContextsHeightsTest(unittest.TestCase):
    def test_all_heights_and_both_w_parameters(self):
        for height in range(1, 9):
            for w in (4, 8):
                with self.subTest(height=height, w=w):
                    signer = make_signer(height=height, w=w)
                    leaf_count = 1 << height
                    chosen = {0, leaf_count - 1}
                    if leaf_count > 2:
                        chosen.add(min(3, leaf_count - 2))
                    indices = tuple(sorted(chosen))
                    messages = tuple(f"m{i}" for i in indices)
                    contexts = tuple(
                        None if position % 2 else f"c{index}"
                        for position, index in enumerate(indices)
                    )
                    signatures = signer.sign_selected(
                        indices, messages, contexts=contexts
                    )
                    self.assertEqual(
                        [s.index for s in signatures], list(indices)
                    )
                    self.assertEqual(signer.next_index, leaf_count)
                    proof = multiproof_encode(signer.public_key, signatures)
                    self.assertTrue(
                        multiproof_verify(messages, proof, contexts=contexts)
                    )
                    for position, (message, signature) in enumerate(
                        zip(messages, signatures)
                    ):
                        context = None if position % 2 else f"c{indices[position]}"
                        self.assertTrue(
                            merkle_verify(
                                message,
                                signature,
                                signer.public_key,
                                context=context,
                            )
                        )


class SignSelectedContextsValidationTest(unittest.TestCase):
    def test_container_type_errors(self):
        for variant in (
            lambda c: make_signer().sign_selected(
                INDICES, MESSAGES, contexts=c
            ),
            lambda c: make_signer().sign_selected_with_checkpoint(
                INDICES, MESSAGES, contexts=c
            ),
        ):
            for bad in ([b"a", None], "ctx", 42, b"ctx"):
                with self.subTest(bad=type(bad).__name__):
                    with self.assertRaises(TypeError):
                        variant(bad)
        for bad in ([b"a", None], "ctx", 42, b"ctx"):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    make_signer().sign_selected_with_auth_state(
                        INDICES,
                        MESSAGES,
                        key=KEY,
                        generation=0,
                        contexts=bad,
                    )

    def test_member_type_errors(self):
        for bad in BAD_CONTEXTS:
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    make_signer().sign_selected(
                        INDICES, MESSAGES, contexts=(b"a", bad, None)
                    )
                with self.assertRaises(TypeError):
                    make_signer().sign_selected_with_checkpoint(
                        INDICES, MESSAGES, contexts=(b"a", bad, None)
                    )
                with self.assertRaises(TypeError):
                    make_signer().sign_selected_with_auth_state(
                        INDICES,
                        MESSAGES,
                        key=KEY,
                        generation=0,
                        contexts=(b"a", bad, None),
                    )

    def test_message_and_index_type_errors_still_raise(self):
        with self.assertRaises(TypeError):
            make_signer().sign_selected(
                (0, 2, 5), (b"a", 42, b"c"), contexts=CONTEXTS
            )
        with self.assertRaises(TypeError):
            make_signer().sign_selected(
                (0, "2", 5), MESSAGES, contexts=CONTEXTS
            )
        with self.assertRaises(TypeError):
            make_signer().sign_selected(
                [0, 2, 5], MESSAGES, contexts=CONTEXTS
            )

    def test_empty_selection_raises_value_error(self):
        with self.assertRaises(ValueError):
            make_signer().sign_selected((), (), contexts=())
        with self.assertRaises(ValueError):
            make_signer().sign_selected_with_checkpoint(
                (), (), contexts=()
            )
        with self.assertRaises(ValueError):
            make_signer().sign_selected_with_auth_state(
                (), (), key=KEY, generation=0, contexts=()
            )

    def test_length_mismatch_raises_value_error(self):
        for contexts in ((), (b"a",), CONTEXTS + (None,)):
            with self.subTest(count=len(contexts)):
                with self.assertRaises(ValueError):
                    make_signer().sign_selected(
                        INDICES, MESSAGES, contexts=contexts
                    )
                with self.assertRaises(ValueError):
                    make_signer().sign_selected_with_checkpoint(
                        INDICES, MESSAGES, contexts=contexts
                    )
                with self.assertRaises(ValueError):
                    make_signer().sign_selected_with_auth_state(
                        INDICES,
                        MESSAGES,
                        key=KEY,
                        generation=0,
                        contexts=contexts,
                    )

    def test_shared_context_conflict_raises_value_error(self):
        for shared in (b"shared", "shared", bytearray(b"shared")):
            with self.subTest(shared=repr(shared)):
                with self.assertRaises(ValueError):
                    make_signer().sign_selected(
                        INDICES, MESSAGES, context=shared, contexts=CONTEXTS
                    )
                with self.assertRaises(ValueError):
                    make_signer().sign_selected_with_checkpoint(
                        INDICES, MESSAGES, context=shared, contexts=CONTEXTS
                    )
                with self.assertRaises(ValueError):
                    make_signer().sign_selected_with_auth_state(
                        INDICES,
                        MESSAGES,
                        key=KEY,
                        generation=0,
                        context=shared,
                        contexts=CONTEXTS,
                    )

    def test_boolean_duplicate_and_descending_indices_raise_value_error(self):
        bad_selections = (
            ((True, 2, 5), MESSAGES),
            ((0, False, 5), MESSAGES),
            ((2, 2, 5), MESSAGES),
            ((5, 2, 0), MESSAGES),
        )
        for indices, messages in bad_selections:
            with self.subTest(indices=indices):
                with self.assertRaises(ValueError):
                    make_signer().sign_selected(
                        indices, messages, contexts=CONTEXTS
                    )

    def test_type_errors_precede_structure_and_conflict(self):
        # A bad contexts member wins over the length and conflict rules.
        with self.assertRaises(TypeError):
            make_signer().sign_selected(
                INDICES, MESSAGES, context=b"shared", contexts=(42,)
            )
        # A bad message member wins as well.
        with self.assertRaises(TypeError):
            make_signer().sign_selected(
                INDICES, (b"a", 42, b"c"), context=b"shared", contexts=CONTEXTS
            )

    def test_structure_precedes_key_and_generation_checks(self):
        signer = make_signer(height=2)
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0, 1), (b"a", b"b"), key=b"", generation=0
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0, 1),
                (b"a", b"b"),
                key=KEY,
                generation=-1,
            )
        with self.assertRaises(ValueError):
            signer.sign_selected_with_auth_state(
                (0, 1),
                (b"a", b"b"),
                key=KEY,
                generation=0,
                contexts=(b"only-one",),
            )
        # Only after the structure passes do key/generation types surface.
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                (0, 1), (b"a", b"b"), key=42, generation=0
            )
        with self.assertRaises(TypeError):
            signer.sign_selected_with_auth_state(
                (0, 1), (b"a", b"b"), key=KEY, generation=True
            )

    def test_exhaustion_and_range_order(self):
        exhausted = make_signer(height=1)  # leaves 0, 1
        exhausted.advance_to(2)
        with self.assertRaises(KeyExhaustedError):
            exhausted.sign_selected((0,), (b"a",), contexts=(b"c",))
        # Input errors still win on an exhausted signer.
        with self.assertRaises(TypeError):
            exhausted.sign_selected((0,), (123,), contexts=(b"c",))
        with self.assertRaises(TypeError):
            exhausted.sign_selected(
                (0,), (b"a",), contexts=(object(),)
            )
        with self.assertRaises(ValueError):
            exhausted.sign_selected((), (), contexts=())
        # A fresh signer reports an out-of-range index as ValueError.
        fresh = make_signer(height=1)
        with self.assertRaises(ValueError):
            fresh.sign_selected((2,), (b"x",), contexts=(None,))
        with self.assertRaises(ValueError):
            fresh.sign_selected((-1,), (b"x",), contexts=(None,))

    def test_failures_consume_no_leaf_and_return_nothing_partial(self):
        signer = make_signer()
        calls = (
            lambda: signer.sign_selected(
                INDICES, MESSAGES, contexts=(b"a",)
            ),
            lambda: signer.sign_selected(
                INDICES, MESSAGES, contexts=(b"a", 42, None)
            ),
            lambda: signer.sign_selected(
                INDICES, MESSAGES, context=b"shared", contexts=CONTEXTS
            ),
            lambda: signer.sign_selected(
                (1, 1), MESSAGES, contexts=CONTEXTS
            ),
            lambda: signer.sign_selected_with_checkpoint(
                INDICES, MESSAGES, contexts=(b"a",)
            ),
            lambda: signer.sign_selected_with_auth_state(
                INDICES,
                MESSAGES,
                key=KEY,
                generation=0,
                contexts=(b"a",),
            ),
        )
        for call in calls:
            with self.assertRaises((TypeError, ValueError)):
                call()
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.sign(b"ok").index, 0)


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

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertGreaterEqual(len(errors), 3)
        winner_picked = sorted(picked)
        self.assertEqual(winner_picked, sorted(set(winner_picked)))
        self.assertEqual(signer.next_index, max(winner_picked) + 1)

    def test_mixes_linearly_with_sign_advance_and_checkpoint(self):
        height = 3
        signer = make_signer(height=height)
        leaf_count = 1 << height
        results = []
        errors = []
        result_lock = threading.Lock()
        barrier = threading.Barrier(3)

        def selected():
            try:
                barrier.wait(timeout=10)
                signatures = signer.sign_selected(
                    (0, 2, 4, 6),
                    tuple("s0123"),
                    contexts=("a", None, b"c", "d"),
                )
                with result_lock:
                    results.extend(signatures)
            except ValueError:
                pass  # Lost the race against the plain signer.
            except Exception as exc:  # pragma: no cover - failure path
                with result_lock:
                    errors.append(exc)

        def plain():
            try:
                barrier.wait(timeout=10)
                for _ in range(leaf_count):
                    signature = signer.sign("p")
                    with result_lock:
                        results.append(signature)
            except KeyExhaustedError:
                pass
            except Exception as exc:  # pragma: no cover - failure path
                with result_lock:
                    errors.append(exc)

        def snapshot():
            try:
                barrier.wait(timeout=10)
                signer.advance_to(signer.next_index)
                signer.checkpoint()
            except Exception as exc:  # pragma: no cover - failure path
                with result_lock:
                    errors.append(exc)

        threads = [
            threading.Thread(target=selected),
            threading.Thread(target=plain),
            threading.Thread(target=snapshot),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        used = {signature.index for signature in results}
        self.assertEqual(len(used), len(results))
        self.assertEqual(signer.next_index, leaf_count)
        self.assertEqual(signer.remaining, 0)
        # Either the plain signer won the lock first (it then spent every
        # leaf and the selection failed) or the gapped selection won (leaves
        # 0, 2, 4, 6 spent) and the plain signer spent the tail leaf 7.
        self.assertIn(
            used, (set(range(leaf_count)), {0, 2, 4, 6, leaf_count - 1})
        )


if __name__ == "__main__":
    unittest.main()

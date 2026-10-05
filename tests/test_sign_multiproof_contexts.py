"""Per-message context binding (``contexts=``) for the multiproof state entries.

Covers ``MerkleSigner.sign_multiproof_with_checkpoint`` and
``MerkleSigner.sign_multiproof_with_auth_state``: positional per-message
contexts, equivalence with ``sign_batch`` + ``multiproof_encode`` +
``checkpoint``/``auth_state_wrap`` from the same starting state, the fixed
validation order (types, then empty/length/conflict, then the auth
parameters, then capacity), the all-or-nothing state rules, restore from
the returned state, and the unchanged legacy behaviour when ``contexts``
is omitted.
"""

import threading
import unittest

from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    auth_state_unwrap,
    auth_state_wrap,
    multiproof_encode,
    multiproof_verify,
    multiproof_verify_bound,
)
from pqattest.merkle import _MULTIPROOF_HEADER_BYTES

KEY = b"shared-secret-key"
UINT64_MAX = 2**64 - 1

MESSAGES = (b"alpha", "beta/ü", bytearray(b"gamma"))
CONTEXTS = (b"ctx-a", "ctx-b/ü", None)  # None == no context for that slot
CONTEXTS_BYTES = tuple(
    None if c is None else (c.encode("utf-8") if isinstance(c, str) else c)
    for c in CONTEXTS
)

BAD_CONTEXTS = (1, 1.5, ["ctx"], {"ctx": 1}, object())


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=3, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def leaf_indices(blob):
    key_length = int.from_bytes(blob[9:13], "big")
    leaf_count = int.from_bytes(blob[13:15], "big")
    offset = _MULTIPROOF_HEADER_BYTES + key_length
    indices = []
    for _ in range(leaf_count):
        indices.append(int.from_bytes(blob[offset : offset + 2], "big"))
        element_count = int.from_bytes(blob[offset + 2 : offset + 4], "big")
        offset += 4 + element_count * 32
    return indices


def batch_reference(messages, contexts, height=3, w=4, spent=0):
    """Proof and checkpoint built the long way from the same starting state."""
    signer = make_signer(height=height, w=w)
    for i in range(spent):
        signer.sign(f"spent-{i}")
    signatures = signer.sign_batch(messages, contexts=contexts)
    proof = multiproof_encode(signer.public_key, signatures)
    return proof, signer.checkpoint(), signer.public_key


class SignMultiproofWithCheckpointContextsTest(unittest.TestCase):
    def test_proof_and_checkpoint_match_sign_batch_then_encode(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                with self.subTest(w=w, height=height):
                    messages = MESSAGES[: 1 << height][:3] or MESSAGES[:1]
                    contexts = CONTEXTS[: len(messages)]
                    signer = make_signer(height=height, w=w)
                    proof, blob = signer.sign_multiproof_with_checkpoint(
                        messages, contexts=contexts
                    )
                    expected_proof, expected_blob, _ = batch_reference(
                        messages, contexts, height=height, w=w
                    )
                    self.assertEqual(proof, expected_proof)
                    self.assertEqual(blob, expected_blob)

    def test_matches_after_prior_spending(self):
        signer = make_signer()
        signer.sign("spent-0")
        signer.sign_batch(("spent-1", "spent-2"))
        proof, blob = signer.sign_multiproof_with_checkpoint(
            MESSAGES, contexts=CONTEXTS
        )
        expected_proof, expected_blob, _ = batch_reference(
            MESSAGES, CONTEXTS, spent=3
        )
        self.assertEqual(proof, expected_proof)
        self.assertEqual(blob, expected_blob)
        self.assertEqual(leaf_indices(proof), [3, 4, 5])

    def test_verifies_with_matching_contexts(self):
        signer = make_signer()
        public_key = signer.public_key
        proof, _ = signer.sign_multiproof_with_checkpoint(
            MESSAGES, contexts=CONTEXTS
        )
        self.assertTrue(multiproof_verify(MESSAGES, proof, contexts=CONTEXTS))
        self.assertTrue(
            multiproof_verify_bound(
                MESSAGES,
                proof,
                public_key=public_key,
                indices=(0, 1, 2),
                contexts=CONTEXTS,
            )
        )

    def test_wrong_or_missing_context_fails_verification(self):
        signer = make_signer()
        public_key = signer.public_key
        proof, _ = signer.sign_multiproof_with_checkpoint(
            MESSAGES, contexts=CONTEXTS
        )
        # A swapped context at any position fails.
        for position in range(len(MESSAGES)):
            wrong = list(CONTEXTS)
            wrong[position] = b"other"
            wrong = tuple(wrong)
            self.assertFalse(multiproof_verify(MESSAGES, proof, contexts=wrong))
            self.assertFalse(
                multiproof_verify_bound(
                    MESSAGES, proof, public_key=public_key, contexts=wrong
                )
            )
        # Dropping a non-empty context fails too.
        dropped = (None,) + CONTEXTS[1:]
        self.assertFalse(multiproof_verify(MESSAGES, proof, contexts=dropped))
        # The shared-context entries cannot reproduce per-message binding.
        self.assertFalse(multiproof_verify(MESSAGES, proof))
        self.assertFalse(
            multiproof_verify(MESSAGES, proof, context=CONTEXTS_BYTES[0])
        )

    def test_same_message_on_different_leaves_with_different_contexts(self):
        signer = make_signer()
        messages = (b"repeat", b"repeat", b"repeat")
        contexts = (b"one", b"two", None)
        proof, _ = signer.sign_multiproof_with_checkpoint(
            messages, contexts=contexts
        )
        self.assertTrue(multiproof_verify(messages, proof, contexts=contexts))
        self.assertFalse(multiproof_verify(messages, proof, contexts=contexts[::-1]))

    def test_none_and_empty_members_mean_no_context(self):
        contexts = (None, b"", "", bytearray())
        messages = ("m0", "m1", "m2", "m3")
        signer = make_signer()
        proof, blob = signer.sign_multiproof_with_checkpoint(
            messages, contexts=contexts
        )
        reference = make_signer()
        legacy_proof, legacy_blob = reference.sign_multiproof_with_checkpoint(
            messages
        )
        self.assertEqual(proof, legacy_proof)
        self.assertEqual(blob, legacy_blob)
        self.assertTrue(multiproof_verify(messages, proof, contexts=contexts))
        self.assertTrue(multiproof_verify(messages, proof))

    def test_omitted_contexts_keeps_legacy_shared_context_behaviour(self):
        signer = make_signer()
        proof, blob = signer.sign_multiproof_with_checkpoint(
            MESSAGES, context="shared"
        )
        reference = make_signer()
        signatures = reference.sign_batch(MESSAGES, context="shared")
        self.assertEqual(
            proof, multiproof_encode(reference.public_key, signatures)
        )
        self.assertEqual(blob, reference.checkpoint())
        self.assertTrue(multiproof_verify(MESSAGES, proof, context="shared"))

    def test_restore_continues_after_the_batch(self):
        signer = make_signer()
        public_key = signer.public_key
        proof, blob = signer.sign_multiproof_with_checkpoint(
            MESSAGES, contexts=CONTEXTS
        )
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, public_key)
        self.assertEqual(restored.next_index, len(MESSAGES))
        follow_up = restored.sign("follow-up", context="next")
        self.assertEqual(follow_up.index, len(MESSAGES))
        self.assertEqual(restored.next_index, len(MESSAGES) + 1)

    def test_restore_exactly_exhausted(self):
        signer = make_signer(height=1)  # exactly two leaves
        proof, blob = signer.sign_multiproof_with_checkpoint(
            ("only", "two"), contexts=("ctx", None)
        )
        self.assertEqual(signer.remaining, 0)
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("nope")

    def test_contexts_not_written_into_proof_or_checkpoint(self):
        signer = make_signer()
        proof, blob = signer.sign_multiproof_with_checkpoint(
            MESSAGES, contexts=CONTEXTS
        )
        # The proof is exactly the existing v1 encoding of the signatures.
        reference = make_signer()
        signatures = reference.sign_batch(MESSAGES, contexts=CONTEXTS)
        self.assertEqual(proof, multiproof_encode(reference.public_key, signatures))
        # The checkpoint restores through the existing v1 entry unchanged.
        restored = MerkleSigner.from_checkpoint(blob)
        self.assertEqual(restored.checkpoint(), blob)

    def test_type_errors_before_value_errors_before_capacity(self):
        signer = make_signer()
        before = signer.next_index
        # Non-tuple containers and illegal members raise TypeError ...
        for bad in ([b"ctx"], "ctx", b"ctx", 1):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    signer.sign_multiproof_with_checkpoint(
                        MESSAGES, contexts=bad
                    )
        for member in BAD_CONTEXTS:
            with self.subTest(member=member):
                with self.assertRaises(TypeError):
                    signer.sign_multiproof_with_checkpoint(
                        MESSAGES, contexts=(None, member, None)
                    )
        with self.assertRaises(TypeError):
            signer.sign_multiproof_with_checkpoint(["a", "b"], contexts=(None, None))
        with self.assertRaises(TypeError):
            signer.sign_multiproof_with_checkpoint(
                MESSAGES, contexts=(None, None, None, None)[:3] + (1,)
            )
        # ... then the value rules raise ValueError ...
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_checkpoint((), contexts=())
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_checkpoint(
                MESSAGES, contexts=(None, None)
            )
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_checkpoint(
                MESSAGES, context="shared", contexts=CONTEXTS
            )
        # ... and only then does capacity raise KeyExhaustedError.
        signer.advance_to(signer.next_index + (1 << 3) - 1)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_multiproof_with_checkpoint(
                ("a", "b"), contexts=(None, None)
            )
        self.assertEqual(signer.remaining, 1)
        # A legal one-message batch still fits afterwards: nothing was spent.
        proof, _ = signer.sign_multiproof_with_checkpoint(
            ("last",), contexts=("ctx",)
        )
        self.assertEqual(leaf_indices(proof), [(1 << 3) - 1])
        self.assertEqual(signer.remaining, 0)

    def test_failures_leave_state_untouched(self):
        signer = make_signer()
        before_blob = signer.checkpoint()
        for call in (
            lambda: signer.sign_multiproof_with_checkpoint(
                MESSAGES, contexts=[b"ctx"] * 3
            ),
            lambda: signer.sign_multiproof_with_checkpoint(
                MESSAGES, contexts=(None, 1, None)
            ),
            lambda: signer.sign_multiproof_with_checkpoint(
                MESSAGES, contexts=(None, None)
            ),
            lambda: signer.sign_multiproof_with_checkpoint(
                MESSAGES, context="shared", contexts=CONTEXTS
            ),
            lambda: signer.sign_multiproof_with_checkpoint(
                tuple(f"m{i}" for i in range(9)),
                contexts=tuple(None for _ in range(9)),
            ),
        ):
            with self.assertRaises((TypeError, ValueError, KeyExhaustedError)):
                call()
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.checkpoint(), before_blob)


class SignMultiproofWithAuthStateContextsTest(unittest.TestCase):
    def test_proof_and_envelope_match_long_way_round(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                with self.subTest(w=w, height=height):
                    messages = MESSAGES[: 1 << height][:3] or MESSAGES[:1]
                    contexts = CONTEXTS[: len(messages)]
                    signer = make_signer(height=height, w=w)
                    proof, envelope = signer.sign_multiproof_with_auth_state(
                        messages, key=KEY, generation=7, contexts=contexts
                    )
                    expected_proof, expected_blob, _ = batch_reference(
                        messages, contexts, height=height, w=w
                    )
                    self.assertEqual(proof, expected_proof)
                    self.assertEqual(
                        envelope,
                        auth_state_wrap(
                            expected_blob,
                            scheme="merkle",
                            key=KEY,
                            generation=7,
                        ),
                    )

    def test_generation_is_not_auto_incremented(self):
        signer = make_signer()
        _, first = signer.sign_multiproof_with_auth_state(
            ("a",), key=KEY, generation=9, contexts=(None,)
        )
        _, second = signer.sign_multiproof_with_auth_state(
            ("b",), key=KEY, generation=9, contexts=(b"ctx",)
        )
        self.assertEqual(auth_state_unwrap(first, key=KEY)[1], 9)
        self.assertEqual(auth_state_unwrap(second, key=KEY)[1], 9)
        self.assertNotEqual(first, second)

    def test_verifies_with_matching_contexts(self):
        signer = make_signer()
        public_key = signer.public_key
        proof, _ = signer.sign_multiproof_with_auth_state(
            MESSAGES, key=KEY, generation=0, contexts=CONTEXTS
        )
        self.assertTrue(multiproof_verify(MESSAGES, proof, contexts=CONTEXTS))
        self.assertTrue(
            multiproof_verify_bound(
                MESSAGES,
                proof,
                public_key=public_key,
                indices=(0, 1, 2),
                contexts=CONTEXTS,
            )
        )
        wrong = (b"other", CONTEXTS[1], CONTEXTS[2])
        self.assertFalse(multiproof_verify(MESSAGES, proof, contexts=wrong))
        dropped = (None, CONTEXTS[1], CONTEXTS[2])
        self.assertFalse(multiproof_verify(MESSAGES, proof, contexts=dropped))

    def test_restore_from_envelope_continues_after_the_batch(self):
        signer = make_signer()
        public_key = signer.public_key
        _, envelope = signer.sign_multiproof_with_auth_state(
            MESSAGES, key=KEY, generation=UINT64_MAX, contexts=CONTEXTS
        )
        restored, generation = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(generation, UINT64_MAX)
        self.assertEqual(restored.public_key, public_key)
        self.assertEqual(restored.next_index, len(MESSAGES))
        follow_up = restored.sign("follow-up")
        self.assertEqual(follow_up.index, len(MESSAGES))

    def test_restore_exactly_exhausted(self):
        signer = make_signer(height=1)
        _, envelope = signer.sign_multiproof_with_auth_state(
            ("only", "two"), key=KEY, generation=0, contexts=("ctx", None)
        )
        restored, _ = MerkleSigner.from_auth_state(envelope, key=KEY)
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("nope")

    def test_omitted_contexts_keeps_legacy_behaviour(self):
        signer = make_signer()
        proof, envelope = signer.sign_multiproof_with_auth_state(
            MESSAGES, key=KEY, generation=3
        )
        reference = make_signer()
        signatures = reference.sign_batch(MESSAGES)
        self.assertEqual(
            proof, multiproof_encode(reference.public_key, signatures)
        )
        self.assertEqual(
            envelope,
            auth_state_wrap(
                reference.checkpoint(), scheme="merkle", key=KEY, generation=3
            ),
        )
        self.assertTrue(multiproof_verify(MESSAGES, proof))

    def test_validation_order_types_then_values_then_auth_then_capacity(self):
        signer = make_signer()
        # Message/context type errors beat every later check, including a
        # bad key type.
        with self.assertRaises(TypeError):
            signer.sign_multiproof_with_auth_state(
                MESSAGES, key=1, generation="x", contexts=[b"ctx"] * 3
            )
        with self.assertRaises(TypeError):
            signer.sign_multiproof_with_auth_state(
                MESSAGES, key=1, generation="x", contexts=(None, 2, None)
            )
        # Empty/length/conflict ValueErrors beat the auth parameters.
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_auth_state(
                (), key=b"", generation=-1, contexts=()
            )
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_auth_state(
                MESSAGES, key=b"", generation=-1, contexts=(None, None)
            )
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_auth_state(
                MESSAGES,
                key=b"",
                generation=-1,
                context="shared",
                contexts=CONTEXTS,
            )
        # Then the auth parameters themselves.
        with self.assertRaises(TypeError):
            signer.sign_multiproof_with_auth_state(
                MESSAGES, key="secret", generation=0, contexts=CONTEXTS
            )
        with self.assertRaises(TypeError):
            signer.sign_multiproof_with_auth_state(
                MESSAGES, key=KEY, generation=True, contexts=CONTEXTS
            )
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_auth_state(
                MESSAGES, key=b"", generation=0, contexts=CONTEXTS
            )
        with self.assertRaises(ValueError):
            signer.sign_multiproof_with_auth_state(
                MESSAGES, key=KEY, generation=UINT64_MAX + 1, contexts=CONTEXTS
            )
        # Capacity comes last.
        signer.advance_to((1 << 3) - 1)
        with self.assertRaises(KeyExhaustedError):
            signer.sign_multiproof_with_auth_state(
                ("a", "b"), key=KEY, generation=0, contexts=(None, None)
            )
        self.assertEqual(signer.remaining, 1)
        self.assertEqual(signer.next_index, (1 << 3) - 1)

    def test_failures_leave_state_untouched(self):
        signer = make_signer()
        before_blob = signer.checkpoint()
        calls = (
            lambda: signer.sign_multiproof_with_auth_state(
                MESSAGES, key=KEY, generation=0, contexts="ctx"
            ),
            lambda: signer.sign_multiproof_with_auth_state(
                MESSAGES, key=KEY, generation=0, contexts=(None, None)
            ),
            lambda: signer.sign_multiproof_with_auth_state(
                MESSAGES, key=b"", generation=0, contexts=CONTEXTS
            ),
            lambda: signer.sign_multiproof_with_auth_state(
                MESSAGES, key=KEY, generation=-1, contexts=CONTEXTS
            ),
            lambda: signer.sign_multiproof_with_auth_state(
                tuple(f"m{i}" for i in range(9)),
                key=KEY,
                generation=0,
                contexts=tuple(None for _ in range(9)),
            ),
        )
        for call in calls:
            with self.assertRaises((TypeError, ValueError, KeyExhaustedError)):
                call()
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.checkpoint(), before_blob)


class SignMultiproofContextsConcurrencyTest(unittest.TestCase):
    def test_no_leaf_is_allocated_twice_and_no_half_batch_is_seen(self):
        height = 4
        leaf_count = 1 << height
        signer = make_signer(height=height)
        results = []
        snapshots = []
        errors = []
        barrier = threading.Barrier(leaf_count // 2)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                if i % 2 == 0:
                    messages = (f"m{i}a", f"m{i}b")
                    contexts = (f"ctx-{i}", None)
                    proof, blob = signer.sign_multiproof_with_checkpoint(
                        messages, contexts=contexts
                    )
                    results.append((messages, contexts, proof, blob))
                else:
                    snapshots.append(signer.checkpoint())
            except KeyExhaustedError:
                pass
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(i,))
            for i in range(leaf_count // 2)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])

        used = sorted(
            index for _, _, proof, _ in results for index in leaf_indices(proof)
        )
        self.assertEqual(len(used), len(set(used)))
        for messages, contexts, proof, blob in results:
            with self.subTest(indices=leaf_indices(proof)):
                self.assertTrue(
                    multiproof_verify(messages, proof, contexts=contexts)
                )
                restored = MerkleSigner.from_checkpoint(blob)
                self.assertEqual(restored.public_key, signer.public_key)
                self.assertEqual(
                    restored.next_index, leaf_indices(proof)[-1] + 1
                )
        for blob in snapshots:
            restored = MerkleSigner.from_checkpoint(blob)
            self.assertEqual(restored.public_key, signer.public_key)


if __name__ == "__main__":
    unittest.main()

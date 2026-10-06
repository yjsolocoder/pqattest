import itertools
import unittest

from pqattest import (
    MerkleSigner,
    merkle_verify_profile,
    multiproof_encode,
    multiproof_expand,
    multiproof_merge,
    multiproof_partition,
    multiproof_select,
    multiproof_verify,
)
from pqattest.merkle import _multiproof_parse


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=3, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def make_proof(height=3, w=4, count=None, start=0, context=None,
               contexts=None, keep=None):
    signer = make_signer(height=height, w=w, start=start)
    leaf_count = 1 << height
    if count is None and keep is None:
        count = leaf_count
    if keep is not None:
        messages = tuple(f"message-{i}" for i in keep)
        if contexts is not None:
            signatures = signer.sign_selected(
                tuple(keep), messages, contexts=contexts
            )
        elif context is not None:
            signatures = signer.sign_selected(
                tuple(keep), messages, context=context
            )
        else:
            signatures = signer.sign_selected(tuple(keep), messages)
    else:
        messages = tuple(f"message-{i}" for i in range(count))
        if contexts is not None:
            signatures = signer.sign_batch(messages, contexts=contexts)
        elif context is not None:
            signatures = signer.sign_batch(messages, context=context)
        else:
            signatures = signer.sign_batch(messages)
    proof = multiproof_encode(signer.public_key, signatures)
    return signer.public_key, messages, signatures, proof


def proof_hashes(public_key, indices):
    """wots + leaf + multi the profile bills an actual leaf-index tuple."""
    profile = merkle_verify_profile(public_key.w, public_key.height, indices)
    return profile.wots + profile.leaf + profile.multi


def verify_key(public_key, packets):
    """The ``prefer="verify"`` key of a returned packet tuple."""
    total_hashes = 0
    ends = ()
    for packet in packets:
        _, leaves, _ = _multiproof_parse(packet)
        indices = tuple(index for index, _ in leaves)
        total_hashes += proof_hashes(public_key, indices)
        ends += (indices[-1],)
    return (
        total_hashes,
        len(packets),
        sum(len(packet) for packet in packets),
        ends,
    )


def compact_key(public_key, packets):
    """The historical ``prefer="compact"`` key of a returned packet tuple."""
    ends = ()
    for packet in packets:
        _, packet_leaves, _ = _multiproof_parse(packet)
        ends += (packet_leaves[-1][0],)
    return (
        len(packets),
        sum(len(packet) for packet in packets),
        ends,
    )


def brute_force_verify_key(
    messages,
    proof,
    public_key,
    byte_budget,
    hash_budget,
    total_budget,
    context=None,
    contexts=None,
):
    """Exhaustively minimise the verify-mode key under every active budget.

    Every fragment must fit the per-packet byte and verification-hash
    budgets and the fragments' bills must sum to at most the total budget;
    among the survivors the key ``(total hashes, packet count, total bytes,
    last-leaf indices)`` is minimised. Returns ``None`` when no
    fragmentation is feasible.
    """
    expand_kwargs = {}
    if contexts is not None:
        expand_kwargs["contexts"] = contexts
    elif context is not None:
        expand_kwargs["context"] = context
    batch = multiproof_expand(
        messages, proof, public_key=public_key, **expand_kwargs
    )
    signatures = batch.signatures
    n = len(signatures)
    sizes, hashes = {}, {}
    for start in range(n):
        for end in range(start + 1, n + 1):
            fragment = tuple(signatures[start:end])
            sizes[(start, end)] = len(
                multiproof_encode(public_key, fragment)
            )
            hashes[(start, end)] = proof_hashes(
                public_key,
                tuple(signature.index for signature in fragment),
            )
    best = None
    for cuts in range(1, n + 1):
        for inner in itertools.combinations(range(1, n), cuts - 1):
            bounds = (0,) + inner + (n,)
            total_bytes = 0
            total_hashes = 0
            ends = ()
            for start, end in zip(bounds, bounds[1:]):
                size = sizes[(start, end)]
                work = hashes[(start, end)]
                if size > byte_budget:
                    break
                if hash_budget is not None and work > hash_budget:
                    break
                total_bytes += size
                total_hashes += work
                ends += (signatures[end - 1].index,)
            else:
                if total_budget is not None and total_hashes > total_budget:
                    continue
                candidate = (total_hashes, cuts, total_bytes, ends)
                if best is None or candidate < best:
                    best = candidate
    return best


class TestPreferValidation(unittest.TestCase):
    def test_non_string_raises_type_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        for bad in (None, 1, 1.5, True, False, b"verify", bytearray(b"verify"),
                    ("verify",), ["compact"], object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    multiproof_partition(
                        messages,
                        proof,
                        public_key=public_key,
                        max_bytes=len(proof),
                        prefer=bad,
                    )

    def test_unknown_string_raises_value_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        for bad in ("", "Compact", "COMPACT", "Verify", "VERIFY",
                    " compact", "compact ", "verify ", "verify\n",
                    "optimal", "compact\0"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    multiproof_partition(
                        messages,
                        proof,
                        public_key=public_key,
                        max_bytes=len(proof),
                        prefer=bad,
                    )

    def test_type_check_precedes_content_check(self):
        public_key, messages, _, proof = make_proof(height=2)
        # Empty messages are a content error, but a wrongly typed prefer
        # must still raise TypeError first.
        with self.assertRaises(TypeError):
            multiproof_partition(
                (),
                proof,
                public_key=public_key,
                max_bytes=len(proof),
                prefer=1,
            )
        # An unknown prefer string is a content error, raised only after
        # every type check passes.
        with self.assertRaises(ValueError):
            multiproof_partition(
                (),
                proof,
                public_key=public_key,
                max_bytes=len(proof),
                prefer="optimal",
            )
        with self.assertRaises(TypeError):
            multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes="100",
                prefer="optimal",
            )

    def test_keyword_only(self):
        public_key, messages, _, proof = make_proof(height=2)
        with self.assertRaises(TypeError):
            multiproof_partition(
                messages,
                proof,
                public_key,
                len(proof),
                None,
                None,
                None,
                None,
                "verify",
            )


class TestPreferCompactCompatibility(unittest.TestCase):
    def test_omitted_and_compact_match_exactly(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                public_key, messages, _, proof = make_proof(w=w, height=height)
                budgets = [len(proof), max(1, len(proof) // 2),
                           max(1, len(proof) // 3)]
                for budget in budgets:
                    for extra in (
                        {},
                        {"max_verify_hashes": proof_hashes(
                            public_key, tuple(range(1 << height)))},
                        {"max_total_verify_hashes": proof_hashes(
                            public_key, tuple(range(1 << height)))},
                    ):
                        with self.subTest(w=w, height=height, budget=budget,
                                          extra=tuple(extra)):
                            try:
                                expected = multiproof_partition(
                                    messages,
                                    proof,
                                    public_key=public_key,
                                    max_bytes=budget,
                                    **extra,
                                )
                            except ValueError:
                                continue
                            self.assertEqual(
                                multiproof_partition(
                                    messages,
                                    proof,
                                    public_key=public_key,
                                    max_bytes=budget,
                                    prefer="compact",
                                    **extra,
                                ),
                                expected,
                            )

    def test_compact_preserves_existing_exceptions(self):
        public_key, messages, _, proof = make_proof(height=3)
        with self.assertRaises(ValueError) as without:
            multiproof_partition(
                messages, proof, public_key=public_key, max_bytes=1
            )
        with self.assertRaises(ValueError) as with_compact:
            multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=1,
                prefer="compact",
            )
        self.assertEqual(str(without.exception), str(with_compact.exception))

    def test_compact_with_contexts_matches_omitted(self):
        contexts = (None, "alpha", "", "beta")
        public_key, messages, _, proof = make_proof(
            height=2, contexts=contexts
        )
        budget = max(1, len(proof) // 2)
        try:
            expected = multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=budget,
                contexts=contexts,
            )
        except ValueError:
            self.skipTest("no feasible fragmentation at this budget")
        self.assertEqual(
            multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=budget,
                contexts=contexts,
                prefer="compact",
            ),
            expected,
        )


class TestPreferVerifySemantics(unittest.TestCase):
    def test_source_fitting_all_budgets_returns_source_bytes(self):
        for w in (4, 8):
            for height in (1, 2, 4):
                public_key, messages, _, proof = make_proof(w=w, height=height)
                with self.subTest(w=w, height=height):
                    self.assertEqual(
                        multiproof_partition(
                            messages,
                            proof,
                            public_key=public_key,
                            max_bytes=len(proof),
                            prefer="verify",
                        ),
                        (bytes(proof),),
                    )
                    self.assertEqual(
                        multiproof_partition(
                            messages,
                            proof,
                            public_key=public_key,
                            max_bytes=len(proof),
                            max_verify_hashes=proof_hashes(
                                public_key, tuple(range(1 << height))
                            ),
                            max_total_verify_hashes=proof_hashes(
                                public_key, tuple(range(1 << height))
                            ),
                            prefer="verify",
                        ),
                        (bytes(proof),),
                    )

    def test_matches_brute_force(self):
        # Full trees for the small heights, sparse leaf sets for the tall
        # ones so the exhaustive enumeration stays small.
        cases = []
        for height in (1, 2, 3):
            cases.append((height, None))
        cases.append((4, (0, 1, 5, 9, 15)))
        cases.append((5, (0, 3, 16, 17, 31)))
        cases.append((6, (1, 2, 8, 33, 63)))
        cases.append((7, (0, 64, 65, 100, 127)))
        cases.append((8, (0, 1, 128, 200, 255)))
        for w in (4, 8):
            for height, keep in cases:
                public_key, messages, _, proof = make_proof(
                    w=w, height=height, keep=keep
                )
                if keep is None:
                    indices = tuple(range(1 << height))
                else:
                    indices = keep
                full_hashes = proof_hashes(public_key, indices)
                budget_sets = [
                    (len(proof), None, None),
                    (max(1, len(proof) // 2), None, None),
                    (max(1, len(proof) // 3), None, None),
                    (max(1, len(proof) // 2), full_hashes, None),
                    (max(1, len(proof) // 2), None, full_hashes * 2),
                    (max(1, len(proof) // 3), full_hashes, full_hashes * 2),
                ]
                for byte_budget, hash_budget, total_budget in budget_sets:
                    with self.subTest(w=w, height=height, keep=keep,
                                      budgets=(byte_budget, hash_budget,
                                               total_budget)):
                        expected = brute_force_verify_key(
                            messages,
                            proof,
                            public_key,
                            byte_budget,
                            hash_budget,
                            total_budget,
                        )
                        if expected is None:
                            with self.assertRaises(ValueError):
                                multiproof_partition(
                                    messages,
                                    proof,
                                    public_key=public_key,
                                    max_bytes=byte_budget,
                                    max_verify_hashes=hash_budget,
                                    max_total_verify_hashes=total_budget,
                                    prefer="verify",
                                )
                            continue
                        packets = multiproof_partition(
                            messages,
                            proof,
                            public_key=public_key,
                            max_bytes=byte_budget,
                            max_verify_hashes=hash_budget,
                            max_total_verify_hashes=total_budget,
                            prefer="verify",
                        )
                        self.assertEqual(
                            verify_key(public_key, packets), expected
                        )

    def test_verify_prefers_fewer_hashes_over_fewer_packets(self):
        # At this budget the compact optimum is three packets billing 8061
        # hashes, while a four-packet fragmentation bills only 8060.
        public_key, messages, _, proof = make_proof(w=4, height=3)
        compact = multiproof_partition(
            messages, proof, public_key=public_key, max_bytes=6574
        )
        verify = multiproof_partition(
            messages, proof, public_key=public_key, max_bytes=6574,
            prefer="verify",
        )
        self.assertEqual(
            compact_key(public_key, compact), (3, 17644, (2, 4, 7))
        )
        self.assertEqual(
            verify_key(public_key, verify), (8060, 4, 17704, (1, 3, 5, 7))
        )
        self.assertNotEqual(compact, verify)

    def test_packets_match_select_and_merge_restores_source(self):
        for w in (4, 8):
            public_key, messages, _, proof = make_proof(w=w, height=3)
            budget = max(1, len(proof) // 2)
            packets = multiproof_partition(
                messages, proof, public_key=public_key, max_bytes=budget,
                prefer="verify",
            )
            position = 0
            groups = []
            for packet in packets:
                _, packet_leaves, _ = _multiproof_parse(packet)
                count = len(packet_leaves)
                fragment = messages[position:position + count]
                groups.append(fragment)
                expected = multiproof_select(
                    messages,
                    proof,
                    public_key=public_key,
                    indices=tuple(
                        index for index, _ in packet_leaves
                    ),
                )
                self.assertEqual(packet, expected)
                self.assertTrue(multiproof_verify(fragment, packet))
                position += count
            self.assertEqual(position, len(messages))
            self.assertEqual(
                multiproof_merge(
                    tuple(groups), packets, public_key=public_key
                ),
                bytes(proof),
            )

    def test_shared_and_per_leaf_contexts(self):
        public_key, messages, _, proof = make_proof(height=3, context="shared")
        budget = max(1, len(proof) // 2)
        expected = brute_force_verify_key(
            messages, proof, public_key, budget, None, None, context="shared"
        )
        packets = multiproof_partition(
            messages, proof, public_key=public_key, max_bytes=budget,
            context="shared", prefer="verify",
        )
        self.assertEqual(verify_key(public_key, packets), expected)

        contexts = tuple(f"ctx-{i}" if i % 2 else None for i in range(8))
        public_key, messages, _, proof = make_proof(
            height=3, contexts=contexts
        )
        budget = max(1, len(proof) // 2)
        expected = brute_force_verify_key(
            messages, proof, public_key, budget, None, None, contexts=contexts
        )
        packets = multiproof_partition(
            messages, proof, public_key=public_key, max_bytes=budget,
            contexts=contexts, prefer="verify",
        )
        self.assertEqual(verify_key(public_key, packets), expected)
        position = 0
        for packet in packets:
            _, packet_leaves, _ = _multiproof_parse(packet)
            count = len(packet_leaves)
            self.assertTrue(
                multiproof_verify(
                    messages[position:position + count],
                    packet,
                    contexts=contexts[position:position + count],
                )
            )
            position += count

    def test_equality_with_limits_is_allowed(self):
        public_key, messages, _, proof = make_proof(w=4, height=3)
        budget = max(1, len(proof) // 2)
        packets = multiproof_partition(
            messages, proof, public_key=public_key, max_bytes=budget,
            prefer="verify",
        )
        biggest = max(len(packet) for packet in packets)
        self.assertEqual(
            multiproof_partition(
                messages, proof, public_key=public_key, max_bytes=biggest,
                prefer="verify",
            ),
            packets,
        )
        total_hashes, _, _, _ = verify_key(public_key, packets)
        per_packet = []
        for packet in packets:
            _, packet_leaves, _ = _multiproof_parse(packet)
            per_packet.append(
                proof_hashes(
                    public_key, tuple(i for i, _ in packet_leaves)
                )
            )
        self.assertEqual(
            multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=biggest,
                max_verify_hashes=max(per_packet),
                max_total_verify_hashes=total_hashes,
                prefer="verify",
            ),
            packets,
        )

    def test_infeasible_raises_value_error(self):
        public_key, messages, _, proof = make_proof(height=3)
        for extra in ({}, {"max_verify_hashes": 1},
                      {"max_total_verify_hashes": 1}):
            with self.subTest(extra=tuple(extra)):
                with self.assertRaises(ValueError):
                    multiproof_partition(
                        messages,
                        proof,
                        public_key=public_key,
                        max_bytes=1,
                        prefer="verify",
                        **extra,
                    )

    def test_deterministic_and_inputs_unchanged(self):
        public_key, messages, _, proof = make_proof(height=3)
        data = bytearray(proof)
        before = bytes(data)
        budget = max(1, len(proof) // 2)
        first = multiproof_partition(
            messages, data, public_key=public_key, max_bytes=budget,
            prefer="verify",
        )
        second = multiproof_partition(
            messages, data, public_key=public_key, max_bytes=budget,
            prefer="verify",
        )
        self.assertEqual(first, second)
        self.assertEqual(bytes(data), before)
        self.assertTrue(all(isinstance(packet, bytes) for packet in first))


if __name__ == "__main__":
    unittest.main()

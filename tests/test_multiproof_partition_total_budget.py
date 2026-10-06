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


def packet_key(packets):
    """The optimisation key of a fragmentation: (count, bytes, end indices)."""
    return (
        len(packets),
        sum(len(packet) for packet in packets),
        tuple(_multiproof_parse(packet)[1][-1][0] for packet in packets),
    )


def verify_hashes(public_key, packet):
    """wots + leaf + multi the profile bills a packet's leaf set."""
    _, leaves, _ = _multiproof_parse(packet)
    indices = tuple(index for index, _ in leaves)
    profile = merkle_verify_profile(public_key.w, public_key.height, indices)
    return profile.wots + profile.leaf + profile.multi


def proof_hashes(public_key, indices):
    """wots + leaf + multi the profile bills an actual leaf-index tuple."""
    profile = merkle_verify_profile(public_key.w, public_key.height, indices)
    return profile.wots + profile.leaf + profile.multi


def brute_force_total_key(
    messages,
    proof,
    public_key,
    byte_budget,
    hash_budget,
    total_budget,
    context=None,
    contexts=None,
):
    """Exhaustively minimise the partition key under all three budgets.

    Every fragment must fit the per-packet byte and verification-hash
    budgets, and the fragments' verification-hash bills must sum to at most
    the total budget; among the survivors the usual
    ``(count, bytes, end indices)`` key is minimised.
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
                candidate = (cuts, total_bytes, ends)
                if best is None or candidate < best:
                    best = candidate
    return best


class TestTotalBudgetValidation(unittest.TestCase):
    def test_none_matches_omitted_exactly(self):
        for w in (4, 8):
            for height in (1, 2, 3, 5):
                public_key, messages, _, proof = make_proof(w=w, height=height)
                for divisor in (1, 2, 3):
                    budget = max(1, len(proof) // divisor)
                    with self.subTest(w=w, height=height, divisor=divisor):
                        try:
                            expected = multiproof_partition(
                                messages,
                                proof,
                                public_key=public_key,
                                max_bytes=budget,
                            )
                        except ValueError:
                            continue
                        for keyword in ({}, {"max_total_verify_hashes": None}):
                            self.assertEqual(
                                multiproof_partition(
                                    messages,
                                    proof,
                                    public_key=public_key,
                                    max_bytes=budget,
                                    **keyword,
                                ),
                                expected,
                            )

    def test_none_preserves_existing_exceptions(self):
        public_key, messages, _, proof = make_proof(height=3)
        with self.assertRaises(ValueError) as without:
            multiproof_partition(
                messages, proof, public_key=public_key, max_bytes=1
            )
        with self.assertRaises(ValueError) as with_none:
            multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=1,
                max_total_verify_hashes=None,
            )
        self.assertEqual(str(without.exception), str(with_none.exception))

    def test_non_integer_raises_type_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        for bad in ("100", 1.5, b"100", bytearray(1), (100,), [100], object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    multiproof_partition(
                        messages,
                        proof,
                        public_key=public_key,
                        max_bytes=len(proof),
                        max_total_verify_hashes=bad,
                    )

    def test_boolean_zero_and_negative_raise_value_error(self):
        public_key, messages, _, proof = make_proof(height=2)
        for bad in (True, False, 0, -1, -10**6):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    multiproof_partition(
                        messages,
                        proof,
                        public_key=public_key,
                        max_bytes=len(proof),
                        max_total_verify_hashes=bad,
                    )

    def test_type_check_precedes_content_check(self):
        public_key, messages, _, proof = make_proof(height=2)
        # Empty messages are a content error, but a wrongly typed budget
        # must still raise TypeError first.
        with self.assertRaises(TypeError):
            multiproof_partition(
                (),
                proof,
                public_key=public_key,
                max_bytes=len(proof),
                max_total_verify_hashes="100",
            )
        # A non-positive budget is still rejected before content checks.
        with self.assertRaises(ValueError):
            multiproof_partition(
                (),
                proof,
                public_key=public_key,
                max_bytes=len(proof),
                max_total_verify_hashes=0,
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
                100,
            )


class TestTotalBudgetSemantics(unittest.TestCase):
    def test_source_fitting_all_budgets_returns_source_bytes(self):
        for w in (4, 8):
            for height in (1, 2, 4):
                public_key, messages, _, proof = make_proof(w=w, height=height)
                indices = tuple(index for index, _ in _multiproof_parse(proof)[1])
                total = proof_hashes(public_key, indices)
                with self.subTest(w=w, height=height):
                    for budget in (total, total + 1, 10**9):
                        packets = multiproof_partition(
                            messages,
                            proof,
                            public_key=public_key,
                            max_bytes=len(proof),
                            max_total_verify_hashes=budget,
                        )
                        self.assertEqual(packets, (proof,))
                        self.assertIsInstance(packets[0], bytes)

    def test_total_below_single_packet_cost_is_infeasible(self):
        # Splitting can only add deduplicated internal-node work, so no
        # fragmentation bills less than the undivided source proof.
        public_key, messages, _, proof = make_proof(height=3)
        indices = tuple(index for index, _ in _multiproof_parse(proof)[1])
        total = proof_hashes(public_key, indices)
        with self.assertRaises(ValueError):
            multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=len(proof),
                max_total_verify_hashes=total - 1,
            )

    def test_returned_packets_respect_total_budget(self):
        for w in (4, 8):
            public_key, messages, _, proof = make_proof(w=w, height=4)
            indices = tuple(index for index, _ in _multiproof_parse(proof)[1])
            full = proof_hashes(public_key, indices)
            byte_budget = len(proof) // 3
            for total_budget in (full * 3, full * 2, full + full // 2):
                with self.subTest(w=w, total_budget=total_budget):
                    try:
                        packets = multiproof_partition(
                            messages,
                            proof,
                            public_key=public_key,
                            max_bytes=byte_budget,
                            max_total_verify_hashes=total_budget,
                        )
                    except ValueError:
                        continue
                    billed = sum(
                        verify_hashes(public_key, packet) for packet in packets
                    )
                    self.assertLessEqual(billed, total_budget)
                    for packet in packets:
                        self.assertLessEqual(len(packet), byte_budget)

    def test_total_budget_is_sum_of_per_packet_profiles(self):
        # The bill is the sum over the returned packets of each packet's own
        # profile total, not the undivided source proof's profile.
        public_key, messages, _, proof = make_proof(height=4)
        indices = tuple(index for index, _ in _multiproof_parse(proof)[1])
        source_cost = proof_hashes(public_key, indices)
        byte_budget = len(proof) // 3
        packets = multiproof_partition(
            messages,
            proof,
            public_key=public_key,
            max_bytes=byte_budget,
        )
        self.assertGreater(len(packets), 1)
        billed = sum(verify_hashes(public_key, packet) for packet in packets)
        self.assertGreater(billed, source_cost)
        # Equality with the partitioned bill returns the baseline
        # fragmentation unchanged; one less must either raise or return a
        # different, genuinely cheaper fragmentation.
        self.assertEqual(
            multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=byte_budget,
                max_total_verify_hashes=billed,
            ),
            packets,
        )
        try:
            cheaper = multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=byte_budget,
                max_total_verify_hashes=billed - 1,
            )
        except ValueError:
            return
        self.assertLessEqual(
            sum(verify_hashes(public_key, packet) for packet in cheaper),
            billed - 1,
        )
        self.assertNotEqual(packet_key(cheaper), packet_key(packets))

    def test_tight_total_budget_forces_new_optimum(self):
        # When the byte-optimal fragmentation exceeds the total budget but
        # another fragmentation fits it, the new optimum is returned.
        for w in (4, 8):
            public_key, messages, _, proof = make_proof(w=w, height=4)
            byte_budget = len(proof) // 3
            baseline = multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=byte_budget,
            )
            baseline_cost = sum(
                verify_hashes(public_key, packet) for packet in baseline
            )
            for total_budget in range(baseline_cost - 1, baseline_cost - 4, -1):
                expected = brute_force_total_key(
                    messages,
                    proof,
                    public_key,
                    byte_budget,
                    baseline_cost,  # per-packet budget never binds here
                    total_budget,
                )
                with self.subTest(w=w, total_budget=total_budget):
                    if expected is None:
                        with self.assertRaises(ValueError):
                            multiproof_partition(
                                messages,
                                proof,
                                public_key=public_key,
                                max_bytes=byte_budget,
                                max_total_verify_hashes=total_budget,
                            )
                    else:
                        packets = multiproof_partition(
                            messages,
                            proof,
                            public_key=public_key,
                            max_bytes=byte_budget,
                            max_total_verify_hashes=total_budget,
                        )
                        self.assertEqual(packet_key(packets), expected)

    def test_total_budget_combines_with_per_packet_budget(self):
        public_key, messages, _, proof = make_proof(height=4)
        indices = tuple(index for index, _ in _multiproof_parse(proof)[1])
        full = proof_hashes(public_key, indices)
        byte_budget = len(proof) // 2
        for hash_budget in (full, full // 2, full // 4):
            for total_budget in (full * 4, full * 2, full):
                expected = brute_force_total_key(
                    messages,
                    proof,
                    public_key,
                    byte_budget,
                    hash_budget,
                    total_budget,
                )
                with self.subTest(
                    hash_budget=hash_budget, total_budget=total_budget
                ):
                    if expected is None:
                        with self.assertRaises(ValueError):
                            multiproof_partition(
                                messages,
                                proof,
                                public_key=public_key,
                                max_bytes=byte_budget,
                                max_verify_hashes=hash_budget,
                                max_total_verify_hashes=total_budget,
                            )
                    else:
                        packets = multiproof_partition(
                            messages,
                            proof,
                            public_key=public_key,
                            max_bytes=byte_budget,
                            max_verify_hashes=hash_budget,
                            max_total_verify_hashes=total_budget,
                        )
                        self.assertEqual(packet_key(packets), expected)

    def test_infeasible_total_budget_raises_without_partial_result(self):
        public_key, messages, _, proof = make_proof(height=3)
        with self.assertRaises(ValueError) as caught:
            multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=len(proof) // 2,
                max_total_verify_hashes=1,
            )
        self.assertIn("max_total_verify_hashes", str(caught.exception))

    def test_source_fully_verified_even_with_generous_budget(self):
        public_key, messages, _, proof = make_proof(height=3)
        corrupted = bytearray(proof)
        corrupted[-1] ^= 0x01
        with self.assertRaises(ValueError):
            multiproof_partition(
                messages,
                bytes(corrupted),
                public_key=public_key,
                max_bytes=10**9,
                max_total_verify_hashes=10**9,
            )
        with self.assertRaises(ValueError):
            multiproof_partition(
                messages + ("extra",),
                proof,
                public_key=public_key,
                max_bytes=10**9,
                max_total_verify_hashes=10**9,
            )


class TestTotalBudgetOptimality(unittest.TestCase):
    def check_against_brute_force(
        self, messages, proof, public_key, context=None, contexts=None
    ):
        indices = tuple(index for index, _ in _multiproof_parse(proof)[1])
        full = proof_hashes(public_key, indices)
        kwargs = {}
        if contexts is not None:
            kwargs["contexts"] = contexts
        elif context is not None:
            kwargs["context"] = context
        for byte_budget in (
            len(proof),
            max(1, len(proof) * 2 // 3),
            max(1, len(proof) // 2),
            max(1, len(proof) // 3),
        ):
            for hash_budget in (None, full, max(1, full // 2)):
                for total_budget in (
                    full * 4,
                    full * 2,
                    full,
                    max(1, full * 2 // 3),
                ):
                    expected = brute_force_total_key(
                        messages,
                        proof,
                        public_key,
                        byte_budget,
                        hash_budget,
                        total_budget,
                        context=context,
                        contexts=contexts,
                    )
                    with self.subTest(
                        byte_budget=byte_budget,
                        hash_budget=hash_budget,
                        total_budget=total_budget,
                    ):
                        if expected is None:
                            with self.assertRaises(ValueError):
                                multiproof_partition(
                                    messages,
                                    proof,
                                    public_key=public_key,
                                    max_bytes=byte_budget,
                                    max_verify_hashes=hash_budget,
                                    max_total_verify_hashes=total_budget,
                                    **kwargs,
                                )
                        else:
                            packets = multiproof_partition(
                                messages,
                                proof,
                                public_key=public_key,
                                max_bytes=byte_budget,
                                max_verify_hashes=hash_budget,
                                max_total_verify_hashes=total_budget,
                                **kwargs,
                            )
                            self.assertEqual(packet_key(packets), expected)

    def test_matches_brute_force_all_heights_and_w(self):
        for w in (4, 8):
            for height in range(1, 9):
                keep = tuple(range(min(1 << height, 6)))
                with self.subTest(w=w, height=height):
                    public_key, messages, _, proof = make_proof(
                        w=w, height=height, keep=keep
                    )
                    self.check_against_brute_force(messages, proof, public_key)

    def test_matches_brute_force_sparse_leaves(self):
        for w in (4, 8):
            for keep in ((0, 3, 7, 11, 15), (1, 2, 5, 8, 13), (2, 9)):
                with self.subTest(w=w, keep=keep):
                    public_key, messages, _, proof = make_proof(
                        w=w, height=4, keep=keep
                    )
                    self.check_against_brute_force(messages, proof, public_key)

    def test_matches_brute_force_shared_context(self):
        for w in (4, 8):
            with self.subTest(w=w):
                public_key, messages, _, proof = make_proof(
                    w=w, height=4, count=6, context="shared-context"
                )
                self.check_against_brute_force(
                    messages, proof, public_key, context="shared-context"
                )

    def test_matches_brute_force_per_leaf_contexts(self):
        for w in (4, 8):
            contexts = tuple(f"leaf-context-{i}" for i in range(6))
            with self.subTest(w=w):
                public_key, messages, _, proof = make_proof(
                    w=w, height=4, count=6, contexts=contexts
                )
                self.check_against_brute_force(
                    messages, proof, public_key, contexts=contexts
                )

    def test_repeated_messages_stay_on_separate_leaves(self):
        signer = make_signer(height=3)
        messages = ("same", "same", "same", "other")
        signatures = signer.sign_batch(messages)
        proof = multiproof_encode(signer.public_key, signatures)
        packets = multiproof_partition(
            messages,
            proof,
            public_key=signer.public_key,
            max_bytes=len(proof) // 2,
            max_total_verify_hashes=10**9,
        )
        covered = []
        for packet in packets:
            _, leaves, _ = _multiproof_parse(packet)
            covered.extend(index for index, _ in leaves)
        self.assertEqual(covered, [0, 1, 2, 3])


class TestTotalBudgetPacketIntegrity(unittest.TestCase):
    def test_each_packet_equals_select_of_same_fragment(self):
        for w in (4, 8):
            public_key, messages, _, proof = make_proof(w=w, height=4)
            indices = tuple(index for index, _ in _multiproof_parse(proof)[1])
            full = proof_hashes(public_key, indices)
            packets = multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=len(proof) // 3,
                max_total_verify_hashes=full * 3,
            )
            self.assertGreater(len(packets), 1)
            for packet in packets:
                _, leaves, _ = _multiproof_parse(packet)
                packet_indices = tuple(index for index, _ in leaves)
                expected = multiproof_select(
                    messages,
                    proof,
                    public_key=public_key,
                    indices=packet_indices,
                )
                self.assertEqual(packet, expected)

    def test_packets_verify_independently_and_remerge(self):
        for w in (4, 8):
            contexts = tuple(f"ctx-{i}" for i in range(8))
            public_key, messages, _, proof = make_proof(
                w=w, height=3, contexts=contexts
            )
            indices = tuple(index for index, _ in _multiproof_parse(proof)[1])
            full = proof_hashes(public_key, indices)
            packets = multiproof_partition(
                messages,
                proof,
                public_key=public_key,
                max_bytes=len(proof) // 3,
                max_total_verify_hashes=full * 3,
                contexts=contexts,
            )
            self.assertGreater(len(packets), 1)
            groups = []
            context_groups = []
            position = 0
            for packet in packets:
                _, leaves, _ = _multiproof_parse(packet)
                count = len(leaves)
                fragment = messages[position : position + count]
                fragment_contexts = contexts[position : position + count]
                self.assertTrue(
                    multiproof_verify(
                        fragment, packet, contexts=fragment_contexts
                    )
                )
                groups.append(fragment)
                context_groups.append(fragment_contexts)
                position += count
            merged = multiproof_merge(
                tuple(groups),
                packets,
                public_key=public_key,
                context_groups=tuple(context_groups),
            )
            self.assertEqual(merged, proof)

    def test_deterministic_and_inputs_untouched(self):
        public_key, messages, _, proof = make_proof(height=4)
        indices = tuple(index for index, _ in _multiproof_parse(proof)[1])
        full = proof_hashes(public_key, indices)
        data = bytearray(proof)
        first = multiproof_partition(
            messages,
            data,
            public_key=public_key,
            max_bytes=len(proof) // 3,
            max_total_verify_hashes=full * 3,
        )
        second = multiproof_partition(
            messages,
            data,
            public_key=public_key,
            max_bytes=len(proof) // 3,
            max_total_verify_hashes=full * 3,
        )
        self.assertEqual(first, second)
        self.assertEqual(bytes(data), proof)
        for packet in first:
            self.assertIsInstance(packet, bytes)


if __name__ == "__main__":
    unittest.main()

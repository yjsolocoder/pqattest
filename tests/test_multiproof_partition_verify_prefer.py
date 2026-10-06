import itertools
import unittest

from pqattest import (
    MerkleSigner,
    merkle_verify_profile,
    multiproof_encode,
    multiproof_expand,
    multiproof_merge,
    multiproof_partition,
    multiproof_verify,
)
from pqattest.merkle import _multiproof_parse


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_proof(height=3, w=4, keep=None, context=None, contexts=None):
    signer = MerkleSigner(height=height, w=w, token_bytes=counter_tokens())
    if keep is None:
        keep = tuple(range(1 << height))
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
    proof = multiproof_encode(signer.public_key, signatures)
    return signer.public_key, messages, proof


def profile_hashes(public_key, indices):
    """The wots + leaf + multi bill of one packet over ``indices``."""
    profile = merkle_verify_profile(public_key.w, public_key.height, indices)
    return profile.wots + profile.leaf + profile.multi


def packet_hashes(public_key, packet):
    _, leaves, _ = _multiproof_parse(packet)
    return profile_hashes(public_key, tuple(index for index, _ in leaves))


def verify_key(public_key, packets):
    """The verify-mode key: (total hashes, count, bytes, end indices)."""
    return (
        sum(packet_hashes(public_key, packet) for packet in packets),
        len(packets),
        sum(len(packet) for packet in packets),
        tuple(_multiproof_parse(packet)[1][-1][0] for packet in packets),
    )


def brute_force_verify_key(
    messages,
    proof,
    public_key,
    max_bytes,
    max_verify_hashes=None,
    max_total_verify_hashes=None,
    context=None,
    contexts=None,
):
    """Exhaustively minimise the verify-mode key over every fragmentation.

    The source is expanded once into standalone signatures (each fragment's
    bytes then come straight from :func:`multiproof_encode`, byte-identical
    to :func:`multiproof_select` on the same fragment), so enumerating
    every consecutive cut set stays cheap.
    """
    expand_kwargs = {}
    if context is not None:
        expand_kwargs["context"] = context
    if contexts is not None:
        expand_kwargs["contexts"] = contexts
    batch = multiproof_expand(
        messages, proof, public_key=public_key, **expand_kwargs
    )
    signatures = batch.signatures
    n = len(signatures)
    sizes, hashes = {}, {}
    for start in range(n):
        for end in range(start + 1, n + 1):
            fragment = tuple(signatures[start:end])
            sizes[(start, end)] = len(multiproof_encode(public_key, fragment))
            hashes[(start, end)] = profile_hashes(
                public_key, tuple(signature.index for signature in fragment)
            )
    best = None
    for cuts in range(1, n + 1):
        for inner in itertools.combinations(range(1, n), cuts - 1):
            bounds = (0,) + inner + (n,)
            total_hashes = 0
            total_bytes = 0
            ends = ()
            for start, end in zip(bounds, bounds[1:]):
                size = sizes[(start, end)]
                work = hashes[(start, end)]
                if size > max_bytes:
                    break
                if max_verify_hashes is not None and work > max_verify_hashes:
                    break
                total_hashes += work
                total_bytes += size
                ends += (signatures[end - 1].index,)
            else:
                if (
                    max_total_verify_hashes is not None
                    and total_hashes > max_total_verify_hashes
                ):
                    continue
                candidate = (total_hashes, cuts, total_bytes, ends)
                if best is None or candidate < best:
                    best = candidate
    return best


class TestVerifyPreferObjective(unittest.TestCase):
    """prefer="verify" matches exhaustive enumeration of every cut set."""

    def check(
        self,
        public_key,
        messages,
        proof,
        max_bytes,
        max_verify_hashes=None,
        max_total_verify_hashes=None,
        context=None,
        contexts=None,
    ):
        kwargs = dict(
            public_key=public_key,
            max_bytes=max_bytes,
            max_verify_hashes=max_verify_hashes,
            max_total_verify_hashes=max_total_verify_hashes,
            prefer="verify",
        )
        if context is not None:
            kwargs["context"] = context
        if contexts is not None:
            kwargs["contexts"] = contexts
        expected = brute_force_verify_key(
            messages,
            proof,
            public_key,
            max_bytes,
            max_verify_hashes,
            max_total_verify_hashes,
            context=context,
            contexts=contexts,
        )
        if expected is None:
            with self.assertRaises(ValueError):
                multiproof_partition(messages, proof, **kwargs)
            return
        packets = multiproof_partition(messages, proof, **kwargs)
        self.assertEqual(verify_key(public_key, packets), expected)
        # The packets cover the source leaves once, in source leaf order,
        # each verifies on its own fragment and the merge restores the
        # source bytes.
        self.assertIsInstance(packets, tuple)
        self.assertTrue(packets)
        position = 0
        groups = []
        group_contexts = []
        for packet in packets:
            self.assertIsInstance(packet, bytes)
            _, leaves, _ = _multiproof_parse(packet)
            count = len(leaves)
            fragment_messages = messages[position : position + count]
            groups.append(fragment_messages)
            verify_kwargs = {}
            if context is not None:
                verify_kwargs["context"] = context
            if contexts is not None:
                fragment_contexts = contexts[position : position + count]
                group_contexts.append(fragment_contexts)
                verify_kwargs["contexts"] = fragment_contexts
            self.assertTrue(
                multiproof_verify(fragment_messages, packet, **verify_kwargs)
            )
            position += count
        self.assertEqual(position, len(messages))
        merge_kwargs = {}
        if context is not None:
            merge_kwargs["context"] = context
        if contexts is not None:
            merge_kwargs["context_groups"] = tuple(group_contexts)
        self.assertEqual(
            multiproof_merge(
                tuple(groups), packets, public_key=public_key, **merge_kwargs
            ),
            bytes(proof),
        )
        # The verify objective never bills more total hashes than compact.
        compact_kwargs = dict(kwargs)
        compact_kwargs["prefer"] = "compact"
        compact = multiproof_partition(messages, proof, **compact_kwargs)
        self.assertLessEqual(
            verify_key(public_key, packets)[0],
            verify_key(public_key, compact)[0],
        )
        # Deterministic for equal inputs.
        again = multiproof_partition(messages, proof, **kwargs)
        self.assertEqual(packets, again)

    def test_dense_trees(self):
        for w in (4, 8):
            for height in (1, 2, 3):
                public_key, messages, proof = make_proof(height=height, w=w)
                budgets = (
                    len(proof),
                    len(proof) * 3 // 4,
                    len(proof) // 2,
                    len(proof) // 3,
                    10**9,
                )
                for budget in budgets:
                    with self.subTest(w=w, height=height, budget=budget):
                        self.check(public_key, messages, proof, budget)

    def test_sparse_leaves(self):
        for w in (4, 8):
            keep = (0, 3, 5, 8, 11, 14)
            public_key, messages, proof = make_proof(height=4, w=w, keep=keep)
            for budget in (len(proof), len(proof) // 2, len(proof) // 3):
                with self.subTest(w=w, budget=budget):
                    self.check(public_key, messages, proof, budget)

    def test_per_packet_hash_budget(self):
        public_key, messages, proof = make_proof(height=3, w=4)
        for hash_budget in (2100, 3200, 4500):
            with self.subTest(hash_budget=hash_budget):
                self.check(
                    public_key,
                    messages,
                    proof,
                    10**9,
                    max_verify_hashes=hash_budget,
                )

    def test_total_hash_budget(self):
        public_key, messages, proof = make_proof(height=3, w=4)
        whole = profile_hashes(public_key, tuple(range(8)))
        for total_budget in (whole, whole + 4200, whole + 9000):
            with self.subTest(total_budget=total_budget):
                self.check(
                    public_key,
                    messages,
                    proof,
                    10**9,
                    max_total_verify_hashes=total_budget,
                )

    def test_all_three_budgets(self):
        public_key, messages, proof = make_proof(height=3, w=8)
        self.check(
            public_key,
            messages,
            proof,
            len(proof) // 2,
            max_verify_hashes=18000,
            max_total_verify_hashes=70000,
        )

    def test_shared_context(self):
        public_key, messages, proof = make_proof(
            height=3, w=4, keep=tuple(range(6)), context="shared"
        )
        self.check(
            public_key, messages, proof, len(proof) // 2, context="shared"
        )

    def test_per_leaf_contexts(self):
        contexts = (None, "a", "", "b", None, "c")
        public_key, messages, proof = make_proof(
            height=3, w=4, keep=tuple(range(6)), contexts=contexts
        )
        self.check(
            public_key, messages, proof, len(proof) // 2, contexts=contexts
        )

    def test_verify_can_differ_from_compact(self):
        # A budget where the compact and verify objectives disagree on at
        # least one surveyed configuration is not guaranteed; instead assert
        # the verify result is never worse on its own objective and that
        # both remain feasible under the same budgets.
        public_key, messages, proof = make_proof(height=4, w=4, keep=(0, 7, 8, 15))
        for budget in (len(proof), len(proof) * 2 // 3, len(proof) // 2):
            with self.subTest(budget=budget):
                self.check(public_key, messages, proof, budget)


class TestVerifyPreferSourceFits(unittest.TestCase):
    def test_source_within_budget_returns_source_unchanged(self):
        for w in (4, 8):
            for height in (1, 2, 3):
                public_key, messages, proof = make_proof(height=height, w=w)
                for budget in (len(proof), len(proof) + 1, 10**6):
                    with self.subTest(w=w, height=height, budget=budget):
                        packets = multiproof_partition(
                            messages,
                            proof,
                            public_key=public_key,
                            max_bytes=budget,
                            prefer="verify",
                        )
                        self.assertEqual(packets, (bytes(proof),))

    def test_source_within_all_budgets_returns_source_unchanged(self):
        public_key, messages, proof = make_proof(height=3, w=4)
        whole = profile_hashes(public_key, tuple(range(8)))
        packets = multiproof_partition(
            messages,
            proof,
            public_key=public_key,
            max_bytes=len(proof),
            max_verify_hashes=whole,
            max_total_verify_hashes=whole,
            prefer="verify",
        )
        self.assertEqual(packets, (bytes(proof),))


class TestPreferArgumentValidation(unittest.TestCase):
    def setUp(self):
        self.public_key, self.messages, self.proof = make_proof(
            height=2, w=4, keep=(0, 1)
        )

    def partition(self, **overrides):
        kwargs = dict(
            public_key=self.public_key, max_bytes=10**9, prefer="verify"
        )
        kwargs.update(overrides)
        return multiproof_partition(self.messages, self.proof, **kwargs)

    def test_omitted_and_compact_match(self):
        default = multiproof_partition(
            self.messages,
            self.proof,
            public_key=self.public_key,
            max_bytes=len(self.proof) * 3 // 4,
        )
        explicit = multiproof_partition(
            self.messages,
            self.proof,
            public_key=self.public_key,
            max_bytes=len(self.proof) * 3 // 4,
            prefer="compact",
        )
        self.assertEqual(default, explicit)

    def test_non_string_prefer_raises_type_error(self):
        for bad in (None, 0, 1, True, b"verify", b"compact", ("verify",), ["compact"], object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    self.partition(prefer=bad)

    def test_unrecognised_string_prefer_raises_value_error(self):
        for bad in (
            "",
            "VERIFY",
            "Verify",
            "COMPACT",
            "Compact",
            " compact",
            "compact ",
            "verify\n",
            "ver",
            "compactify",
            "optimal",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.partition(prefer=bad)

    def test_type_check_precedes_content_check(self):
        # A non-string prefer is a TypeError even alongside an illegal
        # budget; an unrecognised string is a ValueError even then.
        with self.assertRaises(TypeError):
            self.partition(max_bytes=0, prefer=1)
        with self.assertRaises(ValueError):
            self.partition(max_bytes=0, prefer="bogus")
        with self.assertRaises(TypeError):
            self.partition(prefer=None, max_verify_hashes="x")

    def test_original_type_errors_still_type_error(self):
        with self.assertRaises(TypeError):
            self.partition(max_bytes="many")
        with self.assertRaises(TypeError):
            multiproof_partition(
                list(self.messages),
                self.proof,
                public_key=self.public_key,
                max_bytes=10**9,
                prefer="verify",
            )
        with self.assertRaises(TypeError):
            multiproof_partition(
                self.messages,
                "not-bytes",
                public_key=self.public_key,
                max_bytes=10**9,
                prefer="verify",
            )

    def test_infeasible_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.partition(max_bytes=10)
        with self.assertRaises(ValueError):
            self.partition(max_total_verify_hashes=1)
        with self.assertRaises(ValueError):
            self.partition(max_verify_hashes=1)


class TestVerifyPreferLeafSemantics(unittest.TestCase):
    def test_duplicate_messages_kept_separately(self):
        signer = MerkleSigner(height=3, w=4, token_bytes=counter_tokens())
        keep = (1, 4, 6)
        messages = ("same", "same", "same")
        signatures = signer.sign_selected(tuple(keep), messages)
        proof = multiproof_encode(signer.public_key, signatures)
        packets = multiproof_partition(
            messages,
            proof,
            public_key=signer.public_key,
            max_bytes=len(proof) // 2,
            prefer="verify",
        )
        count = sum(len(_multiproof_parse(packet)[1]) for packet in packets)
        self.assertEqual(count, 3)
        self.assertEqual(
            multiproof_merge(
                tuple(("same",) for _ in packets),
                packets,
                public_key=signer.public_key,
            ),
            bytes(proof),
        )

    def test_inputs_not_modified(self):
        public_key, messages, proof = make_proof(height=3, w=4)
        data = bytearray(proof)
        before = bytes(data)
        multiproof_partition(
            messages,
            data,
            public_key=public_key,
            max_bytes=len(proof) // 2,
            prefer="verify",
        )
        self.assertEqual(bytes(data), before)


if __name__ == "__main__":
    unittest.main()

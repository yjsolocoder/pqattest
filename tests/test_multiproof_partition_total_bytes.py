import unittest

from pqattest import (
    merkle_verify_profile,
    multiproof_encode,
    multiproof_expand,
    multiproof_merge,
    multiproof_partition,
    multiproof_verify,
)
from pqattest.merkle import _multiproof_parse

from test_multiproof_partition import make_proof, make_signer


def all_fragmentations(n):
    """Every consecutive fragmentation of n positions, as cut tuples."""
    for mask in range(1 << (n - 1)):
        cuts, start = [], 0
        for i in range(n - 1):
            if mask & (1 << i):
                cuts.append((start, i + 1))
                start = i + 1
        cuts.append((start, n))
        yield cuts


def brute_force(public_key, messages, proof, max_bytes, max_total_bytes,
                max_verify_hashes=None, max_total_verify_hashes=None,
                prefer="compact", context=None, contexts=None):
    """Exhaustively minimise the optimisation key under every active budget."""
    expand_kwargs = {"public_key": public_key}
    if contexts is not None:
        expand_kwargs["contexts"] = contexts
    elif context is not None:
        expand_kwargs["context"] = context
    batch = multiproof_expand(messages, proof, **expand_kwargs)
    signatures = batch.signatures
    n = len(signatures)
    sizes, hashes = {}, {}
    for start in range(n):
        for end in range(start + 1, n + 1):
            fragment = tuple(signatures[start:end])
            sizes[(start, end)] = len(multiproof_encode(public_key, fragment))
            profile = merkle_verify_profile(
                public_key.w,
                public_key.height,
                tuple(signature.index for signature in fragment),
            )
            hashes[(start, end)] = profile.wots + profile.leaf + profile.multi
    best = None
    for cuts in all_fragmentations(n):
        total_bytes = 0
        total_hashes = 0
        ends = ()
        packets = []
        for start, end in cuts:
            size = sizes[(start, end)]
            work = hashes[(start, end)]
            if size > max_bytes:
                break
            if max_verify_hashes is not None and work > max_verify_hashes:
                break
            total_bytes += size
            total_hashes += work
            ends += (signatures[end - 1].index,)
            packets.append(
                multiproof_encode(public_key, tuple(signatures[start:end]))
            )
        else:
            if total_bytes > max_total_bytes:
                continue
            if (max_total_verify_hashes is not None
                    and total_hashes > max_total_verify_hashes):
                continue
            if prefer == "compact":
                key = (len(cuts), total_bytes, ends)
            else:
                key = (total_hashes, len(cuts), total_bytes, ends)
            if best is None or key < best[0]:
                best = (key, tuple(packets))
    return best


class MaxTotalBytesTest(unittest.TestCase):
    def check(self, height, w, keep, max_bytes, max_total_bytes,
              max_verify_hashes=None, max_total_verify_hashes=None,
              prefer="compact", context=None, contexts=None):
        public_key, messages, _, proof = make_proof(
            height=height, w=w, keep=keep, context=context, contexts=contexts
        )
        kwargs = dict(
            public_key=public_key, max_bytes=max_bytes,
            max_verify_hashes=max_verify_hashes,
            max_total_verify_hashes=max_total_verify_hashes,
            max_total_bytes=max_total_bytes, prefer=prefer,
        )
        if contexts is not None:
            kwargs["contexts"] = contexts
        elif context is not None:
            kwargs["context"] = context
        expected = brute_force(
            public_key, messages, proof, max_bytes, max_total_bytes,
            max_verify_hashes, max_total_verify_hashes, prefer,
            context=context, contexts=contexts,
        )
        if expected is None:
            with self.assertRaises(ValueError):
                multiproof_partition(messages, proof, **kwargs)
            return
        result = multiproof_partition(messages, proof, **kwargs)
        self.assertEqual(result, expected[1])
        self.assertLessEqual(sum(len(p) for p in result), max_total_bytes)
        # packets verify and merge back to the source bytes
        groups = []
        context_groups = []
        position = 0
        for packet in result:
            count = len(_multiproof_parse(packet)[1])
            fragment = messages[position:position + count]
            verify_kwargs = {}
            if contexts is not None:
                fragment_contexts = contexts[position:position + count]
                verify_kwargs["contexts"] = fragment_contexts
                context_groups.append(fragment_contexts)
            elif context is not None:
                verify_kwargs["context"] = context
            self.assertTrue(multiproof_verify(fragment, packet,
                                              **verify_kwargs))
            groups.append(fragment)
            position += count
        merge_kwargs = {"public_key": public_key}
        if contexts is not None:
            merge_kwargs["context_groups"] = tuple(context_groups)
        elif context is not None:
            merge_kwargs["context"] = context
        self.assertEqual(
            multiproof_merge(tuple(groups), result, **merge_kwargs), proof
        )

    def test_type_and_value_errors(self):
        public_key, messages, _, proof = make_proof(height=3, w=4, count=4)
        base = dict(public_key=public_key, max_bytes=10 ** 6)
        for bad in ("1", 1.5, [1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                multiproof_partition(
                    messages, proof, max_total_bytes=bad, **base
                )
        for bad in (True, False, 0, -1, -100):
            with self.assertRaises(ValueError, msg=repr(bad)):
                multiproof_partition(
                    messages, proof, max_total_bytes=bad, **base
                )
        # type checks precede content checks
        with self.assertRaises(TypeError):
            multiproof_partition((), proof, max_total_bytes="x", **base)
        with self.assertRaises(TypeError):
            multiproof_partition(
                messages, b"garbage", max_total_bytes=1.5, **base
            )

    def test_none_matches_omitted(self):
        public_key, messages, _, proof = make_proof(height=3, w=4, count=6)
        profile = merkle_verify_profile(
            public_key.w, public_key.height, tuple(range(6))
        )
        source_hashes = profile.wots + profile.leaf + profile.multi
        for prefer in ("compact", "verify"):
            for extra in ({}, {"max_verify_hashes": source_hashes},
                          {"max_total_verify_hashes": 2 * source_hashes}):
                kwargs = dict(public_key=public_key,
                              max_bytes=len(proof) // 2,
                              prefer=prefer, **extra)
                self.assertEqual(
                    multiproof_partition(messages, proof, **kwargs),
                    multiproof_partition(
                        messages, proof, max_total_bytes=None, **kwargs
                    ),
                )

    def test_generous_budget_unchanged(self):
        public_key, messages, _, proof = make_proof(height=3, w=4, count=6)
        for prefer in ("compact", "verify"):
            kwargs = dict(public_key=public_key,
                          max_bytes=len(proof) // 2, prefer=prefer)
            plain = multiproof_partition(messages, proof, **kwargs)
            generous = multiproof_partition(
                messages, proof, max_total_bytes=10 ** 9, **kwargs
            )
            self.assertEqual(plain, generous)
            exact = multiproof_partition(
                messages, proof,
                max_total_bytes=sum(len(p) for p in plain), **kwargs
            )
            self.assertEqual(plain, exact)

    def test_single_packet_shortcut(self):
        public_key, messages, _, proof = make_proof(height=3, w=4, count=4)
        for prefer in ("compact", "verify"):
            result = multiproof_partition(
                messages, proof, public_key=public_key,
                max_bytes=len(proof), max_total_bytes=len(proof),
                prefer=prefer,
            )
            self.assertEqual(result, (proof,))
        # one byte under: the source no longer fits the total budget and no
        # multi-packet fragmentation can be smaller -> ValueError
        for prefer in ("compact", "verify"):
            with self.assertRaises(ValueError):
                multiproof_partition(
                    messages, proof, public_key=public_key,
                    max_bytes=len(proof), max_total_bytes=len(proof) - 1,
                    prefer=prefer,
                )

    def test_forces_more_packets(self):
        public_key, messages, _, proof = make_proof(height=3, w=4, count=6)
        loose = multiproof_partition(
            messages, proof, public_key=public_key, max_bytes=10 ** 6
        )
        self.assertEqual(len(loose), 1)
        with self.assertRaises(ValueError):
            multiproof_partition(
                messages, proof, public_key=public_key,
                max_bytes=10 ** 6, max_total_bytes=len(loose[0]) - 1,
            )

    def test_brute_force_compact(self):
        for height, w, keep in (
            (3, 4, (0, 1, 2, 3, 4, 5)),
            (3, 8, (0, 2, 3, 5, 7)),
            (4, 4, (0, 1, 5, 9, 15)),
            (2, 8, (0, 1, 3)),
        ):
            public_key, messages, _, proof = make_proof(
                height=height, w=w, keep=keep
            )
            single = len(proof)
            for max_bytes in (single // 2, single):
                for max_total_bytes in (
                    single, single + 200, single + 2000, 10 ** 9
                ):
                    with self.subTest(height=height, w=w, keep=keep,
                                      max_bytes=max_bytes,
                                      max_total_bytes=max_total_bytes):
                        self.check(height, w, keep, max_bytes,
                                   max_total_bytes)

    def test_brute_force_verify(self):
        for height, w, keep in (
            (3, 4, (0, 1, 2, 3, 4, 5)),
            (3, 8, (0, 2, 3, 5, 7)),
            (4, 4, (0, 1, 5, 9, 15)),
        ):
            public_key, messages, _, proof = make_proof(
                height=height, w=w, keep=keep
            )
            single = len(proof)
            for max_bytes in (single // 2, single):
                for max_total_bytes in (single + 200, single + 2000, 10 ** 9):
                    with self.subTest(height=height, w=w,
                                      max_bytes=max_bytes,
                                      max_total_bytes=max_total_bytes):
                        self.check(height, w, keep, max_bytes,
                                   max_total_bytes, prefer="verify")

    def test_brute_force_combined_budgets(self):
        keep = (0, 1, 2, 4, 6, 7)
        public_key, messages, _, proof = make_proof(height=3, w=4, keep=keep)
        single = len(proof)
        source_hashes = merkle_verify_profile(
            public_key.w, public_key.height, keep
        )
        source_hashes = (
            source_hashes.wots + source_hashes.leaf + source_hashes.multi
        )
        for prefer in ("compact", "verify"):
            for max_verify_hashes in (None, source_hashes):
                for max_total_verify_hashes in (
                    None, source_hashes + 150, source_hashes * 2
                ):
                    for max_total_bytes in (single + 100, single + 1500):
                        with self.subTest(
                            prefer=prefer, mvh=max_verify_hashes,
                            mtvh=max_total_verify_hashes,
                            mtb=max_total_bytes,
                        ):
                            self.check(
                                3, 4, keep, single, max_total_bytes,
                                max_verify_hashes=max_verify_hashes,
                                max_total_verify_hashes=(
                                    max_total_verify_hashes
                                ),
                                prefer=prefer,
                            )

    def test_brute_force_contexts(self):
        keep = (0, 1, 3, 4, 6)
        contexts = (None, b"ctx-a", "ctx-b", b"", "ctx-c")
        public_key, messages, _, proof = make_proof(
            height=3, w=4, keep=keep, contexts=contexts
        )
        single = len(proof)
        for prefer in ("compact", "verify"):
            with self.subTest(prefer=prefer):
                self.check(3, 4, keep, single // 2, single + 500,
                           prefer=prefer, contexts=contexts)
        # shared context
        public_key, messages, _, proof = make_proof(
            height=3, w=8, keep=keep, context="shared"
        )
        single = len(proof)
        for prefer in ("compact", "verify"):
            with self.subTest(prefer=prefer, shared=True):
                self.check(3, 8, keep, single // 2, single + 500,
                           prefer=prefer, context="shared")

    def test_optimal_fallback_not_failure(self):
        # When the unconstrained optimum exceeds max_total_bytes, another
        # feasible (still optimal-under-budget) fragmentation is returned.
        public_key, messages, _, proof = make_proof(height=3, w=4, count=6)
        plain = multiproof_partition(
            messages, proof, public_key=public_key, max_bytes=10 ** 6
        )
        plain_total = sum(len(p) for p in plain)
        expected = brute_force(public_key, messages, proof, 10 ** 6,
                               plain_total - 1)
        if expected is not None:
            result = multiproof_partition(
                messages, proof, public_key=public_key, max_bytes=10 ** 6,
                max_total_bytes=plain_total - 1,
            )
            self.assertEqual(result, expected[1])
            self.assertLessEqual(
                sum(len(p) for p in result), plain_total - 1
            )

    def test_duplicate_messages_preserved(self):
        signer = make_signer(height=3, w=4)
        messages = ("same", "same", "other", "same", "other", "same")
        proof = multiproof_encode(
            signer.public_key, signer.sign_batch(messages)
        )
        single = len(proof)
        for prefer in ("compact", "verify"):
            result = multiproof_partition(
                messages, proof, public_key=signer.public_key,
                max_bytes=single // 2, max_total_bytes=single + 1500,
                prefer=prefer,
            )
            self.assertLessEqual(sum(len(p) for p in result),
                                 single + 1500)
            covered = 0
            for packet in result:
                count = len(_multiproof_parse(packet)[1])
                self.assertTrue(
                    multiproof_verify(messages[covered:covered + count],
                                      packet)
                )
                covered += count
            self.assertEqual(covered, len(messages))

    def test_inputs_unmodified_and_deterministic(self):
        public_key, messages, _, proof = make_proof(height=3, w=4, count=5)
        data = bytearray(proof)
        before = bytes(data)
        kwargs = dict(public_key=public_key, max_bytes=len(proof) // 2,
                      max_total_bytes=len(proof) + 300)
        first = multiproof_partition(messages, data, **kwargs)
        second = multiproof_partition(messages, data, **kwargs)
        self.assertEqual(first, second)
        self.assertEqual(bytes(data), before)
        self.assertIsInstance(first, tuple)
        self.assertTrue(all(isinstance(p, bytes) for p in first))


if __name__ == "__main__":
    unittest.main()

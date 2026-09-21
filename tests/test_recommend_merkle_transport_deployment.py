import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    MerkleBatchProof,
    MerkleSigner,
    MerkleStorageProfile,
    MerkleTransportDeploymentProfile,
    merkle_storage_profile,
    merkle_transport_profile,
    multiproof_encode,
    recommend_merkle_transport_deployment,
)

# w=4: n=67, steps=1005; w=8: n=34, steps=8670
_INDICES = (0, 1)


def _expected(indices, capacity, budgets, *, prefer="multiproof"):
    """Brute-force the recommended profile with the documented ranking."""
    limits = budgets
    required = max(capacity, indices[-1] + 1)
    candidates = []
    for candidate_w in (4, 8):
        for candidate_h in range(1, 9):
            storage = merkle_storage_profile(candidate_w, candidate_h)
            if storage.leaf_count < required:
                continue
            nodes, batch, multi = merkle_transport_profile(candidate_w, candidate_h, indices)
            steps = 1005 if candidate_w == 4 else 8670
            measured = (storage.checkpoint_bytes, batch, multi, steps)
            if any(limit is not None and value > limit for value, limit in zip(measured, limits)):
                continue
            candidates.append((storage, nodes, batch, multi, steps))
    if prefer == "multiproof":
        candidates.sort(
            key=lambda c: (c[3], c[2], c[0].checkpoint_bytes, c[0].leaf_count, c[0].w, c[0].height)
        )
    elif prefer == "batch":
        candidates.sort(
            key=lambda c: (c[2], c[3], c[0].checkpoint_bytes, c[0].leaf_count, c[0].w, c[0].height)
        )
    else:
        candidates.sort(
            key=lambda c: (c[4], c[3], c[2], c[0].checkpoint_bytes, c[0].leaf_count, c[0].w, c[0].height)
        )
    storage, nodes, batch, multi, _steps = candidates[0]
    return MerkleTransportDeploymentProfile(storage, nodes, batch, multi)


class RecommendMerkleTransportDeploymentTest(unittest.TestCase):
    def test_default_prefers_multiproof(self):
        result = recommend_merkle_transport_deployment(
            4, _INDICES, (None, None, None, 9000)
        )
        self.assertEqual(result, _expected(_INDICES, 4, (None, None, None, 9000)))
        self.assertEqual(result.config, merkle_storage_profile(8, 2))
        self.assertEqual(result.nodes, 1)
        # S(8,2) = 16 + 32 * 36 = 1168; m = 1 for the adjacent pair at height 2
        self.assertEqual(result.batch, 58 + 2 * (4 + 1168))
        self.assertEqual(result.multi, 60 + 2 * (4 + 32 * 34) + 35)

    def test_batch_preference_agrees_on_compact_config(self):
        # across w in (4,8) x height in 1..8, batch and multi induce the same
        # ordering; both preferences pick w=8 at the smallest covering height
        for prefer in ("multiproof", "batch"):
            with self.subTest(prefer=prefer):
                result = recommend_merkle_transport_deployment(
                    4, _INDICES, (None, None, None, 9000), prefer=prefer
                )
                self.assertEqual(result.config, merkle_storage_profile(8, 2))

    def test_speed_prefers_w4(self):
        result = recommend_merkle_transport_deployment(
            4, _INDICES, (None, None, None, 9000), prefer="speed"
        )
        self.assertEqual(result, _expected(_INDICES, 4, (None, None, None, 9000), prefer="speed"))
        self.assertEqual(result.config, merkle_storage_profile(4, 2))
        self.assertEqual(result.nodes, 1)
        self.assertEqual(result.batch, 58 + 2 * (4 + 16 + 32 * (67 + 2)))
        self.assertEqual(result.multi, 60 + 2 * (4 + 32 * 67) + 35)

    def test_indices_force_height_beyond_capacity(self):
        # capacity 2 needs only height 1, but leaf 3 forces height 2
        indices = (0, 1, 2, 3)
        result = recommend_merkle_transport_deployment(
            2, indices, (None, None, None, 9000)
        )
        self.assertEqual(result.config.height, 2)
        self.assertEqual(result, _expected(indices, 2, (None, None, None, 9000)))
        self.assertEqual(result.nodes, 0)
        self.assertEqual(result.multi, 60 + 4 * (4 + 32 * 34))
        self.assertEqual(result.batch, 58 + 4 * (4 + 16 + 32 * (34 + 2)))

    def test_batch_budget_filters_candidates(self):
        indices = (0, 1, 2)
        # w=4 h=2 batch is 6742 bytes; a 4000-byte budget leaves only w=8
        result = recommend_merkle_transport_deployment(
            4, indices, (None, 4000, None, None)
        )
        self.assertEqual(result.config, merkle_storage_profile(8, 2))
        self.assertEqual(result, _expected(indices, 4, (None, 4000, None, None), prefer="batch"))
        self.assertEqual(result.nodes, 1)
        self.assertEqual(result.batch, 58 + 3 * (4 + 16 + 32 * (34 + 2)))
        self.assertEqual(result.multi, 60 + 3 * (4 + 32 * 34) + 35)

    def test_multiproof_budget_is_inclusive(self):
        indices = (0, 1, 2)
        nodes, batch, multi = merkle_transport_profile(8, 2, indices)
        result = recommend_merkle_transport_deployment(
            4, indices, (None, None, multi, None)
        )
        self.assertEqual(result.config, merkle_storage_profile(8, 2))
        self.assertEqual((result.nodes, result.batch, result.multi), (nodes, batch, multi))
        # h=3 multiproof is 35 bytes larger and must be excluded just below it
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment(
                4, indices, (None, None, multi - 1, None)
            )

    def test_checkpoint_budget_forces_w8(self):
        # w=4 h=1 checkpoint is 4369 bytes; 3000 leaves only w=8
        result = recommend_merkle_transport_deployment(
            1, (0,), (3000, None, None, None)
        )
        self.assertEqual(result.config, merkle_storage_profile(8, 1))
        self.assertEqual(result.nodes, 1)
        self.assertEqual(result.batch, 58 + 1 * (4 + 16 + 32 * (34 + 1)))
        self.assertEqual(result.multi, 60 + 1 * (4 + 32 * 34) + 35)

    def test_steps_budget_inclusive(self):
        result = recommend_merkle_transport_deployment(
            4, _INDICES, (None, None, None, 1005), prefer="speed"
        )
        self.assertEqual(result.config, merkle_storage_profile(4, 2))
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment(
                4, _INDICES, (None, None, None, 1004), prefer="speed"
            )

    def test_all_budgets_combined(self):
        indices = (2, 7)
        result = recommend_merkle_transport_deployment(
            8, indices, (60000, 5000, 5000, 9000), prefer="speed"
        )
        self.assertEqual(result, _expected(indices, 8, (60000, 5000, 5000, 9000), prefer="speed"))
        config = result.config
        self.assertEqual(config.w, 4)
        self.assertEqual(config.height, 3)
        self.assertLessEqual(config.checkpoint_bytes, 60000)
        self.assertLessEqual(result.batch, 5000)
        self.assertLessEqual(result.multi, 5000)

    def test_fields_match_transport_profile_for_all_candidates(self):
        for capacity, indices in ((1, (0,)), (16, (3, 5)), (256, tuple(range(0, 256, 37)))):
            with self.subTest(capacity=capacity, indices=indices):
                result = recommend_merkle_transport_deployment(
                    capacity, indices, (None, None, None, 10_000_000)
                )
                nodes, batch, multi = merkle_transport_profile(
                    result.config.w, result.config.height, indices
                )
                self.assertEqual((result.nodes, result.batch, result.multi), (nodes, batch, multi))
                self.assertEqual(result.config, merkle_storage_profile(result.config.w, result.config.height))

    def test_sizes_match_real_blobs(self):
        result = recommend_merkle_transport_deployment(
            16, (3, 5), (None, None, 8000, None)
        )
        signer = MerkleSigner(w=result.config.w, height=result.config.height)
        signatures = tuple(signer.sign(b"m%d" % i) for i in range(6))
        chosen = (signatures[3], signatures[5])
        batch = MerkleBatchProof(
            public_key=signer.public_key, signatures=chosen
        ).to_bytes()
        multi = multiproof_encode(signer.public_key, chosen)
        self.assertEqual(len(batch), result.batch)
        self.assertEqual(len(multi), result.multi)

    def test_no_feasible_candidate_raises(self):
        # checkpoint budget below every candidate
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment(1, (0,), (100, None, None, None))
        # leaf 256 cannot exist in any height-8 tree
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment(
                1, (256,), (None, None, None, None)
            )
        # steps below the w=4 minimum
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment(
                256, tuple(range(256)), (None, None, None, 100)
            )

    def test_indices_must_be_tuple(self):
        for bad in ([0, 1], {0, 1}, "ab", None, 7, range(2)):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_transport_deployment(
                        4, bad, (None, None, None, 9000)
                    )

    def test_index_members_are_value_errors(self):
        for bad in ((0, "1"), (0, 1.0), (0, None), (0, object())):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_deployment(
                        4, bad, (None, None, None, 9000)
                    )

    def test_index_value_errors(self):
        for bad in (
            (),
            (True,),
            (0, False),
            (-1, 0),
            (7, 7),
            (2, 1),
            (1, 0, 2),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_deployment(
                        4, bad, (None, None, None, 9000)
                    )

    def test_budgets_must_be_tuple(self):
        for bad in ([None, None, None, 9000], "budget", None, 7, {1, 2}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_transport_deployment(4, _INDICES, bad)

    def test_budgets_length(self):
        for bad in ((), (None,), (None, None, None), (None,) * 5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_deployment(4, _INDICES, bad)

    def test_budget_members_validated(self):
        for bad_member in (0, -1, True, 1.5, "100"):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_deployment(
                        4, _INDICES, (None, None, bad_member, None)
                    )

    def test_at_least_one_budget_required(self):
        with self.assertRaises(ValueError):
            recommend_merkle_transport_deployment(
                4, _INDICES, (None, None, None, None)
            )

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_deployment(
                        bad, (0,), (None, None, None, 9000)
                    )

    def test_invalid_prefer_rejected(self):
        for bad in ("fast", "size", "MULTIPROOF", None, 8):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_transport_deployment(
                        4, _INDICES, (None, None, None, 9000), prefer=bad
                    )

    def test_returns_profile_type(self):
        result = recommend_merkle_transport_deployment(
            4, _INDICES, (None, None, None, 9000)
        )
        self.assertIsInstance(result, MerkleTransportDeploymentProfile)
        self.assertIsInstance(result.config, MerkleStorageProfile)
        for value in (result.nodes, result.batch, result.multi):
            self.assertIsInstance(value, int)

    def test_profile_frozen_positional_equal_hashable(self):
        result = recommend_merkle_transport_deployment(
            4, _INDICES, (None, None, None, 9000)
        )
        positional = MerkleTransportDeploymentProfile(
            result.config, result.nodes, result.batch, result.multi
        )
        keyword = MerkleTransportDeploymentProfile(
            config=result.config,
            nodes=result.nodes,
            batch=result.batch,
            multi=result.multi,
        )
        self.assertEqual(result, positional)
        self.assertEqual(positional, keyword)
        self.assertEqual(hash(result), hash(positional))
        self.assertEqual(
            {result, positional, keyword},
            {keyword},
        )
        with self.assertRaises(FrozenInstanceError):
            result.multi = 1  # type: ignore[misc]

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        first = recommend_merkle_transport_deployment(
            4, (0, 1), (None, None, None, 9000)
        )
        second = recommend_merkle_transport_deployment(
            4, (0, 1), (None, None, None, 9000)
        )
        self.assertEqual(first, second)
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

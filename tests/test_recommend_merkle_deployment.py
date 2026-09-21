import unittest

from pqattest import (
    MerkleSigner,
    MerkleStorageProfile,
    merkle_storage_profile,
    profile,
    recommend_merkle_deployment,
)


def _candidates():
    """All feasible (storage, steps) pairs for a given capacity/budgets."""
    for w in (4, 8):
        for height in range(1, 9):
            yield merkle_storage_profile(w, height), profile(
                "merkle", w=w, height=height
            ).steps


class RecommendMerkleDeploymentTest(unittest.TestCase):
    def test_size_only_signature_budget(self):
        # only w=8 fits 1300-byte signatures; smallest height covering 16
        self.assertEqual(
            recommend_merkle_deployment(16, (None, 1300, None, None)),
            merkle_storage_profile(8, 4),
        )

    def test_size_minimises_signature_then_proof_then_checkpoint(self):
        # both w fit; size picks w=8 (shorter signatures) at minimal height
        self.assertEqual(
            recommend_merkle_deployment(4, (None, None, None, 9000)),
            merkle_storage_profile(8, 2),
        )

    def test_speed_minimises_steps_first(self):
        # w=4 has fewer steps (1005 < 8670) even though its wires are longer
        self.assertEqual(
            recommend_merkle_deployment(4, (None, None, None, 9000), prefer="speed"),
            merkle_storage_profile(4, 2),
        )

    def test_speed_then_falls_back_to_size_order(self):
        # steps tie within w=4; then shortest signature/proof/checkpoint wins
        self.assertEqual(
            recommend_merkle_deployment(2, (None, None, None, 2000), prefer="speed"),
            merkle_storage_profile(4, 1),
        )

    def test_checkpoint_budget_forces_w8(self):
        # w=4 checkpoints start at 4369 bytes; a 3000-byte budget leaves w=8
        self.assertEqual(
            recommend_merkle_deployment(2, (3000, None, None, None)),
            merkle_storage_profile(8, 1),
        )

    def test_proof_budget_filters_independently(self):
        # proof = signature + 60; a 1260-byte proof budget fits w=8 h=3 exactly
        self.assertEqual(
            recommend_merkle_deployment(8, (None, None, 1260, None)),
            merkle_storage_profile(8, 3),
        )

    def test_capacity_forces_height(self):
        # 100 leaves need height 7 regardless of preference
        for prefer in ("size", "speed"):
            with self.subTest(prefer=prefer):
                result = recommend_merkle_deployment(
                    100, (None, None, None, 9000), prefer=prefer
                )
                self.assertEqual(result.height, 7)
                self.assertEqual(result.w, 8 if prefer == "size" else 4)

    def test_budgets_are_inclusive(self):
        storage = merkle_storage_profile(8, 4)
        steps = profile("merkle", w=8, height=4).steps
        exact = (
            storage.checkpoint_bytes,
            storage.signature_wire_bytes,
            storage.proof_wire_bytes,
            steps,
        )
        self.assertEqual(
            recommend_merkle_deployment(16, exact),
            storage,
        )

    def test_all_budgets_combined(self):
        result = recommend_merkle_deployment(8, (9000, 1300, 1400, 9000))
        self.assertEqual(result, merkle_storage_profile(8, 3))

    def test_no_feasible_candidate_raises(self):
        # checkpoint budget below every candidate's checkpoint size
        with self.assertRaises(ValueError):
            recommend_merkle_deployment(1, (100, None, None, None))
        # capacity 256 needs height 8; a signature budget of 1000 kills w=4
        # and w=8 h=8 signatures are 1360 bytes
        with self.assertRaises(ValueError):
            recommend_merkle_deployment(256, (None, 1000, None, None))

    def test_budgets_must_be_tuple(self):
        for bad in ([None, 1300, None, None], "budget", None, 7, {1, 2}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    recommend_merkle_deployment(4, bad)

    def test_budgets_length(self):
        for bad in ((), (None,), (None, None, None), (None,) * 5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment(4, bad)

    def test_budget_members_validated(self):
        for bad_member in (0, -1, True, 1.5, "100"):
            with self.subTest(bad_member=bad_member):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment(4, (None, bad_member, None, None))

    def test_at_least_one_budget_required(self):
        with self.assertRaises(ValueError):
            recommend_merkle_deployment(4, (None, None, None, None))

    def test_invalid_capacity_rejected(self):
        for bad in (0, 257, -1, 1.5, True, False, None, "16"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment(bad, (None, 1300, None, None))

    def test_invalid_prefer_rejected(self):
        for bad in ("fast", "SIZE", None, 8):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    recommend_merkle_deployment(4, (None, 1300, None, None), prefer=bad)

    def test_returns_storage_profile(self):
        result = recommend_merkle_deployment(4, (None, None, None, 9000))
        self.assertIsInstance(result, MerkleStorageProfile)
        self.assertEqual(result, merkle_storage_profile(result.w, result.height))

    def test_pure_no_state_change(self):
        signer = MerkleSigner(w=4, height=2)
        recommend_merkle_deployment(2, (None, None, None, 9000))
        self.assertEqual(signer.next_index, 0)


if __name__ == "__main__":
    unittest.main()

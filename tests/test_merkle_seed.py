import hashlib
import threading
import unittest

from pqattest import KeyExhaustedError, MerkleSigner, merkle_verify
from pqattest.merkle import (
    _SEED_CHECKPOINT_MAGIC,
    _SEED_CHECKPOINT_TOTAL_BYTES,
    _seeded_chain_start,
)

SEED_A = b"\x01" * 32
SEED_B = b"\x02" * 32


class FromSeedTest(unittest.TestCase):
    def test_defaults(self):
        signer = MerkleSigner.from_seed(SEED_A)
        self.assertEqual(signer.public_key.w, 4)
        self.assertEqual(signer.public_key.height, 4)
        self.assertEqual(signer.public_key.leaf_count, 16)
        self.assertEqual(signer.next_index, 0)
        self.assertEqual(signer.remaining, 16)

    def test_deterministic_public_key_and_signatures(self):
        for w in (4, 8):
            for height in (1, 2, 4, 8):
                with self.subTest(w=w, height=height):
                    first = MerkleSigner.from_seed(SEED_A, height=height, w=w)
                    second = MerkleSigner.from_seed(
                        bytearray(SEED_A), height=height, w=w
                    )
                    self.assertEqual(first.public_key, second.public_key)
                    messages = tuple(f"leaf-{i}" for i in range(1 << height))
                    signatures = first.sign_batch(messages)
                    rebuilt = second.sign_batch(messages)
                    # value-for-value identical per-leaf signatures
                    self.assertEqual(signatures, rebuilt)
                    for message, signature in zip(messages, signatures):
                        self.assertTrue(
                            merkle_verify(message, signature, first.public_key)
                        )

    def test_different_seeds_give_different_public_keys(self):
        self.assertNotEqual(
            MerkleSigner.from_seed(SEED_A).public_key,
            MerkleSigner.from_seed(SEED_B).public_key,
        )

    def test_parameters_are_isolated(self):
        base = MerkleSigner.from_seed(SEED_A, height=4, w=4)
        other_w = MerkleSigner.from_seed(SEED_A, height=4, w=8)
        other_h = MerkleSigner.from_seed(SEED_A, height=3, w=4)
        self.assertNotEqual(base.public_key.root, other_w.public_key.root)
        self.assertNotEqual(base.public_key.root, other_h.public_key.root)

    def test_leaf_and_chain_positions_are_isolated(self):
        starts = {
            _seeded_chain_start(SEED_A, 4, 3, leaf, chain)
            for leaf in range(8)
            for chain in range(67)
        }
        self.assertEqual(len(starts), 8 * 67)
        self.assertNotEqual(
            _seeded_chain_start(SEED_A, 4, 3, 0, 255),
            _seeded_chain_start(SEED_A, 4, 3, 0, 256),
        )

    def test_seed_type_must_be_bytes_or_bytearray(self):
        for bad in (None, 4, "s" * 32, memoryview(b"\x00" * 32), [0] * 32):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    MerkleSigner.from_seed(bad)

    def test_seed_must_be_exactly_32_bytes(self):
        for length in (0, 1, 31, 33, 64):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_seed(b"\x00" * length)

    def test_parameters_keep_existing_validation(self):
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed(SEED_A, w=2)
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed(SEED_A, height=0)
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed(SEED_A, height=9)

    def test_seed_signer_uses_existing_entries_and_stays_exhausted(self):
        signer = MerkleSigner.from_seed(SEED_A, height=2)
        signature = signer.sign(b"message")
        self.assertTrue(merkle_verify(b"message", signature, signer.public_key))
        signer.sign_batch((b"a", b"b"))
        self.assertEqual(signer.next_index, 3)
        signer.advance_to(4)
        self.assertEqual(signer.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            signer.sign(b"again")
        with self.assertRaises(ValueError):
            signer.advance_to(3)

    def test_random_signer_has_no_seed_behaviour_change(self):
        signer = MerkleSigner(height=2)
        self.assertEqual(signer.public_key.leaf_count, 4)
        with self.assertRaises(ValueError):
            signer.seed_checkpoint()


class SeedCheckpointTest(unittest.TestCase):
    def test_layout_is_fixed_109_bytes(self):
        signer = MerkleSigner.from_seed(SEED_A, height=2)
        blob = signer.seed_checkpoint()
        self.assertIsInstance(blob, bytes)
        self.assertEqual(len(blob), 109)
        self.assertEqual(_SEED_CHECKPOINT_TOTAL_BYTES, 109)
        self.assertEqual(blob[:8], _SEED_CHECKPOINT_MAGIC)
        self.assertEqual(blob[8], 1)
        self.assertEqual(blob[9:41], SEED_A)
        self.assertEqual(blob[41], 4)
        self.assertEqual(blob[42], 2)
        self.assertEqual(blob[43:45], (0).to_bytes(2, "big"))
        self.assertEqual(blob[45:77], signer.public_key.root)
        self.assertEqual(blob[77:], hashlib.sha256(blob[:77]).digest())

    def test_repeat_snapshot_at_same_state_is_identical(self):
        signer = MerkleSigner.from_seed(SEED_A, height=3)
        self.assertEqual(signer.seed_checkpoint(), signer.seed_checkpoint())
        signer.sign(b"x")
        self.assertEqual(signer.seed_checkpoint(), signer.seed_checkpoint())

    def test_snapshot_tracks_signing_advance_and_exhaustion(self):
        signer = MerkleSigner.from_seed(SEED_A, height=2)
        self.assertEqual(signer.seed_checkpoint()[43:45], (0).to_bytes(2, "big"))
        signer.sign(b"a")
        self.assertEqual(signer.seed_checkpoint()[43:45], (1).to_bytes(2, "big"))
        signer.advance_to(3)
        self.assertEqual(signer.seed_checkpoint()[43:45], (3).to_bytes(2, "big"))
        signer.sign(b"last")
        exhausted = signer.seed_checkpoint()
        self.assertEqual(exhausted[43:45], (4).to_bytes(2, "big"))

    def test_roundtrip_at_every_index(self):
        for w in (4, 8):
            for height in (1, 2, 4):
                signer = MerkleSigner.from_seed(SEED_B, height=height, w=w)
                for index in range(1 << height):
                    restored = MerkleSigner.from_seed_checkpoint(
                        signer.seed_checkpoint()
                    )
                    self.assertEqual(restored.public_key, signer.public_key)
                    self.assertEqual(restored.next_index, index)
                    self.assertEqual(restored.remaining, (1 << height) - index)
                    signer.sign(f"m{index}")
                restored = MerkleSigner.from_seed_checkpoint(
                    bytearray(signer.seed_checkpoint())
                )
                self.assertEqual(restored.remaining, 0)
                with self.assertRaises(KeyExhaustedError):
                    restored.sign(b"x")
                with self.assertRaises(ValueError):
                    restored.advance_to(0)

    def test_restored_signatures_match_fresh_derivation(self):
        signer = MerkleSigner.from_seed(SEED_A, height=3)
        signer.sign_batch((b"a", b"b"))
        restored = MerkleSigner.from_seed_checkpoint(signer.seed_checkpoint())
        fresh = MerkleSigner.from_seed(SEED_A, height=3)
        fresh.sign_batch((b"a", b"b"))
        signature = restored.sign(b"c")
        self.assertEqual(signature, fresh.sign(b"c"))
        self.assertTrue(merkle_verify(b"c", signature, signer.public_key))

    def test_restored_signer_supports_both_checkpoint_formats(self):
        signer = MerkleSigner.from_seed(SEED_A, height=2)
        signer.sign(b"x")
        restored = MerkleSigner.from_seed_checkpoint(signer.seed_checkpoint())
        self.assertEqual(restored.seed_checkpoint(), signer.seed_checkpoint())
        full_restored = MerkleSigner.from_checkpoint(restored.checkpoint())
        self.assertEqual(full_restored.public_key, signer.public_key)
        self.assertEqual(full_restored.next_index, 1)
        with self.assertRaises(ValueError):
            full_restored.seed_checkpoint()

    def test_compact_and_full_formats_are_independent(self):
        signer = MerkleSigner.from_seed(SEED_A, height=2)
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed_checkpoint(signer.checkpoint())
        with self.assertRaises(ValueError):
            MerkleSigner.from_checkpoint(signer.seed_checkpoint())

    def test_seed_checkpoint_rejected_for_random_signer(self):
        signer = MerkleSigner(height=2)
        signer.sign(b"x")
        with self.assertRaises(ValueError):
            signer.seed_checkpoint()

    def test_restore_requires_bytes_or_bytearray(self):
        for bad in (None, 4, "blob", memoryview(b"0" * 109), [0] * 109):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    MerkleSigner.from_seed_checkpoint(bad)

    def _blob(self, *, seed=SEED_A, w=4, height=2, next_index=0, root="default"):
        if root == "default":
            root = MerkleSigner.from_seed(seed, w=w, height=height).public_key.root
        body = (
            _SEED_CHECKPOINT_MAGIC
            + bytes((1,))
            + seed
            + bytes((w, height))
            + next_index.to_bytes(2, "big")
            + root
        )
        return body + hashlib.sha256(body).digest()

    def test_malformed_blobs_rejected(self):
        good = self._blob()
        valid_root = good[45:77]
        cases = {
            "bad magic": bytes((good[0] ^ 0xFF,)) + good[1:],
            "bad version": good[:8] + bytes((2,)) + good[9:],
            "truncated": good[:-1],
            "trailing": good + b"\x00",
            "empty": b"",
            "bad w": self._blob(w=2, root=valid_root),
            "bad height": self._blob(height=9, root=valid_root),
            "next_index past leaf count": self._blob(next_index=5),
            "next_index uint16 max": self._blob(next_index=0xFFFF),
            "wrong root": self._blob(root=b"\x00" * 32),
            "seed/root disagreement": self._blob(
                seed=SEED_A,
                root=MerkleSigner.from_seed(SEED_B, height=2).public_key.root,
            ),
        }
        for name, blob in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_seed_checkpoint(blob)

    def test_every_single_byte_flip_is_rejected(self):
        good = self._blob()
        for position in range(len(good)):
            corrupted = bytearray(good)
            corrupted[position] ^= 0x01
            with self.subTest(position=position):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_seed_checkpoint(bytes(corrupted))

    def test_snapshot_linearised_with_signing(self):
        signer = MerkleSigner.from_seed(SEED_A, height=4)
        seen_indices = []
        errors = []

        def worker_sign():
            try:
                for _ in range(8):
                    signer.sign(b"m")
            except Exception as exc:  # pragma: no cover - failure reporter
                errors.append(exc)

        def worker_snapshot():
            try:
                for _ in range(8):
                    blob = signer.seed_checkpoint()
                    seen_indices.append(int.from_bytes(blob[43:45], "big"))
            except Exception as exc:  # pragma: no cover - failure reporter
                errors.append(exc)

        threads = [
            threading.Thread(target=worker_sign),
            threading.Thread(target=worker_snapshot),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertFalse(errors)
        # Every observed index is a real state, and none skips past the end.
        self.assertTrue(0 <= min(seen_indices) <= max(seen_indices) <= 8)


if __name__ == "__main__":
    unittest.main()

import hashlib
import unittest

from pqattest import KeyExhaustedError, MerkleSigner, merkle_verify
from pqattest.merkle import (
    _CHECKPOINT_MAGIC,
    _SEED_CHECKPOINT_MAGIC,
    _SEED_CHECKPOINT_BYTES,
)

SEED = bytes(range(32))
OTHER_SEED = b"\xff" * 32


def make_seed_signer(height=2, w=4, seed=SEED):
    return MerkleSigner.from_seed(seed, height=height, w=w)


class FromSeedTest(unittest.TestCase):
    def test_deterministic_public_key(self):
        self.assertEqual(
            make_seed_signer().public_key, make_seed_signer().public_key
        )
        self.assertEqual(
            make_seed_signer().public_key,
            MerkleSigner.from_seed(bytearray(SEED), height=2, w=4).public_key,
        )

    def test_deterministic_per_leaf_signatures(self):
        first = make_seed_signer(height=2)
        second = make_seed_signer(height=2)
        for _ in range(4):
            self.assertEqual(first.sign("message"), second.sign("message"))

    def test_different_seed_different_public_key(self):
        self.assertNotEqual(
            make_seed_signer().public_key,
            make_seed_signer(seed=OTHER_SEED).public_key,
        )

    def test_parameter_combinations_are_isolated(self):
        base = make_seed_signer(height=2, w=4).public_key
        self.assertNotEqual(base, make_seed_signer(height=3, w=4).public_key)
        self.assertNotEqual(base, make_seed_signer(height=2, w=8).public_key)

    def test_defaults_match_random_constructor(self):
        signer = MerkleSigner.from_seed(SEED)
        self.assertEqual(signer.public_key.w, 4)
        self.assertEqual(signer.public_key.height, 4)
        self.assertEqual(signer.remaining, 16)

    def test_signatures_verify(self):
        signer = make_seed_signer(height=2)
        signature = signer.sign("hello")
        self.assertTrue(merkle_verify("hello", signature, signer.public_key))

    def test_seed_type_errors(self):
        for bad in (123, None, "x" * 32, memoryview(SEED), [SEED]):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    MerkleSigner.from_seed(bad)

    def test_seed_length_errors(self):
        for bad in (b"", SEED[:31], SEED + b"x"):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    MerkleSigner.from_seed(bad)
                with self.assertRaises(ValueError):
                    MerkleSigner.from_seed(bytearray(bad))

    def test_parameter_errors(self):
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed(SEED, w=5)
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed(SEED, height=0)
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed(SEED, height=9)


class SeedCheckpointFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        signer = make_seed_signer(height=2, w=4)
        blob = signer.seed_checkpoint()
        self.assertIsInstance(blob, bytes)
        self.assertEqual(len(blob), 109)
        self.assertEqual(len(blob), _SEED_CHECKPOINT_BYTES)
        self.assertEqual(blob[:8], _SEED_CHECKPOINT_MAGIC)
        self.assertEqual(blob[8], 1)  # version
        self.assertEqual(blob[9], 4)  # w
        self.assertEqual(blob[10], 2)  # height
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 0)  # next_index
        self.assertEqual(blob[13:45], SEED)
        self.assertEqual(blob[45:77], signer.public_key.root)
        self.assertEqual(hashlib.sha256(blob[:-32]).digest(), blob[-32:])

    def test_deterministic_for_same_state(self):
        signer = make_seed_signer()
        self.assertEqual(signer.seed_checkpoint(), signer.seed_checkpoint())

    def test_snapshot_tracks_signing(self):
        signer = make_seed_signer(height=2)
        fresh = signer.seed_checkpoint()
        signer.sign("one")
        blob = signer.seed_checkpoint()
        self.assertNotEqual(blob, fresh)
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 1)
        self.assertEqual(blob[:11], fresh[:11])
        self.assertEqual(blob[13:-32], fresh[13:-32])

    def test_snapshot_tracks_advance_to(self):
        signer = make_seed_signer(height=2)
        signer.advance_to(3)
        blob = signer.seed_checkpoint()
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 3)

    def test_snapshot_after_exhaustion(self):
        signer = make_seed_signer(height=2)
        signer.advance_to(4)
        blob = signer.seed_checkpoint()
        self.assertEqual(int.from_bytes(blob[11:13], "big"), 4)
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("x")

    def test_non_seed_signer_rejected(self):
        with self.assertRaises(ValueError):
            MerkleSigner(height=2).seed_checkpoint()

    def test_full_checkpoint_restore_is_not_seed_derived(self):
        signer = MerkleSigner.from_checkpoint(make_seed_signer().checkpoint())
        with self.assertRaises(ValueError):
            signer.seed_checkpoint()


class FromSeedCheckpointTest(unittest.TestCase):
    def test_round_trip(self):
        signer = make_seed_signer(height=3)
        signer.sign("one")
        signer.sign("two")
        restored = MerkleSigner.from_seed_checkpoint(signer.seed_checkpoint())
        self.assertEqual(restored.public_key, signer.public_key)
        self.assertEqual(restored.next_index, 2)
        self.assertEqual(restored.remaining, 6)
        signature = restored.sign("three")
        self.assertEqual(signature.index, 2)
        self.assertTrue(merkle_verify("three", signature, restored.public_key))

    def test_restored_signer_matches_original_signatures(self):
        signer = make_seed_signer(height=2)
        restored = MerkleSigner.from_seed_checkpoint(signer.seed_checkpoint())
        for _ in range(4):
            self.assertEqual(signer.sign("m"), restored.sign("m"))

    def test_restored_signer_is_seed_derived(self):
        signer = make_seed_signer(height=2)
        signer.sign("one")
        blob = signer.seed_checkpoint()
        restored = MerkleSigner.from_seed_checkpoint(blob)
        self.assertEqual(restored.seed_checkpoint(), blob)

    def test_accepts_bytearray(self):
        signer = make_seed_signer()
        restored = MerkleSigner.from_seed_checkpoint(
            bytearray(signer.seed_checkpoint())
        )
        self.assertEqual(restored.public_key, signer.public_key)

    def test_exhaustion_is_preserved(self):
        signer = make_seed_signer(height=2)
        for _ in range(4):
            signer.sign("m")
        restored = MerkleSigner.from_seed_checkpoint(signer.seed_checkpoint())
        self.assertEqual(restored.next_index, 4)
        self.assertEqual(restored.remaining, 0)
        with self.assertRaises(KeyExhaustedError):
            restored.sign("m")

    def test_type_errors(self):
        for bad in (123, None, "x" * 109):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(TypeError):
                    MerkleSigner.from_seed_checkpoint(bad)

    def test_length_errors(self):
        blob = make_seed_signer().seed_checkpoint()
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed_checkpoint(blob[:-1])
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed_checkpoint(b"")
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed_checkpoint(blob + b"x")

    def test_bad_magic(self):
        blob = bytearray(make_seed_signer().seed_checkpoint())
        blob[0] ^= 1
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed_checkpoint(bytes(blob))

    def test_bad_version(self):
        blob = bytearray(make_seed_signer().seed_checkpoint())
        blob[8] = 2
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed_checkpoint(bytes(blob))

    def test_bad_parameters(self):
        blob = make_seed_signer().seed_checkpoint()
        for offset, value in ((9, 5), (10, 0), (10, 99)):
            with self.subTest(offset=offset, value=value):
                corrupted = bytearray(blob)
                corrupted[offset] = value
                with self.assertRaises(ValueError):
                    MerkleSigner.from_seed_checkpoint(bytes(corrupted))

    def test_next_index_out_of_range(self):
        blob = bytearray(make_seed_signer(height=2).seed_checkpoint())
        blob[11:13] = (5).to_bytes(2, "big")  # leaf count is 4
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed_checkpoint(bytes(blob))

    def test_checksum_mismatch(self):
        blob = bytearray(make_seed_signer().seed_checkpoint())
        blob[-1] ^= 1
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed_checkpoint(bytes(blob))

    def test_root_mismatch(self):
        blob = bytearray(make_seed_signer().seed_checkpoint())
        blob[45] ^= 1  # flip a root byte, then repair the checksum
        body = bytes(blob[:-32])
        repaired = body + hashlib.sha256(body).digest()
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed_checkpoint(repaired)

    def test_full_checkpoint_not_accepted(self):
        full = make_seed_signer().checkpoint()
        with self.assertRaises(ValueError):
            MerkleSigner.from_seed_checkpoint(full)

    def test_seed_checkpoint_not_accepted_by_from_checkpoint(self):
        blob = make_seed_signer().seed_checkpoint()
        self.assertNotEqual(blob[:8], _CHECKPOINT_MAGIC)
        with self.assertRaises(ValueError):
            MerkleSigner.from_checkpoint(blob)


if __name__ == "__main__":
    unittest.main()

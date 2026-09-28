import hashlib
import threading
import unittest
from unittest import mock

import pqattest
from pqattest import (
    KeyExhaustedError,
    OneTimeSigner,
    WOTSOneTimeSigner,
    keygen,
    ots_pair_checkpoint,
    ots_pair_restore,
    sign_ots_pair_with_checkpoint,
    verify,
    wots_keygen,
    wots_verify,
)
from pqattest import _PAIR_CHECKPOINT_MAGIC


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_pair(bits=8, w=4):
    lamport = OneTimeSigner(keygen(bits=bits, token_bytes=counter_tokens())[0])
    wots = WOTSOneTimeSigner(wots_keygen(w=w, token_bytes=counter_tokens(1000))[0])
    return lamport, wots


class PairCheckpointFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for bits in (1, 8, 16):
            for w in (4, 8):
                with self.subTest(bits=bits, w=w):
                    lamport, wots = make_pair(bits=bits, w=w)
                    blob = ots_pair_checkpoint(lamport, wots)
                    lamport_blob = lamport.checkpoint()
                    wots_blob = wots.checkpoint()
                    header = 8 + 1 + 4 + 4
                    self.assertEqual(
                        len(blob),
                        header + len(lamport_blob) + len(wots_blob) + 32,
                    )
                    self.assertEqual(blob[:8], _PAIR_CHECKPOINT_MAGIC)
                    self.assertEqual(blob[:8], b"PQAOPCP\0")
                    self.assertEqual(blob[8], 1)  # version
                    self.assertEqual(
                        int.from_bytes(blob[9:13], "big"), len(lamport_blob)
                    )
                    self.assertEqual(
                        int.from_bytes(blob[13:17], "big"), len(wots_blob)
                    )
                    self.assertEqual(
                        blob[header : header + len(lamport_blob)], lamport_blob
                    )
                    self.assertEqual(
                        blob[
                            header
                            + len(lamport_blob) : header
                            + len(lamport_blob)
                            + len(wots_blob)
                        ],
                        wots_blob,
                    )
                    body, checksum = blob[:-32], blob[-32:]
                    self.assertEqual(hashlib.sha256(body).digest(), checksum)

    def test_checkpoint_returns_bytes(self):
        lamport, wots = make_pair()
        self.assertIsInstance(ots_pair_checkpoint(lamport, wots), bytes)

    def test_encoding_is_deterministic(self):
        lamport, wots = make_pair(w=8)
        self.assertEqual(
            ots_pair_checkpoint(lamport, wots), ots_pair_checkpoint(lamport, wots)
        )

    def test_same_state_encodes_identically(self):
        lamport, wots = make_pair()
        blob = ots_pair_checkpoint(lamport, wots)
        restored_lamport, restored_wots = ots_pair_restore(blob)
        self.assertEqual(
            ots_pair_checkpoint(restored_lamport, restored_wots), blob
        )
        lamport.sign(b"m")
        wots.sign(b"m")
        blob_used = ots_pair_checkpoint(lamport, wots)
        used_lamport, used_wots = ots_pair_restore(blob_used)
        self.assertEqual(ots_pair_checkpoint(used_lamport, used_wots), blob_used)

    def test_used_flags_show_in_embedded_checkpoints(self):
        lamport, wots = make_pair()
        blob = ots_pair_checkpoint(lamport, wots)
        lamport_length = int.from_bytes(blob[9:13], "big")
        self.assertEqual(blob[17 + 9], 0)
        self.assertEqual(blob[17 + lamport_length + 10], 0)
        lamport.sign(b"m")
        wots.sign(b"m")
        blob = ots_pair_checkpoint(lamport, wots)
        self.assertEqual(blob[17 + 9], 1)
        self.assertEqual(blob[17 + lamport_length + 10], 1)


class PairCheckpointTypeTest(unittest.TestCase):
    def test_checkpoint_requires_lamport_first(self):
        lamport, wots = make_pair()
        for bad in (wots, None, 42, b"x", b"", object(), (lamport,)):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    ots_pair_checkpoint(bad, wots)

    def test_checkpoint_requires_wots_second(self):
        lamport, wots = make_pair()
        for bad in (lamport, None, 42, b"x", object(), (wots,)):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    ots_pair_checkpoint(lamport, bad)

    def test_swapped_order_rejected(self):
        lamport, wots = make_pair()
        with self.assertRaises(TypeError):
            ots_pair_checkpoint(wots, lamport)

    def test_restore_non_bytes_types_raise_type_error(self):
        lamport, wots = make_pair()
        blob = ots_pair_checkpoint(lamport, wots)
        for bad in (None, 42, 4.5, "checkpoint", [blob], (blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    ots_pair_restore(bad)


class PairCheckpointRoundTripTest(unittest.TestCase):
    def test_public_keys_preserved(self):
        for bits in (1, 8, 16):
            for w in (4, 8):
                with self.subTest(bits=bits, w=w):
                    lamport, wots = make_pair(bits=bits, w=w)
                    restored_lamport, restored_wots = ots_pair_restore(
                        ots_pair_checkpoint(lamport, wots)
                    )
                    self.assertEqual(restored_lamport.public_key, lamport.public_key)
                    self.assertEqual(restored_wots.public_key, wots.public_key)
                    self.assertFalse(restored_lamport.used)
                    self.assertFalse(restored_wots.used)

    def test_private_state_preserved_in_order(self):
        lamport, wots = make_pair(bits=8, w=8)
        restored_lamport, restored_wots = ots_pair_restore(
            ots_pair_checkpoint(lamport, wots)
        )
        self.assertEqual(
            restored_lamport._private_key.secrets, lamport._private_key.secrets
        )
        self.assertEqual(
            restored_wots._private_key.elements, wots._private_key.elements
        )
        self.assertEqual(restored_wots._private_key.w, wots._private_key.w)

    def test_restored_signatures_verify_against_original_public_keys(self):
        lamport, wots = make_pair(bits=16)
        restored_lamport, restored_wots = ots_pair_restore(
            ots_pair_checkpoint(lamport, wots)
        )
        message = b"position claim"
        lamport_signature = restored_lamport.sign(message)
        wots_signature = restored_wots.sign(message)
        self.assertTrue(verify(message, lamport_signature, lamport.public_key))
        self.assertTrue(wots_verify(message, wots_signature, wots.public_key))

    def test_each_restored_side_allows_exactly_one_signature(self):
        lamport, wots = make_pair()
        restored_lamport, restored_wots = ots_pair_restore(
            ots_pair_checkpoint(lamport, wots)
        )
        restored_lamport.sign(b"one")
        restored_wots.sign(b"one")
        with self.assertRaises(KeyExhaustedError):
            restored_lamport.sign(b"two")
        with self.assertRaises(KeyExhaustedError):
            restored_wots.sign(b"two")
        # The original instances are untouched by the restored copies.
        self.assertFalse(lamport.used)
        self.assertFalse(wots.used)
        lamport.sign(b"other")
        wots.sign(b"other")

    def test_restored_wots_signature_matches_stateless_sign(self):
        lamport, wots = make_pair(w=4)
        restored_lamport, restored_wots = ots_pair_restore(
            ots_pair_checkpoint(lamport, wots)
        )
        from pqattest import wots_sign

        self.assertEqual(
            restored_wots.sign(b"m"), wots_sign(b"m", wots._private_key)
        )

    def test_accepts_bytearray(self):
        lamport, wots = make_pair()
        blob = bytearray(ots_pair_checkpoint(lamport, wots))
        restored_lamport, restored_wots = ots_pair_restore(blob)
        self.assertEqual(restored_lamport.public_key, lamport.public_key)
        self.assertEqual(restored_wots.public_key, wots.public_key)

    def test_restore_does_not_mutate_input(self):
        lamport, wots = make_pair()
        raw = ots_pair_checkpoint(lamport, wots)
        buf = bytearray(raw)
        ots_pair_restore(buf)
        self.assertEqual(bytes(buf), raw)

    def test_used_flag_combinations_round_trip(self):
        for lamport_used in (False, True):
            for wots_used in (False, True):
                with self.subTest(lamport_used=lamport_used, wots_used=wots_used):
                    lamport, wots = make_pair()
                    if lamport_used:
                        lamport.sign(b"lm")
                    if wots_used:
                        wots.sign(b"wm")
                    restored_lamport, restored_wots = ots_pair_restore(
                        ots_pair_checkpoint(lamport, wots)
                    )
                    self.assertEqual(restored_lamport.used, lamport_used)
                    self.assertEqual(restored_wots.used, wots_used)
                    if lamport_used:
                        with self.assertRaises(KeyExhaustedError):
                            restored_lamport.sign(b"again")
                    else:
                        restored_lamport.sign(b"still allowed")
                    if wots_used:
                        with self.assertRaises(KeyExhaustedError):
                            restored_wots.sign(b"again")
                    else:
                        restored_wots.sign(b"still allowed")

    def test_restore_uses_no_randomness(self):
        lamport, wots = make_pair()
        blob = ots_pair_checkpoint(lamport, wots)

        def exploding_token_bytes(size):
            raise AssertionError("ots_pair_restore must not draw randomness")

        with mock.patch.object(pqattest.secrets, "token_bytes", exploding_token_bytes):
            restored_lamport, restored_wots = ots_pair_restore(blob)
        self.assertEqual(restored_lamport.public_key, lamport.public_key)
        self.assertEqual(restored_wots.public_key, wots.public_key)

    def test_checkpoint_does_not_mutate_signers(self):
        lamport, wots = make_pair()
        ots_pair_checkpoint(lamport, wots)
        self.assertFalse(lamport.used)
        self.assertFalse(wots.used)

    def test_exhaustion_takes_priority_on_restored_used_side(self):
        lamport, wots = make_pair()
        lamport.sign(b"one")
        wots.sign(b"one")
        restored_lamport, restored_wots = ots_pair_restore(
            ots_pair_checkpoint(lamport, wots)
        )
        for call in (
            lambda: restored_lamport.sign(123),
            lambda: restored_lamport.sign(b"two"),
            lambda: restored_wots.sign(123),
            lambda: restored_wots.sign(b"two"),
        ):
            with self.assertRaises(KeyExhaustedError):
                call()


class PairCheckpointValidationTest(unittest.TestCase):
    def setUp(self):
        self.lamport, self.wots = make_pair()
        self.blob = ots_pair_checkpoint(self.lamport, self.wots)
        self.lamport_length = int.from_bytes(self.blob[9:13], "big")
        self.wots_length = int.from_bytes(self.blob[13:17], "big")

    def assert_rejected(self, data):
        with self.assertRaises(ValueError):
            ots_pair_restore(data)

    def test_truncated_and_empty_rejected(self):
        self.assert_rejected(b"")
        self.assert_rejected(self.blob[:16])
        self.assert_rejected(self.blob[:48])
        self.assert_rejected(self.blob[:-1])

    def test_extended_rejected(self):
        self.assert_rejected(self.blob + b"\x00")

    def test_bad_magic_rejected(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        self.assert_rejected(bytes(bad))

    def test_bad_version_rejected(self):
        for version in (0, 2, 255):
            with self.subTest(version=version):
                bad = bytearray(self.blob)
                bad[8] = version
                self.assert_rejected(bytes(bad))

    def test_zero_length_fields_rejected(self):
        for slot in (slice(9, 13), slice(13, 17)):
            with self.subTest(slot=slot):
                bad = bytearray(self.blob)
                bad[slot] = b"\x00\x00\x00\x00"
                self.assert_rejected(bytes(bad))

    def test_bad_length_fields_rejected(self):
        for count in (
            self.lamport_length - 1,
            self.lamport_length + 1,
            2**32 - 1,
        ):
            with self.subTest(count=count):
                bad = bytearray(self.blob)
                bad[9:13] = count.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))
        for count in (
            self.wots_length - 1,
            self.wots_length + 1,
            2**32 - 1,
        ):
            with self.subTest(count=count):
                bad = bytearray(self.blob)
                bad[13:17] = count.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_bad_checksum_rejected(self):
        bad = bytearray(self.blob)
        bad[-1] ^= 0x01
        self.assert_rejected(bytes(bad))

    def test_flipped_nested_lamport_byte_rejected(self):
        bad = bytearray(self.blob)
        bad[17] ^= 0x01
        self.assert_rejected(bytes(bad))

    def test_flipped_nested_wots_byte_rejected(self):
        bad = bytearray(self.blob)
        bad[17 + self.lamport_length] ^= 0x01
        self.assert_rejected(bytes(bad))

    def test_corrupted_nested_checkpoint_rejected_even_with_recomputed_checksum(self):
        # Corrupt the nested Lamport checkpoint's own magic, then fix the
        # outer SHA-256: the nested parse must still fail.
        bad = bytearray(self.blob)
        bad[17] ^= 0x01
        bad[-32:] = hashlib.sha256(bytes(bad[:-32])).digest()
        self.assert_rejected(bytes(bad))
        # Same for the W-OTS side.
        bad = bytearray(self.blob)
        bad[17 + self.lamport_length] ^= 0x01
        bad[-32:] = hashlib.sha256(bytes(bad[:-32])).digest()
        self.assert_rejected(bytes(bad))

    def test_swapped_nested_checkpoints_rejected(self):
        lamport_bytes = self.blob[17 : 17 + self.lamport_length]
        wots_bytes = self.blob[
            17 + self.lamport_length : 17 + self.lamport_length + self.wots_length
        ]
        body = (
            b"PQAOPCP\0"
            + bytes((1,))
            + self.wots_length.to_bytes(4, "big")
            + self.lamport_length.to_bytes(4, "big")
            + wots_bytes
            + lamport_bytes
        )
        self.assert_rejected(body + hashlib.sha256(body).digest())

    def test_valid_checkpoint_still_accepted(self):
        restored_lamport, restored_wots = ots_pair_restore(self.blob)
        self.assertEqual(restored_lamport.public_key, self.lamport.public_key)
        self.assertEqual(restored_wots.public_key, self.wots.public_key)

    def test_wots_parameter_survives_in_nested_block(self):
        # The embedded W-OTS checkpoint carries w; an odd w in the nested
        # block must fail the nested parser rather than be reinterpreted.
        lamport, wots = make_pair(w=4)
        blob = bytearray(ots_pair_checkpoint(lamport, wots))
        lamport_length = int.from_bytes(blob[9:13], "big")
        # Nested W-OTS layout: magic(8) version(1) w(1) used(1) count(2)
        blob[17 + lamport_length + 9] = 16
        blob[-32:] = hashlib.sha256(bytes(blob[:-32])).digest()
        self.assert_rejected(bytes(blob))


class PairCheckpointConcurrencyTest(unittest.TestCase):
    def test_snapshot_lands_before_or_after_a_pair_signature(self):
        lamport, wots = make_pair(bits=8)
        snapshots = []
        errors = []
        barrier = threading.Barrier(16)

        def worker(i):
            try:
                barrier.wait(timeout=10)
                if i % 2 == 0:
                    try:
                        sign_ots_pair_with_checkpoint(lamport, wots, f"m{i}")
                    except KeyExhaustedError:
                        pass
                else:
                    snapshots.append(ots_pair_checkpoint(lamport, wots))
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertTrue(lamport.used and wots.used)
        for blob in snapshots:
            with self.subTest(blob=blob[:20]):
                restored_lamport, restored_wots = ots_pair_restore(blob)
                self.assertEqual(restored_lamport.public_key, lamport.public_key)
                self.assertEqual(restored_wots.public_key, wots.public_key)
                # The two sides must never disagree about whether the pair
                # advanced: a snapshot is whole, so both used flags match.
                self.assertEqual(restored_lamport.used, restored_wots.used)


if __name__ == "__main__":
    unittest.main()

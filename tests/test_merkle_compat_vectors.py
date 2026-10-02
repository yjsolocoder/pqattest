"""Fixed-byte compatibility regression tests for the Merkle v1 formats.

These tests pin the on-disk v1 encodings of :class:`MerklePublicKey`, a
single :class:`MerkleSignature` and the full :class:`MerkleSigner`
checkpoint to checked-in golden bytes (see
``tests/fixtures/merkle_compat/README.md``). The golden samples were
produced once from documented deterministic inputs and are only ever read
here: they are never regenerated through the encoder under test, and the
assertions are byte-for-byte comparisons against the samples rather than
length checks or current-version round trips.

Coverage for each of ``w=4`` and ``w=8`` (tree height 2, four leaves):

* the frozen public key decodes through the public entry and a signer built
  from the same deterministic ``token_bytes`` input encodes to the same
  bytes;
* the initial, one-message-spent and fully exhausted checkpoints all restore
  through ``MerkleSigner.from_checkpoint`` with the expected
  ``next_index``/``remaining``, and a fresh signer over the same inputs
  reproduces each checkpoint byte for byte;
* the frozen leaf-0 signature decodes, verifies for its message and not for
  a changed message, and a restored middle state continues on leaf 1 with an
  encoding identical to the frozen continuation signature.

The failure cases pin the documented restore semantics: ``bytes`` and
``bytearray`` are equivalent, every other type raises ``TypeError``, and
unknown version / truncation / trailing data / bad checksum / a checksum
corrected over a tampered root all raise ``ValueError`` without returning a
signer. An exhausted restore signs nothing and leaves its checkpoint bytes
unchanged across the failed attempt.
"""

import hashlib
import os
import unittest

from pqattest import (
    KeyExhaustedError,
    MerklePublicKey,
    MerkleSignature,
    MerkleSigner,
    merkle_verify,
)

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "merkle_compat")

HEIGHT = 2
MESSAGE_ONE = b"compat-message-one"
MESSAGE_TWO = b"compat-message-two"
MESSAGES = (
    MESSAGE_ONE,
    MESSAGE_TWO,
    b"compat-message-three",
    b"compat-message-four",
)
# A fixed, different message; no signature was ever made over it.
MESSAGE_TAMPERED = b"compat-message-two-changed"

# Documented v1 checkpoint layout (see MerkleSigner.checkpoint docstring and
# README): 8 magic | 1 version | 1 w | 1 height | 2 next_index |
# 4 element_count | 32 root | ...private elements... | 32 SHA-256 checksum.
_VERSION_OFFSET = 8
_ROOT_OFFSET = 17
_ROOT_END = _ROOT_OFFSET + 32
_CHECKSUM_BYTES = 32


def counter_tokens(start: int = 0):
    """Deterministic key input shared by the frozen samples.

    The Nth call returns N as 8-byte big-endian zero-padded to 32 bytes, so
    every W-OTS chain start of every leaf is a public, repeatable value.
    """
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def fixture(w: int, name: str) -> bytes:
    with open(os.path.join(FIXTURE_DIR, f"w{w}", name), "rb") as handle:
        return handle.read()


def load_samples(w: int) -> dict:
    return {
        "public_key": fixture(w, "public_key.bin"),
        "checkpoint_initial": fixture(w, "checkpoint_initial.bin"),
        "checkpoint_after_one": fixture(w, "checkpoint_after_one.bin"),
        "checkpoint_exhausted": fixture(w, "checkpoint_exhausted.bin"),
        "signature_one": fixture(w, "signature_one.bin"),
        "signature_two": fixture(w, "signature_two.bin"),
    }


class MerkleCompatVectorTest(unittest.TestCase):
    def test_public_key_samples_decode_and_reencode_byte_for_byte(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                public_key = MerklePublicKey.from_bytes(samples["public_key"])
                self.assertEqual(public_key.w, w)
                self.assertEqual(public_key.height, HEIGHT)
                self.assertEqual(public_key.leaf_count, 1 << HEIGHT)
                # bytearray must decode identically.
                self.assertEqual(
                    MerklePublicKey.from_bytes(
                        bytearray(samples["public_key"])
                    ),
                    public_key,
                )
                # The encoder over the same key input must match the sample.
                signer = MerkleSigner(
                    height=HEIGHT, w=w, token_bytes=counter_tokens()
                )
                self.assertEqual(signer.public_key, public_key)
                self.assertEqual(
                    signer.public_key.to_bytes(), samples["public_key"]
                )

    def test_checkpoint_samples_restore_with_expected_state(self):
        expected = {
            "checkpoint_initial": (0, 4),
            "checkpoint_after_one": (1, 3),
            "checkpoint_exhausted": (4, 0),
        }
        for w in (4, 8):
            samples = load_samples(w)
            public_key = MerklePublicKey.from_bytes(samples["public_key"])
            for name, (next_index, remaining) in expected.items():
                with self.subTest(w=w, state=name):
                    raw = samples[name]
                    signer = MerkleSigner.from_checkpoint(raw)
                    # bytes and bytearray inputs restore value-identically.
                    signer_from_array = MerkleSigner.from_checkpoint(
                        bytearray(raw)
                    )
                    self.assertEqual(signer.public_key, public_key)
                    self.assertEqual(signer_from_array.public_key, public_key)
                    self.assertEqual(signer.next_index, next_index)
                    self.assertEqual(signer_from_array.next_index, next_index)
                    self.assertEqual(signer.remaining, remaining)
                    self.assertEqual(signer_from_array.remaining, remaining)
                    # A restored signer re-checkpoints to the frozen bytes.
                    self.assertEqual(signer.checkpoint(), raw)
                    self.assertEqual(signer_from_array.checkpoint(), raw)

    def test_fresh_encoding_matches_each_frozen_checkpoint(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                signer = MerkleSigner(
                    height=HEIGHT, w=w, token_bytes=counter_tokens()
                )
                self.assertEqual(
                    signer.checkpoint(), samples["checkpoint_initial"]
                )
                signature = signer.sign(MESSAGE_ONE)
                self.assertEqual(signature.index, 0)
                self.assertEqual(
                    signature.to_bytes(signer.public_key),
                    samples["signature_one"],
                )
                self.assertEqual(
                    signer.checkpoint(), samples["checkpoint_after_one"]
                )
                # Reaching exhaustion over the fixed messages reproduces the
                # frozen exhausted checkpoint byte for byte.
                for message in MESSAGES[1:]:
                    signer.sign(message)
                self.assertEqual(signer.next_index, 4)
                self.assertEqual(signer.remaining, 0)
                self.assertEqual(
                    signer.checkpoint(), samples["checkpoint_exhausted"]
                )

    def test_frozen_leaf_zero_signature_decodes_and_verifies(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                public_key = MerklePublicKey.from_bytes(samples["public_key"])
                signature = MerkleSignature.from_bytes(
                    samples["signature_one"], public_key
                )
                self.assertEqual(signature.index, 0)
                self.assertEqual(
                    len(signature.auth_path), HEIGHT
                )
                self.assertTrue(
                    merkle_verify(MESSAGE_ONE, signature, public_key)
                )
                self.assertFalse(
                    merkle_verify(MESSAGE_TAMPERED, signature, public_key)
                )
                # bytearray input decodes to an equal signature.
                signature_from_array = MerkleSignature.from_bytes(
                    bytearray(samples["signature_one"]), public_key
                )
                self.assertEqual(signature_from_array, signature)

    def test_restored_middle_state_continues_on_leaf_one(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                public_key = MerklePublicKey.from_bytes(samples["public_key"])
                signer = MerkleSigner.from_checkpoint(
                    samples["checkpoint_after_one"]
                )
                self.assertEqual(signer.next_index, 1)
                self.assertEqual(signer.remaining, 3)
                signature = signer.sign(MESSAGE_TWO)
                self.assertEqual(signature.index, 1)
                encoded = signature.to_bytes(public_key)
                # Continuation output is pinned by the frozen sample, not by a
                # re-encode of the object under test.
                self.assertEqual(encoded, samples["signature_two"])
                decoded = MerkleSignature.from_bytes(encoded, public_key)
                self.assertTrue(
                    merkle_verify(MESSAGE_TWO, decoded, public_key)
                )
                self.assertFalse(
                    merkle_verify(MESSAGE_TAMPERED, decoded, public_key)
                )
                # The leaf-1 index moved exactly once and the key remains the
                # long-term key committed in the frozen public key.
                self.assertEqual(signer.next_index, 2)
                self.assertEqual(signer.remaining, 2)
                self.assertEqual(signer.public_key, public_key)

    def test_checkpoint_rejects_non_bytes_types(self):
        for w in (4, 8):
            raw = load_samples(w)["checkpoint_initial"]
            for bad in ("not bytes", [raw], 123, None, object(), memoryview(raw)):
                with self.subTest(w=w, bad=type(bad).__name__):
                    with self.assertRaises(TypeError):
                        MerkleSigner.from_checkpoint(bad)

    def test_public_key_and_signature_entries_reject_non_bytes_types(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                public_key = MerklePublicKey.from_bytes(samples["public_key"])
                for bad in ("not bytes", 123, None, [samples["public_key"]]):
                    with self.subTest(entry="public_key", bad=type(bad).__name__):
                        with self.assertRaises(TypeError):
                            MerklePublicKey.from_bytes(bad)
                    with self.subTest(entry="signature", bad=type(bad).__name__):
                        with self.assertRaises(TypeError):
                            MerkleSignature.from_bytes(bad, public_key)
                with self.assertRaises(TypeError):
                    MerkleSignature.from_bytes(samples["signature_one"], b"")

    def test_corrupt_checkpoints_raise_value_error(self):
        for w in (4, 8):
            samples = load_samples(w)
            raw = samples["checkpoint_initial"]
            cases = {}

            # Unknown version byte.
            unknown_version = bytearray(raw)
            unknown_version[_VERSION_OFFSET] = 2
            cases["unknown_version"] = bytes(unknown_version)

            # Truncated.
            cases["truncated"] = raw[:-1]

            # Trailing data.
            cases["trailing"] = raw + b"\x00"

            # Checksum mismatch over otherwise intact content.
            bad_checksum = bytearray(raw)
            bad_checksum[-1] ^= 0xFF
            cases["bad_checksum"] = bytes(bad_checksum)

            # Root replaced with a different value, checksum recomputed so
            # only the root/private-key mismatch remains.
            tampered = bytearray(raw)
            tampered_root = bytes((i + 1) & 0xFF for i in range(32))
            tampered[_ROOT_OFFSET:_ROOT_END] = tampered_root
            tampered_body = bytes(tampered[:-_CHECKSUM_BYTES])
            cases["root_mismatch_with_valid_checksum"] = (
                tampered_body
                + hashlib.sha256(tampered_body).digest()
            )

            for name, blob in cases.items():
                with self.subTest(w=w, case=name):
                    with self.assertRaises(ValueError):
                        MerkleSigner.from_checkpoint(blob)

    def test_exhausted_restore_cannot_sign_and_keeps_checkpoint(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                raw = samples["checkpoint_exhausted"]
                signer = MerkleSigner.from_checkpoint(raw)
                self.assertEqual(signer.next_index, 1 << HEIGHT)
                self.assertEqual(signer.remaining, 0)
                before = signer.checkpoint()
                self.assertEqual(before, raw)
                with self.assertRaises(KeyExhaustedError):
                    signer.sign(b"a perfectly legal fresh message")
                after = signer.checkpoint()
                self.assertEqual(after, before)
                self.assertEqual(after, raw)


if __name__ == "__main__":
    unittest.main()

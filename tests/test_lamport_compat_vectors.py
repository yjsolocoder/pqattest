"""Fixed-byte compatibility regression tests for the Lamport v1 formats.

These tests pin the on-disk v1 encodings of :class:`PrivateKey`,
:class:`PublicKey`, a stateless signature and the :class:`OneTimeSigner`
checkpoint to checked-in golden bytes (see
``tests/fixtures/lamport_compat/README.md``). The golden samples were
produced once from documented deterministic inputs and are only ever
read here: they are never regenerated through the encoder under test,
and the assertions are byte-for-byte comparisons against the samples
rather than length checks or current-version round trips. A missing
sample fails the test outright — nothing falls back to generating
fresh bytes.

Coverage for each of ``bits=7`` and ``bits=256``:

* a key pair generated through the public ``keygen`` entry from the
  documented deterministic ``token_bytes`` input encodes to the frozen
  private-key and public-key bytes, and the frozen bytes decode back to
  keys equal by value;
* a signer over the same input signs the fixed message
  ``b"compat-lamport-v1"`` to the frozen signature bytes and checkpoints
  to the frozen unused/used state bytes; omitting ``context``, passing
  ``None`` or passing an empty byte string all yield those same bytes,
  each time on an independently restored signer;
* restoring the frozen unused checkpoint through
  ``OneTimeSigner.from_checkpoint`` gives an unused signer whose first
  signature matches the frozen signature and whose post-sign checkpoint
  matches the frozen used checkpoint, and ``sign_with_checkpoint`` from
  the same starting state returns those same two items; restoring the
  frozen used checkpoint gives a signer whose every ``sign`` raises
  ``KeyExhaustedError`` and whose checkpoint bytes stay unchanged;
* the frozen signature decodes through ``lamport_signature_from_bytes``
  and verifies against the frozen public key for its message; for
  ``bits=256`` it does not verify for a fixed different message (for
  ``bits=7`` only 7 digest bits are covered, so a changed message is
  not guaranteed to fail and no such assertion is made).

The failure cases pin the documented parsing boundaries of every decode
entry involved here (``PrivateKey.from_bytes``,
``PublicKey.from_bytes``, ``lamport_signature_from_bytes`` and
``OneTimeSigner.from_checkpoint``): ``bytes`` and ``bytearray`` are
equivalent, a ``str`` raises ``TypeError``, and bad magic / unknown
version / out-of-range ``bits`` / element-count mismatch / truncation /
trailing data all raise ``ValueError``. The checkpoint cases
additionally cover an invalid ``used`` flag, a mismatched key-length
field, a corrupt nested key and a checksum mismatch, with the checksum
recomputed over structural corruptions so each field check is proven to
fire on its own rather than being masked by the checksum layer.
"""

import hashlib
import os
import unittest

from pqattest import (
    KeyExhaustedError,
    OneTimeSigner,
    PrivateKey,
    PublicKey,
    keygen,
    lamport_signature_from_bytes,
    lamport_signature_to_bytes,
    verify,
)

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "lamport_compat")

MESSAGE = b"compat-lamport-v1"
# A fixed, different message; no signature was ever made over it.
MESSAGE_TAMPERED = b"compat-lamport-v1-changed"

# Documented v1 codec layout (see PrivateKey.to_bytes docstring and
# README): 8 magic | 1 version | 2 bits | 2 element_count | ...elements...
_CODEC_VERSION_OFFSET = 8
_CODEC_BITS_OFFSET = 9
_CODEC_COUNT_OFFSET = 11

# Documented v1 checkpoint layout (see OneTimeSigner.checkpoint
# docstring and README): 8 magic | 1 version | 1 used |
# 4 private_key_length | ...private key encoding... | 32 SHA-256 checksum.
_CHECKPOINT_VERSION_OFFSET = 8
_CHECKPOINT_USED_OFFSET = 9
_CHECKPOINT_KEY_LENGTH_OFFSET = 10
_CHECKPOINT_HEADER_BYTES = 8 + 1 + 1 + 4
_CHECKPOINT_CHECKSUM_BYTES = 32


def compat_tokens():
    """Deterministic key input shared by the frozen samples.

    The first call returns the integer 1 as a 32-byte big-endian value
    and every later call the next integer, so every Lamport secret is a
    public, repeatable value. Each parameter ``bits`` uses its own
    independent counter.
    """
    state = {"value": 0}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(32, "big")

    return token_bytes


def fixture(bits: int, name: str) -> bytes:
    with open(os.path.join(FIXTURE_DIR, f"bits{bits}", name), "rb") as handle:
        return handle.read()


def load_samples(bits: int) -> dict:
    return {
        "private_key": fixture(bits, "private_key.bin"),
        "public_key": fixture(bits, "public_key.bin"),
        "signature": fixture(bits, "signature.bin"),
        "checkpoint_unused": fixture(bits, "checkpoint_unused.bin"),
        "checkpoint_used": fixture(bits, "checkpoint_used.bin"),
    }


def decode_entries(samples: dict):
    """Every decode entry involved in this chain, with a valid sample."""
    return (
        ("private_key", PrivateKey.from_bytes, samples["private_key"]),
        ("public_key", PublicKey.from_bytes, samples["public_key"]),
        ("signature", lamport_signature_from_bytes, samples["signature"]),
        (
            "checkpoint",
            OneTimeSigner.from_checkpoint,
            samples["checkpoint_unused"],
        ),
    )


def recompute_checksum(blob: bytes) -> bytes:
    """Re-stamp a tampered checkpoint body with a valid SHA-256 checksum."""
    body = blob[:-_CHECKPOINT_CHECKSUM_BYTES]
    return body + hashlib.sha256(body).digest()


class LamportCompatVectorTest(unittest.TestCase):
    def test_keygen_and_key_codecs_match_frozen_samples(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                samples = load_samples(bits)
                private_key, public_key = keygen(
                    bits=bits, token_bytes=compat_tokens()
                )
                # The encoder over the documented input matches the
                # frozen bytes exactly.
                self.assertEqual(private_key.to_bytes(), samples["private_key"])
                self.assertEqual(public_key.to_bytes(), samples["public_key"])
                # The frozen bytes decode to keys equal by value.
                self.assertEqual(
                    PrivateKey.from_bytes(samples["private_key"]), private_key
                )
                self.assertEqual(
                    PublicKey.from_bytes(samples["public_key"]), public_key
                )

    def test_signature_and_checkpoints_match_frozen_samples(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                samples = load_samples(bits)
                private_key, _ = keygen(bits=bits, token_bytes=compat_tokens())
                signer = OneTimeSigner(private_key)
                self.assertFalse(signer.used)
                self.assertEqual(signer.checkpoint(), samples["checkpoint_unused"])
                signature = signer.sign(MESSAGE)
                self.assertEqual(
                    lamport_signature_to_bytes(signature, bits=bits),
                    samples["signature"],
                )
                self.assertTrue(signer.used)
                self.assertEqual(signer.checkpoint(), samples["checkpoint_used"])

    def test_omitted_none_and_empty_context_give_identical_bytes(self):
        for bits in (7, 256):
            samples = load_samples(bits)
            variants = {
                "omitted": lambda signer: signer.sign(MESSAGE),
                "none": lambda signer: signer.sign(MESSAGE, context=None),
                "empty_bytes": lambda signer: signer.sign(MESSAGE, context=b""),
            }
            for name, sign_call in variants.items():
                with self.subTest(bits=bits, variant=name):
                    # Each variant restores independently from the frozen
                    # unused checkpoint; no signer is shared across calls.
                    signer = OneTimeSigner.from_checkpoint(
                        samples["checkpoint_unused"]
                    )
                    signature = sign_call(signer)
                    self.assertEqual(
                        lamport_signature_to_bytes(signature, bits=bits),
                        samples["signature"],
                    )
                    self.assertEqual(
                        signer.checkpoint(), samples["checkpoint_used"]
                    )

    def test_frozen_signature_decodes_and_verifies(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                samples = load_samples(bits)
                # Restore and verify rely only on the samples and the
                # public message, never on a previously created signer.
                public_key = PublicKey.from_bytes(samples["public_key"])
                decoded_bits, elements = lamport_signature_from_bytes(
                    samples["signature"]
                )
                self.assertEqual(decoded_bits, bits)
                self.assertTrue(verify(MESSAGE, elements, public_key))
                if bits == 256:
                    # A legally decoded signature fails for a different
                    # message. Only the 256-bit sample covers the whole
                    # digest, so only there is a mismatch guaranteed.
                    self.assertFalse(
                        verify(MESSAGE_TAMPERED, elements, public_key)
                    )

    def test_restored_unused_checkpoint_signs_frozen_signature(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                samples = load_samples(bits)
                signer = OneTimeSigner.from_checkpoint(
                    samples["checkpoint_unused"]
                )
                self.assertFalse(signer.used)
                self.assertEqual(
                    signer.public_key,
                    PublicKey.from_bytes(samples["public_key"]),
                )
                signature = signer.sign(MESSAGE)
                self.assertEqual(
                    lamport_signature_to_bytes(signature, bits=bits),
                    samples["signature"],
                )
                self.assertTrue(signer.used)
                self.assertEqual(signer.checkpoint(), samples["checkpoint_used"])

    def test_sign_with_checkpoint_matches_frozen_samples(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                samples = load_samples(bits)
                signer = OneTimeSigner.from_checkpoint(
                    samples["checkpoint_unused"]
                )
                signature, checkpoint = signer.sign_with_checkpoint(MESSAGE)
                self.assertEqual(
                    lamport_signature_to_bytes(signature, bits=bits),
                    samples["signature"],
                )
                self.assertEqual(checkpoint, samples["checkpoint_used"])
                self.assertEqual(signer.checkpoint(), samples["checkpoint_used"])

    def test_restored_used_checkpoint_cannot_sign_and_keeps_bytes(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                samples = load_samples(bits)
                signer = OneTimeSigner.from_checkpoint(samples["checkpoint_used"])
                self.assertTrue(signer.used)
                before = signer.checkpoint()
                self.assertEqual(before, samples["checkpoint_used"])
                with self.assertRaises(KeyExhaustedError):
                    signer.sign(MESSAGE)
                after = signer.checkpoint()
                self.assertEqual(after, before)
                self.assertEqual(after, samples["checkpoint_used"])


class LamportCompatParsingBoundaryTest(unittest.TestCase):
    def test_bytes_and_bytearray_decode_equivalently(self):
        for bits in (7, 256):
            samples = load_samples(bits)
            for name, decode, raw in decode_entries(samples):
                with self.subTest(bits=bits, entry=name):
                    from_bytes = decode(raw)
                    from_array = decode(bytearray(raw))
                    if name == "checkpoint":
                        # Signers have no value equality; compare the
                        # observable restored state instead.
                        self.assertFalse(from_bytes.used)
                        self.assertFalse(from_array.used)
                        self.assertEqual(
                            from_array.public_key, from_bytes.public_key
                        )
                        self.assertEqual(from_array.checkpoint(), raw)
                    else:
                        self.assertEqual(from_array, from_bytes)

    def test_str_input_raises_type_error(self):
        for bits in (7, 256):
            samples = load_samples(bits)
            for name, decode, raw in decode_entries(samples):
                with self.subTest(bits=bits, entry=name):
                    with self.assertRaises(TypeError):
                        decode(raw.decode("latin1"))

    def test_codec_entries_reject_bad_magic_version_bits_and_count(self):
        for bits in (7, 256):
            samples = load_samples(bits)
            entries = decode_entries(samples)[:3]  # the three v1 codecs
            for name, decode, raw in entries:
                for case in ("bad_magic", "unknown_version", "invalid_bits"):
                    with self.subTest(bits=bits, entry=name, case=case):
                        bad = bytearray(raw)
                        if case == "bad_magic":
                            bad[0] ^= 0x01
                        elif case == "unknown_version":
                            bad[_CODEC_VERSION_OFFSET] = 2
                        else:
                            bad[_CODEC_BITS_OFFSET:_CODEC_BITS_OFFSET + 2] = (
                                0
                            ).to_bytes(2, "big")
                        with self.assertRaises(ValueError):
                            decode(bytes(bad))
                with self.subTest(bits=bits, entry=name, case="element_count"):
                    bad = bytearray(raw)
                    count = int.from_bytes(
                        bad[_CODEC_COUNT_OFFSET:_CODEC_COUNT_OFFSET + 2], "big"
                    )
                    bad[_CODEC_COUNT_OFFSET:_CODEC_COUNT_OFFSET + 2] = (
                        count + 1
                    ).to_bytes(2, "big")
                    with self.assertRaises(ValueError):
                        decode(bytes(bad))

    def test_entries_reject_truncation_and_trailing_data(self):
        for bits in (7, 256):
            samples = load_samples(bits)
            for name, decode, raw in decode_entries(samples):
                for case, blob in (
                    ("empty", b""),
                    ("truncated_header", raw[:11]),
                    ("truncated", raw[:-1]),
                    ("trailing", raw + b"\x00"),
                ):
                    with self.subTest(bits=bits, entry=name, case=case):
                        with self.assertRaises(ValueError):
                            decode(blob)

    def test_checkpoint_field_errors_are_not_checksum_errors(self):
        # Every structural field is corrupted and the checksum is then
        # recomputed over the tampered body, so each rejection must come
        # from the field check itself, not from the checksum layer.
        for bits in (7, 256):
            raw = load_samples(bits)["checkpoint_unused"]
            cases = {}

            bad_magic = bytearray(raw)
            bad_magic[0] ^= 0x01
            cases["bad_magic"] = (bytes(bad_magic), "bad checkpoint magic")

            bad_version = bytearray(raw)
            bad_version[_CHECKPOINT_VERSION_OFFSET] = 2
            cases["unknown_version"] = (
                bytes(bad_version),
                "unsupported checkpoint version",
            )

            bad_used = bytearray(raw)
            bad_used[_CHECKPOINT_USED_OFFSET] = 2
            cases["invalid_used_flag"] = (
                bytes(bad_used),
                "used flag must be 0 or 1",
            )

            bad_length = bytearray(raw)
            bad_length[
                _CHECKPOINT_KEY_LENGTH_OFFSET:_CHECKPOINT_KEY_LENGTH_OFFSET + 4
            ] = (0).to_bytes(4, "big")
            cases["key_length"] = (
                bytes(bad_length),
                "private key length field does not match",
            )

            # Corrupt the nested private key's magic byte; the outer
            # checkpoint structure stays intact.
            bad_nested = bytearray(raw)
            bad_nested[_CHECKPOINT_HEADER_BYTES] ^= 0x01
            cases["nested_key"] = (
                bytes(bad_nested),
                "invalid nested private key encoding",
            )

            for name, (blob, pattern) in cases.items():
                with self.subTest(bits=bits, case=name):
                    blob = recompute_checksum(blob)
                    with self.assertRaisesRegex(ValueError, pattern):
                        OneTimeSigner.from_checkpoint(blob)

    def test_checkpoint_checksum_mismatch_is_distinct(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                raw = load_samples(bits)["checkpoint_unused"]
                bad = bytearray(raw)
                bad[-1] ^= 0xFF
                with self.assertRaisesRegex(
                    ValueError, "checkpoint checksum mismatch"
                ):
                    OneTimeSigner.from_checkpoint(bytes(bad))

    def test_checkpoint_rejections_return_no_signer(self):
        for bits in (7, 256):
            raw = load_samples(bits)["checkpoint_unused"]
            bad_used = bytearray(raw)
            bad_used[_CHECKPOINT_USED_OFFSET] = 7
            bad_checksum = bytearray(raw)
            bad_checksum[-1] ^= 0xFF
            for name, blob in (
                ("invalid_used_flag", recompute_checksum(bytes(bad_used))),
                ("checksum_mismatch", bytes(bad_checksum)),
            ):
                with self.subTest(bits=bits, case=name):
                    # The call raises instead of returning a signer.
                    with self.assertRaises(ValueError):
                        OneTimeSigner.from_checkpoint(blob)


if __name__ == "__main__":
    unittest.main()

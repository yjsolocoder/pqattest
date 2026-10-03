"""Fixed-byte compatibility regression tests for the Lamport v1 formats.

These tests pin the on-disk v1 encodings of :class:`PrivateKey`,
:class:`PublicKey`, a stateless signature and the :class:`OneTimeSigner`
checkpoint to checked-in golden bytes (see
``tests/fixtures/lamport_compat/README.md``). The golden samples were
produced once from documented deterministic inputs and are only ever
read here: they are never regenerated through the encoder under test,
and the assertions are byte-for-byte comparisons against the samples
rather than length checks or current-version round trips.

Coverage for each of ``bits=7`` and ``bits=256``:

* a key pair generated through the public ``keygen`` entry from the
  documented deterministic ``token_bytes`` input encodes to the frozen
  private-key and public-key bytes, and the frozen bytes decode back
  through the public decode entries to value-equal keys;
* the frozen context-free signature decodes through
  ``lamport_signature_from_bytes`` to the same elements a fresh
  stateless ``sign`` produces and verifies against the frozen public
  key;
* restoring the frozen unused checkpoint through
  ``OneTimeSigner.from_checkpoint`` gives an unused signer whose first
  signature matches the frozen signature and whose post-sign checkpoint
  matches the frozen used checkpoint, and ``sign_with_checkpoint`` from
  the same initial state returns those same two results;
* omitting ``context``, passing ``None`` or passing an empty byte
  string all yield the frozen signature bytes, with a separately
  restored signer for every comparison;
* restoring the frozen used checkpoint gives a signer whose every
  ``sign`` raises ``KeyExhaustedError`` and whose checkpoint bytes stay
  unchanged.

The 256-bit sample additionally proves the frozen signature does not
verify for a fixed, different-digest message.

The failure cases pin the documented parsing boundaries of every decode
entry involved here (``PrivateKey.from_bytes``,
``PublicKey.from_bytes``, ``lamport_signature_from_bytes`` and
``OneTimeSigner.from_checkpoint``): ``bytes`` and ``bytearray`` are
equivalent, a ``str`` raises ``TypeError``, and bad magic / unknown
version / truncation / trailing data all raise ``ValueError``. The
checkpoint cases additionally cover an invalid ``used`` flag, a wrong
key-length field and a checksum mismatch, and corrupt structural fields
with a *recomputed* checksum so each field check is proven to fire on
its own rather than being masked by the checksum layer.

The three test classes separate the three regression signals: encoding
byte changes (:class:`LamportCompatVectorTest`), exhausted-state
distortion (:class:`LamportCompatExhaustedStateTest`) and old-sample
parse failures (:class:`LamportCompatParsingBoundaryTest`).
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
    sign,
    verify,
)

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "lamport_compat")

MESSAGE = b"compat-lamport-v1"
# A fixed, different message; no signature was ever made over it. Used
# only on the verifier side, and only meaningfully at 256 bits: at
# 7 bits two distinct digests can trivially share their first bits.
MESSAGE_TAMPERED = b"compat-lamport-v1-changed"

SAMPLE_NAMES = (
    "private_key.bin",
    "public_key.bin",
    "signature.bin",
    "checkpoint_unused.bin",
    "checkpoint_used.bin",
)

# Documented v1 codec layout (see the to_bytes docstrings and README):
# 8 magic | 1 version | 2 bits | 2 element_count | ...elements...
_CODEC_VERSION_OFFSET = 8
_CODEC_HEADER_BYTES = 13

# Documented v1 checkpoint layout (see OneTimeSigner.checkpoint
# docstring and README): 8 magic | 1 version | 1 used |
# 4 private-key length | ...private key encoding... | 32 SHA-256.
_CHECKPOINT_VERSION_OFFSET = 8
_CHECKPOINT_USED_OFFSET = 9
_CHECKPOINT_KEY_LENGTH_OFFSET = 10
_CHECKPOINT_CHECKSUM_BYTES = 32


def compat_tokens():
    """Deterministic key input shared by the frozen samples.

    The first call returns the integer 1 as a 32-byte big-endian value
    and every later call the next integer, so every Lamport secret is a
    public, repeatable value. Each bit count uses its own independent
    counter.
    """
    state = {"value": 0}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(32, "big")

    return token_bytes


def fixture(bits: int, name: str) -> bytes:
    """Read one frozen sample; a missing sample fails, never skips.

    A missing golden file is a compatibility failure in its own right
    (the fixed regression basis is gone), so it raises
    ``AssertionError`` instead of returning ``None`` or triggering
    regeneration.
    """
    path = os.path.join(FIXTURE_DIR, f"b{bits}", name)
    if not os.path.isfile(path):
        raise AssertionError(
            f"missing frozen Lamport compatibility sample: {path!s}; "
            "the golden samples must be checked in and must never be "
            "regenerated by the test suite"
        )
    with open(path, "rb") as handle:
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
    def test_all_frozen_samples_are_present(self):
        for bits in (7, 256):
            for name in SAMPLE_NAMES:
                with self.subTest(bits=bits, name=name):
                    # fixture() fails rather than skipping when absent.
                    self.assertTrue(
                        os.path.isfile(
                            os.path.join(FIXTURE_DIR, f"b{bits}", name)
                        )
                    )

    def test_keygen_and_key_codecs_match_frozen_samples(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                samples = load_samples(bits)
                private_key, public_key = keygen(
                    bits=bits, token_bytes=compat_tokens()
                )
                # The encoder over the documented input matches the
                # frozen bytes exactly: any difference here is an
                # encoding change, not a parse failure.
                self.assertEqual(private_key.to_bytes(), samples["private_key"])
                self.assertEqual(public_key.to_bytes(), samples["public_key"])
                # The frozen bytes decode through the public entries to
                # keys equal by value.
                restored_private = PrivateKey.from_bytes(samples["private_key"])
                restored_public = PublicKey.from_bytes(samples["public_key"])
                self.assertEqual(restored_private, private_key)
                self.assertEqual(restored_public, public_key)
                self.assertEqual(restored_private.bits, bits)
                self.assertEqual(restored_public.bits, bits)

    def test_frozen_signature_decodes_and_matches_stateless_sign(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                samples = load_samples(bits)
                restored_private = PrivateKey.from_bytes(samples["private_key"])
                restored_public = PublicKey.from_bytes(samples["public_key"])
                decoded_bits, elements = lamport_signature_from_bytes(
                    samples["signature"]
                )
                self.assertEqual(decoded_bits, bits)
                # The frozen signature content is exactly what the
                # public stateless signer produces from the restored key.
                self.assertEqual(
                    elements, sign(MESSAGE, restored_private)
                )
                self.assertTrue(verify(MESSAGE, elements, restored_public))

    def test_frozen_signature_verifies_original_message(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                samples = load_samples(bits)
                public_key = PublicKey.from_bytes(samples["public_key"])
                _, elements = lamport_signature_from_bytes(samples["signature"])
                self.assertTrue(verify(MESSAGE, elements, public_key))

    def test_256_bit_frozen_signature_rejects_different_message(self):
        samples = load_samples(256)
        public_key = PublicKey.from_bytes(samples["public_key"])
        _, elements = lamport_signature_from_bytes(samples["signature"])
        # The different fixed message has a different 256-bit digest.
        self.assertNotEqual(
            hashlib.sha256(MESSAGE).digest(),
            hashlib.sha256(MESSAGE_TAMPERED).digest(),
        )
        self.assertFalse(verify(MESSAGE_TAMPERED, elements, public_key))

    def test_unused_checkpoint_encodes_from_fresh_signer(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                samples = load_samples(bits)
                private_key, _ = keygen(bits=bits, token_bytes=compat_tokens())
                signer = OneTimeSigner(private_key)
                self.assertFalse(signer.used)
                self.assertEqual(signer.checkpoint(), samples["checkpoint_unused"])

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

    def test_sign_with_checkpoint_matches_both_frozen_halves(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                samples = load_samples(bits)
                # Starts from the same initial state (the frozen unused
                # checkpoint); both returned halves must match.
                signer = OneTimeSigner.from_checkpoint(
                    samples["checkpoint_unused"]
                )
                signature, checkpoint = signer.sign_with_checkpoint(MESSAGE)
                self.assertEqual(
                    lamport_signature_to_bytes(signature, bits=bits),
                    samples["signature"],
                )
                self.assertEqual(checkpoint, samples["checkpoint_used"])
                self.assertTrue(signer.used)
                # The atomic snapshot is exactly the post-sign state.
                self.assertEqual(checkpoint, signer.checkpoint())

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
                    # Every comparison restores its own signer from the
                    # frozen unused checkpoint; no signer is shared.
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


class LamportCompatExhaustedStateTest(unittest.TestCase):
    def test_restored_used_checkpoint_cannot_sign_and_keeps_bytes(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                samples = load_samples(bits)
                signer = OneTimeSigner.from_checkpoint(samples["checkpoint_used"])
                self.assertTrue(signer.used)
                before = signer.checkpoint()
                self.assertEqual(before, samples["checkpoint_used"])
                # A perfectly legal message must still be refused: the
                # exhausted state, not message validation, is what fails.
                with self.assertRaises(KeyExhaustedError):
                    signer.sign(MESSAGE)
                after = signer.checkpoint()
                self.assertEqual(after, before)
                self.assertEqual(after, samples["checkpoint_used"])

    def test_exhausted_state_round_trips_back_to_frozen_bytes(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                samples = load_samples(bits)
                # Re-restoring the frozen used bytes must not move the
                # used flag or any state byte.
                signer = OneTimeSigner.from_checkpoint(samples["checkpoint_used"])
                re_restored = OneTimeSigner.from_checkpoint(signer.checkpoint())
                self.assertTrue(re_restored.used)
                self.assertEqual(
                    re_restored.checkpoint(), samples["checkpoint_used"]
                )


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

    def test_entries_reject_bad_magic_and_unknown_version(self):
        for bits in (7, 256):
            samples = load_samples(bits)
            for name, decode, raw in decode_entries(samples):
                for case, tamper in (
                    ("bad_magic", lambda b: b.__setitem__(0, b[0] ^ 0x01)),
                    (
                        "unknown_version",
                        lambda b: b.__setitem__(_CODEC_VERSION_OFFSET, 2),
                    ),
                ):
                    with self.subTest(bits=bits, entry=name, case=case):
                        bad = bytearray(raw)
                        tamper(bad)
                        with self.assertRaises(ValueError):
                            decode(bytes(bad))

    def test_entries_reject_truncation_and_trailing_data(self):
        for bits in (7, 256):
            samples = load_samples(bits)
            for name, decode, raw in decode_entries(samples):
                for case, blob in (
                    ("empty", b""),
                    ("truncated_header", raw[: _CODEC_VERSION_OFFSET]),
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
            cases["bad_magic"] = bytes(bad_magic)

            bad_version = bytearray(raw)
            bad_version[_CHECKPOINT_VERSION_OFFSET] = 2
            cases["unknown_version"] = bytes(bad_version)

            bad_used = bytearray(raw)
            bad_used[_CHECKPOINT_USED_OFFSET] = 2
            cases["invalid_used_flag"] = bytes(bad_used)

            bad_length = bytearray(raw)
            key_length = int.from_bytes(
                bad_length[_CHECKPOINT_KEY_LENGTH_OFFSET : _CHECKPOINT_KEY_LENGTH_OFFSET + 4],
                "big",
            )
            bad_length[
                _CHECKPOINT_KEY_LENGTH_OFFSET : _CHECKPOINT_KEY_LENGTH_OFFSET + 4
            ] = (key_length + 1).to_bytes(4, "big")
            cases["wrong_key_length"] = bytes(bad_length)

            # One body byte short with a freshly matching checksum:
            # only the length/structure check can fire.
            short_body = raw[:-_CHECKPOINT_CHECKSUM_BYTES][:-1]
            cases["length_mismatch"] = (
                short_body + hashlib.sha256(short_body).digest()
            )

            for name, blob in cases.items():
                with self.subTest(bits=bits, case=name):
                    if name != "length_mismatch":
                        blob = recompute_checksum(blob)
                    with self.assertRaises(ValueError):
                        OneTimeSigner.from_checkpoint(blob)

    def test_checkpoint_checksum_corruption_is_rejected(self):
        for bits in (7, 256):
            with self.subTest(bits=bits):
                raw = load_samples(bits)["checkpoint_unused"]
                bad = bytearray(raw)
                bad[-1] ^= 0x01
                with self.assertRaisesRegex(
                    ValueError, "checkpoint checksum mismatch"
                ):
                    OneTimeSigner.from_checkpoint(bytes(bad))


if __name__ == "__main__":
    unittest.main()

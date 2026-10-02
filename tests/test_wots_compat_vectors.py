"""Fixed-byte compatibility regression tests for the W-OTS v1 formats.

These tests pin the on-disk v1 encodings of :class:`WOTSPrivateKey`,
:class:`WOTSPublicKey`, a stateless signature and the
:class:`WOTSOneTimeSigner` checkpoint to checked-in golden bytes (see
``tests/fixtures/wots_compat/README.md``). The golden samples were
produced once from documented deterministic inputs and are only ever
read here: they are never regenerated through the encoder under test,
and the assertions are byte-for-byte comparisons against the samples
rather than length checks or current-version round trips.

Coverage for each of ``w=4`` and ``w=8``:

* a key pair generated through the public ``wots_keygen`` entry from the
  documented deterministic ``token_bytes`` input encodes to the frozen
  private-key and public-key bytes, and the frozen bytes decode back to
  keys equal by value;
* a signer over the same input signs the fixed message
  ``b"compat-wots-v1"`` to the frozen signature bytes and checkpoints to
  the frozen unused/used state bytes; omitting ``context``, passing
  ``None`` or passing an empty byte string all yield those same bytes;
* restoring the frozen unused checkpoint through
  ``WOTSOneTimeSigner.from_checkpoint`` gives an unused signer whose
  first signature matches the frozen signature and whose post-sign
  checkpoint matches the frozen used checkpoint; restoring the frozen
  used checkpoint gives a signer whose every ``sign`` raises
  ``KeyExhaustedError`` and whose checkpoint bytes stay unchanged;
* the frozen signature decodes through ``wots_signature_from_bytes`` and
  verifies against the frozen public key for its message and not for a
  changed message, using only the samples and public inputs.

The failure cases pin the documented parsing boundaries of every decode
entry involved here (``WOTSPrivateKey.from_bytes``,
``WOTSPublicKey.from_bytes``, ``wots_signature_from_bytes`` and
``WOTSOneTimeSigner.from_checkpoint``): ``bytes`` and ``bytearray`` are
equivalent, a ``str`` raises ``TypeError``, and bad magic / unknown
version / invalid ``w`` / element-count mismatch / truncation / trailing
data all raise ``ValueError``. The checkpoint cases additionally cover
an invalid ``used`` flag and a checksum mismatch, and corrupt structural
fields with a *recomputed* checksum so each field check is proven to
fire on its own rather than being masked by the checksum layer.
"""

import hashlib
import os
import unittest

from pqattest import (
    KeyExhaustedError,
    WOTSOneTimeSigner,
    WOTSPrivateKey,
    WOTSPublicKey,
    wots_keygen,
    wots_signature_from_bytes,
    wots_signature_to_bytes,
    wots_verify,
)

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "wots_compat")

MESSAGE = b"compat-wots-v1"
# A fixed, different message; no signature was ever made over it.
MESSAGE_TAMPERED = b"compat-wots-v1-changed"

# Documented v1 codec layout (see WOTSPrivateKey.to_bytes docstring and
# README): 8 magic | 1 version | 1 w | 2 element_count | ...elements...
_CODEC_VERSION_OFFSET = 8
_CODEC_W_OFFSET = 9
_CODEC_COUNT_OFFSET = 10

# Documented v1 checkpoint layout (see WOTSOneTimeSigner.checkpoint
# docstring and README): 8 magic | 1 version | 1 w | 1 used |
# 2 element_count | ...private elements... | 32 SHA-256 checksum.
_CHECKPOINT_VERSION_OFFSET = 8
_CHECKPOINT_W_OFFSET = 9
_CHECKPOINT_USED_OFFSET = 10
_CHECKPOINT_COUNT_OFFSET = 11
_CHECKPOINT_CHECKSUM_BYTES = 32


def compat_tokens():
    """Deterministic key input shared by the frozen samples.

    The first call returns the integer 1 as a 32-byte big-endian value
    and every later call the next integer, so every W-OTS chain start is
    a public, repeatable value. Each parameter ``w`` uses its own
    independent counter.
    """
    state = {"value": 0}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(32, "big")

    return token_bytes


def fixture(w: int, name: str) -> bytes:
    with open(os.path.join(FIXTURE_DIR, f"w{w}", name), "rb") as handle:
        return handle.read()


def load_samples(w: int) -> dict:
    return {
        "private_key": fixture(w, "private_key.bin"),
        "public_key": fixture(w, "public_key.bin"),
        "signature": fixture(w, "signature.bin"),
        "checkpoint_unused": fixture(w, "checkpoint_unused.bin"),
        "checkpoint_used": fixture(w, "checkpoint_used.bin"),
    }


def decode_entries(samples: dict):
    """Every decode entry involved in this chain, with a valid sample."""
    return (
        ("private_key", WOTSPrivateKey.from_bytes, samples["private_key"]),
        ("public_key", WOTSPublicKey.from_bytes, samples["public_key"]),
        ("signature", wots_signature_from_bytes, samples["signature"]),
        (
            "checkpoint",
            WOTSOneTimeSigner.from_checkpoint,
            samples["checkpoint_unused"],
        ),
    )


def recompute_checksum(blob: bytes) -> bytes:
    """Re-stamp a tampered checkpoint body with a valid SHA-256 checksum."""
    body = blob[:-_CHECKPOINT_CHECKSUM_BYTES]
    return body + hashlib.sha256(body).digest()


class WotsCompatVectorTest(unittest.TestCase):
    def test_keygen_and_key_codecs_match_frozen_samples(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                private_key, public_key = wots_keygen(
                    w=w, token_bytes=compat_tokens()
                )
                # The encoder over the documented input matches the
                # frozen bytes exactly.
                self.assertEqual(private_key.to_bytes(), samples["private_key"])
                self.assertEqual(public_key.to_bytes(), samples["public_key"])
                # The frozen bytes decode to keys equal by value.
                self.assertEqual(
                    WOTSPrivateKey.from_bytes(samples["private_key"]),
                    private_key,
                )
                self.assertEqual(
                    WOTSPublicKey.from_bytes(samples["public_key"]),
                    public_key,
                )

    def test_signature_and_checkpoints_match_frozen_samples(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                private_key, _ = wots_keygen(w=w, token_bytes=compat_tokens())
                signer = WOTSOneTimeSigner(private_key)
                self.assertFalse(signer.used)
                self.assertEqual(signer.checkpoint(), samples["checkpoint_unused"])
                signature = signer.sign(MESSAGE)
                self.assertEqual(
                    wots_signature_to_bytes(signature, w=w),
                    samples["signature"],
                )
                self.assertTrue(signer.used)
                self.assertEqual(signer.checkpoint(), samples["checkpoint_used"])

    def test_omitted_none_and_empty_context_give_identical_bytes(self):
        for w in (4, 8):
            samples = load_samples(w)
            variants = {
                "omitted": lambda signer: signer.sign(MESSAGE),
                "none": lambda signer: signer.sign(MESSAGE, context=None),
                "empty_bytes": lambda signer: signer.sign(MESSAGE, context=b""),
            }
            for name, sign_call in variants.items():
                with self.subTest(w=w, variant=name):
                    # Each variant restores independently from the frozen
                    # unused checkpoint; no signer is shared across calls.
                    signer = WOTSOneTimeSigner.from_checkpoint(
                        samples["checkpoint_unused"]
                    )
                    signature = sign_call(signer)
                    self.assertEqual(
                        wots_signature_to_bytes(signature, w=w),
                        samples["signature"],
                    )
                    self.assertEqual(
                        signer.checkpoint(), samples["checkpoint_used"]
                    )

    def test_frozen_signature_decodes_and_verifies(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                # Restore and verify rely only on the samples and the
                # public message, never on a previously created signer.
                public_key = WOTSPublicKey.from_bytes(samples["public_key"])
                decoded_w, elements = wots_signature_from_bytes(
                    samples["signature"]
                )
                self.assertEqual(decoded_w, w)
                self.assertTrue(wots_verify(MESSAGE, elements, public_key))
                # A legally decoded signature fails for a different message.
                self.assertFalse(
                    wots_verify(MESSAGE_TAMPERED, elements, public_key)
                )

    def test_restored_unused_checkpoint_signs_frozen_signature(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                signer = WOTSOneTimeSigner.from_checkpoint(
                    samples["checkpoint_unused"]
                )
                self.assertFalse(signer.used)
                self.assertEqual(
                    signer.public_key,
                    WOTSPublicKey.from_bytes(samples["public_key"]),
                )
                signature = signer.sign(MESSAGE)
                self.assertEqual(
                    wots_signature_to_bytes(signature, w=w),
                    samples["signature"],
                )
                self.assertTrue(signer.used)
                self.assertEqual(signer.checkpoint(), samples["checkpoint_used"])

    def test_restored_used_checkpoint_cannot_sign_and_keeps_bytes(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                signer = WOTSOneTimeSigner.from_checkpoint(
                    samples["checkpoint_used"]
                )
                self.assertTrue(signer.used)
                before = signer.checkpoint()
                self.assertEqual(before, samples["checkpoint_used"])
                with self.assertRaises(KeyExhaustedError):
                    signer.sign(MESSAGE)
                after = signer.checkpoint()
                self.assertEqual(after, before)
                self.assertEqual(after, samples["checkpoint_used"])


class WotsCompatParsingBoundaryTest(unittest.TestCase):
    def test_bytes_and_bytearray_decode_equivalently(self):
        for w in (4, 8):
            samples = load_samples(w)
            for name, decode, raw in decode_entries(samples):
                with self.subTest(w=w, entry=name):
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
        for w in (4, 8):
            samples = load_samples(w)
            for name, decode, raw in decode_entries(samples):
                with self.subTest(w=w, entry=name):
                    with self.assertRaises(TypeError):
                        decode(raw.decode("latin1"))

    def test_codec_entries_reject_bad_magic_version_w_and_count(self):
        for w in (4, 8):
            samples = load_samples(w)
            entries = decode_entries(samples)[:3]  # the three v1 codecs
            cases = {}
            for label, offset, bad_value in (
                ("bad_magic", 0, None),
                ("unknown_version", _CODEC_VERSION_OFFSET, 2),
                ("invalid_w", _CODEC_W_OFFSET, 2),
            ):
                cases[label] = (offset, bad_value)
            for name, decode, raw in entries:
                for case, (offset, bad_value) in cases.items():
                    with self.subTest(w=w, entry=name, case=case):
                        bad = bytearray(raw)
                        if bad_value is None:
                            bad[offset] ^= 0x01
                        else:
                            bad[offset] = bad_value
                        with self.assertRaises(ValueError):
                            decode(bytes(bad))
                with self.subTest(w=w, entry=name, case="element_count"):
                    bad = bytearray(raw)
                    count = int.from_bytes(
                        bad[_CODEC_COUNT_OFFSET:_CODEC_COUNT_OFFSET + 2], "big"
                    )
                    bad[_CODEC_COUNT_OFFSET:_CODEC_COUNT_OFFSET + 2] = (
                        count + 1
                    ).to_bytes(2, "big")
                    with self.assertRaises(ValueError):
                        decode(bytes(bad))

    def test_codec_entries_reject_truncation_and_trailing_data(self):
        for w in (4, 8):
            samples = load_samples(w)
            for name, decode, raw in decode_entries(samples):
                for case, blob in (
                    ("empty", b""),
                    ("truncated_header", raw[:11]),
                    ("truncated", raw[:-1]),
                    ("trailing", raw + b"\x00"),
                ):
                    with self.subTest(w=w, entry=name, case=case):
                        with self.assertRaises(ValueError):
                            decode(blob)

    def test_checkpoint_field_errors_are_not_checksum_errors(self):
        # Every structural field is corrupted and the checksum is then
        # recomputed over the tampered body, so each rejection must come
        # from the field check itself, not from the checksum layer.
        for w in (4, 8):
            raw = load_samples(w)["checkpoint_unused"]
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

            bad_w = bytearray(raw)
            bad_w[_CHECKPOINT_W_OFFSET] = 2
            cases["invalid_w"] = (bytes(bad_w), "w must be 4 or 8")

            bad_used = bytearray(raw)
            bad_used[_CHECKPOINT_USED_OFFSET] = 2
            cases["invalid_used_flag"] = (
                bytes(bad_used),
                "used flag must be 0 or 1",
            )

            bad_count = bytearray(raw)
            bad_count[
                _CHECKPOINT_COUNT_OFFSET:_CHECKPOINT_COUNT_OFFSET + 2
            ] = (0).to_bytes(2, "big")
            cases["element_count"] = (
                bytes(bad_count),
                "element count does not match the chain count for w",
            )

            # One element byte short with a matching count and checksum:
            # only the length check can fire.
            body = raw[:-_CHECKPOINT_CHECKSUM_BYTES]
            short_body = body[:-1]
            cases["length_mismatch"] = (
                short_body + hashlib.sha256(short_body).digest(),
                "checkpoint length does not match the element count",
            )

            for name, (blob, pattern) in cases.items():
                with self.subTest(w=w, case=name):
                    if name != "length_mismatch":
                        blob = recompute_checksum(blob)
                    with self.assertRaisesRegex(ValueError, pattern):
                        WOTSOneTimeSigner.from_checkpoint(blob)

    def test_checkpoint_checksum_mismatch_is_distinct(self):
        for w in (4, 8):
            with self.subTest(w=w):
                raw = load_samples(w)["checkpoint_unused"]
                bad = bytearray(raw)
                bad[-1] ^= 0xFF
                with self.assertRaisesRegex(
                    ValueError, "checkpoint checksum mismatch"
                ):
                    WOTSOneTimeSigner.from_checkpoint(bytes(bad))

    def test_checkpoint_rejections_return_no_signer(self):
        for w in (4, 8):
            raw = load_samples(w)["checkpoint_unused"]
            bad_used = bytearray(raw)
            bad_used[_CHECKPOINT_USED_OFFSET] = 7
            bad_checksum = bytearray(raw)
            bad_checksum[-1] ^= 0xFF
            for name, blob in (
                ("invalid_used_flag", recompute_checksum(bytes(bad_used))),
                ("checksum_mismatch", bytes(bad_checksum)),
            ):
                with self.subTest(w=w, case=name):
                    # The call raises instead of returning a signer.
                    with self.assertRaises(ValueError):
                        WOTSOneTimeSigner.from_checkpoint(blob)


if __name__ == "__main__":
    unittest.main()

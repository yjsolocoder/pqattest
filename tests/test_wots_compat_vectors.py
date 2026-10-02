"""Fixed-byte compatibility regression tests for the W-OTS v1 chain.

These tests pin the on-disk v1 encodings of :class:`WOTSPrivateKey`,
:class:`WOTSPublicKey`, the stateless W-OTS signature and the
:class:`WOTSOneTimeSigner` checkpoint to checked-in golden bytes (see
``tests/fixtures/wots_compat/README.md``) for both ``w=4`` and ``w=8``.
The golden samples were produced once from documented deterministic
inputs and are only ever read here: they are never regenerated through
the encoder under test, and the assertions are byte-for-byte comparisons
against the samples rather than length checks or current-version round
trips. A future change that moves the Winternitz chain computation, the
v1 codec or the checkpoint layout in encoder and decoder at the same
time still breaks one of these byte comparisons.

Coverage for each of ``w=4`` and ``w=8``:

* ``wots_keygen`` over a fixed counter ``token_bytes`` (the first call
  returns the integer 1 as 32-byte big-endian, then 2, 3, ...) and the
  key codecs reproduce the frozen private/public bytes, and the samples
  decode back to value-equal keys;
* the frozen signature over ``b"compat-wots-v1"`` decodes through the
  public signature codec and passes ``wots_verify``, while a different
  message verifies ``False``; omitting ``context`` or passing ``None`` /
  ``b""`` produces the identical signature bytes;
* the unused checkpoint restores with ``used=False``, its first
  signature equals the frozen signature and the post-sign checkpoint
  equals the frozen used sample; the used checkpoint restores already
  spent, raises ``KeyExhaustedError`` on another sign and keeps its
  checkpoint bytes unchanged across the failed attempt.

The failure cases pin the parse boundary of every decoder involved
(private key, public key, signature and checkpoint): ``bytes`` and
``bytearray`` are equivalent, a ``str`` raises ``TypeError``, and bad
magic / unknown version / illegal ``w`` / element-count mismatch /
truncation / trailing data raise ``ValueError``. Structural checkpoint
field cases are rebuilt with a correct SHA-256 trailer so rejection is
proven at the field layer rather than only at the checksum layer; the
bad-checksum case keeps the body intact and flips only the trailer.
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
    wots_sign,
    wots_signature_from_bytes,
    wots_signature_to_bytes,
    wots_verify,
)
from pqattest.wots import _params

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "wots_compat")

MESSAGE = b"compat-wots-v1"
# A fixed, different message; no signature was ever made over it.
MESSAGE_TAMPERED = b"compat-wots-v1-changed"

# Documented v1 layouts (see the codec docstrings and README): the shared
# key/signature layout is 8 magic | 1 version | 1 w | 2 element_count |
# ...32-byte elements...; the checkpoint is 8 magic | 1 version | 1 w |
# 1 used | 2 element_count | ...private elements... | 32 SHA-256.
_CODEC_COUNT_OFFSET = 10
_CHECKPOINT_VERSION_OFFSET = 8
_CHECKPOINT_W_OFFSET = 9
_CHECKPOINT_USED_OFFSET = 10
_CHECKPOINT_COUNT_OFFSET = 11
_CHECKPOINT_CHECKSUM_BYTES = 32


def counter_tokens():
    """Deterministic key input shared by the frozen samples.

    The first call returns the integer 1 as 32-byte big-endian; each
    following call increments the integer by one. Each ``w`` gets its own
    fresh counter, so the two parameter sets start from independent but
    fully public, repeatable inputs.
    """
    state = {"value": 0}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(size, "big")

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


def chains_for(w: int) -> int:
    _, l1, l2 = _params(w)
    return l1 + l2


def with_fresh_checksum(body: bytes) -> bytes:
    """Append a correct SHA-256 trailer to a tampered checkpoint body.

    Structural-field corruption cases use this so that rejection must
    come from the field validation itself, not from the trailing
    checksum check.
    """
    return body + hashlib.sha256(body).digest()


class WotsCompatVectorTest(unittest.TestCase):
    def test_keygen_and_key_codecs_match_frozen_samples(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                private_key, public_key = wots_keygen(
                    w=w, token_bytes=counter_tokens()
                )
                # Public keygen plus the public encoders must reproduce
                # the frozen bytes exactly.
                self.assertEqual(
                    private_key.to_bytes(), samples["private_key"]
                )
                self.assertEqual(public_key.to_bytes(), samples["public_key"])
                # The samples decode to value-equal keys.
                restored_private = WOTSPrivateKey.from_bytes(
                    samples["private_key"]
                )
                restored_public = WOTSPublicKey.from_bytes(
                    samples["public_key"]
                )
                self.assertEqual(restored_private, private_key)
                self.assertEqual(restored_public, public_key)
                # bytearray input must decode value-identically.
                self.assertEqual(
                    WOTSPrivateKey.from_bytes(
                        bytearray(samples["private_key"])
                    ),
                    private_key,
                )
                self.assertEqual(
                    WOTSPublicKey.from_bytes(
                        bytearray(samples["public_key"])
                    ),
                    public_key,
                )

    def test_signature_sample_decodes_and_verifies(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                private_key = WOTSPrivateKey.from_bytes(samples["private_key"])
                public_key = WOTSPublicKey.from_bytes(samples["public_key"])
                # The public stateless signing/encoding entries reproduce
                # the frozen signature bytes.
                signature = wots_sign(MESSAGE, private_key)
                self.assertEqual(
                    wots_signature_to_bytes(signature, w=w),
                    samples["signature"],
                )
                decoded_w, decoded = wots_signature_from_bytes(
                    samples["signature"]
                )
                self.assertEqual(decoded_w, w)
                self.assertEqual(decoded, signature)
                self.assertTrue(
                    wots_verify(MESSAGE, decoded, public_key)
                )
                # A legally decoded signature must not verify a different
                # message.
                self.assertFalse(
                    wots_verify(MESSAGE_TAMPERED, decoded, public_key)
                )
                # bytearray input decodes to an equal signature.
                self.assertEqual(
                    wots_signature_from_bytes(
                        bytearray(samples["signature"])
                    ),
                    (w, signature),
                )

    def test_omitted_none_and_empty_context_give_identical_bytes(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                private_key = WOTSPrivateKey.from_bytes(samples["private_key"])
                variants = (
                    wots_sign(MESSAGE, private_key),
                    wots_sign(MESSAGE, private_key, context=None),
                    wots_sign(MESSAGE, private_key, context=b""),
                )
                for signature in variants:
                    self.assertEqual(
                        wots_signature_to_bytes(signature, w=w),
                        samples["signature"],
                    )

    def test_unused_checkpoint_restores_and_reproduces_frozen_signature(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                raw = samples["checkpoint_unused"]
                public_key = WOTSPublicKey.from_bytes(samples["public_key"])
                # Each restore starts only from the frozen bytes; no
                # in-memory signer created earlier is consulted.
                signer = WOTSOneTimeSigner.from_checkpoint(raw)
                self.assertFalse(signer.used)
                self.assertEqual(signer.public_key, public_key)
                signature = signer.sign(MESSAGE)
                self.assertEqual(
                    wots_signature_to_bytes(signature, w=w),
                    samples["signature"],
                )
                self.assertTrue(signer.used)
                self.assertEqual(
                    signer.checkpoint(), samples["checkpoint_used"]
                )
                # bytearray input restores value-identically.
                signer_from_array = WOTSOneTimeSigner.from_checkpoint(
                    bytearray(raw)
                )
                self.assertFalse(signer_from_array.used)
                self.assertEqual(signer_from_array.public_key, public_key)
                self.assertEqual(signer_from_array.checkpoint(), raw)

    def test_unused_checkpoint_context_variants_match_frozen_signature(self):
        # Each one-time signer gets exactly one sign, so every context
        # variant starts from its own fresh restore of the frozen sample.
        for w in (4, 8):
            raw = load_samples(w)["checkpoint_unused"]
            variants = (
                lambda signer: signer.sign(MESSAGE),
                lambda signer: signer.sign(MESSAGE, context=None),
                lambda signer: signer.sign(MESSAGE, context=b""),
            )
            for variant in variants:
                with self.subTest(w=w, variant=variant.__name__):
                    samples = load_samples(w)
                    signer = WOTSOneTimeSigner.from_checkpoint(
                        samples["checkpoint_unused"]
                    )
                    signature = variant(signer)
                    self.assertEqual(
                        wots_signature_to_bytes(signature, w=w),
                        samples["signature"],
                    )
                    self.assertTrue(signer.used)
                    self.assertEqual(
                        signer.checkpoint(), samples["checkpoint_used"]
                    )

    def test_used_checkpoint_blocks_signing_and_keeps_bytes(self):
        for w in (4, 8):
            with self.subTest(w=w):
                samples = load_samples(w)
                raw = samples["checkpoint_used"]
                public_key = WOTSPublicKey.from_bytes(samples["public_key"])
                signer = WOTSOneTimeSigner.from_checkpoint(raw)
                self.assertTrue(signer.used)
                self.assertEqual(signer.public_key, public_key)
                before = signer.checkpoint()
                self.assertEqual(before, raw)
                with self.assertRaises(KeyExhaustedError):
                    signer.sign(b"a perfectly legal fresh message")
                # The failed attempt changes no state: re-checkpointing
                # before and after gives the same frozen bytes.
                after = signer.checkpoint()
                self.assertEqual(after, before)
                self.assertEqual(after, raw)


class WotsCodecBoundaryTest(unittest.TestCase):
    """Parse boundary for the shared v1 key/signature decoders."""

    ENTRIES = (
        ("private_key", WOTSPrivateKey.from_bytes),
        ("public_key", WOTSPublicKey.from_bytes),
        ("signature", wots_signature_from_bytes),
    )

    def test_bytes_and_bytearray_decode_equally(self):
        for w in (4, 8):
            samples = load_samples(w)
            for name, from_bytes in self.ENTRIES:
                with self.subTest(w=w, entry=name):
                    raw = samples[name]
                    self.assertEqual(
                        from_bytes(bytearray(raw)), from_bytes(raw)
                    )

    def test_string_input_raises_type_error(self):
        for w in (4, 8):
            for name, from_bytes in self.ENTRIES:
                with self.subTest(w=w, entry=name):
                    with self.assertRaises(TypeError):
                        from_bytes("not bytes")

    def test_malformed_blobs_raise_value_error(self):
        for w in (4, 8):
            chains = chains_for(w)
            samples = load_samples(w)
            for name, from_bytes in self.ENTRIES:
                raw = samples[name]

                bad_magic = bytearray(raw)
                bad_magic[0] ^= 0x01

                unknown_version = bytearray(raw)
                unknown_version[8] = 2

                bad_w = bytearray(raw)
                bad_w[9] = 2

                bad_count_low = bytearray(raw)
                bad_count_low[_CODEC_COUNT_OFFSET:_CODEC_COUNT_OFFSET + 2] = (
                    (chains - 1).to_bytes(2, "big")
                )
                bad_count_high = bytearray(raw)
                bad_count_high[_CODEC_COUNT_OFFSET:_CODEC_COUNT_OFFSET + 2] = (
                    (chains + 1).to_bytes(2, "big")
                )

                cases = {
                    "bad_magic": bytes(bad_magic),
                    "unknown_version": bytes(unknown_version),
                    "illegal_w": bytes(bad_w),
                    "element_count_low": bytes(bad_count_low),
                    "element_count_high": bytes(bad_count_high),
                    "truncated_middle": raw[:-33],
                    "truncated_empty": b"",
                    "trailing_data": raw + b"\x00",
                }
                for case, blob in cases.items():
                    with self.subTest(w=w, entry=name, case=case):
                        with self.assertRaises(ValueError):
                            from_bytes(blob)


class WotsCheckpointBoundaryTest(unittest.TestCase):
    def test_bytes_and_bytearray_restore_equally(self):
        for w in (4, 8):
            samples = load_samples(w)
            raw = samples["checkpoint_unused"]
            signer = WOTSOneTimeSigner.from_checkpoint(raw)
            signer_from_array = WOTSOneTimeSigner.from_checkpoint(
                bytearray(raw)
            )
            self.assertEqual(
                signer_from_array.public_key, signer.public_key
            )
            self.assertEqual(signer_from_array.used, signer.used)
            self.assertEqual(signer_from_array.checkpoint(), signer.checkpoint())

    def test_string_input_raises_type_error(self):
        for w in (4, 8):
            with self.assertRaises(TypeError):
                WOTSOneTimeSigner.from_checkpoint("not bytes")

    def test_structural_fields_rejected_even_with_correct_checksum(self):
        for w in (4, 8):
            chains = chains_for(w)
            samples = load_samples(w)
            raw = samples["checkpoint_unused"]
            body = bytearray(raw[:-_CHECKPOINT_CHECKSUM_BYTES])

            bad_magic = bytearray(body)
            bad_magic[0] ^= 0x01

            unknown_version = bytearray(body)
            unknown_version[_CHECKPOINT_VERSION_OFFSET] = 2

            bad_w = bytearray(body)
            bad_w[_CHECKPOINT_W_OFFSET] = 2

            bad_used = bytearray(body)
            bad_used[_CHECKPOINT_USED_OFFSET] = 2

            bad_count = bytearray(body)
            bad_count[_CHECKPOINT_COUNT_OFFSET:_CHECKPOINT_COUNT_OFFSET + 2] = (
                (chains + 1).to_bytes(2, "big")
            )

            # Every case carries a freshly computed, correct SHA-256 over
            # the tampered body: rejection therefore proves the structural
            # field is validated, instead of only the checksum failing.
            cases = {
                "bad_magic": bytes(bad_magic),
                "unknown_version": bytes(unknown_version),
                "illegal_w": bytes(bad_w),
                "illegal_used_flag": bytes(bad_used),
                "element_count_mismatch": bytes(bad_count),
            }
            for case, tampered_body in cases.items():
                with self.subTest(w=w, case=case):
                    with self.assertRaises(ValueError):
                        WOTSOneTimeSigner.from_checkpoint(
                            with_fresh_checksum(tampered_body)
                        )

    def test_truncation_and_trailing_data_rejected(self):
        for w in (4, 8):
            raw = load_samples(w)["checkpoint_unused"]
            for case, blob in (
                ("empty", b""),
                ("header_only", raw[:12]),
                ("missing_one_byte", raw[:-1]),
                ("trailing_data", raw + b"\x00"),
            ):
                with self.subTest(w=w, case=case):
                    with self.assertRaises(ValueError):
                        WOTSOneTimeSigner.from_checkpoint(blob)

    def test_checksum_mismatch_rejected_with_intact_body(self):
        for w in (4, 8):
            raw = load_samples(w)["checkpoint_unused"]
            bad = bytearray(raw)
            bad[-1] ^= 0x01
            with self.subTest(w=w):
                with self.assertRaises(ValueError):
                    WOTSOneTimeSigner.from_checkpoint(bytes(bad))

    def test_field_errors_are_distinct_from_checksum_errors(self):
        # The same body tamper must fail for two independent reasons:
        # the stale trailer (checksum layer) and, after the trailer is
        # corrected, the illegal field itself (structure layer).
        for w in (4, 8):
            raw = load_samples(w)["checkpoint_unused"]
            body = bytearray(raw[:-_CHECKPOINT_CHECKSUM_BYTES])
            body[_CHECKPOINT_USED_OFFSET] = 2
            stale_trailer = bytes(body) + raw[-_CHECKPOINT_CHECKSUM_BYTES:]
            with self.subTest(w=w, layer="checksum"):
                with self.assertRaises(ValueError):
                    WOTSOneTimeSigner.from_checkpoint(stale_trailer)
            with self.subTest(w=w, layer="field"):
                with self.assertRaises(ValueError):
                    WOTSOneTimeSigner.from_checkpoint(
                        with_fresh_checksum(bytes(body))
                    )


if __name__ == "__main__":
    unittest.main()

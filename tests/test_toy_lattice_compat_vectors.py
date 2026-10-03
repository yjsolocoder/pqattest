"""Fixed-byte compatibility regression tests for the toy lattice v1 signature path.

These tests pin the on-disk v1 encodings of :class:`ToyLatticePrivateKey`,
:class:`ToyLatticePublicKey` and :class:`ToyLatticeSignature` — together
with the public ``toy_lattice_keygen`` / ``toy_lattice_sign`` /
``toy_lattice_verify`` path — to checked-in golden bytes (see
``tests/fixtures/toy_lattice_compat/README.md``). The golden samples were
produced once from documented deterministic inputs (a fixed eight-byte
keygen token, a fixed eight-byte signing token and a fixed message) and
are only ever read here: they are never regenerated through the functions
under test, and the assertions are byte-for-byte comparisons against the
samples rather than length checks or current-version round trips. A round
trip that merely succeeds against the current version proves nothing about
compatibility; only equality with the frozen bytes does.

Coverage:

* a key pair generated through the public ``toy_lattice_keygen`` entry
  from the documented fixed eight-byte token input encodes to the frozen
  private-key and public-key bytes, and the frozen bytes decode back
  through the public ``from_bytes`` entries to value-equal keys;
* a signature made through the public ``toy_lattice_sign`` entry from the
  documented fixed eight-byte randomness input encodes to the frozen
  signature bytes, for both the context-free sample and the sample bound
  to the fixed non-empty Chinese context;
* keys and signatures restored *only* from the frozen bytes verify the
  original message, and the restored private key re-signing the same
  message with the same fixed randomness reproduces the frozen signature
  byte-for-byte;
* omitting ``context``, passing ``None`` and passing any of the three
  legal empty values (``b""``, ``bytearray(b"")``, ``""``) all yield the
  frozen context-free signature bytes;
* the message and the context are each accepted as ``str``, UTF-8
  ``bytes`` and ``bytearray`` with byte-identical results;
* the correct combination verifies ``True`` while a changed message,
  public key, signature tag or context — including crossing a context
  signature with no context or vice versa — verifies ``False``.

The failure cases pin the documented parsing boundaries of the three
decode entries involved here (``ToyLatticePrivateKey.from_bytes``,
``ToyLatticePublicKey.from_bytes`` and ``ToyLatticeSignature.from_bytes``):
``bytes`` and ``bytearray`` are equivalent, any other input type raises
``TypeError``, and bad magic / unknown version / truncation / trailing
data / a vector coefficient above 256 / a signature tag length other than
32 all raise ``ValueError``. A coefficient of exactly 256 stays legal on
the decode path even though key generation only ever draws single-byte
coefficients. A structurally legal signature whose tag was altered still
decodes and then verifies ``False``, and a mistyped public key or context
on the verify side raises ``TypeError``.

The two test classes separate the two regression signals: encoding byte
changes (:class:`ToyLatticeCompatVectorTest`) and old-sample parse
failures (:class:`ToyLatticeCompatParsingBoundaryTest`).
"""

import os
import unittest

from pqattest import (
    ToyLatticePrivateKey,
    ToyLatticePublicKey,
    ToyLatticeSignature,
    toy_lattice_keygen,
    toy_lattice_sign,
    toy_lattice_verify,
)
from pqattest.toy_lattice import _decode_e

FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "fixtures", "toy_lattice_compat"
)

# Documented deterministic inputs of the frozen samples (see the fixture
# README). All are public, non-secret test values.
KEY_TOKEN = b"compat-k"  # fixed eight-byte keygen token input
SIGN_TOKEN = b"compat-s"  # fixed eight-byte signing randomness input
OTHER_KEY_TOKEN = b"compat-K"  # a different fixed key input, never sampled
MESSAGE = b"compat-toy-lattice-v1"
MESSAGE_TAMPERED = b"compat-toy-lattice-v1-changed"
CONTEXT = "格基玩具/上下文/v1"  # non-empty Chinese context
CONTEXT_BYTES = CONTEXT.encode("utf-8")

SAMPLE_NAMES = (
    "private_key.bin",
    "public_key.bin",
    "signature.bin",
    "signature_context.bin",
)

# Documented v1 codec layout (see the to_bytes docstrings and README):
# 8 magic | 1 version | 16 E-encoded vector | ...; keys end there
# (25 bytes), signatures add 4 tag-length bytes and the 32-byte tag
# (61 bytes).
_VERSION_OFFSET = 8
_VECTOR_OFFSET = 9
_ELEMENT_BYTES = 16
_KEY_BYTES = _VECTOR_OFFSET + _ELEMENT_BYTES
_TAG_LENGTH_OFFSET = _VECTOR_OFFSET + _ELEMENT_BYTES
_SIGNATURE_BYTES = _TAG_LENGTH_OFFSET + 4 + 32


def fixed_tokens(value: bytes):
    """A ``token_bytes`` source returning one fixed eight-byte value."""

    def token_bytes(size: int) -> bytes:
        assert size == len(value)
        return value

    return token_bytes


def fixture(name: str) -> bytes:
    """Read one frozen sample; a missing sample fails, never skips.

    A missing golden file is a compatibility failure in its own right
    (the fixed regression basis is gone), so it raises
    ``AssertionError`` instead of returning ``None`` or triggering
    regeneration.
    """
    path = os.path.join(FIXTURE_DIR, name)
    if not os.path.isfile(path):
        raise AssertionError(
            f"missing frozen toy-lattice compatibility sample: {path!s}; "
            "the golden samples must be checked in and must never be "
            "regenerated by the test suite"
        )
    with open(path, "rb") as handle:
        return handle.read()


def load_samples() -> dict:
    return {name[:-4]: fixture(name) for name in SAMPLE_NAMES}


def decode_entries(samples: dict):
    """Every decode entry involved in this chain, with a valid sample."""
    return (
        ("private_key", ToyLatticePrivateKey.from_bytes, samples["private_key"]),
        ("public_key", ToyLatticePublicKey.from_bytes, samples["public_key"]),
        ("signature", ToyLatticeSignature.from_bytes, samples["signature"]),
    )


def restore_pair(samples: dict):
    """Restore the key pair and context-free signature from samples only."""
    private_key = ToyLatticePrivateKey.from_bytes(samples["private_key"])
    public_key = ToyLatticePublicKey.from_bytes(samples["public_key"])
    signature = ToyLatticeSignature.from_bytes(samples["signature"])
    return private_key, public_key, signature


class ToyLatticeCompatVectorTest(unittest.TestCase):
    def test_all_frozen_samples_are_present(self):
        for name in SAMPLE_NAMES:
            with self.subTest(name=name):
                # fixture() fails rather than skipping when absent.
                self.assertTrue(os.path.isfile(os.path.join(FIXTURE_DIR, name)))

    def test_keygen_and_key_codecs_match_frozen_samples(self):
        samples = load_samples()
        private_key, public_key = toy_lattice_keygen(
            token_bytes=fixed_tokens(KEY_TOKEN)
        )
        # The encoders over the documented fixed input match the frozen
        # bytes exactly: any difference here is an encoding change, not a
        # parse failure.
        self.assertEqual(private_key.to_bytes(), samples["private_key"])
        self.assertEqual(public_key.to_bytes(), samples["public_key"])
        # The frozen bytes decode through the public entries to keys
        # equal by value.
        self.assertEqual(
            ToyLatticePrivateKey.from_bytes(samples["private_key"]), private_key
        )
        self.assertEqual(
            ToyLatticePublicKey.from_bytes(samples["public_key"]), public_key
        )

    def test_sign_matches_frozen_context_free_sample(self):
        samples = load_samples()
        private_key, _ = toy_lattice_keygen(token_bytes=fixed_tokens(KEY_TOKEN))
        signature = toy_lattice_sign(
            MESSAGE, private_key, token_bytes=fixed_tokens(SIGN_TOKEN)
        )
        self.assertEqual(signature.to_bytes(), samples["signature"])
        self.assertEqual(
            ToyLatticeSignature.from_bytes(samples["signature"]), signature
        )

    def test_restored_sample_objects_verify_original_message(self):
        samples = load_samples()
        _, public_key, signature = restore_pair(samples)
        # Message accepted as bytes, bytearray and str alike.
        self.assertTrue(toy_lattice_verify(MESSAGE, signature, public_key))
        self.assertTrue(
            toy_lattice_verify(bytearray(MESSAGE), signature, public_key)
        )
        self.assertTrue(
            toy_lattice_verify(MESSAGE.decode("ascii"), signature, public_key)
        )

    def test_restored_private_key_resigns_frozen_signature(self):
        samples = load_samples()
        private_key, _, _ = restore_pair(samples)
        # The private key recovered only from the frozen bytes reproduces
        # the frozen signature under the documented fixed randomness.
        resigned = toy_lattice_sign(
            MESSAGE, private_key, token_bytes=fixed_tokens(SIGN_TOKEN)
        )
        self.assertEqual(resigned.to_bytes(), samples["signature"])

    def test_omitted_none_and_empty_contexts_give_frozen_bytes(self):
        samples = load_samples()
        private_key, _ = toy_lattice_keygen(token_bytes=fixed_tokens(KEY_TOKEN))
        variants = {
            "omitted": {},
            "none": {"context": None},
            "empty_bytes": {"context": b""},
            "empty_bytearray": {"context": bytearray(b"")},
            "empty_str": {"context": ""},
        }
        for name, kwargs in variants.items():
            with self.subTest(variant=name):
                signature = toy_lattice_sign(
                    MESSAGE,
                    private_key,
                    token_bytes=fixed_tokens(SIGN_TOKEN),
                    **kwargs,
                )
                self.assertEqual(signature.to_bytes(), samples["signature"])

    def test_sign_matches_frozen_context_sample_for_all_input_forms(self):
        samples = load_samples()
        private_key, public_key = toy_lattice_keygen(
            token_bytes=fixed_tokens(KEY_TOKEN)
        )
        messages = (MESSAGE, bytearray(MESSAGE), MESSAGE.decode("ascii"))
        contexts = (CONTEXT, CONTEXT_BYTES, bytearray(CONTEXT_BYTES))
        for message in messages:
            for context in contexts:
                with self.subTest(
                    message=type(message).__name__,
                    context=type(context).__name__,
                ):
                    signature = toy_lattice_sign(
                        message,
                        private_key,
                        token_bytes=fixed_tokens(SIGN_TOKEN),
                        context=context,
                    )
                    # Every str/bytes/bytearray spelling of the same
                    # message and context yields the frozen bytes.
                    self.assertEqual(
                        signature.to_bytes(), samples["signature_context"]
                    )
                    self.assertTrue(
                        toy_lattice_verify(
                            message, signature, public_key, context=context
                        )
                    )

    def test_frozen_context_sample_verifies_from_samples_only(self):
        samples = load_samples()
        public_key = ToyLatticePublicKey.from_bytes(samples["public_key"])
        signature = ToyLatticeSignature.from_bytes(samples["signature_context"])
        self.assertTrue(
            toy_lattice_verify(MESSAGE, signature, public_key, context=CONTEXT)
        )

    def test_mismatches_return_false(self):
        samples = load_samples()
        _, public_key, signature = restore_pair(samples)
        _, other_public = toy_lattice_keygen(
            token_bytes=fixed_tokens(OTHER_KEY_TOKEN)
        )
        # A different message.
        self.assertFalse(toy_lattice_verify(MESSAGE_TAMPERED, signature, public_key))
        self.assertFalse(toy_lattice_verify(b"", signature, public_key))
        # A different public key.
        self.assertFalse(toy_lattice_verify(MESSAGE, signature, other_public))
        # An altered signature tag on an otherwise legal structure.
        tampered = ToyLatticeSignature(signature.u, b"\x00" * 32)
        self.assertFalse(toy_lattice_verify(MESSAGE, tampered, public_key))
        # A non-empty context rejects the context-free signature.
        self.assertFalse(
            toy_lattice_verify(MESSAGE, signature, public_key, context=CONTEXT)
        )

    def test_context_and_context_free_signatures_do_not_cross_verify(self):
        samples = load_samples()
        public_key = ToyLatticePublicKey.from_bytes(samples["public_key"])
        context_free = ToyLatticeSignature.from_bytes(samples["signature"])
        context_bound = ToyLatticeSignature.from_bytes(samples["signature_context"])
        # The two samples share key, message and randomness; only the
        # context binding separates them.
        self.assertEqual(context_free.u, context_bound.u)
        self.assertNotEqual(context_free.tag, context_bound.tag)
        self.assertFalse(
            toy_lattice_verify(MESSAGE, context_bound, public_key)
        )
        self.assertFalse(
            toy_lattice_verify(MESSAGE, context_bound, public_key, context=b"x")
        )
        self.assertFalse(
            toy_lattice_verify(
                MESSAGE, context_free, public_key, context=CONTEXT
            )
        )
        self.assertTrue(
            toy_lattice_verify(
                MESSAGE, context_bound, public_key, context=CONTEXT
            )
        )
        self.assertTrue(toy_lattice_verify(MESSAGE, context_free, public_key))


class ToyLatticeCompatParsingBoundaryTest(unittest.TestCase):
    def test_bytes_and_bytearray_decode_equivalently(self):
        samples = load_samples()
        for name, decode, raw in decode_entries(samples):
            with self.subTest(entry=name):
                self.assertEqual(decode(bytearray(raw)), decode(raw))

    def test_non_bytes_input_raises_type_error(self):
        samples = load_samples()
        for name, decode, raw in decode_entries(samples):
            for bad in (
                raw.decode("latin1"),
                None,
                42,
                [raw],
                memoryview(raw),
            ):
                with self.subTest(entry=name, bad=type(bad).__name__):
                    with self.assertRaises(TypeError):
                        decode(bad)

    def test_entries_reject_bad_magic_and_unknown_version(self):
        samples = load_samples()
        for name, decode, raw in decode_entries(samples):
            for case, offset, value in (
                ("bad_magic", 0, raw[0] ^ 0x01),
                ("unknown_version", _VERSION_OFFSET, 2),
            ):
                with self.subTest(entry=name, case=case):
                    bad = bytearray(raw)
                    bad[offset] = value
                    with self.assertRaises(ValueError):
                        decode(bytes(bad))

    def test_entries_reject_truncation_and_trailing_data(self):
        samples = load_samples()
        for name, decode, raw in decode_entries(samples):
            for case, blob in (
                ("empty", b""),
                ("truncated_header", raw[:_VERSION_OFFSET]),
                ("truncated", raw[:-1]),
                ("trailing", raw + b"\x00"),
            ):
                with self.subTest(entry=name, case=case):
                    with self.assertRaises(ValueError):
                        decode(blob)

    def test_entries_reject_coefficient_above_256(self):
        samples = load_samples()
        for name, decode, raw in decode_entries(samples):
            with self.subTest(entry=name):
                bad = bytearray(raw)
                # First vector coefficient 257 is out of the 0..256 range.
                bad[_VECTOR_OFFSET : _VECTOR_OFFSET + 2] = b"\x01\x01"
                with self.assertRaises(ValueError):
                    decode(bytes(bad))

    def test_coefficient_256_remains_decodable(self):
        # Key generation only draws single-byte coefficients, but the
        # decode range is the full 0..256 of the E encoding and must not
        # be narrowed: a coefficient of exactly 256 stays legal.
        vector = b"\x01\x00" + b"\x00" * 14
        for name, decode, raw in decode_entries(load_samples()):
            with self.subTest(entry=name):
                blob = bytearray(raw)
                blob[_VECTOR_OFFSET : _VECTOR_OFFSET + _ELEMENT_BYTES] = vector
                decoded = decode(bytes(blob))
                field = decoded.s if name == "private_key" else (
                    decoded.t if name == "public_key" else decoded.u
                )
                self.assertEqual(_decode_e(field)[0], 256)

    def test_signature_rejects_tag_length_other_than_32(self):
        raw = load_samples()["signature"]
        header = raw[:_TAG_LENGTH_OFFSET]
        for case, blob in (
            ("tag_length_31", header + (31).to_bytes(4, "big") + b"\x00" * 31),
            ("tag_length_33", header + (33).to_bytes(4, "big") + b"\x00" * 33),
            ("tag_length_0", header + (0).to_bytes(4, "big")),
        ):
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    ToyLatticeSignature.from_bytes(blob)

    def test_tag_tampered_sample_decodes_and_verifies_false(self):
        samples = load_samples()
        public_key = ToyLatticePublicKey.from_bytes(samples["public_key"])
        tampered = bytearray(samples["signature"])
        tampered[-1] ^= 0x01  # flip one tag bit; structure stays legal
        signature = ToyLatticeSignature.from_bytes(bytes(tampered))
        self.assertIsInstance(signature, ToyLatticeSignature)
        self.assertFalse(toy_lattice_verify(MESSAGE, signature, public_key))

    def test_verify_rejects_mistyped_public_key_and_context(self):
        samples = load_samples()
        private_key, public_key, signature = restore_pair(samples)
        for bad in (None, samples["public_key"], private_key, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    toy_lattice_verify(MESSAGE, signature, bad)
        for bad in (0, 1, 1.5, ["ctx"], {"ctx": 1}, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    toy_lattice_verify(MESSAGE, signature, public_key, context=bad)
                with self.assertRaises(TypeError):
                    toy_lattice_sign(
                        MESSAGE,
                        private_key,
                        token_bytes=fixed_tokens(SIGN_TOKEN),
                        context=bad,
                    )


if __name__ == "__main__":
    unittest.main()

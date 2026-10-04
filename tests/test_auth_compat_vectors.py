"""Fixed-byte compatibility regression tests for the auth envelope formats.

These tests pin the on-disk v1 (:func:`auth_wrap` / :func:`auth_unwrap`)
and v2 (:func:`auth_state_wrap` / :func:`auth_state_unwrap` /
:func:`auth_state_fingerprint`) authenticated envelope encodings to
checked-in golden bytes (see ``tests/fixtures/auth_compat/README.md``).
The golden samples were produced once from documented deterministic
public inputs and are only ever read here: they are never regenerated
through the encoder under test, and the assertions are byte-for-byte
comparisons against the samples rather than current-version round trips
— an encoder and decoder that drift together do not satisfy these tests.

Coverage:

* every frozen payload is rebuilt from its documented deterministic
  public input through the public key-generation entries and must match
  the frozen payload bytes, and wrapping the frozen payload through
  ``auth_wrap`` / ``auth_state_wrap`` must reproduce the frozen envelope
  byte for byte;
* every frozen envelope decodes through the public decode entry to the
  documented scheme, generation and the frozen payload bytes, and every
  frozen v2 envelope's ``auth_state_fingerprint`` equals the frozen
  32-byte fingerprint;
* repeated identical calls and ``bytes`` vs ``bytearray`` inputs give
  identical results, and decoded payloads and fingerprints are
  ``bytes``;
* version isolation: a frozen v1 envelope fed to the v2 decode or
  fingerprint entries, and a frozen v2 envelope fed to the v1 decode
  entry, all raise ``ValueError``;
* wrong key, tag tampering, truncation, trailing data and an ``expect``
  mismatch all raise ``ValueError``, and an envelope whose length field
  is corrupted but whose tag is *recomputed* over the tampered body is
  still rejected by the structural checks;
* the generation floor accepts a generation equal to the floor and
  rejects one below it; the two same-generation Merkle envelopes decode
  independently, each is rejected when unwrapped with the *other's*
  frozen fingerprint, and a replay of the exact accepted envelope with
  its own fingerprint still succeeds;
* non-bytes inputs raise ``TypeError`` at every public entry.

A missing golden file fails the test outright (``AssertionError``); the
suite never skips, regenerates or updates the samples.
"""

import hashlib
import hmac
import os
import unittest

from pqattest import (
    MerkleSigner,
    OneTimeSigner,
    WOTSOneTimeSigner,
    auth_state_fingerprint,
    auth_state_unwrap,
    auth_state_wrap,
    auth_unwrap,
    auth_wrap,
    keygen,
    toy_lattice_keygen,
    wots_keygen,
)

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "auth_compat")

# The frozen shared test key lives in auth_key.bin; this distinct fixed
# value only plays the attacker's key on the rejection paths.
WRONG_KEY = b"wrong-auth-compat-key"

# Fixed message behind payload_merkle_spent.bin (see the fixture README).
MERKLE_MESSAGE = b"compat-auth-merkle"

UINT64_MAX = 2**64 - 1

# v1 samples: envelope file -> (scheme, payload file).
V1_SAMPLES = {
    "v1_lamport.bin": ("lamport", "payload_lamport.bin"),
    "v1_wots.bin": ("wots", "payload_wots.bin"),
    "v1_merkle.bin": ("merkle", "payload_merkle_initial.bin"),
    "v1_lattice.bin": ("lattice", "payload_lattice.bin"),
}

# v2 samples: envelope file -> (scheme, payload file, generation). The set
# covers generation 0, an ordinary positive generation and 2**64 - 1.
V2_SAMPLES = {
    "v2_lamport_g0.bin": ("lamport", "payload_lamport.bin", 0),
    "v2_wots_g7.bin": ("wots", "payload_wots.bin", 7),
    "v2_merkle_initial_g3.bin": ("merkle", "payload_merkle_initial.bin", 3),
    "v2_merkle_spent_g3.bin": ("merkle", "payload_merkle_spent.bin", 3),
    "v2_lattice_gmax.bin": ("lattice", "payload_lattice.bin", UINT64_MAX),
}

PAYLOAD_NAMES = (
    "payload_lamport.bin",
    "payload_wots.bin",
    "payload_merkle_initial.bin",
    "payload_merkle_spent.bin",
    "payload_lattice.bin",
)


def counter_tokens():
    """Deterministic key input shared by the frozen samples.

    The Nth call returns the integer N as a 32-byte big-endian value, so
    every secret is a public, repeatable value. Each scheme uses its own
    independent counter.
    """
    state = {"value": 0}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(32, "big")

    return token_bytes


def fixed_token(value: bytes):
    """A ``token_bytes`` source returning one fixed value once."""

    def token_bytes(size: int) -> bytes:
        assert len(value) == size
        return value

    return token_bytes


def rebuild_payloads() -> dict:
    """Rebuild every frozen payload from its documented public input."""
    lamport = OneTimeSigner(keygen(bits=32, token_bytes=counter_tokens())[0])
    wots = WOTSOneTimeSigner(wots_keygen(w=4, token_bytes=counter_tokens())[0])
    merkle = MerkleSigner(height=2, w=4, token_bytes=counter_tokens())
    merkle_spent = MerkleSigner(height=2, w=4, token_bytes=counter_tokens())
    merkle_spent.sign(MERKLE_MESSAGE)
    lattice_private, _ = toy_lattice_keygen(token_bytes=fixed_token(b"compat-k"))
    return {
        "payload_lamport.bin": lamport.checkpoint(),
        "payload_wots.bin": wots.checkpoint(),
        "payload_merkle_initial.bin": merkle.checkpoint(),
        "payload_merkle_spent.bin": merkle_spent.checkpoint(),
        "payload_lattice.bin": lattice_private.to_bytes(),
    }


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
            f"missing frozen auth compatibility sample: {path!s}; "
            "the golden samples must be checked in and must never be "
            "regenerated by the test suite"
        )
    with open(path, "rb") as handle:
        return handle.read()


def auth_key() -> bytes:
    return fixture("auth_key.bin")


def fingerprint_name(envelope_name: str) -> str:
    return envelope_name.replace("v2_", "fingerprint_", 1)


def retag_with_wrong_length(blob: bytes, length_offset: int, delta: int) -> bytes:
    """Corrupt the 4-byte length field and re-tag with the frozen key.

    The tag is valid for the tampered body, so only the structural
    length/contents check — never the tag check — can reject the result.
    """
    body = bytearray(blob[:-32])
    claimed = int.from_bytes(body[length_offset : length_offset + 4], "big")
    body[length_offset : length_offset + 4] = (claimed + delta).to_bytes(4, "big")
    return bytes(body) + hmac.new(
        auth_key(), bytes(body), hashlib.sha256
    ).digest()


class AuthCompatVectorTest(unittest.TestCase):
    def test_all_frozen_samples_are_present(self):
        names = ["auth_key.bin", *PAYLOAD_NAMES]
        names += sorted(V1_SAMPLES)
        names += sorted(V2_SAMPLES)
        names += sorted(fingerprint_name(name) for name in V2_SAMPLES)
        for name in names:
            with self.subTest(name=name):
                # fixture() fails rather than skipping when absent.
                self.assertTrue(os.path.isfile(os.path.join(FIXTURE_DIR, name)))

    def test_rebuilt_payloads_match_frozen_payloads(self):
        rebuilt = rebuild_payloads()
        for name in PAYLOAD_NAMES:
            with self.subTest(name=name):
                self.assertEqual(rebuilt[name], fixture(name))

    def test_v1_encode_matches_frozen_envelopes(self):
        for name, (scheme, payload_name) in V1_SAMPLES.items():
            with self.subTest(name=name):
                blob = auth_wrap(
                    fixture(payload_name), scheme=scheme, key=auth_key()
                )
                self.assertEqual(blob, fixture(name))

    def test_v2_encode_matches_frozen_envelopes(self):
        for name, (scheme, payload_name, generation) in V2_SAMPLES.items():
            with self.subTest(name=name):
                blob = auth_state_wrap(
                    fixture(payload_name),
                    scheme=scheme,
                    key=auth_key(),
                    generation=generation,
                )
                self.assertEqual(blob, fixture(name))

    def test_v1_decode_recovers_scheme_and_frozen_payload(self):
        for name, (scheme, payload_name) in V1_SAMPLES.items():
            with self.subTest(name=name):
                got_scheme, payload = auth_unwrap(
                    fixture(name), key=auth_key()
                )
                self.assertEqual(got_scheme, scheme)
                self.assertEqual(payload, fixture(payload_name))
                self.assertIsInstance(payload, bytes)

    def test_v2_decode_recovers_scheme_generation_and_frozen_payload(self):
        for name, (scheme, payload_name, generation) in V2_SAMPLES.items():
            with self.subTest(name=name):
                got_scheme, got_generation, payload = auth_state_unwrap(
                    fixture(name), key=auth_key()
                )
                self.assertEqual(got_scheme, scheme)
                self.assertEqual(got_generation, generation)
                self.assertEqual(payload, fixture(payload_name))
                self.assertIsInstance(payload, bytes)

    def test_fingerprints_match_frozen_values(self):
        for name in V2_SAMPLES:
            with self.subTest(name=name):
                state_id = auth_state_fingerprint(
                    fixture(name), key=auth_key()
                )
                self.assertIsInstance(state_id, bytes)
                self.assertEqual(len(state_id), 32)
                self.assertEqual(state_id, fixture(fingerprint_name(name)))

    def test_encode_is_deterministic_over_frozen_inputs(self):
        payload = fixture("payload_lamport.bin")
        first = auth_wrap(payload, scheme="lamport", key=auth_key())
        second = auth_wrap(payload, scheme="lamport", key=auth_key())
        self.assertEqual(first, second)
        self.assertEqual(first, fixture("v1_lamport.bin"))
        first_v2 = auth_state_wrap(
            payload, scheme="lamport", key=auth_key(), generation=0
        )
        second_v2 = auth_state_wrap(
            payload, scheme="lamport", key=auth_key(), generation=0
        )
        self.assertEqual(first_v2, second_v2)
        self.assertEqual(first_v2, fixture("v2_lamport_g0.bin"))

    def test_bytes_and_bytearray_inputs_are_equivalent(self):
        payload = fixture("payload_wots.bin")
        from_arrays = auth_wrap(
            bytearray(payload), scheme="wots", key=bytearray(auth_key())
        )
        self.assertEqual(from_arrays, fixture("v1_wots.bin"))
        from_arrays_v2 = auth_state_wrap(
            bytearray(payload),
            scheme="wots",
            key=bytearray(auth_key()),
            generation=7,
        )
        self.assertEqual(from_arrays_v2, fixture("v2_wots_g7.bin"))

        blob = fixture("v2_wots_g7.bin")
        scheme, generation, payload_out = auth_state_unwrap(
            bytearray(blob), key=bytearray(auth_key())
        )
        self.assertEqual((scheme, generation), ("wots", 7))
        self.assertEqual(payload_out, payload)
        self.assertIsInstance(payload_out, bytes)

        state_id = auth_state_fingerprint(
            bytearray(blob), key=bytearray(auth_key())
        )
        self.assertIsInstance(state_id, bytes)
        self.assertEqual(state_id, fixture("fingerprint_wots_g7.bin"))


class AuthCompatVersionIsolationTest(unittest.TestCase):
    def test_v1_envelope_rejected_by_v2_entries(self):
        for name in V1_SAMPLES:
            with self.subTest(name=name):
                blob = fixture(name)
                self.assertEqual(blob[8], 1)
                with self.assertRaises(ValueError):
                    auth_state_unwrap(blob, key=auth_key())
                with self.assertRaises(ValueError):
                    auth_state_fingerprint(blob, key=auth_key())

    def test_v2_envelope_rejected_by_v1_unwrap(self):
        for name in V2_SAMPLES:
            with self.subTest(name=name):
                blob = fixture(name)
                self.assertEqual(blob[8], 2)
                with self.assertRaises(ValueError):
                    auth_unwrap(blob, key=auth_key())


class AuthCompatRejectionTest(unittest.TestCase):
    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            auth_unwrap(fixture("v1_lamport.bin"), key=WRONG_KEY)
        with self.assertRaises(ValueError):
            auth_state_unwrap(fixture("v2_wots_g7.bin"), key=WRONG_KEY)
        with self.assertRaises(ValueError):
            auth_state_fingerprint(fixture("v2_wots_g7.bin"), key=WRONG_KEY)

    def test_tampered_tag_rejected(self):
        for name in ("v1_lamport.bin", "v2_lamport_g0.bin"):
            with self.subTest(name=name):
                bad = bytearray(fixture(name))
                bad[-1] ^= 0x01
                with self.assertRaises(ValueError):
                    auth_unwrap(bytes(bad), key=auth_key())
                with self.assertRaises(ValueError):
                    auth_state_unwrap(bytes(bad), key=auth_key())

    def test_truncation_rejected(self):
        for name in ("v1_wots.bin", "v2_wots_g7.bin"):
            blob = fixture(name)
            for cut in (0, 8, len(blob) - 33, len(blob) - 1):
                with self.subTest(name=name, cut=cut):
                    with self.assertRaises(ValueError):
                        auth_unwrap(blob[:cut], key=auth_key())
                    with self.assertRaises(ValueError):
                        auth_state_unwrap(blob[:cut], key=auth_key())

    def test_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            auth_unwrap(fixture("v1_lattice.bin") + b"\x00", key=auth_key())
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                fixture("v2_lattice_gmax.bin") + b"\x00", key=auth_key()
            )
        with self.assertRaises(ValueError):
            auth_state_fingerprint(
                fixture("v2_lattice_gmax.bin") + b"\x00", key=auth_key()
            )

    def test_expect_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            auth_unwrap(fixture("v1_lamport.bin"), key=auth_key(), expect="wots")
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                fixture("v2_wots_g7.bin"), key=auth_key(), expect="merkle"
            )
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                fixture("v2_lattice_gmax.bin"),
                key=auth_key(),
                expect="lamport",
            )

    def test_valid_tag_with_wrong_length_field_still_rejected(self):
        # The tag matches the tampered body, so the rejection must come
        # from the structural length check itself.
        # v1 header: magic(8) | version(1) | scheme(1) | length(4) at 10.
        forged_v1 = retag_with_wrong_length(
            fixture("v1_lamport.bin"), 10, +1
        )
        with self.assertRaises(ValueError):
            auth_unwrap(forged_v1, key=auth_key())
        # v2 header: magic(8) | version(1) | scheme(1) | generation(8) |
        # length(4) at 18.
        forged_v2_short = retag_with_wrong_length(
            fixture("v2_lamport_g0.bin"), 18, -1
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(forged_v2_short, key=auth_key())
        forged_v2_long = retag_with_wrong_length(
            fixture("v2_lamport_g0.bin"), 18, +1
        )
        with self.assertRaises(ValueError):
            auth_state_unwrap(forged_v2_long, key=auth_key())
        with self.assertRaises(ValueError):
            auth_state_fingerprint(forged_v2_long, key=auth_key())


class AuthCompatStateBindingTest(unittest.TestCase):
    def test_generation_equal_to_floor_accepted(self):
        cases = (
            ("v2_lamport_g0.bin", 0),
            ("v2_wots_g7.bin", 7),
            ("v2_merkle_initial_g3.bin", 3),
            ("v2_lattice_gmax.bin", UINT64_MAX),
        )
        for name, generation in cases:
            with self.subTest(name=name):
                scheme, got_generation, payload = auth_state_unwrap(
                    fixture(name), key=auth_key(), min_generation=generation
                )
                self.assertEqual(got_generation, generation)
                self.assertEqual(scheme, V2_SAMPLES[name][0])
                self.assertEqual(payload, fixture(V2_SAMPLES[name][1]))

    def test_generation_below_floor_rejected(self):
        cases = (
            ("v2_lamport_g0.bin", 1),
            ("v2_wots_g7.bin", 8),
            ("v2_merkle_spent_g3.bin", 4),
        )
        for name, floor in cases:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    auth_state_unwrap(
                        fixture(name), key=auth_key(), min_generation=floor
                    )

    def test_same_generation_payloads_decode_independently(self):
        initial = auth_state_unwrap(
            fixture("v2_merkle_initial_g3.bin"), key=auth_key()
        )
        spent = auth_state_unwrap(
            fixture("v2_merkle_spent_g3.bin"), key=auth_key()
        )
        self.assertEqual(initial[0], spent[0])
        self.assertEqual(initial[1], spent[1])
        self.assertEqual(initial[2], fixture("payload_merkle_initial.bin"))
        self.assertEqual(spent[2], fixture("payload_merkle_spent.bin"))
        self.assertNotEqual(initial[2], spent[2])

    def test_cross_envelope_fingerprint_rejected(self):
        # The floor cannot tell the two generation-3 envelopes apart; the
        # pinned state identity can.
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                fixture("v2_merkle_initial_g3.bin"),
                key=auth_key(),
                min_generation=3,
                expect_state_id=fixture("fingerprint_merkle_spent_g3.bin"),
            )
        with self.assertRaises(ValueError):
            auth_state_unwrap(
                fixture("v2_merkle_spent_g3.bin"),
                key=auth_key(),
                min_generation=3,
                expect_state_id=fixture("fingerprint_merkle_initial_g3.bin"),
            )

    def test_replay_of_accepted_envelope_still_succeeds(self):
        blob = fixture("v2_merkle_spent_g3.bin")
        state_id = fixture("fingerprint_merkle_spent_g3.bin")
        for attempt in (1, 2):
            with self.subTest(attempt=attempt):
                scheme, generation, payload = auth_state_unwrap(
                    blob,
                    key=auth_key(),
                    min_generation=3,
                    expect_state_id=state_id,
                )
                self.assertEqual((scheme, generation), ("merkle", 3))
                self.assertEqual(payload, fixture("payload_merkle_spent.bin"))

    def test_own_fingerprint_accepted_for_every_v2_sample(self):
        for name in V2_SAMPLES:
            with self.subTest(name=name):
                scheme, generation, payload = auth_state_unwrap(
                    fixture(name),
                    key=auth_key(),
                    expect_state_id=fixture(fingerprint_name(name)),
                )
                self.assertEqual(scheme, V2_SAMPLES[name][0])
                self.assertEqual(generation, V2_SAMPLES[name][2])
                self.assertEqual(payload, fixture(V2_SAMPLES[name][1]))


class AuthCompatTypeErrorTest(unittest.TestCase):
    def test_non_bytes_inputs_rejected(self):
        payload = fixture("payload_lamport.bin")
        blob_v1 = fixture("v1_lamport.bin")
        blob_v2 = fixture("v2_lamport_g0.bin")
        for bad in (None, 42, 4.5, "blob", [blob_v1], (blob_v1,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_wrap(bad, scheme="lamport", key=auth_key())
                with self.assertRaises(TypeError):
                    auth_state_wrap(
                        bad, scheme="lamport", key=auth_key(), generation=0
                    )
                with self.assertRaises(TypeError):
                    auth_unwrap(bad, key=auth_key())
                with self.assertRaises(TypeError):
                    auth_state_unwrap(bad, key=auth_key())
                with self.assertRaises(TypeError):
                    auth_state_fingerprint(bad, key=auth_key())
        for bad in (None, 42, "key", ["k"], object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    auth_wrap(payload, scheme="lamport", key=bad)
                with self.assertRaises(TypeError):
                    auth_state_wrap(
                        payload, scheme="lamport", key=bad, generation=0
                    )
                with self.assertRaises(TypeError):
                    auth_unwrap(blob_v1, key=bad)
                with self.assertRaises(TypeError):
                    auth_state_unwrap(blob_v2, key=bad)
                with self.assertRaises(TypeError):
                    auth_state_fingerprint(blob_v2, key=bad)


if __name__ == "__main__":
    unittest.main()

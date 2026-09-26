import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    LamportProof,
    OtsPairProof,
    PublicKey,
    WOTSProof,
    WOTSPublicKey,
    keygen,
    message_bits,
    sign,
    wots_keygen,
    wots_sign,
)

_PAIR_HEADER_BYTES = 8 + 1 + 4 + 4


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_lamport_proof(bits=8, start=0, message=b"position claim"):
    private_key, public_key = keygen(bits=bits, token_bytes=counter_tokens(start))
    signature = sign(message, private_key)
    return public_key, LamportProof(public_key=public_key, signature=signature)


def make_wots_proof(w=4, start=1000, message=b"position claim"):
    private_key, public_key = wots_keygen(w=w, token_bytes=counter_tokens(start))
    signature = wots_sign(message, private_key)
    return public_key, WOTSProof(public_key=public_key, signature=signature)


def make_pair(bits=8, w=4, message=b"position claim"):
    lamport_key, lamport = make_lamport_proof(bits=bits, start=0, message=message)
    wots_key, wots = make_wots_proof(w=w, start=1000, message=message)
    return (lamport_key, wots_key), OtsPairProof(lamport=lamport, wots=wots)


def pair_envelope(lamport_blob: bytes, wots_blob: bytes) -> bytes:
    return (
        b"PQAOPRF\0"
        + bytes((1,))
        + len(lamport_blob).to_bytes(4, "big")
        + len(wots_blob).to_bytes(4, "big")
        + lamport_blob
        + wots_blob
    )


class OtsPairProofConstructionTest(unittest.TestCase):
    def test_fields_and_equality(self):
        _, lamport = make_lamport_proof()
        _, wots = make_wots_proof()
        pair = OtsPairProof(lamport, wots)
        self.assertIs(pair.lamport, lamport)
        self.assertIs(pair.wots, wots)
        self.assertEqual(pair, OtsPairProof(lamport=lamport, wots=wots))
        self.assertEqual(hash(pair), hash(OtsPairProof(lamport=lamport, wots=wots)))

    def test_positional_construction(self):
        _, lamport = make_lamport_proof()
        _, wots = make_wots_proof()
        self.assertEqual(
            OtsPairProof(lamport, wots),
            OtsPairProof(lamport=lamport, wots=wots),
        )

    def test_frozen(self):
        _, pair = make_pair()
        with self.assertRaises(FrozenInstanceError):
            pair.lamport = pair.lamport
        with self.assertRaises(FrozenInstanceError):
            pair.wots = pair.wots

    def test_wrong_field_types_raise_type_error(self):
        _, lamport = make_lamport_proof()
        _, wots = make_wots_proof()
        for bad in (None, 42, "proof", b"raw", wots, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    OtsPairProof(lamport=bad, wots=wots)
        for bad in (None, 42, "proof", b"raw", lamport, object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    OtsPairProof(lamport=lamport, wots=bad)

    def test_swapped_fields_raise_type_error(self):
        _, lamport = make_lamport_proof()
        _, wots = make_wots_proof()
        with self.assertRaises(TypeError):
            OtsPairProof(lamport=wots, wots=lamport)

    def test_foreign_member_proofs_build_but_do_not_verify(self):
        # Construction checks member types only: without a message the pair
        # cannot cryptographically cross-check the proofs, so proofs from
        # unrelated keys are accepted here and fail at verify time (the pair
        # stores no message).
        _, lamport = make_lamport_proof(start=0)
        _, wots = make_wots_proof(start=2000, message=b"unrelated")
        pair = OtsPairProof(lamport=lamport, wots=wots)
        self.assertFalse(pair.verify(b"position claim"))


class OtsPairProofFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for w in (4, 8):
            with self.subTest(w=w):
                _, pair = make_pair(w=w)
                lamport_blob = pair.lamport.to_bytes()
                wots_blob = pair.wots.to_bytes()
                blob = pair.to_bytes()
                self.assertEqual(
                    len(blob),
                    _PAIR_HEADER_BYTES + len(lamport_blob) + len(wots_blob),
                )
                self.assertEqual(blob[:8], b"PQAOPRF\0")
                self.assertEqual(blob[8], 1)  # version
                self.assertEqual(
                    int.from_bytes(blob[9:13], "big"), len(lamport_blob)
                )
                self.assertEqual(int.from_bytes(blob[13:17], "big"), len(wots_blob))
                self.assertEqual(
                    blob[_PAIR_HEADER_BYTES : _PAIR_HEADER_BYTES + len(lamport_blob)],
                    lamport_blob,
                )
                self.assertEqual(blob[_PAIR_HEADER_BYTES + len(lamport_blob) :], wots_blob)

    def test_to_bytes_returns_bytes(self):
        _, pair = make_pair()
        self.assertIsInstance(pair.to_bytes(), bytes)

    def test_encoding_is_deterministic(self):
        _, pair = make_pair()
        self.assertEqual(pair.to_bytes(), pair.to_bytes())
        _, same = make_pair()
        self.assertEqual(pair.to_bytes(), same.to_bytes())

    def test_equal_values_have_equal_bytes(self):
        _, lamport = make_lamport_proof()
        _, wots = make_wots_proof()
        pair_a = OtsPairProof(lamport, wots)
        pair_b = OtsPairProof(lamport, wots)
        self.assertEqual(pair_a, pair_b)
        self.assertEqual(pair_a.to_bytes(), pair_b.to_bytes())

    def test_to_bytes_on_foreign_object_raises_type_error(self):
        for bad in (None, 42, "proof", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    OtsPairProof.to_bytes(bad)

    def test_corrupted_fields_encode_raises_value_error(self):
        _, pair = make_pair()
        object.__setattr__(pair, "lamport", "not-a-proof")
        with self.assertRaises(ValueError):
            pair.to_bytes()
        _, pair2 = make_pair()
        object.__setattr__(pair2, "wots", object())
        with self.assertRaises(ValueError):
            pair2.to_bytes()


class OtsPairProofRoundTripTest(unittest.TestCase):
    def test_round_trip(self):
        for w in (4, 8):
            for bits in (8, 32):
                with self.subTest(w=w, bits=bits):
                    _, pair = make_pair(bits=bits, w=w, message=b"hi")
                    restored = OtsPairProof.from_bytes(pair.to_bytes())
                    self.assertEqual(restored, pair)
                    self.assertEqual(restored.lamport, pair.lamport)
                    self.assertEqual(restored.wots, pair.wots)
                    self.assertEqual(restored.to_bytes(), pair.to_bytes())
                    self.assertTrue(restored.verify(b"hi"))

    def test_accepts_bytearray(self):
        _, pair = make_pair()
        restored = OtsPairProof.from_bytes(bytearray(pair.to_bytes()))
        self.assertEqual(restored, pair)

    def test_standalone_transport(self):
        _, pair = make_pair(message=b"position claim")
        blob = pair.to_bytes()
        # The receiver needs nothing but the blob.
        received = OtsPairProof.from_bytes(blob)
        self.assertTrue(received.verify(b"position claim"))
        self.assertFalse(received.verify(b"other claim"))


class OtsPairProofFromBytesValidationTest(unittest.TestCase):
    def setUp(self):
        _, self.pair = make_pair()
        self.blob = self.pair.to_bytes()
        self.lamport_len = int.from_bytes(self.blob[9:13], "big")
        self.wots_len = int.from_bytes(self.blob[13:17], "big")

    def assert_rejected(self, data):
        with self.assertRaises(ValueError):
            OtsPairProof.from_bytes(data)

    def test_non_bytes_types_raise_type_error(self):
        for bad in (None, 42, 4.5, "proof", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    OtsPairProof.from_bytes(bad)

    def test_truncated_and_empty_rejected(self):
        for cut in (0, 8, 9, 16, _PAIR_HEADER_BYTES, len(self.blob) - 1):
            with self.subTest(cut=cut):
                self.assert_rejected(self.blob[:cut])

    def test_trailing_data_rejected(self):
        self.assert_rejected(self.blob + b"\x00")
        self.assert_rejected(self.blob + b"tail")

    def test_bad_magic_rejected(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0x01
        self.assert_rejected(bytes(bad))
        self.assert_rejected(b"PQALPRF\0" + self.blob[8:])

    def test_bad_version_rejected(self):
        for version in (0, 2, 255):
            with self.subTest(version=version):
                bad = bytearray(self.blob)
                bad[8] = version
                self.assert_rejected(bytes(bad))

    def test_zero_lengths_rejected(self):
        for offset in (9, 13):
            with self.subTest(offset=offset):
                bad = bytearray(self.blob)
                bad[offset : offset + 4] = (0).to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_lamport_length_out_of_bounds_rejected(self):
        payload = len(self.blob) - _PAIR_HEADER_BYTES
        for length in (payload + 1, payload + 100, 1 << 31, 0xFFFFFFFF):
            with self.subTest(length=length):
                bad = bytearray(self.blob)
                bad[9:13] = length.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_wots_length_out_of_bounds_rejected(self):
        payload = len(self.blob) - _PAIR_HEADER_BYTES
        for length in (payload - self.lamport_len + 1, 1 << 31, 0xFFFFFFFF):
            with self.subTest(length=length):
                bad = bytearray(self.blob)
                bad[13:17] = length.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_lamport_length_shorter_than_encoding_rejected(self):
        for new_len in (1, self.lamport_len - 1):
            with self.subTest(new_len=new_len):
                bad = bytearray(self.blob)
                bad[9:13] = new_len.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_lamport_length_longer_misaligns_wots(self):
        bad = bytearray(self.blob)
        bad[9:13] = (self.lamport_len + 1).to_bytes(4, "big")
        self.assert_rejected(bytes(bad))

    def test_wots_length_shorter_truncates_proof(self):
        for new_len in (1, self.wots_len - 1):
            with self.subTest(new_len=new_len):
                bad = bytearray(self.blob)
                bad[13:17] = new_len.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_nested_lamport_encoding_corrupted(self):
        for name, delta in (("magic", 0), ("version", 8)):
            with self.subTest(field=name):
                bad = bytearray(self.blob)
                bad[_PAIR_HEADER_BYTES + delta] ^= 0x01
                self.assert_rejected(bytes(bad))

    def test_nested_wots_encoding_corrupted(self):
        for name, delta in (("magic", 0), ("version", 8)):
            with self.subTest(field=name):
                bad = bytearray(self.blob)
                bad[_PAIR_HEADER_BYTES + self.lamport_len + delta] ^= 0x01
                self.assert_rejected(bytes(bad))

    def test_swapped_members_rejected_by_nested_codecs(self):
        lamport_blob = self.pair.lamport.to_bytes()
        wots_blob = self.pair.wots.to_bytes()
        self.assert_rejected(pair_envelope(wots_blob, lamport_blob))

    def test_repartitioned_lengths_rejected_by_nested_codecs(self):
        # Same total payload, shifted boundary: the nested Lamport slice
        # carries a trailing byte and the nested codec must reject it.
        payload = self.blob[_PAIR_HEADER_BYTES:]
        bad = (
            b"PQAOPRF\0"
            + bytes((1,))
            + (self.lamport_len + 1).to_bytes(4, "big")
            + (self.wots_len - 1).to_bytes(4, "big")
            + payload
        )
        self.assert_rejected(bad)

    def test_no_half_valid_object_on_nested_failure(self):
        # A valid W-OTS member with a corrupted Lamport member must not
        # yield any object at all.
        bad = bytearray(self.blob)
        bad[_PAIR_HEADER_BYTES] ^= 0x01
        self.assert_rejected(bytes(bad))


class OtsPairProofVerifyTest(unittest.TestCase):
    def test_verify_signed_message_only(self):
        _, pair = make_pair(message=b"position claim")
        self.assertTrue(pair.verify(b"position claim"))
        self.assertTrue(pair.verify(bytearray(b"position claim")))
        self.assertTrue(pair.verify("position claim"))
        self.assertFalse(pair.verify(b"other claim"))
        self.assertFalse(pair.verify(b""))

    def test_either_side_failing_is_false(self):
        (lamport_key, wots_key), pair = make_pair()
        # Lamport side forged, W-OTS side intact.
        bad_lamport_sig = pair.lamport.signature[:-1] + (b"\x00" * 32,)
        forged_lamport = LamportProof(public_key=lamport_key, signature=bad_lamport_sig)
        self.assertFalse(
            OtsPairProof(lamport=forged_lamport, wots=pair.wots).verify(
                b"position claim"
            )
        )
        # W-OTS side forged, Lamport side intact.
        bad_wots_sig = pair.wots.signature[:-1] + (b"\x00" * 32,)
        forged_wots = WOTSProof(public_key=wots_key, signature=bad_wots_sig)
        self.assertFalse(
            OtsPairProof(lamport=pair.lamport, wots=forged_wots).verify(
                b"position claim"
            )
        )

    def test_illegal_message_type_returns_false(self):
        _, pair = make_pair()
        for bad in (None, 42, 3.5, object(), ["x"]):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(pair.verify(bad))

    def test_tampered_selected_lamport_branch_returns_false(self):
        (lamport_key, _), pair = make_pair()
        bits = message_bits(b"position claim", bits=lamport_key.bits)
        # Flip a digest on a branch the message bits actually select.
        digests = list(lamport_key.digests)
        selected = 2 * 0 + bits[0]
        digests[selected] = bytes(32)
        tampered_key = PublicKey(tuple(digests))
        forged = LamportProof(public_key=tampered_key, signature=pair.lamport.signature)
        self.assertFalse(
            OtsPairProof(lamport=forged, wots=pair.wots).verify(b"position claim")
        )

    def test_unselected_lamport_branch_tamper_not_covered_by_verify(self):
        # The pair's verify inherits the Lamport guarantee boundary: a
        # public-key branch no message bit selects is outside the
        # tamper-evidence of plain verify; verify_bound closes that gap.
        (lamport_key, wots_key), pair = make_pair()
        bits = message_bits(b"position claim", bits=lamport_key.bits)
        digests = list(lamport_key.digests)
        unselected = 2 * 0 + (1 - bits[0])
        digests[unselected] = bytes(32)
        tampered_key = PublicKey(tuple(digests))
        forged = LamportProof(public_key=tampered_key, signature=pair.lamport.signature)
        rogue = OtsPairProof(lamport=forged, wots=pair.wots)
        self.assertTrue(rogue.verify(b"position claim"))
        self.assertFalse(
            rogue.verify_bound(
                b"position claim", lamport_key=lamport_key, wots_key=wots_key
            )
        )

    def test_tampered_wots_key_returns_false(self):
        (_, wots_key), pair = make_pair()
        elements = list(wots_key.elements)
        elements[0] = bytes(32)
        tampered_key = WOTSPublicKey(w=wots_key.w, elements=tuple(elements))
        forged = WOTSProof(public_key=tampered_key, signature=pair.wots.signature)
        self.assertFalse(
            OtsPairProof(lamport=pair.lamport, wots=forged).verify(b"position claim")
        )

    def test_corrupted_fields_return_false(self):
        _, pair = make_pair()
        object.__setattr__(pair, "lamport", "not-a-proof")
        self.assertFalse(pair.verify(b"position claim"))
        _, pair2 = make_pair()
        object.__setattr__(pair2, "wots", object())
        self.assertFalse(pair2.verify(b"position claim"))

    def test_wrong_type_field_with_always_true_verify_returns_false(self):
        class AlwaysTrue:
            def verify(self, message):
                return True

        _, pair = make_pair()
        object.__setattr__(pair, "lamport", AlwaysTrue())
        self.assertFalse(pair.verify(b"position claim"))
        _, pair2 = make_pair()
        object.__setattr__(pair2, "wots", AlwaysTrue())
        self.assertFalse(pair2.verify(b"position claim"))

    def test_hostile_field_objects_do_not_leak_exceptions_from_verify(self):
        class Boom:
            def verify(self, message):
                raise RuntimeError("boom")

        _, pair = make_pair()
        object.__setattr__(pair, "lamport", Boom())
        self.assertFalse(pair.verify(b"position claim"))
        _, pair2 = make_pair()
        object.__setattr__(pair2, "wots", Boom())
        self.assertFalse(pair2.verify(b"position claim"))
        # Fields missing entirely.
        rogue = object.__new__(OtsPairProof)
        self.assertFalse(rogue.verify(b"position claim"))

    def test_pair_does_not_store_message(self):
        _, pair = make_pair(message=b"the message")
        self.assertFalse(hasattr(pair, "message"))
        self.assertEqual(sorted(vars(pair).keys()), ["lamport", "wots"])


class OtsPairProofVerifyBoundTest(unittest.TestCase):
    def test_bound_verifies_signed_message(self):
        (lamport_key, wots_key), pair = make_pair()
        self.assertTrue(
            pair.verify_bound(
                b"position claim", lamport_key=lamport_key, wots_key=wots_key
            )
        )

    def test_message_types_match_member_verify(self):
        for message in ("claim", b"bytes claim", bytearray(b"array claim")):
            with self.subTest(kind=type(message).__name__):
                lamport_key, lamport = make_lamport_proof(message=message)
                wots_key, wots = make_wots_proof(message=message)
                pair = OtsPairProof(lamport=lamport, wots=wots)
                self.assertTrue(
                    pair.verify_bound(
                        message, lamport_key=lamport_key, wots_key=wots_key
                    )
                )

    def test_value_equal_distinct_keys_accepted(self):
        (lamport_key, wots_key), pair = make_pair()
        other_lamport = PublicKey(tuple(lamport_key.digests))
        other_wots = WOTSPublicKey(w=wots_key.w, elements=tuple(wots_key.elements))
        self.assertIsNot(other_lamport, lamport_key)
        self.assertIsNot(other_wots, wots_key)
        self.assertTrue(
            pair.verify_bound(
                b"position claim", lamport_key=other_lamport, wots_key=other_wots
            )
        )

    def test_keys_must_be_keyword(self):
        (lamport_key, wots_key), pair = make_pair()
        with self.assertRaises(TypeError):
            pair.verify_bound(b"position claim", lamport_key, wots_key)

    def test_wrong_key_types_raise_type_error(self):
        (lamport_key, wots_key), pair = make_pair()
        for bad in (None, 42, 4.5, "key", b"key", wots_key, object(), ()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    pair.verify_bound(
                        b"position claim", lamport_key=bad, wots_key=wots_key
                    )
        for bad in (None, 42, 4.5, "key", b"key", lamport_key, object(), ()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    pair.verify_bound(
                        b"position claim", lamport_key=lamport_key, wots_key=bad
                    )

    def test_type_errors_take_precedence_over_other_failures(self):
        _, pair = make_pair()
        with self.assertRaises(TypeError):
            pair.verify_bound(b"wrong", lamport_key="not-a-key", wots_key="not-a-key")

    def test_key_value_mismatch_is_false(self):
        (lamport_key, wots_key), pair = make_pair()
        foreign_lamport_key, _ = make_lamport_proof(start=5000)
        foreign_wots_key, _ = make_wots_proof(start=6000)
        self.assertFalse(
            pair.verify_bound(
                b"position claim",
                lamport_key=foreign_lamport_key,
                wots_key=wots_key,
            )
        )
        self.assertFalse(
            pair.verify_bound(
                b"position claim",
                lamport_key=lamport_key,
                wots_key=foreign_wots_key,
            )
        )
        self.assertFalse(
            pair.verify_bound(
                b"position claim",
                lamport_key=foreign_lamport_key,
                wots_key=foreign_wots_key,
            )
        )

    def test_wrong_message_is_false_even_with_matching_keys(self):
        (lamport_key, wots_key), pair = make_pair()
        self.assertFalse(
            pair.verify_bound(b"other", lamport_key=lamport_key, wots_key=wots_key)
        )
        self.assertFalse(
            pair.verify_bound(None, lamport_key=lamport_key, wots_key=wots_key)
        )

    def test_malformed_bypass_constructed_pair_is_false(self):
        (lamport_key, wots_key), pair = make_pair()
        rogue = object.__new__(OtsPairProof)
        object.__setattr__(rogue, "lamport", "not-a-proof")
        object.__setattr__(rogue, "wots", "not-a-proof")
        self.assertFalse(
            rogue.verify_bound(
                b"position claim", lamport_key=lamport_key, wots_key=wots_key
            )
        )
        rogue2 = object.__new__(OtsPairProof)
        object.__setattr__(rogue2, "lamport", pair.lamport)
        object.__setattr__(rogue2, "wots", "not-a-proof")
        self.assertFalse(
            rogue2.verify_bound(
                b"position claim", lamport_key=lamport_key, wots_key=wots_key
            )
        )
        rogue3 = object.__new__(OtsPairProof)
        object.__setattr__(rogue3, "lamport", "x")
        object.__setattr__(rogue3, "wots", pair.wots)
        self.assertFalse(
            rogue3.verify_bound(
                b"position claim", lamport_key=lamport_key, wots_key=wots_key
            )
        )
        # Fields missing entirely.
        rogue4 = object.__new__(OtsPairProof)
        self.assertFalse(
            rogue4.verify_bound(
                b"position claim", lamport_key=lamport_key, wots_key=wots_key
            )
        )

    def test_bypass_corrupted_nested_fields_are_false(self):
        (lamport_key, wots_key), pair = make_pair()
        bad_lamport = object.__new__(LamportProof)
        object.__setattr__(bad_lamport, "public_key", "not-a-key")
        object.__setattr__(bad_lamport, "signature", pair.lamport.signature)
        rogue = object.__new__(OtsPairProof)
        object.__setattr__(rogue, "lamport", bad_lamport)
        object.__setattr__(rogue, "wots", pair.wots)
        self.assertFalse(
            rogue.verify_bound(
                b"position claim", lamport_key=lamport_key, wots_key=wots_key
            )
        )

    def test_hostile_field_objects_do_not_leak_exceptions(self):
        class Boom:
            def __eq__(self, other):
                raise RuntimeError("boom")

            def __ne__(self, other):
                raise RuntimeError("boom")

        (lamport_key, wots_key), pair = make_pair()
        hostile_lamport = object.__new__(LamportProof)
        object.__setattr__(hostile_lamport, "public_key", Boom())
        object.__setattr__(hostile_lamport, "signature", pair.lamport.signature)
        rogue = object.__new__(OtsPairProof)
        object.__setattr__(rogue, "lamport", hostile_lamport)
        object.__setattr__(rogue, "wots", pair.wots)
        self.assertFalse(
            rogue.verify_bound(
                b"position claim", lamport_key=lamport_key, wots_key=wots_key
            )
        )

    def test_round_tripped_pair_still_verifies_bound(self):
        (lamport_key, wots_key), pair = make_pair(message=b"m")
        restored = OtsPairProof.from_bytes(pair.to_bytes())
        self.assertEqual(restored, pair)
        self.assertTrue(
            restored.verify_bound(b"m", lamport_key=lamport_key, wots_key=wots_key)
        )

    def test_plain_verify_unchanged(self):
        _, pair = make_pair(message=b"m")
        self.assertTrue(pair.verify(b"m"))
        self.assertFalse(pair.verify(b"other"))
        self.assertEqual(sorted(vars(pair).keys()), ["lamport", "wots"])


if __name__ == "__main__":
    unittest.main()

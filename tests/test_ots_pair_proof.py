import unittest
from dataclasses import FrozenInstanceError

from pqattest import (
    LamportProof,
    OtsPairProof,
    WOTSProof,
    keygen,
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


def make_pair(message=b"position claim"):
    lamport_key, lamport_proof = make_lamport_proof(message=message)
    wots_key, wots_proof = make_wots_proof(message=message)
    return (lamport_key, wots_key), OtsPairProof(lamport=lamport_proof, wots=wots_proof)


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
        _, lamport_proof = make_lamport_proof()
        _, wots_proof = make_wots_proof()
        pair = OtsPairProof(lamport_proof, wots_proof)
        self.assertIs(pair.lamport, lamport_proof)
        self.assertIs(pair.wots, wots_proof)
        self.assertEqual(pair, OtsPairProof(lamport=lamport_proof, wots=wots_proof))
        self.assertEqual(
            hash(pair), hash(OtsPairProof(lamport=lamport_proof, wots=wots_proof))
        )

    def test_positional_construction(self):
        _, lamport_proof = make_lamport_proof()
        _, wots_proof = make_wots_proof()
        self.assertEqual(
            OtsPairProof(lamport_proof, wots_proof),
            OtsPairProof(lamport=lamport_proof, wots=wots_proof),
        )

    def test_frozen(self):
        _, pair = make_pair()
        with self.assertRaises(FrozenInstanceError):
            pair.lamport = pair.lamport
        with self.assertRaises(FrozenInstanceError):
            pair.wots = pair.wots

    def test_wrong_field_types_raise_type_error(self):
        _, lamport_proof = make_lamport_proof()
        _, wots_proof = make_wots_proof()
        for bad in (None, 42, "proof", wots_proof, b"raw", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    OtsPairProof(lamport=bad, wots=wots_proof)
        for bad in (None, 42, "proof", lamport_proof, b"raw", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    OtsPairProof(lamport=lamport_proof, wots=bad)


class OtsPairProofFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        _, pair = make_pair()
        lamport_blob = pair.lamport.to_bytes()
        wots_blob = pair.wots.to_bytes()
        blob = pair.to_bytes()
        self.assertEqual(len(blob), _PAIR_HEADER_BYTES + len(lamport_blob) + len(wots_blob))
        self.assertEqual(blob[:8], b"PQAOPRF\0")
        self.assertEqual(blob[8], 1)
        self.assertEqual(int.from_bytes(blob[9:13], "big"), len(lamport_blob))
        self.assertEqual(int.from_bytes(blob[13:17], "big"), len(wots_blob))
        self.assertEqual(
            blob[_PAIR_HEADER_BYTES : _PAIR_HEADER_BYTES + len(lamport_blob)],
            lamport_blob,
        )
        self.assertEqual(blob[_PAIR_HEADER_BYTES + len(lamport_blob) :], wots_blob)

    def test_deterministic_encoding(self):
        _, pair = make_pair()
        self.assertEqual(pair.to_bytes(), pair.to_bytes())
        _, same = make_pair()
        self.assertEqual(pair.to_bytes(), same.to_bytes())

    def test_round_trip(self):
        _, pair = make_pair()
        restored = OtsPairProof.from_bytes(pair.to_bytes())
        self.assertEqual(restored, pair)
        self.assertIsInstance(restored.lamport, LamportProof)
        self.assertIsInstance(restored.wots, WOTSProof)

    def test_from_bytes_accepts_bytearray(self):
        _, pair = make_pair()
        self.assertEqual(OtsPairProof.from_bytes(bytearray(pair.to_bytes())), pair)

    def test_from_bytes_rejects_other_types(self):
        _, pair = make_pair()
        for bad in (None, 42, "blob", pair.to_bytes().decode("latin1"), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    OtsPairProof.from_bytes(bad)

    def test_bad_magic_version_truncation_trailing(self):
        _, pair = make_pair()
        blob = pair.to_bytes()
        with self.assertRaises(ValueError):
            OtsPairProof.from_bytes(b"PQAOPRX\0" + blob[8:])
        with self.assertRaises(ValueError):
            OtsPairProof.from_bytes(blob[:8] + bytes((2,)) + blob[9:])
        with self.assertRaises(ValueError):
            OtsPairProof.from_bytes(blob[: _PAIR_HEADER_BYTES - 1])
        with self.assertRaises(ValueError):
            OtsPairProof.from_bytes(blob[:-1])
        with self.assertRaises(ValueError):
            OtsPairProof.from_bytes(blob + b"\x00")

    def test_length_field_mismatch(self):
        _, pair = make_pair()
        blob = pair.to_bytes()
        lamport_blob = pair.lamport.to_bytes()
        wots_blob = pair.wots.to_bytes()
        # lamport length too large -> truncated
        bad = blob[:9] + (len(lamport_blob) + 1).to_bytes(4, "big") + blob[13:]
        with self.assertRaises(ValueError):
            OtsPairProof.from_bytes(bad)
        # zero lengths
        for lamport_len, wots_len in ((0, len(wots_blob)), (len(lamport_blob), 0)):
            with self.subTest(lamport_len=lamport_len, wots_len=wots_len):
                bad = (
                    blob[:9]
                    + lamport_len.to_bytes(4, "big")
                    + wots_len.to_bytes(4, "big")
                    + blob[17:]
                )
                with self.assertRaises(ValueError):
                    OtsPairProof.from_bytes(bad)

    def test_invalid_nested_encodings(self):
        _, pair = make_pair()
        lamport_blob = pair.lamport.to_bytes()
        wots_blob = pair.wots.to_bytes()
        # corrupt nested lamport proof magic
        bad_lamport = b"PQALPRX\0" + lamport_blob[8:]
        with self.assertRaises(ValueError):
            OtsPairProof.from_bytes(pair_envelope(bad_lamport, wots_blob))
        # corrupt nested wots proof magic
        bad_wots = b"PQAWPRX\0" + wots_blob[8:]
        with self.assertRaises(ValueError):
            OtsPairProof.from_bytes(pair_envelope(lamport_blob, bad_wots))
        # swapped halves are rejected by the nested magics
        with self.assertRaises(ValueError):
            OtsPairProof.from_bytes(pair_envelope(wots_blob, lamport_blob))

    def test_corrupted_fields_encode_raises_value_error(self):
        _, pair = make_pair()
        object.__setattr__(pair, "lamport", "not-a-proof")
        with self.assertRaises(ValueError):
            pair.to_bytes()
        _, pair2 = make_pair()
        object.__setattr__(pair2, "wots", object())
        with self.assertRaises(ValueError):
            pair2.to_bytes()
        # corrupted nested field surfaces through the inner encoder
        _, pair3 = make_pair()
        object.__setattr__(pair3.lamport, "signature", list(pair3.lamport.signature))
        with self.assertRaises(ValueError):
            pair3.to_bytes()


class OtsPairProofVerifyTest(unittest.TestCase):
    def test_verify_signed_message_only(self):
        _, pair = make_pair(message=b"position claim")
        self.assertTrue(pair.verify(b"position claim"))
        self.assertTrue(pair.verify(bytearray(b"position claim")))
        self.assertTrue(pair.verify("position claim"))
        self.assertFalse(pair.verify(b"other claim"))
        self.assertFalse(pair.verify(b""))

    def test_either_side_failing_returns_false(self):
        (lamport_key, wots_key), pair = make_pair()
        # tampered lamport signature element
        bad_lamport = LamportProof(
            public_key=lamport_key,
            signature=pair.lamport.signature[:-1] + (b"\x00" * 32,),
        )
        self.assertFalse(OtsPairProof(lamport=bad_lamport, wots=pair.wots).verify(b"position claim"))
        # tampered wots signature element
        bad_wots = WOTSProof(
            public_key=wots_key,
            signature=pair.wots.signature[:-1] + (b"\x00" * 32,),
        )
        self.assertFalse(OtsPairProof(lamport=pair.lamport, wots=bad_wots).verify(b"position claim"))

    def test_unselected_lamport_branch_tamper_passes_verify(self):
        # A Lamport public-key branch never selected by the message bits is
        # outside what verify can reach; verify_bound is the backstop.
        (lamport_key, wots_key), pair = make_pair(message=b"position claim")
        from pqattest import PublicKey, message_bits

        bits = message_bits(b"position claim", bits=lamport_key.bits)
        digests = list(lamport_key.digests)
        index = next(i for i, bit in enumerate(bits) if bit == 0)
        digests[2 * index + 1] = b"\x00" * 32  # unselected branch
        tampered_key = PublicKey(tuple(digests))
        tampered = OtsPairProof(
            lamport=LamportProof(public_key=tampered_key, signature=pair.lamport.signature),
            wots=pair.wots,
        )
        self.assertTrue(tampered.verify(b"position claim"))
        self.assertFalse(
            tampered.verify_bound(
                b"position claim", lamport_key=lamport_key, wots_key=wots_key
            )
        )

    def test_illegal_message_type_returns_false(self):
        _, pair = make_pair()
        for bad in (None, 42, 3.5, object(), ["x"]):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(pair.verify(bad))

    def test_corrupted_fields_return_false(self):
        _, pair = make_pair()
        object.__setattr__(pair, "lamport", "not-a-proof")
        self.assertFalse(pair.verify(b"position claim"))
        _, pair2 = make_pair()
        object.__setattr__(pair2, "wots", object())
        self.assertFalse(pair2.verify(b"position claim"))


class OtsPairProofVerifyBoundTest(unittest.TestCase):
    def test_bound_to_expected_keys(self):
        (lamport_key, wots_key), pair = make_pair()
        self.assertTrue(
            pair.verify_bound(
                b"position claim", lamport_key=lamport_key, wots_key=wots_key
            )
        )

    def test_key_type_errors(self):
        (lamport_key, wots_key), pair = make_pair()
        for bad in (None, 42, "key", wots_key, b"raw", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    pair.verify_bound(
                        b"position claim", lamport_key=bad, wots_key=wots_key
                    )
        for bad in (None, 42, "key", lamport_key, b"raw", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    pair.verify_bound(
                        b"position claim", lamport_key=lamport_key, wots_key=bad
                    )

    def test_foreign_keys_return_false(self):
        (lamport_key, wots_key), pair = make_pair()
        other_lamport_key, _ = make_lamport_proof(start=5000)
        other_wots_key, _ = make_wots_proof(start=6000)
        self.assertFalse(
            pair.verify_bound(
                b"position claim", lamport_key=other_lamport_key, wots_key=wots_key
            )
        )
        self.assertFalse(
            pair.verify_bound(
                b"position claim", lamport_key=lamport_key, wots_key=other_wots_key
            )
        )

    def test_wrong_message_returns_false(self):
        (lamport_key, wots_key), pair = make_pair()
        self.assertFalse(
            pair.verify_bound(b"other claim", lamport_key=lamport_key, wots_key=wots_key)
        )
        self.assertFalse(
            pair.verify_bound(None, lamport_key=lamport_key, wots_key=wots_key)
        )

    def test_corrupted_fields_return_false(self):
        (lamport_key, wots_key), pair = make_pair()
        object.__setattr__(pair, "lamport", "not-a-proof")
        self.assertFalse(
            pair.verify_bound(
                b"position claim", lamport_key=lamport_key, wots_key=wots_key
            )
        )
        _, pair2 = make_pair()
        object.__setattr__(pair2, "wots", object())
        self.assertFalse(
            pair2.verify_bound(
                b"position claim", lamport_key=lamport_key, wots_key=wots_key
            )
        )


if __name__ == "__main__":
    unittest.main()

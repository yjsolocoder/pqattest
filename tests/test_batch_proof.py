import unittest

from pqattest import (
    MerkleBatchProof,
    MerklePublicKey,
    MerkleSignature,
    MerkleSigner,
    merkle_verify,
)
from pqattest.merkle import _BATCH_PROOF_HEADER_BYTES


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


def make_batch(height=2, w=4, start=0, messages=("m0", "m1", "m2")):
    signer = make_signer(height=height, w=w, start=start)
    signatures = tuple(signer.sign(message) for message in messages)
    return signer, MerkleBatchProof(
        public_key=signer.public_key, signatures=signatures
    )


def batch_envelope(key_blob: bytes, sig_blobs: tuple[bytes, ...]) -> bytes:
    parts = [
        b"PQAMBAT\0",
        bytes((1,)),
        len(key_blob).to_bytes(4, "big"),
        len(sig_blobs).to_bytes(2, "big"),
        key_blob,
    ]
    for sig_blob in sig_blobs:
        parts.append(len(sig_blob).to_bytes(4, "big"))
        parts.append(sig_blob)
    return b"".join(parts)


class BatchConstructionTest(unittest.TestCase):
    def test_fields_and_equality(self):
        signer = make_signer()
        signatures = (signer.sign("a"), signer.sign("b"))
        batch = MerkleBatchProof(public_key=signer.public_key, signatures=signatures)
        self.assertIs(batch.public_key, signer.public_key)
        self.assertIs(batch.signatures, signatures)
        self.assertEqual(
            batch,
            MerkleBatchProof(public_key=signer.public_key, signatures=signatures),
        )
        self.assertEqual(hash(batch), hash(batch))

    def test_positional_construction(self):
        signer = make_signer()
        signatures = (signer.sign("a"),)
        self.assertEqual(
            MerkleBatchProof(signer.public_key, signatures),
            MerkleBatchProof(public_key=signer.public_key, signatures=signatures),
        )

    def test_single_signature_allowed(self):
        signer, batch = make_batch(messages=("only",))
        self.assertEqual(len(batch.signatures), 1)
        self.assertTrue(batch.verify(("only",)))

    def test_frozen(self):
        _, batch = make_batch()
        with self.assertRaises(Exception):
            batch.public_key = batch.public_key
        with self.assertRaises(Exception):
            batch.signatures = batch.signatures

    def test_wrong_field_types_raise_type_error(self):
        signer = make_signer()
        signatures = (signer.sign("a"),)
        for bad in (None, 42, "key", signatures, b"raw", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleBatchProof(public_key=bad, signatures=signatures)
        for bad in (None, 42, "sigs", signer.public_key, b"raw", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleBatchProof(public_key=signer.public_key, signatures=bad)
        for bad_member in (None, 42, "sig", signer.public_key, b"raw", object()):
            with self.subTest(bad=type(bad_member).__name__):
                with self.assertRaises(TypeError):
                    MerkleBatchProof(
                        public_key=signer.public_key,
                        signatures=(signatures[0], bad_member),
                    )

    def test_list_container_rejected(self):
        signer = make_signer()
        signature = signer.sign("a")
        with self.assertRaises(TypeError):
            MerkleBatchProof(
                public_key=signer.public_key, signatures=[signature]
            )

    def test_empty_signatures_rejected(self):
        signer = make_signer()
        with self.assertRaises(ValueError):
            MerkleBatchProof(public_key=signer.public_key, signatures=())

    def test_non_increasing_indices_rejected(self):
        signer = make_signer(height=2)
        first = signer.sign("a")
        second = signer.sign("b")
        third = signer.sign("c")
        for bad in ((second, first), (first, first), (first, third, second)):
            with self.subTest(indices=tuple(s.index for s in bad)):
                with self.assertRaises(ValueError):
                    MerkleBatchProof(
                        public_key=signer.public_key, signatures=bad
                    )

    def test_parameter_mismatch_rejected(self):
        cases = (
            (make_signer(w=4), make_signer(w=8, start=1000)),
            (make_signer(height=2), make_signer(height=3, start=2000)),
        )
        for own, other in cases:
            with self.subTest(other=other.public_key):
                with self.assertRaises(ValueError):
                    MerkleBatchProof(
                        public_key=other.public_key,
                        signatures=(own.sign("m"),),
                    )

    def test_same_shape_foreign_signature_builds_but_does_not_verify(self):
        # Construction checks parameter/count consistency only: without the
        # messages the batch cannot cryptographically cross-check the pair.
        signer_a = make_signer(start=0)
        signer_b = make_signer(start=1000)
        foreign = signer_a.sign("m")
        batch = MerkleBatchProof(
            public_key=signer_b.public_key, signatures=(foreign,)
        )
        self.assertFalse(batch.verify(("m",)))


class BatchFormatTest(unittest.TestCase):
    def test_layout_and_length(self):
        for w in (4, 8):
            for height in (1, 3):
                with self.subTest(w=w, height=height):
                    signer, batch = make_batch(
                        w=w, height=height, messages=("m0", "m1")
                    )
                    key_blob = signer.public_key.to_bytes()
                    sig_blobs = tuple(
                        signature.to_bytes(signer.public_key)
                        for signature in batch.signatures
                    )
                    blob = batch.to_bytes()
                    self.assertEqual(
                        len(blob),
                        _BATCH_PROOF_HEADER_BYTES
                        + len(key_blob)
                        + sum(4 + len(sig_blob) for sig_blob in sig_blobs),
                    )
                    self.assertEqual(blob[:8], b"PQAMBAT\0")
                    self.assertEqual(blob[8], 1)  # version
                    self.assertEqual(
                        int.from_bytes(blob[9:13], "big"), len(key_blob)
                    )
                    self.assertEqual(
                        int.from_bytes(blob[13:15], "big"), len(sig_blobs)
                    )
                    offset = _BATCH_PROOF_HEADER_BYTES
                    self.assertEqual(blob[offset : offset + len(key_blob)], key_blob)
                    offset += len(key_blob)
                    for sig_blob in sig_blobs:
                        self.assertEqual(
                            int.from_bytes(blob[offset : offset + 4], "big"),
                            len(sig_blob),
                        )
                        offset += 4
                        self.assertEqual(
                            blob[offset : offset + len(sig_blob)], sig_blob
                        )
                        offset += len(sig_blob)
                    self.assertEqual(offset, len(blob))

    def test_to_bytes_returns_bytes(self):
        _, batch = make_batch()
        self.assertIsInstance(batch.to_bytes(), bytes)

    def test_encoding_is_deterministic(self):
        _, batch = make_batch()
        self.assertEqual(batch.to_bytes(), batch.to_bytes())

    def test_equal_values_have_equal_bytes(self):
        signer = make_signer()
        signatures = (signer.sign("a"), signer.sign("b"))
        batch_a = MerkleBatchProof(signer.public_key, signatures)
        batch_b = MerkleBatchProof(signer.public_key, signatures)
        self.assertEqual(batch_a, batch_b)
        self.assertEqual(batch_a.to_bytes(), batch_b.to_bytes())

    def test_to_bytes_on_foreign_object_raises_type_error(self):
        for bad in (None, 42, "batch", object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleBatchProof.to_bytes(bad)


class BatchRoundTripTest(unittest.TestCase):
    def test_round_trip_all_w_and_heights(self):
        for w in (4, 8):
            for height in (1, 2, 5, 8):
                with self.subTest(w=w, height=height):
                    messages = ("hi0", "hi1")
                    signer, batch = make_batch(w=w, height=height, messages=messages)
                    restored = MerkleBatchProof.from_bytes(batch.to_bytes())
                    self.assertEqual(restored, batch)
                    self.assertEqual(restored.public_key, batch.public_key)
                    self.assertEqual(restored.signatures, batch.signatures)
                    self.assertEqual(restored.to_bytes(), batch.to_bytes())
                    self.assertTrue(restored.verify(messages))

    def test_accepts_bytearray(self):
        _, batch = make_batch()
        restored = MerkleBatchProof.from_bytes(bytearray(batch.to_bytes()))
        self.assertEqual(restored, batch)

    def test_standalone_transport(self):
        signer = make_signer(height=3, w=8)
        messages = (b"claim 0", b"claim 1")
        signatures = tuple(signer.sign(message) for message in messages)
        blob = MerkleBatchProof(signer.public_key, signatures).to_bytes()
        # The receiver needs nothing but the blob.
        received = MerkleBatchProof.from_bytes(blob)
        self.assertTrue(received.verify(messages))
        self.assertFalse(received.verify((b"claim 0", b"other claim")))


class BatchFromBytesValidationTest(unittest.TestCase):
    def setUp(self):
        self.signer, self.batch = make_batch()
        self.blob = self.batch.to_bytes()
        self.key_len = int.from_bytes(self.blob[9:13], "big")
        self.count = int.from_bytes(self.blob[13:15], "big")
        self.sig_len = int.from_bytes(
            self.blob[
                _BATCH_PROOF_HEADER_BYTES
                + self.key_len : _BATCH_PROOF_HEADER_BYTES
                + self.key_len
                + 4
            ],
            "big",
        )

    def assert_rejected(self, data):
        with self.assertRaises(ValueError):
            MerkleBatchProof.from_bytes(data)

    def test_non_bytes_types_raise_type_error(self):
        for bad in (None, 42, 4.5, "batch", [self.blob], (self.blob,), object()):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    MerkleBatchProof.from_bytes(bad)

    def test_truncated_and_empty_rejected(self):
        for cut in (0, 8, 9, 13, 14, _BATCH_PROOF_HEADER_BYTES, len(self.blob) - 1):
            with self.subTest(cut=cut):
                self.assert_rejected(self.blob[:cut])

    def test_trailing_data_rejected(self):
        self.assert_rejected(self.blob + b"\x00")
        self.assert_rejected(self.blob + b"tail")

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

    def test_zero_key_length_rejected(self):
        bad = bytearray(self.blob)
        bad[9:13] = (0).to_bytes(4, "big")
        self.assert_rejected(bytes(bad))

    def test_zero_signature_count_rejected(self):
        bad = bytearray(self.blob)
        bad[13:15] = (0).to_bytes(2, "big")
        self.assert_rejected(bytes(bad))

    def test_key_length_out_of_bounds_rejected(self):
        payload = len(self.blob) - _BATCH_PROOF_HEADER_BYTES
        for length in (payload + 1, payload + 100, 1 << 31, 0xFFFFFFFF):
            with self.subTest(length=length):
                bad = bytearray(self.blob)
                bad[9:13] = length.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_count_exceeding_entries_rejected(self):
        bad = bytearray(self.blob)
        bad[13:15] = (self.count + 1).to_bytes(2, "big")
        self.assert_rejected(bytes(bad))

    def test_signature_length_zero_rejected(self):
        offset = _BATCH_PROOF_HEADER_BYTES + self.key_len
        bad = bytearray(self.blob)
        bad[offset : offset + 4] = (0).to_bytes(4, "big")
        self.assert_rejected(bytes(bad))

    def test_signature_length_out_of_bounds_rejected(self):
        offset = _BATCH_PROOF_HEADER_BYTES + self.key_len
        for length in (len(self.blob), 1 << 31, 0xFFFFFFFF):
            with self.subTest(length=length):
                bad = bytearray(self.blob)
                bad[offset : offset + 4] = length.to_bytes(4, "big")
                self.assert_rejected(bytes(bad))

    def test_nested_public_key_encoding_corrupted(self):
        for name, delta in (("magic", 0), ("version", 8), ("w", 9), ("height", 10)):
            with self.subTest(field=name):
                bad = bytearray(self.blob)
                bad[_BATCH_PROOF_HEADER_BYTES + delta] ^= 0x01
                self.assert_rejected(bytes(bad))

    def test_nested_signature_magic_corrupted(self):
        offset = _BATCH_PROOF_HEADER_BYTES + self.key_len + 4
        bad = bytearray(self.blob)
        bad[offset] ^= 0x01
        self.assert_rejected(bytes(bad))

    def test_nested_signature_version_corrupted(self):
        offset = _BATCH_PROOF_HEADER_BYTES + self.key_len + 4 + 8
        bad = bytearray(self.blob)
        bad[offset] = 2
        self.assert_rejected(bytes(bad))

    def test_cross_inconsistent_key_and_signature_rejected(self):
        signer_a = make_signer(height=2, w=4, start=0)
        sig_a = signer_a.sign("m")
        key_blob = signer_a.public_key.to_bytes()
        for other in (
            make_signer(height=2, w=8, start=1000),
            make_signer(height=3, w=4, start=2000),
        ):
            with self.subTest(other=other.public_key):
                foreign_blob = other.sign("m").to_bytes(other.public_key)
                self.assert_rejected(batch_envelope(key_blob, (foreign_blob,)))
        # Sanity: the matching pair parses and verifies.
        restored = MerkleBatchProof.from_bytes(
            batch_envelope(key_blob, (sig_a.to_bytes(signer_a.public_key),))
        )
        self.assertTrue(restored.verify(("m",)))

    def test_duplicate_indices_in_encoding_rejected(self):
        signer = make_signer()
        signature = signer.sign("m")
        sig_blob = signature.to_bytes(signer.public_key)
        blob = batch_envelope(
            signer.public_key.to_bytes(), (sig_blob, sig_blob)
        )
        self.assert_rejected(blob)

    def test_decreasing_indices_in_encoding_rejected(self):
        signer = make_signer()
        first = signer.sign("a").to_bytes(signer.public_key)
        second = signer.sign("b").to_bytes(signer.public_key)
        blob = batch_envelope(signer.public_key.to_bytes(), (second, first))
        self.assert_rejected(blob)

    def test_repartitioned_lengths_rejected_by_nested_codecs(self):
        # Same total payload, shifted boundary: the nested key slice carries
        # a trailing byte and the nested codec must reject it.
        payload = self.blob[_BATCH_PROOF_HEADER_BYTES:]
        first_sig_len = 4 + self.sig_len
        bad = (
            b"PQAMBAT\0"
            + bytes((1,))
            + (self.key_len + 1).to_bytes(4, "big")
            + self.count.to_bytes(2, "big")
            + payload[: self.key_len + 1]
            + (self.sig_len - 1).to_bytes(4, "big")
            + payload[self.key_len + 5 : self.key_len + first_sig_len]
            + payload[self.key_len + first_sig_len :]
        )
        self.assertEqual(len(bad), len(self.blob))
        self.assert_rejected(bad)


class BatchVerifyTest(unittest.TestCase):
    def test_message_types_match_merkle_verify(self):
        messages = ("claim", b"bytes claim", bytearray(b"array claim"))
        signer = make_signer()
        signatures = tuple(signer.sign(message) for message in messages)
        batch = MerkleBatchProof(signer.public_key, signatures)
        self.assertTrue(batch.verify(messages))
        for message, signature in zip(messages, signatures):
            self.assertTrue(merkle_verify(message, signature, signer.public_key))

    def test_wrong_message_fails(self):
        _, batch = make_batch(messages=(b"signed text", b"other text"))
        self.assertTrue(batch.verify((b"signed text", b"other text")))
        self.assertFalse(batch.verify((b"signed text!", b"other text")))
        self.assertFalse(batch.verify((b"signed text", b"other text!")))

    def test_swapped_messages_fail(self):
        _, batch = make_batch(messages=("first", "second"))
        self.assertFalse(batch.verify(("second", "first")))

    def test_non_tuple_messages_is_false_not_raise(self):
        _, batch = make_batch()
        for bad in (None, 42, 4.5, "messages", b"messages", object()):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(batch.verify(bad))

    def test_list_messages_is_false_not_raise(self):
        _, batch = make_batch(messages=("m0", "m1", "m2"))
        self.assertFalse(batch.verify(["m0", "m1", "m2"]))

    def test_count_mismatch_is_false_not_raise(self):
        _, batch = make_batch(messages=("m0", "m1", "m2"))
        self.assertFalse(batch.verify(("m0", "m1")))
        self.assertFalse(batch.verify(("m0", "m1", "m2", "m3")))
        self.assertFalse(batch.verify(()))

    def test_illegal_message_member_is_false_not_raise(self):
        _, batch = make_batch(messages=("m0", "m1", "m2"))
        for bad_member in (None, 42, 4.5, [1, 2], object()):
            with self.subTest(bad=type(bad_member).__name__):
                self.assertFalse(batch.verify(("m0", bad_member, "m2")))

    def test_tampered_signature_element_fails(self):
        signer = make_signer()
        signatures = (signer.sign("a"), signer.sign("b"))
        batch = MerkleBatchProof(signer.public_key, signatures)
        self.assertTrue(batch.verify(("a", "b")))
        tampered_elements = list(signatures[1].wots_signature)
        tampered_elements[0] = bytes(32)
        tampered = MerkleSignature(
            index=signatures[1].index,
            wots_signature=tuple(tampered_elements),
            auth_path=signatures[1].auth_path,
        )
        # Still structurally consistent with the key, so the batch builds —
        # but cryptography rejects it.
        tampered_batch = MerkleBatchProof(
            signer.public_key, (signatures[0], tampered)
        )
        self.assertFalse(tampered_batch.verify(("a", "b")))

    def test_tampered_blob_fails_after_parsing(self):
        signer = make_signer()
        signatures = (signer.sign("a"),)
        blob = MerkleBatchProof(signer.public_key, signatures).to_bytes()
        # Flip the last byte (inside the auth path).
        bad = bytearray(blob)
        bad[-1] ^= 0x01
        restored = MerkleBatchProof.from_bytes(bytes(bad))
        self.assertFalse(restored.verify(("a",)))

    def test_batch_does_not_store_messages(self):
        _, batch = make_batch(messages=("the message",))
        self.assertFalse(hasattr(batch, "messages"))
        self.assertEqual(sorted(vars(batch).keys()), ["public_key", "signatures"])


if __name__ == "__main__":
    unittest.main()

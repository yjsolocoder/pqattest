import hashlib
import threading
import unittest
from dataclasses import replace

from pqattest import (
    KeyExhaustedError,
    MerklePublicKey,
    MerkleSignature,
    MerkleSigner,
    PrivateKey as LamportPrivateKey,
    PublicKey as LamportPublicKey,
    WOTSPublicKey,
    merkle_verify,
    wots_keygen,
    wots_sign,
)
from pqattest.merkle import _leaf_hash, _node_hash


def counter_tokens(start: int = 0):
    state = {"value": start}

    def token_bytes(size: int) -> bytes:
        state["value"] += 1
        return state["value"].to_bytes(8, "big").rjust(size, b"\x00")

    return token_bytes


def make_signer(height=2, w=4, start=0):
    return MerkleSigner(height=height, w=w, token_bytes=counter_tokens(start))


class ParameterTest(unittest.TestCase):
    def test_defaults(self):
        signer = MerkleSigner(token_bytes=counter_tokens())
        self.assertEqual(signer.public_key.w, 4)
        self.assertEqual(signer.public_key.height, 4)
        self.assertEqual(signer.remaining, 16)

    def test_invalid_height_rejected(self):
        for bad_height in (0, 9, -1, 100, 4.0, True, None, "4"):
            with self.subTest(bad_height=bad_height):
                with self.assertRaises(ValueError):
                    MerkleSigner(height=bad_height, token_bytes=counter_tokens())

    def test_invalid_w_rejected(self):
        for bad_w in (2, 16, 0, -4, 4.0, True, None, "4"):
            with self.subTest(bad_w=bad_w):
                with self.assertRaises(ValueError):
                    MerkleSigner(w=bad_w, token_bytes=counter_tokens())

    def test_token_length_enforced(self):
        with self.assertRaises(ValueError):
            MerkleSigner(height=1, token_bytes=lambda size: b"short")


class PublicKeyShapeTest(unittest.TestCase):
    def test_shape_and_frozen(self):
        signer = make_signer(height=3)
        public_key = signer.public_key
        self.assertIsInstance(public_key, MerklePublicKey)
        self.assertEqual(public_key.w, 4)
        self.assertEqual(public_key.height, 3)
        self.assertIsInstance(public_key.root, bytes)
        self.assertEqual(len(public_key.root), 32)
        with self.assertRaises(AttributeError):
            public_key.root = b"\x00" * 32
        with self.assertRaises(AttributeError):
            public_key.height = 1

    def test_public_key_is_read_only_property(self):
        signer = make_signer()
        with self.assertRaises(AttributeError):
            signer.public_key = None

    def test_bad_root_rejected(self):
        with self.assertRaises(TypeError):
            MerklePublicKey(w=4, height=2, root="not bytes")
        with self.assertRaises(ValueError):
            MerklePublicKey(w=4, height=2, root=b"\x00" * 31)
        with self.assertRaises(ValueError):
            MerklePublicKey(w=4, height=0, root=b"\x00" * 32)
        with self.assertRaises(ValueError):
            MerklePublicKey(w=2, height=2, root=b"\x00" * 32)

    def test_deterministic_root_from_token_stream(self):
        first = make_signer(height=2, start=0)
        second = make_signer(height=2, start=0)
        self.assertEqual(first.public_key, second.public_key)
        different = make_signer(height=2, start=1000)
        self.assertNotEqual(first.public_key, different.public_key)


class SignatureShapeTest(unittest.TestCase):
    def test_signature_shape_and_frozen(self):
        signer = make_signer(height=3)
        signature = signer.sign("m")
        self.assertIsInstance(signature, MerkleSignature)
        self.assertEqual(signature.index, 0)
        self.assertEqual(len(signature.wots_signature), 67)
        self.assertEqual(len(signature.auth_path), 3)
        for node in signature.auth_path:
            self.assertIsInstance(node, bytes)
            self.assertEqual(len(node), 32)
        with self.assertRaises(AttributeError):
            signature.index = 1
        with self.assertRaises(AttributeError):
            signature.auth_path = ()

    def test_signature_w8_shape(self):
        signer = make_signer(height=1, w=8)
        signature = signer.sign("m")
        self.assertEqual(len(signature.wots_signature), 34)

    def test_bad_signature_fields_rejected(self):
        good = make_signer().sign("m")
        with self.assertRaises(ValueError):
            replace(good, index=-1)
        with self.assertRaises(ValueError):
            replace(good, index=True)
        with self.assertRaises(ValueError):
            replace(good, index=4)  # 2**2 leaves: 0..3 only
        with self.assertRaises(TypeError):
            replace(good, wots_signature=list(good.wots_signature))
        with self.assertRaises(ValueError):
            replace(good, wots_signature=good.wots_signature[:-1])
        with self.assertRaises(ValueError):
            replace(good, wots_signature=(b"short",) + good.wots_signature[1:])
        with self.assertRaises(TypeError):
            replace(good, auth_path=list(good.auth_path))
        with self.assertRaises(ValueError):
            replace(good, auth_path=())
        with self.assertRaises(ValueError):
            replace(good, auth_path=(b"\x00" * 31,) * 2)


class KnownAnswerTest(unittest.TestCase):
    def test_leaf_and_node_domains(self):
        elements = (b"\x01" * 32, b"\x02" * 32)
        self.assertEqual(
            _leaf_hash(4, elements),
            hashlib.sha256(b"pqattest/leaf" + b"\x04" + b"".join(elements)).digest(),
        )
        left, right = b"\x03" * 32, b"\x04" * 32
        self.assertEqual(
            _node_hash(left, right),
            hashlib.sha256(b"pqattest/node" + left + right).digest(),
        )

    def test_hand_built_tree_matches_signer(self):
        # Rebuild the whole construction by hand from the same token stream.
        tokens = counter_tokens()
        pairs = [wots_keygen(w=4, token_bytes=tokens) for _ in range(4)]
        publics = [public for _, public in pairs]
        leaves = [_leaf_hash(4, public.elements) for public in publics]
        node01 = _node_hash(leaves[0], leaves[1])
        node23 = _node_hash(leaves[2], leaves[3])
        root = _node_hash(node01, node23)

        signer = MerkleSigner(height=2, w=4, token_bytes=counter_tokens())
        self.assertEqual(signer.public_key.root, root)

        # Sign with leaf 2 by hand: path is (leaf sibling 3, then node01).
        signature = MerkleSignature(
            index=2,
            wots_signature=wots_sign("manual", pairs[2][0]),
            auth_path=(leaves[3], node01),
        )
        self.assertTrue(merkle_verify("manual", signature, signer.public_key))
        # Leaf-level sibling comes first: swapping the path levels breaks it.
        swapped = replace(signature, auth_path=(node01, leaves[3]))
        self.assertFalse(merkle_verify("manual", swapped, signer.public_key))


class SignVerifyTest(unittest.TestCase):
    def test_round_trip_both_w(self):
        for w in (4, 8):
            with self.subTest(w=w):
                signer = make_signer(height=2, w=w)
                for message in (b"claim", bytearray(b"claim"), "claim"):
                    signature = signer.sign(message)
                    self.assertTrue(merkle_verify(message, signature, signer.public_key))

    def test_indices_increment_from_zero(self):
        signer = make_signer(height=2)
        indices = [signer.sign(f"m{i}").index for i in range(4)]
        self.assertEqual(indices, [0, 1, 2, 3])
        self.assertEqual(signer.remaining, 0)

    def test_every_leaf_verifies(self):
        signer = make_signer(height=3)
        for i in range(8):
            signature = signer.sign(f"leaf-{i}")
            self.assertEqual(signature.index, i)
            self.assertTrue(merkle_verify(f"leaf-{i}", signature, signer.public_key))

    def test_exhaustion_raises(self):
        signer = make_signer(height=1)
        signer.sign("one")
        signer.sign("two")
        with self.assertRaises(KeyExhaustedError):
            signer.sign("three")

    def test_failed_sign_does_not_consume_leaf(self):
        signer = make_signer(height=1)
        with self.assertRaises(TypeError):
            signer.sign(123)
        self.assertEqual(signer.remaining, 2)
        signature = signer.sign("ok")
        self.assertEqual(signature.index, 0)

    def test_concurrent_signing_allocates_unique_indices(self):
        signer = make_signer(height=4)  # 16 leaves
        results, errors = [], []
        barrier = threading.Barrier(16)

        def worker(i):
            barrier.wait()
            try:
                results.append(signer.sign(f"m{i}").index)
            except KeyExhaustedError:
                errors.append(i)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), list(range(16)))

    def test_concurrent_excess_signers_get_exhausted(self):
        signer = make_signer(height=1)  # 2 leaves, 6 competitors
        results, errors = [], []
        barrier = threading.Barrier(6)

        def worker(i):
            barrier.wait()
            try:
                results.append(signer.sign(f"m{i}").index)
            except KeyExhaustedError:
                errors.append(i)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results), [0, 1])
        self.assertEqual(len(errors), 4)


class RejectionTest(unittest.TestCase):
    def setUp(self):
        self.signer = make_signer(height=2)
        self.signature = self.signer.sign("position claim")
        self.public_key = self.signer.public_key

    def test_different_message_fails(self):
        self.assertFalse(merkle_verify("position claim!", self.signature, self.public_key))

    def test_bad_message_type_returns_false(self):
        self.assertFalse(merkle_verify(123, self.signature, self.public_key))

    def test_tampered_wots_element_fails(self):
        elements = list(self.signature.wots_signature)
        tampered = bytearray(elements[0])
        tampered[0] ^= 0x01
        elements[0] = bytes(tampered)
        signature = replace(self.signature, wots_signature=tuple(elements))
        self.assertFalse(merkle_verify("position claim", signature, self.public_key))

    def test_tampered_auth_path_fails(self):
        path = list(self.signature.auth_path)
        path[0] = bytes(b ^ 0x01 for b in path[0])
        signature = replace(self.signature, auth_path=tuple(path))
        self.assertFalse(merkle_verify("position claim", signature, self.public_key))

    def test_wrong_index_fails(self):
        # Index bits select left/right at each level; flipping them breaks the root.
        other = self.signer.sign("other")
        moved = replace(self.signature, index=other.index)
        self.assertFalse(merkle_verify("position claim", moved, self.public_key))

    def test_swapped_whole_signature_fails(self):
        # A signature from leaf 1 must not verify against leaf 0's path.
        other = self.signer.sign("position claim")
        mixed = replace(other, auth_path=self.signature.auth_path)
        self.assertFalse(merkle_verify("position claim", mixed, self.public_key))

    def test_tampered_root_fails(self):
        root = bytearray(self.public_key.root)
        root[0] ^= 0x01
        public_key = replace(self.public_key, root=bytes(root))
        self.assertFalse(merkle_verify("position claim", self.signature, public_key))

    def test_cross_tree_fails(self):
        other_signer = make_signer(height=2, start=1000)
        self.assertFalse(
            merkle_verify("position claim", self.signature, other_signer.public_key)
        )
        other_signature = other_signer.sign("position claim")
        self.assertFalse(merkle_verify("position claim", other_signature, self.public_key))

    def test_w_mismatch_fails(self):
        signer8 = make_signer(height=2, w=8, start=2000)
        signature8 = signer8.sign("position claim")
        self.assertFalse(merkle_verify("position claim", signature8, self.public_key))

    def test_height_mismatch_fails(self):
        taller = make_signer(height=3, start=3000)
        signature = taller.sign("position claim")
        # auth_path of length 3 cannot match a height-2 public key
        self.assertFalse(merkle_verify("position claim", signature, self.public_key))

    def test_non_merkle_signature_returns_false(self):
        for bad in (object(), None, 42, "sig", self.signature.wots_signature):
            with self.subTest(bad=type(bad).__name__):
                self.assertFalse(merkle_verify("position claim", bad, self.public_key))

    def test_wrong_public_key_type_raises(self):
        _, wots_public = wots_keygen(token_bytes=counter_tokens())
        bad_keys = (
            object(),
            None,
            "key",
            LamportPublicKey(()),
            LamportPrivateKey(()),
            wots_public,
        )
        for bad_key in bad_keys:
            with self.subTest(bad_key=type(bad_key).__name__):
                with self.assertRaises(TypeError):
                    merkle_verify("position claim", self.signature, bad_key)


if __name__ == "__main__":
    unittest.main()

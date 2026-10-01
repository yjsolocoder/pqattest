"""pqattest - hash-based one-time and few-times signatures, plus a toy KEM.

Public API: keygen / public_key_from / sign / verify / message_bits /
OneTimeSigner / KeyExhaustedError, with a deterministic, versioned v1 binary
codec for the Lamport keys and stateless signatures:
PrivateKey.to_bytes / PrivateKey.from_bytes,
PublicKey.to_bytes / PublicKey.from_bytes,
lamport_signature_to_bytes / lamport_signature_from_bytes, and a versioned
state checkpoint for the signer: OneTimeSigner.checkpoint /
OneTimeSigner.from_checkpoint; the Winternitz
construction: wots_keygen / wots_sign / wots_verify / WOTSPrivateKey /
WOTSPublicKey / WOTSOneTimeSigner / wots_signature_to_bytes /
wots_signature_from_bytes, plus the standalone one-time proof packs
LamportProof and WOTSProof that bundle each construction's public key and
signature into one independently transportable, deterministic v1 byte
block, and OtsPairProof that pairs one LamportProof with one WOTSProof
for the same message into a single independently transportable v1 byte
block (its verify_bound additionally binds the pair to the receiver's
expected public keys), Merkle-aggregated W-OTS: MerkleSigner /
MerklePublicKey / MerkleSignature / MerkleProof / MerkleBatchProof /
merkle_verify / multiproof_encode / multiproof_verify /
multiproof_verify_bound (the two proof classes' verify_bound and this
function bind a proof to the receiver's expected public key and,
optionally, an explicit leaf-index selection), static
parameter analysis: Params / profile / recommend / recommend_scheme /
scheme_frontier /
recommend_scheme_weighted to rank that cross-scheme frontier by a
two-tuple of non-negative weights over min-max-normalised costs (single
signature serialised size and verifier chain steps), the weighted sum
divided by the weight total, with exact Fraction arithmetic,
recommend_scheme_weighted_scenarios to rank that same cross-scheme
frontier by the smallest worst-case regret over a non-empty tuple of
such two-weight scenarios, again with exact Fraction arithmetic,
explain_scheme_weighted to export that same weighted ranking's
decision-cost breakdown as a tuple of frozen SchemeScore rows — one per
frontier member, in frontier order, each carrying the candidate's
metrics, its two normalised costs, its final score and a selected flag —
again with exact Fraction arithmetic,
explain_scheme_weighted_scenarios to export the multi-scenario
cross-scheme ranking's decision-cost breakdown as a tuple of frozen
SchemeScenarioScore rows — one per frontier member, in frontier order,
each carrying the candidate's metrics, its two normalised costs, its
per-scenario scores and regrets and a selected flag — again with exact
Fraction arithmetic,
recommend_merkle_deployment /
merkle_deployment_frontier /
recommend_merkle_deployment_weighted to rank that ordinary-deployment
frontier by a four-tuple of non-negative weights over min-max-normalised
costs (checkpoint bytes, signature wire length, standalone proof wire
length and verifier steps), the weighted sum divided by the weight total,
with exact Fraction arithmetic,
recommend_merkle_deployment_weighted_scenarios to rank that same
ordinary-deployment frontier by the smallest worst-case regret over a
non-empty tuple of such four-weight scenarios, again with exact Fraction
arithmetic,
explain_merkle_deployment_weighted to export that same weighted
ranking's decision-cost breakdown as a tuple of frozen
MerkleDeploymentScore rows — one per frontier member, in frontier order,
each carrying the candidate's config, its four normalised costs, its
final score and a selected flag — again with exact Fraction arithmetic,
explain_merkle_deployment_weighted_scenarios to export the
multi-scenario ordinary-deployment ranking's decision-cost breakdown as
a tuple of frozen MerkleDeploymentScenarioScore rows — one per frontier
member, in frontier order, each carrying the candidate's config, its
four normalised costs, its per-scenario scores and regrets and a
selected flag — again with exact Fraction arithmetic,
MerkleStorageProfile / merkle_storage_profile / merkle_transport_profile /
recommend_merkle_transport_deployment / MerkleTransportDeploymentProfile /
merkle_transport_deployment_frontier /
recommend_merkle_transport_deployment_weighted to rank that frontier by a
five-tuple of non-negative weights over min-max-normalised costs with exact
Fraction arithmetic,
recommend_merkle_transport_deployment_weighted_scenarios to rank that same
frontier by the smallest worst-case regret over a non-empty tuple of such
five-weight scenarios, again with exact Fraction arithmetic,
explain_merkle_transport_deployment_weighted to export the single-weight
joint-deployment ranking's decision-cost breakdown as a tuple of frozen
MerkleTransportDeploymentScore rows — one per frontier member, in frontier
order, each carrying the candidate's deployment, its five normalised
costs, its final score and a selected flag — again with exact Fraction
arithmetic,
explain_merkle_transport_deployment_weighted_scenarios to export the
multi-scenario joint-deployment ranking's decision-cost breakdown as a
tuple of frozen MerkleTransportDeploymentScenarioScore rows — one per
frontier member, in frontier order, each carrying the candidate's
deployment, its five normalised costs, its per-scenario scores and
regrets and a selected flag — again with exact Fraction arithmetic,
recommend_merkle_transport_workload / MerkleTransportWorkloadProfile /
merkle_transport_workload_frontier /
recommend_merkle_transport_workload_weighted to rank that workload
frontier by a four-tuple of non-negative weights over min-max-normalised
costs (checkpoint bytes, single-group peak, total transport and verifier
steps), the weighted sum divided by the weight total, with exact Fraction
arithmetic,
recommend_merkle_transport_workload_weighted_scenarios to rank that same
workload frontier by the smallest worst-case regret over a non-empty
tuple of such four-weight scenarios, again with exact Fraction
arithmetic,
explain_merkle_transport_workload_weighted to export the single-weight
workload ranking's decision-cost breakdown as a tuple of frozen
MerkleTransportWorkloadScore rows — one per frontier member, in frontier
order, each carrying the candidate's workload plan, its four normalised
costs, its final score and a selected flag — again with exact Fraction
arithmetic,
explain_merkle_transport_workload_weighted_scenarios to export the
multi-scenario workload ranking's decision-cost breakdown as a tuple of
frozen MerkleTransportWorkloadScenarioScore rows — one per frontier
member, in frontier order, each carrying the candidate's workload plan,
its four normalised costs, its per-scenario scores and regrets and a
selected flag — again with exact Fraction arithmetic,
merkle_mode_frontier /
recommend_merkle_mode_deployment,
recommend_merkle_mode_weighted to rank that mode frontier by a five-tuple
of non-negative weights over min-max-normalised costs (checkpoint bytes,
single-group peak, total transport, verifier steps and carried nodes), the
weighted sum divided by the weight total, with exact Fraction arithmetic,
recommend_merkle_mode_weighted_scenarios to rank that mode frontier by the
smallest worst-case regret over a non-empty tuple of five-weight scenarios
(checkpoint bytes, single-group peak, total transport, verifier steps and
carried nodes) with exact Fraction arithmetic,
explain_merkle_mode_weighted to export the single-weight mode ranking's
decision-cost breakdown as a tuple of frozen MerkleModeScore rows — one
per frontier member, in frontier order, each carrying the candidate's
workload plan, its five normalised costs, its final score and a selected
flag — again with exact Fraction arithmetic,
explain_merkle_mode_weighted_scenarios to export the multi-scenario mode
ranking's decision-cost breakdown as a tuple of frozen
MerkleModeScenarioScore rows — one per frontier member, in frontier
order, each carrying the candidate's workload plan, its five normalised
costs, its per-scenario scores and regrets and a selected flag — again
with exact Fraction arithmetic,
MerkleVerifyProfile / merkle_verify_profile,
MerkleVerifyWorkloadProfile / merkle_verify_workload_profile,
MerkleModeCost / merkle_verify_mode_frontier,
merkle_cardinality_frontier for the worst-case-position cardinality
frontier, recommend_merkle_cardinality_deployment to rank that frontier
by one of five preferences, recommend_merkle_cardinality_weighted to
rank it by a five-tuple of non-negative weights over min-max-normalised
costs with exact Fraction arithmetic,
recommend_merkle_verify_mode_weighted to rank the fixed-position joint
verify-mode frontier by the smallest worst-case regret over a non-empty
tuple of such five-weight scenarios, again with exact Fraction arithmetic,
recommend_merkle_cardinality_weighted_scenarios to rank the
worst-case-position cardinality frontier that same way, by the smallest
worst-case regret over a non-empty tuple of five-weight scenarios with
exact Fraction arithmetic,
explain_merkle_cardinality_weighted to export the single-weight
cardinality ranking's decision-cost breakdown as a tuple of frozen
MerkleCardinalityScore rows — one per frontier member, in frontier order,
each carrying the candidate's plan/cost pairing, its five normalised
costs, its final score and a selected flag — again with exact Fraction
arithmetic,
explain_merkle_cardinality_weighted_scenarios to export the
multi-scenario cardinality ranking's decision-cost breakdown as a tuple
of frozen MerkleCardinalityScenarioScore rows — one per frontier member,
in frontier order, each carrying the candidate's plan/cost pairing, its
five normalised costs, its per-scenario scores and regrets and a
selected flag — again with exact Fraction arithmetic,
recommend_merkle_verify_mode_deployment to rank the fixed-position
verify-mode frontier by one of five business preferences (compact /
verify / nodes / speed / robust),
recommend_merkle_verify_mode_deployment_weighted to rank that same
fixed-position verify-mode frontier by a five-tuple of non-negative weights
over min-max-normalised costs (total transport, single-group peak, total
verifier hashes, carried nodes and per-signature chain steps), the weighted
sum divided by the weight total, with exact Fraction arithmetic,
explain_merkle_verify_mode_deployment_weighted to export that same weighted
fixed-position ranking's decision-cost breakdown as a tuple of frozen
MerkleVerifyModeDeploymentScore rows — one per frontier member, in frontier
order, each carrying the candidate's plan/cost pairing, its five
normalised costs, its final score and a selected flag — again with exact
Fraction arithmetic,
and
the teaching-only toy lattice KEM and signature toys:
toy_lattice_keygen / toy_lattice_encapsulate /
toy_lattice_decapsulate / toy_lattice_sign / toy_lattice_verify /
ToyLatticePublicKey / ToyLatticePrivateKey /
ToyLatticeCiphertext / ToyLatticeSignature, the latter carrying the
E-encoded random vector and 32-byte keyed tag under its own versioned v1
wire encoding. The three plaintext signer checkpoints and the toy
lattice private key's versioned encoding can be sealed
in a keyed HMAC-SHA-256 envelope with auth_wrap / auth_unwrap; a v2
envelope with auth_state_wrap / auth_state_unwrap additionally binds a
uint64 generation so an externally tracked floor can detect rollback.
The Lamport and W-OTS signers additionally offer from_auth_state, which
authenticates and restores a v2 envelope and then invokes a caller-supplied
monotonic claim callback exactly once; restore_ots_pair restores a
same-generation Lamport/W-OTS pair and claims both sides with a single
callback, so a claim can never succeed for only one side;
ots_pair_checkpoint bundles one OneTimeSigner followed by one
WOTSOneTimeSigner (the order is fixed) into a single deterministic
plaintext v1 byte block that embeds their two existing v1 checkpoints
verbatim, Lamport first and W-OTS second, under a SHA-256 trailer, taking
both signing locks in that fixed order; ots_pair_restore parses the block
back into the (lamport_signer, wots_signer) tuple without randomness,
preserving both public keys and used flags (the block is plaintext
private-state material with a corruption-detection checksum only — it is
not an auth-wrap payload, so neither envelope scheme is extended to
accept it, and it offers no authentication, encryption, atomic
persistence or rollback protection);
sign_ots_pair signs one message with a Lamport/W-OTS signer pair under a
joint lock and returns both signatures together with the v2 envelopes of
the two advanced states, so the pair either advances together or not at
all; sign_with_checkpoint on each one-time signer and
sign_ots_pair_with_checkpoint for the pair are the plaintext atomic
counterparts, returning the signature(s) together with the raw v1
checkpoint bytes of the advanced state(s) in one locked step;
sign_ots_pair_proof_with_checkpoint is its proof-packing counterpart,
returning the OtsPairProof of the two fresh signatures together with the
two raw v1 checkpoint bytes in one locked step;
sign_ots_pair_proof_with_auth_state is the authenticated counterpart of
that proof-packing entry, returning the same OtsPairProof together with
the two v2 auth_state_wrap envelopes of the advanced states (Lamport
first, W-OTS second) in one locked step;
sign_ots_pair_proof_auth_state is the stateless conversion entry: it
authenticates a same-generation Lamport/W-OTS v2 envelope pair (both tags
constant-time first), restores their v1 checkpoints, signs one message
with each throwaway signer, and returns the OtsPairProof, the two
next-generation envelopes (Lamport first, W-OTS second) and g+1, all
under one paired claim over the (g, g+1) transition that runs only after
every output exists and keeps no hidden state;
sign_lamport_auth_state and sign_wots_auth_state are the single-signer
stateless restore-sign-wrap conversions for the two one-time schemes: each
authenticates the matching v2 envelope, restores its v1 checkpoint, signs
one message with the throwaway signer, and returns the signature, the
next-generation envelope of the used state and g+1 under one paired
(("scheme", g), ("scheme", g+1)) claim that runs only after every output
exists and keeps no hidden state;
restore_merkle_claimed does the same one-step authenticated restore and
claim for a Merkle signer v2 envelope; restore_lattice_claimed does it
for a toy lattice private key v2 envelope, restoring the key with
ToyLatticePrivateKey.from_bytes and claiming ("lattice", generation).
sign_merkle_auth_state is the stateless restore-sign-wrap conversion: it
authenticates a Merkle v2 envelope and restores its v1 payload, signs the
restored signer's current minimum leaf, wraps the advanced checkpoint at
generation g+1 and, only once every output exists, performs one paired
claim over the (g, g+1) transition — it keeps no hidden state and changes
no old interface or wire byte. sign_merkle_auth_state_batch is the batch
counterpart: it restores the same way, signs a non-empty tuple of messages
with consecutive leaves in a single sign_batch run, and returns the
signature tuple together with the envelope and generation g+1.
sign_multiproof_merkle_auth_state is its multiproof counterpart: it
restores the same way, signs the batch on consecutive leaves from the
current index (or on an explicit strictly increasing indices selection,
voiding the gaps), and returns the deduplicated multiproof_encode proof
bytes over the batch together with the envelope and generation g+1.
advance_merkle_auth_state is the stateless authenticated counterpart of
MerkleSigner.advance_to_with_auth_state: it restores the same way, advances
the next-leaf index with advance_to semantics (an equal target is legal and
still yields the next-generation envelope), and returns the (before, after)
index pair together with the envelope and generation g+1, all under one
(g, g+1) claim that runs only after every output exists.
advance_and_sign_merkle_auth_state combines the two: it restores the same
way, advances the next-leaf index to a caller-chosen target (the leaf count
itself is not legal — the target leaf must remain signable), signs one
message with that target leaf, and returns the (before, target) index pair,
the signature, the envelope and generation g+1, again under a single
(g, g+1) claim that runs only after every output exists.
advance_and_sign_merkle_auth_state_batch is its batch counterpart: it
restores the same way, advances to a caller-chosen still-signable target and
then signs a non-empty tuple of messages on the consecutive leaves from
that target in a single sign_batch run, returning the (before, target)
index pair, the signature tuple, the envelope and generation g+1, all under
the same single (g, g+1) claim.
advance_and_multiproof_merkle_auth_state is its multiproof counterpart: it
restores and advances the same way, signs the same consecutive batch from
the target, and returns the (before, target) index pair, the deduplicated
multiproof_encode proof bytes over the batch, the envelope and generation
g+1, again under the same single (g, g+1) claim.
Both envelopes authenticate but do not encrypt and give no replay
protection on their own.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from ._errors import KeyExhaustedError
from .auth import (
    _authenticate_auth_state_pair,
    _restore_auth_state,
    _restore_auth_state_pair,
    _validate_claim,
    _validate_generation,
    _validate_key,
    auth_state_unwrap,
    auth_state_wrap,
    auth_unwrap,
    auth_wrap,
)
from .merkle import (
    MerkleBatchProof,
    MerkleProof,
    MerklePublicKey,
    MerkleSignature,
    MerkleSigner,
    merkle_verify,
    multiproof_encode,
    multiproof_verify,
    multiproof_verify_bound,
)
from .params import (
    MerkleCardinalityScore,
    MerkleCardinalityScenarioScore,
    MerkleDeploymentScore,
    MerkleDeploymentScenarioScore,
    MerkleStorageProfile,
    MerkleTransportDeploymentProfile,
    MerkleTransportDeploymentScore,
    MerkleTransportDeploymentScenarioScore,
    MerkleTransportWorkloadProfile,
    MerkleTransportWorkloadScore,
    MerkleTransportWorkloadScenarioScore,
    MerkleModeCost,
    MerkleModeScore,
    MerkleModeScenarioScore,
    MerkleVerifyProfile,
    MerkleVerifyWorkloadProfile,
    MerkleVerifyModeScore,
    MerkleVerifyModeDeploymentScore,
    Params,
    SchemeScore,
    SchemeScenarioScore,
    merkle_storage_profile,
    merkle_transport_profile,
    merkle_transport_deployment_frontier,
    merkle_transport_workload_frontier,
    merkle_mode_frontier,
    merkle_verify_mode_frontier,
    merkle_cardinality_frontier,
    recommend_merkle_cardinality_deployment,
    recommend_merkle_cardinality_weighted,
    recommend_merkle_cardinality_weighted_scenarios,
    explain_merkle_cardinality_weighted,
    explain_merkle_cardinality_weighted_scenarios,
    recommend_merkle_verify_mode_deployment,
    recommend_merkle_verify_mode_deployment_weighted,
    recommend_merkle_verify_mode_weighted,
    explain_merkle_verify_mode_weighted,
    explain_merkle_verify_mode_deployment_weighted,
    merkle_verify_profile,
    merkle_verify_workload_profile,
    profile,
    recommend,
    recommend_scheme,
    scheme_frontier,
    recommend_scheme_weighted,
    recommend_scheme_weighted_scenarios,
    explain_scheme_weighted,
    explain_scheme_weighted_scenarios,
    recommend_merkle_deployment,
    merkle_deployment_frontier,
    recommend_merkle_deployment_weighted,
    recommend_merkle_deployment_weighted_scenarios,
    explain_merkle_deployment_weighted,
    explain_merkle_deployment_weighted_scenarios,
    recommend_merkle_mode_deployment,
    recommend_merkle_mode_weighted,
    recommend_merkle_mode_weighted_scenarios,
    explain_merkle_mode_weighted,
    explain_merkle_mode_weighted_scenarios,
    recommend_merkle_transport_deployment,
    recommend_merkle_transport_deployment_weighted,
    recommend_merkle_transport_deployment_weighted_scenarios,
    explain_merkle_transport_deployment_weighted,
    explain_merkle_transport_deployment_weighted_scenarios,
    recommend_merkle_transport_workload,
    recommend_merkle_transport_workload_weighted,
    recommend_merkle_transport_workload_weighted_scenarios,
    explain_merkle_transport_workload_weighted,
    explain_merkle_transport_workload_weighted_scenarios,
)
from .toy_lattice import (
    ToyLatticeCiphertext,
    ToyLatticePrivateKey,
    ToyLatticeProof,
    ToyLatticePublicKey,
    ToyLatticeSignature,
    toy_lattice_decapsulate,
    toy_lattice_encapsulate,
    toy_lattice_keygen,
    toy_lattice_sign,
    toy_lattice_verify,
)
from .wots import (
    ELEMENT_BYTES,
    WOTSOneTimeSigner,
    WOTSPrivateKey,
    WOTSProof,
    WOTSPublicKey,
    wots_keygen,
    wots_sign,
    wots_signature_from_bytes,
    wots_signature_to_bytes,
    wots_verify,
)

__all__ = [
    "BITS",
    "ELEMENT_BYTES",
    "HASH_BYTES",
    "KeyExhaustedError",
    "LamportProof",
    "MerkleBatchProof",
    "MerkleCardinalityScore",
    "MerkleCardinalityScenarioScore",
    "MerkleDeploymentScore",
    "MerkleDeploymentScenarioScore",
    "MerkleProof",
    "MerklePublicKey",
    "MerkleSignature",
    "MerkleSigner",
    "MerkleStorageProfile",
    "MerkleTransportDeploymentProfile",
    "MerkleTransportDeploymentScore",
    "MerkleTransportDeploymentScenarioScore",
    "MerkleTransportWorkloadProfile",
    "MerkleTransportWorkloadScore",
    "MerkleTransportWorkloadScenarioScore",
    "MerkleModeCost",
    "MerkleModeScore",
    "MerkleModeScenarioScore",
    "MerkleVerifyModeScore",
    "MerkleVerifyModeDeploymentScore",
    "MerkleVerifyProfile",
    "MerkleVerifyWorkloadProfile",
    "OneTimeSigner",
    "OtsPairProof",
    "Params",
    "PrivateKey",
    "PublicKey",
    "SchemeScore",
    "SchemeScenarioScore",
    "ToyLatticeCiphertext",
    "ToyLatticePrivateKey",
    "ToyLatticeProof",
    "ToyLatticePublicKey",
    "ToyLatticeSignature",
    "WOTSOneTimeSigner",
    "WOTSPrivateKey",
    "WOTSProof",
    "WOTSPublicKey",
    "advance_and_multiproof_merkle_auth_state",
    "advance_and_sign_merkle_auth_state",
    "advance_and_sign_merkle_auth_state_batch",
    "advance_merkle_auth_state",
    "auth_state_unwrap",
    "auth_state_wrap",
    "auth_unwrap",
    "auth_wrap",
    "explain_merkle_cardinality_weighted",
    "explain_merkle_cardinality_weighted_scenarios",
    "explain_merkle_deployment_weighted",
    "explain_merkle_deployment_weighted_scenarios",
    "explain_merkle_mode_weighted",
    "explain_merkle_mode_weighted_scenarios",
    "explain_merkle_transport_deployment_weighted",
    "explain_merkle_transport_deployment_weighted_scenarios",
    "explain_merkle_transport_workload_weighted",
    "explain_merkle_transport_workload_weighted_scenarios",
    "explain_merkle_verify_mode_weighted",
    "explain_merkle_verify_mode_deployment_weighted",
    "explain_scheme_weighted",
    "explain_scheme_weighted_scenarios",
    "keygen",
    "lamport_signature_from_bytes",
    "lamport_signature_to_bytes",
    "merkle_verify",
    "merkle_deployment_frontier",
    "merkle_storage_profile",
    "merkle_transport_profile",
    "merkle_transport_deployment_frontier",
    "merkle_transport_workload_frontier",
    "merkle_mode_frontier",
    "merkle_verify_mode_frontier",
    "merkle_cardinality_frontier",
    "recommend_merkle_cardinality_deployment",
    "recommend_merkle_cardinality_weighted",
    "recommend_merkle_cardinality_weighted_scenarios",
    "recommend_merkle_verify_mode_deployment",
    "recommend_merkle_verify_mode_deployment_weighted",
    "recommend_merkle_verify_mode_weighted",
    "merkle_verify_profile",
    "merkle_verify_workload_profile",
    "message_bits",
    "message_digest",
    "multiproof_encode",
    "multiproof_verify",
    "multiproof_verify_bound",
    "ots_pair_checkpoint",
    "ots_pair_restore",
    "profile",
    "public_key_from",
    "recommend",
    "recommend_scheme",
    "recommend_scheme_weighted",
    "recommend_scheme_weighted_scenarios",
    "restore_lattice_claimed",
    "restore_merkle_claimed",
    "restore_ots_pair",
    "scheme_frontier",
    "recommend_merkle_deployment",
    "recommend_merkle_deployment_weighted",
    "recommend_merkle_deployment_weighted_scenarios",
    "recommend_merkle_transport_deployment",
    "recommend_merkle_transport_deployment_weighted",
    "recommend_merkle_transport_deployment_weighted_scenarios",
    "recommend_merkle_transport_workload",
    "recommend_merkle_transport_workload_weighted",
    "recommend_merkle_transport_workload_weighted_scenarios",
    "recommend_merkle_mode_deployment",
    "recommend_merkle_mode_weighted",
    "recommend_merkle_mode_weighted_scenarios",
    "sign",
    "sign_lamport_auth_state",
    "sign_merkle_auth_state",
    "sign_merkle_auth_state_batch",
    "sign_multiproof_merkle_auth_state",
    "sign_ots_pair",
    "sign_ots_pair_proof_auth_state",
    "sign_ots_pair_proof_with_auth_state",
    "sign_ots_pair_proof_with_checkpoint",
    "sign_ots_pair_with_checkpoint",
    "sign_wots_auth_state",
    "toy_lattice_decapsulate",
    "toy_lattice_encapsulate",
    "toy_lattice_keygen",
    "toy_lattice_sign",
    "toy_lattice_verify",
    "verify",
    "wots_keygen",
    "wots_sign",
    "wots_signature_from_bytes",
    "wots_signature_to_bytes",
    "wots_verify",
]

BITS = 256
HASH_BYTES = 32
_DOMAIN = b"pqattest/lamport/v1"

_PRIVATE_KEY_MAGIC = b"PQALPRV\0"
_PUBLIC_KEY_MAGIC = b"PQALPUB\0"
_SIGNATURE_MAGIC = b"PQALSIG\0"
_CODEC_VERSION = 1
_CODEC_HEADER_BYTES = 8 + 1 + 2 + 2

_CHECKPOINT_MAGIC = b"PQALCP\0\0"
_CHECKPOINT_VERSION = 1
_CHECKPOINT_HEADER_BYTES = 8 + 1 + 1 + 4
_CHECKPOINT_CHECKSUM_BYTES = 32

_PROOF_MAGIC = b"PQALPRF\0"
_PROOF_VERSION = 1
_PROOF_HEADER_BYTES = 8 + 1 + 4 + 4

_PAIR_PROOF_MAGIC = b"PQAOPRF\0"
_PAIR_PROOF_VERSION = 1
_PAIR_PROOF_HEADER_BYTES = 8 + 1 + 4 + 4

_PAIR_CHECKPOINT_MAGIC = b"PQAOPCP\0"
_PAIR_CHECKPOINT_VERSION = 1
_PAIR_CHECKPOINT_HEADER_BYTES = 8 + 1 + 4 + 4
_PAIR_CHECKPOINT_CHECKSUM_BYTES = 32


def _validate_bits(bits: Any) -> int:
    if isinstance(bits, bool) or not isinstance(bits, int) or not 1 <= bits <= BITS:
        raise ValueError(f"bits must be a non-boolean integer between 1 and {BITS}")
    return bits


def _validate_container(elements: Any, label: str) -> None:
    if not isinstance(elements, tuple):
        raise TypeError(f"{label} collection must be a tuple of {HASH_BYTES}-byte values")
    for element in elements:
        if not isinstance(element, bytes):
            raise TypeError(f"every {label} must be bytes")
        if len(element) != HASH_BYTES:
            raise ValueError(f"every {label} must be exactly {HASH_BYTES} bytes")


def _encode_v1(magic: bytes, bits: int, elements: tuple[bytes, ...]) -> bytes:
    """Shared v1 layout: magic, version, ``bits``, element count, elements."""
    return (
        magic
        + bytes((_CODEC_VERSION,))
        + bits.to_bytes(2, "big")
        + len(elements).to_bytes(2, "big")
        + b"".join(elements)
    )


def _decode_v1(data: Any, magic: bytes, name: str, *, is_key: bool) -> tuple[int, tuple[bytes, ...]]:
    """Parse a v1 blob into ``(bits, elements)``; ``name`` labels errors.

    Keys carry ``2 * bits`` elements, signatures carry ``bits``.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{name} data must be bytes or bytearray")
    data = bytes(data)
    if len(data) < _CODEC_HEADER_BYTES:
        raise ValueError(f"{name} encoding is truncated")
    if data[:8] != magic:
        raise ValueError(f"bad {name} magic")
    if data[8] != _CODEC_VERSION:
        raise ValueError(f"unsupported {name} version: {data[8]}")
    bits = int.from_bytes(data[9:11], "big")
    _validate_bits(bits)
    element_count = int.from_bytes(data[11:13], "big")
    expected_count = 2 * bits if is_key else bits
    if element_count != expected_count:
        raise ValueError("element count does not match bits")
    expected_length = _CODEC_HEADER_BYTES + element_count * HASH_BYTES
    if len(data) < expected_length:
        raise ValueError(f"{name} encoding is truncated")
    if len(data) > expected_length:
        raise ValueError(f"trailing data after the {name} encoding")
    elements = tuple(
        data[_CODEC_HEADER_BYTES + i * HASH_BYTES : _CODEC_HEADER_BYTES + (i + 1) * HASH_BYTES]
        for i in range(element_count)
    )
    return bits, elements


def _as_bytes(message: Any) -> bytes:
    if isinstance(message, bytes):
        return message
    if isinstance(message, bytearray):
        return bytes(message)
    if isinstance(message, str):
        return message.encode("utf-8")
    raise TypeError("message must be bytes, bytearray or str")


def message_digest(message: Any) -> bytes:
    """SHA-256 digest of the message."""
    return hashlib.sha256(_as_bytes(message)).digest()


def message_bits(message: Any, *, bits: int = BITS) -> tuple[int, ...]:
    """Expand the digest into ``bits`` bits, most significant bit first."""
    if not isinstance(bits, int) or not 1 <= bits <= BITS:
        raise ValueError(f"bits must be an integer between 1 and {BITS}")
    digest = message_digest(message)
    return tuple((digest[index >> 3] >> (7 - (index & 7))) & 1 for index in range(bits))


def _secret_digest(secret: bytes) -> bytes:
    return hashlib.sha256(_DOMAIN + secret).digest()


def _key_to_bytes(key: Any, key_type: type, field_name: str, magic: bytes, label: str) -> bytes:
    if not isinstance(key, key_type):
        raise TypeError(f"to_bytes must be called on a {key_type.__name__}")
    elements = getattr(key, field_name, None)
    _validate_container(elements, label)
    bits = len(elements) // 2
    _validate_bits(bits)
    if len(elements) != 2 * bits:
        raise ValueError("key must contain exactly 2 * bits elements")
    return _encode_v1(magic, bits, elements)


@dataclass(frozen=True)
class PrivateKey:
    """``2 * bits`` secret values: index ``2 * i + b`` belongs to bit ``i``, branch ``b``."""

    secrets: tuple[bytes, ...]

    @property
    def bits(self) -> int:
        return len(self.secrets) // 2

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQALPRV\\0"``; the version byte
        (1); ``bits`` and the element count (``2 * bits``) as 2 big-endian
        bytes each; then every secret in its original position, 32 bytes
        each. Encoding is deterministic: the same key always produces the
        same bytes. A field corrupted by bypassing the frozen value shape —
        a non-tuple container or non-``bytes`` members — raises ``TypeError``;
        an out-of-range ``bits``, a wrong element count or a member that is
        not exactly 32 bytes raises ``ValueError``. The blob contains the
        private secrets in the clear — store it as a secret.
        """
        return _key_to_bytes(self, PrivateKey, "secrets", _PRIVATE_KEY_MAGIC, "private secret")

    @classmethod
    def from_bytes(cls, data: Any) -> "PrivateKey":
        """Parse ``to_bytes()`` output back into a :class:`PrivateKey`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, an out-of-range
        ``bits`` value, an element count that is not ``2 * bits``,
        truncation or trailing data raises ``ValueError`` and no instance is
        returned. The restored key is equal by value to the original.
        """
        _bits, secrets = _decode_v1(data, _PRIVATE_KEY_MAGIC, "private key", is_key=True)
        return cls(secrets)


@dataclass(frozen=True)
class PublicKey:
    """One-way images of the private secrets, in the same order."""

    digests: tuple[bytes, ...]

    @property
    def bits(self) -> int:
        return len(self.digests) // 2

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQALPUB\\0"``; the version byte
        (1); ``bits`` and the element count (``2 * bits``) as 2 big-endian
        bytes each; then every digest in its original position, 32 bytes
        each. Encoding is deterministic: the same key always produces the
        same bytes. A field corrupted by bypassing the frozen value shape —
        a non-tuple container or non-``bytes`` members — raises ``TypeError``;
        an out-of-range ``bits`` value, a wrong element count or a member
        that is not exactly 32 bytes raises ``ValueError``.
        """
        return _key_to_bytes(self, PublicKey, "digests", _PUBLIC_KEY_MAGIC, "public digest")

    @classmethod
    def from_bytes(cls, data: Any) -> "PublicKey":
        """Parse ``to_bytes()`` output back into a :class:`PublicKey`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, an out-of-range
        ``bits`` value, an element count that is not ``2 * bits``,
        truncation or trailing data raises ``ValueError`` and no instance is
        returned. The restored key is equal by value to the original.
        """
        _bits, digests = _decode_v1(data, _PUBLIC_KEY_MAGIC, "public key", is_key=True)
        return cls(digests)


def keygen(*, bits: int = BITS, token_bytes: Callable[[int], bytes] = secrets.token_bytes) -> tuple[PrivateKey, PublicKey]:
    """Generate a fresh one-time key pair."""
    if not isinstance(bits, int) or not 1 <= bits <= BITS:
        raise ValueError(f"bits must be an integer between 1 and {BITS}")
    secrets_tuple = tuple(bytes(token_bytes(HASH_BYTES)) for _ in range(2 * bits))
    for secret in secrets_tuple:
        if len(secret) != HASH_BYTES:
            raise ValueError(f"token_bytes must return {HASH_BYTES} bytes")
    private_key = PrivateKey(secrets_tuple)
    return private_key, public_key_from(private_key)


def public_key_from(private_key: PrivateKey) -> PublicKey:
    """Recompute the public key from a private key."""
    if not isinstance(private_key, PrivateKey):
        raise TypeError("private_key must be a PrivateKey")
    return PublicKey(tuple(_secret_digest(secret) for secret in private_key.secrets))


def sign(message: Any, private_key: PrivateKey) -> tuple[bytes, ...]:
    """Produce a one-time signature: reveal one secret per digest bit."""
    if not isinstance(private_key, PrivateKey):
        raise TypeError("private_key must be a PrivateKey")
    bits = message_bits(message, bits=private_key.bits)
    return tuple(private_key.secrets[2 * index + bit] for index, bit in enumerate(bits))


def verify(message: Any, signature: Sequence[bytes], public_key: PublicKey) -> bool:
    """Check a signature against the digest bits of ``message``."""
    if not isinstance(public_key, PublicKey):
        raise TypeError("public_key must be a PublicKey")
    materialised = tuple(bytes(part) for part in signature)
    if len(materialised) != public_key.bits:
        return False
    bits = message_bits(message, bits=public_key.bits)
    for index, bit in enumerate(bits):
        if _secret_digest(materialised[index]) != public_key.digests[2 * index + bit]:
            return False
    return True


def _lamport_signature_matches_key(signature: Any, public_key: Any) -> bool:
    """Non-raising parameter/count check for a Lamport proof pair."""
    if not isinstance(public_key, PublicKey):
        return False
    try:
        bits = _validate_bits(public_key.bits)
    except (ValueError, AttributeError):
        return False
    if not isinstance(signature, tuple) or len(signature) != bits:
        return False
    return all(isinstance(element, bytes) and len(element) == HASH_BYTES
               for element in signature)


@dataclass(frozen=True)
class LamportProof:
    """Frozen, self-contained bundle of one Lamport public key and one signature.

    Unlike a bare signature tuple (whose wire encoding needs the
    corresponding :class:`PublicKey` plus ``bits`` supplied separately), a
    proof carries the :class:`PublicKey` that constrains its signature, so it
    can be transported on its own as a single byte block and verified with
    :meth:`verify`. The proof stores no message and is a pure serialisation
    container: it offers neither authentication nor encryption of the wrapper
    itself, draws no randomness, generates no keys and keeps no state.
    """

    public_key: PublicKey
    signature: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.public_key, PublicKey):
            raise TypeError("public_key must be a PublicKey")
        if not isinstance(self.signature, tuple):
            raise TypeError("signature must be a tuple of 32-byte values")
        if not all(isinstance(element, bytes) for element in self.signature):
            raise TypeError("every signature element must be bytes")
        if not _lamport_signature_matches_key(self.signature, self.public_key):
            raise ValueError("signature bits or element count do not match the public key")

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 proof wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQALPRF\\0"``; one version byte
        (1); the public-key and signature lengths as 4 big-endian bytes each;
        then the existing v1 encodings of the public key and of the signature
        constrained by that key, in that order (the inner encodings are
        reused unchanged). Encoding is deterministic: the same proof always
        produces the same bytes. A field corrupted by bypassing the frozen
        constructor raises ``ValueError`` instead of producing malformed
        bytes.
        """
        if not isinstance(self, LamportProof):
            raise TypeError("to_bytes must be called on a LamportProof")
        try:
            key_bytes = self.public_key.to_bytes()
            signature_bytes = lamport_signature_to_bytes(
                self.signature, bits=self.public_key.bits
            )
        except (TypeError, AttributeError) as exc:
            raise ValueError(f"corrupted proof field: {exc}") from exc
        return (
            _PROOF_MAGIC
            + bytes((_PROOF_VERSION,))
            + len(key_bytes).to_bytes(4, "big")
            + len(signature_bytes).to_bytes(4, "big")
            + key_bytes
            + signature_bytes
        )

    @classmethod
    def from_bytes(cls, data: Any) -> "LamportProof":
        """Parse ``to_bytes()`` output back into a :class:`LamportProof`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. The embedded public key is recovered first and then
        constrains the signature. A bad magic, an unknown version, a length
        field that is out of bounds or disagrees with the actual content,
        truncation, trailing data, an invalid nested encoding, or a signature
        inconsistent with the key (wrong bits or count) raises ``ValueError``
        and no half-valid object is returned.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("proof data must be bytes or bytearray")
        data = bytes(data)
        if len(data) < _PROOF_HEADER_BYTES:
            raise ValueError("proof encoding is truncated")
        if data[:8] != _PROOF_MAGIC:
            raise ValueError("bad proof magic")
        if data[8] != _PROOF_VERSION:
            raise ValueError(f"unsupported proof version: {data[8]}")
        key_length = int.from_bytes(data[9:13], "big")
        signature_length = int.from_bytes(data[13:17], "big")
        key_end = _PROOF_HEADER_BYTES + key_length
        signature_end = key_end + signature_length
        if key_length == 0 or signature_length == 0:
            raise ValueError("a length field must not be zero")
        if key_end > len(data) or signature_end > len(data):
            raise ValueError("proof encoding is truncated")
        if signature_end < len(data):
            raise ValueError("trailing data after the proof encoding")
        public_key = PublicKey.from_bytes(data[_PROOF_HEADER_BYTES:key_end])
        bits, signature = lamport_signature_from_bytes(data[key_end:signature_end])
        if bits != public_key.bits:
            raise ValueError("signature bits do not match the public key")
        return cls(public_key=public_key, signature=signature)

    def verify(self, message: Any) -> bool:
        """Verify the embedded signature against the embedded public key.

        Accepts ``bytes``/``bytearray``/``str`` exactly like :func:`verify`,
        to which this call delegates; it returns ``True`` only for the
        message that was actually signed. Any change to the message, public
        key or signature, an illegal message type, or fields corrupted by
        bypassing the frozen constructor returns ``False`` instead of
        raising. The proof itself carries no message and cannot authenticate
        its own origin.
        """
        try:
            return verify(message, self.signature, self.public_key)
        except Exception:
            return False

    def verify_bound(self, message: Any, *, public_key: Any) -> bool:
        """Verify the signature and bind the proof to an expected public key.

        First requires ``public_key`` to equal the public key embedded in
        the proof, compared by value, then runs the exact verification of
        :meth:`verify` — ``message`` is checked against the embedded
        signature, accepting ``bytes``/``bytearray``/``str`` (a ``str`` is
        encoded as UTF-8). This is the caller-side backstop for what plain
        :meth:`verify` cannot cover: Lamport public-key branches not
        selected by the message bits. No wire format changes, no new
        objects, no randomness and no state are involved.

        ``public_key`` must be a :class:`PublicKey`; any other type raises
        ``TypeError``. Missing or mistyped embedded fields (including
        values corrupted by bypassing the frozen constructor), any
        public-key value mismatch, and any message or signature mismatch
        return ``False`` without leaking any other exception.
        """
        if not isinstance(public_key, PublicKey):
            raise TypeError("public_key must be a PublicKey")
        try:
            embedded_key = self.public_key
            signature = self.signature
            if not isinstance(embedded_key, PublicKey):
                return False
            if embedded_key != public_key:
                return False
            return verify(message, signature, embedded_key)
        except Exception:
            # A bypass-constructed proof may carry arbitrary field objects
            # whose access or comparison raises anything; the bound check
            # reports every such malformed structure as ``False``. External
            # argument type errors were raised before this block.
            return False


@dataclass(frozen=True)
class OtsPairProof:
    """Frozen pair of one Lamport proof and one W-OTS proof for one message.

    The two standalone proof packs (:class:`LamportProof` and
    :class:`WOTSProof`) each transport on their own, but nothing binds a
    Lamport proof and a W-OTS proof for the *same* message into one
    transferable unit. This pair bundles exactly one of each — both
    carrying their own public key and signature — so the double proof can
    be transported as a single deterministic v1 byte block and verified
    together with :meth:`verify`. The pair stores no message and is a pure
    serialisation container: it offers neither authentication nor
    encryption of the wrapper itself, draws no randomness, generates no
    keys and keeps no state.
    """

    lamport: LamportProof
    wots: WOTSProof

    def __post_init__(self) -> None:
        if not isinstance(self.lamport, LamportProof):
            raise TypeError("lamport must be a LamportProof")
        if not isinstance(self.wots, WOTSProof):
            raise TypeError("wots must be a WOTSProof")

    def to_bytes(self) -> bytes:
        """Serialise to the versioned v1 pair-proof wire format as ``bytes``.

        The layout is the 8-byte magic ``b"PQAOPRF\\0"``; one version byte
        (1); the Lamport-proof and W-OTS-proof lengths as 4 big-endian
        bytes each; then the existing v1 encodings of the two member
        proofs, Lamport first and W-OTS second (the inner encodings are
        reused unchanged). Encoding is deterministic: the same pair always
        produces the same bytes. A field corrupted by bypassing the frozen
        constructor raises ``ValueError`` instead of producing malformed
        bytes.
        """
        if not isinstance(self, OtsPairProof):
            raise TypeError("to_bytes must be called on an OtsPairProof")
        try:
            lamport_bytes = self.lamport.to_bytes()
            wots_bytes = self.wots.to_bytes()
        except (TypeError, AttributeError) as exc:
            raise ValueError(f"corrupted proof field: {exc}") from exc
        return (
            _PAIR_PROOF_MAGIC
            + bytes((_PAIR_PROOF_VERSION,))
            + len(lamport_bytes).to_bytes(4, "big")
            + len(wots_bytes).to_bytes(4, "big")
            + lamport_bytes
            + wots_bytes
        )

    @classmethod
    def from_bytes(cls, data: Any) -> "OtsPairProof":
        """Parse ``to_bytes()`` output back into a :class:`OtsPairProof`.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. The two member proofs are recovered Lamport first,
        W-OTS second, each by its own existing v1 parser. A bad magic, an
        unknown version, a length field that is out of bounds or disagrees
        with the actual content, truncation, trailing data, or an invalid
        nested proof encoding raises ``ValueError`` and no half-valid
        object is returned.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("proof data must be bytes or bytearray")
        data = bytes(data)
        if len(data) < _PAIR_PROOF_HEADER_BYTES:
            raise ValueError("proof encoding is truncated")
        if data[:8] != _PAIR_PROOF_MAGIC:
            raise ValueError("bad proof magic")
        if data[8] != _PAIR_PROOF_VERSION:
            raise ValueError(f"unsupported proof version: {data[8]}")
        lamport_length = int.from_bytes(data[9:13], "big")
        wots_length = int.from_bytes(data[13:17], "big")
        lamport_end = _PAIR_PROOF_HEADER_BYTES + lamport_length
        wots_end = lamport_end + wots_length
        if lamport_length == 0 or wots_length == 0:
            raise ValueError("a length field must not be zero")
        if lamport_end > len(data) or wots_end > len(data):
            raise ValueError("proof encoding is truncated")
        if wots_end < len(data):
            raise ValueError("trailing data after the proof encoding")
        lamport = LamportProof.from_bytes(data[_PAIR_PROOF_HEADER_BYTES:lamport_end])
        wots = WOTSProof.from_bytes(data[lamport_end:wots_end])
        return cls(lamport=lamport, wots=wots)

    def verify(self, message: Any) -> bool:
        """Verify both embedded proofs against ``message``.

        Accepts ``bytes``/``bytearray``/``str`` exactly like the member
        proofs' own ``verify`` methods, to which this call delegates; it
        returns ``True`` only when the Lamport proof *and* the W-OTS proof
        both verify for the message that was actually signed. Any change
        to the message, to a public-key branch or signature element used
        by the message bits, an illegal message type, or fields corrupted
        by bypassing the frozen constructor returns ``False`` instead of
        raising — including a member field replaced by a wrong-type
        object, even one whose own ``verify`` would return ``True``. Lamport public-key branches not selected by the message
        bits are outside this guarantee — binding the pair to expected
        public keys with :meth:`verify_bound` closes that gap. The pair
        itself carries no message and cannot authenticate its own origin.
        """
        try:
            lamport = self.lamport
            wots = self.wots
            if not isinstance(lamport, LamportProof):
                return False
            if not isinstance(wots, WOTSProof):
                return False
            return lamport.verify(message) and wots.verify(message)
        except Exception:
            return False

    def verify_bound(self, message: Any, *, lamport_key: Any, wots_key: Any) -> bool:
        """Verify both proofs and bind the pair to the expected public keys.

        First requires ``lamport_key`` to equal the public key embedded in
        the Lamport proof and ``wots_key`` to equal the one embedded in
        the W-OTS proof, each compared by value, then runs the exact
        verification of :meth:`verify` — ``message`` is checked against
        both member proofs, accepting ``bytes``/``bytearray``/``str`` (a
        ``str`` is encoded as UTF-8). This is the caller-side backstop for
        what plain :meth:`verify` cannot cover: Lamport public-key
        branches not selected by the message bits. No wire format changes,
        no new objects, no randomness and no state are involved.

        ``lamport_key`` must be a :class:`PublicKey` and ``wots_key`` a
        :class:`WOTSPublicKey`; any other type raises ``TypeError``.
        Missing or mistyped embedded fields (including values corrupted by
        bypassing the frozen constructor), any public-key value mismatch,
        and any message or signature mismatch return ``False`` without
        leaking any other exception.
        """
        if not isinstance(lamport_key, PublicKey):
            raise TypeError("lamport_key must be a PublicKey")
        if not isinstance(wots_key, WOTSPublicKey):
            raise TypeError("wots_key must be a WOTSPublicKey")
        try:
            lamport = self.lamport
            wots = self.wots
            if not isinstance(lamport, LamportProof):
                return False
            if not isinstance(wots, WOTSProof):
                return False
            if lamport.public_key != lamport_key:
                return False
            if wots.public_key != wots_key:
                return False
            return lamport.verify(message) and wots.verify(message)
        except Exception:
            # A bypass-constructed pair may carry arbitrary field objects
            # whose access or comparison raises anything; the bound check
            # reports every such malformed structure as ``False``. External
            # argument type errors were raised before this block.
            return False


class OneTimeSigner:
    """Thread-safe, single-use wrapper around a :class:`PrivateKey`.

    The first :meth:`sign` call returns the ordinary Lamport signature and
    marks the key as used; every later call raises :class:`KeyExhaustedError`.
    The guard is per instance and per process — copying the private key,
    calling the stateless :func:`sign` directly or reusing the key in another
    process is the caller's responsibility. State can be persisted with
    :meth:`checkpoint` and restored in another process with
    :meth:`from_checkpoint`; the checkpoint contains the private key in the
    clear and is protected only by a SHA-256 checksum against accidental
    corruption, so callers must store it securely.
    :meth:`sign_with_checkpoint` pairs the single signature with the
    post-sign checkpoint in one atomic call.
    """

    __slots__ = ("_lock", "_private_key", "_public_key", "_used")

    def __init__(self, private_key: PrivateKey) -> None:
        if not isinstance(private_key, PrivateKey):
            raise TypeError("private_key must be a PrivateKey")
        self._restore_state(private_key, public_key_from(private_key), False)

    def _restore_state(
        self,
        private_key: PrivateKey,
        public_key: PublicKey,
        used: bool,
    ) -> None:
        self._lock = threading.Lock()
        self._private_key = private_key
        self._public_key = public_key
        self._used = used

    @property
    def public_key(self) -> PublicKey:
        """Public key derived from the wrapped private key (read-only)."""
        return self._public_key

    @property
    def used(self) -> bool:
        """``True`` once a signature has been produced (read-only)."""
        return self._used

    def sign(self, message: Any) -> tuple[bytes, ...]:
        """Sign once.

        Behaves exactly like :func:`sign` on the first call, accepting
        ``bytes``/``bytearray``/``str``; an unsupported message type raises
        ``TypeError`` without consuming the key. Any later call raises
        :class:`KeyExhaustedError`. Concurrent calls are serialised so that at
        most one of them can succeed.
        """
        with self._lock:
            if self._used:
                raise KeyExhaustedError("this one-time signing key has already been used")
            signature = sign(message, self._private_key)
            self._used = True
            return signature

    def _checkpoint_bytes(self) -> bytes:
        """Serialise the signer state; the caller holds the lock."""
        key_blob = self._private_key.to_bytes()
        body = (
            _CHECKPOINT_MAGIC
            + bytes((_CHECKPOINT_VERSION, int(self._used)))
            + len(key_blob).to_bytes(4, "big")
            + key_blob
        )
        return body + hashlib.sha256(body).digest()

    def checkpoint(self) -> bytes:
        """Serialise the signer state (private key plus ``used``) to ``bytes``.

        The v1 layout is: the 8-byte magic ``b"PQALCP\\0\\0"``; one byte each
        for the version (1) and ``used`` (0 or 1); the length of the nested
        private key encoding as 4 big-endian bytes; the complete
        :meth:`PrivateKey.to_bytes` output; and finally the SHA-256 of all
        preceding content. Encoding is deterministic: the same state always
        produces the same bytes.

        The checkpoint shares the signing lock, so a concurrent snapshot
        reflects the state either immediately before or immediately after an
        in-flight :meth:`sign`, never part-way through one. The blob contains
        the private key in the clear and the trailing hash only detects
        accidental corruption — it provides neither authentication nor
        encryption, so store it as a secret.
        """
        with self._lock:
            return self._checkpoint_bytes()

    def sign_with_checkpoint(self, message: Any) -> tuple[tuple[bytes, ...], bytes]:
        """Sign once and snapshot the used state in one atomic step.

        Behaves like :meth:`sign` — same ``bytes``/``bytearray``/``str``
        message rules, same one-time Lamport signature and the same
        post-sign ``used=True`` state, all under the signing lock — but
        instead of the signature alone it returns ``(signature,
        checkpoint)``: the first half is the ordinary immutable signature
        tuple that :meth:`sign` returns, value-for-value identical to
        calling :meth:`sign` on the same message from the same starting
        state, and the second is the ``bytes`` that :meth:`checkpoint`
        returns immediately after signing, byte-for-byte the same v1
        encoding holding the private key and ``used=1``. Pairing the two
        halves in one call keeps the signature and the state it advanced
        to together, so a caller can never match a signature against a
        checkpoint taken at the wrong point under concurrency.

        A rejected message type raises ``TypeError`` without consuming the
        key, and an already used instance raises
        :class:`KeyExhaustedError`; a failed call returns no partial
        result. The whole call — signature, ``used`` flip and snapshot —
        linearises with :meth:`sign` and :meth:`checkpoint` under the same
        lock, so at most one concurrent caller succeeds, and no randomness
        is drawn. The returned checkpoint still carries the private key in
        the clear and its trailing hash only detects accidental corruption
        — it offers no authentication, encryption or atomic persistence,
        so confidentiality, durable storage and rollback protection remain
        the caller's responsibility.
        """
        message = _as_bytes(message)
        with self._lock:
            if self._used:
                raise KeyExhaustedError("this one-time signing key has already been used")
            signature = sign(message, self._private_key)
            self._used = True
            return signature, self._checkpoint_bytes()

    def sign_with_auth_state(
        self, message: Any, *, key: Any, generation: Any
    ) -> tuple[tuple[bytes, ...], bytes]:
        """Sign once and return the advanced state as a v2 auth envelope.

        Behaves like :meth:`sign` — same ``bytes``/``bytearray``/``str``
        message rules, same one-time Lamport signature and the same post-sign
        ``used=True`` state, all under the signing lock — but instead of the
        signature alone it returns ``(signature, envelope)``: the first half
        is the ordinary immutable signature tuple that :meth:`sign` returns,
        and the second is the :func:`auth_state_wrap` v2 envelope (``bytes``)
        over the v1 :meth:`checkpoint` bytes of the used state with
        ``scheme="lamport"`` and the given ``key`` and ``generation``. The
        wrapped checkpoint is byte-for-byte identical to the one
        :meth:`checkpoint` returns immediately after signing, so the envelope
        is byte-for-byte identical to signing and then wrapping an explicit
        checkpoint. Pairing the two halves in one call keeps the signature
        and the state it advanced to together, so a caller can never match a
        signature against a checkpoint taken at the wrong point under
        concurrency.

        Every argument is validated before the key is spent: ``key`` is
        keyword-only and must be a non-empty ``bytes``/``bytearray`` shared
        secret; ``generation`` is keyword-only and must be a non-boolean
        integer in ``0 .. 2**64 - 1``. A wrong message or key type raises
        ``TypeError``; an empty key or an out-of-range generation raises
        ``ValueError``; an already used instance raises
        :class:`KeyExhaustedError`. Every failure leaves ``used`` untouched
        and returns no partial result. The whole call — signature, ``used``
        flip, snapshot and wrapping — linearises with :meth:`sign` and
        :meth:`checkpoint` under the same lock, at most one concurrent caller
        succeeds, and no randomness is drawn. The envelope is plaintext and
        authenticated only; it provides neither encryption nor protection
        against replay or rollback on its own.
        """
        message = _as_bytes(message)
        key_bytes = _validate_key(key)
        generation_value = _validate_generation(generation, "generation")
        with self._lock:
            if self._used:
                raise KeyExhaustedError("this one-time signing key has already been used")
            signature = sign(message, self._private_key)
            self._used = True
            checkpoint = self._checkpoint_bytes()
            envelope = auth_state_wrap(
                checkpoint,
                scheme="lamport",
                key=key_bytes,
                generation=generation_value,
            )
            return signature, envelope

    @classmethod
    def from_checkpoint(cls, data: Any) -> "OneTimeSigner":
        """Restore a signer from ``checkpoint()`` output without randomness.

        ``data`` must be ``bytes`` or ``bytearray``; anything else raises
        ``TypeError``. A bad magic, an unknown version, a ``used`` flag that
        is not 0 or 1, a private key length field that does not match the
        content, an invalid nested private key encoding, truncation, trailing
        data or a checksum mismatch raises ``ValueError`` and no instance is
        returned. The private key and the public key rebuilt from it are
        identical to the original's, so a restored unused signer still allows
        exactly one signature and a checkpoint taken after signing restores a
        signer whose every call raises :class:`KeyExhaustedError`.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("checkpoint data must be bytes or bytearray")
        data = bytes(data)
        header = _CHECKPOINT_HEADER_BYTES
        if len(data) < header + _CHECKPOINT_CHECKSUM_BYTES:
            raise ValueError("checkpoint is too short")
        body, checksum = data[:-_CHECKPOINT_CHECKSUM_BYTES], data[-_CHECKPOINT_CHECKSUM_BYTES:]
        if body[:8] != _CHECKPOINT_MAGIC:
            raise ValueError("bad checkpoint magic")
        if body[8] != _CHECKPOINT_VERSION:
            raise ValueError(f"unsupported checkpoint version: {body[8]}")
        used_byte = body[9]
        if used_byte not in (0, 1):
            raise ValueError("used flag must be 0 or 1")
        key_length = int.from_bytes(body[10:14], "big")
        if len(body) != header + key_length:
            raise ValueError("private key length field does not match the checkpoint length")
        if hashlib.sha256(body).digest() != checksum:
            raise ValueError("checkpoint checksum mismatch")
        try:
            private_key = PrivateKey.from_bytes(body[header:])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid nested private key encoding: {exc}") from exc
        signer = cls.__new__(cls)
        signer._restore_state(private_key, public_key_from(private_key), bool(used_byte))
        return signer

    @classmethod
    def from_auth_state(
        cls, data: Any, *, key: Any, min_generation: Any = None, claim: Any
    ) -> tuple["OneTimeSigner", int]:
        """Restore a signer from a v2 ``"lamport"`` envelope and claim it once.

        Combines v2 verification, the generation floor and the v1 checkpoint
        restore in one call without drawing randomness, and — only once
        everything has succeeded — performs the external monotonic claim so a
        caller can never accept a restored key without also claiming its
        generation. Only an envelope produced by :func:`auth_state_wrap` with
        ``scheme="lamport"`` is accepted; no new format is introduced.
        ``key``, ``min_generation`` and ``claim`` are keyword-only. Returns
        ``(signer, generation)``: the restored :class:`OneTimeSigner` (equal to
        :meth:`from_checkpoint` on the embedded payload) and the non-negative
        uint64 generation carried in the envelope.

        ``data`` must be ``bytes`` or ``bytearray``; ``key`` must be a
        non-empty ``bytes``/``bytearray`` shared secret; ``min_generation``
        must be ``None`` or a non-boolean integer in ``0 .. 2**64 - 1``;
        ``claim`` must be callable. A wrong type (including a boolean floor or
        a non-callable claim) raises ``TypeError``. The v2 HMAC tag is
        verified first with :func:`hmac.compare_digest`; the envelope scheme
        is then fixed to ``"lamport"``, the payload magic checked and the
        generation floor applied; only afterwards is the untouched payload
        handed to :meth:`from_checkpoint`. Once the checkpoint is restored,
        ``claim`` is called exactly once with the single token
        ``("lamport", generation)``; the restore succeeds only when that call
        returns ``True`` (compared by identity), and any exception it raises
        propagates untouched. An empty key, a bad tag or envelope, a
        non-lamport scheme (including a v1 envelope), a generation below the
        floor, an invalid checkpoint, or a claim that is not ``True`` raises
        ``ValueError`` and the callback is never invoked on such a failure.
        """
        return _restore_auth_state(
            "lamport",
            data,
            key=key,
            min_generation=min_generation,
            claim=claim,
            restore=cls.from_checkpoint,
        )


def restore_ots_pair(
    a: Any, b: Any, *, key: Any, floor: Any = None, claim: Any
) -> tuple[tuple["OneTimeSigner", "WOTSOneTimeSigner"], int]:
    """Restore a same-generation Lamport/W-OTS pair and claim both at once.

    Paired counterpart of :meth:`OneTimeSigner.from_auth_state` and
    :meth:`WOTSOneTimeSigner.from_auth_state` for callers that keep the two
    one-time keys in lockstep: ``a`` must be a v2
    :func:`auth_state_wrap` envelope with ``scheme="lamport"`` and ``b`` one
    with ``scheme="wots"``, and the two envelopes must carry the same
    generation. Both states are fully verified and restored before any claim,
    so a caller can never successfully claim only one side; no new wire
    format, randomness or library state is involved. ``key``, ``floor`` and
    ``claim`` are keyword-only. Returns ``((lamport_signer, wots_signer),
    generation)``: the restored :class:`OneTimeSigner` and
    :class:`WOTSOneTimeSigner` (each equal to its ``from_checkpoint`` on the
    embedded payload) and the common non-negative uint64 generation.

    ``a`` and ``b`` must each be ``bytes`` or ``bytearray``; ``key`` must be
    a non-empty ``bytes``/``bytearray`` shared secret; ``floor`` must be
    ``None`` or a non-boolean integer in ``0 .. 2**64 - 1`` and, when given,
    both generations must be at least that high; ``claim`` must be callable.
    A wrong type (including a boolean floor or a non-callable claim) raises
    ``TypeError``. Both envelopes' v2 HMAC tags are verified first with
    :func:`hmac.compare_digest` — neither envelope's fields are parsed until
    both tags check out; the fixed schemes, payload magics, the
    common generation and the floor are checked next, and both v1
    checkpoints are restored last. Only then is ``claim`` called exactly
    once with the paired token ``(("lamport", generation), ("wots",
    generation))``; the restore succeeds only when that call returns
    ``True`` (compared by identity), and any exception it raises propagates
    untouched. An empty key, a bad tag or envelope on either side, wrong
    schemes (including a v1 envelope), differing generations, a generation
    below the floor, an invalid checkpoint, or a claim that is not ``True``
    raises ``ValueError`` and the callback is never invoked on such a
    failure.
    """
    return _restore_auth_state_pair(
        a,
        b,
        key=key,
        floor=floor,
        claim=claim,
        restore_a=OneTimeSigner.from_checkpoint,
        restore_b=WOTSOneTimeSigner.from_checkpoint,
    )


def ots_pair_checkpoint(lamport: Any, wots: Any) -> bytes:
    """Snapshot a Lamport/W-OTS signer pair as one deterministic v1 block.

    The two one-time signers each have their own v1 checkpoint
    (:meth:`OneTimeSigner.checkpoint` and
    :meth:`WOTSOneTimeSigner.checkpoint`), but nothing bundles the two
    states that are always kept in lockstep into one transferable byte
    block. This entry point takes exactly one :class:`OneTimeSigner`
    followed by exactly one :class:`WOTSOneTimeSigner` and returns their
    joint state as ``bytes``; the order is fixed — the Lamport signer is
    always first and a W-OTS signer (or anything else) in its place
    raises ``TypeError``. The two existing v1 checkpoints are embedded
    unchanged, Lamport first and W-OTS second, so no single-signer wire
    format changes, no randomness is drawn and no input object is
    mutated.

    The v1 layout is: the 8-byte magic ``b"PQAOPCP\\0"``; the version byte
    (1); the Lamport and W-OTS checkpoint lengths as 4 big-endian bytes
    each; the complete :meth:`OneTimeSigner.checkpoint` output; the
    complete :meth:`WOTSOneTimeSigner.checkpoint` output; and finally the
    SHA-256 digest of every preceding byte. Encoding is deterministic:
    the same pair state always produces the same bytes.

    Both signing locks are acquired together, Lamport first and W-OTS
    second — the same order every paired signing entry uses — and each
    snapshot shares its signer's own signing lock, so a concurrent
    snapshot can only reflect the pair state immediately before or after a
    paired (or single-side) operation, never part-way through one. The
    block contains both private keys in the clear and its trailing hash
    only detects accidental corruption — it provides neither
    authentication nor encryption — so store it as a secret; atomic
    durability, copy protection and rollback protection remain the
    caller's responsibility.
    """
    if not isinstance(lamport, OneTimeSigner):
        raise TypeError("lamport must be a OneTimeSigner")
    if not isinstance(wots, WOTSOneTimeSigner):
        raise TypeError("wots must be a WOTSOneTimeSigner")
    with lamport._lock, wots._lock:
        lamport_checkpoint = lamport._checkpoint_bytes()
        wots_checkpoint = wots._checkpoint_bytes()
    body = (
        _PAIR_CHECKPOINT_MAGIC
        + bytes((_PAIR_CHECKPOINT_VERSION,))
        + len(lamport_checkpoint).to_bytes(4, "big")
        + len(wots_checkpoint).to_bytes(4, "big")
        + lamport_checkpoint
        + wots_checkpoint
    )
    return body + hashlib.sha256(body).digest()


def ots_pair_restore(data: Any) -> tuple["OneTimeSigner", "WOTSOneTimeSigner"]:
    """Restore a Lamport/W-OTS signer pair from :func:`ots_pair_checkpoint`.

    ``data`` must be ``bytes`` or ``bytearray``; anything else raises
    ``TypeError``. The block is parsed without randomness: the magic,
    version, both length fields and the trailing SHA-256 are verified
    first, and only then are the two embedded v1 checkpoints handed
    unchanged to :meth:`OneTimeSigner.from_checkpoint` and
    :meth:`WOTSOneTimeSigner.from_checkpoint`, Lamport first and W-OTS
    second. A bad magic, an unknown version, a length field that
    disagrees with the content, truncation, trailing data, a checksum
    mismatch, or a nested checkpoint that fails its own parser raises
    ``ValueError`` and no signer instance is returned.

    On success returns ``(lamport_signer, wots_signer)`` — the
    :class:`OneTimeSigner` first and the :class:`WOTSOneTimeSigner`
    second — each equal by value to the signer packed at that position:
    the rebuilt public keys match value-for-value and the ``used`` flags
    are preserved, so an unused side still allows exactly one signature
    while a used side raises :class:`KeyExhaustedError` on every call.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("pair checkpoint data must be bytes or bytearray")
    data = bytes(data)
    header = _PAIR_CHECKPOINT_HEADER_BYTES
    if len(data) < header + _PAIR_CHECKPOINT_CHECKSUM_BYTES:
        raise ValueError("pair checkpoint is too short")
    body, checksum = (
        data[: -_PAIR_CHECKPOINT_CHECKSUM_BYTES],
        data[-_PAIR_CHECKPOINT_CHECKSUM_BYTES:],
    )
    if body[:8] != _PAIR_CHECKPOINT_MAGIC:
        raise ValueError("bad pair checkpoint magic")
    if body[8] != _PAIR_CHECKPOINT_VERSION:
        raise ValueError(f"unsupported pair checkpoint version: {body[8]}")
    lamport_length = int.from_bytes(body[9:13], "big")
    wots_length = int.from_bytes(body[13:17], "big")
    lamport_end = header + lamport_length
    wots_end = lamport_end + wots_length
    if lamport_length == 0 or wots_length == 0:
        raise ValueError("a length field must not be zero")
    if len(body) != wots_end:
        raise ValueError("pair checkpoint length fields do not match the content")
    if hashlib.sha256(body).digest() != checksum:
        raise ValueError("pair checkpoint checksum mismatch")
    try:
        lamport = OneTimeSigner.from_checkpoint(body[header:lamport_end])
        wots = WOTSOneTimeSigner.from_checkpoint(body[lamport_end:wots_end])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid nested signer checkpoint: {exc}") from exc
    return lamport, wots


def sign_ots_pair(
    lamport: Any, wots: Any, message: Any, *, key: Any, generation: Any
) -> tuple[tuple[tuple[bytes, ...], tuple[bytes, ...]], tuple[bytes, bytes]]:
    """Sign one message with a Lamport/W-OTS pair and wrap both advanced states.

    Paired counterpart of :meth:`OneTimeSigner.sign_with_auth_state` and
    :meth:`WOTSOneTimeSigner.sign_with_auth_state` for callers that keep the
    two one-time keys in lockstep: ``lamport`` must be a
    :class:`OneTimeSigner` and ``wots`` a :class:`WOTSOneTimeSigner`, and the
    single ``message`` is signed by both under one joint critical section, so
    the pair either advances together or not at all. No new wire format,
    randomness or library state is involved. ``key`` and ``generation`` are
    keyword-only. Returns ``((lamport_signature, wots_signature),
    (lamport_envelope, wots_envelope))``: the two ordinary immutable
    signature tuples, each equal to what the corresponding signer's
    :meth:`sign` returns for ``message`` from the same state, and the two
    :func:`auth_state_wrap` v2 envelopes (``bytes``) over the v1
    :meth:`checkpoint` bytes of each used state with ``scheme="lamport"`` and
    ``scheme="wots"`` respectively and the given ``key`` and ``generation``.
    Each wrapped checkpoint is byte-for-byte identical to the one the
    matching :meth:`checkpoint` returns immediately after the call, so each
    envelope is byte-for-byte identical to signing and then wrapping an
    explicit checkpoint.

    Every argument is validated before either key is spent: ``message``
    follows the usual ``bytes``/``bytearray``/``str`` rules; ``key`` must be
    a non-empty ``bytes``/``bytearray`` shared secret; ``generation`` must be
    a non-boolean integer in ``0 .. 2**64 - 1``. A wrong signer, message or
    key type (including a boolean generation) raises ``TypeError``; an empty
    key or an out-of-range generation raises ``ValueError``; an already used
    signer on either side raises :class:`KeyExhaustedError`. Every failure
    leaves both ``used`` flags untouched and returns no partial result. Both
    signing locks are acquired together, Lamport first and W-OTS second, and
    the whole call — both signatures, both ``used`` flips, both snapshots and
    both wrappings — linearises with :meth:`OneTimeSigner.sign`,
    :meth:`WOTSOneTimeSigner.sign` and both :meth:`checkpoint` methods, so at
    most one concurrent caller can succeed and no randomness is drawn. The
    envelopes are plaintext and authenticated only; they provide neither
    encryption nor protection against replay or rollback on their own.
    """
    if not isinstance(lamport, OneTimeSigner):
        raise TypeError("lamport must be a OneTimeSigner")
    if not isinstance(wots, WOTSOneTimeSigner):
        raise TypeError("wots must be a WOTSOneTimeSigner")
    message = _as_bytes(message)
    key_bytes = _validate_key(key)
    generation_value = _validate_generation(generation, "generation")
    with lamport._lock, wots._lock:
        if lamport._used:
            raise KeyExhaustedError(
                "this lamport one-time signing key has already been used"
            )
        if wots._used:
            raise KeyExhaustedError(
                "this wots one-time signing key has already been used"
            )
        lamport_signature = sign(message, lamport._private_key)
        wots_signature = wots_sign(message, wots._private_key)
        lamport._used = True
        wots._used = True
        lamport_envelope = auth_state_wrap(
            lamport._checkpoint_bytes(),
            scheme="lamport",
            key=key_bytes,
            generation=generation_value,
        )
        wots_envelope = auth_state_wrap(
            wots._checkpoint_bytes(),
            scheme="wots",
            key=key_bytes,
            generation=generation_value,
        )
        return (lamport_signature, wots_signature), (lamport_envelope, wots_envelope)


def sign_ots_pair_with_checkpoint(
    lamport: Any, wots: Any, message: Any
) -> tuple[tuple[tuple[bytes, ...], tuple[bytes, ...]], tuple[bytes, bytes]]:
    """Sign one message with a Lamport/W-OTS pair and snapshot both states.

    Plaintext paired counterpart of :func:`sign_ots_pair` — and of
    :meth:`OneTimeSigner.sign_with_checkpoint` and
    :meth:`WOTSOneTimeSigner.sign_with_checkpoint` — for callers that keep
    the two one-time keys in lockstep: ``lamport`` must be a
    :class:`OneTimeSigner` and ``wots`` a :class:`WOTSOneTimeSigner`, and
    the single ``message`` is signed by both under one joint critical
    section, so the pair either advances together or not at all. No new
    wire format, randomness or library state is involved. Returns
    ``((lamport_signature, wots_signature), (lamport_checkpoint,
    wots_checkpoint))``: the two ordinary immutable signature tuples, each
    equal to what the corresponding signer's :meth:`sign` returns for
    ``message`` from the same state, and the two v1 :meth:`checkpoint`
    byte strings of the used states, each byte-for-byte identical to the
    one the matching :meth:`checkpoint` returns immediately after the
    call. Every item equals the corresponding half of calling each
    signer's :meth:`sign_with_checkpoint` individually from the same
    state.

    Every argument is validated before either key is spent: ``message``
    follows the usual ``bytes``/``bytearray``/``str`` rules. A wrong
    signer or message type raises ``TypeError``; an already used signer on
    either side raises :class:`KeyExhaustedError`. Every failure leaves
    both ``used`` flags untouched and returns no partial result — when
    either side is already used, neither side is consumed. Both signing
    locks are acquired together, Lamport first and W-OTS second, and the
    whole call — both signatures, both ``used`` flips and both snapshots —
    linearises with :meth:`OneTimeSigner.sign`,
    :meth:`WOTSOneTimeSigner.sign` and both :meth:`checkpoint` methods, so
    at most one concurrent caller can succeed and no randomness is drawn.
    The returned checkpoints still carry the private keys in the clear and
    their trailing hashes only detect accidental corruption — they offer
    no authentication, encryption or atomic persistence, so
    confidentiality, durable storage and rollback protection remain the
    caller's responsibility.
    """
    if not isinstance(lamport, OneTimeSigner):
        raise TypeError("lamport must be a OneTimeSigner")
    if not isinstance(wots, WOTSOneTimeSigner):
        raise TypeError("wots must be a WOTSOneTimeSigner")
    message = _as_bytes(message)
    with lamport._lock, wots._lock:
        if lamport._used:
            raise KeyExhaustedError(
                "this lamport one-time signing key has already been used"
            )
        if wots._used:
            raise KeyExhaustedError(
                "this wots one-time signing key has already been used"
            )
        lamport_signature = sign(message, lamport._private_key)
        wots_signature = wots_sign(message, wots._private_key)
        lamport._used = True
        wots._used = True
        return (lamport_signature, wots_signature), (
            lamport._checkpoint_bytes(),
            wots._checkpoint_bytes(),
        )


def sign_ots_pair_proof_with_checkpoint(
    lamport: Any, wots: Any, message: Any
) -> tuple[OtsPairProof, tuple[bytes, bytes]]:
    """Sign one message with a Lamport/W-OTS pair, pack the proof, snapshot both.

    Proof-packing counterpart of :func:`sign_ots_pair_with_checkpoint` for
    callers that keep the two one-time keys in lockstep: ``lamport`` must be
    a :class:`OneTimeSigner` and ``wots`` a :class:`WOTSOneTimeSigner`, and
    the single ``message`` is signed by both under one joint critical
    section, so the pair either advances together or not at all. No new
    wire format, randomness or library state is involved. Returns
    ``(pair_proof, (lamport_checkpoint, wots_checkpoint))``: an
    :class:`OtsPairProof` holding the :class:`LamportProof` first and the
    :class:`WOTSProof` second, each carrying the signature produced by this
    call together with the corresponding signer's public key, and the two
    v1 :meth:`checkpoint` byte strings of the used states in the same
    Lamport-first order. The proof encodes byte-for-byte identically to an
    :class:`OtsPairProof` assembled by hand from the same two signatures
    and public keys, verifies ``True`` for ``message``, and each signature
    is value-for-value identical to what the matching signer's
    :meth:`sign` returns for ``message`` from the same state. Each
    checkpoint is byte-for-byte identical to the one the matching
    :meth:`checkpoint` returns immediately after the call.

    Every argument is validated before either key is spent: ``message``
    follows the usual ``bytes``/``bytearray``/``str`` rules. A wrong
    signer or message type raises ``TypeError``; an already used signer on
    either side raises :class:`KeyExhaustedError`. Every failure leaves
    both ``used`` flags untouched and returns no partial result — when
    either side is already used, neither side is consumed. Both signing
    locks are acquired together, Lamport first and W-OTS second, and the
    whole call — both signatures, both ``used`` flips, the proof packing
    and both snapshots — linearises with :meth:`OneTimeSigner.sign`,
    :meth:`WOTSOneTimeSigner.sign` and both :meth:`checkpoint` methods, so
    at most one concurrent caller can succeed and no randomness is drawn.
    The returned checkpoints still carry the private keys in the clear and
    their trailing hashes only detect accidental corruption — they offer
    no authentication, encryption or atomic persistence, so
    confidentiality, durable storage and rollback protection remain the
    caller's responsibility.
    """
    if not isinstance(lamport, OneTimeSigner):
        raise TypeError("lamport must be a OneTimeSigner")
    if not isinstance(wots, WOTSOneTimeSigner):
        raise TypeError("wots must be a WOTSOneTimeSigner")
    message = _as_bytes(message)
    with lamport._lock, wots._lock:
        if lamport._used:
            raise KeyExhaustedError(
                "this lamport one-time signing key has already been used"
            )
        if wots._used:
            raise KeyExhaustedError(
                "this wots one-time signing key has already been used"
            )
        lamport_signature = sign(message, lamport._private_key)
        wots_signature = wots_sign(message, wots._private_key)
        lamport._used = True
        wots._used = True
        pair_proof = OtsPairProof(
            lamport=LamportProof(
                public_key=lamport._public_key, signature=lamport_signature
            ),
            wots=WOTSProof(
                public_key=wots._public_key, signature=wots_signature
            ),
        )
        return pair_proof, (
            lamport._checkpoint_bytes(),
            wots._checkpoint_bytes(),
        )


def sign_ots_pair_proof_with_auth_state(
    lamport: Any, wots: Any, message: Any, *, key: Any, generation: Any
) -> tuple[OtsPairProof, tuple[bytes, bytes]]:
    """Sign one message with a Lamport/W-OTS pair, pack the proof, wrap both.

    Authenticated proof-packing counterpart of
    :func:`sign_ots_pair_proof_with_checkpoint` — and the proof-packing
    counterpart of :func:`sign_ots_pair` — for callers that keep the two
    one-time keys in lockstep: ``lamport`` must be a :class:`OneTimeSigner`
    and ``wots`` a :class:`WOTSOneTimeSigner`, and the single ``message`` is
    signed by both under one joint critical section, so the pair either
    advances together or not at all. No new wire format, randomness or
    library state is involved. ``key`` and ``generation`` are keyword-only.
    Returns ``(pair_proof, (lamport_envelope, wots_envelope))``: an
    :class:`OtsPairProof` holding the :class:`LamportProof` first and the
    :class:`WOTSProof` second, each carrying the signature produced by this
    call together with the corresponding signer's public key, and the two
    :func:`auth_state_wrap` v2 envelopes (``bytes``) over the v1
    :meth:`checkpoint` bytes of each used state with ``scheme="lamport"``
    and ``scheme="wots"`` respectively and the given ``key`` and
    ``generation``, in the same Lamport-first order. The proof encodes
    byte-for-byte identically to an :class:`OtsPairProof` assembled by hand
    from the same two signatures and public keys, verifies ``True`` for
    ``message``, and each signature is value-for-value identical to what
    the matching signer's :meth:`sign` returns for ``message`` from the
    same state. Each wrapped checkpoint is byte-for-byte identical to the
    one the matching :meth:`checkpoint` returns immediately after the call,
    so each envelope is byte-for-byte identical to signing and then
    wrapping an explicit checkpoint.

    Every argument is validated before either key is spent: ``message``
    follows the usual ``bytes``/``bytearray``/``str`` rules; ``key`` must
    be a non-empty ``bytes``/``bytearray`` shared secret; ``generation``
    must be a non-boolean integer in ``0 .. 2**64 - 1``. A wrong signer,
    message or key type (including a boolean generation) raises
    ``TypeError``; an empty key or an out-of-range generation raises
    ``ValueError``; an already used signer on either side raises
    :class:`KeyExhaustedError`. Every failure leaves both ``used`` flags
    untouched and returns no partial result — when either side is already
    used, neither side is consumed. Both signing locks are acquired
    together, Lamport first and W-OTS second, and the whole call — both
    signatures, both ``used`` flips, the proof packing, both snapshots and
    both wrappings — linearises with :meth:`OneTimeSigner.sign`,
    :meth:`WOTSOneTimeSigner.sign` and both :meth:`checkpoint` methods, so
    at most one concurrent caller can succeed and no randomness is drawn.
    The envelopes are plaintext and authenticated only; they provide
    neither encryption nor protection against replay or rollback on their
    own.
    """
    if not isinstance(lamport, OneTimeSigner):
        raise TypeError("lamport must be a OneTimeSigner")
    if not isinstance(wots, WOTSOneTimeSigner):
        raise TypeError("wots must be a WOTSOneTimeSigner")
    message = _as_bytes(message)
    key_bytes = _validate_key(key)
    generation_value = _validate_generation(generation, "generation")
    with lamport._lock, wots._lock:
        if lamport._used:
            raise KeyExhaustedError(
                "this lamport one-time signing key has already been used"
            )
        if wots._used:
            raise KeyExhaustedError(
                "this wots one-time signing key has already been used"
            )
        lamport_signature = sign(message, lamport._private_key)
        wots_signature = wots_sign(message, wots._private_key)
        lamport._used = True
        wots._used = True
        pair_proof = OtsPairProof(
            lamport=LamportProof(
                public_key=lamport._public_key, signature=lamport_signature
            ),
            wots=WOTSProof(
                public_key=wots._public_key, signature=wots_signature
            ),
        )
        lamport_envelope = auth_state_wrap(
            lamport._checkpoint_bytes(),
            scheme="lamport",
            key=key_bytes,
            generation=generation_value,
        )
        wots_envelope = auth_state_wrap(
            wots._checkpoint_bytes(),
            scheme="wots",
            key=key_bytes,
            generation=generation_value,
        )
        return pair_proof, (lamport_envelope, wots_envelope)


def sign_ots_pair_proof_auth_state(
    a: Any, b: Any, message: Any, *, key: Any, min_generation: Any = None, claim: Any
) -> tuple[OtsPairProof, tuple[bytes, bytes], int]:
    """Restore a same-generation Lamport/W-OTS pair, sign once each, pack, wrap.

    The stateless counterpart of :func:`sign_ots_pair_proof_with_auth_state`
    for callers that persist the two one-time keys only as v2 envelopes:
    ``a`` must be a :func:`auth_state_wrap` v2 envelope with
    ``scheme="lamport"`` and ``b`` one with ``scheme="wots"``, and the two
    envelopes must carry the same generation ``g``. The envelopes are
    authenticated and their v1 checkpoints restored without mutating any
    object, the single ``message`` is signed by the two fresh signers, the
    two signatures are packed into one :class:`OtsPairProof`, and each used
    state is re-wrapped at generation ``g + 1``. No new wire format,
    randomness or library state is involved. ``key``, ``min_generation`` and
    ``claim`` are keyword-only; only ``min_generation`` has a default
    (``None``, no floor). Returns ``(pair_proof, (lamport_envelope,
    wots_envelope), next_generation)``: the :class:`OtsPairProof` holding the
    :class:`LamportProof` first and the :class:`WOTSProof` second, each
    carrying the signature produced by this call together with the
    corresponding signer's public key; the two next-generation
    :func:`auth_state_wrap` v2 envelopes in the same Lamport-first order,
    each byte-for-byte identical to signing and then wrapping an explicit
    post-sign checkpoint; and the new generation ``g + 1``.

    The proof encodes byte-for-byte identically to an :class:`OtsPairProof`
    assembled by hand from the same two signatures and public keys, verifies
    ``True`` for ``message``, and each signature is value-for-value
    identical to what the matching restored signer's first :meth:`sign`
    returns for ``message``.

    Argument types are checked first; both v2 HMAC tags are then verified
    with :func:`hmac.compare_digest` — neither envelope's fields are parsed
    until both tags check out — and the fixed schemes, payload magics, the
    common generation and the floor are checked next; the two v1 checkpoints
    are restored only afterwards. The input generation ``g`` must be strictly
    below ``2**64 - 1`` so the advanced generation fits a uint64. Once both
    checkpoints are restored, a used state on either side raises
    :class:`KeyExhaustedError` while the other side is left untouched;
    neither restored signer outlives the call, so nothing is consumed in any
    lasting sense. The proof and the two candidate advanced envelopes are
    built before any claim, and only once every output exists is ``claim``
    called exactly once with the paired-transition token
    ``((("lamport", g), ("wots", g)), (("lamport", g + 1), ("wots", g + 1)))``
    — an old-generation pair token followed by a new-generation pair token,
    each with the same shape :func:`restore_ots_pair` uses, in that fixed
    order. The call succeeds only when that return value ``is True``
    (otherwise it raises ``ValueError``), and any exception ``claim`` raises
    propagates untouched. No earlier failure invokes the callback or returns
    a partial result. The same inputs always produce byte-identical outputs
    and no randomness is drawn, and no input object is mutated. The
    envelopes are plaintext and authenticated only; they provide neither
    encryption nor protection against replay or rollback on their own.

    ``a`` and ``b`` must each be ``bytes`` or ``bytearray``; ``key`` must be
    a non-empty ``bytes``/``bytearray`` shared secret; ``message`` follows
    the usual ``bytes``/``bytearray``/``str`` rules; ``min_generation`` must
    be ``None`` or a non-boolean integer in ``0 .. 2**64 - 1``; ``claim``
    must be callable. A wrong type (including a bad message type, a boolean
    floor or a non-callable claim) raises ``TypeError``. An empty key, a bad
    tag or envelope on either side, wrong schemes (including a v1
    envelope), differing generations, a generation below the floor, a
    generation at the uint64 ceiling, an invalid checkpoint, or a claim that
    is not ``True`` raises ``ValueError``.
    """
    # Type checks come first, before a single tag is computed.
    if not isinstance(a, (bytes, bytearray)):
        raise TypeError("a must be bytes or bytearray")
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("b must be bytes or bytearray")
    key_bytes = _validate_key(key)
    if min_generation is not None:
        _validate_generation(min_generation, "min_generation")
    claim_callable = _validate_claim(claim)
    message = _as_bytes(message)

    # Both tags first (constant time), then schemes, common generation and
    # the floor; no checkpoint is restored until all of that holds.
    generation, lamport_checkpoint, wots_checkpoint = _authenticate_auth_state_pair(
        a, b, key=key_bytes, floor=min_generation
    )
    if generation >= 2**64 - 1:
        raise ValueError("generation must be below 2**64-1 so it can advance by one")
    next_generation = generation + 1

    # The restored signers are throwaway: a used state on either side must
    # fail before any output or claim, leaving the other side restorable.
    lamport = OneTimeSigner.from_checkpoint(lamport_checkpoint)
    wots = WOTSOneTimeSigner.from_checkpoint(wots_checkpoint)
    with lamport._lock, wots._lock:
        if lamport._used:
            raise KeyExhaustedError(
                "this lamport one-time signing key has already been used"
            )
        if wots._used:
            raise KeyExhaustedError(
                "this wots one-time signing key has already been used"
            )
        lamport_signature = sign(message, lamport._private_key)
        wots_signature = wots_sign(message, wots._private_key)
        lamport._used = True
        wots._used = True
        pair_proof = OtsPairProof(
            lamport=LamportProof(
                public_key=lamport._public_key, signature=lamport_signature
            ),
            wots=WOTSProof(
                public_key=wots._public_key, signature=wots_signature
            ),
        )
        lamport_envelope = auth_state_wrap(
            lamport._checkpoint_bytes(),
            scheme="lamport",
            key=key_bytes,
            generation=next_generation,
        )
        wots_envelope = auth_state_wrap(
            wots._checkpoint_bytes(),
            scheme="wots",
            key=key_bytes,
            generation=next_generation,
        )

    # Every output exists: exactly one paired (g, g+1) claim, old first.
    result = claim_callable(
        (
            (("lamport", generation), ("wots", generation)),
            (("lamport", next_generation), ("wots", next_generation)),
        )
    )
    if result is not True:
        raise ValueError("claim callback did not return True")
    return pair_proof, (lamport_envelope, wots_envelope), next_generation


def sign_lamport_auth_state(
    data: Any, message: Any, *, key: Any, min_generation: Any = None, claim: Any
) -> tuple[tuple[bytes, ...], bytes, int]:
    """Restore a Lamport v2 envelope, sign once, and wrap the used state.

    The stateless restore-sign-wrap conversion for a one-time Lamport key
    persisted only as a v2 envelope: combines authenticated v2 restore, a
    single one-time Lamport signature and wrapping of the used v1 checkpoint
    in one call without mutating any object, keeping any library state or
    introducing a new wire format. The envelope in ``data`` is authenticated
    and restored exactly like :meth:`OneTimeSigner.from_auth_state`; the
    restored throwaway signer then signs ``message`` exactly like the first
    :meth:`OneTimeSigner.sign` call. ``key``, ``min_generation`` and
    ``claim`` are keyword-only; only ``min_generation`` has a default
    (``None``, no floor). Returns ``(signature, envelope, generation)``: the
    ordinary immutable Lamport signature tuple, value-for-value identical to
    the first :meth:`OneTimeSigner.sign` of the restored signer on
    ``message``; the :func:`auth_state_wrap` v2 envelope (``bytes``) over the
    v1 :meth:`OneTimeSigner.checkpoint` bytes of the used state with
    ``scheme="lamport"``, the original ``key`` and generation ``g + 1`` —
    byte-for-byte identical to calling :func:`auth_state_wrap` on the
    checkpoint a signer returns from :meth:`~OneTimeSigner.checkpoint`
    immediately after signing — and the new generation ``g + 1``.

    ``data`` must be ``bytes`` or ``bytearray`` holding a v2 envelope;
    ``key`` must be a non-empty ``bytes``/``bytearray`` shared secret;
    ``message`` follows the usual ``bytes``/``bytearray``/``str`` rules;
    ``min_generation`` must be ``None`` or a non-boolean integer in
    ``0 .. 2**64 - 1``; ``claim`` must be callable. A wrong type (including a
    boolean floor or a non-callable claim) raises ``TypeError``. The input
    generation ``g`` must be strictly below ``2**64 - 1`` so the advanced
    generation fits a uint64; an envelope at ``2**64 - 1`` raises
    ``ValueError``. A restored signer whose key is already used raises
    :class:`KeyExhaustedError`; the throwaway signer does not outlive the
    call, so no key is consumed in any lasting sense and no partial result is
    left. The v2 HMAC tag is verified first with
    :func:`hmac.compare_digest`, the envelope is fixed to ``"lamport"`` and
    the generation floor applied, the v1 checkpoint is restored, the
    signature and the candidate used-state envelope are built, and only once
    every output exists is ``claim`` called exactly once with the paired
    token ``(("lamport", g), ("lamport", g + 1))`` — old first, new second;
    the call succeeds only when that return value ``is True`` — an empty
    key, a bad tag or envelope, a non-lamport scheme (including a v1
    envelope), a generation below the floor or at the uint64 ceiling, an
    invalid checkpoint, or a claim that is not ``True`` raises
    ``ValueError`` — and any exception ``claim`` raises propagates untouched.
    No earlier failure invokes the callback. The same inputs always produce
    byte-identical outputs, no randomness is drawn, no input object is
    mutated, and no library state is kept. The envelope is plaintext and
    authenticated only; it provides neither encryption nor protection against
    replay or rollback on its own.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    key_bytes = _validate_key(key)
    if min_generation is not None:
        _validate_generation(min_generation, "min_generation")
    claim_callable = _validate_claim(claim)
    message = _as_bytes(message)

    # Authenticate first: no field (including the generation) is trusted
    # until the HMAC tag over the whole body checks out.
    _, generation, checkpoint = auth_state_unwrap(
        data,
        key=key_bytes,
        expect="lamport",
        min_generation=min_generation,
    )
    if generation >= 2**64 - 1:
        raise ValueError("generation must be below 2**64-1 so it can advance by one")
    next_generation = generation + 1
    signer = OneTimeSigner.from_checkpoint(checkpoint)
    # Build every output before the claim: a used state or any failure here
    # must leave no partial result and must not call claim. The restored
    # signer is throwaway, so flipping its used flag consumes nothing
    # lasting; only the returned advanced envelope retires the key.
    with signer._lock:
        if signer._used:
            raise KeyExhaustedError("this one-time signing key has already been used")
        signature = sign(message, signer._private_key)
        signer._used = True
        envelope = auth_state_wrap(
            signer._checkpoint_bytes(),
            scheme="lamport",
            key=key_bytes,
            generation=next_generation,
        )
    result = claim_callable((("lamport", generation), ("lamport", next_generation)))
    if result is not True:
        raise ValueError("claim callback did not return True")
    return signature, envelope, next_generation


def sign_wots_auth_state(
    data: Any, message: Any, *, key: Any, min_generation: Any = None, claim: Any
) -> tuple[tuple[bytes, ...], bytes, int]:
    """Restore a W-OTS v2 envelope, sign once, and wrap the used state.

    The stateless restore-sign-wrap conversion for a one-time W-OTS key
    persisted only as a v2 envelope: combines authenticated v2 restore, a
    single one-time W-OTS signature and wrapping of the used v1 checkpoint
    in one call without mutating any object, keeping any library state or
    introducing a new wire format. The envelope in ``data`` is authenticated
    and restored exactly like :meth:`WOTSOneTimeSigner.from_auth_state`; the
    restored throwaway signer then signs ``message`` exactly like the first
    :meth:`WOTSOneTimeSigner.sign` call. ``key``, ``min_generation`` and
    ``claim`` are keyword-only; only ``min_generation`` has a default
    (``None``, no floor). Returns ``(signature, envelope, generation)``: the
    ordinary immutable W-OTS signature tuple, value-for-value identical to
    the first :meth:`WOTSOneTimeSigner.sign` of the restored signer on
    ``message``; the :func:`auth_state_wrap` v2 envelope (``bytes``) over the
    v1 :meth:`WOTSOneTimeSigner.checkpoint` bytes of the used state with
    ``scheme="wots"``, the original ``key`` and generation ``g + 1`` —
    byte-for-byte identical to calling :func:`auth_state_wrap` on the
    checkpoint a signer returns from
    :meth:`~WOTSOneTimeSigner.checkpoint` immediately after signing — and the
    new generation ``g + 1``.

    ``data`` must be ``bytes`` or ``bytearray`` holding a v2 envelope;
    ``key`` must be a non-empty ``bytes``/``bytearray`` shared secret;
    ``message`` follows the usual ``bytes``/``bytearray``/``str`` rules;
    ``min_generation`` must be ``None`` or a non-boolean integer in
    ``0 .. 2**64 - 1``; ``claim`` must be callable. A wrong type (including a
    boolean floor or a non-callable claim) raises ``TypeError``. The input
    generation ``g`` must be strictly below ``2**64 - 1`` so the advanced
    generation fits a uint64; an envelope at ``2**64 - 1`` raises
    ``ValueError``. A restored signer whose key is already used raises
    :class:`KeyExhaustedError`; the throwaway signer does not outlive the
    call, so no key is consumed in any lasting sense and no partial result is
    left. The v2 HMAC tag is verified first with
    :func:`hmac.compare_digest`, the envelope is fixed to ``"wots"`` and the
    generation floor applied, the v1 checkpoint is restored, the signature
    and the candidate used-state envelope are built, and only once every
    output exists is ``claim`` called exactly once with the paired token
    ``(("wots", g), ("wots", g + 1))`` — old first, new second; the call
    succeeds only when that return value ``is True`` — an empty key, a bad
    tag or envelope, a non-wots scheme (including a v1 envelope), a
    generation below the floor or at the uint64 ceiling, an invalid
    checkpoint, or a claim that is not ``True`` raises ``ValueError`` — and
    any exception ``claim`` raises propagates untouched. No earlier failure
    invokes the callback. The same inputs always produce byte-identical
    outputs, no randomness is drawn, no input object is mutated, and no
    library state is kept. The envelope is plaintext and authenticated only;
    it provides neither encryption nor protection against replay or rollback
    on its own.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    key_bytes = _validate_key(key)
    if min_generation is not None:
        _validate_generation(min_generation, "min_generation")
    claim_callable = _validate_claim(claim)
    message = _as_bytes(message)

    # Authenticate first: no field (including the generation) is trusted
    # until the HMAC tag over the whole body checks out.
    _, generation, checkpoint = auth_state_unwrap(
        data,
        key=key_bytes,
        expect="wots",
        min_generation=min_generation,
    )
    if generation >= 2**64 - 1:
        raise ValueError("generation must be below 2**64-1 so it can advance by one")
    next_generation = generation + 1
    signer = WOTSOneTimeSigner.from_checkpoint(checkpoint)
    # Build every output before the claim: a used state or any failure here
    # must leave no partial result and must not call claim. The restored
    # signer is throwaway, so flipping its used flag consumes nothing
    # lasting; only the returned advanced envelope retires the key.
    with signer._lock:
        if signer._used:
            raise KeyExhaustedError("this one-time signing key has already been used")
        signature = wots_sign(message, signer._private_key)
        signer._used = True
        envelope = auth_state_wrap(
            signer._checkpoint_bytes(),
            scheme="wots",
            key=key_bytes,
            generation=next_generation,
        )
    result = claim_callable((("wots", generation), ("wots", next_generation)))
    if result is not True:
        raise ValueError("claim callback did not return True")
    return signature, envelope, next_generation


def restore_merkle_claimed(
    data: Any, *, key: Any, floor: Any = None, claim: Any
) -> tuple["MerkleSigner", int]:
    """Restore a Merkle signer from a v2 envelope and claim it once.

    The Merkle counterpart of :meth:`OneTimeSigner.from_auth_state`:
    combines v2 verification, the generation floor and the v1 checkpoint
    restore in one call without drawing randomness, and — only once
    everything has succeeded — performs the external monotonic claim so a
    caller can never accept a restored signer without also claiming its
    generation. Only an envelope produced by :func:`auth_state_wrap` with
    ``scheme="merkle"`` is accepted; no new wire format or library state is
    introduced. ``key``, ``floor`` and ``claim`` are keyword-only; only
    ``floor`` has a default (``None``, no floor). Returns
    ``(signer, generation)``: the restored :class:`MerkleSigner` (equal to
    :meth:`MerkleSigner.from_checkpoint` on the embedded payload) and the
    non-negative uint64 generation carried in the envelope.

    ``data`` must be ``bytes`` or ``bytearray``; ``key`` must be a
    non-empty ``bytes``/``bytearray`` shared secret; ``floor`` must be
    ``None`` or a non-boolean integer in ``0 .. 2**64 - 1``; ``claim`` must
    be callable. A wrong type (including a boolean floor or a non-callable
    claim) raises ``TypeError``. The v2 HMAC tag is verified first with
    :func:`hmac.compare_digest`; the envelope scheme is then fixed to
    ``"merkle"``, the payload magic checked and the generation floor
    applied; only afterwards is the untouched payload handed to
    :meth:`MerkleSigner.from_checkpoint`. Once the checkpoint is fully
    restored, ``claim`` is called exactly once with the single token
    ``("merkle", generation)``; the restore succeeds only when that call
    returns ``True`` (compared by identity), and any exception it raises
    propagates untouched. An empty key, a bad tag or envelope, a non-merkle
    scheme (including a v1 envelope), a generation below the floor, an
    invalid checkpoint, or a claim that is not ``True`` raises
    ``ValueError`` and the callback is never invoked on such a failure.
    """
    return _restore_auth_state(
        "merkle",
        data,
        key=key,
        min_generation=floor,
        claim=claim,
        restore=MerkleSigner.from_checkpoint,
    )


def restore_lattice_claimed(
    data: Any, *, key: Any, floor: Any = None, claim: Any
) -> tuple["ToyLatticePrivateKey", int]:
    """Restore a toy lattice private key from a v2 envelope and claim it once.

    The lattice counterpart of :func:`restore_merkle_claimed`: combines v2
    verification, the generation floor and the versioned private key parse
    in one call without drawing randomness or generating keys, and — only
    once everything has succeeded — performs the external monotonic claim
    so a caller can never accept a restored key without also claiming its
    generation. Only an envelope produced by :func:`auth_state_wrap` with
    ``scheme="lattice"`` is accepted; no new wire format or library state
    is introduced. ``key``, ``floor`` and ``claim`` are keyword-only; only
    ``floor`` has a default (``None``, no floor). Returns
    ``(private_key, generation)``: the restored
    :class:`ToyLatticePrivateKey` (equal by value to
    :meth:`ToyLatticePrivateKey.from_bytes` on the embedded payload) and
    the non-negative uint64 generation carried in the envelope.

    ``data`` must be ``bytes`` or ``bytearray``; ``key`` must be a
    non-empty ``bytes``/``bytearray`` shared secret; ``floor`` must be
    ``None`` or a non-boolean integer in ``0 .. 2**64 - 1``; ``claim`` must
    be callable. A wrong type (including a boolean floor or a non-callable
    claim) raises ``TypeError``. The v2 HMAC tag is verified first with
    :func:`hmac.compare_digest`; the envelope scheme is then fixed to
    ``"lattice"``, the payload magic checked and the generation floor
    applied; only afterwards is the untouched payload handed to
    :meth:`ToyLatticePrivateKey.from_bytes`. Once the private key is fully
    restored, ``claim`` is called exactly once with the single token
    ``("lattice", generation)``; the restore succeeds only when that call
    returns ``True`` (compared by identity), and any exception it raises
    propagates untouched. An empty key, a bad tag or envelope, a
    non-lattice scheme (including a v1 envelope), a generation below the
    floor, an invalid private key encoding (bad magic or version,
    truncation, trailing data, out-of-range coefficients), or a claim that
    is not ``True`` raises ``ValueError`` and the callback is never invoked
    on such a failure.
    """
    return _restore_auth_state(
        "lattice",
        data,
        key=key,
        min_generation=floor,
        claim=claim,
        restore=ToyLatticePrivateKey.from_bytes,
    )


def sign_merkle_auth_state(
    data: Any, message: Any, *, key: Any, min_generation: Any = None, claim: Any
) -> tuple[MerkleSignature, bytes, int]:
    """Restore a Merkle v2 envelope, sign one leaf, and wrap the advanced state.

    The stateless counterpart of :meth:`MerkleSigner.sign_with_auth_state`:
    combines authenticated v2 restore, a single current-leaf Merkle signature
    and wrapping of the next v1 checkpoint in one call without mutating any
    object, keeping any library state or introducing a new wire format. The
    envelope in ``data`` is authenticated and restored exactly like
    :meth:`MerkleSigner.from_auth_state`; the restored signer then signs
    ``message`` with its current lowest unused leaf, exactly like
    :meth:`MerkleSigner.sign`. ``key``, ``min_generation`` and ``claim`` are
    keyword-only; only ``min_generation`` has a default (``None``, no floor).
    Returns ``(signature, envelope, generation)``: the
    :class:`MerkleSignature` for the current minimum leaf, the
    :func:`auth_state_wrap` v2 envelope (``bytes``) over the advanced v1
    :meth:`MerkleSigner.checkpoint` bytes with ``scheme="merkle"``, the
    original ``key`` and generation ``g + 1`` — byte-for-byte identical to
    calling :func:`auth_state_wrap` on the checkpoint a signer with the
    advanced ``next_index`` returns from :meth:`checkpoint` — and the new
    generation ``g + 1``.

    ``data`` must be ``bytes`` or ``bytearray`` holding a v2 envelope;
    ``key`` must be a non-empty ``bytes``/``bytearray`` shared secret;
    ``message`` follows the usual ``bytes``/``bytearray``/``str`` rules;
    ``min_generation`` must be ``None`` or a non-boolean integer in
    ``0 .. 2**64 - 1``; ``claim`` must be callable. A wrong type (including a
    boolean floor or a non-callable claim) raises ``TypeError``. The input
    generation ``g`` must be strictly below ``2**64 - 1`` so the advanced
    generation fits a uint64; an envelope at ``2**64 - 1`` raises
    ``ValueError``. A restored signer with no leaf left raises
    :class:`KeyExhaustedError`. The v2 HMAC tag is verified first with
    :func:`hmac.compare_digest`, the envelope is fixed to ``"merkle"`` and
    the generation floor applied, the v1 checkpoint is restored, the
    signature and the candidate advanced checkpoint/envelope are built, and
    only once every output exists is ``claim`` called exactly once with the
    paired token ``(("merkle", g), ("merkle", g + 1))``; the call succeeds
    only when that return value ``is True`` — wrapping, authentication, the
    floor, a generation at the uint64 ceiling, or a claim that is not
    ``True`` raises ``ValueError`` — and any exception ``claim`` raises
    propagates untouched. No earlier failure invokes the callback or returns
    a partial result. The envelope is plaintext and authenticated only; it
    provides neither encryption nor protection against replay or rollback on
    its own.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    key_bytes = _validate_key(key)
    if min_generation is not None:
        _validate_generation(min_generation, "min_generation")
    claim_callable = _validate_claim(claim)
    message = _as_bytes(message)

    # Authenticate first: no field (including the generation) is trusted
    # until the HMAC tag over the whole body checks out.
    _, generation, checkpoint = auth_state_unwrap(
        data,
        key=key_bytes,
        expect="merkle",
        min_generation=min_generation,
    )
    if generation >= 2**64 - 1:
        raise ValueError("generation must be below 2**64-1 so it can advance by one")
    next_generation = generation + 1
    signer = MerkleSigner.from_checkpoint(checkpoint)
    # Build every output before the claim: a leaf-exhausted state or any
    # failure here must leave no partial result and must not call claim.
    with signer._lock:
        if signer._next_index >= len(signer._private_keys):
            raise KeyExhaustedError("all Merkle leaves have been used")
        index = signer._next_index
        signature = signer._signature_at(index, message)
        advanced_checkpoint = signer._checkpoint_bytes(index + 1)
    envelope = auth_state_wrap(
        advanced_checkpoint,
        scheme="merkle",
        key=key_bytes,
        generation=next_generation,
    )
    result = claim_callable((("merkle", generation), ("merkle", next_generation)))
    if result is not True:
        raise ValueError("claim callback did not return True")
    return signature, envelope, next_generation


def sign_merkle_auth_state_batch(
    data: Any, messages: Any, *, key: Any, min_generation: Any = None, claim: Any
) -> tuple[tuple[MerkleSignature, ...], bytes, int]:
    """Restore a Merkle v2 envelope, sign a batch of leaves, and wrap the state.

    The batch counterpart of :func:`sign_merkle_auth_state`: combines
    authenticated v2 restore, one contiguous :meth:`MerkleSigner.sign_batch`
    run and wrapping of the next v1 checkpoint in a single call without
    mutating any object, keeping any library state or introducing a new wire
    format. The envelope in ``data`` is authenticated and restored exactly
    like :meth:`MerkleSigner.from_auth_state`; the restored signer then signs
    every message in ``messages`` on its current lowest unused leaves,
    consecutively and in order, exactly like
    :meth:`MerkleSigner.sign_batch`. ``key``, ``min_generation`` and
    ``claim`` are keyword-only; only ``min_generation`` has a default
    (``None``, no floor). Returns ``(signatures, envelope, generation)``:
    the tuple of one :class:`MerkleSignature` per message (in order, with
    strictly increasing indices), the :func:`auth_state_wrap` v2 envelope
    (``bytes``) over the advanced v1 :meth:`MerkleSigner.checkpoint` bytes
    with ``scheme="merkle"``, the original ``key`` and generation ``g + 1``
    — byte-for-byte identical to calling :func:`auth_state_wrap` on the
    checkpoint a signer with the advanced ``next_index`` returns from
    :meth:`checkpoint` — and the new generation ``g + 1``.

    ``data`` must be ``bytes`` or ``bytearray`` holding a v2 envelope;
    ``key`` must be a non-empty ``bytes``/``bytearray`` shared secret;
    ``messages`` must be a **non-empty** ``tuple`` whose members each follow
    the usual ``bytes``/``bytearray``/``str`` (UTF-8) message rules;
    ``min_generation`` must be ``None`` or a non-boolean integer in
    ``0 .. 2**64 - 1``; ``claim`` must be callable. A wrong type (including a
    non-tuple ``messages``, a bad message member, a boolean floor or a
    non-callable claim) raises ``TypeError``. An empty batch, an empty
    ``key``, a bad envelope, a generation ``g`` at the uint64 ceiling (it
    must be strictly below ``2**64 - 1`` so the advanced generation fits) or
    any other library-side rejection raises ``ValueError``. A restored
    signer without enough leaves left for the whole batch raises
    :class:`KeyExhaustedError`. The v2 HMAC tag is verified first with
    :func:`hmac.compare_digest`, the envelope is fixed to ``"merkle"`` and
    the generation floor applied, the v1 checkpoint is restored, all
    signatures and the candidate advanced checkpoint/envelope are built in
    one critical section, and only once every output exists is ``claim``
    called exactly once with the paired token
    ``(("merkle", g), ("merkle", g + 1))``; the call succeeds only when that
    return value ``is True``, and any exception ``claim`` raises propagates
    untouched. No earlier failure invokes the callback, advances any state or
    returns a partial result. The same inputs always produce byte-identical
    outputs and no randomness is drawn. The envelope is plaintext and
    authenticated only; it provides neither encryption nor protection
    against replay or rollback on its own.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    key_bytes = _validate_key(key)
    if min_generation is not None:
        _validate_generation(min_generation, "min_generation")
    claim_callable = _validate_claim(claim)
    if not isinstance(messages, tuple):
        raise TypeError("messages must be a tuple of messages")
    if not messages:
        raise ValueError("messages must not be empty")
    batch_messages = tuple(_as_bytes(message) for message in messages)

    # Authenticate first: no field (including the generation) is trusted
    # until the HMAC tag over the whole body checks out.
    _, generation, checkpoint = auth_state_unwrap(
        data,
        key=key_bytes,
        expect="merkle",
        min_generation=min_generation,
    )
    if generation >= 2**64 - 1:
        raise ValueError("generation must be below 2**64-1 so it can advance by one")
    next_generation = generation + 1
    signer = MerkleSigner.from_checkpoint(checkpoint)
    # Build every output before the claim: an under-capacity state or any
    # failure here must leave no partial result and must not call claim.
    with signer._lock:
        base = signer._next_index
        leaf_count = len(signer._private_keys)
        if len(batch_messages) > leaf_count - base:
            raise KeyExhaustedError("not enough Merkle leaves remain for the batch")
        signatures = tuple(
            signer._signature_at(base + offset, message)
            for offset, message in enumerate(batch_messages)
        )
        advanced_checkpoint = signer._checkpoint_bytes(base + len(signatures))
    envelope = auth_state_wrap(
        advanced_checkpoint,
        scheme="merkle",
        key=key_bytes,
        generation=next_generation,
    )
    result = claim_callable((("merkle", generation), ("merkle", next_generation)))
    if result is not True:
        raise ValueError("claim callback did not return True")
    return signatures, envelope, next_generation


def sign_multiproof_merkle_auth_state(
    data: Any, messages: Any, *, indices: Any = None, key: Any,
    min_generation: Any = None, claim: Any,
) -> tuple[bytes, bytes, int]:
    """Restore a Merkle v2 envelope, sign leaves, and wrap a multiproof.

    The multiproof counterpart of :func:`sign_merkle_auth_state_batch`:
    combines authenticated v2 restore, one batch of signatures, a
    deduplicated :func:`multiproof_encode` proof over them and wrapping of
    the next v1 checkpoint in a single call without mutating any object,
    keeping any library state or introducing a new wire format. The envelope
    in ``data`` is authenticated and restored exactly like
    :meth:`MerkleSigner.from_auth_state`; the restored signer then signs
    every message in ``messages`` exactly like
    :func:`sign_merkle_auth_state_batch`, except that the leaves are chosen
    by ``indices``. ``indices``, ``key``, ``min_generation`` and ``claim``
    are keyword-only; only ``indices`` and ``min_generation`` have a default
    (``None``). Returns ``(proof, envelope, generation)``: ``proof`` is the
    ``bytes`` produced by calling :func:`multiproof_encode` on the restored
    public key and this call's signatures — byte-for-byte identical to
    encoding the same signatures on a signer restored from the same state,
    and ``multiproof_verify(messages, proof)`` returns ``True`` — the
    :func:`auth_state_wrap` v2 envelope (``bytes``) over the advanced v1
    :meth:`MerkleSigner.checkpoint` bytes with ``scheme="merkle"``, the
    original ``key`` and generation ``g + 1`` — byte-for-byte identical to
    calling :func:`auth_state_wrap` on the checkpoint a signer with the
    advanced ``next_index`` returns from :meth:`checkpoint` — and the new
    generation ``g + 1``.

    With ``indices=None`` the leaves are allocated consecutively from the
    restored signer's current lowest unused leaf, exactly like
    :func:`sign_merkle_auth_state_batch`. An explicit ``indices`` must be a
    ``tuple`` of the same length as ``messages``, strictly increasing, whose
    members are non-boolean integers between the restored current
    ``next_index`` and the last leaf; the gaps between selected leaves are
    voided and the post-call ``next_index`` is the last selected index plus
    one. A non-tuple ``indices`` or a non-integer member raises
    ``TypeError``; a wrong length, a boolean member, a non-strictly-
    increasing sequence or an out-of-range member raises ``ValueError``.

    Every other input, exception and claim rule is exactly the one of
    :func:`sign_merkle_auth_state_batch`: ``data`` must be ``bytes`` or
    ``bytearray`` holding a v2 envelope; ``key`` must be a non-empty
    ``bytes``/``bytearray`` shared secret; ``messages`` must be a
    **non-empty** ``tuple`` whose members each follow the usual
    ``bytes``/``bytearray``/``str`` (UTF-8) message rules;
    ``min_generation`` must be ``None`` or a non-boolean integer in
    ``0 .. 2**64 - 1``; ``claim`` must be callable. A wrong type raises
    ``TypeError``; an empty batch or key, a bad envelope or an input
    generation ``g`` at the uint64 ceiling (it must be strictly below
    ``2**64 - 1`` so ``g + 1`` fits) raises ``ValueError``. With
    ``indices=None`` a restored signer without enough leaves left for the
    whole batch raises :class:`KeyExhaustedError`. The v2 HMAC tag is
    verified first with :func:`hmac.compare_digest`, the envelope is fixed
    to ``"merkle"`` and the generation floor applied, the v1 checkpoint is
    restored, all signatures and the candidate advanced checkpoint are
    built in one critical section, and only once every output exists is
    ``claim`` called exactly once with the paired token
    ``(("merkle", g), ("merkle", g + 1))``; the call succeeds only when that
    return value ``is True``, and any exception ``claim`` raises propagates
    untouched. No earlier failure invokes the callback, advances any state
    or returns a partial result. The same inputs always produce
    byte-identical outputs and no randomness is drawn. The envelope is
    plaintext and authenticated only; it provides neither encryption nor
    protection against replay or rollback on its own.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    key_bytes = _validate_key(key)
    if min_generation is not None:
        _validate_generation(min_generation, "min_generation")
    claim_callable = _validate_claim(claim)
    if not isinstance(messages, tuple):
        raise TypeError("messages must be a tuple of messages")
    if not messages:
        raise ValueError("messages must not be empty")
    batch_messages = tuple(_as_bytes(message) for message in messages)
    if indices is not None:
        if not isinstance(indices, tuple):
            raise TypeError("indices must be a tuple of leaf indices")
        if len(indices) != len(batch_messages):
            raise ValueError("indices must have the same length as messages")
        if any(isinstance(index, bool) for index in indices):
            raise ValueError("index members must not be booleans")
        if any(not isinstance(index, int) for index in indices):
            raise TypeError("every index must be an integer")
        if any(former >= latter for former, latter in zip(indices, indices[1:])):
            raise ValueError("indices must be strictly increasing and unique")

    # Authenticate first: no field (including the generation) is trusted
    # until the HMAC tag over the whole body checks out.
    _, generation, checkpoint = auth_state_unwrap(
        data,
        key=key_bytes,
        expect="merkle",
        min_generation=min_generation,
    )
    if generation >= 2**64 - 1:
        raise ValueError("generation must be below 2**64-1 so it can advance by one")
    next_generation = generation + 1
    signer = MerkleSigner.from_checkpoint(checkpoint)
    # Build every output before the claim: an out-of-range selection, an
    # under-capacity state or any failure here must leave no partial result
    # and must not call claim.
    with signer._lock:
        base = signer._next_index
        leaf_count = len(signer._private_keys)
        if indices is None:
            if len(batch_messages) > leaf_count - base:
                raise KeyExhaustedError(
                    "not enough Merkle leaves remain for the multiproof"
                )
            selected = tuple(range(base, base + len(batch_messages)))
        else:
            if indices[0] < base or indices[-1] > leaf_count - 1:
                raise ValueError(
                    "indices must be between the current index and the last leaf"
                )
            selected = indices
        signatures = tuple(
            signer._signature_at(index, message)
            for index, message in zip(selected, batch_messages)
        )
        advanced_checkpoint = signer._checkpoint_bytes(selected[-1] + 1)
    proof = multiproof_encode(signer.public_key, signatures)
    envelope = auth_state_wrap(
        advanced_checkpoint,
        scheme="merkle",
        key=key_bytes,
        generation=next_generation,
    )
    result = claim_callable((("merkle", generation), ("merkle", next_generation)))
    if result is not True:
        raise ValueError("claim callback did not return True")
    return proof, envelope, next_generation


def advance_merkle_auth_state(
    data: Any, next_index: Any, *, key: Any, min_generation: Any = None, claim: Any
) -> tuple[tuple[int, int], bytes, int]:
    """Restore a Merkle v2 envelope, void leaves to ``next_index``, and wrap.

    The stateless counterpart of
    :meth:`MerkleSigner.advance_to_with_auth_state`: combines authenticated
    v2 restore, an :meth:`MerkleSigner.advance_to`-semantics jump and
    wrapping of the advanced v1 checkpoint in one call without mutating any
    object, keeping any library state or introducing a new wire format. The
    envelope in ``data`` is authenticated and restored exactly like
    :meth:`MerkleSigner.from_auth_state`; the restored signer then advances
    its next-leaf index to ``next_index`` exactly like
    :meth:`MerkleSigner.advance_to`, so leaves below the target can never be
    signed again. ``key``, ``min_generation`` and ``claim`` are keyword-only;
    only ``min_generation`` has a default (``None``, no floor). Returns
    ``((before, after), envelope, generation)``: the inner tuple is the
    next-leaf index before and after the jump, exactly what
    :meth:`MerkleSigner.advance_to` returns for the same target (an equal
    target is legal and returns the same value twice), the
    :func:`auth_state_wrap` v2 envelope (``bytes``) over the advanced v1
    :meth:`MerkleSigner.checkpoint` bytes with ``scheme="merkle"``, the
    original ``key`` and generation ``g + 1`` — byte-for-byte identical to
    calling :func:`auth_state_wrap` on the checkpoint a signer advanced with
    :meth:`MerkleSigner.advance_to` returns from :meth:`checkpoint` — and the
    new generation ``g + 1``. An equal target still produces the next
    generation envelope even though the wrapped state is unchanged.

    ``data`` must be ``bytes`` or ``bytearray`` holding a v2 envelope;
    ``next_index`` must be a non-boolean integer in the closed interval
    ``[current next_index, public leaf count]``; ``key`` must be a non-empty
    ``bytes``/``bytearray`` shared secret; ``min_generation`` must be ``None``
    or a non-boolean integer in ``0 .. 2**64 - 1``; ``claim`` must be
    callable. A wrong type (including a boolean target or floor, or a
    non-callable claim) raises ``TypeError``. The v2 HMAC tag is verified
    first with :func:`hmac.compare_digest`, the envelope is fixed to
    ``"merkle"`` and the generation floor applied, the v1 checkpoint is
    restored untouched, and the target is range-checked with
    :meth:`advance_to` semantics — a target below the restored current index
    or above the leaf count, or an input generation ``g`` at the uint64
    ceiling (it must be strictly below ``2**64 - 1`` so ``g + 1`` fits),
    raises ``ValueError``. Only once every output exists is ``claim`` called
    exactly once with the paired token
    ``(("merkle", g), ("merkle", g + 1))``; the call succeeds only when that
    return value ``is True`` — otherwise it raises ``ValueError`` — and any
    exception ``claim`` raises propagates untouched. No earlier failure
    invokes the callback or returns a partial result. No object is mutated,
    the same inputs always produce byte-identical outputs and no randomness
    is drawn. The envelope is plaintext and authenticated only; it provides
    neither encryption nor protection against replay or rollback on its own.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    if isinstance(next_index, bool) or not isinstance(next_index, int):
        raise TypeError("next_index must be a non-boolean integer")
    key_bytes = _validate_key(key)
    if min_generation is not None:
        _validate_generation(min_generation, "min_generation")
    claim_callable = _validate_claim(claim)

    # Authenticate first: no field (including the generation) is trusted
    # until the HMAC tag over the whole body checks out.
    _, generation, checkpoint = auth_state_unwrap(
        data,
        key=key_bytes,
        expect="merkle",
        min_generation=min_generation,
    )
    if generation >= 2**64 - 1:
        raise ValueError("generation must be below 2**64-1 so it can advance by one")
    next_generation = generation + 1
    signer = MerkleSigner.from_checkpoint(checkpoint)
    # Build every output before the claim: an out-of-range target or any
    # failure here must leave no partial result and must not call claim.
    with signer._lock:
        before = signer._next_index
        leaf_count = len(signer._private_keys)
        if next_index < before or next_index > leaf_count:
            raise ValueError(
                "next_index must be between the current index and the leaf count"
            )
        advanced_checkpoint = signer._checkpoint_bytes(next_index)
    envelope = auth_state_wrap(
        advanced_checkpoint,
        scheme="merkle",
        key=key_bytes,
        generation=next_generation,
    )
    result = claim_callable((("merkle", generation), ("merkle", next_generation)))
    if result is not True:
        raise ValueError("claim callback did not return True")
    return (before, next_index), envelope, next_generation


def advance_and_sign_merkle_auth_state(
    data: Any, next_index: Any, message: Any, *, key: Any,
    min_generation: Any = None, claim: Any,
) -> tuple[tuple[int, int], MerkleSignature, bytes, int]:
    """Restore a Merkle v2 envelope, void leaves to ``next_index``, sign there.

    The stateless combination of :func:`advance_merkle_auth_state` and
    :func:`sign_merkle_auth_state`: combines authenticated v2 restore, an
    :meth:`MerkleSigner.advance_to`-semantics jump to ``next_index``, a single
    signature with the target leaf and wrapping of the advanced v1 checkpoint
    in one call without mutating any object, keeping any library state or
    introducing a new wire format. The envelope in ``data`` is authenticated
    and restored exactly like :meth:`MerkleSigner.from_auth_state`; the
    restored signer then advances its next-leaf index to ``next_index``
    exactly like :meth:`MerkleSigner.advance_to` and signs ``message`` with
    that target leaf, exactly like :meth:`MerkleSigner.sign` would from the
    advanced state. ``key``, ``min_generation`` and ``claim`` are
    keyword-only; only ``min_generation`` has a default (``None``, no floor).
    Returns ``((before, target), signature, envelope, generation)``: the
    inner tuple is the next-leaf index before and after the jump, exactly
    what :meth:`MerkleSigner.advance_to` returns for the same target (an
    equal target is legal and returns the same value twice); ``signature``
    is the :class:`MerkleSignature` produced for ``message`` at leaf
    ``target``; ``envelope`` is the :func:`auth_state_wrap` v2 envelope
    (``bytes``) over the v1 :meth:`MerkleSigner.checkpoint` bytes with
    ``next_index == target + 1``, ``scheme="merkle"``, the original ``key``
    and generation ``g + 1`` — byte-for-byte identical to calling
    :func:`auth_state_wrap` on the checkpoint a signer advanced to
    ``target`` and then signed once returns from :meth:`checkpoint` — and
    ``generation`` is the new generation ``g + 1``.

    ``data`` must be ``bytes`` or ``bytearray`` holding a v2 envelope;
    ``next_index`` must be a non-boolean integer in the closed interval
    ``[current next_index, leaf count - 1]`` — unlike
    :func:`advance_merkle_auth_state`, the leaf count itself is not a legal
    target because the target leaf must still be signable; ``message``
    follows the usual ``bytes``/``bytearray``/``str`` rules; ``key`` must be
    a non-empty ``bytes``/``bytearray`` shared secret; ``min_generation``
    must be ``None`` or a non-boolean integer in ``0 .. 2**64 - 1``;
    ``claim`` must be callable. A wrong type (including a boolean target or
    floor, or a non-callable claim) raises ``TypeError``. The v2 HMAC tag is
    verified first with :func:`hmac.compare_digest`, the envelope is fixed
    to ``"merkle"`` and the generation floor applied, the v1 checkpoint is
    restored untouched, and the target is range-checked against the restored
    state — a target below the restored current index or above the last leaf
    raises ``ValueError``, as does an input generation ``g`` at the uint64
    ceiling (it must be strictly below ``2**64 - 1`` so ``g + 1`` fits). A
    restored signer with no leaf left to sign raises
    :class:`KeyExhaustedError`. Only once every output exists is ``claim``
    called exactly once with the paired token
    ``(("merkle", g), ("merkle", g + 1))``; the call succeeds only when that
    return value ``is True`` — otherwise it raises ``ValueError`` — and any
    exception ``claim`` raises propagates untouched. No earlier failure
    invokes the callback or returns a partial result. No object is mutated,
    the same inputs always produce byte-identical outputs and no randomness
    is drawn. The envelope is plaintext and authenticated only; it provides
    neither encryption nor protection against replay or rollback on its own.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    if isinstance(next_index, bool) or not isinstance(next_index, int):
        raise TypeError("next_index must be a non-boolean integer")
    key_bytes = _validate_key(key)
    if min_generation is not None:
        _validate_generation(min_generation, "min_generation")
    claim_callable = _validate_claim(claim)
    message = _as_bytes(message)

    # Authenticate first: no field (including the generation) is trusted
    # until the HMAC tag over the whole body checks out.
    _, generation, checkpoint = auth_state_unwrap(
        data,
        key=key_bytes,
        expect="merkle",
        min_generation=min_generation,
    )
    if generation >= 2**64 - 1:
        raise ValueError("generation must be below 2**64-1 so it can advance by one")
    next_generation = generation + 1
    signer = MerkleSigner.from_checkpoint(checkpoint)
    # Build every output before the claim: an exhausted state, an
    # out-of-range target or any failure here must leave no partial result
    # and must not call claim.
    with signer._lock:
        before = signer._next_index
        leaf_count = len(signer._private_keys)
        if before >= leaf_count:
            raise KeyExhaustedError("all Merkle leaves have been used")
        if next_index < before or next_index > leaf_count - 1:
            raise ValueError(
                "next_index must be between the current index and the last leaf"
            )
        signature = signer._signature_at(next_index, message)
        advanced_checkpoint = signer._checkpoint_bytes(next_index + 1)
    envelope = auth_state_wrap(
        advanced_checkpoint,
        scheme="merkle",
        key=key_bytes,
        generation=next_generation,
    )
    result = claim_callable((("merkle", generation), ("merkle", next_generation)))
    if result is not True:
        raise ValueError("claim callback did not return True")
    return (before, next_index), signature, envelope, next_generation


def advance_and_sign_merkle_auth_state_batch(
    data: Any, next_index: Any, messages: Any, *, key: Any,
    min_generation: Any = None, claim: Any,
) -> tuple[tuple[int, int], tuple[MerkleSignature, ...], bytes, int]:
    """Restore, void leaves to ``next_index``, then sign a batch from there.

    The batch counterpart of :func:`advance_and_sign_merkle_auth_state` and
    the jump-first counterpart of :func:`sign_merkle_auth_state_batch`:
    combines authenticated v2 restore, an :meth:`MerkleSigner.advance_to`
    -semantics jump to ``next_index``, one contiguous
    :meth:`MerkleSigner.sign_batch` run from that target and wrapping of the
    advanced v1 checkpoint in a single call without mutating any object,
    keeping any library state or introducing a new wire format. The envelope
    in ``data`` is authenticated and restored exactly like
    :meth:`MerkleSigner.from_auth_state`; the restored signer then advances
    its next-leaf index to ``next_index`` exactly like
    :meth:`MerkleSigner.advance_to` and signs every message in ``messages``
    on the consecutive leaves starting at that target, exactly like
    :meth:`MerkleSigner.sign_batch` would from the advanced state. ``key``,
    ``min_generation`` and ``claim`` are keyword-only; only
    ``min_generation`` has a default (``None``, no floor). Returns
    ``((before, target), signatures, envelope, generation)``: the inner
    tuple is the next-leaf index before and after the jump, exactly what
    :meth:`MerkleSigner.advance_to` returns for the same target (an equal
    target is legal and returns the same value twice); ``signatures`` is the
    tuple of one :class:`MerkleSignature` per message (in order, with
    strictly increasing indices beginning at ``target``), value-for-value
    identical to ``advance_to(target)`` followed by
    ``sign_batch(messages)`` on a signer restored from the same state;
    ``envelope`` is the :func:`auth_state_wrap` v2 envelope (``bytes``) over
    the v1 :meth:`MerkleSigner.checkpoint` bytes with
    ``next_index == target + len(messages)``, ``scheme="merkle"``, the
    original ``key`` and generation ``g + 1`` — byte-for-byte identical to
    calling :func:`auth_state_wrap` on the checkpoint a signer advanced to
    ``target`` and then batch-signed returns from :meth:`checkpoint` — and
    ``generation`` is the new generation ``g + 1``.

    ``data`` must be ``bytes`` or ``bytearray`` holding a v2 envelope;
    ``next_index`` must be a non-boolean integer in the closed interval
    ``[current next_index, leaf count - 1]`` — as in
    :func:`advance_and_sign_merkle_auth_state`, the leaf count itself is not
    a legal target because the target leaf must still be signable;
    ``messages`` must be a **non-empty** ``tuple`` whose members each follow
    the usual ``bytes``/``bytearray``/``str`` (UTF-8) message rules;
    ``key`` must be a non-empty ``bytes``/``bytearray`` shared secret;
    ``min_generation`` must be ``None`` or a non-boolean integer in
    ``0 .. 2**64 - 1``; ``claim`` must be callable. A wrong type (including
    a non-tuple ``messages``, a bad message member, a boolean target or
    floor, or a non-callable claim) raises ``TypeError``. The v2 HMAC tag is
    verified first with :func:`hmac.compare_digest`, the envelope is fixed
    to ``"merkle"`` and the generation floor applied, the v1 checkpoint is
    restored untouched, and the target is range-checked against the restored
    state — a target below the restored current index or above the last leaf,
    an empty batch, or an input generation ``g`` at the uint64 ceiling (it
    must be strictly below ``2**64 - 1`` so ``g + 1`` fits) raises
    ``ValueError``. A restored state without enough leaves left for the jump
    plus the whole batch raises :class:`KeyExhaustedError`; the target leaf
    itself is guaranteed signable, so this only fires when the batch runs
    past the last leaf. The jump, every signature and the candidate advanced
    checkpoint/envelope are built in one critical section, and only once
    every output exists is ``claim`` called exactly once with the paired
    token ``(("merkle", g), ("merkle", g + 1))``; the call succeeds only
    when that return value ``is True`` — otherwise it raises ``ValueError``
    — and any exception ``claim`` raises propagates untouched. No earlier
    failure invokes the callback, advances any state or returns a partial
    result. No object is mutated, the same inputs always produce
    byte-identical outputs and no randomness is drawn. The envelope is
    plaintext and authenticated only; it provides neither encryption nor
    protection against replay or rollback on its own.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    if isinstance(next_index, bool) or not isinstance(next_index, int):
        raise TypeError("next_index must be a non-boolean integer")
    key_bytes = _validate_key(key)
    if min_generation is not None:
        _validate_generation(min_generation, "min_generation")
    claim_callable = _validate_claim(claim)
    if not isinstance(messages, tuple):
        raise TypeError("messages must be a tuple of messages")
    if not messages:
        raise ValueError("messages must not be empty")
    batch_messages = tuple(_as_bytes(message) for message in messages)

    # Authenticate first: no field (including the generation) is trusted
    # until the HMAC tag over the whole body checks out.
    _, generation, checkpoint = auth_state_unwrap(
        data,
        key=key_bytes,
        expect="merkle",
        min_generation=min_generation,
    )
    if generation >= 2**64 - 1:
        raise ValueError("generation must be below 2**64-1 so it can advance by one")
    next_generation = generation + 1
    signer = MerkleSigner.from_checkpoint(checkpoint)
    # Build every output before the claim: an out-of-range target, an
    # under-capacity state or any failure here must leave no partial result
    # and must not call claim.
    with signer._lock:
        before = signer._next_index
        leaf_count = len(signer._private_keys)
        if next_index < before or next_index > leaf_count - 1:
            raise ValueError(
                "next_index must be between the current index and the last leaf"
            )
        if len(batch_messages) > leaf_count - next_index:
            raise KeyExhaustedError("not enough Merkle leaves remain for the batch")
        signatures = tuple(
            signer._signature_at(next_index + offset, message)
            for offset, message in enumerate(batch_messages)
        )
        advanced_checkpoint = signer._checkpoint_bytes(
            next_index + len(signatures)
        )
    envelope = auth_state_wrap(
        advanced_checkpoint,
        scheme="merkle",
        key=key_bytes,
        generation=next_generation,
    )
    result = claim_callable((("merkle", generation), ("merkle", next_generation)))
    if result is not True:
        raise ValueError("claim callback did not return True")
    return (before, next_index), signatures, envelope, next_generation


def advance_and_multiproof_merkle_auth_state(
    data: Any, next_index: Any, messages: Any, *, key: Any,
    min_generation: Any = None, claim: Any,
) -> tuple[tuple[int, int], bytes, bytes, int]:
    """Restore, void leaves to ``next_index``, batch-sign, and multiproof.

    The multiproof counterpart of
    :func:`advance_and_sign_merkle_auth_state_batch`: combines authenticated
    v2 restore, an :meth:`MerkleSigner.advance_to`-semantics jump to
    ``next_index``, one contiguous :meth:`MerkleSigner.sign_batch` run from
    that target, a deduplicated :func:`multiproof_encode` proof over the
    batch and wrapping of the advanced v1 checkpoint in a single call
    without mutating any object, keeping any library state or introducing a
    new wire format. The envelope in ``data`` is authenticated and restored
    exactly like :meth:`MerkleSigner.from_auth_state`; the restored signer
    then advances its next-leaf index to ``next_index`` exactly like
    :meth:`MerkleSigner.advance_to` and signs every message in ``messages``
    on the consecutive leaves starting at that target, exactly like
    :meth:`MerkleSigner.sign_batch` would from the advanced state. ``key``,
    ``min_generation`` and ``claim`` are keyword-only; only
    ``min_generation`` has a default (``None``, no floor). Returns
    ``((before, target), proof, envelope, generation)``: the inner tuple is
    the next-leaf index before and after the jump, exactly what
    :meth:`MerkleSigner.advance_to` returns for the same target (an equal
    target is legal and returns the same value twice); ``proof`` is the
    ``bytes`` produced by calling :func:`multiproof_encode` on the restored
    public key and this batch's signatures — byte-for-byte identical to
    encoding the signatures of ``advance_to(target)`` followed by
    ``sign_batch(messages)`` on a signer restored from the same state, and
    ``multiproof_verify(messages, proof)`` returns ``True``; ``envelope``
    is the :func:`auth_state_wrap` v2 envelope (``bytes``) over the v1
    :meth:`MerkleSigner.checkpoint` bytes with
    ``next_index == target + len(messages)``, ``scheme="merkle"``, the
    original ``key`` and generation ``g + 1`` — byte-for-byte identical to
    calling :func:`auth_state_wrap` on the checkpoint a signer advanced to
    ``target`` and then batch-signed returns from :meth:`checkpoint` — and
    ``generation`` is the new generation ``g + 1``.

    ``data`` must be ``bytes`` or ``bytearray`` holding a v2 envelope;
    ``next_index`` must be a non-boolean integer in the closed interval
    ``[current next_index, leaf count - 1]`` — as in
    :func:`advance_and_sign_merkle_auth_state_batch`, the leaf count itself
    is not a legal target because the target leaf must still be signable;
    ``messages`` must be a **non-empty** ``tuple`` whose members each follow
    the usual ``bytes``/``bytearray``/``str`` (UTF-8) message rules;
    ``key`` must be a non-empty ``bytes``/``bytearray`` shared secret;
    ``min_generation`` must be ``None`` or a non-boolean integer in
    ``0 .. 2**64 - 1``; ``claim`` must be callable. A wrong type (including
    a non-tuple ``messages``, a bad message member, a boolean target or
    floor, or a non-callable claim) raises ``TypeError``. The v2 HMAC tag is
    verified first with :func:`hmac.compare_digest`, the envelope is fixed
    to ``"merkle"`` and the generation floor applied, the v1 checkpoint is
    restored untouched, and the target is range-checked against the restored
    state — a target below the restored current index or above the last
    leaf, an empty batch, or an input generation ``g`` at the uint64 ceiling
    (it must be strictly below ``2**64 - 1`` so ``g + 1`` fits) raises
    ``ValueError``. A restored state without enough leaves left for the jump
    plus the whole batch raises :class:`KeyExhaustedError`. The jump, every
    signature and the candidate advanced checkpoint are built in one
    critical section, and only once every output exists is ``claim`` called
    exactly once with the paired token
    ``(("merkle", g), ("merkle", g + 1))``; the call succeeds only when that
    return value ``is True`` — otherwise it raises ``ValueError`` — and any
    exception ``claim`` raises propagates untouched. No earlier failure
    invokes the callback, advances any state or returns a partial result. No
    object is mutated, the same inputs always produce byte-identical outputs
    and no randomness is drawn. The envelope is plaintext and authenticated
    only; it provides neither encryption nor protection against replay or
    rollback on its own.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    if isinstance(next_index, bool) or not isinstance(next_index, int):
        raise TypeError("next_index must be a non-boolean integer")
    key_bytes = _validate_key(key)
    if min_generation is not None:
        _validate_generation(min_generation, "min_generation")
    claim_callable = _validate_claim(claim)
    if not isinstance(messages, tuple):
        raise TypeError("messages must be a tuple of messages")
    if not messages:
        raise ValueError("messages must not be empty")
    batch_messages = tuple(_as_bytes(message) for message in messages)

    # Authenticate first: no field (including the generation) is trusted
    # until the HMAC tag over the whole body checks out.
    _, generation, checkpoint = auth_state_unwrap(
        data,
        key=key_bytes,
        expect="merkle",
        min_generation=min_generation,
    )
    if generation >= 2**64 - 1:
        raise ValueError("generation must be below 2**64-1 so it can advance by one")
    next_generation = generation + 1
    signer = MerkleSigner.from_checkpoint(checkpoint)
    # Build every output before the claim: an out-of-range target, an
    # under-capacity state or any failure here must leave no partial result
    # and must not call claim.
    with signer._lock:
        before = signer._next_index
        leaf_count = len(signer._private_keys)
        if next_index < before or next_index > leaf_count - 1:
            raise ValueError(
                "next_index must be between the current index and the last leaf"
            )
        if len(batch_messages) > leaf_count - next_index:
            raise KeyExhaustedError("not enough Merkle leaves remain for the batch")
        signatures = tuple(
            signer._signature_at(next_index + offset, message)
            for offset, message in enumerate(batch_messages)
        )
        advanced_checkpoint = signer._checkpoint_bytes(
            next_index + len(signatures)
        )
    proof = multiproof_encode(signer.public_key, signatures)
    envelope = auth_state_wrap(
        advanced_checkpoint,
        scheme="merkle",
        key=key_bytes,
        generation=next_generation,
    )
    result = claim_callable((("merkle", generation), ("merkle", next_generation)))
    if result is not True:
        raise ValueError("claim callback did not return True")
    return (before, next_index), proof, envelope, next_generation


def lamport_signature_to_bytes(signature: Any, *, bits: int) -> bytes:
    """Serialise a stateless Lamport signature to the versioned v1 wire format.

    ``signature`` must be a ``tuple`` whose members are all ``bytes`` — the
    shape :func:`sign` returns; a non-tuple container or a non-``bytes``
    member raises ``TypeError``. ``bits`` is keyword-only and must be a
    non-boolean integer between 1 and 256; the signature must contain
    exactly ``bits`` elements and every element must be exactly 32 bytes,
    else ``ValueError``.

    The layout is the 8-byte magic ``b"PQALSIG\\0"``; the version byte (1);
    ``bits`` and the element count (equal to ``bits``) as 2 big-endian
    bytes each; then every signature element in its original order, 32
    bytes each. Encoding is deterministic: the same signature and ``bits``
    always produce the same bytes.
    """
    if not isinstance(signature, tuple):
        raise TypeError("signature must be a tuple of 32-byte values")
    for element in signature:
        if not isinstance(element, bytes):
            raise TypeError("every signature element must be bytes")
    bits = _validate_bits(bits)
    if len(signature) != bits:
        raise ValueError(f"signature must contain exactly {bits} elements")
    for element in signature:
        if len(element) != HASH_BYTES:
            raise ValueError(f"every signature element must be exactly {HASH_BYTES} bytes")
    return _encode_v1(_SIGNATURE_MAGIC, bits, signature)


def lamport_signature_from_bytes(data: Any) -> tuple[int, tuple[bytes, ...]]:
    """Parse :func:`lamport_signature_to_bytes` output back into ``(bits, elements)``.

    ``data`` must be ``bytes`` or ``bytearray``; anything else raises
    ``TypeError``. A bad magic, an unknown version, an out-of-range
    ``bits`` value, an element count that is not ``bits``, truncation or
    trailing data raises ``ValueError``. The returned ``bits`` is an
    ``int`` and ``elements`` is an immutable ``tuple`` of 32-byte
    ``bytes`` in their original order, ready for :func:`verify`.
    """
    return _decode_v1(data, _SIGNATURE_MAGIC, "signature", is_key=False)

from typing import Optional, Dict, Any
from cap.models import (
    Action, Attestation, TraceEnvelope, Decision, EvidenceStatus,
    ContinuityScope, KeyResolution
)
from cap.hash_utils import sha256_hex
from cap.canonicalize import canonicalize
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def build_attestation(action: Action,
                      authority_reference: str,
                      sequence_number: int,
                      timestamp: int) -> Attestation:
    params_hash = sha256_hex(action.canonical())
    return Attestation(
        action_type=action.action_type,
        resource=action.resource,
        parameters_hash=params_hash,
        sequence_number=sequence_number,
        authority_reference=authority_reference,
        timestamp=timestamp
    )

def sign_envelope(envelope: TraceEnvelope, private_key: Ed25519PrivateKey) -> TraceEnvelope:
    envelope.signature = private_key.sign(envelope.canonical_bytes()).hex()
    return envelope

def build_envelope(action: Action,
                   decision: Decision,
                   attestation: Attestation,
                   evidence_status,
                   policy_version: str,
                   policy_bundle_digest: str,
                   authority_state: str,
                   continuity_valid: bool,
                   continuity_scope: ContinuityScope,
                   key_resolution: KeyResolution,
                   runtime_context: Optional[Dict[str, Any]] = None,
                   observer_id: str = "decisionassure-reference",
                   reference_frame: str = "cap-envelope-v1") -> TraceEnvelope:
    return TraceEnvelope(
        version="cap-envelope-v1",
        decision=decision,
        action=action,
        attestation=attestation,
        evidence_status=list(evidence_status),
        policy_version=policy_version,
        policy_bundle_digest=policy_bundle_digest,
        authority_state=authority_state,
        continuity_valid=continuity_valid,
        continuity_scope=continuity_scope,
        key_resolution=key_resolution,
        observer_id=observer_id,
        reference_frame=reference_frame,
        runtime_context=runtime_context or {},
        key_id=key_resolution.key_id
    )
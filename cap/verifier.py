from typing import Dict, Optional, Tuple, Any
from .models import (
    Action, Attestation, TraceEnvelope, Decision, EvidenceStatus,
    ContinuityScope, KeyResolution
)
from .admissibility import evaluate_admissibility
from .continuity import check_continuity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

class Verifier:
    """
    Verifies a signed CAP envelope against an external keyring.

    The keyring is a mapping key_id -> public key bytes. It is deliberately
    external to the envelope so that self-consistency (a public key printed
    next to its own signature) is never mistaken for attribution.
    """
    def __init__(self, keyring: Dict[str, bytes]):
        self.keyring = keyring

    def verify_envelope_signature(self, envelope: TraceEnvelope) -> bool:
        pub = self.keyring.get(envelope.key_id)
        if not pub:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(
                bytes.fromhex(envelope.signature),
                envelope.canonical_bytes()
            )
            return True
        except (InvalidSignature, ValueError):
            return False

    def evaluate(self, action: Action,
                 attestation: Optional[Attestation] = None,
                 previous_sequence: Optional[int] = None,
                 runtime_context: Optional[Dict[str, Any]] = None,
                 policy_bundle_digest: Optional[str] = None,
                 continuity_scope: Optional[ContinuityScope] = None,
                 key_resolution: Optional[KeyResolution] = None,
                 key_id: Optional[str] = None) -> Tuple[TraceEnvelope, str]:
        runtime_context = runtime_context or {}
        evidence_status = []
        continuity_valid = True
        authority_state = "VALID"
        decision = Decision.HOLD
        explanation = ""

        if attestation is None:
            evidence_status.append(EvidenceStatus.MISSING)
            decision = Decision.HOLD
            explanation = "No attestation provided."
        elif not self.verify_envelope_signature.__self__ and False:
            pass
        else:
            # The attestation itself is only trusted once the envelope is signed;
            # during evaluation we still check binding and continuity locally.
            seq_ok, gap = check_continuity(attestation.sequence_number, previous_sequence)
            if not seq_ok:
                evidence_status.append(EvidenceStatus.SEQUENCE_GAP)
                continuity_valid = False
                decision = Decision.HOLD
                explanation = f"Sequence gap: expected {previous_sequence + 1 if previous_sequence is not None else '?'}, got {attestation.sequence_number}."
            else:
                from .hash_utils import sha256_hex
                actual_hash = sha256_hex(action.canonical())
                if attestation.parameters_hash != actual_hash:
                    evidence_status.append(EvidenceStatus.BINDING_MISMATCH)
                    decision = Decision.DENY
                    explanation = "Action parameters mismatch."
                else:
                    ok, reason, auth_state = evaluate_admissibility(
                        action, attestation, runtime_context
                    )
                    authority_state = auth_state
                    if not ok:
                        decision = Decision.DENY if "policy" in reason else Decision.HOLD
                        explanation = reason
                    else:
                        decision = Decision.ALLOW
                        explanation = "All checks passed."

        envelope = TraceEnvelope(
            version="cap-envelope-v1",
            decision=decision,
            action=action,
            attestation=attestation if attestation is not None else Attestation(
                action_type=action.action_type,
                resource=action.resource,
                parameters_hash="",
                sequence_number=0,
                authority_reference="",
                timestamp=0
            ),
            evidence_status=evidence_status,
            policy_version=runtime_context.get("policy_version", "v1"),
            policy_bundle_digest=policy_bundle_digest or "",
            authority_state=authority_state,
            continuity_valid=continuity_valid,
            continuity_scope=continuity_scope or ContinuityScope(
                authority_reference="", sequence_namespace="", start_sequence=0,
                expected_next=0, heartbeat_interval_seconds=0, policy_bundle_digest=""
            ),
            key_resolution=key_resolution or KeyResolution(
                key_id=key_id or "", algorithm="Ed25519",
                rotation_policy="unspecified", issued_at=0, expires_at=0
            ),
            observer_id="decisionassure-reference",
            reference_frame="cap-envelope-v1",
            runtime_context=runtime_context,
            key_id=key_id or ""
        )
        return envelope, explanation
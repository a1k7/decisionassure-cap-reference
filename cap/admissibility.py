"""Deterministic reference policy at the execution boundary."""
from __future__ import annotations
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .continuity import verify_continuity
from .models import Action, AdmissibilityResult, AuthorizationAttestation, Decision, RuntimeContext, VerificationStatus
from attestation.sequence import verify_sequence
from attestation.verifier import verify_action_binding, verify_attestation


def evaluate_admissibility(attestation: AuthorizationAttestation | None, execution_action: Action,
                           context: RuntimeContext, keys: dict[str, Ed25519PublicKey]) -> AdmissibilityResult:
    """Apply the small, explicit CAP reference policy.

    Precedence intentionally makes explicit forgery/substitution DENY, insufficient
    evidence HOLD, and a changed otherwise-valid governance state REAUTHORIZE.
    """
    if attestation is None or not context.attestation_available:
        return AdmissibilityResult(Decision.HOLD, "CAP-REF-001", ("ATTESTATION_UNAVAILABLE",))
    attest = verify_attestation(attestation, keys)
    binding = verify_action_binding(attestation, execution_action)
    sequence = verify_sequence(context.expected_sequence, attestation.sequence_number)
    continuity = verify_continuity(context)
    if attest.status is VerificationStatus.INVALID:
        return AdmissibilityResult(Decision.DENY, "CAP-REF-002", attest.reasons, attest.status, binding.status, continuity.status)
    if binding.status is VerificationStatus.INVALID:
        return AdmissibilityResult(Decision.DENY, "CAP-REF-003", binding.reasons, attest.status, binding.status, continuity.status)
    if context.governance_state.authority_valid is False:
        return AdmissibilityResult(Decision.DENY, "CAP-REF-004", ("AUTHORITY_INVALID",), attest.status, binding.status, continuity.status)
    if not context.governance_state.policy_allows_action:
        return AdmissibilityResult(Decision.DENY, "CAP-REF-005", ("POLICY_PROHIBITS_ACTION",), attest.status, binding.status, continuity.status)
    if sequence.status is VerificationStatus.INVALID:
        return AdmissibilityResult(Decision.HOLD, "CAP-REF-006", sequence.reasons, attest.status, binding.status, continuity.status)
    if (attest.status is VerificationStatus.UNKNOWN or context.governance_state.authority_valid is None or
            continuity.status is VerificationStatus.UNKNOWN or any(e.freshness_status is not VerificationStatus.VALID for e in context.evidence)):
        return AdmissibilityResult(Decision.HOLD, "CAP-REF-007", ("MATERIAL_EVIDENCE_UNAVAILABLE",), attest.status, binding.status, continuity.status)
    if continuity.status is VerificationStatus.INVALID:
        return AdmissibilityResult(Decision.REAUTHORIZE, "CAP-REF-008", continuity.reasons, attest.status, binding.status, continuity.status)
    return AdmissibilityResult(Decision.ALLOW, "CAP-REF-009", (), attest.status, binding.status, continuity.status)

"""Replay declared trace inputs without inventing missing evidence."""
from __future__ import annotations
from typing import Any
from .hash_utils import sha256_digest
from .models import Decision, EvidenceCompleteness, ReplayResult


def trace_digest(trace: dict[str, Any]) -> str:
    """Hash a trace excluding its self-referential integrity field."""
    return sha256_digest({k: v for k, v in trace.items() if k != "trace_hash"})


def replay_trace(trace: dict[str, Any]) -> ReplayResult:
    """Reconstruct the declared decision from a fixture's declared conditions.

    Static fixtures are deterministic demonstration artifacts, not signed
    attestations. Their trace_hash detects fixture modification.
    """
    reasons: list[str] = []
    if trace.get("trace_hash") != trace_digest(trace):
        return ReplayResult(False, None, None, False, ("TRACE_INTEGRITY_MISMATCH",), EvidenceCompleteness.UNKNOWN)
    evidence = trace.get("evidence")
    if evidence is None:
        return ReplayResult(False, None, Decision(trace.get("decision")) if trace.get("decision") else None,
                            False, ("EVIDENCE_UNDECLARED",), EvidenceCompleteness.UNKNOWN)
    completeness = EvidenceCompleteness.COMPLETE
    if any(item.get("freshness_status") == "UNKNOWN" for item in evidence):
        completeness = EvidenceCompleteness.PARTIAL
    declared = trace.get("declared_conditions", {})
    if not declared.get("attestation_available", True):
        reconstructed = Decision.HOLD; reasons.append("ATTESTATION_UNAVAILABLE")
    elif not declared.get("signature_valid", False):
        reconstructed = Decision.DENY; reasons.append("INVALID_SIGNATURE")
    elif not declared.get("binding_valid", False):
        reconstructed = Decision.DENY; reasons.append("ACTION_BINDING_MISMATCH")
    elif not declared.get("authority_valid", False):
        reconstructed = Decision.DENY; reasons.append("AUTHORITY_INVALID")
    elif declared.get("sequence_status") != "VALID":
        reconstructed = Decision.HOLD; reasons.append("ATTESTATION_SEQUENCE_GAP")
    elif declared.get("continuity_status") == "CHANGED":
        reconstructed = Decision.REAUTHORIZE; reasons.append("CONTINUITY_HASH_MISMATCH")
    elif completeness is not EvidenceCompleteness.COMPLETE:
        reconstructed = Decision.HOLD; reasons.append("MATERIAL_EVIDENCE_UNAVAILABLE")
    else:
        reconstructed = Decision.ALLOW
    original = Decision(trace["decision"])
    return ReplayResult(True, reconstructed, original, reconstructed is original, tuple(reasons), completeness)

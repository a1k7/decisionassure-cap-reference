"""Typed data models for the CAP reference implementation."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from .hash_utils import sha256_digest


class VerificationStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    DENY = "DENY"
    REAUTHORIZE = "REAUTHORIZE"


class EvidenceCompleteness(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Action:
    action_type: str
    resource: str
    parameters: dict[str, Any]
    parameters_hash: str = ""

    def __post_init__(self) -> None:
        expected = sha256_digest(self.parameters)
        if self.parameters_hash and self.parameters_hash != expected:
            raise ValueError("parameters_hash must match canonical parameters")
        object.__setattr__(self, "parameters_hash", expected)

    def binding_payload(self) -> dict[str, Any]:
        """Return the exact fields an authorization binds."""
        return {"action_type": self.action_type, "resource": self.resource,
                "parameters_hash": self.parameters_hash}

    def to_dict(self) -> dict[str, Any]:
        return {"action_type": self.action_type, "resource": self.resource,
                "parameters": self.parameters, "parameters_hash": self.parameters_hash}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Action":
        return cls(value["action_type"], value["resource"], value["parameters"],
                   value.get("parameters_hash", ""))


@dataclass(frozen=True)
class AuthorizationAttestation:
    attestation_id: str
    action: Action
    sequence_number: int
    authorization_timestamp: str
    clock_source: str
    authority_reference: str
    signing_key_id: str
    signature: str = ""

    def payload(self) -> dict[str, Any]:
        """Return the signed payload, deliberately excluding the signature."""
        return {"attestation_id": self.attestation_id, "action": self.action.to_dict(),
                "sequence_number": self.sequence_number,
                "authorization_timestamp": self.authorization_timestamp,
                "clock_source": self.clock_source, "authority_reference": self.authority_reference,
                "signing_key_id": self.signing_key_id}

    def to_dict(self) -> dict[str, Any]:
        return self.payload() | {"signature": self.signature}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AuthorizationAttestation":
        return cls(value["attestation_id"], Action.from_dict(value["action"]),
                   int(value["sequence_number"]), value["authorization_timestamp"],
                   value["clock_source"], value["authority_reference"], value["signing_key_id"],
                   value.get("signature", ""))


@dataclass(frozen=True)
class Heartbeat:
    heartbeat_id: str
    sequence_number: int
    timestamp: str
    previous_sequence: int
    clock_source: str
    signing_key_id: str
    signature: str = ""

    def payload(self) -> dict[str, Any]:
        return {"heartbeat_id": self.heartbeat_id, "sequence_number": self.sequence_number,
                "timestamp": self.timestamp, "previous_sequence": self.previous_sequence,
                "clock_source": self.clock_source, "signing_key_id": self.signing_key_id}


@dataclass(frozen=True)
class EvidenceReference:
    evidence_id: str
    evidence_type: str
    observed_at: str | None
    freshness_status: VerificationStatus
    reference: str


@dataclass(frozen=True)
class GovernanceState:
    observer_identity: str
    reference_frame: str
    policy_version: str
    authority_reference: str
    delegation_reference: str
    authority_valid: bool | None
    external_state: VerificationStatus
    policy_allows_action: bool = True

    def continuity_payload(self) -> dict[str, Any]:
        return {"observer_identity": self.observer_identity, "reference_frame": self.reference_frame,
                "policy_version": self.policy_version, "authority_reference": self.authority_reference,
                "delegation_reference": self.delegation_reference,
                "external_state": self.external_state.value}

    def continuity_hash(self) -> str:
        return sha256_digest(self.continuity_payload())


@dataclass(frozen=True)
class RuntimeContext:
    governance_state: GovernanceState
    evidence: tuple[EvidenceReference, ...] = field(default_factory=tuple)
    expected_sequence: int | None = None
    attestation_available: bool = True
    baseline_continuity_hash: str | None = None


@dataclass(frozen=True)
class AdmissibilityResult:
    decision: Decision
    rule_id: str
    failure_reasons: tuple[str, ...] = ()
    attestation_status: VerificationStatus = VerificationStatus.UNKNOWN
    binding_status: VerificationStatus = VerificationStatus.UNKNOWN
    continuity_status: VerificationStatus = VerificationStatus.UNKNOWN


@dataclass(frozen=True)
class ReplayResult:
    replay_success: bool
    reconstructed_decision: Decision | None
    original_decision: Decision | None
    decision_matches: bool
    failure_reasons: tuple[str, ...]
    evidence_completeness_status: EvidenceCompleteness

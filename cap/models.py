from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from enum import Enum

class Decision(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    HOLD = "HOLD"
    REAUTHORIZE = "REAUTHORIZE"

class EvidenceStatus(Enum):
    FRESH = "FRESH"
    STALE = "STALE"
    MISSING = "MISSING"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    BINDING_MISMATCH = "BINDING_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    POLICY_MISMATCH = "POLICY_MISMATCH"
    AUTHORITY_REVOKED = "AUTHORITY_REVOKED"

@dataclass
class Action:
    action_type: str
    resource: str
    parameters: Dict[str, Any] = field(default_factory=dict)

    def canonical(self) -> bytes:
        from .canonicalize import canonicalize
        return canonicalize({
            "action_type": self.action_type,
            "resource": self.resource,
            "parameters": self.parameters
        })

@dataclass
class Attestation:
    action_type: str
    resource: str
    parameters_hash: str       # hex sha256 over the whole Action canonical bytes
    sequence_number: int
    authority_reference: str
    timestamp: int

@dataclass
class ContinuityScope:
    authority_reference: str
    sequence_namespace: str
    start_sequence: int
    expected_next: int
    heartbeat_interval_seconds: int
    policy_bundle_digest: str

@dataclass
class KeyResolution:
    key_id: str
    algorithm: str             # "Ed25519"
    rotation_policy: str       # e.g. "annual", free text
    issued_at: int
    expires_at: int

@dataclass
class TraceEnvelope:
    version: str
    decision: Decision
    action: Action
    attestation: Attestation
    evidence_status: List[EvidenceStatus]
    policy_version: str
    policy_bundle_digest: str
    authority_state: str
    continuity_valid: bool
    continuity_scope: ContinuityScope
    key_resolution: KeyResolution
    observer_id: str
    reference_frame: str
    runtime_context: Dict[str, Any]
    key_id: str
    signature: str = ""

    def to_signing_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict
        d = asdict(self)
        d["decision"] = self.decision.value
        d["evidence_status"] = [e.value for e in self.evidence_status]
        d.pop("signature", None)
        return d

    def canonical_bytes(self) -> bytes:
        from .canonicalize import canonicalize
        return canonicalize(self.to_signing_dict())

    def to_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict
        d = asdict(self)
        d["decision"] = self.decision.value
        d["evidence_status"] = [e.value for e in self.evidence_status]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TraceEnvelope":
        return cls(
            version=data["version"],
            decision=Decision(data["decision"]),
            action=Action(**data["action"]),
            attestation=Attestation(**data["attestation"]),
            evidence_status=[EvidenceStatus(e) for e in data["evidence_status"]],
            policy_version=data["policy_version"],
            policy_bundle_digest=data["policy_bundle_digest"],
            authority_state=data["authority_state"],
            continuity_valid=data["continuity_valid"],
            continuity_scope=ContinuityScope(**data["continuity_scope"]),
            key_resolution=KeyResolution(**data["key_resolution"]),
            observer_id=data["observer_id"],
            reference_frame=data["reference_frame"],
            runtime_context=data["runtime_context"],
            key_id=data["key_id"],
            signature=data.get("signature", ""),
        )
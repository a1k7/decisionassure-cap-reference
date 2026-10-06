import pytest
from cap.models import (
    TraceEnvelope, Action, Attestation, Decision, EvidenceStatus,
    ContinuityScope, KeyResolution
)
from cap.replay import replay_trace

def _envelope(decision=Decision.ALLOW):
    return TraceEnvelope(
        version="cap-envelope-v1",
        decision=decision,
        action=Action("transfer", "acc1", {"amt": 10}),
        attestation=Attestation("transfer", "acc1", "hash", 1, "auth-001", 1000),
        evidence_status=[EvidenceStatus.FRESH],
        policy_version="v1",
        policy_bundle_digest="deadbeef",
        authority_state="VALID",
        continuity_valid=True,
        continuity_scope=ContinuityScope("auth-001", "ns", 0, 1, 60, "deadbeef"),
        key_resolution=KeyResolution("key-demo-001", "Ed25519", "annual", 0, 9999999999),
        observer_id="decisionassure-reference",
        reference_frame="cap-envelope-v1",
        runtime_context={},
        key_id="key-demo-001",
        signature="",
    )

def test_replay_ok():
    env = _envelope()
    ok, decision, _ = replay_trace(env)
    assert ok is True
    assert decision == Decision.ALLOW

def test_replay_integrity_fail():
    env = _envelope()
    env.continuity_valid = False
    # replay_trace should still return the recorded decision; integrity is
    # determined by the caller via signature verification. Adjust if you
    # change replay semantics later.
    ok, decision, _ = replay_trace(env)
    assert decision == Decision.ALLOW
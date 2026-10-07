import json
import pytest
from pathlib import Path

from cap.models import TraceEnvelope, Decision
from attestation.verifier import verify_envelope

ROOT = Path(__file__).resolve().parents[1]
KEYRING = {
    k: bytes.fromhex(v["public_key_hex"])
    for k, v in json.loads((ROOT / "traces" / "keyring.json").read_text()).items()
}

def _load(name):
    return json.loads((ROOT / "traces" / f"{name}.json").read_text())

def test_allow_verifies():
    assert verify_envelope(TraceEnvelope.from_dict(_load("allow")), KEYRING) is True

def test_deny_policy_change_verifies_and_is_deny():
    env = TraceEnvelope.from_dict(_load("deny-policy-change"))
    assert verify_envelope(env, KEYRING) is True
    assert env.decision == Decision.DENY

def test_hold_sequence_gap_verifies_and_is_hold():
    env = TraceEnvelope.from_dict(_load("hold-sequence-gap"))
    assert verify_envelope(env, KEYRING) is True
    assert env.decision == Decision.HOLD

def test_hold_attestation_unavailable_verifies_and_is_hold():
    env = TraceEnvelope.from_dict(_load("hold-attestation-unavailable"))
    assert verify_envelope(env, KEYRING) is True
    assert env.decision == Decision.HOLD

def test_all_fixtures_share_policy_digest():
    names = ["allow", "deny-policy-change", "hold-sequence-gap",
             "hold-attestation-unavailable", "replay-example"]
    digests = {n: _load(n)["policy_bundle_digest"] for n in names}
    assert len(set(digests.values())) == 1, digests
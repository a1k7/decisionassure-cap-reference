import json, copy
import pytest
from pathlib import Path

from cap.models import TraceEnvelope
from attestation.verifier import verify_envelope

ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture
def keyring():
    data = json.loads((ROOT / "traces" / "keyring.json").read_text())
    return {k: bytes.fromhex(v["public_key_hex"]) for k, v in data.items()}

@pytest.fixture
def envelope_dict():
    return json.loads((ROOT / "traces" / "allow.json").read_text())

def _verify(d, keyring):
    return verify_envelope(TraceEnvelope.from_dict(d), keyring)

def test_unmodified_verifies(envelope_dict, keyring):
    assert _verify(envelope_dict, keyring) is True

def test_changed_decision_fails(envelope_dict, keyring):
    d = copy.deepcopy(envelope_dict); d["decision"] = "DENY"
    assert _verify(d, keyring) is False

def test_changed_policy_digest_fails(envelope_dict, keyring):
    d = copy.deepcopy(envelope_dict); d["policy_bundle_digest"] = "00" * 32
    assert _verify(d, keyring) is False

def test_changed_authority_state_fails(envelope_dict, keyring):
    d = copy.deepcopy(envelope_dict); d["authority_state"] = "REVOKED"
    assert _verify(d, keyring) is False

def test_changed_continuity_valid_fails(envelope_dict, keyring):
    d = copy.deepcopy(envelope_dict); d["continuity_valid"] = False
    assert _verify(d, keyring) is False

def test_changed_scope_expected_next_fails(envelope_dict, keyring):
    d = copy.deepcopy(envelope_dict); d["continuity_scope"]["expected_next"] = 9999
    assert _verify(d, keyring) is False

def test_changed_key_resolution_fails(envelope_dict, keyring):
    d = copy.deepcopy(envelope_dict); d["key_resolution"]["rotation_policy"] = "monthly"
    assert _verify(d, keyring) is False

def test_changed_action_parameters_fails(envelope_dict, keyring):
    d = copy.deepcopy(envelope_dict); d["action"]["parameters"]["amount"] = 999
    assert _verify(d, keyring) is False

def test_changed_attestation_sequence_fails(envelope_dict, keyring):
    d = copy.deepcopy(envelope_dict); d["attestation"]["sequence_number"] = 9999
    assert _verify(d, keyring) is False
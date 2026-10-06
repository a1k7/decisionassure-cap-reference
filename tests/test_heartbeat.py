import pytest
from attestation.heartbeat import build_heartbeat
from cap.models import Action, Decision, ContinuityScope, KeyResolution
from cap.verifier import Verifier
from cap.hash_utils import sha256_hex
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

@pytest.fixture
def keys():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return priv, pub

def test_heartbeat_builds(keys):
    heartbeat = build_heartbeat(42, 1000, "auth-001")
    assert heartbeat.action_type == "heartbeat"
    assert heartbeat.sequence_number == 42

def test_heartbeat_evaluates(keys):
    priv, pub = keys
    verifier = Verifier({"key-demo-001": pub})
    heartbeat = build_heartbeat(42, 1000, "auth-001")
    action = Action("heartbeat", "none", {})
    envelope, _ = verifier.evaluate(
        action, heartbeat, previous_sequence=41,
        runtime_context={"current_time": 1500, "policy_version": "v1"},
        policy_bundle_digest=sha256_hex(b"policy"),
        continuity_scope=ContinuityScope(
            "auth-001", "ns", 0, 42, 60, sha256_hex(b"policy")
        ),
        key_resolution=KeyResolution(
            "key-demo-001", "Ed25519", "annual", 0, 9999999999
        ),
        key_id="key-demo-001",
    )
    assert envelope.decision == Decision.ALLOW
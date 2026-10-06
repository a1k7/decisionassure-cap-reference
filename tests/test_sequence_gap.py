import pytest
from cap.models import Action, EvidenceStatus, Decision, ContinuityScope, KeyResolution
from cap.verifier import Verifier
from attestation.schema import build_attestation
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

def test_sequence_gap(keys):
    priv, pub = keys
    verifier = Verifier({"key-demo-001": pub})
    action = Action("transfer", "acc1", {"amt": 10})
    att = build_attestation(action, "auth-001", 5, 1000)
    envelope, _ = verifier.evaluate(
        action, att, previous_sequence=3,
        runtime_context={"current_time": 1500, "policy_version": "v1"},
        policy_bundle_digest=sha256_hex(b"policy"),
        continuity_scope=ContinuityScope(
            "auth-001", "ns", 0, 5, 60, sha256_hex(b"policy")
        ),
        key_resolution=KeyResolution(
            "key-demo-001", "Ed25519", "annual", 0, 9999999999
        ),
        key_id="key-demo-001",
    )
    assert envelope.decision == Decision.HOLD
    assert EvidenceStatus.SEQUENCE_GAP in envelope.evidence_status
    assert envelope.continuity_valid is False
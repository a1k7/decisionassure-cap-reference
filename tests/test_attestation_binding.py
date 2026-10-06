import pytest
from cap.models import Action, EvidenceStatus
from cap.verifier import Verifier
from attestation.schema import build_attestation, build_envelope, sign_envelope
from cap.models import Decision, ContinuityScope, KeyResolution
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

def test_binding_match(keys):
    priv, pub = keys
    verifier = Verifier({"key-demo-001": pub})
    action = Action("transfer", "acc1", {"amt": 10})
    att = build_attestation(action, "auth-001", 1, 1000)
    envelope, _ = verifier.evaluate(
        action, att, previous_sequence=None,
        runtime_context={"current_time": 1500, "policy_version": "v1"},
        policy_bundle_digest=sha256_hex(b"policy"),
        continuity_scope=ContinuityScope(
            "auth-001", "ns", 0, 1, 60, sha256_hex(b"policy")
        ),
        key_resolution=KeyResolution(
            "key-demo-001", "Ed25519", "annual", 0, 9999999999
        ),
        key_id="key-demo-001",
    )
    assert envelope.decision == Decision.ALLOW
    assert EvidenceStatus.BINDING_MISMATCH not in envelope.evidence_status

def test_binding_mismatch(keys):
    priv, pub = keys
    verifier = Verifier({"key-demo-001": pub})
    action1 = Action("transfer", "acc1", {"amt": 10})
    action2 = Action("transfer", "acc1", {"amt": 20})
    att = build_attestation(action1, "auth-001", 1, 1000)
    envelope, _ = verifier.evaluate(
        action2, att, previous_sequence=None,
        runtime_context={"current_time": 1500, "policy_version": "v1"},
        policy_bundle_digest=sha256_hex(b"policy"),
        continuity_scope=ContinuityScope(
            "auth-001", "ns", 0, 1, 60, sha256_hex(b"policy")
        ),
        key_resolution=KeyResolution(
            "key-demo-001", "Ed25519", "annual", 0, 9999999999
        ),
        key_id="key-demo-001",
    )
    assert envelope.decision == Decision.DENY
    assert EvidenceStatus.BINDING_MISMATCH in envelope.evidence_status
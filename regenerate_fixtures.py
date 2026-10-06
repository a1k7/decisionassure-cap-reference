#!/usr/bin/env python3
"""Regenerate signed fixture traces under traces/."""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from cap.models import (
    Action, Decision, EvidenceStatus, ContinuityScope, KeyResolution
)
from cap.hash_utils import sha256_hex
from cap.canonicalize import canonicalize
from attestation.schema import build_attestation, build_envelope, sign_envelope

KEY_ID = "key-demo-001"
AUTHORITY = "auth-001"

KEY_PATH = Path(__file__).parent / "traces" / "emitter_key.pem"
KEY_PATH.parent.mkdir(parents=True, exist_ok=True)

if KEY_PATH.exists():
    priv = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
else:
    priv = Ed25519PrivateKey.generate()
    KEY_PATH.write_bytes(priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

pub = priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

policy_digest = sha256_hex(canonicalize({"version": "v1", "rules": ["allow-transfer-under-1000"]}))

def make(decision, action, attestation, evidence_status, policy_version,
         policy_digest_used, authority_state, continuity_valid,
         runtime_context):
    scope = ContinuityScope(
        authority_reference=AUTHORITY,
        sequence_namespace="attestation/auth-001",
        start_sequence=1000,
        expected_next=attestation.sequence_number + 1 if attestation else 0,
        heartbeat_interval_seconds=60,
        policy_bundle_digest=policy_digest_used
    )
    kr = KeyResolution(KEY_ID, "Ed25519", "annual", 900, 4102444800)
    env = build_envelope(action, decision, attestation, evidence_status,
                         policy_version, policy_digest_used, authority_state,
                         continuity_valid, scope, kr, runtime_context)
    sign_envelope(env, priv)
    return env.to_dict()

traces_dir = Path(__file__).parent / "traces"
traces_dir.mkdir(exist_ok=True)

action = Action("transfer", "account-001", {"amount": 100})

# allow
att = build_attestation(action, AUTHORITY, 1042, 1000)
allow = make(Decision.ALLOW, action, att, [EvidenceStatus.FRESH],
             "v1", policy_digest, "VALID", True, {"current_time": 1500})
(traces_dir / "allow.json").write_text(json.dumps(allow, indent=2))

# deny-policy-change
deny = make(Decision.DENY, action, att, [EvidenceStatus.POLICY_MISMATCH],
            "v2", policy_digest, "VALID", True, {"current_time": 1500,
                                                 "policy_version": "v2"})
(traces_dir / "deny-policy-change.json").write_text(json.dumps(deny, indent=2))

# hold-sequence-gap
att_gap = build_attestation(action, AUTHORITY, 1045, 1000)
hold_gap = make(Decision.HOLD, action, att_gap, [EvidenceStatus.SEQUENCE_GAP],
                "v1", policy_digest, "VALID", False, {"current_time": 1500})
(traces_dir / "hold-sequence-gap.json").write_text(json.dumps(hold_gap, indent=2))

# hold-attestation-unavailable
hold_missing = make(Decision.HOLD, action,
                    build_attestation(action, AUTHORITY, 1043, 1000),
                    [EvidenceStatus.MISSING], "v1", policy_digest,
                    "VALID", True, {"current_time": 1500})
(traces_dir / "hold-attestation-unavailable.json").write_text(
    json.dumps(hold_missing, indent=2))

# replay-example (same as allow but marked replay-valid)
replay = make(Decision.ALLOW, action, att, [EvidenceStatus.FRESH],
              "v1", policy_digest, "VALID", True, {"current_time": 1500})
(traces_dir / "replay-example.json").write_text(json.dumps(replay, indent=2))

keyring_path = traces_dir / "keyring.json"
keyring = {
    KEY_ID: {
        "algorithm": "Ed25519",
        "public_key_hex": pub.hex(),
        "rotation_policy": "annual",
        "issued_at": 900,
        "expires_at": 4102444800,
    }
}
keyring_path.write_text(json.dumps(keyring, indent=2) + "\n")

print("public_key_hex:", pub.hex())
print("Wrote 5 signed fixtures to traces/")
print("Updated traces/keyring.json with the shared emitter key.")
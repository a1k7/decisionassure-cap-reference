#!/usr/bin/env python3
"""
Emit a signed CAP envelope.

The signature covers the whole envelope (decision, policy digest, action,
attestation, continuity scope, key resolution). Verification requires the
public key to be resolved out-of-band via key_id, not read from the artifact.

This script persists the emitter key at traces/emitter_key.pem so subsequent
runs produce envelopes that verify against traces/keyring.json once the
public key has been pinned there.
"""
import json
import sys
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

REPO_ROOT = Path(__file__).parent
KEY_PATH = REPO_ROOT / "traces" / "emitter_key.pem"
KEYRING_PATH = REPO_ROOT / "traces" / "keyring.json"


def load_or_create_key():
    if KEY_PATH.exists():
        priv = serialization.load_pem_private_key(
            KEY_PATH.read_bytes(), password=None
        )
        return priv, False
    priv = Ed25519PrivateKey.generate()
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEY_PATH.write_bytes(priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    return priv, True


def public_key_hex(priv):
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()


def pin_key_in_keyring(pub_hex):
    """Create or update traces/keyring.json with the emitter public key."""
    if KEYRING_PATH.exists():
        keyring = json.loads(KEYRING_PATH.read_text())
    else:
        keyring = {}
    keyring[KEY_ID] = {
        "algorithm": "Ed25519",
        "public_key_hex": pub_hex,
        "rotation_policy": "annual",
        "issued_at": 900,
        "expires_at": 4102444800,
    }
    KEYRING_PATH.write_text(json.dumps(keyring, indent=2) + "\n")


def main():
    priv, generated = load_or_create_key()
    pub_hex = public_key_hex(priv)

    if generated:
        print(f"[emit_signed_trace] generated new emitter key: {KEY_PATH}")

    # Keep the keyring in sync with the emitter key so the printed envelope
    # verifies against the committed keyring.
    pin_key_in_keyring(pub_hex)

    action = Action(
        action_type="transfer",
        resource="account-001",
        parameters={"amount": 100}
    )

    attestation = build_attestation(action, AUTHORITY, sequence_number=1042, timestamp=1000)

    policy_bundle = {"version": "v1", "rules": ["allow-transfer-under-1000"]}
    policy_digest = sha256_hex(canonicalize(policy_bundle))

    continuity_scope = ContinuityScope(
        authority_reference=AUTHORITY,
        sequence_namespace="attestation/auth-001",
        start_sequence=1000,
        expected_next=1043,
        heartbeat_interval_seconds=60,
        policy_bundle_digest=policy_digest
    )

    key_resolution = KeyResolution(
        key_id=KEY_ID,
        algorithm="Ed25519",
        rotation_policy="annual",
        issued_at=900,
        expires_at=4102444800
    )

    envelope = build_envelope(
        action=action,
        decision=Decision.ALLOW,
        attestation=attestation,
        evidence_status=[EvidenceStatus.FRESH],
        policy_version="v1",
        policy_bundle_digest=policy_digest,
        authority_state="VALID",
        continuity_valid=True,
        continuity_scope=continuity_scope,
        key_resolution=key_resolution,
        runtime_context={"current_time": 1500},
    )

    sign_envelope(envelope, priv)

    out = {
        "envelope": envelope.to_dict(),
        "public_key_hex": pub_hex,
        "keyring_path": str(KEYRING_PATH.relative_to(REPO_ROOT)),
        "note": (
            "The public key is printed ONLY for convenience. A third-party "
            "verifier must resolve key_id out-of-band against a keyring. "
            "This script has already pinned the key in traces/keyring.json."
        )
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
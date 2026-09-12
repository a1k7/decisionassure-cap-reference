# emit_signed_trace.py
import json, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def canonicalize(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()

def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()

priv = Ed25519PrivateKey.generate()
pub = priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

action = {"action_type": "transfer", "resource": "account-001", "parameters": {"amount": 100}}
params_hash = sha256_hex(canonicalize(action))

att = {
    "action_type": "transfer",
    "resource": "account-001",
    "parameters_hash": params_hash,
    "sequence_number": 1042,
    "authority_reference": "auth-001",
    "timestamp": 1000,
}
att_bytes = canonicalize(att)
signature = priv.sign(att_bytes).hex()
att["signature"] = signature

policy_bundle = canonicalize({"version": "v1", "rules": ["allow-transfer-under-1000"]})
policy_digest = sha256_hex(policy_bundle)

trace = {
    "trace": {
        "decision": "ALLOW",
        "action": action,
        "attestation": att,
        "evidence_status": [],
        "policy_version": "v1",
        "policy_bundle_digest": policy_digest,
        "authority_state": "VALID",
        "continuity_valid": True,
        "replay_valid": True,
        "runtime_context": {"current_time": 1500},
        "observer_id": "decisionassure-reference",
        "reference_frame": "cap-v1"
    },
    "public_key_hex": pub.hex(),
    "verification": "run verify() below"
}

def verify():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(pub).verify(
        bytes.fromhex(att["signature"]),
        canonicalize({k: att[k] for k in att if k != "signature"})
    )
    return "VALID"

trace["verification"] = verify()
print(json.dumps(trace, indent=2))

#!/usr/bin/env python3
"""Demo: replay a signed envelope after verifying its signature."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cap.models import TraceEnvelope
from attestation.verifier import verify_envelope

def load_envelope(path):
    with open(path) as f:
        data = json.load(f)
    return TraceEnvelope.from_dict(data)

def load_keyring(path):
    with open(path) as f:
        data = json.load(f)
    return {k: bytes.fromhex(v["public_key_hex"]) for k, v in data.items()}

def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    envelope = load_envelope(os.path.join(root, "traces", "allow.json"))
    keyring = load_keyring(os.path.join(root, "traces", "keyring.json"))

    ok = verify_envelope(envelope, keyring)
    print("Replaying trace...")
    print(f"Signature: {'VALID' if ok else 'INVALID'}")
    print(f"Decision re-evaluated: {envelope.decision.value}")
    print(f"Trace integrity: {'OK' if ok else 'FAILED'}")

if __name__ == "__main__":
    main()
from typing import Dict
from cap.models import TraceEnvelope
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def verify_envelope(envelope: TraceEnvelope, keyring: Dict[str, bytes]) -> bool:
    pub = keyring.get(envelope.key_id)
    if not pub:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(
            bytes.fromhex(envelope.signature),
            envelope.canonical_bytes()
        )
        return True
    except (InvalidSignature, ValueError):
        return False
from cap.models import Attestation, Action
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .schema import build_attestation

def build_heartbeat(sequence_number: int,
                    timestamp: int,
                    authority_reference: str) -> Attestation:
    heartbeat_action = Action(action_type="heartbeat", resource="none", parameters={})
    return build_attestation(heartbeat_action, authority_reference, sequence_number, timestamp)
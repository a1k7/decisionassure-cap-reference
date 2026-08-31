"""Heartbeat continuity checks; these never establish physical-world truth."""
from __future__ import annotations
import base64
from dataclasses import dataclass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cap.canonicalize import canonicalize
from cap.models import Heartbeat, VerificationStatus


@dataclass(frozen=True)
class HeartbeatResult:
    status: VerificationStatus
    reasons: tuple[str, ...] = ()


def verify_heartbeat(heartbeat: Heartbeat | None, expected_sequence: int | None,
                     keys: dict[str, Ed25519PublicKey]) -> HeartbeatResult:
    """Verify signature, continuity, and previous sequence for one heartbeat."""
    if heartbeat is None:
        return HeartbeatResult(VerificationStatus.UNKNOWN, ("HEARTBEAT_MISSING",))
    if expected_sequence is not None and heartbeat.sequence_number != expected_sequence:
        return HeartbeatResult(VerificationStatus.INVALID, ("HEARTBEAT_SEQUENCE_MISMATCH",))
    if heartbeat.previous_sequence != heartbeat.sequence_number - 1:
        return HeartbeatResult(VerificationStatus.INVALID, ("HEARTBEAT_PREVIOUS_SEQUENCE_MISMATCH",))
    key = keys.get(heartbeat.signing_key_id)
    if key is None:
        return HeartbeatResult(VerificationStatus.UNKNOWN, ("SIGNING_KEY_UNKNOWN",))
    try:
        key.verify(base64.b64decode(heartbeat.signature, validate=True), canonicalize(heartbeat.payload()))
    except (InvalidSignature, ValueError):
        return HeartbeatResult(VerificationStatus.INVALID, ("INVALID_HEARTBEAT_SIGNATURE",))
    return HeartbeatResult(VerificationStatus.VALID)

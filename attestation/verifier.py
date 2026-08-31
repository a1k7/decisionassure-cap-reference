"""Cryptographic and structural attestation verification."""
from __future__ import annotations
import base64
from dataclasses import dataclass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cap.canonicalize import canonicalize
from cap.hash_utils import sha256_digest
from cap.models import Action, AuthorizationAttestation, VerificationStatus


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    reasons: tuple[str, ...] = ()


def verify_attestation(attestation: AuthorizationAttestation, keys: dict[str, Ed25519PublicKey]) -> VerificationResult:
    """Verify known-key signature plus mandatory structural fields.

    VALID proves only payload integrity and association with the configured key.
    It does not establish that the signer is trustworthy or truthful.
    """
    required = (attestation.authorization_timestamp, attestation.clock_source, attestation.authority_reference,
                attestation.signing_key_id, attestation.signature)
    if not all(required):
        return VerificationResult(VerificationStatus.INVALID, ("ATTESTATION_REQUIRED_FIELD_MISSING",))
    if attestation.action.parameters_hash != sha256_digest(attestation.action.parameters):
        return VerificationResult(VerificationStatus.INVALID, ("ACTION_PARAMETERS_HASH_MISMATCH",))
    key = keys.get(attestation.signing_key_id)
    if key is None:
        return VerificationResult(VerificationStatus.UNKNOWN, ("SIGNING_KEY_UNKNOWN",))
    try:
        key.verify(base64.b64decode(attestation.signature, validate=True), canonicalize(attestation.payload()))
    except (InvalidSignature, ValueError):
        return VerificationResult(VerificationStatus.INVALID, ("INVALID_SIGNATURE",))
    return VerificationResult(VerificationStatus.VALID)


def verify_action_binding(attestation: AuthorizationAttestation, execution_action: Action) -> VerificationResult:
    """Verify that action type, resource, and canonical parameter hash are identical."""
    if attestation.action.binding_payload() != execution_action.binding_payload():
        return VerificationResult(VerificationStatus.INVALID, ("ACTION_BINDING_MISMATCH",))
    return VerificationResult(VerificationStatus.VALID)

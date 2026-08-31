"""Ed25519 signing helpers. Keys are always supplied/generated in memory."""
from __future__ import annotations
import base64
from dataclasses import replace
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cap.canonicalize import canonicalize
from cap.models import AuthorizationAttestation, Heartbeat


def generate_demo_key() -> Ed25519PrivateKey:
    """Generate an ephemeral Ed25519 key for a local demonstration."""
    return Ed25519PrivateKey.generate()


def public_key_bytes(key: Ed25519PrivateKey) -> bytes:
    """Return raw public-key bytes for in-memory verifier configuration."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def sign_attestation(attestation: AuthorizationAttestation, key: Ed25519PrivateKey) -> AuthorizationAttestation:
    """Return a copy signed over its canonical payload."""
    return replace(attestation, signature=base64.b64encode(key.sign(canonicalize(attestation.payload()))).decode())


def sign_heartbeat(heartbeat: Heartbeat, key: Ed25519PrivateKey) -> Heartbeat:
    """Return a heartbeat signed over its canonical payload."""
    return replace(heartbeat, signature=base64.b64encode(key.sign(canonicalize(heartbeat.payload()))).decode())


def load_public_key(raw: bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from raw bytes."""
    return Ed25519PublicKey.from_public_bytes(raw)

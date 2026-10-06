"""Hash utilities."""
import hashlib

def sha256(data: bytes) -> bytes:
    """Return the SHA-256 digest of data as raw bytes."""
    return hashlib.sha256(data).digest()

def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 digest of data as a lowercase hex string."""
    return hashlib.sha256(data).hexdigest()
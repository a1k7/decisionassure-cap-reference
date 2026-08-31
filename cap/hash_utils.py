"""Hash helpers."""
from __future__ import annotations
import hashlib
from typing import Any
from .canonicalize import canonicalize


def sha256_digest(obj: Any) -> str:
    """Return a lower-case SHA-256 hex digest of canonical JSON input."""
    return hashlib.sha256(canonicalize(obj)).hexdigest()

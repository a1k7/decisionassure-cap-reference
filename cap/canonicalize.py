"""Deterministic JSON serialization used by CAP hashes and signatures."""
from __future__ import annotations

import dataclasses
import enum
import json
from typing import Any


def _normalise(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return _normalise(dataclasses.asdict(value))
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _normalise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    return value


def canonicalize(obj: Any) -> bytes:
    """Return canonical UTF-8 JSON bytes for JSON-compatible input."""
    return json.dumps(_normalise(obj), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")

"""
Minimal RFC 8785 (JCS) canonicalizer covering the subset used by CAP.
"""
import json
import math

def _canonical_number(n):
    if isinstance(n, bool):
        return "true" if n else "false"
    if isinstance(n, int):
        return str(n)
    if isinstance(n, float):
        if math.isnan(n) or math.isinf(n):
            raise ValueError("JCS does not permit NaN or Infinity")
        if n == int(n):
            return str(int(n))
        return repr(n)
    raise TypeError(f"Unsupported number type: {type(n)}")

def _serialize(obj) -> str:
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return _canonical_number(obj)
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_serialize(x) for x in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: kv[0])
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + _serialize(v)
            for k, v in items
        ) + "}"
    raise TypeError(f"Unsupported type: {type(obj)}")

def canonicalize(obj) -> bytes:
    return _serialize(obj).encode("utf-8")
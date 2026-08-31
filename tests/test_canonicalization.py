from cap.canonicalize import canonicalize
from cap.hash_utils import sha256_digest

def test_canonical_json_is_order_independent():
    assert canonicalize({"b": 1, "a": [2]}) == canonicalize({"a": [2], "b": 1})
    assert sha256_digest({"b": 1, "a": 2}) == sha256_digest({"a": 2, "b": 1})

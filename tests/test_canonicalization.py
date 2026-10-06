import pytest
from cap.canonicalize import canonicalize

def test_canonicalize_sorts_keys():
    obj = {"b": 1, "a": 2}
    assert canonicalize(obj) == b'{"a":2,"b":1}'

def test_canonicalize_nested():
    obj = {"x": {"y": 1, "z": 2}, "a": 3}
    assert canonicalize(obj) == b'{"a":3,"x":{"y":1,"z":2}}'

def test_canonicalize_non_ascii_unescaped():
    # JCS keeps printable non-ASCII characters unescaped.
    obj = {"s": "é"}
    assert canonicalize(obj) == '{"s":"é"}'.encode("utf-8")

def test_canonicalize_integer_float_equivalence():
    # JCS: 1.0 must be written as 1
    assert canonicalize({"n": 1.0}) == b'{"n":1}'
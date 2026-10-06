import pytest
from cap.continuity import check_continuity

def test_continuity_ok():
    ok, gap = check_continuity(1043, 1042)
    assert ok is True
    assert gap is False

def test_continuity_gap():
    ok, gap = check_continuity(1045, 1042)
    assert ok is False
    assert gap is True

def test_no_previous():
    ok, gap = check_continuity(100, None)
    assert ok is True
    assert gap is False
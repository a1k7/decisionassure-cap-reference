from cap.continuity import check_continuity

def test_drop_in_middle_is_detected():
    ok, gap = check_continuity(1045, 1043)
    assert ok is False and gap is True

def test_drop_at_end_is_not_detectable_by_local_check():
    """
    Known unsupported. A dropped final event is not detectable without an
    anchored heartbeat or a completeness proof over the declared scope.
    """
    ok, gap = check_continuity(1043, 1042)
    assert ok is True and gap is False

def test_drop_at_beginning_is_not_detectable_by_local_check():
    """
    Known unsupported. A beginning-of-window drop requires the anchored
    continuity_scope (start_sequence / expected_next) to be evaluated, not
    only the local previous-sequence check.
    """
    ok, gap = check_continuity(1043, None)
    assert ok is True and gap is False
"""Sequence continuity checks for CAP."""
from typing import Optional, Tuple

def check_continuity(current_seq: int, previous_seq: Optional[int]) -> Tuple[bool, bool]:
    """
    Check that the sequence number is exactly previous_seq + 1.

    Returns (continuity_ok, gap_detected).
    If previous_seq is None, continuity is assumed and no gap is reported.
    """
    if previous_seq is None:
        return True, False
    if current_seq == previous_seq + 1:
        return True, False
    return False, True
"""Monotonic sequence verification."""
from __future__ import annotations
from dataclasses import dataclass
from cap.models import VerificationStatus


@dataclass(frozen=True)
class SequenceResult:
    status: VerificationStatus
    expected: int | None
    observed: int
    reasons: tuple[str, ...] = ()


def verify_sequence(expected: int | None, observed: int) -> SequenceResult:
    """Check an observed sequence against the exact expected next value."""
    if expected is None:
        return SequenceResult(VerificationStatus.VALID, None, observed)
    if observed == expected:
        return SequenceResult(VerificationStatus.VALID, expected, observed)
    reason = "ATTESTATION_SEQUENCE_GAP" if observed > expected else "ATTESTATION_SEQUENCE_OUT_OF_ORDER"
    return SequenceResult(VerificationStatus.INVALID, expected, observed, (reason,))

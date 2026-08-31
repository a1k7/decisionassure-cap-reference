"""Runtime governance-continuity evaluation."""
from __future__ import annotations
from dataclasses import dataclass
from .models import RuntimeContext, VerificationStatus


@dataclass(frozen=True)
class ContinuityResult:
    status: VerificationStatus
    current_hash: str | None
    reasons: tuple[str, ...] = ()


def verify_continuity(context: RuntimeContext) -> ContinuityResult:
    """Compare declared governance state with the authorization-time baseline."""
    state = context.governance_state
    if state.external_state is VerificationStatus.UNKNOWN:
        return ContinuityResult(VerificationStatus.UNKNOWN, None, ("EXTERNAL_STATE_UNKNOWN",))
    current = state.continuity_hash()
    if context.baseline_continuity_hash is None:
        return ContinuityResult(VerificationStatus.UNKNOWN, current, ("CONTINUITY_BASELINE_UNAVAILABLE",))
    if current != context.baseline_continuity_hash:
        return ContinuityResult(VerificationStatus.INVALID, current, ("CONTINUITY_HASH_MISMATCH",))
    return ContinuityResult(VerificationStatus.VALID, current)

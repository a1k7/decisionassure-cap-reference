"""Replay of a signed CAP envelope."""
from .models import TraceEnvelope, Decision
from typing import Tuple

def replay_trace(envelope: TraceEnvelope) -> Tuple[bool, Decision, str]:
    """
    Replay a signed envelope.

    The caller is responsible for verifying the envelope signature against an
    external keyring before calling this function. Replay itself only checks
    structural integrity and returns the recorded decision.
    """
    if not envelope.action or not envelope.decision:
        return False, Decision.DENY, "Incomplete envelope."
    return True, envelope.decision, "Replay successful."
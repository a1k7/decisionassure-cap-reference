from cap.continuity import verify_continuity
from cap.models import GovernanceState, RuntimeContext, VerificationStatus

def state(policy="1"):
    return GovernanceState("observer", "frame", policy, "authority", "delegation", True, VerificationStatus.VALID)

def test_valid_and_changed_continuity():
    original = state(); assert verify_continuity(RuntimeContext(original, baseline_continuity_hash=original.continuity_hash())).status is VerificationStatus.VALID
    assert verify_continuity(RuntimeContext(state("2"), baseline_continuity_hash=original.continuity_hash())).reasons == ("CONTINUITY_HASH_MISMATCH",)

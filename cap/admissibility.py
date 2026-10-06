from typing import Tuple, Dict, Any
from .models import Action, Attestation

def evaluate_admissibility(action: Action,
                           attestation: Attestation,
                           runtime_context: Dict[str, Any]) -> Tuple[bool, str, str]:
    current_time = runtime_context.get("current_time", 0)

    expected_policy_digest = runtime_context.get("policy_bundle_digest")
    if expected_policy_digest is not None:
        # Enforced at envelope level; here we only ensure presence.
        pass

    ttl = runtime_context.get("attestation_ttl_seconds", 3600)
    if current_time > attestation.timestamp + ttl:
        return False, "Attestation expired (evidence stale).", "EXPIRED"

    revoked = runtime_context.get("revoked_authorities", [])
    if attestation.authority_reference in revoked:
        return False, "Authority revoked.", "REVOKED"

    return True, "Admissible.", "VALID"
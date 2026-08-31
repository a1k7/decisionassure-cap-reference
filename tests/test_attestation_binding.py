from dataclasses import replace
from attestation.schema import generate_demo_key, load_public_key, public_key_bytes, sign_attestation
from attestation.verifier import verify_action_binding, verify_attestation
from cap.models import Action, AuthorizationAttestation, VerificationStatus
from cap.admissibility import evaluate_admissibility
from cap.models import Decision, EvidenceReference, GovernanceState, RuntimeContext

def signed():
    key = generate_demo_key(); action = Action("transfer", "r1", {"amount": 1})
    att = sign_attestation(AuthorizationAttestation("a", action, 1, "2026-01-01T00:00:00Z", "clock", "auth", "key"), key)
    return att, action, {"key": load_public_key(public_key_bytes(key))}

def test_signature_valid_modified_and_wrong_key():
    att, action, keys = signed()
    assert verify_attestation(att, keys).status is VerificationStatus.VALID
    assert verify_attestation(replace(att, authority_reference="other"), keys).status is VerificationStatus.INVALID
    assert verify_attestation(att, {"key": generate_demo_key().public_key()}).status is VerificationStatus.INVALID

def test_action_binding_exactness():
    att, action, _ = signed()
    assert verify_action_binding(att, action).status is VerificationStatus.VALID
    for changed in (Action("transfer", "r1", {"amount": 2}), Action("transfer", "r2", {"amount": 1}), Action("delete", "r1", {"amount": 1})):
        assert verify_action_binding(att, changed).reasons == ("ACTION_BINDING_MISMATCH",)

def test_admissibility_reference_decisions():
    key = generate_demo_key(); action = Action("transfer", "r", {"amount": 1})
    att = sign_attestation(AuthorizationAttestation("a", action, 1, "2026-01-01T00:00:00Z", "c", "auth", "k"), key)
    state = GovernanceState("o", "f", "1", "auth", "d", True, VerificationStatus.VALID)
    context = RuntimeContext(state, (EvidenceReference("e", "x", "now", VerificationStatus.VALID, "ref"),), 1, True, state.continuity_hash())
    keys = {"k": load_public_key(public_key_bytes(key))}
    assert evaluate_admissibility(att, action, context, keys).decision is Decision.ALLOW
    assert evaluate_admissibility(att, action, replace(context, expected_sequence=2), keys).decision is Decision.HOLD
    assert evaluate_admissibility(None, action, replace(context, attestation_available=False), keys).decision is Decision.HOLD
    assert evaluate_admissibility(replace(att, signature="bad"), action, context, keys).decision is Decision.DENY
    assert evaluate_admissibility(att, Action("transfer", "r", {"amount": 2}), context, keys).decision is Decision.DENY
    changed = replace(context, governance_state=GovernanceState("o", "f", "2", "auth", "d", True, VerificationStatus.VALID))
    assert evaluate_admissibility(att, action, changed, keys).decision is Decision.REAUTHORIZE

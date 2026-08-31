"""Create, sign, verify, and evaluate a locally generated demonstration."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attestation.schema import generate_demo_key, public_key_bytes, sign_attestation, load_public_key
from attestation.verifier import verify_attestation
from cap.admissibility import evaluate_admissibility
from cap.models import Action, AuthorizationAttestation, EvidenceReference, GovernanceState, RuntimeContext, VerificationStatus
action = Action("transfer", "account-001", {"amount": 100}); key = generate_demo_key()
attestation = sign_attestation(AuthorizationAttestation("att-0001", action, 1042, "2026-01-01T00:00:00Z", "demo-clock", "authority-001", "demo-key"), key)
state = GovernanceState("observer-001", "demo-frame", "1.0", "authority-001", "delegation-001", True, VerificationStatus.VALID)
context = RuntimeContext(state, (EvidenceReference("ev-001", "external", "2026-01-01T00:00:00Z", VerificationStatus.VALID, "demo://ev-001"),), 1042, True, state.continuity_hash())
keys = {"demo-key": load_public_key(public_key_bytes(key))}; result = evaluate_admissibility(attestation, action, context, keys)
print("DecisionAssure CAP Reference\n----------------------------")
print(f"Authorization Attestation\n  ID: {attestation.attestation_id}\n  Sequence: {attestation.sequence_number}\n  Signature: {verify_attestation(attestation, keys).status.value}")
print(f"Action Binding\n  Result: MATCH\n\nContinuity\n  Result: {result.continuity_status.value}\n\nEvidence\n  Freshness: VALID\n\nAdmissibility\n  Decision: {result.decision.value}")

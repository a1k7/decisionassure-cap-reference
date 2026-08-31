"""Show denial when a bound parameter is substituted at execution."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attestation.schema import generate_demo_key, sign_attestation
from attestation.verifier import verify_action_binding
from cap.models import Action, AuthorizationAttestation
key = generate_demo_key(); authorized = Action("transfer", "account-001", {"amount": 100}); execution = Action("transfer", "account-001", {"amount": 1000})
att = sign_attestation(AuthorizationAttestation("att-0002", authorized, 1042, "2026-01-01T00:00:00Z", "demo-clock", "authority-001", "demo-key"), key)
r = verify_action_binding(att, execution)
print("DecisionAssure CAP Reference\n----------------------------")
print("Action Binding\n  Authorized: transfer account-001 amount=100\n  Execution: transfer account-001 amount=1000")
print(f"  Result: {r.reasons[0]}\n\nAdmissibility\n  Decision: DENY")

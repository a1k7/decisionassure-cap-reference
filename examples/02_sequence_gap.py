"""Show a sequence gap produces HOLD."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attestation.sequence import verify_sequence
r = verify_sequence(1043, 1044)
print("DecisionAssure CAP Reference\n----------------------------")
print(f"Sequence Continuity\n  Expected: {r.expected}\n  Observed: {r.observed}\n  Result: GAP\n\nAdmissibility\n  Decision: HOLD\n  Reason: {r.reasons[0]}")

"""Replay the complete static demonstration trace."""
from pathlib import Path
import json, sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cap.replay import replay_trace
trace = json.loads((Path(__file__).resolve().parents[1] / "traces" / "replay-example.json").read_text()); r = replay_trace(trace)
print("DecisionAssure CAP Reference\n----------------------------")
print(f"Replay\n  Original decision: {r.original_decision.value}\n  Reconstructed decision: {r.reconstructed_decision.value}\n  Decision match: {str(r.decision_matches).lower()}\n  Evidence completeness: {r.evidence_completeness_status.value}")

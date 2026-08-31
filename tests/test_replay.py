import json
from pathlib import Path
from cap.models import Decision, EvidenceCompleteness
from cap.replay import replay_trace

ROOT = Path(__file__).resolve().parents[1]
def load(name): return json.loads((ROOT / "traces" / name).read_text())
def test_replay_matches_and_detects_tampering():
    r = replay_trace(load("replay-example.json")); assert r.replay_success and r.decision_matches and r.reconstructed_decision is Decision.ALLOW
    trace = load("replay-example.json"); trace["decision"] = "DENY"; assert not replay_trace(trace).replay_success
def test_incomplete_evidence_is_represented():
    r = replay_trace(load("hold-attestation-unavailable.json")); assert r.evidence_completeness_status is EvidenceCompleteness.PARTIAL

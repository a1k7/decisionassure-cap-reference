# DecisionAssure CAP Reference

## Continuous Admissibility Protocol

**Status: reference implementation / proposed technical validation.** This small, local-only repository demonstrates consuming independently produced authorization attestations at an execution boundary. It is designed for inspection, reproducibility, and explicit failure semantics—not production deployment.

```
Physical / External Trust Domain
        |  Independent Attestation
        v
DecisionAssure Evidence Layer -> Continuity Verification -> Action Binding
        |                                              |
        v                                              v
Runtime Admissibility -> ALLOW / HOLD / DENY / REAUTHORIZE -> Commit / Execution -> Replay
```

### Problem and model

An earlier approval may no longer be admissible at commit time: authority, policy, evidence, and the requested action can change. CAP evaluates authority, evidence, context, action, and continuity immediately at the execution boundary. An attestation binds its action type, resource, and canonical parameters hash; it cannot authorize a substituted action.

### Outcomes

- `ALLOW`: valid attestation, binding, authority, freshness, sequence, and continuity.
- `HOLD`: material evidence/attestation is unavailable or sequence continuity has a gap.
- `DENY`: signature, action binding, authority, or policy is explicitly invalid.
- `REAUTHORIZE`: otherwise-valid governance state materially changed, requiring fresh authorization.

### External attestation, sequence, and heartbeat

Ed25519 signing is a local cryptographic demonstration. The verifier distinguishes `VALID`, `INVALID`, and `UNKNOWN`; a valid signature associates an artifact with a configured key, not a trustworthy signer. Monotonic sequences expose gaps. Heartbeats represent continuity of the implemented channel, not an authorization event or physical-world truth.

### Replay

Fixtures retain declared evidence, policy and authority conditions, action, continuity condition, rule version, and integrity digest. Replay reconstructs only from those inputs and reports evidence completeness. Static trace fixtures are explicitly deterministic demonstration artifacts and contain no fake production signatures.

### Known limitations

> This repository is a reference implementation. It does not establish hardware-rooted trust. A cryptographic signature proves artifact integrity and key association; it does not by itself prove that the signer is truthful or uncompromised. A heartbeat proves continuity of the attestation channel as represented by the implementation; it does not prove physical-world truth. Infrastructure controlled by a cloud or hosting provider remains an explicit trust boundary. The reference implementation intentionally exposes these limitations.

It does not provide TEEs, remote hardware attestation, secure cloud infrastructure, physical-world truth, or universal governance completeness.

### Quick start

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
python examples/01_authorize.py
python examples/02_sequence_gap.py
python examples/03_attestation_binding.py
python examples/04_replay.py
python -m compileall cap attestation examples
```

See [docs/](docs/) for the model, threat and trust-boundary analysis, replay, and validation scope.

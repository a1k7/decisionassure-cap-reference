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
## Generating a Signed Proof Trace

To emit a self-contained, signed CAP proof trace with an embedded public key:

python emit_signed_trace.py

See [docs/](docs/) for the model, threat and trust-boundary analysis, replay, and validation scope.


## Signed Envelope

The signed object is the **envelope**, not the attestation. The envelope
contains the decision, action, attestation, policy-bundle digest, continuity
scope, key resolution, and evidence status. The Ed25519 signature covers the
RFC 8785 (JCS) canonical encoding of the envelope minus the `signature` field.

    canonicalize(envelope \ {signature})  →  Ed25519 sign/verify

Two properties follow:

1. Changing `decision`, `policy_bundle_digest`, `authority_state`,
   `continuity_valid`, or the action parameters invalidates the signature.
2. `key_id` is resolved out-of-band against a keyring. The public key is
   never read from the artifact. Self-consistency is not attribution.

### Canonicalization

All signed data uses RFC 8785 (JCS). JSON produced by `json.dumps` with
`sorted_keys=True` is not JCS and diverges on non-ASCII strings and number
formatting. Do not sign anything that has not passed through
`cap.canonicalize.canonicalize`.

### Refusal Symmetry

ALLOW, DENY, HOLD, and REAUTHORIZE envelopes share one schema and commit to
the same `policy_bundle_digest`. A reviewer can distinguish a DENY under
policy X from a DENY under an earlier version of the policy without trusting
the emitter.

### Continuity Scope

`continuity_scope` is signed inside the envelope. Sequence-gap detection is
relative to an anchored scope, not a mutable local parameter. If the scope is
narrowed after the fact, the envelope's signature fails.

### Verifying an Envelope

    from attestation.verifier import verify_envelope
    from cap.models import TraceEnvelope

    envelope = TraceEnvelope(**json.loads(open("traces/allow.json").read()))
    keyring  = {"key-demo-001": bytes.fromhex(open("traces/keyring.json").read()["key-demo-001"]["public_key_hex"])}
    assert verify_envelope(envelope, keyring)
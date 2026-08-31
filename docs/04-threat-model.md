# Threat model

- **T1 agent fabricates authorization:** require separately signed artifact.
- **T2 receipt modification:** canonical payload signatures detect modification.
- **T3 compromised signer:** explicitly unresolved; signature is not source truth.
- **T4 sequence gap:** detect and `HOLD` rather than infer a cause.
- **T5 stale replay:** policy/continuity checks require current declared state.
- **T6 action substitution:** action type, resource, and parameters hash must match.
- **T7 attestation unavailable:** `HOLD`.
- **T8 infrastructure compromise:** a remaining explicit trust boundary.

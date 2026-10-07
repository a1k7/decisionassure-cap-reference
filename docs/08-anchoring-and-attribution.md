# Anchoring and Attribution

## What the current revision establishes

- **Envelope integrity.** The Ed25519 signature covers the whole envelope
  (decision, action, attestation, policy_bundle_digest, authority_state,
  continuity_valid, continuity_scope, key_resolution). Any change to a
  signed field invalidates the signature.
- **Key resolution, not attribution.** `key_id` resolves against
  `traces/keyring.json`. This proves that the artifact was signed by the
  key identified in the keyring. It does not prove that the key belongs to
  any particular identity.

## What is not yet established

- **External anchoring.** No RFC 3161 timestamp, transparency-log entry,
  or third-party notary commits to the envelope before the events it
  covers. The envelope has no independent evidence of when it existed.
- **Identity attribution.** `traces/keyring.json` is committed in the
  repository and self-asserted. No external identity is bound to
  `key-demo-001`.
- **Key rotation and revocation.** Declared in `key_resolution`, not
  enforced by a resolver.
- **Completeness beyond gap detection.** `continuity_scope` is signed and
  anchored inside the envelope. The completeness claim is bounded to the
  declared observed scope. A Merkle proof alone would not establish that
  every real-world event was captured.

## What the next revision must add

1. An anchor receipt: RFC 3161 timestamp, transparency-log entry, or
   equivalent, over the envelope digest.
2. A signed keyring attestation binding `key_id` to an external identity.
3. A resolver enforcing rotation windows and revocation lists.
4. A completeness proof over the declared window, if a completeness claim
   is to be made rather than only gap detection.
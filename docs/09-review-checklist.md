# Review Checklist

| Test | Supported? | Where |
|---|---|---|
| Envelope verifies unmodified | yes | tests/test_signed_refusals.py |
| Changed decision fails | yes | tests/test_envelope_tampering.py |
| Changed policy_bundle_digest fails | yes | tests/test_envelope_tampering.py |
| Changed authority_state fails | yes | tests/test_envelope_tampering.py |
| Changed continuity_valid fails | yes | tests/test_envelope_tampering.py |
| Changed continuity_scope fails | yes | tests/test_envelope_tampering.py |
| Changed key_resolution fails | yes | tests/test_envelope_tampering.py |
| Changed action parameters fail | yes | tests/test_envelope_tampering.py |
| Changed attestation sequence fails | yes | tests/test_envelope_tampering.py |
| Signed refusal cases verify | yes | tests/test_signed_refusals.py |
| Dropped event in middle | yes | tests/test_dropped_events.py |
| Dropped event at beginning | no | tests/test_dropped_events.py |
| Dropped event at end | no | tests/test_dropped_events.py |
| Expired key | no | tests/test_key_lifecycle.py (skipped) |
| Revoked key | no | tests/test_key_lifecycle.py (skipped) |
| External anchoring receipt | no | docs/08-anchoring-and-attribution.md |
| Keyring trust basis beyond integrity | no | docs/08-anchoring-and-attribution.md |
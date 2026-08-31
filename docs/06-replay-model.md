# Replay model

Replay deterministically uses declared trace inputs: evidence references, authority state, policy version, action, binding and continuity conditions, original decision, and rule version. A trace digest detects fixture alteration. Replay does not create absent evidence, and therefore reports `COMPLETE`, `PARTIAL`, or `UNKNOWN` evidence completeness. It reconstructs a declared decision, not unrecorded facts.

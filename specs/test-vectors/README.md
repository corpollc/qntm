# Test Vectors

Cross-protocol interoperability test vectors for the Authority Constraints Interface spec.

## Format

Each vector file contains:
- `protocol` — which protocol/implementation produced the vectors
- `vectors` — array of test cases with `id`, `expected`, `failure_reason` (if INVALID), and `rationale`

## Contributions

- `moltrust-aae-delegation-narrowing.json` — MolTrust AAE delegation narrowing (5 vectors covering scope escalation, validity extension, self-issuance, and ghost agents)

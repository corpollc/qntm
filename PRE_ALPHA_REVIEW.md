# Pre-alpha Review Findings (2026-02-14)

## Scope checked
- Security flaws
- Cryptographic correctness
- Dead code / stubs
- Missing / mocked features
- demo.md accuracy
- Accidental key inclusion
- Feature completeness against QSP v1.1

## Critical findings

1. **QSP v1.1 features are not implemented in runtime code.**
   - The v1.1 spec requires `conv_epoch`, `group_rekey`, and `handle_reveal`, plus related key schedule and verification rules.
   - The protocol data structures and message flow still only implement v1.0-era fields and types.

2. **Nonce derivation does not match spec intent.**
   - `DeriveNonce` comment claims `HMAC-SHA-256(k_nonce, msg_id)` but implementation is plain `SHA256(k_nonce || msg_id)`.
   - This is a cryptographic mismatch and should be corrected or documented as intentional with test vectors.

3. **Gate service has no authentication/authorization on admin APIs.**
   - Org creation, credential insertion, and request submission endpoints are open HTTP handlers.
   - Any caller can create orgs and attach credentials in the current process.

## High findings

4. **Credential handling contradicts stated secrecy claims.**
   - Credentials are stored in plaintext in memory (`Credential.Value`).
   - Forwarded target response body is returned verbatim in `execution_result`, so reflected credentials can leak to callers.

5. **go test cannot run due to dependency hygiene issue.**
   - Test run fails with missing `go.sum` entry for `golang.org/x/sys/cpu` required by `x/crypto/chacha20poly1305`.

## Medium findings

6. **Stubbed / not implemented functionality exists in shipped CLI paths.**
   - `identity import`, `identity export`, and `group remove` are present but return explicit `not implemented` errors.

7. **ACK serialization path is explicitly TODO / placeholder.**
   - `SendACK` currently sends formatted text (`ack:<msgid>:<status>`) rather than structured protocol object.

8. **Demo output has drift / self-contradictions.**
   - Demo claims credentials never appear in responses, but later output includes `Bearer sk_live_demo_key_2026` in the body.
   - Demo also documents commands that return stubs, which is acceptable for transparency but not production-ready behavior.

## Key leakage check
- No obvious private-key PEM or cloud provider key format strings were found in repository sources.
- `demo.md` contains a clearly synthetic token-like value (`sk_live_demo_key_2026`), used as documentation data.

## Recommended immediate actions
1. Implement v1.1 wire/data model (`conv_epoch`, new body types, epoch key derivation).
2. Fix nonce derivation to actual HMAC-SHA-256 (or update spec/comments and test vectors if intentional).
3. Add authn/authz on gate management and signing endpoints.
4. Redact/guard execution response bodies or introduce allowlist filtering.
5. Resolve module checksum issues and gate CI on `go test ./...`.
6. Remove/feature-flag stub CLI commands until implemented.

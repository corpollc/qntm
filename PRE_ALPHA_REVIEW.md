# Pre-alpha Review Findings (2026-02-14)

## Scope checked
- Security flaws
- Cryptographic errors
- Dead code
- Missing / faked / mocked code
- `demo.md` accuracy
- Accidental key inclusion
- Feature completeness against QSP v1.1

## What I ran
- `go test ./...`
- `uvx showboat --help`
- Static scans (`rg`) for: v1.1 fields, TODO/not-implemented markers, and secret-like strings.

## Environment limitations
1. **Automated test execution is blocked by network policy in this environment.**
   - `go test ./...` fails while downloading modules from `proxy.golang.org` (HTTP Forbidden).
2. **Demo regeneration could not be executed.**
   - `uvx showboat --help` fails because PyPI fetch to `https://pypi.org/simple/showboat/` cannot connect through the environment tunnel.

## Findings

### High
1. **Gate admin protection is optional and defaults to disabled.**
   - `gate.NewServer()` calls `NewServerWithToken("")` and `requireAdmin` allows all admin operations when no token is set.
   - Impact: org creation and credential insertion are unauthenticated by default unless operators explicitly pass `--admin-token` / `QNTM_GATE_TOKEN`.

### Medium
2. **Credentials are stored in plaintext in memory.**
   - `Credential.Value` is stored as a raw string in the in-memory org store.
   - Impact: practical pre-alpha tradeoff, but still sensitive material handling risk.

3. **Unwired command implementations remain in tree (dead code / partial feature).**
   - `identity import` and `identity export` command handlers exist but are not registered in CLI init and return `not implemented yet`.

4. **A placeholder URL is still baked into invite creation output.**
   - `invite create` formats links using `https://qntm.example.com/join`.
   - Impact: demo/developer convenience, but inaccurate for production guidance unless explicitly overridden/documented.

### Pass / verified
5. **Core v1.1 artifacts appear implemented in code paths and tests.**
   - `conv_epoch` is present in envelope/AAD types and set during message creation.
   - Group rekey message handling (`group_rekey`) and handle reveal (`handle_reveal`) code paths are present.
   - Epoch-key derivation tests exist for v1.0 compatibility at epoch 0 and epoch separation.

6. **Nonce derivation matches the stated HMAC construction.**
   - `DeriveNonce` uses `HMAC-SHA-256(k_nonce, msg_id)` and truncates to 24 bytes.

7. **Credential reflection mitigation is present in gate execution results and demo output.**
   - Execution results return metadata (status/content type/content length) without response body.
   - Demo sections for gate execution also show redacted body behavior.

8. **No obvious real secrets were found in repo text.**
   - Pattern scan found only the demo string `sk_live_demo_key_2026` in documentation context.

## Recommended next actions
1. Make admin auth **secure-by-default** for gate (`--admin-token` required in non-dev mode).
2. Add optional at-rest/in-memory credential hardening strategy (KMS, envelope encryption, or external secret source).
3. Either implement or remove/unexpose identity import/export stubs.
4. Replace placeholder invite base URL with config-derived value and document clearly in `demo.md`.
5. Re-run full quality gates and regenerate demos in a network-enabled CI environment.

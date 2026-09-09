# Client safety audit: P1 remediation

This change follows the [September 7 audit](2026-09-07-client-safety.md). Beads tracks the four original findings and the gateway prerequisites brought forward to run their acceptance gate. All exploit regressions used generated identities and local workers.

## Changes

| Bead | Remediation |
|---|---|
| `qntm-mcww` | Receipt signatures remain checked, but receipt authors cannot delete messages. `required_acks` stays in the signed wire format for compatibility and `deleted` is always false. Unique-reader telemetry is capped at 256. Public statistics no longer enumerate conversation IDs. |
| `qntm-lfpp` | Python CLI/MCP JSON state uses owner-only POSIX directories/files, repairs existing permissions when accessed, and replaces files atomically after flushing. Unsafe links, special files, other-user ownership, and shared root configuration paths are rejected. Naming, announcement state, and learned participant keys use the same writer. |
| `qntm-fods` | CLI and MCP share receive processing. Genesis/add/remove/rekey events update local state, including keys needed by subsequent messages in the same batch. Non-text bodies survive in `unsafe_body` or `unsafe_body_b64`. History and conversation state are saved before the receive cursor. Stale rekeys cannot roll back an epoch. |
| `qntm-udxj` | AIM resolves React Router and React Router DOM 7.18.3; TUI resolves ws 8.21.3. Runtime audits report zero findings. Lockfile changes are limited to those packages and correcting AIM's existing package-version metadata. CI runs runtime audits and the cross-surface acceptance workflow. |
| `qntm-3u01` | The old acceptance stack's gateway fixes were absent from this branch. The restored regression reproduced below-quorum governance application. Brought forward trusted majority governance, authenticated bootstrap, canonical key/epoch validation, conversation binding for requests/votes, and non-overwriting repeat bootstrap. Repeat bootstrap also re-arms maintenance after restart. AIM requests a masked promotion token and does not persist it. |

The gateway changes derive from the existing `67d1d13`, `e855dab`, and `068ef2e` fixes, plus the acceptance stack's maintenance regression. The refreshed harness uses current UI controls, local API fixtures, and public bootstrap/subscribe APIs. Its adversarial tests retain missing/wrong-token, below-quorum, and cross-conversation cases.

## Dependency reachability

AIM is a static Vite application using `HashRouter`. It does not run the React Router framework's SSR, RSC, server actions, or prerender pipeline, so the advisories confined to those server paths are not exercised by this deployment. Client navigation is exercised, and the complete router dependency pair was upgraded. See the upstream [RSC CSRF advisory](https://github.com/advisories/GHSA-qwww-vcr4-c8h2).

TUI's ws dependency comes from Ink's React DevTools window polyfill. Ink loads that module when `DEV=true`; the normal Node 22 relay client uses the native WebSocket API. This limits exposure in the default TUI path, while the upgrade also protects the optional path. See the upstream [ws fragmentation memory-exhaustion advisory](https://github.com/advisories/GHSA-96hv-2xvq-fx4p).

## Operational boundaries

The operator-token setup described in this historical audit was superseded on 2026-09-08 by [participant invitations and signed acceptance](../gateway-invitations.md). Deploy the updated gateway and clients together; no promotion token is required. These changes have not been deployed to production.

Private file permissions do not encrypt local state or protect it from the same operating-system user. Individual file replacement is atomic; concurrent writers still require coordination. Guidance review remains offline: receive pending messages first to refresh the locally known audience. A valid signature or pinned contact does not grant authority to execute advice.

The original P2 backup-import validation finding remains tracked as `qntm-fwds`. Development-only npm advisories remain outside the runtime upgrade and are tracked for reachability review and toolchain updates in `qntm-yokf`.

## Validation

- Python: 295 passed, 1 explicitly disabled live DID-network test skipped, 3 subtests passed. The wheel/source build passed and includes the new storage module.
- Protocol client: 191 tests and TypeScript build passed.
- AIM: 58 tests and production build passed.
- TUI: 13 tests passed, including the real PTY composer join/send/quit exchange; its TypeScript build passed.
- Gateway: 66 tests and typecheck passed. Relay typecheck passed; 7 focused policy/real-worker tests passed.
- Model integration: 24 tests passed. The full 13-scenario local acceptance gate passed, covering authenticated setup, below-quorum and cross-conversation rejection, request execution, restart, expiry recovery, membership/rekey isolation, and relay replay/receipt retention.
- Both `npm audit --omit=dev --json` reports contain zero vulnerabilities. Workflow YAML and `git diff --check` pass.
- ProofShot verified guidance navigation, back/deep-link reload, disabled empty requests, masked required promotion-token entry without persistence, and a 390-pixel mobile layout without horizontal overflow. The final session reports zero console/server errors. Local artifacts: `ui/aim-chat/proofshot-artifacts/2026-09-08_02-25-10_verify-required-masked-gateway-promotion/`.

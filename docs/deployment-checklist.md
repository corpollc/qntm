# Release and deployment procedure

Public packages and Cloudflare surfaces ship from one tagged commit. The charter VM is deployed from the same release source using the [charter runbook](charter-operations.md). Pushing `main` runs CI without deploying. Pushing `vX.Y.Z` runs the complete reusable CI workflow inside `Release`; only its successful **Release gate** authorizes publication.

The existing `release.yml` and `publish-npm.yml` workflow identities are retained for PyPI/npm trusted publishing. npm, AIM, relay, gateway, and echo workflows wait for the successful gate on the exact tag and SHA. A failed, cancelled, skipped, missing, or timed-out gate stops publication. A successful gate does not guarantee every later publishing service succeeds: monitor all six workflows and verify their outputs.

## Release preparation

1. Reconcile the candidate with `main` and the latest published tag. Preserve fixes published from another branch.
2. Run `python3 scripts/set_release_version.py X.Y.Z`. Refresh `python-dist/uv.lock` with `uv lock` if dependencies changed. The Python/TypeScript packages, browser, terminal UI, and Claude plugin use the release version; private worker and adapter package versions are independent.
3. Write `docs/releases/vX.Y.Z.md` and update `docs/CHANGELOG.md`. Include compatibility changes and experimental boundaries. Regenerate CLI help with `python scripts/generate_cli_reference.py` in a qntm Python environment.
4. Run `python3 scripts/check_release.py`, then the full CI workflow on the candidate. Use the same gates locally when changing code.
5. Merge or fast-forward the passing candidate to `main`, verify that commit, then create and push its release tag.

## Quality gates

| Surface | Checks |
| --- | --- |
| TypeScript library | Crypto/protocol/event/subscription tests, build, package contents |
| Python | Full suite with MCP extras on Python 3.10 and 3.12; minimum WebSocket dependency on 3.10; generated help |
| Charter | Go race tests, vet, and vulnerability scan; real Go/TypeScript HTTP/restart tests; deterministic shared vectors |
| Browser | Unit/component tests, production build, Playwright conversation journeys, runtime dependency audit |
| Terminal | Unit/component tests, real PTY input and receive tests, build, runtime dependency audit |
| Relay | Typecheck; real Worker subscription/receipt/idle-expiry tests; SQLite migration/retention regressions |
| Gateway | Security/governance tests and typecheck; browser/CLI approval, membership/rekey, expiry, restart, and signed invitation/acceptance journeys |
| Adapters | OpenClaw, retained NanoClaw, and Claude channel tests/typecheck; OpenClaw 2026.9.3 compiled-package install and real host text/restart smoke on Node 24; real MCP channel transport; runtime dependency audits |
| Integration and packaging | Protocol model suite; browser/CLI/MCP guidance; TypeScript-to-CLI webhook/executable delivery and restart; lost HTTP acknowledgement recovery; real echo Worker cron delivery and README-extracted quick-start/Python/gateway commands; echo-worker typecheck; source/lockfile version checks; Python runtime/MCP lock vulnerability audit, build, and twine validation |

The cross-surface suite uses local Workers and browser instances; some API recipe journeys call public services. Test failures there must be diagnosed rather than silently skipped. Adapter contract tests do not replace smoke tests in each external host release. The public charter service remains experimental and unwitnessed; its resource limits, TLS, backup restoration and private telemetry require deployment checks in addition to CI.

## Publish and verify

```sh
git tag vX.Y.Z
git push origin vX.Y.Z
gh run list --commit COMMIT_SHA
```

Verify `Release`, `Publish npm`, `Deploy AIM UI`, `Deploy Dropbox Relay Worker`, `Deploy Gateway Worker`, and `Deploy Echo Bot`. The release body comes from the curated notes, not generated commit titles. Install the published Python wheel and npm tarball in fresh environments; verify versions, messaging, and the charter export. Check:

```sh
curl --fail https://inbox.qntm.corpo.llc/healthz
curl --fail https://gateway.corpo.llc/health
curl --fail https://charter.qntm.corpo.llc/healthz
```

Open `https://chat.corpo.llc`, check its version and a private messaging conversation, and exercise gateway admission against the deployed worker. See [relay operations](relay-operations.md) for a two-client transport check and certificate diagnostics.

## Credentials and recovery

The repository needs `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and `QNTM_GATE_VAULT_KEY`. PyPI and npm use their configured trusted publishers. `SITE_DEPLOY_TOKEN` is optional; when absent, the release logs that the separate site's version file was not updated.

Manual relay/gateway/echo deployment runs the full CI gate on the selected ref before deploying. Deploy a previous compatible ref to roll back code. Published package versions are immutable; fix forward with a new version if a release artifact is wrong. Do not move a published tag or rotate the gateway vault key during a routine release: existing credentials depend on that key.

Relay cleanup is logical expiry. Cloudflare recovery history and copies stored in clients or gateways have separate retention. Old dormant Durable Objects begin metadata migration and alarm scheduling when they next wake; deployment alone does not enumerate them.

## Feature journey coverage

`cd integration && npm run test:acceptance` includes the existing messaging, gateway, policy, and membership journeys plus the v0.6.0 feature journeys. `npm run test:features` runs just the latter during development.

| Feature | Cross-client evidence |
| --- | --- |
| Gateway admission | CLI invitation and authenticated gateway acceptance validated by TypeScript and observed in browser history; existing UI workflow invites the gateway from the browser |
| Guidance categories | CLI pins for all three categories, discovered/prepared/sent through a real MCP connection, received in the browser; changed reviewed content is rejected |
| Browser guidance | Browser pin, exact-message review without transmission, then send and matching CLI receive; no automatic history attachment |
| Receive hooks | TypeScript sender through a real relay to Python watch, HTTP and executable hooks; a failing webhook does not repeat successful executable delivery; pending events survive restart and a shared CLI cursor advance |
| Send acknowledgement recovery | Proxy drops the successful HTTP response; CLI reconciles through the real WebSocket relay; TypeScript receives one message and the proxy observes one POST |
| Claude channel | Real MCP client observes pending/live signed events, stable IDs, binary payloads, and self-message suppression; durable queue tests cover failure and restart |
| Charter | Real Go server accepts self-charters, parent-governed children and namespace experiments from TypeScript; verifies threshold transitions, rejects unauthorized rotation/forks, and survives abrupt restart |
| Relay retention | Real Worker WebSocket replay and idle alarms, plus SQLite migration, expired sequence gaps and multiple-page replay |

The charter boundary runs with `cd client && npm run test:charter-server`; the Claude channel runs with `cd channel && npm test`. Both are mandatory parts of the same complete CI/release gate.

## README example coverage

`cd integration && npm run test:readme` extracts and executes the README quick-start, inline Python, linked offline examples, and gateway commands. Tests replace profile paths, generated IDs and service origins; the gateway example retains the real recipe schema and echoes its approved payload through a local HTTP fixture. A separate test runs the actual echo Worker scheduled handler against the actual relay.

Install/build commands are covered by package builds and clean installs in CI and release verification. MCP stdio behavior is exercised by the guidance journeys. The public demo invitation is checked live after deployment, because CI should not depend on the public channel's cron timing. This is explicit coverage of documented flows, not a claim that every illustrative code fragment in every document is executable.

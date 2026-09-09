# Release and deployment procedure

All public packages and hosted surfaces ship from one tagged commit. Pushing `main` runs CI without deploying. Pushing `vX.Y.Z` runs the complete reusable CI workflow inside `Release`; only its successful **Release gate** authorizes publication.

The existing `release.yml` and `publish-npm.yml` workflow identities are retained for PyPI/npm trusted publishing. npm, AIM, relay, and gateway workflows wait for the successful gate on the exact tag and SHA. A failed, cancelled, skipped, missing, or timed-out gate stops publication. A successful gate does not guarantee every later publishing service succeeds: monitor all five workflows and verify their outputs.

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
| Charter | Go race tests and vet; real Go/TypeScript HTTP/restart tests; deterministic shared vectors |
| Browser | Unit/component tests, production build, Playwright conversation journeys, runtime dependency audit |
| Terminal | Unit/component tests, real PTY input and receive tests, build, runtime dependency audit |
| Relay | Typecheck; real Worker subscription/receipt/idle-expiry tests; SQLite migration/retention regressions |
| Gateway | Security/governance tests and typecheck; browser/CLI approval, membership/rekey, expiry, and restart journeys |
| Adapters | OpenClaw, NanoClaw, and Claude channel tests/typecheck; real MCP channel transport; runtime dependency audits |
| Integration and packaging | Protocol model suite; echo-worker typecheck; source/lockfile version checks; Python build and twine validation |

The cross-surface suite uses local Workers and browser instances; some API recipe journeys call public services. Test failures there must be diagnosed rather than silently skipped. Adapter contract tests do not replace smoke tests in each external host release. Go charter support is a reference implementation, not a public service.

## Publish and verify

```sh
git tag vX.Y.Z
git push origin vX.Y.Z
gh run list --commit COMMIT_SHA
```

Verify `Release`, `Publish npm`, `Deploy AIM UI`, `Deploy Dropbox Relay Worker`, and `Deploy Gateway Worker`. The release body comes from the curated notes, not generated commit titles. Install the published Python wheel and npm tarball in fresh environments; verify versions, messaging, and the charter export. Check:

```sh
curl --fail https://inbox.qntm.corpo.llc/healthz
curl --fail https://gateway.corpo.llc/health
```

Open `https://chat.corpo.llc`, check its version and a private messaging conversation, and exercise gateway admission against the deployed worker. See [relay operations](relay-operations.md) for a two-client transport check and certificate diagnostics.

## Credentials and recovery

The repository needs `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and `QNTM_GATE_VAULT_KEY`. PyPI and npm use their configured trusted publishers. `SITE_DEPLOY_TOKEN` is optional; when absent, the release logs that the separate site's version file was not updated.

Manual relay/gateway deployment runs the full CI gate on the selected ref before deploying. Deploy a previous compatible ref to roll back code. Published package versions are immutable; fix forward with a new version if a release artifact is wrong. Do not move a published tag or rotate the gateway vault key during a routine release: existing credentials depend on that key.

Relay cleanup is logical expiry. Cloudflare recovery history and copies stored in clients or gateways have separate retention. Old dormant Durable Objects begin metadata migration and alarm scheduling when they next wake; deployment alone does not enumerate them.

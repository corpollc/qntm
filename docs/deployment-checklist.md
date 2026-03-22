# Deployment Checklist

This is the operational checklist for shipping the hosted qntm stack without drifting the browser UI, published clients, relay worker, and gateway worker out of sync.

## What Deploys What

- Push to `main`:
  - `Deploy Dropbox Relay Worker`
  - `Deploy Gateway Worker`
- Push tag `v*`:
  - `Deploy AIM UI`
  - `Publish npm`
  - `Release` (PyPI + GitHub release)
  - `Update Site Version`

Important:

- A tag push does **not** deploy the relay worker.
- A tag push does **not** deploy the gateway worker.
- A push to `main` does **not** deploy the AIM UI or publish the client libraries.

## Required Secrets

GitHub repository secrets:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `QNTM_GATE_VAULT_KEY`
- `SITE_DEPLOY_TOKEN` for the site version update job

Cloudflare token UI permissions for the hosted deploy token:

- `Account` -> `Account Settings` -> `Read`
- `Account` -> `Workers Scripts` -> `Edit`
- `Account` -> `Workers KV Storage` -> `Edit`
- `Zone` -> `Workers Routes` -> `Edit`
- `User` -> `User Details` -> `Read`
- `User` -> `Memberships` -> `Read`

Optional:

- `Account` -> `Workers Tail` -> `Read`

## Preflight

Run these from a clean checkout of the release candidate commit:

```bash
cd client && npm ci && npm test && npm run build && npm pack --dry-run
cd ../worker && npm ci && npx tsc --noEmit
cd ../gateway-worker && npm ci && npm test && npm run typecheck
cd ../ui/aim-chat && npm install && npm test && npm run build
cd ../python-dist && uv run python -m pytest && uv build
cd ../ui/tui && npm install && npm run build
```

If you are not shipping a component, note that explicitly in the release notes instead of silently skipping it.

## Release Sequence

1. Land the code on `main`.

2. Watch the worker deploys from that exact `main` commit:

```bash
gh run list --workflow "Deploy Dropbox Relay Worker" --limit 1
gh run list --workflow "Deploy Gateway Worker" --limit 1
```

3. Verify the hosted worker endpoints:

```bash
curl https://inbox.qntm.corpo.llc/healthz
curl https://gateway.corpo.llc/health
```

4. Create and push the release tag from the same `main` commit:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

5. Watch the tag-driven release jobs:

```bash
gh run list --workflow "Deploy AIM UI" --limit 1
gh run list --workflow "Publish npm" --limit 1
gh run list --workflow "Release" --limit 1
gh run list --workflow "Update Site Version" --limit 1
```

6. Smoke test the live surfaces:

- `https://chat.corpo.llc`
- `https://inbox.qntm.corpo.llc/healthz`
- `https://gateway.corpo.llc/health`
- latest npm package metadata
- latest PyPI package metadata

## High-Risk Failure Modes

- Tagging before `main` is deployed leaves the UI and published clients ahead of the hosted workers.
- Pushing `main` without tagging leaves the hosted workers ahead of the AIM UI and package releases.
- Rotating `QNTM_GATE_VAULT_KEY` without a migration strands existing gateway secrets.
- Changing relay storage behavior should include a quota review for KV and Durable Objects before release.

## Polling Shutdown Notes

For changes that remove or deprecate protocol paths, verify all of these together:

- relay endpoint behavior
- gateway background behavior
- browser UI bundle behavior
- TypeScript client behavior
- Python CLI behavior
- release notes calling out the incompatibility

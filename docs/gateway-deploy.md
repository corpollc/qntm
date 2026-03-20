# Gateway Deployment

The official hosted qntm gateway runs at `https://gateway.corpo.llc`.
It is a separate Cloudflare Worker trust boundary from the relay at `https://inbox.qntm.corpo.llc`.

This worker can decrypt gateway-provisioned API credentials in order to execute approved requests, so some users will prefer to run their own copy. The source is in [`gateway-worker/`](../gateway-worker/), and the AIM UI can point at any compatible deployment.

## Prerequisites

- Cloudflare account with the `qntm.corpo.llc` zone, or your own zone for a self-hosted deployment
- Node.js 22
- `wrangler` access via `wrangler login` or `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID`
- A 32-byte vault key for at-rest secret encryption

Generate a vault key once and keep it stable across deploys:

```bash
openssl rand -hex 32
```

## Official Hosted Deploy

1. Build the shared client package.

```bash
cd client
npm ci
npm run build
```

2. Install and validate the worker.

```bash
cd ../gateway-worker
npm ci
npm test
npm run typecheck
```

3. Set the vault secret.

```bash
printf '%s' "$GATE_VAULT_KEY" | npx wrangler secret put GATE_VAULT_KEY
```

4. Deploy the worker.

```bash
npx wrangler deploy
```

5. Verify the deployment.

```bash
curl https://gateway.corpo.llc/health
```

Expected response:

```json
{"status":"ok","service":"qntm-gateway"}
```

The committed [`gateway-worker/wrangler.toml`](../gateway-worker/wrangler.toml) already targets:

- Worker name: `qntm-gateway`
- Custom domain: `gateway.corpo.llc`
- Relay URL: `https://inbox.qntm.corpo.llc`

## GitHub Actions Deploy

The repo includes [`.github/workflows/deploy-gateway.yml`](../.github/workflows/deploy-gateway.yml) for repeatable deploys from `main`.

Configure these repository secrets before enabling the workflow:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `QNTM_GATE_VAULT_KEY`

The workflow builds `client/`, runs gateway tests and typechecking, upserts `GATE_VAULT_KEY`, then deploys the worker.

## Self-Hosting

To run your own gateway:

1. Copy [`gateway-worker/wrangler.toml`](../gateway-worker/wrangler.toml) and replace the custom domain route with your own hostname.
2. Keep `DROPBOX_URL` pointed at the relay you want to trust.
3. Set your own `GATE_VAULT_KEY`.
4. Deploy with `npx wrangler deploy`.

Then point clients at your endpoint:

- AIM UI: set `VITE_DEFAULT_GATEWAY_URL=https://your-gateway.example` at build time, or override the `Gateway server` field in the UI.
- Local AIM development still defaults to `http://localhost:8080`.
- Terminal and Python clients already take an explicit gateway URL when promoting or executing gateway flows.

## Operational Notes

- Rotating `GATE_VAULT_KEY` without re-encrypting stored secrets will strand previously provisioned credentials.
- The gateway stores conversation-specific state in Durable Objects. Redeploying code is fine; deleting DO state is not.
- `GET /health` is the only intended unauthenticated public endpoint. All conversation control flow goes through signed qntm messages.

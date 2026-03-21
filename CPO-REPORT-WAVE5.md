# CPO Report — Wave 5: Time-to-First-Message Audit + API Gateway Next Steps

**Author:** CPO (Chief Product Officer)  
**Date:** 2026-03-21  
**Status:** Delivered to Founder

---

## Part 1: Time-to-First-Message Audit

### Chairman's Directive
> First message should take **<10 seconds**, not <5 minutes.

### Current State Summary

| Client | Current TTFM | Target | Gap |
|--------|-------------|--------|-----|
| **Web UI** (chat.corpo.llc) | ~45-90 seconds | <10 sec | 4-9x over |
| **Python CLI** (uvx qntm) | ~60-120 seconds | <10 sec | 6-12x over |
| **Terminal UI** (npm) | ~180-300 seconds | <10 sec | 18-30x over |

---

### Client 1: Web UI (chat.corpo.llc)

#### Exact Steps from Zero to First Sent Message

| Step | Action | Estimated Time |
|------|--------|---------------|
| 1 | Visit chat.corpo.llc | 2-4s (page load + JS bundle) |
| 2 | Read WelcomeCard — "Start a conversation" | 5-10s (orientation) |
| 3 | Click "Open Invites panel" | 1s |
| 4 | Understand invite model (create vs join) | 10-20s |
| 5 | Click "Create conversation" (identity auto-generated in browser) | 2-3s |
| 6 | *Realize you're alone in the conversation* | 5s of confusion |
| 7 | Type a message and hit send | 3-5s |

**Total: ~30-50 seconds** (solo message, no recipient)  
**Total with actual recipient: ~60-90 seconds** (must share invite, wait for join)

#### Friction Points

1. **Identity is invisible.** The browser auto-generates a keypair on first load, but the user never sees this happen. No confirmation, no "you are X."
2. **WelcomeCard is 2-step but feels like 5.** Step 1 says "Open Invites panel" — why not just create the conversation directly from the welcome card?
3. **No demo mode.** A visitor who wants to try the product must commit to the full create→invite→share→join flow. There's no "send a test message to yourself" or "try the echo bot."
4. **Conversation starts empty.** After creation, you see an empty chat with no one in it. The product feels broken until someone joins.
5. **Invite token UX is cryptographic jargon.** Users see base64url tokens. No copy-to-clipboard button mentioned in getting-started. No QR code.

#### Recommendations to Hit <10 Seconds

| Priority | Recommendation | Impact |
|----------|---------------|--------|
| P0 | **Auto-create a "Welcome" conversation on first visit** with a qntm echo bot participant. User lands in a live chat, types "hello", gets a response. TTFM = page load + typing time ≈ **5-8 seconds**. | Eliminates steps 2-6 entirely |
| P0 | **One-click "Try it"** button on landing page that opens chat.corpo.llc with a pre-joined echo conversation. No invite flow needed. | Demo scenario solved |
| P1 | **Show identity creation confirmation** — a toast: "🔑 Identity created. You are `abc123`." Builds trust, teaches the model. | Reduces confusion |
| P1 | **Inline conversation creation** in WelcomeCard — "Create a conversation" button right there, not "Open Invites panel" (an extra click + panel context switch). | Saves 5-10s |
| P2 | **Pre-populate a solo conversation** with a system message: "This is your private scratch pad. Invite someone to start a real conversation." | Empty chat no longer feels broken |

---

### Client 2: Python CLI (uvx qntm)

#### Exact Steps from Zero to First Sent Message

| Step | Action | Estimated Time |
|------|--------|---------------|
| 1 | Have `uv` installed (prerequisite) | 0s if present, 30-60s if not |
| 2 | `uvx qntm identity generate` | 8-15s (first run downloads package + deps: PyNaCl, cryptography, cbor2, httpx) |
| 3 | `uvx qntm convo create --name "Test"` | 3-5s (creates convo, prints invite token) |
| 4 | Parse JSON output to extract conversation ID | 5-10s (must read JSON, find `conversation_id` field) |
| 5 | `uvx qntm send <conv-id> "hello world"` | 3-5s (encrypts, POSTs to relay) |

**Total: ~20-35 seconds** (experienced developer, `uv` already installed)  
**Total (cold start): ~60-120 seconds** (install uv, first-time package download)

#### Friction Points

1. **`uv` is not ubiquitous.** Many developers don't have it. `pip install qntm` works but the docs lead with `uvx`.
2. **JSON output is hostile to first-time humans.** The default output is machine JSON. A newcomer running `qntm convo create` sees a wall of JSON and has to hunt for the conversation ID. `--human` flag exists but is not the default and not prominent in docs.
3. **No single-command demo.** The README shows 4 commands. There's no `qntm demo` or `qntm quickstart` that does identity→create→send in one shot.
4. **Conversation ID is a 32-char hex string.** Users must copy-paste it. No tab completion, no aliases by default (naming exists but requires extra steps).
5. **`uvx` re-resolves on every call.** Each `uvx qntm ...` invocation re-checks the package, adding 1-3s latency. Four commands = 4-12s of overhead.

#### Recommendations to Hit <10 Seconds

| Priority | Recommendation | Impact |
|----------|---------------|--------|
| P0 | **`qntm quickstart` command** — single command that: (1) generates identity if needed, (2) creates a conversation, (3) sends "hello world", (4) prints the result with human-friendly output. Target: **one command, <10 seconds**. | ```bash\nuvx qntm quickstart\n# → Identity created: abc123\n# → Conversation created: "My First Chat" (def456)\n# → Message sent: "hello world"\n# → Done! Share this invite link: https://chat.corpo.llc?invite=...\n``` |
| P0 | **`pip install qntm && qntm quickstart`** — two commands total in docs. Lead with pip, not uvx. | Reduces prerequisite friction |
| P1 | **Default to `--human` when stdout is a TTY.** JSON stays default for pipes/scripts. Interactive terminal users get readable output automatically. | Huge UX win, zero breakage for automation |
| P1 | **Auto-name conversations** with incrementing labels: "Chat 1", "Chat 2" — and accept names as send targets: `qntm send "Chat 1" "hello"`. | Eliminates hex ID copy-paste |
| P2 | **Cache `uvx` resolution** or document `pip install qntm` first so subsequent calls are instant. | Saves 4-12s across multi-command flows |

---

### Client 3: Terminal UI (TUI)

#### Exact Steps from Zero to First Sent Message

| Step | Action | Estimated Time |
|------|--------|---------------|
| 1 | Clone the repo (or navigate to it) | 10-30s |
| 2 | `cd ui/tui` | 1s |
| 3 | `npm install` | 30-90s (downloads ink, react, @corpollc/qntm, tsx, etc.) |
| 4 | `npm start` | 5-10s (tsx compilation + startup) |
| 5 | Orient yourself in the TUI (sidebar, chat pane, status bar) | 10-20s |
| 6 | Figure out how to create a conversation (keyboard shortcut or command) | 10-30s |
| 7 | Create conversation | 3-5s |
| 8 | Type and send a message | 5-10s |

**Total: ~80-200 seconds** (3-5 minutes)

#### Friction Points

1. **Requires cloning the entire monorepo.** There's no `npx @qntm/tui` or standalone install.
2. **`npm install` is 30-90 seconds.** The client dependency on `file:../../client` means you must build the TS library first.
3. **No published npm package.** The TUI isn't on npm as a standalone tool.
4. **Separate data directory (`~/.qntm-human/`).** If you already have a Python CLI identity, the TUI can't see it. Two identities, two worlds.
5. **Learning curve for keybindings.** No visible menu or help text on first launch (must discover shortcuts).

#### Recommendations to Hit <10 Seconds

| Priority | Recommendation | Impact |
|----------|---------------|--------|
| P0 | **Publish `@qntm/tui` to npm.** Then: `npx @qntm/tui` — one command, no clone needed. | Eliminates steps 1-3 |
| P0 | **Auto-create identity + demo conversation on first launch.** Same pattern as Web UI recommendation. | TTFM ≈ install time + 5s |
| P1 | **Share identity with Python CLI** (or at least offer import). `~/.qntm/` should be the single source of truth. | Eliminates "two identities" confusion |
| P1 | **Show help overlay on first launch** — keybindings, how to create convo, how to type. | Eliminates orientation time |
| P2 | **Pre-built binaries via pkg or similar** — zero npm install time. | Aspirational but huge for demo scenario |

---

### The Demo Scenario: "Someone visits our site"

**Current experience (Web UI — best case):**
1. Visit chat.corpo.llc (2-4s)
2. Read welcome card (5-10s)
3. Click through to create conversation (5-10s)
4. Send message to empty room (3-5s)
5. **Feel disappointed because no one's there to respond** (∞)

**Total: ~20-30 seconds to send into the void. Not satisfying.**

**Target experience:**
1. Visit chat.corpo.llc (2-4s)
2. See a pre-joined conversation with **qntm-echo-bot** already in it
3. Type "hello" and hit enter (3-5s)
4. Get an encrypted echo response (1-2s)
5. **"Wow, that was encrypted end-to-end and I didn't install anything."**

**Total: ~8 seconds. Message sent AND received.**

#### Implementation: Echo Bot

Deploy a lightweight agent that:
- Runs `qntm recv` in a loop on a known "demo" conversation
- Echoes back: `"🔒 Echo: {your message} (encrypted end-to-end, verified by kid:{sender_kid[:8]})"` 
- Pre-join the demo conversation via a hardcoded invite token
- Web UI auto-joins this conversation on first visit (or offers one-click "Try the demo")

This is the single highest-leverage feature for time-to-first-message.

---

## Part 2: API Gateway Next Steps Spec

### Current Gateway State

The gateway-worker is a Cloudflare Worker with Durable Objects. It:
- ✅ Bootstraps per-conversation keypairs (`POST /v1/promote`)
- ✅ Polls the relay via SSE subscription
- ✅ Processes `gate.request`, `gate.approval`, `gate.secret`, `gate.executed`
- ✅ Verifies Ed25519 signatures on all requests and approvals
- ✅ Encrypts secrets at rest with AES-256-GCM (vault)
- ✅ Executes approved HTTP requests with credential injection
- ✅ Supports governance proposals (floor changes, member add/remove)
- ✅ Write-ahead log for crash recovery
- ✅ Starter recipe catalog (HN, httpbin, dad jokes, trivia, dogs, leet, ASCII art)

**What's missing (per Chairman's directive):**
1. Sample server setups (working examples, not just docs)
2. Better UI/UX for key/secret management
3. Real smoke tests (store key → call Gemini → get response)
4. Document signing that actually signs

---

### Next Step 1: Sample Server Setups

**Spec ID:** GATE-NS1  
**Title:** Three Working Gateway Setups (Copy-Paste Ready)

#### Acceptance Criteria

1. **Local dev setup script** (`scripts/gateway-local-dev.sh`) that:
   - Starts miniflare with the gateway-worker
   - Sets `GATE_VAULT_KEY` to a deterministic test key
   - Sets `DROPBOX_URL` to the hosted relay (or local relay if running)
   - Prints: "Gateway running at http://localhost:8787"
   - Exits 0 on success, non-zero with clear error on failure
   - **Test:** `bash scripts/gateway-local-dev.sh && curl http://localhost:8787/health` returns `{"status":"ok"}`

2. **Hosted setup checklist** (`docs/gateway-hosted-setup.md`) that:
   - Lists every Cloudflare secret needed: `GATE_VAULT_KEY`, `DROPBOX_URL`, `POLL_INTERVAL_MS`
   - Shows exact `wrangler secret put` commands
   - Shows exact `wrangler deploy` command
   - Includes a post-deploy smoke test: `curl https://gateway.corpo.llc/health`
   - **Test:** Following the doc from zero produces a working gateway

3. **Docker compose setup** (`docker/docker-compose.gateway.yml`) that:
   - Runs the gateway worker in a Node.js container (workerd or miniflare)
   - Runs a local relay worker alongside
   - Includes a healthcheck
   - **Test:** `docker compose up -d && curl http://localhost:8787/health` within 30s

#### Deliverables
- `scripts/gateway-local-dev.sh`
- `docs/gateway-hosted-setup.md` (update from existing gateway-deploy.md)
- `docker/docker-compose.gateway.yml`
- Each setup must include a README section with copy-paste commands

---

### Next Step 2: Better UI/UX for Key/Secret Management

**Spec ID:** GATE-NS2  
**Title:** Secret Management Dashboard

#### Current State
- Web UI has a GatePanel.tsx with basic "Add API Key" form (service, header name, header template, value)
- CLI has `gate-secret` command that requires `--gateway-pubkey` (a 32-byte base64url key the user must find somehow)
- No way to list stored secrets, check expiry, or revoke from the UI
- No way to see which services have active credentials

#### Acceptance Criteria

1. **Web UI: Secret Status Panel**
   - Shows a table of services with provisioned secrets
   - Columns: Service name, Header name, Status (active/expired), Provisioned date, Expires date, Actions (revoke)
   - Gateway posts `gate.secret-ack` messages when it successfully processes a secret (new message type)
   - Panel reads conversation history to derive secret status
   - **Test:** Provision a secret for "httpbin" → see it appear in the panel as "active" within 10 seconds

2. **Web UI: One-click secret provisioning**
   - "Add Secret" button opens a modal with:
     - Service dropdown (pre-populated from recipe catalog profiles)
     - API key input (password field, masked)
     - Auto-filled header name and template based on service profile
     - TTL selector (1 hour, 24 hours, 7 days, 30 days, no expiry)
   - Gateway public key auto-fetched from conversation state (no manual copy-paste)
   - **Test:** User can provision a secret in 3 clicks + 1 paste (the API key value)

3. **CLI: `gate-secret` UX improvements**
   - Auto-detect gateway public key from conversation history (no `--gateway-pubkey` needed if convo is already promoted)
   - `gate-secret list` — show provisioned secrets from conversation history
   - `gate-secret revoke --service <name>` — revoke a secret
   - **Test:** `qntm gate-secret -c <conv> --service httpbin --value "test123"` works without `--gateway-pubkey`

4. **Secret rotation workflow**
   - When a secret expires, gateway posts `gate.expired` to conversation (already implemented)
   - Web UI shows a "⚠️ Expired" badge and a "Re-provision" button that pre-fills the service name
   - **Test:** Set TTL=60s, wait 60s, see expired badge, click re-provision, enter new key, see "active" again

#### Deliverables
- Updated `GatePanel.tsx` with secret status table
- New `SecretModal.tsx` component
- Updated `cli.py` with `gate-secret list` and `gate-secret revoke` subcommands
- New `gate.secret-ack` message type in protocol (gateway → conversation)

---

### Next Step 3: Real Smoke Tests (Gemini with Bearer Auth)

**Spec ID:** GATE-NS3  
**Title:** End-to-End Smoke Test: Store Key → Call Gemini → Get Response

#### Why Gemini Specifically
- Google Gemini API uses a simple `x-goog-api-key: {value}` header (no OAuth dance)
- Free tier available (gemini-2.0-flash)
- Demonstrates real-world value: "my agent made an AI API call, approved by my team"

#### Acceptance Criteria

1. **New recipe: `gemini.generate`**
   ```json
   {
     "name": "gemini.generate",
     "description": "Generate text with Google Gemini (gemini-2.0-flash)",
     "service": "gemini",
     "verb": "POST",
     "endpoint": "/v1beta/models/gemini-2.0-flash:generateContent",
     "target_url": "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
     "risk_tier": "write",
     "threshold": 2,
     "content_type": "application/json",
     "body_schema": {
       "type": "object",
       "properties": {
         "contents": {
           "type": "array",
           "items": {
             "type": "object",
             "properties": {
               "parts": {
                 "type": "array",
                 "items": {
                   "type": "object",
                   "properties": {
                     "text": { "type": "string" }
                   }
                 }
               }
             }
           }
         }
       }
     },
     "body_example": {
       "contents": [{"parts": [{"text": "Say hello in exactly 5 words"}]}]
     }
   }
   ```
   - Header: `x-goog-api-key` with template `{value}` (no "Bearer" prefix)
   - **Test:** Recipe resolves to correct URL with body substitution

2. **Automated smoke test script** (`tests/smoke/gateway-gemini-e2e.sh`) that:
   - Creates two identities (Alice, Bob)
   - Creates a group conversation
   - Both join the conversation
   - Alice promotes the conversation to gateway with threshold=2
   - Alice provisions a Gemini API key as a secret
   - Alice submits a `gemini.generate` request
   - Bob approves the request
   - Gateway executes the API call
   - Both Alice and Bob see the Gemini response in conversation history
   - **Test:** Script exits 0 when Gemini returns HTTP 200 with generated text
   - **Requires:** `GEMINI_API_KEY` env var (skip test if not set)
   - **Timeout:** 60 seconds total

3. **CI integration**
   - Smoke test runs in CI when `GEMINI_API_KEY` secret is available
   - Skipped gracefully otherwise (not a blocking test)
   - **Test:** CI pipeline shows green with or without the secret

4. **Recipes for other auth-required APIs** (stretch):
   - `openai.chat` — OpenAI Chat Completions (Bearer token)
   - `anthropic.messages` — Anthropic Messages (x-api-key header)
   - `github.repos` — GitHub API (Bearer token)
   - Each with correct header_name and header_template

#### Exact Command Sequence (the "show, don't tell" demo)

```bash
# === Setup (Alice's terminal) ===
export ALICE_DIR=$(mktemp -d)
export BOB_DIR=$(mktemp -d)

# Generate identities
qntm --config-dir $ALICE_DIR identity generate
qntm --config-dir $BOB_DIR identity generate

# Alice creates a group conversation
ALICE_OUTPUT=$(qntm --config-dir $ALICE_DIR convo create --name "AI Team" --group)
CONV_ID=$(echo $ALICE_OUTPUT | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['conversation_id'])")
INVITE=$(echo $ALICE_OUTPUT | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['invite_token'])")

# Bob joins
qntm --config-dir $BOB_DIR convo join "$INVITE" --name "AI Team"

# Both send a message so they learn each other's public keys
qntm --config-dir $ALICE_DIR send $CONV_ID "Alice here"
qntm --config-dir $BOB_DIR recv $CONV_ID
qntm --config-dir $BOB_DIR send $CONV_ID "Bob here"
qntm --config-dir $ALICE_DIR recv $CONV_ID

# === Gateway Setup ===
# Promote conversation (Alice needs gateway_kid from promote response)
# First, call the gateway's /v1/promote HTTP endpoint to bootstrap
CONV_KEYS=$(python3 -c "
import json
convos = json.load(open('$ALICE_DIR/conversations.json'))
c = [x for x in convos if x['id'] == '$CONV_ID'][0]
print(json.dumps({'aead_key': c['keys']['aead_key'], 'nonce_key': c['keys']['nonce_key'], 'epoch': c.get('current_epoch', 0)}))
")
AEAD_KEY=$(echo $CONV_KEYS | python3 -c "import sys,json; print(json.load(sys.stdin)['aead_key'])")
NONCE_KEY=$(echo $CONV_KEYS | python3 -c "import sys,json; print(json.load(sys.stdin)['nonce_key'])")
EPOCH=$(echo $CONV_KEYS | python3 -c "import sys,json; print(json.load(sys.stdin)['epoch'])")

PROMOTE_RESP=$(curl -s -X POST https://gateway.corpo.llc/v1/promote \
  -H "Content-Type: application/json" \
  -d "{\"conv_id\":\"$CONV_ID\",\"conv_aead_key\":\"$AEAD_KEY\",\"conv_nonce_key\":\"$NONCE_KEY\",\"conv_epoch\":$EPOCH}")
GATEWAY_KID=$(echo $PROMOTE_RESP | python3 -c "import sys,json; print(json.load(sys.stdin)['gateway_kid'])")
GATEWAY_PK=$(echo $PROMOTE_RESP | python3 -c "import sys,json; print(json.load(sys.stdin)['gateway_public_key'])")

# Alice sends gate.promote message
qntm --config-dir $ALICE_DIR gate-promote -c $CONV_ID --threshold 2 --gateway-kid $GATEWAY_KID

# === Provision Gemini API Key ===
qntm --config-dir $ALICE_DIR gate-secret -c $CONV_ID \
  --service gemini \
  --gateway-pubkey $GATEWAY_PK \
  --header-name "x-goog-api-key" \
  --header-template "{value}" \
  --value "$GEMINI_API_KEY"

# === Submit API Request ===
qntm --config-dir $ALICE_DIR gate-run gemini.generate -c $CONV_ID \
  --arg 'contents=[{"parts":[{"text":"Say hello in exactly 5 words"}]}]'

# Alice polls to get the request ID
sleep 2
qntm --config-dir $BOB_DIR recv $CONV_ID
# Bob sees the request and approves
REQUEST_ID=$(qntm --config-dir $BOB_DIR gate-pending -c $CONV_ID | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['data']['pending'][0]['request_id'])")
qntm --config-dir $BOB_DIR gate-approve $REQUEST_ID -c $CONV_ID

# === Wait for execution ===
sleep 5

# Both poll for the result
qntm --config-dir $ALICE_DIR recv $CONV_ID
qntm --config-dir $BOB_DIR recv $CONV_ID

# Verify: history should contain a gate.result with Gemini's response
qntm --config-dir $ALICE_DIR history $CONV_ID | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
results = [e for e in data['data']['entries'] if e.get('body_type') == 'gate.result']
if results:
    body = json.loads(results[-1]['unsafe_body'])
    print('✅ Gemini responded:', body.get('body', '')[:200])
    sys.exit(0)
else:
    print('❌ No gate.result found')
    sys.exit(1)
"
```

#### Deliverables
- `gate/recipes/starter.json` updated with `gemini.generate`, `openai.chat`, `anthropic.messages`, `github.repos`
- `tests/smoke/gateway-gemini-e2e.sh` — full end-to-end script
- `tests/smoke/README.md` — how to run, env vars needed
- CI job definition (GitHub Actions or equivalent)

---

### Next Step 4: Document Signing That Actually Signs

**Spec ID:** GATE-NS4  
**Title:** Cryptographic Document Signing via Gateway

#### Concept
A conversation participant submits a document hash. Other participants "sign" it by approving a gateway request that records their Ed25519 signatures over the document hash. The gateway posts a `gate.signed-document` message containing all signatures, the document hash, and the signer identities.

This is NOT a gateway HTTP call to an external API. It's a new gateway-native operation.

#### Acceptance Criteria

1. **New message type: `gate.sign-request`**
   ```json
   {
     "type": "gate.sign-request",
     "conv_id": "...",
     "document_id": "uuid",
     "document_hash": "sha256:base64url",
     "document_name": "Q1-2026-Budget.pdf",
     "document_mime_type": "application/pdf",
     "signers_required": 2,
     "eligible_signer_kids": ["kid1", "kid2", "kid3"],
     "expires_at": "2026-03-22T00:00:00Z",
     "signer_kid": "kid1",
     "signature": "base64url(Ed25519(privateKey, canonical(sign-request)))"
   }
   ```
   - **Test:** Submitting a sign-request with a valid document hash and signature is accepted by the gateway

2. **New message type: `gate.sign-approval`**
   ```json
   {
     "type": "gate.sign-approval",
     "conv_id": "...",
     "document_id": "uuid",
     "document_hash": "sha256:base64url",
     "signer_kid": "kid2",
     "signature": "base64url(Ed25519(privateKey, canonical(sign-approval)))"
   }
   ```
   - The signature covers: `document_id || document_hash || conv_id` (canonical CBOR)
   - **Test:** Approval signature verifies against the signer's known public key

3. **Gateway emits `gate.signed-document` when threshold met**
   ```json
   {
     "type": "gate.signed-document",
     "document_id": "uuid",
     "document_hash": "sha256:base64url",
     "document_name": "Q1-2026-Budget.pdf",
     "signatures": [
       {"signer_kid": "kid1", "signature": "base64url", "signed_at": "..."},
       {"signer_kid": "kid2", "signature": "base64url", "signed_at": "..."}
     ],
     "signed_at": "2026-03-21T23:59:59Z",
     "verification_bundle": "base64url(CBOR(all signatures + public keys + document hash))"
   }
   ```
   - `verification_bundle` is a self-contained proof that can be verified offline
   - **Test:** Extract verification_bundle, verify all Ed25519 signatures against included public keys and document hash without any network access

4. **CLI commands**
   ```bash
   # Hash a local file and submit for signing
   qntm gate-sign -c <conv> --file Q1-2026-Budget.pdf --signers-required 2

   # Approve a signing request (after recv)
   qntm gate-sign-approve -c <conv> <document_id>

   # Verify a signed document bundle
   qntm gate-sign-verify <verification_bundle_file>

   # List pending signing requests
   qntm gate-sign-pending -c <conv>
   ```
   - **Test:** `qntm gate-sign-verify` returns exit 0 for valid bundles, exit 1 for tampered ones

5. **Web UI support**
   - Signing requests appear as rich cards in the conversation
   - Card shows: document name, hash (truncated), who's signed, who hasn't, expiry countdown
   - "Sign" button on the card
   - Completed signatures show a ✅ with all signers listed
   - **Test:** Two users in Web UI can sign a document in <30 seconds

#### Deliverables
- `gateway-worker/src/sign.ts` — document signing logic in the DO
- Updated `gateway-worker/src/do.ts` — new message type handlers
- Updated `python-dist/src/qntm/cli.py` — `gate-sign`, `gate-sign-approve`, `gate-sign-verify`, `gate-sign-pending` commands
- Updated `python-dist/src/qntm/gate.py` — signing primitives
- `ui/aim-chat/src/components/SigningCard.tsx` — UI component
- `tests/test_document_signing.py` — unit tests for signing primitives
- `tests/smoke/gateway-signing-e2e.sh` — end-to-end test

---

## Priority Matrix

| Spec | Effort | Impact | Priority | Timeline |
|------|--------|--------|----------|----------|
| **Echo Bot + Demo Conv** (TTFM) | S (2-3 days) | 🔴 Critical — makes or breaks demos | P0 | Week 1 |
| **`qntm quickstart` command** (TTFM) | S (1-2 days) | 🔴 Critical — CLI first impression | P0 | Week 1 |
| **TTY-default `--human` output** (TTFM) | XS (0.5 days) | 🟠 High — every CLI user benefits | P1 | Week 1 |
| **Gemini Smoke Test** (GATE-NS3) | M (3-5 days) | 🔴 Critical — proves gateway works end-to-end | P0 | Week 1-2 |
| **Sample Server Setups** (GATE-NS1) | M (3-4 days) | 🟠 High — unblocks external contributors | P1 | Week 2 |
| **Secret Management UX** (GATE-NS2) | L (5-7 days) | 🟠 High — key management is core to gateway | P1 | Week 2-3 |
| **Document Signing** (GATE-NS4) | XL (7-10 days) | 🟡 Medium — differentiator but not blocking | P2 | Week 3-4 |

---

## Summary for the Founder

**The single most important thing we can build this week is an echo bot + auto-joined demo conversation.** It takes the Web UI from 45-90 seconds TTFM to <10 seconds. It makes every demo, every pitch, and every "try it yourself" moment actually work.

For the CLI, `qntm quickstart` + TTY-aware output gets us from 60-120 seconds to <15 seconds with no architectural changes.

For the gateway, the Gemini smoke test is the "show, don't tell" moment. When we can demo "Alice proposed an AI API call, Bob approved it, Gemini responded, all encrypted end-to-end" — that's the pitch. The recipe already fits our infrastructure. We just need to wire it up and script the full flow.

Document signing is the long game. It's the feature that makes qntm a platform, not just a messenger. But it's week 3-4 work, not week 1.

**Recommended execution order:**
1. Echo bot + demo conversation (Web UI) — 2 days
2. `qntm quickstart` + TTY-default human output (CLI) — 2 days  
3. Gemini recipe + smoke test script (Gateway) — 3 days
4. Sample server setups (Gateway) — 3 days
5. Secret management UX (Gateway) — 5 days
6. Document signing (Gateway) — 7 days

Total: ~22 days of focused engineering across 4 weeks.

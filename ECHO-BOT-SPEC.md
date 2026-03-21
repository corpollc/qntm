# Echo Bot — Technical Design Specification

**Author:** CTO, qntm  
**Date:** 2026-03-21  
**Status:** Draft  
**Priority:** #1 Feature

---

## 1. Goal

When a new visitor opens `chat.corpo.llc`, they are in a live conversation with an echo bot within **<10 seconds**. The bot echoes their message back with an encryption proof, demonstrating qntm's end-to-end encryption in a zero-friction experience.

**Response format:**
```
🔒 Echo: {message} (e2e encrypted, verified by kid:{sender_kid[:8]})
```

---

## 2. Architecture Decision

### Recommendation: **Cloudflare Worker with Durable Object** (echo-bot-worker)

| Option | Pros | Cons | Verdict |
|--------|------|------|---------|
| CF Worker + DO | Always-on via WebSocket hibernation in DO; same infra as relay; zero cold-start for subscribers; auto-scales; no server to manage | Must port crypto to CF runtime (Web Crypto API); key stored as DO storage or CF secret | **✅ Selected** |
| Python daemon | Existing `python-dist` client; easy to prototype | Requires persistent hosting; single point of failure; needs process supervision; latency for new messages depends on poll interval | ❌ |
| Hybrid (CF Worker triggers Python) | Could use Python for crypto | Over-engineered; adds latency; two deployments | ❌ |

**Key insight:** The relay worker already runs the full `@corpollc/qntm` TypeScript client library in Cloudflare Workers. The echo bot worker can import the same library. The `ConversationSequencerDO` already supports WebSocket subscriptions with message replay — the bot simply subscribes like any other client.

### Deployment Topology

```
┌─────────────────┐     WebSocket /v1/subscribe      ┌─────────────────────────┐
│  echo-bot-worker │ ◄──────────────────────────────► │  qntm-dropbox (relay)   │
│  (CF Worker + DO)│ ──── POST /v1/send ────────────► │  inbox.qntm.corpo.llc   │
│                  │                                   │                         │
│  EchoBotDO       │                                   │  ConversationSequencerDO │
│  (1 instance,    │                                   │  (per-conversation)      │
│   singleton by   │                                   └─────────────────────────┘
│   conv_id name)  │
└─────────────────┘

┌─────────────────────┐
│  chat.corpo.llc     │  ← New visitor auto-joins demo convo
│  (React UI)         │     via hardcoded invite token
└─────────────────────┘
```

---

## 3. Identity Management

### 3.1 Keypair Generation

The echo bot has a **single, long-lived Ed25519 identity** generated once during initial setup.

```typescript
// One-time bootstrap script (run locally, not in production)
import { generateIdentity, keyIDFromPublicKey, serializeIdentity } from '@corpollc/qntm';

const botIdentity = generateIdentity();
// botIdentity.privateKey: Uint8Array (64 bytes — Ed25519 seed+pub concatenation)
// botIdentity.publicKey:  Uint8Array (32 bytes)
// botIdentity.keyID:      Uint8Array (16 bytes — Trunc16(SHA-256(publicKey)))
```

### 3.2 Storage

The bot's private key is stored as a **Cloudflare Worker secret** (never in code or KV):

| Secret Name | Format | Content |
|---|---|---|
| `BOT_PRIVATE_KEY` | hex string (128 chars) | Ed25519 private key (64 bytes) |
| `BOT_PUBLIC_KEY` | hex string (64 chars) | Ed25519 public key (32 bytes) |

Set via:
```bash
echo "<hex>" | wrangler secret put BOT_PRIVATE_KEY --name qntm-echo-bot
echo "<hex>" | wrangler secret put BOT_PUBLIC_KEY --name qntm-echo-bot
```

The DO reconstructs the `Identity` struct on each wake:
```typescript
function loadBotIdentity(env: Env): Identity {
  const privateKey = hexToBytes(env.BOT_PRIVATE_KEY);  // 64 bytes
  const publicKey = hexToBytes(env.BOT_PUBLIC_KEY);     // 32 bytes
  const keyID = keyIDFromPublicKey(publicKey);           // 16 bytes
  return { privateKey, publicKey, keyID };
}
```

### 3.3 Rotation

Key rotation is manual and infrequent (the bot has no long-term secret material worth rotating frequently — it only echoes). Rotation procedure:

1. Generate new identity locally
2. Update CF secrets
3. Re-run conversation bootstrap to add new identity as participant
4. Deploy new worker version (DO will restart and pick up new secrets)

---

## 4. Demo Conversation Setup

### 4.1 Bootstrap Procedure (One-Time)

A **bootstrap script** (`scripts/bootstrap-echo-bot.ts`) runs once to:

1. Generate the bot's identity keypair (if not already generated)
2. Create an invite (calling `createInvite(botIdentity, 'direct')`)
3. Derive conversation keys (`deriveConversationKeys(invite)`)
4. Create the conversation object (`createConversation(invite, keys)`)
5. Serialize and output:
   - The **invite token** (base64url-encoded CBOR) — this becomes the well-known token
   - The **conversation ID** (hex) — hardcoded into the echo bot worker config
   - The **conversation keys** (hex) — stored as CF secrets
   - The bot's private/public key (hex) — stored as CF secrets

### 4.2 Well-Known Invite Token

The invite token is a **build-time constant** embedded in both:
- The echo bot worker (`wrangler.toml` vars or hardcoded)
- The web UI (`ui/aim-chat/src/constants/demo.ts`)

Because the token encodes the `invite_secret` and `invite_salt`, anyone who has it can derive the conversation AEAD keys — this is by design for a public demo conversation.

### 4.3 Conversation Secrets (Worker)

| Secret / Var | Format | Purpose |
|---|---|---|
| `DEMO_CONV_ID` | hex (32 chars) | Conversation ID (16 bytes) |
| `DEMO_CONV_AEAD_KEY` | hex (64 chars) | AEAD encryption key (32 bytes) |
| `DEMO_CONV_NONCE_KEY` | hex (64 chars) | Nonce derivation key (32 bytes) |
| `DEMO_CONV_ROOT_KEY` | hex (64 chars) | Root key (32 bytes) |
| `DEMO_INVITE_TOKEN` | base64url string | Full invite token for the demo convo |

These are set as `wrangler secret` values, not `[vars]`, because they contain keying material.

---

## 5. Message Flow

### 5.1 Subscription Model

The echo bot uses a **Durable Object (`EchoBotDO`)** that maintains a persistent WebSocket subscription to the relay's `/v1/subscribe` endpoint for the demo conversation.

```
EchoBotDO lifecycle:
  1. alarm() fires (every 30s heartbeat, or on first creation)
  2. If no active WebSocket → connect to relay via /v1/subscribe
  3. On incoming WebSocket frame (type: "message"):
     a. Deserialize envelope (deserializeEnvelope)
     b. Decrypt message (decryptMessage with demo conv keys)
     c. Check: is sender == bot's own keyID? → skip (don't echo self)
     d. Extract plaintext body and sender_kid
     e. Construct echo response text
     f. Create encrypted envelope (createMessage)
     g. Serialize and POST to relay /v1/send
  4. On WebSocket close → schedule alarm for reconnect
```

### 5.2 Detailed Decrypt → Echo → Encrypt Flow

```typescript
// Inside EchoBotDO.handleIncomingMessage(envelope_b64: string)

async handleIncomingMessage(envelopeB64: string): Promise<void> {
  const identity = loadBotIdentity(this.env);
  const conversation = this.getDemoConversation();  // Returns Conversation struct

  // 1. Deserialize
  const rawBytes = base64ToUint8(envelopeB64);
  const envelope = deserializeEnvelope(rawBytes);

  // 2. Decrypt
  let message;
  try {
    message = decryptMessage(envelope, conversation);
  } catch {
    return; // Can't decrypt — ignore (could be from before bot joined)
  }

  // 3. Skip self-echo
  const senderKid = message.inner.sender_kid;
  if (uint8ArrayEquals(senderKid, identity.keyID)) {
    return;
  }

  // 4. Extract plaintext
  const bodyType = message.inner.body_type;
  if (bodyType !== 'text') {
    return; // Only echo text messages
  }
  const plaintext = new TextDecoder().decode(message.inner.body);
  const senderKidHex = bytesToHex(senderKid);

  // 5. Construct echo
  const echoText = `🔒 Echo: ${plaintext} (e2e encrypted, verified by kid:${senderKidHex.slice(0, 8)})`;

  // 6. Encrypt
  const echoBody = new TextEncoder().encode(echoText);
  const echoEnvelope = createMessage(
    identity,
    conversation,
    'text',
    echoBody,
    undefined,
    defaultTTL(),
  );

  // 7. Send
  const serialized = serializeEnvelope(echoEnvelope);
  const dropbox = new DropboxClient(this.env.DROPBOX_URL);
  await dropbox.postMessage(conversation.id, serialized);
}
```

### 5.3 Sequence Tracking

The DO persists `last_seq` in Durable Object storage so reconnections resume from the correct position:

```typescript
// On message received with seq N:
await this.ctx.storage.put('last_seq', seq);

// On reconnect:
const fromSeq = (await this.ctx.storage.get<number>('last_seq')) ?? 0;
// → pass to /v1/subscribe?from_seq={fromSeq}
```

### 5.4 Rate Limiting / Abuse Prevention

- **Self-echo guard:** Always skip messages where `sender_kid === bot.keyID`
- **Rate limit:** Max 1 echo per sender per second (tracked in DO memory)
- **Message length cap:** Truncate echoed messages to 500 chars
- **Body type filter:** Only echo `text` body types; ignore `gate.*`, `gov.*`, `group_*` system messages

---

## 6. Web UI Changes

### 6.1 New File: `ui/aim-chat/src/constants/demo.ts`

```typescript
/**
 * Demo conversation configuration.
 * The invite token is public — it lets anyone join the demo echo conversation.
 */
export const DEMO_INVITE_TOKEN = '<base64url invite token from bootstrap>';
export const DEMO_CONVERSATION_NAME = 'Echo Bot Demo';
export const DEMO_ENABLED = true;
```

### 6.2 Changes to `ui/aim-chat/src/App.tsx`

**Auto-join logic** added to `initializeProfiles()`:

After profile creation/loading, check if the user already has the demo conversation. If not, auto-join:

```typescript
// In initializeProfiles(), after profiles are loaded:
if (DEMO_ENABLED) {
  const convos = store.listConversations(nextActiveId);
  const demoConvExists = convos.some(c => c.inviteToken === DEMO_INVITE_TOKEN);

  if (!demoConvExists) {
    try {
      const result = qntm.acceptInviteForProfile(
        nextActiveId,
        DEMO_INVITE_TOKEN,
        DEMO_CONVERSATION_NAME,
      );
      // Select the demo conversation as the active one
      setSelectedConversationId(result.conversationId);
    } catch {
      // Non-fatal — user can still manually join
    }
  }
}
```

**Key detail:** `acceptInviteForProfile` is synchronous crypto (no network call). It:
1. Deserializes the invite token → gets `conv_id`, `invite_secret`, `invite_salt`
2. Derives conversation keys locally
3. Stores the conversation in localStorage

This takes **<50ms** — well within the 10-second budget. The WebSocket subscription then auto-connects (existing `useEffect` on `subscriptionConversationIds`).

### 6.3 Changes to `ui/aim-chat/src/components/WelcomeCard.tsx`

The `WelcomeCard` should be updated to reflect the demo experience:

```typescript
// WelcomeCard.tsx — updated to show demo conversation info when available
export interface WelcomeCardProps {
  conversationCount: number
  isWorking: boolean
  onOpenInvites: () => void
  hasDemoConversation: boolean  // NEW
}
```

When `hasDemoConversation` is true, Step 1 shows "✓ Connected to Echo Bot" and Step 2 changes to "Send a message — the bot will echo it back encrypted."

### 6.4 Changes to `ui/aim-chat/src/store.ts`

**No changes required.** The existing `addConversation`, `findConversation`, and invite token storage already support everything needed. The demo conversation is stored identically to any user-created conversation.

### 6.5 Invite Token Matching

To detect whether the demo conversation already exists, we match on the stored `inviteToken` field (already persisted in `StoredConversation`). We could also match on `conv_id` derived from the token, but `inviteToken` is simpler and already stored.

---

## 7. Deployment

### 7.1 New Worker: `echo-bot-worker/`

Directory structure:
```
echo-bot-worker/
├── src/
│   ├── index.ts          # Worker entry + EchoBotDO class
│   ├── identity.ts       # loadBotIdentity(), hex helpers
│   └── echo.ts           # handleIncomingMessage() logic
├── wrangler.toml
├── package.json
├── tsconfig.json
└── vitest.config.ts
```

### 7.2 `echo-bot-worker/wrangler.toml`

```toml
name = "qntm-echo-bot"
main = "src/index.ts"
compatibility_date = "2025-09-01"

# No custom domain — this worker has no HTTP API.
# It runs entirely via Durable Object alarms.

[[durable_objects.bindings]]
name = "ECHO_BOT_DO"
class_name = "EchoBotDO"

[[migrations]]
tag = "echo-bot-v1"
new_sqlite_classes = ["EchoBotDO"]

[vars]
DROPBOX_URL = "https://inbox.qntm.corpo.llc"
HEARTBEAT_INTERVAL_MS = "30000"

# Secrets (set via `wrangler secret put`):
# BOT_PRIVATE_KEY    — hex, 128 chars (64 bytes Ed25519 private key)
# BOT_PUBLIC_KEY     — hex, 64 chars  (32 bytes Ed25519 public key)
# DEMO_CONV_ID       — hex, 32 chars  (16 bytes conversation ID)
# DEMO_CONV_AEAD_KEY — hex, 64 chars  (32 bytes AEAD key)
# DEMO_CONV_NONCE_KEY — hex, 64 chars (32 bytes nonce key)
# DEMO_CONV_ROOT_KEY  — hex, 64 chars (32 bytes root key)
```

### 7.3 `echo-bot-worker/src/index.ts` — Entry Point

```typescript
import { DurableObject } from "cloudflare:workers";

export interface Env {
  ECHO_BOT_DO: DurableObjectNamespace;
  DROPBOX_URL: string;
  HEARTBEAT_INTERVAL_MS: string;
  BOT_PRIVATE_KEY: string;
  BOT_PUBLIC_KEY: string;
  DEMO_CONV_ID: string;
  DEMO_CONV_AEAD_KEY: string;
  DEMO_CONV_NONCE_KEY: string;
  DEMO_CONV_ROOT_KEY: string;
}

export class EchoBotDO extends DurableObject<Env> {
  // WebSocket to relay
  private ws: WebSocket | null = null;
  private rateLimits: Map<string, number> = new Map();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Schedule first alarm immediately
    ctx.storage.setAlarm(Date.now() + 100);
  }

  async alarm(): Promise<void> {
    // Ensure WebSocket is connected; reconnect if needed
    await this.ensureConnected();
    // Schedule next heartbeat
    const interval = parseInt(this.env.HEARTBEAT_INTERVAL_MS || '30000', 10);
    this.ctx.storage.setAlarm(Date.now() + interval);
  }

  async fetch(request: Request): Promise<Response> {
    // Health check / manual trigger endpoint
    const url = new URL(request.url);
    if (url.pathname === '/healthz') {
      return Response.json({ status: 'ok', connected: this.ws !== null });
    }
    if (url.pathname === '/wake') {
      await this.ensureConnected();
      return Response.json({ status: 'connected' });
    }
    return new Response('not found', { status: 404 });
  }

  private async ensureConnected(): Promise<void> { /* ... */ }
  private async handleFrame(data: string): Promise<void> { /* ... */ }
  private async handleIncomingMessage(seq: number, envelopeB64: string): Promise<void> { /* ... */ }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Route all requests to the singleton DO instance
    const id = env.ECHO_BOT_DO.idFromName('echo-bot-singleton');
    const stub = env.ECHO_BOT_DO.get(id);
    return stub.fetch(request);
  },
} satisfies ExportedHandler<Env>;
```

### 7.4 Worker Activation

The DO is a singleton (keyed by `idFromName('echo-bot-singleton')`). On first deployment, it needs a single HTTP request to wake it up and start the alarm chain:

```bash
curl https://qntm-echo-bot.<account>.workers.dev/wake
```

After that, the alarm chain self-perpetuates. The DO will:
- Wake every 30s via alarm
- Check WebSocket health
- Reconnect if disconnected
- Process incoming messages

### 7.5 Secrets Setup Checklist

```bash
# 1. Run bootstrap script to generate keys + invite
npx tsx scripts/bootstrap-echo-bot.ts

# 2. Set worker secrets
wrangler secret put BOT_PRIVATE_KEY --name qntm-echo-bot
wrangler secret put BOT_PUBLIC_KEY --name qntm-echo-bot
wrangler secret put DEMO_CONV_ID --name qntm-echo-bot
wrangler secret put DEMO_CONV_AEAD_KEY --name qntm-echo-bot
wrangler secret put DEMO_CONV_NONCE_KEY --name qntm-echo-bot
wrangler secret put DEMO_CONV_ROOT_KEY --name qntm-echo-bot

# 3. Update UI constant
# → Paste invite token into ui/aim-chat/src/constants/demo.ts

# 4. Deploy
cd echo-bot-worker && wrangler deploy
cd ../ui/aim-chat && npm run build && <deploy>

# 5. Wake the bot
curl https://qntm-echo-bot.<account>.workers.dev/wake
```

---

## 8. File-by-File Implementation Plan

### New Files

| # | File | Purpose | Complexity |
|---|------|---------|------------|
| 1 | `echo-bot-worker/package.json` | Dependencies: `@corpollc/qntm`, `wrangler` | Trivial |
| 2 | `echo-bot-worker/tsconfig.json` | TypeScript config (mirror `gateway-worker/`) | Trivial |
| 3 | `echo-bot-worker/wrangler.toml` | Worker + DO config (see §7.2) | Low |
| 4 | `echo-bot-worker/vitest.config.ts` | Test config | Trivial |
| 5 | `echo-bot-worker/src/index.ts` | Worker entry, `EchoBotDO` class, alarm loop, WebSocket management | **High** — core logic |
| 6 | `echo-bot-worker/src/identity.ts` | `loadBotIdentity(env)`, `getDemoConversation(env)`, hex utils | Low |
| 7 | `echo-bot-worker/src/echo.ts` | `handleIncomingMessage()` — decrypt, build echo, encrypt, send | **Medium** — uses qntm client APIs |
| 8 | `scripts/bootstrap-echo-bot.ts` | One-time script: generate identity, create invite, output secrets | Medium |
| 9 | `ui/aim-chat/src/constants/demo.ts` | `DEMO_INVITE_TOKEN`, `DEMO_CONVERSATION_NAME`, `DEMO_ENABLED` | Trivial |

### Modified Files

| # | File | Change | Complexity |
|---|------|--------|------------|
| 10 | `ui/aim-chat/src/App.tsx` | Add auto-join logic in `initializeProfiles()` (~15 lines) | Low |
| 11 | `ui/aim-chat/src/components/WelcomeCard.tsx` | Add `hasDemoConversation` prop, update copy for demo flow | Low |

### Files NOT Modified

- `worker/src/index.ts` (relay) — no changes needed; the bot uses existing `/v1/subscribe` and `/v1/send` APIs
- `client/src/*` — no changes needed; all required crypto functions already exported
- `ui/aim-chat/src/store.ts` — no changes needed; existing conversation storage works
- `ui/aim-chat/src/qntm.ts` — no changes needed; `acceptInviteForProfile` already handles token-based join
- `ui/aim-chat/src/api.ts` — no changes needed; existing `acceptInvite` flow works

---

## 9. Risk / Complexity Assessment

### What's Easy ✅

| Item | Why |
|------|-----|
| **UI auto-join** | `acceptInviteForProfile()` already exists and is pure local crypto. Just call it on load. 15 lines of code. |
| **Invite token generation** | `createInvite()` + `inviteToToken()` already work. Bootstrap script is straightforward. |
| **Message encryption/decryption** | `createMessage()` and `decryptMessage()` are battle-tested in the existing UI and gateway worker. |
| **Relay communication** | `DropboxClient` already supports both `postMessage()` and `subscribeMessages()`. The bot uses the same client. |
| **Identity from secrets** | Just hex-decode two environment variables → reconstruct `Identity` struct. |

### What's Medium 🟡

| Item | Why | Mitigation |
|------|-----|------------|
| **DO WebSocket lifecycle** | Durable Object WebSocket hibernation has quirks: the DO must handle reconnections, the relay closing the socket, and alarm-driven health checks. | Follow the pattern from `gateway-worker/src/do.ts` which already manages a similar relay subscription. |
| **@corpollc/qntm in CF Worker** | The client library uses `@noble/hashes` which should work in CF Workers, but needs verification that all crypto primitives (Ed25519 sign/verify, HKDF, ChaCha20-Poly1305) work in the CF runtime. | The `gateway-worker` already imports `@corpollc/qntm` successfully — confirms compatibility. |
| **Conversation epoch tracking** | If the demo conversation ever gets rekeyed (group_rekey), the bot needs to handle epoch transitions. For a simple demo conversation this is unlikely but should be handled gracefully. | For v1: catch decryption failures silently. The demo convo is `direct` type with epoch 0 — rekey won't happen unless explicitly triggered. |

### What's Hard 🔴

| Item | Why | Mitigation |
|------|-----|------------|
| **Multi-participant key derivation** | Every visitor joins with the same invite token, so they all derive the same AEAD keys. This means all visitors can read all messages in the demo conversation. This is **by design** for a demo, but must be clearly communicated. | Add a banner in the UI: "This is a public demo conversation. Messages are encrypted but visible to all demo participants." |
| **Durable Object singleton reliability** | If the DO hits its memory limit or crashes, the alarm chain restarts it, but there may be a gap. CF DOs have a 128MB memory limit and 30s CPU time per request. | Keep DO state minimal (only `last_seq` persisted). Rate limit map is in-memory and resets on DO restart — acceptable. |
| **Demo conversation key exposure** | The invite token (containing `invite_secret`) is embedded in the UI source code. An attacker could extract it and spam the conversation. | Rate limiting on the relay (already 500 req/min per IP). Rate limiting in the echo bot (1 echo/sender/sec). The demo conversation is ephemeral by nature — messages expire after 7 days (relay TTL). Consider: add a `/v1/send` rate limit per `conv_id` on the relay for additional protection. |

### Non-Risks

- **Privacy:** The demo conversation is explicitly public. No user expects privacy in a demo echo channel.
- **Key compromise:** The bot's private key only signs echo messages. Compromise means an attacker can send messages as the bot — annoying but not catastrophic. Rotation is simple (update CF secrets + redeploy).
- **Scale:** A single DO instance can handle hundreds of concurrent subscribers. The echo bot only processes one conversation. If needed, CF auto-handles DO placement globally.

---

## 10. Open Questions

1. **Should the demo conversation auto-expire messages faster?** Currently relay TTL is 7 days. For a demo, 24 hours might be cleaner. Could set a per-conversation TTL in the relay, but that requires a relay change.

2. **Should visitors see each other's messages?** With a shared invite token, yes — all participants share the same AEAD keys. This could be confusing. Alternative: generate a unique conversation per visitor (but then the bot needs to manage N conversations, significantly increasing complexity). **Recommendation for v1:** shared conversation with a clear "public demo" banner.

3. **Should the bot have a display name?** Currently, senders are identified by `kid` hex. The UI's contact alias system could auto-set the bot's kid → "Echo Bot" alias. This could be done in the auto-join flow by calling `store.setContact(profileId, botKidHex, 'Echo Bot')`.

4. **Custom domain for echo-bot-worker?** Not required — the worker has no public HTTP API. The `/wake` endpoint is only for initial activation and could be behind CF Access if desired.

---

## 11. Implementation Order

1. **`scripts/bootstrap-echo-bot.ts`** — Generate keys and invite token (blocks everything else)
2. **`echo-bot-worker/`** — Core worker with DO, WebSocket subscription, echo logic
3. **`ui/aim-chat/src/constants/demo.ts`** — Embed invite token
4. **`ui/aim-chat/src/App.tsx`** — Auto-join logic
5. **`ui/aim-chat/src/components/WelcomeCard.tsx`** — Updated demo copy
6. **Deploy + test end-to-end**

Estimated implementation time: **2–3 days** for a senior engineer familiar with the codebase.

---

## 12. Success Criteria

- [ ] New visitor at `chat.corpo.llc` sees a conversation named "Echo Bot Demo" within 3 seconds of page load
- [ ] Sending "hello" returns `🔒 Echo: hello (e2e encrypted, verified by kid:abcd1234)` within 2 seconds
- [ ] Bot correctly ignores its own echoed messages (no infinite loop)
- [ ] Bot survives relay restarts (reconnects via alarm)
- [ ] Bot handles malformed/expired messages gracefully (no crashes)
- [ ] Multiple concurrent visitors can all send and receive echoes

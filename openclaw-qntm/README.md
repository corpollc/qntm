# qntm OpenClaw Plugin

`openclaw-qntm` is an OpenClaw channel plugin for qntm relay conversations. It subscribes to multiple qntm conversations at once, decrypts inbound relay traffic, and routes replies back to the originating conversation.

## Install from this checkout

The unreleased adapter targets **OpenClaw 2026.9.3** and uses its actual public SDK in tests and typechecking. Use Node **24.16.0 or later in the 24.x line**, or **26.1.0+**. Earlier OpenClaw versions are not covered by this adapter's current host test; upgrade the host before installing this revision.

From the repository root:

```bash
npm --prefix client ci
npm --prefix client run build
cd openclaw-qntm
npm ci --ignore-scripts
npm run pack:plugin
openclaw plugins install --force --accept-capabilities ./dist/qntm-0.1.0.tgz
openclaw plugins doctor
```

The archive bundles this checkout's built qntm client and its runtime dependencies. Installing the development directory directly leaves a `file:../client` symlink outside the plugin boundary, which current OpenClaw's install scanner rejects. Review the generated archive as local plugin code; `--force` acknowledges its non-ClawHub source, and does not disable the scanner. Configure the channel below, then restart the OpenClaw gateway.

The generated manifest exposes the channel schema before runtime loading and marks private identities and invite tokens as sensitive in setup surfaces. Regenerate it with `npm run build:manifest` after changing the Zod schema. See OpenClaw's [channel configuration contract](https://docs.openclaw.ai/plugins/sdk-channel-plugins) for the host metadata surface.

## What It Does

- Opens one relay websocket subscription per enabled qntm conversation binding
- Atomically persists current keys, authenticated conversation state, pending delivery and cursor per account/conversation
- Recovers pending host delivery after restart, including a failure before OpenClaw accepts ownership
- Routes direct chats according to OpenClaw `session.dmScope` semantics
- Sends agent replies back through qntm's encrypted `postMessage` path
- Falls back to attachment URL text when OpenClaw asks to send media

## Configuration

Add the plugin to an OpenClaw extensions install and configure `channels.qntm` with either invite tokens or an OpenClaw-owned qntm profile directory. Inbound delivery is relay-websocket based; this plugin does not expose a webhook receiver.

```json
{
  "channels": {
    "qntm": {
      "defaultAccount": "default",
      "accounts": {
        "default": {
          "enabled": true,
          "relayUrl": "https://inbox.qntm.corpo.llc",
          "identityDir": "/Users/pv/.openclaw/qntm/default",
          "defaultTo": "ops",
          "conversations": {
            "alice": {
              "convId": "be96bcc53fa787c1f6cfc1f20afc0049",
              "name": "Alice"
            },
            "ops": {
              "convId": "0050a49f0b2e738063a89621d1c9b055",
              "name": "Ops Room"
            }
          }
        }
      }
    }
  }
}
```

## Runtime Notes

- `identityDir` reads `identity.json` and `conversations.json` from a dedicated qntm profile directory managed for OpenClaw.
- `convId` bindings require `identityDir` because the plugin must load the matching conversation keys from that profile directory.
- Invite-token bindings are still supported via `identity` or `identityFile`.
- Each configured binding is addressed by either its binding key, such as `ops`, or the raw qntm `conv_id`.
- Direct-conversation session collapse/isolation is controlled by OpenClaw `session.dmScope`. With the default `main`, qntm DMs share `agent:main:main`; use `per-channel-peer` or `per-account-channel-peer` if you want isolated qntm DM sessions.
- Current state and the delivery queue are stored in the plugin's private account directory; see the storage and recovery notes below.
- `trigger: "mention"` requires at least one matching `triggerNames` entry to wake the agent. Authenticated protocol controls still update keys and membership when no mention matches.
- Outbound media is flattened into text lines like `Attachment: https://...` because qntm currently only exposes text sends through this plugin path.

## Protocol Compatibility

| qntm capability | Status | Notes |
|-----------------|:------:|-------|
| Text conversations | ✅ | Inbound decrypt + outbound reply are implemented. |
| Multiple bound conversations | ✅ | One relay subscription and cursor per enabled binding. |
| Rekey, removal and replay | ✅ | Shared authenticated reducer; current keys and removal survive restart. Replies use the latest keys and refuse a removed local identity. |
| Non-text `body_type` ingest | Partial | Gateway events are verified by the shared reducer, then delivered as untrusted contextual text like `[gate.request] ...`. No gateway action tool yet. |
| qntm API Gateway `gate.*` actions | ❌ | The plugin does not create or submit `gate.request`, `gate.approval`, `gate.disapproval`, `gate.promote`, `gate.secret`, or related message types. |
| Media attachments | Partial | OpenClaw media sends are flattened into attachment URLs inside a text message. |

## Local Verification

```bash
cd openclaw-qntm
npm test
npm run typecheck
npm run check:manifest
npm run test:host
```

`test:host` installs a packaged plugin into a fresh temporary OpenClaw state directory. It starts the actual pinned host with a local wire-level relay fixture and checks encrypted direct/group replies, rekey/replay and removal across restart. It also locks the disposable host's session database to force admission failure, verifies qntm retained the message after advancing its relay cursor, kills the host with `SIGKILL`, and confirms delivery after restart without resending. A separate test-only reply hook returns deterministic text before model invocation; this test requires no provider key and does not exercise a model's judgment. It leaves existing OpenClaw configuration and conversations untouched. CI runs this check on Node 24. Set `QNTM_KEEP_HOST_SMOKE=1` only when you need the disposable state for diagnosis.

Unit tests also cover disk-full rollback, failed checkpoint writes, stale claim ownership, duplicate admission, bounded storage, strict identity parsing, delayed replies across rekeys, and removal while a reply is in flight. Structured outbound gateway actions remain follow-up work.

## Local storage, privacy and recovery

The base directory is `OPENCLAW_STATE_DIR`, or `~/.openclaw` when unset. qntm owns `plugins/qntm/accounts/<account>/` beneath it. New account/conversation directories use mode `0700`; checkpoint and SQLite files use `0600`. These are local file permissions, **not encryption at rest**. The plugin uses its own SQLite database and public OpenClaw dispatch lifecycle; local archive installation does not require access to OpenClaw's registry-trusted plugin state API.

| File | Contents and retention |
| --- | --- |
| `conversations/<conv_id>.json` | Current conversation keys/epoch, creation date/type, participant IDs and known public keys, signed gateway invitation/context, verified gateway workflow history, removal status, relay/legacy cursors, initial configuration hash, identity key ID, exact replay IDs/digests, and up to 64 pending plaintext deliveries. Current state remains until the operator removes it. No prior epoch keys are retained. Replay history is capped at 8,192 IDs; workflow history at 4,096 events and approximately 8 MiB. The complete file is capped at 16 MiB. |
| `ingress.sqlite` and SQLite sidecars | Pending/claimed/failed plaintext deliveries: conversation and message IDs, sender key ID/public key, epoch, creation time, body type/text and gateway-verification flag; queue account/channel, lane, arrival/update/attempt timestamps, attempt counts and claim token/owner/heartbeat. Host exceptions are replaced by fixed failure strings. At most 1,024 pending/claimed events are admitted; full storage retains the checkpoint outbox and applies backpressure. Pending work has no time-based expiry. |
| Completed/failed queue records | A completed row drops its plaintext payload when OpenClaw durably adopts the turn, or when a synchronous dispatch completes. Completed IDs are retained for seven days, capped at 8,192; failed records retain their payload for seven days, capped at 1,024. Pruning runs at startup and approximately hourly while the monitor runs. The SQLite main file has a 65,536-page limit (256 MiB with its default page size); sidecars and checkpoint files are additional storage. |

Plaintext delivery text is limited to 64 KiB. Queue deletion and payload clearing are logical operations: SQLite journals, filesystem snapshots and backups can retain earlier data. OpenClaw's own sessions, transcripts, logs, hooks and model-provider calls have separate visibility and retention; qntm's limits do not delete those copies. The relay and dashboard do not receive this local state. See the [metadata inventory](../docs/metadata-privacy.md).

Configured invite tokens or source profiles can still contain initial conversation keys. Updating the checkpoint does not rewrite or erase that source configuration.

Protocol state, cursor and pending delivery commit together before queue admission. Queue admission is idempotent by conversation/message ID, and a claim token prevents a stale worker from completing a newer claim. A failed host dispatch remains retryable; after repeated failures, the pinned host's retry policy can move it to the failed queue. Operators should inspect `lastError`, preserve the private account directory for diagnosis, and resolve the underlying storage/host failure. There is no shipped failed-record repair/resubmission command yet. Back up a stopped host's entire account directory, or use a consistent SQLite backup; copying just the live `.sqlite` file can omit its WAL.

This is durable, at-least-once handoff, not exactly-once external effects. After OpenClaw adopts a turn, its recovery owns that turn. A crash around adoption, expired deduplication records, or an uncertain relay POST can still require reconciliation. An unknown reply-send outcome is reported as such.

Existing `cursors/<conv_id>.json` files are read as migration hints. Without `OPENCLAW_STATE_DIR`, their old location is `~/.openclaw/state/plugins/qntm/...`. Available protocol history is replayed to establish keys/membership, while deliveries at or below the legacy cursor do not wake the agent. If required rekey history has expired, a cursor cannot reconstruct it; provide a current conversation profile. Malformed state and identity/configuration mismatches fail closed rather than resetting the cursor. Keep one writer per profile, and preserve both checkpoint and queue when moving state.

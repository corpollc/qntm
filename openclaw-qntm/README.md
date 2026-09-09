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
- Persists an independent cursor per account and conversation
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
- Cursor state is stored under `OPENCLAW_STATE_DIR/plugins/qntm/accounts/<account>/cursors/<conv_id>.json`, or `~/.openclaw/state/plugins/qntm/...` when `OPENCLAW_STATE_DIR` is unset.
- Outbound media is flattened into text lines like `Attachment: https://...` because qntm currently only exposes text sends through this plugin path.

## Protocol Compatibility

| qntm capability | Status | Notes |
|-----------------|:------:|-------|
| Text conversations | ✅ | Inbound decrypt + outbound reply are implemented. |
| Multiple bound conversations | ✅ | One relay subscription and cursor per enabled binding. |
| Non-text `body_type` ingest | Partial | Delivered to the agent as contextual text like `[gate.request] ...`, not parsed into typed workflow objects. |
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

`test:host` installs a packaged plugin into a fresh temporary OpenClaw state directory. It starts the actual pinned host with a local wire-level relay fixture, checks encrypted direct and group replies, then restarts the host and checks replay suppression. A separate test-only reply hook returns deterministic text before model invocation; this test requires no provider key and does not exercise a model's judgment. It leaves existing OpenClaw configuration and conversations untouched. CI runs this check on Node 24. Set `QNTM_KEEP_HOST_SMOKE=1` only when you need the disposable state for diagnosis.

This verifies host installation and text delivery. Structured gateway actions and durable recovery around a failed agent dispatch are still follow-up work; the successful restart test is not a claim of exactly-once delivery across crashes.

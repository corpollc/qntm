# qntm OpenClaw Plugin

`openclaw-qntm` is an OpenClaw channel plugin for qntm relay conversations. It subscribes to multiple qntm conversations at once, decrypts inbound relay traffic, and routes replies back to the originating conversation.

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
```

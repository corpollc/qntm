# qntm OpenClaw Plugin

`openclaw-qntm` is an OpenClaw channel plugin for qntm relay conversations. It subscribes to multiple qntm conversations at once, decrypts inbound relay traffic, and routes replies back to the originating conversation.

## What It Does

- Opens one relay websocket subscription per enabled qntm conversation binding
- Persists an independent cursor per account and conversation
- Routes direct chats with per-conversation session keys so separate qntm DMs do not collapse into one OpenClaw session
- Sends agent replies back through qntm's encrypted `postMessage` path
- Falls back to attachment URL text when OpenClaw asks to send media

## Configuration

Add the plugin to an OpenClaw extensions install and configure `channels.qntm` with an identity plus one or more invite tokens.

```json
{
  "channels": {
    "qntm": {
      "defaultAccount": "default",
      "accounts": {
        "default": {
          "enabled": true,
          "relayUrl": "https://inbox.qntm.corpo.llc",
          "identityFile": "/Users/pv/.openclaw/qntm-identity.txt",
          "defaultTo": "ops",
          "conversations": {
            "alice": {
              "invite": "qntm://...",
              "name": "Alice"
            },
            "ops": {
              "invite": "qntm://...",
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

- Each configured binding is addressed by either its binding key, such as `ops`, or the raw qntm `conv_id`.
- Cursor state is stored under `OPENCLAW_STATE_DIR/plugins/qntm/accounts/<account>/cursors/<conv_id>.json`.
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

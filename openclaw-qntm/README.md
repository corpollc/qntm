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

## Local Verification

```bash
cd openclaw-qntm
npm test
npm run typecheck
```

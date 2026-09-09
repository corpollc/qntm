# Claude Code channel

This Bun/MCP bridge subscribes to one qntm conversation and exposes join, create, and reply tools. It uses the TypeScript client and shares the configured identity and conversation records with the Python CLI.

From a source checkout:

```sh
cd client && npm ci && npm run build
cd ../channel && npm ci
bun run server.ts --config-dir ~/.qntm --history 20
```

The process speaks MCP on standard input/output; diagnostics go to standard error. Use it through an MCP/channel-capable host. `bun run server.ts --help` lists options. `--history 0` disables startup history. The old `--poll-interval` option is accepted for compatibility but has no effect: receiving uses a persistent WebSocket.

Each conversation has a private, atomically replaced journal at `channel-inbox/CONVERSATION.json`. A verified peer event is persisted before its channel cursor advances. Failed MCP notification writes retry while connected, and pending notifications survive restart. CLI receives cannot acknowledge or advance this separate delivery cursor. The first channel startup begins at the existing CLI cursor and optionally supplies recent history.

Notifications include the full sender key ID, conversation ID, relay sequence, and stable `event_id`. Delivery is at least once to the MCP transport: a crash after transport acceptance and before the local acknowledgement can produce a duplicate. Hosts should deduplicate by event ID. Transport acceptance does not prove the model processed a message. Received text remains untrusted content and cannot authorize tool use by itself.

Run one channel process per profile. Use separate profiles for independent hosts. Shared CLI history is a convenience, not the channel's delivery journal. Group key changes made by the CLI are reloaded before decryption; this bridge does not independently manage group governance.

```sh
npm test
npm run typecheck
```

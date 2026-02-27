# qntm AIM Chat UI

A Vite + React chat interface that drives `qntm` messaging from a local API bridge.

## What it does

- AIM-style chat layout (buddy/room list + message pane)
- Multiple identity profiles (separate `--config-dir` values)
- Invite create/accept workflows
- Send + receive/poll messages through `qntm`
- Local history per profile and conversation
- Per-profile contact aliases for friendly sender names

## Command resolution

The API bridge runs `qntm` in this order:

1. `QNTM_BIN` env var (if set)
2. `./qntm` binary at repo root (if present)
3. `go run ./cmd/qntm`

## Run

```bash
cd ui/aim-chat
npm install
npm run dev
```

- Vite UI: `http://localhost:5173`
- API bridge: `http://localhost:8787`

## Local two-identity test

1. Open UI profile `Agent 1` and click `Generate keypair`.
2. Add profile `Agent 2` and generate keypair.
3. On `Agent 1`, click `Create + self-join`, then copy token.
4. Switch to `Agent 2`, paste token, click `Accept invite`.
5. Pick the conversation on both profiles and chat.

## Testing with an LLM process

Use one profile in this UI and another process (CLI or your LLM agent runtime) with a different `--config-dir` but the same storage/dropbox.

- Default storage for new profiles is the hosted HTTP inbox at `https://inbox.qntm.corpo.llc`.
- For local dev storage, set `QNTM_UI_DEFAULT_STORAGE=local:/absolute/path/to/dropbox` before starting `npm run dev`.
- You can override the default HTTP inbox with `QNTM_UI_DEFAULT_DROPBOX_URL`.

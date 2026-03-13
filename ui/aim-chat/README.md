# qntm AIM Chat UI

A Vite + React AIM-style chat interface that uses `@qntm/client` directly in the browser.

## What it does

- AIM-style chat layout (buddy/room list + message pane)
- Multiple browser-local identity profiles
- Invite create/accept workflows
- Send + receive/poll messages through the dropbox relay
- Local history per profile and conversation
- Per-profile contact aliases for friendly sender names
- Gate request / approval / secret flows from the browser

There is no Express server or local API bridge anymore. The browser app uses the TypeScript library directly for identity, invite, encryption, decryption, and gate message signing.

## Run

```bash
cd ui/aim-chat
npm install
npm run dev
```

- Vite UI: `http://localhost:5173`
- Production build: `npm run build`
- Tests: `npm test`

## Storage

- Identities, conversation keys, history, and contact aliases are stored in browser `localStorage`.
- The default relay URL is `https://inbox.qntm.corpo.llc`.
- You can change the relay URL from the in-app Settings panel.

## Security model

- Private keys and conversation keys remain in the browser; they are not sent to an app server.
- Those secrets are still recoverable by any script that can execute on the same origin, so treat the browser profile as sensitive.
- The app ships with a restrictive Content Security Policy to reduce script-injection risk, but that does not make `localStorage` equivalent to hardware-backed key storage.
- For higher-trust deployments, use a dedicated browser profile and consider a future move to WebCrypto non-exportable keys + IndexedDB.

## Local two-identity test

1. Open UI profile `Agent 1` and click `Generate keypair`.
2. Add profile `Agent 2` and generate keypair.
3. On `Agent 1`, click `Create invite`, then copy the token.
4. Switch to `Agent 2`, paste token, click `Accept invite`.
5. Pick the conversation on both profiles and chat.

## Testing with an LLM process

Use one profile in this UI and another process (CLI or your LLM agent runtime) against the same dropbox relay.

- The browser profile and the CLI keep separate local state.
- Share invite tokens between them out of band.
- For local relay development, point the UI Settings panel at your local relay URL.

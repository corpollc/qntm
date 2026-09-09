# qntm AIM Chat UI

A Vite + React AIM-style chat interface that uses `@corpollc/qntm` directly in the browser.

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

From the repository root, build the local TypeScript dependency first:

```bash
npm --prefix client ci
npm --prefix client run build
cd ui/aim-chat
npm ci
npm run dev
```

- Vite UI: `http://localhost:5173`
- Production build: `npm run build`
- Preview that build locally: `npm run preview`
- Tests: `npm test`

The checked-in lockfile includes platform-specific Rollup packages. Local builds, CI and the Pages deployment use `npm ci`; do not install a separate Linux binary or modify dependencies during deployment. The static `dist/` artifact uses the domain root (`/`) and HashRouter routes. A custom-domain cutover is a separate deployment step.

For the production Pages project, credentials, deployment triggers, preview behavior and rollback, see the [AIM deployment runbook](../../docs/aim-deploy.md).

## Storage

- Identities, conversation keys, history, and contact aliases are stored in browser `localStorage`.
- The default relay URL is `https://inbox.qntm.corpo.llc`.
- You can change the relay URL from the in-app Settings panel.

## Security model

- Messages are encrypted in the browser. A gateway explicitly invited to a conversation receives its keys, and invite links carry bootstrap secrets; both are deliberate key sharing.
- Those secrets are still recoverable by any script that can execute on the same origin, so treat the browser profile as sensitive.
- The hosted browser was updated on September 9, 2026: copied invite links keep their bootstrap secret in a URL fragment, which the browser does not send to the web host. The source at the 0.6.1 tag still emits query links. Older `?invite=` links remain readable but expose their token in the initial HTTP request. See the [exact metadata inventory](../../docs/metadata-privacy.md).
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

## Guidance contacts

Open **Request guidance** to configure local contacts for legal, moral/ethical, and law-enforcement questions. Review the destination, known audience, and exact message before sending. No contacts ship by default. Pins belong to each browser profile and appear in backups. See [Request guidance](../../docs/guidance.md).

**Settings → Backup & Restore** downloads password-encrypted backups and accepts validated legacy JSON files. Restore previews replacement counts, identities, relays, gateways and guidance destinations before confirmation. Local browser storage remains plaintext. See [backup format and limits](../../docs/browser-backups.md).

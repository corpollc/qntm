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

The hosted app is available at `https://chat.corpo.llc` and `https://web.qntm.corpo.llc`. Each address has separate browser storage. Existing users can stay at their original address or intentionally transfer a password-encrypted backup; see [custom domains and existing profiles](../../docs/aim-deploy.md#custom-domains-and-existing-profiles).

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

## Contact groups (unreleased)

Open **Contacts** in the sidebar to pin a known contact's full Ed25519 public
key after verifying it with them. A short key ID or a display alias is not enough.
An existing contact name cannot silently pin a different key. Removing a local
pin leaves group membership unchanged.

Choose **Create contact group**, select a pinned contact, and choose **Add to
group**. Addition grants membership, rotates the group keys and posts a signed
welcome encrypted to that identity. Share the returned **public group link**.
It contains the group ID, inviter public key and relay URL, with no secret keys
or expiry. The recipient opens it using their existing identity and confirms the
contact pin and relay before the browser contacts that relay. Multiple contacts
may open their links in a different order from their additions. Ordinary members
may add contacts; the original creator cannot be removed.

**Remove from group** rotates keys for the remaining members. A removed member's
saved checkpoint stays removed across restarts. Explicit readmission produces a
new epoch; it does not disclose messages from an interval of exclusion. New
members receive no earlier epoch keys.

**Refresh welcome** resends current keys to a still-admitted contact who missed
the welcome's delivery window. It changes no membership. If the recipient reports
missing history, paste their recovery challenge into the optional challenge
field before refreshing, then share your returned link. An old welcome reposted
at a newer relay sequence cannot answer the challenge. Refresh cannot undo a
saved removal; that requires an explicit new addition.

The browser saves an unfinished operation before posting and verifies its exact
controls through relay replay before releasing the welcome. **Retry saved
operation** resumes those exact encrypted messages after an uncertain send.
Ordinary messaging pauses during an unfinished operation, key rotation, removal,
or required recovery. The welcome signs the sender’s fully processed relay cursor as a replay anchor.
Opening its link verifies coverage from that anchor and replays retained
decryptable transitions, including a rekey posted while the welcome was being
delivered. A missing row before the welcome therefore still requires recovery.
Opening also checks the entire captured batch for unverified earlier-epoch
envelopes after that anchor. Only the exact add/rekey ciphertext signed into the
welcome is exempt. A late competing rotation therefore pauses the new member
before messages appear, without giving them pre-admission roots. A current
member can answer the recipient's saved recovery challenge with a fresh welcome,
including a corrected root at the same epoch.
Later receive batches make the same check when the saved session has no eligible
earlier key archive, and pause the whole batch before displaying its messages.

Contact groups use a dedicated authenticated receive checkpoint. Legacy invite
conversations and existing gateway conversations retain their existing flows;
this browser does not infer a trusted full roster from message senders or migrate
legacy groups automatically. Gateway promotion and governed welcome delivery for
new contact groups remain unavailable. If a competing rekey rewinds accepted
state, the browser preserves the pending operation and requests fresh recovery
instead of claiming it reconstructed missing descendants. Expired/conflicting
outbox reconciliation (`qntm-qp22`) remains a release prerequisite. The signed
anchor detects missing pre-welcome rows; it does not establish consensus about
membership against a relay that fabricates a complete-looking replay.
This source change is not a claim that the hosted 0.6.1 browser includes it.

### Browser storage and metadata

For contact groups, one `localStorage` write saves the current keys, complete
roster, exclusion/recovery state and challenge, relay cursor, pending ciphertext,
exact unfinished operation, and local decrypted history together. Web Locks
serialize writers across tabs; browsers without Web Locks cannot update contact
groups. Pending ciphertext is limited to 256 envelopes / 4 MiB. The existing
history limit remains 1,000 messages per conversation. Contact pins and per-group
relay URLs are saved locally. Password-encrypted backups preserve these fields;
restore validates the identity/key/roster/cursor relationships and previews pins,
relays and group status before replacing data. Live browser storage is not
password encrypted and remains accessible to scripts on the same origin.

The relay sees the existing conversation/message identifiers, sequence order,
outer timestamps and epoch, envelope sizes and transport metadata, plus the
`group_welcome` kind. It cannot read contact names, recipient identity, membership
roster, recovery challenge, keys or message plaintext inside the encrypted
welcome. This browser feature adds no server metrics or identity labels. The
public link uses a fragment, which is not part of the HTTP request to the web
host; opening it subsequently reveals the group ID to its configured relay.
See [the shared wire and storage design](../../docs/group-welcomes.md).

### Contact-group tests

`npm test` covers browser checkpoint persistence, reverse opening order,
member-initiated additions, missing/expired controls, replayed stale welcomes,
delayed welcomes, uncertain-send retries and backup schema validation.
`npm run test:e2e -- contact-groups.spec.ts` exercises the real browser with
TypeScript and fresh Python CLI peers, including removal/restart/readmission and
challenge recovery. Install `python-dist` in Python 3.12 first, or set
`QNTM_TEST_PYTHON` to that interpreter. Python peers always use this checkout's
`python-dist/src` via `PYTHONPATH`.

After installing `client`, `worker`, `ui/aim-chat` and `integration` dependencies,
the repeatable real-worker journey is:

```bash
cd integration
QNTM_TEST_PYTHON=/path/to/python npx vitest run browser-contact-welcome.test.ts
```

The fixture uses isolated local Worker storage, a separate Vite server, synthetic
identities and no production relay or external contacts. Deterministic missing-row
recovery is covered separately by the browser relay fixture.

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

**Refresh welcome** sends current keys to a still-admitted contact who missed
the welcome's delivery window. When the sender has complete evidence of that
contact's current admission, it sends an admission renewal containing that exact
proof. A recipient with a saved removal can open this renewal only if an explicit
new addition already admitted them after that removal. Founding members and
older checkpoints without admission evidence receive a generic refresh, which
cannot undo a saved removal. Neither operation changes membership or discloses
earlier epoch keys. If the recipient reports
missing history, paste their recovery challenge into the optional challenge
field before refreshing, then share your returned link. An old welcome reposted
at a newer relay sequence cannot answer the challenge. A renewal for an older
admission cannot undo a later removal.

The browser saves an unfinished operation before posting and verifies its exact
controls through relay replay before releasing the welcome. **Retry saved
operation** checks accepted admission evidence before posting old controls. A
completed addition with a still-current, unexpired welcome retries its exact
ciphertext, even if the bounded replay cache has evicted its controls. If the
delivery window expired or another accepted rotation changed the current keys,
retry sends a renewal only when the same exact addition still proves the
recipient's completed admission. It changes no membership and does not repeat
the obsolete controls. If the original addition is accepted but its completing
rotation expired or no longer fits the current roster, retry saves a new rotation
for that roster first. The browser installs its keys and prepares a welcome only
after authenticated relay replay proves a canonical completing rotation. It never
posts a second addition. Removal, another readmission or required recovery blocks
this repair; another unfinished membership change must complete before renewing
an already completed admission.
Saved renewals include the recipient's full key, exact admission proof and
complete expected admission map; retry checks them against the current state
before posting. Encrypted backups preserve this evidence and the original
challenge. A saved generic refresh also retries its exact valid ciphertext. If it
expires or its keys become stale, Retry authenticates its original signed box,
recipient and challenge, then saves a generic refresh of the current keys for that
same current member. It remains generic even when admission evidence is now known;
it cannot undo a recipient's saved removal. New journals record the full recipient
and optional challenge explicitly. Older single-welcome journals recover them only
from a unique authenticated box over the saved roster; ambiguous or malformed
journals remain blocked and preserved. Sender removal, recipient absence, required
recovery or an unfinished key rotation prevents replacement.
When retry replaces an old addition's welcome, it retains the original encrypted
controls and welcome, recipient, challenge, exact admission ID/digest and delivery
uncertainty once. Superseded repairs, renewals and generic refreshes are retained as a flat list of
exact encrypted envelopes and delivery counts. The evidence is limited to 256
superseded revisions and 4 MiB including the original admission archive; reaching
either limit preserves the operation and stops further sends. The archive contains
no old expected checkpoints or plaintext group roots. Each new expected checkpoint
contains the current or proposed keys with no earlier key archive; proposed keys
are never installed from a POST acknowledgement alone. Valid uncertain delivery
retries the same ciphertext. A later expiry or changed current state can create a
replacement only after rechecking the exact original admission. The optional
challenge remains bound to the signed original welcome. This also applies to
renewals issued directly through **Refresh welcome**. Fully acknowledged welcome journals can be cleared even after
later removal, recovery or expiry, without another network request.
Older draft addition journals without enough exact recipient admission evidence
remain importable but cannot use this recovery path; retry preserves them rather
than inferring whom to admit from roster differences.
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
Group history records the exact envelope digest, source epoch and persistent
display validity independently of the bounded replay cache. A verified rewind
invalidates descendant history; a replacement welcome invalidates all previous
bindings because it does not establish their lineage. Invalidated plaintext is
retained in private browser storage and encrypted backups, but hidden from the
chat and excluded from receive callbacks. An exact newly verified replay may
establish a new binding; reusing a message ID cannot restore different old text.
Older draft group history without these bindings is likewise retained privately
and hidden until verified again. Legacy conversation history is unchanged.

Contact groups use a dedicated authenticated receive checkpoint. Legacy invite
conversations and existing gateway conversations retain their existing flows;
this browser does not infer a trusted full roster from message senders or migrate
legacy groups automatically. Gateway promotion and governed welcome delivery for
new contact groups remain unavailable. If a competing rekey rewinds accepted
state, the browser preserves the pending operation and requests fresh recovery
instead of claiming it reconstructed missing descendants. Recovery and reconciliation
for other expired/conflicting operation kinds (`qntm-qp22`) remain a release prerequisite. Unknown
standalone controls from an older epoch are retained rather than posted as new
proposals. The signed
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

# qntm terminal client

The Ink client stores one local identity in `~/.qntm-human`, independently of the Python CLI's `~/.qntm` directory. Run `npm ci && npm run build` in `client/`, then `npm ci && npm start` here. Use `--config-dir <path>` for an isolated profile and `--relay-url <url>` for another relay.

`/invite [name]` creates a conversation; `/join <token-or-link>` joins one. `/help` lists commands and `/help <command>` gives details. Keyboard navigation applies only when the composer is empty, so digits in message text and IDs cannot switch conversations. Escape enters scroll mode; j/k scroll by terminal line. Gateway summaries fit the viewport; complete action details appear in a separate paged review.

## Contact groups (unreleased)

Contact groups use the matching Python client's durable receiver and operation
outbox. Install it from the same checkout before starting the terminal:

```bash
# From the repository root; choose a private environment location.
python3 -m venv .venv-tui
.venv-tui/bin/python -m pip install ./python-dist
export QNTM_TUI_PYTHON="$PWD/.venv-tui/bin/python"
cd ui/tui
npm start
```

`QNTM_TUI_PYTHON` is one executable path, not a shell command. Without it the
terminal uses `python3`. An incompatible or missing package produces a setup
message when using contact commands; legacy chat and gateway commands continue
to use the TypeScript client. Published 0.6.1 packages do not have these contact
group operations.

Verify a contact's full Ed25519 public key through your existing contact channel,
then add it to the local address book. `/identity` shows your own public key.
Names containing spaces can be quoted; a short key ID or `/alias` display label
does not substitute for a pinned address.

```text
/contact add "Alex Morgan" FULL_PUBLIC_KEY
/group create Project chat
/group add "Alex Morgan"
```

Adding admits that identity and sends its fresh group keys in a recipient-encrypted
welcome through the existing group stream. Any current ordinary member can add
a contact. Share the returned public link; the added contact opens it with
`/join <link>` or `/group open <link>`. No membership request or further approval
is needed. Contacts can open in a different order from their additions; the
receiver catches up through later rekeys before enabling sends. New members
receive no pre-admission keys or history.

| Command in the active contact group | Effect |
| --- | --- |
| `/group add <contact>` | Admit the pinned identity, rotate keys and deliver its welcome |
| `/group remove <contact>` | Remove the member and rotate keys for those remaining |
| `/group refresh <contact>` | Deliver current keys to an existing member without changing membership |
| `/group link` | Show your public locator for contacts whose welcomes you issued |
| `/group status` | Show epoch, member count, relay, unfinished operation and recovery challenge |
| `/group retry` | Check current group state and continue a saved operation |
| `/group rekey` | Finish an interrupted membership rotation |
| `/contact list` | Show full locally pinned addresses |
| `/contact remove <name>` | Delete a local pin without changing group membership |

The public link contains the group ID, inviter public key and relay URL. It
contains no encryption keys and has no expiry. A welcome has a seven-day maximum
lifetime and can disappear with relay retention. Missing that delivery window
does not end membership: a current member can issue `/group refresh <contact>`
and share their returned link. A refresh cannot undo a saved removal. Explicit
readmission requires a new addition and does not expose the interval of exclusion.
The creator cannot be removed.

An incomplete-history warning remains above the composer while sends are paused.
Use `/group status` to copy the complete recovery challenge to a current member
through your existing contact channel. That member uses:

```text
/group refresh "Alex Morgan" --challenge RECOVERY_CHALLENGE
```

Then the recovering member opens the returned public link again. The challenge
binds the signed, encrypted welcome to this recovery; reposting an old welcome
does not clear the warning. It grants no admission permission. Explicit
readmission also accepts `/group add <contact> --challenge <challenge>`.
The supplying member must still have current membership state.

Pending operations, missing history, unfinished rotation and saved removal all
block sends in the receiver, even if a terminal view is stale. A failed operation
keeps its saved ciphertext for `/group retry`; do not delete the profile to retry.
If creation was interrupted, select its group from the sidebar and inspect
`/group status`. Conflicting or expired operations may require further recovery;
retry does not invent a new membership decision.

One resident `recv --watch` process keeps a WebSocket subscription open per
contact group. It reconnects on network failures and shares locked state with
one-shot commands. `/quit`, Ctrl-C and normal process termination stop these
receivers. An unexpected receiver exit is shown in chat; restart the terminal
to resume. There is no polling daemon to install and no incoming-message hook
that can authorize membership changes.

Ordinary contact groups and legacy/gateway groups retain separate authenticated
state. Automatic migration of old groups and gateway promotion of a contact
group are not implemented yet. Existing gateway conversations keep the review
and governance flows below. See [the shared welcome design](../../docs/group-welcomes.md)
for protocol boundaries and remaining conflict-recovery work.

## Gateway actions (unreleased)

Gateway authority comes from the participant's signed invitation and the gateway's matching signed acceptance in chat. Received requests cannot choose the trusted gateway, policy, or signer roster.

| Command | Effect |
| --- | --- |
| `/gate` | Inspect accepted identity, policy, and verified request/proposal states |
| `/gate invite https://gateway.corpo.llc 2` | Prepare an invitation with a request approval floor of 2 |
| `/gate retry` | Resubmit a saved sealed HTTP bootstrap after delivery failure |
| `/request <json-file>` | Prepare a signed API request |
| `/approve <request-id-prefix>` | Review a pending request and prepare your approval |
| `/disapprove <request-id-prefix>` | Review withdrawal of your vote |
| `/secret <json-file>` | Prepare a credential sealed to the accepted gateway |
| `/propose <json-file>` | Prepare a policy or membership proposal |
| `/gov-approve <proposal-id-prefix>` | Review a governance approval |
| `/gov-disapprove <proposal-id-prefix>` | Review withdrawal of a governance vote |
| `/review <page>` | Read a page of the current review |
| `/confirm` | Send the reviewed action after every page has been shown |
| `/cancel` | Clear the pending action without sending it |

ID prefixes need at least four characters and must match exactly one verified subject. Approvals use the full referenced request/proposal, including its target, payload, roster, threshold, and expiry. Confirmation rechecks the current gateway, roster, policy, keys, epoch, and workflow status. A changed context, expired subject, or terminal result requires a fresh review. Typing an action command only prepares it; `/confirm` sends it. Inviting a gateway contacts the given HTTP endpoint to obtain its public identity first, but discloses conversation keys only after confirmation.

Successful sends show the encrypted message's ID in a receipt. This confirms relay submission; use `/gate` for verified gateway acceptance, votes, and execution results. While an action is running, another gateway command shows a warning and must be entered again after completion. Signed actions are never automatically retried.

HTTP admission success does not activate a gateway: its signed `gate.accept` must arrive in chat. Failed bootstrap delivery is saved for `/gate retry`, including across restart. An expired pending invitation can be replaced with a new `/gate invite`; this does not revoke any keys previously disclosed. An accepted gateway cannot be replaced through this command.

A disapproval withdraws your own vote; other participants can still approve. `approved` is a local count, not proof of execution or credential availability. Only authenticated gateway results establish execution. Credential-free service-entry behavior is unchanged; see the main README's existing demonstration.

### JSON examples

Save request options in a regular UTF-8 file (maximum 64 KiB):

```json
{
  "service": "example",
  "endpoint": "/records",
  "verb": "POST",
  "targetUrl": "https://api.example.test/records",
  "payload": { "name": "Demo" },
  "requiredApprovals": 2,
  "expiresInSeconds": 3600
}
```

Then use `/request /absolute/path/request.json`. The `.test` destination above is illustrative; choose a service and endpoint your gateway supports. Optional `recipeName` and `arguments` describe the request, but this command does not resolve a recipe catalog for you.

For a credential, use a private file with mode `0600`:

```json
{
  "service": "example",
  "value": "your-service-credential",
  "headerName": "Authorization",
  "headerTemplate": "Bearer {value}",
  "ttl": 3600
}
```

`/secret /absolute/path/credential.json` reviews the accepted gateway public key, service, header/template, expiry, and the credential's byte length and SHA-256. It does not display the plaintext. The source file remains on disk; this is not an encrypted local credential vault. JavaScript strings and the unlocked process can contain sensitive material. Delete your source file when appropriate.

Governance options use `proposalType` plus its matching field:

```json
{ "proposalType": "floor_change", "proposedFloor": 2 }
```

Other branches are `rules_change` with `proposedRules: [{service, endpoint, verb, m}]`, `member_add` with `proposedMembers: [{kid, publicKey}]`, and `member_remove` with `removedMemberKids: [kid]`. Governance IDs and public keys use canonical base64url. Governance always needs a strict majority of current participants. Optional `requiredApprovals` can raise that quorum; `expiresInSeconds` sets the lifetime.

## Local persistence and limits

New writes use private `0600` files in a `0700` directory and atomic replacement. `conversations.json` commits current keys, verified protocol state, message history and the receive cursor together. Old `history.json` and `cursors.json` are read during migration and left on disk. A process crash before the commit replays the envelope; exact already-authenticated replay is deduplicated without keeping old keys. Send responses never advance the receive cursor. One running TUI process should own a config directory; file replacement is not a multi-process locking protocol.

Contact groups instead live in the private `contact-groups/` child profile,
using the **same identity** as the terminal. Its identity copy must match; a
different saved identity is refused. The Python receiver alone writes its
`conversations.json`, atomically saving keys, roster, decrypted history, cursor,
recovery challenge, pending ciphertext and exact outbox under process locks and
revision checks. The terminal reads that record without copying group keys or
checkpoints into its native `conversations.json`. Contact pins live in this
child profile's `contacts.json`; local display aliases remain in `store.json`.
Back up the entire terminal profile, including `contact-groups/`. Ordinary group
history is not subject to the native 1,000-message display-history limit below
and has no automatic local expiry.

Each received group event also saves its verified ciphertext digest, source epoch
and delivery eligibility. Plaintext from a superseded branch can remain in local
history for inspection, but is excluded from receive results and hooks. Valid
pending delivery survives ordinary replay-cache eviction.

Local identity, conversation keys, decrypted history, and accepted gateway checkpoints are **unencrypted at rest**. File permissions protect them from other ordinary users, not the account owner or malware. Treat this directory as sensitive; do not import someone else's checkpoint as proof of authority. History retains 1,000 display messages, 4,096 verified gateway events, and 8,192 replay digests per conversation. Missing older subjects fail verification instead of accepting unreferenced votes.

The contact-group profile and pinned names are never uploaded. The terminal adds
no relay metrics or recipient labels. The relay sees its existing conversation
locator, message ordering, timestamps, epoch, encrypted sizes and transport
metadata, plus the welcome envelope's kind; it cannot read the welcome's member
identities, roster, challenge or keys. Public links disclose the locator and
inviter public key to their holders. Opening a link contacts its named relay,
so use a link from your verified contact.

A legacy installation with only display history cannot reconstruct an accepted gateway from that text. It needs retained, verifiable invitation/acceptance envelopes and matching epoch keys. Joining an already-rekeyed conversation from an old invite remains a tracked cross-client limitation (`qntm-2g7v`). This release does not claim to recover deleted or expired relay history. Removed identities receive no future epoch key and cannot create terminal gateway actions.

Tests exercise the canonical state reducer, forged signatures and authority, exact review/cancel/send, changed-state rejection, private atomic restart recovery, real PTY input, and four-client journeys through a real relay/gateway with Python, TypeScript, and browser peers.

`npm test` also invokes Python for contact-group tests; install this checkout's
`python-dist` first or set `QNTM_TEST_PYTHON` to an installed interpreter. The
suite checks full-key pins, profile isolation, resident receiver replacement,
noncreator addition of a TypeScript peer, removal, challenged recovery and exact
retry after an outage. The opt-in real PTY/worker journey is:

```bash
# From integration/, after building client/ and ui/tui/ and installing worker/.
QNTM_TEST_PYTHON=/absolute/path/to/python npx vitest run terminal-contact-welcome.test.ts
```

It exercises both welcome opening orders, re-admission, process restart, actual
relay retention, challenged recovery and a removed terminal joiner. It records
ANSI terminal proof in the printed artifact directory and deletes test identity
and relay data at completion.

# qntm terminal client

The Ink client stores one local identity in `~/.qntm-human`, independently of the Python CLI's `~/.qntm` directory. Run `npm ci && npm run build` in `client/`, then `npm ci && npm start` here. Use `--config-dir <path>` for an isolated profile and `--relay-url <url>` for another relay.

`/invite [name]` creates a conversation; `/join <token-or-link>` joins one. `/help` lists commands and `/help <command>` gives details. Keyboard navigation applies only when the composer is empty, so digits in message text and IDs cannot switch conversations. Escape enters scroll mode; j/k scroll by terminal line. Gateway summaries fit the viewport; complete action details appear in a separate paged review.

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

Local identity, conversation keys, decrypted history, and accepted gateway checkpoints are **unencrypted at rest**. File permissions protect them from other ordinary users, not the account owner or malware. Treat this directory as sensitive; do not import someone else's checkpoint as proof of authority. History retains 1,000 display messages, 4,096 verified gateway events, and 8,192 replay digests per conversation. Missing older subjects fail verification instead of accepting unreferenced votes.

A legacy installation with only display history cannot reconstruct an accepted gateway from that text. It needs retained, verifiable invitation/acceptance envelopes and matching epoch keys. Joining an already-rekeyed conversation from an old invite remains a tracked cross-client limitation (`qntm-2g7v`). This release does not claim to recover deleted or expired relay history. Removed identities receive no future epoch key and cannot create terminal gateway actions.

Tests exercise the canonical state reducer, forged signatures and authority, exact review/cancel/send, changed-state rejection, private atomic restart recovery, real PTY input, and four-client journeys through a real relay/gateway with Python, TypeScript, and browser peers.

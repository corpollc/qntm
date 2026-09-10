# qntm OpenClaw Plugin

`openclaw-qntm` is an OpenClaw channel plugin for qntm relay conversations. It subscribes to multiple qntm conversations at once, decrypts inbound relay traffic, and routes replies back to the originating conversation.

## Install from this checkout

The unreleased adapter targets **OpenClaw 2026.9.3** and uses its actual public SDK in tests and typechecking. Use Node **24.16.0 or later in the 24.x line**, or **26.1.0+**. Earlier OpenClaw versions are not covered by this adapter's current host test; upgrade the host before installing this revision.

From the repository root:

```bash
npm --prefix client ci
npm --prefix client run build
cd openclaw-qntm
npm ci --ignore-scripts
npm run pack:plugin
openclaw plugins install --force --accept-capabilities ./dist/qntm-0.1.0.tgz
openclaw plugins doctor
```

The archive bundles this checkout's built qntm client and its runtime dependencies. Installing the development directory directly leaves a `file:../client` symlink outside the plugin boundary, which current OpenClaw's install scanner rejects. Review the generated archive as local plugin code; `--force` acknowledges its non-ClawHub source, and does not disable the scanner. Configure the channel below, then restart the OpenClaw gateway.

The generated manifest exposes the channel schema before runtime loading and marks private identities and invite tokens as sensitive in setup surfaces. Regenerate it with `npm run build:manifest` after changing the Zod schema. See OpenClaw's [channel configuration contract](https://docs.openclaw.ai/plugins/sdk-channel-plugins) for the host metadata surface.

## What It Does

- Opens one relay websocket subscription per enabled qntm conversation binding
- Atomically persists current keys, authenticated conversation state, pending delivery and cursor per account/conversation
- Recovers pending host delivery after restart, including a failure before OpenClaw accepts ownership
- Routes direct chats according to OpenClaw `session.dmScope` semantics
- Sends agent replies back through qntm's encrypted `postMessage` path
- Falls back to attachment URL text when OpenClaw asks to send media

## Configuration

Add the plugin to an OpenClaw extensions install and configure `channels.qntm` with a pinned public group link, a legacy invite token, or an OpenClaw-owned qntm profile directory. See [contact groups](#contact-groups-unreleased) for the key-free link flow. Inbound delivery is relay-websocket based; this plugin does not expose a webhook receiver.

```json
{
  "channels": {
    "qntm": {
      "defaultAccount": "default",
      "accounts": {
        "default": {
          "enabled": true,
          "relayUrl": "https://inbox.qntm.corpo.llc",
          "identityDir": "/Users/pv/.openclaw/qntm/default",
          "defaultTo": "ops",
          "conversations": {
            "alice": {
              "convId": "be96bcc53fa787c1f6cfc1f20afc0049",
              "name": "Alice"
            },
            "ops": {
              "convId": "0050a49f0b2e738063a89621d1c9b055",
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

- `identityDir` reads `identity.json` and `conversations.json` from a dedicated qntm profile directory managed for OpenClaw.
- `convId` bindings require `identityDir` because the plugin must load the matching conversation keys from that profile directory.
- Invite-token bindings are still supported via `identity` or `identityFile`.
- Each configured binding is addressed by either its binding key, such as `ops`, or the raw qntm `conv_id`.
- Direct-conversation session collapse/isolation is controlled by OpenClaw `session.dmScope`. With the default `main`, qntm DMs share `agent:main:main`; use `per-channel-peer` or `per-account-channel-peer` if you want isolated qntm DM sessions.
- Current state and the delivery queue are stored in the plugin's private account directory; see the storage and recovery notes below.
- `trigger: "mention"` requires at least one matching `triggerNames` entry to wake the agent. Authenticated protocol controls still update keys and membership when no mention matches.
- Outbound media is flattened into text lines like `Attachment: https://...` because qntm currently only exposes text sends through this plugin path.

## Protocol Compatibility

| qntm capability | Status | Notes |
|-----------------|:------:|-------|
| Text conversations | ✅ | Inbound decrypt + outbound reply are implemented. |
| Multiple bound conversations | ✅ | One relay subscription and cursor per enabled binding. |
| Rekey, removal and replay | ✅ | Shared authenticated reducer; current keys and removal survive restart. Replies use the latest keys and refuse a removed local identity. |
| Non-text `body_type` ingest | ✅ | Gateway events are verified by the shared reducer, then delivered as untrusted contextual text like `[gate.request] ...`. The optional gateway tool reads verified workflow state. |
| qntm API Gateway `gate.*` actions | ✅ | Unreleased opt-in `qntm_gateway` supports reviewed admission, requests, votes, credentials and governance. Real host journeys with Python/browser/TypeScript peers verify actual gateway execution, rejection and rekey/restart. |
| Contact addition and public links | ✅ | Unreleased ordinary-group add/open/remove/refresh/rekey/retry, known contact pins and challenge-bound recovery; actual native-host/Python/TypeScript journeys. Governed group admission and full competing-operation reconciliation remain separate. |
| Media attachments | Partial | OpenClaw media sends are flattened into attachment URLs inside a text message. |

## Local Verification

```bash
cd openclaw-qntm
npm test
npm run typecheck
npm run check:manifest
npm run test:host
```

`test:host` installs a packaged plugin into a fresh temporary OpenClaw state directory. It starts the actual pinned host with a local wire-level relay fixture and checks encrypted direct/group replies, rekey/replay and removal across restart. It also locks the disposable host's session database to force admission failure, verifies qntm retained the message after advancing its relay cursor, kills the host with `SIGKILL`, and confirms delivery after restart without resending. A local deterministic model drives the host's actual tool-call loop through status, prepare and commit for requests, votes, credentials and governance; a peer verifies the resulting encrypted messages. Ordinary chat checks use a test-only reply hook. These fixtures require no external model/provider key and do not test a model's judgment or real gateway API execution. Existing OpenClaw configuration and conversations are untouched. CI runs this check on Node 24. Set `QNTM_KEEP_HOST_SMOKE=1` only when you need the disposable state for diagnosis.

The deliberate session lock waits for the host's previous writes to finish within the existing smoke deadline. Lock acquisition failures stay distinct from the admission failure being tested. Partial setup still releases owned resources, and cleanup errors are reported without hiding the original failure.

Unit tests also cover disk-full rollback, failed checkpoint writes, stale claim ownership, duplicate admission, bounded storage, strict identity parsing, delayed replies across rekeys, and removal while a reply is in flight. Gateway tool tests cover native routing, changed permissions, one-use reviews, expiry, removal/rekey, verified votes and terminal events, sealed credentials, uncertain sends, and persisted bootstrap retry.

The full [cross-client acceptance suite](../docs/deployment-checklist.md) also installs the actual OpenClaw host against local relay and gateway Workers, with Python, TypeScript and browser peers. It verifies signed admission, actual API execution, vote withdrawal and restored quorum, governance, a different requester trying to consume a review, stale review rejection after membership rekey, discarded reviews after `SIGKILL`, successful execution after restart, and persisted removal. Run `npm --prefix integration run test:openclaw` after installing the acceptance dependencies; the suite requires a supported Node 24/26 host and Chromium. Its local model fixture exercises tool routing and protocol behavior, not model judgment.

## Optional gateway tools

This checkout adds `qntm_gateway`; it is not part of published 0.6.1. Enable it in the host tool policy, then grant the desired actions on each conversation binding:

```json
{
  "tools": { "alsoAllow": ["qntm_gateway"] },
  "channels": {
    "qntm": {
      "conversations": {
        "ops": {
          "convId": "0050a49f0b2e738063a89621d1c9b055",
          "gatewayActions": ["request", "approve", "disapprove", "propose", "gov-approve", "gov-disapprove"]
        }
      }
    }
  }
}
```

Merge this example into an existing configured account with its identity/profile. `gatewayActions` is an explicit local permission list. Missing or empty disables the tool for that conversation; `invite` and `secret` are separate permissions. Account-specific configuration puts the same setting under `channels.qntm.accounts.<account>.conversations.<binding>`. Existing host deny rules still apply.

The tool is available only in a native qntm agent turn. Account, conversation, requester and session come from OpenClaw's routing context; tool arguments cannot select another identity or conversation. Received text and verified peer requests remain untrusted input for the agent's decision. Enabling an action permits the local agent to assess and perform it under its instructions; no extra human or central gateway approval is introduced.

Call `status` to inspect admission and paginated workflow summaries (`offset`, `limit`, default 20, maximum 50). Call `prepare` with an action and its options. The result includes the complete proposed effect, signer, gateway, membership/policy, relevant request or proposal, a `reviewToken` and `reviewHash`. Assess that content before calling `commit` with both exact values. `cancel` discards a review by token.

| Action | Options |
| --- | --- |
| `invite` | `gatewayUrl`, optional `floor` (default 1). HTTPS required except loopback. |
| `request` | `service`, `endpoint`, `verb`, `targetUrl`; optional `payload`, `recipeName`, `arguments`, `requiredApprovals`, `expiresInSeconds`. |
| `approve`, `disapprove` | `id`: the complete verified request ID. A withdrawal removes this identity's vote; it is not a veto or execution rollback. |
| `secret` | `service`, `value`; optional `headerName`, `headerTemplate`, `ttl`. |
| `propose` | `proposalType`; the applicable `proposedFloor`, `proposedRules`, `proposedMembers` or `removedMemberKids`; optional `requiredApprovals`, `expiresInSeconds`. |
| `gov-approve`, `gov-disapprove` | `id`: the complete verified proposal ID. |
| `retry-bootstrap` | No options; requires `invite` permission and a matching saved invitation. |

Proposal types are `floor_change`, `rules_change`, `member_add` and `member_remove`. Rules use `{service, endpoint, verb, m}`. Proposed members use `{kid, public_key}` with base64url-encoded key IDs and public keys; `removedMemberKids` is an array of base64url key IDs. If a host truncates or summarizes a review, the agent must not commit without inspecting the complete proposed effect.

Reviews expire within five minutes, live only in this host process and require the original native session/requester. Commit checks current configuration, membership, keys, policy, expiry and verified subject status again. A valid commit attempt consumes the token even if delivery fails; cancelled or ambiguous sends are not automatically retried. The relay subscription alone advances protocol state and its cursor, so a delayed POST acknowledgement cannot overwrite a newer rekey. `submitted` means the relay acknowledged a message, not that an API call ran. A `delivery_unknown` receipt includes its message ID for reconciliation against verified history before preparing another action.

Gateway admission intentionally shares the current conversation keys with the reviewed gateway. Preparation obtains its public invitation; commit posts the signed chat invitation and delivers sealed bootstrap data. HTTP success does not confer authority: the subscription must verify the matching signed `gate.accept`. A failed bootstrap delivery leaves a private sealed file; after the subscription verifies the posted invitation, prepare and commit `retry-bootstrap` to resend that same bootstrap without posting another invitation. If saving fails, the tool reports that the invitation was posted but bootstrap was not delivered. Gateway setup calls have a 30-second deadline, reject redirects, cap responses at 64 KiB and propagate host cancellation. Cancellation after a POST cannot retract that message or prove that the server ignored it.

Credential plaintext appears in the tool's input and can therefore reach the host transcript and configured model provider. The review omits plaintext and ciphertext, showing byte count and a SHA-256 digest; the emitted credential is sealed to the accepted gateway. Neither hashing nor sealing removes earlier input copies. Use a dedicated identity/profile and configure host/provider retention accordingly.

## Local storage, privacy and recovery

The base directory is `OPENCLAW_STATE_DIR`, or `~/.openclaw` when unset. qntm owns `plugins/qntm/accounts/<account>/` beneath it. New account/conversation directories use mode `0700`; checkpoint and SQLite files use `0600`. These are local file permissions, **not encryption at rest**. The plugin uses its own SQLite database and public OpenClaw dispatch lifecycle; local archive installation does not require access to OpenClaw's registry-trusted plugin state API.

| File | Contents and retention |
| --- | --- |
| `conversations/<conv_id>.json` | Current conversation keys/epoch, creation date/type, participant IDs and known public keys, signed gateway invitation/context, verified gateway workflow history, removal status, relay/legacy cursors, initial configuration hash, identity key ID, exact replay IDs/digests, and up to 64 pending plaintext deliveries. Current state remains until the operator removes it. No prior epoch keys are retained. Replay history is capped at 8,192 IDs; workflow history at 4,096 events and approximately 8 MiB. The complete file is capped at 16 MiB. |
| `conversations/<conv_id>.json.gateway-bootstrap` | At most 96 KiB: sealed bootstrap ciphertext, identity/conversation/invitation/message IDs, epoch, relay/gateway URLs, gateway public key, relay sequence and expiry. Contains no plaintext conversation keys. Removed after verified acceptance on a received event; failed cleanup retries on later events. Otherwise remains until overwritten by later admission or removed by the operator, including after expiry. Expired or mismatched bootstrap cannot be retried. |
| `groups/<conv_id>.json` | Ordinary-group identity/configuration hash and revision, current root and full roster, source replay/bootstrap cursors, saved removal sequence, recovery boundary/reason/challenge, a random local dispatch generation, up to 8,192 authenticated IDs/digests, up to 64 prior source-key/roster checkpoints, up to 256 pending ciphertext entries/4 MiB, up to 64 pending plaintext deliveries, own welcome sequence receipts, and an exact unfinished operation including expected keys. Admission recovery retains the original encrypted controls/welcome, delivery counters, recipient pin and exact admission ID/digest once, alongside the current exact repair or renewal. Superseded recovery ciphertext and delivery counters form a flat history capped at 256 revisions; original plus superseded evidence is capped at 4 MiB of canonical CBOR. At either bound, replacement is refused and the saved operation remains. Retained evidence contains no old expected plaintext roots. Prior roots authenticate competing rekeys only; eligibility lasts at most 24 hours; expired archive entries are pruned on successful receive writes. Whole file capped at 16 MiB; backups can retain earlier keys. A temporary `.lock` file contains the writer PID. |
| `ingress.sqlite` and SQLite sidecars | Pending/claimed/failed plaintext deliveries: conversation and message IDs, sender key ID/public key, epoch, creation time, body type/text and gateway-verification flag; ordinary-group dispatch generation and accepted envelope digest; queue account/channel, lane, arrival/update/attempt timestamps, attempt counts and claim token/owner/heartbeat. Host exceptions are replaced by fixed failure strings. At most 1,024 pending/claimed events are admitted; full storage retains the checkpoint outbox and applies backpressure. Pending work has no time-based expiry. |
| Completed/failed queue records | A completed row drops its plaintext payload when OpenClaw durably adopts the turn, or when a synchronous dispatch completes. Completed IDs are retained for seven days, capped at 8,192; failed records retain their payload for seven days, capped at 1,024. Pruning runs at startup and approximately hourly while the monitor runs. The SQLite main file has a 65,536-page limit (256 MiB with its default page size); sidecars and checkpoint files are additional storage. |

Plaintext delivery text is limited to 64 KiB. Queue deletion and payload clearing are logical operations: SQLite journals, filesystem snapshots and backups can retain earlier data. OpenClaw's own sessions, transcripts, logs, hooks and model-provider calls have separate visibility and retention; qntm's limits do not delete those copies. The relay and dashboard do not receive this local state. See the [metadata inventory](../docs/metadata-privacy.md).

The gateway tool holds up to 64 pending/in-progress reviews per plugin instance in memory. Options are limited to 64 KiB and complete review output to 128 KiB. Pending reviews contain signed action material, subject/context and any sealed credential, expire within five minutes, and are discarded on process exit. These bounds do not limit copies retained by OpenClaw or a model provider.

Configured invite tokens or source profiles can still contain initial conversation keys. Updating the checkpoint does not rewrite or erase that source configuration.

Protocol state, cursor and pending delivery commit together before queue admission. Gateway queue admission is idempotent by conversation/message ID; ordinary-group private queue keys also include the dispatch generation and exact envelope digest. Public message IDs stay unchanged. A claim token prevents a stale worker from completing a newer claim. A failed host dispatch remains retryable; after repeated failures, the pinned host's retry policy can move it to the failed queue. Operators should inspect `lastError`, preserve the private account directory for diagnosis, and resolve the underlying storage/host failure. There is no shipped failed-record repair/resubmission command yet. Back up a stopped host's entire account directory, or use a consistent SQLite backup; copying just the live `.sqlite` file can omit its WAL.

This is durable, at-least-once handoff, not exactly-once external effects. After OpenClaw adopts a turn, its recovery owns that turn. A crash around adoption, expired deduplication records, or an uncertain relay POST can still require reconciliation. An unknown reply-send outcome is reported as such.

Existing `cursors/<conv_id>.json` files are read as migration hints. Without `OPENCLAW_STATE_DIR`, their old location is `~/.openclaw/state/plugins/qntm/...`. Available protocol history is replayed to establish keys/membership, while deliveries at or below the legacy cursor do not wake the agent. If required rekey history has expired, a cursor cannot reconstruct it; provide a current conversation profile. Malformed state and identity/configuration mismatches fail closed rather than resetting the cursor. Keep one writer per profile, and preserve both checkpoint and queue when moving state.

## Contact groups (unreleased)

Ordinary groups now use the shared TypeScript membership/checkpoint helpers.
Adding a known contact is admission: the inviter rotates keys, verifies replay
of the exact addition/rekey, then sends a welcome encrypted to that contact's
identity. The public group link contains no encryption keys and has no expiry.
Contacts can open in a different order from their additions. Legacy `invite`
bindings and gateway tools retain their existing behavior.

First verify full Ed25519 public keys through your existing contact channel.
A short key ID cannot be used as a contact pin. Add the host identity from a
current client, then configure the returned `group_link` and inviter's pin:

```json
{
  "tools": { "alsoAllow": ["qntm_group"] },
  "channels": {
    "qntm": {
      "identityFile": "/private/openclaw-qntm/identity.json",
      "relayUrl": "https://inbox.qntm.corpo.llc",
      "contacts": {
        "Colleague": "FULL_ED25519_PUBLIC_KEY_HEX_OR_BASE64URL"
      },
      "conversations": {
        "team": {
          "groupLink": "PUBLIC_GROUP_LINK_FROM_COLLEAGUE",
          "groupActions": ["add", "remove", "refresh", "rekey", "retry", "open", "send"],
          "trigger": "mention",
          "triggerNames": ["my-agent"]
        }
      }
    }
  }
}
```

Replace the placeholder values; they intentionally are not working credentials.
Configuring the public link explicitly authorizes fetching its encrypted welcome.
The link's inviter must match a configured contact, and its relay must exactly
match `relayUrl`. The adapter uses its existing identity, finishes relay replay
and persists the verified checkpoint before permitting messages or agent wakeups.
Each welcome signs the sender’s fully processed replay cursor. The recipient
checks coverage from that anchor and replays available decryptable controls,
including those posted before welcome delivery. An omitted intervening rekey
therefore requires recovery instead of silently enabling stale keys.
An unexpected envelope from an earlier epoch after that anchor also requires
recovery: the recipient has no pre-admission key with which to rule out a competing
rekey. Only the exact admission controls authenticated by the welcome are exempt.
An in-flight older message or unauthenticated relay noise can therefore pause a
newly opened group until a current member supplies a challenged refresh.
The same check applies to later arrivals when the checkpoint has no usable source
key, before any message in that receive batch is dispatched to the agent.
Contact pins are local configuration; inbound text cannot add or replace one.
Changing a pin also invalidates any outstanding action review.

`qntm_group` is optional and only available in that account's native qntm
conversation, with a host session and nonempty `groupActions`. An incoming message
is context, never authorization. Use `status` to inspect verified members, pinned
contacts, pending operation, recovery challenge and public link. For a change,
call `prepare`, inspect its complete effect under the host's instructions, then
`commit` with the exact returned `reviewToken` and `reviewHash`. Reviews expire
after five minutes, host restart, native session changes or relevant membership,
contact or permission changes. Cancel a review with `cancel` and `reviewToken`.

| Action | Options | Effect |
| --- | --- | --- |
| `add` | `{ "contact": "Colleague", "challenge": "optional 64 hex" }` | Admit a pinned identity, rotate, deliver welcome. Any current ordinary member may add. |
| `remove` | `{ "contact": "Colleague" }` | Remove and rotate for remaining members; creator removal is rejected. |
| `refresh` | `{ "contact": "Colleague", "challenge": "optional 64 hex" }` | Deliver current keys without rotation. Include renewal proof when this member has a known completed admission; otherwise use generic refresh. |
| `rekey` | `{}` | Complete a pending rotation or rotate the current roster. |
| `retry` | `{}` | Review exact retry, acknowledged-welcome cleanup, replacement rotation for the same pending admission, or current-key renewal. Original and superseded ciphertext remain retained. |
| `open` | `{ "link": "optional public link" }` | Reopen a pinned link for this configured group/relay. |
| `send` | `{ "text": "Complete text to review" }` | Review and send explicit text. Normal native replies retain existing host authorization. |

A missing relay sequence, expired authenticated control or competing-rekey rewind
pauses sends and agent dispatch. The checkpoint records a fresh `recovery.challenge`;
give it to a current member, who can run:

```sh
qntm group refresh GROUP_ID Colleague --challenge RECOVERY_CHALLENGE
```

A running host watches for the response on its configured public link. On restart
it also retries that pinned welcome. The challenge is signed and encrypted inside
the welcome, so reposting an older welcome at a newer relay sequence does not
clear recovery. A matching challenged refresh can replace a competing key at the
same epoch; queued plaintext from the abandoned branch is discarded before agent
dispatch. Generic refresh cannot undo saved removal. After an explicit later
readmission, refresh can deliver its accepted admission proof with current keys
even if that admission's first welcome expired. Neither form admits a removed
identity or grants keys from before admission. For a blocked host whose agent cannot be awakened, the local
operator can inspect the `session.recovery` field in the private checkpoint below.
No unsolicited guidance request or message to another party is sent automatically.

Private checkpoints live under
`<OPENCLAW_STATE_DIR>/plugins/qntm/accounts/<account>/groups/<conversation>.json`.
They atomically store current keys, full roster, replay cursor, recovery challenge,
saved removal epoch, accepted admission IDs/digests/source epochs and completing
rekey IDs/digests, bounded pending ciphertext, exact unfinished outgoing operation, and **plaintext
messages awaiting host dispatch**. Files are mode `0600` in private directories;
this is filesystem protection, not password encryption. Host transcripts and the
existing durable ingress queue can retain plaintext after dispatch. Pending
renewals retain the expected current keys and full admission map, pinned recipient,
welcome purpose and original recovery challenge so restart retries can recheck
the same proof and send identical ciphertext. These checkpoint files and contact
names are not uploaded. Welcomes carry current keys, roster, admission proof and
any challenge encrypted to the recipient; the relay and its metrics cannot read
those contents.
Tool status and reviews expose their displayed contact/member metadata to the host
transcript and configured model provider, including welcome purpose and any
displayed recovery challenge. Prepared encryption keys and full admission proofs
stay in private plugin state and are omitted from tool review output.
See [metadata boundaries](../docs/group-welcomes.md#metadata-and-security-boundaries).

Local writers serialize with a per-group lock and revision check. Pending
ciphertext is bounded to 256 entries/4 MiB, and pending dispatch to 64 entries.
An ambiguous POST retains the operation; retry verifies the exact signed control
before publishing anything else or releasing a welcome. A saved authenticated
receipt still counts after that message expires, and an already accepted text
finishes without reposting after a later key rotation. On startup and receive,
the monitor clears a pending text send only when retained authenticated replay
matches its exact ciphertext, so a crash after relay acceptance cannot leave
agent dispatch blocked behind a completed reply. This does not automatically
POST uncertain sends or retry membership changes. Challenged welcomes are
checked after subscription backlog replay as well as on live arrival.
The receiving client also accepts admission-renewal welcomes from the pinned
contact. A renewal carries current keys and authenticated evidence of an existing
admission; it does not add a member or rotate keys. It can recover delivery of a
later readmission whose first welcome expired, but cannot undo a newer saved
removal. Candidate selection prefers the highest epoch, then the newest refresh
or renewal; its historical admission rekey ID is never treated as a fresh
rotation. The native `refresh` action issues renewal when the pinned recipient
has complete current admission proof. Founding members and older checkpoints
without that proof keep generic refresh. The review identifies which form will
be sent; admission changes invalidate it. A pending renewal also checks the full
current admission map before release, and restart retries keep its exact bytes
and challenge. Older pending generic-refresh journals remain retryable as written.
The existing reviewed `retry` can also finish a pending addition whose exact
current admission and completing rotation are durably authenticated. A valid
original welcome is sent unchanged even after deduplication-cache eviction. If
its delivery window expired, a later rotation changed current keys, or another
valid rekey completed that same admission, the review proposes a current-key
renewal. Preparing the review does not modify the saved operation or post any
message. Commit preserves the original encrypted intent once and atomically
saves the reviewed renewal before POST; it never sends obsolete addition controls
or restores a different admission. The original recipient and recovery challenge
remain bound. A valid renewal is retried byte-for-byte after uncertain delivery. If a derived
renewal later expires or no longer matches current keys or admission provenance,
the review identifies `exact_renewal` or `replacement_renewal`, and retry reviews
another current-key renewal only while the original exact admission
still exists. Every superseded recovery attempt remains as bounded exact
ciphertext evidence; no old expected plaintext roots or nested journals are kept.
The review fingerprint binds the complete pending journal and current admission
map, so a changed proof, removal, recovery barrier or contact pin requires a new
review. Fully acknowledged welcome journals can be cleared locally after later
state changes; review and cleanup still require relay sync, so this is not an
offline cleanup path. An acknowledgement alone is not proof the recipient received it.

New group messages remain deferred while an operation is pending. An agent turn
already running can review retry, but inbound messages cannot start a recovery
turn through that barrier after restart. A separate local recovery entry point
has not yet shipped. Expired messages without authenticated acceptance and
removed or superseded admission identities remain preserved and blocked.

When the ADD is already authenticated but its completing rotation expired or
was prepared for an obsolete roster, retry can review a replacement rotation
for that same still-pending admission and the complete current roster. It never
posts another ADD. The review identifies `exact_rotation` or `replacement_rotation`. This first
commit saves and posts only the exact reviewed rotation; the relay acknowledgement does not install predicted keys, fill a
missing control sequence, or authorize a welcome. After canonical replay confirms
completion, the tool returns `rotation_verified`, `welcomePending: true`, and
instructs the current agent turn to prepare `retry` again. That second review
covers current-key welcome delivery using the fully processed replay cursor.
These are two cycles of the existing tool review, not another membership or
human approval step. A competing canonical winner is used only in the second
current-welcome review. An uncertain valid repair stays exact; another expired
or stale repair requires a fresh review and retains its predecessor in the same
bounded history. Removal, a different admission, or incomplete-history recovery
blocks both stages. Do not delete the
profile to clear a blocked operation. Full competing-branch reconciliation remains
unfinished: this adapter instead requires a fresh challenged welcome and discards
undispatched plaintext from the superseded state. Entering recovery, removal, or
installing a fresh welcome changes the local dispatch generation, invalidating
previously queued host jobs. Their generation and digest are checked again before
agent dispatch, after the current subscription replay completes. Ordinary key
rotations and deduplication-cache eviction preserve valid pending deliveries.
Older unreleased ordinary-group queue entries without this binding are discarded;
the adapter cannot infer their validity from a reused message ID. These private
bindings are not sent to the relay or included in its metrics. No operation can
retract an agent turn that already started.

A `convId`/`identityDir` binding can also import a trusted CLI `group_session`
checkpoint after the CLI has finished its pending operation and receive backlog.
Provision from a dedicated profile copy and retain that seed unchanged; OpenClaw
then owns its separate private checkpoint. Legacy groups without a complete
trusted checkpoint are not silently migrated. Ordinary `groupActions` cannot be
combined with `gatewayActions`; admission into gateway-governed groups and
ordinary-to-gateway handoff remain separate work.

Validation includes real cryptographic unit tests, the installed OpenClaw host's
existing gateway/restart smoke, and a real relay/Python/TypeScript/native-host
journey:

```sh
# Use supported Node 24.16+ (below 25), or Node 26.1+.
cd openclaw-qntm
npm test
npm run typecheck
npm run test:host
cd ../integration
npx vitest run --maxWorkers=1 openclaw-contact-welcome.test.ts
```

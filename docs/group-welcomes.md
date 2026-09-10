# Contact addition and encrypted group welcomes

This unreleased extension implements the [add-contact design](design/group-membership.md)
in the browser, Python CLI/MCP, terminal and OpenClaw, with matching Python and
TypeScript library operations. Gateway-governed welcomes, legacy migration and
complete recovery across competing rekeys remain unfinished (`qntm-2g7v`). It is not part
of the published 0.6.1 packages or hosted browser.

The public link has no expiry, and contacts can open their links in a different
order from their additions. An added contact is already a member: later rekeys
include that identity, so their client can replay from its welcome to the current
epoch. The welcome itself has a seven-day maximum lifetime; relay retention may
also remove it or a needed rekey. Missing that delivery window does not end
membership. A member with current state can now send a new welcome containing
current keys with `group refresh`, without changing membership or rotating keys.

Each welcome signs the sender's fully processed relay position at preparation.
The recipient checks that every later relay position is present, including the
interval before the welcome was posted. A rotation can race into that interval;
if retention has removed it, the recipient pauses and requests a fresh welcome
instead of treating the older keys as current. History before the signed position
is not required. The position stays inside the encrypted welcome.

A newcomer cannot authenticate a competing rekey encrypted under an older source
epoch without learning pre-admission keys. During bootstrap, an older-source
envelope after the signed position therefore also pauses the client, except for
the exact addition/rekey ciphertext hashes signed into its welcome. A current
member can process the winning branch and issue a challenged refresh. That fresh
response may replace a losing root at the same epoch; an unsolicited conflicting
welcome still cannot replace saved state. A generic refresh cannot undo saved
removal; an admission renewal must prove a later admission.
After bootstrap, older-source ciphertext also pauses a client that has neither a
usable source-key archive nor an exact previously verified digest.

## Client interfaces

| Client | Entry point | Persistence and requirements |
| --- | --- | --- |
| Browser | Contacts panel; create/add/open/remove/refresh actions | Per-identity browser storage with Web Locks and encrypted backup support; [browser guide](../ui/aim-chat/README.md) |
| Python CLI/MCP | Commands and tools below | Private, atomic profile shared with `recv --watch` |
| Terminal | `/contact`, `/group`, `/join` | Matching Python package and private `contact-groups` profile; [terminal guide](../ui/tui/README.md) |
| OpenClaw | Configured pins/group link or trusted checkpoint, optional `qntm_group` tool | Native host session, configured allowed actions and complete review; [adapter guide](../openclaw-qntm/README.md) |

The browser, CLI and terminal can create a new ordinary group. OpenClaw binds to
a configured group and manages membership through its locally enabled actions.
Pin removal changes the local address book only; group removal is a separate
membership operation. Each client's guide describes its stored keys, plaintext
history or dispatch queue and recovery limits. These interfaces add no relay
endpoint or metrics label.

## CLI and MCP

Pin the contact's full Ed25519 public key after verifying its owner. A short key
ID is insufficient to add someone. An existing contact name cannot silently
change its pinned key.

```bash
qntm group create "Team" --contact
qntm contact add Colleague FULL_PUBLIC_KEY
qntm group add GROUP_ID Colleague
# Share the group_link from this command's JSON result.

# The added contact uses their existing identity:
qntm group join PUBLIC_GROUP_LINK
qntm send GROUP_ID "Hello"

# Remove the contact and rotate the remaining members' keys:
qntm group remove GROUP_ID Colleague
```

`group create --contact` creates the ordinary-group checkpoint and saves its
exact signed genesis before posting. It returns a public group link, with no
bearer invite or implicit admission. Creation is complete only after the exact
genesis appears in relay replay; uncertain delivery leaves the operation saved
for `group retry`. Sends and additions wait for that operation to finish. The
existing `group create` command without `--contact` retains legacy bearer invites
and gateway compatibility. It now saves its original encrypted genesis before
posting and returns an error, with a conversation ID and retry instruction, if
sending fails. `qntm group retry GROUP_ID` (or MCP `group_retry`) uses the same
profile, identity, relay and ciphertext after a restart. Pending legacy creation
must finish before contact-group conversion.

Legacy creation results distinguish `evidence: relay_acknowledgement` (the relay
acknowledged the POST) from `evidence: exact_replay` (the full original ciphertext
was found in bounded relay replay). Both report `delivery: accepted`; neither
confirms a peer received the message. Unlike contact-group creation, legacy
creation does not require a replay check after an acknowledged POST. Unknown
outcomes and explicit rejections return errors and preserve the journal. Retry
checks replay before resending; it never generates a replacement genesis. An
expired genesis without a saved receipt or exact replay match remains blocked
for reconciliation. Keep the profile instead of repeating `group create`, which
would create another group.

The private local `groups/GROUP_ID.creation.json` journal contains the original
encrypted genesis, conversation ID, relay URL, creator public key and any relay
receipt. Atomic writes and a per-group process lock protect retry progress;
completed receipts are retained so retry after a lost command result does not
post again. The legacy conversation file still contains its unencrypted keys
and bearer invite, under the existing local storage protections.

For a still-admitted contact who missed the welcome's delivery window:

```bash
qntm group refresh GROUP_ID Colleague
# Share the returned group_link; the same inviter produces the same link.
```

The command verifies the recipient against the current local roster after relay
replay and saves the exact encrypted welcome for `group retry`. When the saved
state proves the recipient's completed admission, it issues an admission renewal.
This also recovers delivery after a legitimate later readmission whose welcome
expired: the original admission must be newer than the receiver's saved removal.
Founding members and older checkpoints without that proof receive a generic
refresh, which cannot undo saved removal. No form of welcome recovers keys for
an interval of exclusion.
If another current member sends the refresh, use that member's returned link,
which pins their signing identity.

If a previously joined client detects missing history, `recv` reports
`recovery_required: true` and a `recovery` object containing `afterSequence`,
`reason` and a 64-hex `challenge`. Sends, membership changes and receive hooks
pause until recovery. Pass that challenge to an up-to-date member through your
existing contact channel:

```bash
qntm group refresh GROUP_ID Colleague --challenge RECOVERY_CHALLENGE
# The recovering contact then opens the returned public group link again.
```

The welcome signs and encrypts the challenge together with the recipient, group,
keys and roster. Reposting an old welcome at a newer relay sequence cannot answer
it. A newly detected gap generates a new challenge; retrying the same gap keeps
the saved one. This proves that the response was prepared for this recovery,
not that the sender has a globally complete view of membership. The sender must
still have current state and verify that the recipient remains a member.
Explicit readmission can include `group add ... --challenge RECOVERY_CHALLENGE`;
the challenge itself grants no permission to add anyone.

`group add` saves the exact encrypted operation before sending, verifies the
addition and rekey from relay replay, then sends the recipient-encrypted welcome.
If delivery is uncertain, keep the profile and use `qntm group retry GROUP_ID`;
this resumes the saved ciphertext. Repeating `group add` cannot overwrite a
pending operation. Sending ordinary messages is blocked while an operation is
pending or while membership awaits key rotation.

For a **completed** saved addition, retry in the maintained clients can recover an expired
welcome or a completing rekey superseded by a later canonical rotation. It checks
the original add ID and exact ciphertext digest against current admission
provenance before touching the old control queue. When the original welcome is
still valid for current keys, retry retains its exact bytes, even after the
original controls leave the replay cache. Otherwise it saves a new admission
renewal using current keys and the fully processed current replay position.
It preserves the original optional recovery challenge. No add or obsolete rekey
is reposted during this recovery, and a removed or subsequently readmitted
recipient cannot use the previous admission's operation.

The renewal journal retains the original ciphertext, intended member and public
key, add ID/digest, welcome acknowledgement count and unknown delivery status.
It does not nest old checkpoints or duplicate their plaintext group roots. State,
operation identity and expiry are checked again under the receive lock before
each welcome POST. An uncertain renewal POST keeps the same bytes for retry;
fully recorded welcome acknowledgements can complete cleanup after a crash
without reposting old controls. All of this metadata remains in the private
profile until the operation finishes. The relay receives only encrypted envelopes.

If the original add was accepted but its completing rekey expired or no longer
matches the verified current roster, retry saves a replacement rotation before
posting it. The exact original admission must still be pending at the current
epoch. Only existing current members receive the new wrapped keys; the contact's
welcome is released after authenticated replay confirms a completing rotation.
A competing member's canonical rotation can complete this phase too. An unknown
replacement-rotation response keeps the exact wire for restart; a replay-confirmed
completion skips that wire even after replay-cache eviction. The renewal journal
retains both the original intent and replacement rotation ciphertext. A POST
acknowledgement alone never installs predicted keys or fills missing control
history.

OpenClaw keeps its native review boundary: the first prepare/commit retry repairs
the rotation and returns `rotation_verified` with `welcomePending`. The next
prepare/commit retry reviews delivery from the now-verified current state. Both
cycles can run in the same authorized agent turn. The browser and Python/terminal
retry action complete these phases together after verified replay.

If a replacement rotation or renewal becomes stale again, explicit retry
can repeat this reconciliation for the same current admission. Valid uncertain
ciphertext stays unchanged. A stale rotation still requires an incomplete
admission at the current source epoch; a stale renewal requires a complete current
admission. Changed membership or incomplete authenticated history blocks both.
For example, a competing branch that requires an expired control to reconstruct
still needs recovery from a current member; retry cannot waive that boundary.

Superseded recovery operations remain as a flat private list of exact control
and welcome ciphertext, acknowledgement counts and unknown delivery status.
Entries contain no old expected checkpoints or nested operation histories. The
list is limited to 256 entries and 4 MiB of canonical encoded evidence. Browser
and OpenClaw include the original intent in that byte budget; Python retains its
fixed original intent and current repair separately. At either limit, retry preserves
the journal and sends nothing; it never silently discards uncertain delivery.
The entire operation journal is removed after completion.

Browser, Python CLI/MCP, terminal and OpenClaw can also repair an expired completing rotation after proving the
original removal through authenticated receive. New removal journals pin the
target's full key and admission incarnation. Retry retains the original removal
ciphertext and rotates for the current roster; it never removes a later
readmission again. If another verified rotation already completed that removal,
retry finishes without posting. Standalone rotation retries keep valid exact
ciphertext, replace a stale current-epoch rotation when safe, or recognize that a
later verified rotation fulfilled the intent. This last case does not claim the
original control was delivered. An unproven expired or superseded removal stays
preserved. OpenClaw presents the concrete replacement rotation for review and
checks that the original removal action is still locally permitted. Browser and
OpenClaw retain the original removal receipt when saving the repair journal;
replacing a checkpoint with a challenged welcome invalidates prior receipts and
can leave the operation preserved until explicit local reconciliation is available.
Remaining unproven-removal recovery is tracked under `qntm-ra0e`; broader
recovery remains `qntm-qp22`.

Python CLI/MCP provides an explicit local escape for a removal that was never
verified and can no longer be retried exactly:

```sh
qntm group retry CONVERSATION --release-unproven
```

MCP exposes the same action as `group_retry(conversation, release_unproven=True)`.
After complete replay, this moves the uncertain operation into a private local
archive and releases its ownership of the retry slot. It sends nothing and
changes no membership. It refuses verified or still-exactly-retryable removals,
incomplete history, and unrelated operation kinds. Removed-member and pending
rotation barriers remain in force. A fresh removal is a separate explicit action
against current membership; release cannot revoke old ciphertext that might
arrive later. The archive retains original and superseded ciphertext, target
pins, delivery counts, reason and time, but omits predicted keys. At 256 entries
or 4 MiB, release refuses rather than discarding uncertain evidence. This archive
stays on the client and is not sent to the relay. Browser, terminal and OpenClaw
release controls remain tracked under `qntm-ra0e`.

Saved **generic refreshes** for founding members or checkpoints without admission
proof can also be retried after expiry or a later rotation. Maintained clients
authenticate the original signed recipient box and optional recovery challenge,
check that the full recipient key remains in the current roster, and retain the
old ciphertext before preparing current delivery. Older single-recipient journals
can recover their missing metadata from the authenticated box. A generic refresh
keeps its purpose even if admission proof is now known; it cannot clear saved
removal. OpenClaw reviews the concrete replacement before saving and posting it.

Completed removal and rotation operations can finish after their exact controls
leave the bounded replay cache, including after a later valid rotation. Python
uses authenticated history bindings; the browser and OpenClaw keep private
pending-control receipts with the ciphertext digest, message ID, source epoch,
verified relay sequence and branch validity. Receive saves this proof atomically
with the checkpoint. A competing rekey invalidates proof from the losing branch;
a replacement welcome invalidates prior local proof. An acknowledgement, absent
member or matching expected root is not an acceptance receipt. Retry preserves
older journals whose acceptance can no longer be proven. Receipt-based cleanup
posts no obsolete controls and keeps the current keys. OpenClaw exposes this as
an `accepted_cleanup` review, subject to the existing local action permissions.
These receipts stay in client storage and add no relay metadata or wire fields.

When an OpenClaw restart leaves an operation pending, a local operator can start
a scoped recovery turn through the running OpenClaw Gateway with
`openclaw agent --channel qntm --to GROUP_ID --message 'Review the saved qntm group operation and retry it if appropriate.' --json`.
The command starts an agent turn; it does not approve or commit the operation.
The existing tool permissions, prepare/commit review and current-state guards
still apply. Group messages remain deferred until the saved operation completes.
See the [native adapter instructions](../openclaw-qntm/README.md#local-recovery-entry-point)
for host requirements and the local transcript footprint.

The relay stores each accepted POST as a new sequence row. Explicit retry after
an unknown acknowledgement can therefore store identical ciphertext twice.
Receiver replay checks prevent duplicate message effects; this is distinct from
server-side deduplication. The current clients do not recognize an already-stored
welcome before retrying its exact POST. The real relay journeys verify both rows,
unchanged membership and keys, and one delivered reply.

`qntm group link GROUP_ID` retrieves the public locator pinned to **your**
identity, for contacts whose welcomes you issued. It does not add anyone or
deliver a replacement welcome. `contact list` and `contact remove NAME` manage
local pins; deleting a contact pin does not remove that person from any group.

MCP exposes `group_create`, `contact_add`, `contact_list`, `contact_remove`, `group_add_contact`,
`group_remove_contact`, `group_rekey`, `group_refresh`, `group_retry` and `group_link`.
`conversation_join` opens the public link. These tools share the CLI profile,
receiver and recovery state. Membership changes and sends require the host's
existing authorization; incoming messages cannot supply that authorization.

Opening a link trusts its inviter pin and relay destination, so use a link from
the verified contact. CLI and MCP save the link's relay for later sends and
receives. Wrong recipients, older epochs and replayed welcomes that would undo
saved removal are rejected. Conflicting same-epoch keys require a persisted
recovery barrier and an exactly matching signed challenge. Re-adding a removed contact creates
a fresh epoch; opening the resulting link preserves existing local history but
does not grant keys for the interval when that identity was absent.

This increment supports newly created ordinary groups and legacy profiles with
a complete, trusted local roster. It detects missing relay sequences after a
saved cursor or the welcome's signed replay position, and expired authenticated controls for which it has
keys. It does not reconstruct missing legacy roster history, establish freshness
against a relay that fabricates a complete-looking replay, recover an addition
superseded by another rekey, or integrate gateway admission/governance.
A refresh requires a sender whose saved membership and keys are current;
completion of a relay subscription alone cannot establish that if needed
controls have expired. A saved operation that no
longer matches accepted state fails without releasing its welcome unless the
completed-addition recovery described above proves the same current admission.
The remaining cases are release gaps, not additional admission steps.

## CLI local storage

For groups using this receiver, private `conversations.json` stores the current
keys and checkpoint, full roster, **decrypted message history**, relay cursor,
pending ciphertext and exact unfinished outgoing operation in one atomic update.
It also stores the recovery boundary, reason and challenge, and sequence receipts
for locally posted genesis, welcomes and text. Known own receipts can account for those
expired rows without treating an unknown missing control as harmless. Welcome
and genesis receipts are pruned when the receive cursor passes them; text receipts remain
with local history.
Contact names and public keys live in private `contacts.json`. File locks serialize
receive writes and individual group operations; revision checks reject stale
metadata writes that would erase receive progress.

Pending undecryptable ciphertext is limited to 256 messages and 4 MiB of decoded
wire data. Exceeding that bound fails the receive update without advancing its
saved cursor. Late-decrypted messages keep their original public relay sequence;
a private delivery order makes them available to hooks after catch-up.
Each received history row also stores a verified ciphertext digest, source epoch
and delivery-validity flag. Competing-branch descendants and superseded rekeys
lose delivery eligibility; installing a replacement welcome invalidates prior
queued events without erasing their plaintext history. Ordinary replay-cache
eviction does not discard valid pending hook deliveries. The resident receiver
waits for complete replay before dispatch, with an additional 8,192-message /
16 MiB frame buffer bound. See [receive-hook semantics](receive-hooks.md#delivery-and-restart-semantics).

These files use restrictive local permissions, not password encryption. Local
message history has no automatic expiry. Migrating a legacy group copies its
history into the record and retains the old history file; backups can retain both.
The outgoing operation contains encrypted controls and welcomes plus expected
group keys until it completes. None of these private records, contact names or
plaintext history is uploaded to the relay or added to telemetry. The pure
library checkpoint described below contains no message plaintext.

## Library operation

`prepareGroupAddition` / `prepare_group_addition` takes the local identity,
conversation, trusted local `GroupState` and the new contacts' public keys. It
validates the complete roster and the inviter's membership before returning an operation
containing the encrypted `group_add`, a fresh-key `group_rekey`, one sealed
welcome per added contact, and the resulting local state. It never mutates the
supplied checkpoint. A current noncreator member can add contacts, preserving
the existing ordinary-group policy rather than introducing an admin-only gate;
the creator's identity in the snapshot stays unchanged.

Addition and refresh preparation take an optional `replayFromSequence`
argument in TypeScript or `replay_from_sequence` in Python. Hosts pass the relay
cursor fully processed into the supplied checkpoint, before preparing the
operation. Never substitute a later POST receipt or a head whose messages have
not been processed. The default is zero, conservatively requiring coverage from
the beginning. The opened welcome exposes the same field. Older draft welcomes
without a signed position also use zero.

Hosts publish the addition and rekey before sending any welcome. They must
persist the exact operation for uncertain-send recovery and commit local state
with the accepted transition. Preparing a second operation to retry an uncertain
first one would generate a different rekey and is not a retry. Gateway-governed
groups continue to require their existing governance operation.

`createGroupLink` / `create_group_link` makes a group locator link from the group
ID, inviter public key and configured relay URL. Its fragment contains only
those public values and format identifiers. It contains no group encryption
keys, invite secret, recipient identity or roster. Legacy invite links retain
their existing bearer-capability semantics.

`parseGroupLink` / `parse_group_link` performs no network access and confers no
trust in the supplied contact. The host confirms the contact/link and relay
before fetching. `openGroupWelcome` / `open_group_welcome` requires that pinned
inviter and group ID; it does not trust a key asserted by an incoming envelope.
It returns only the admitted epoch's keys and authenticated snapshot. Hosts
must protect existing state against rollback, and replay subsequent membership
changes before enabling sends or agent actions. Opening an old welcome is not
proof of current membership.

## Local receive state

`createGroupSession` / `create_group_session` starts an ordinary-group checkpoint
from trusted local state or an opened welcome. `restoreGroupSession` /
`restore_group_session` validates that private JSON after restart and binds it
to the local identity. The JSON format is identical in both languages. This is
not a way to accept another participant's unsigned checkpoint as authority.

`receiveGroupEvent` / `receive_group_event` authenticates the encrypted envelope,
checks the sender against the current roster and returns new state without
mutating its input. It preserves ordinary members' existing ability to add
contacts, rejects repeated genesis and creator removal, and requires rekey
recipients to match the complete accepted roster. Removal stays effective across
replay and restart; an old-key addition cannot silently restore that identity.
Readmission must use a new, authorized welcome.

`createGroupControlMessage` / `create_group_control_message` includes the source
epoch in the signed control body. New checkpoints require this binding. Existing
QSP v1.1 checkpoints can be migrated with the explicit `signedEpoch: false` /
`signed_epoch=False` option; a supplied epoch must still match. This compatibility
option does not add the missing binding to legacy messages.

After an addition or removal, `assertGroupCanSend` / `assert_group_can_send`
refuses application sends until the rekey is accepted, and always refuses sends
for a removed local identity. `prepareGroupSessionAddition` /
`prepare_group_session_addition` uses those guards when preparing a new addition.
Before releasing its welcomes, `assertGroupAdditionAccepted` /
`assert_group_addition_accepted` requires verified receipt of the exact prepared
addition and rekey and checks that the result still matches current state. A
successful relay POST alone is insufficient.

`prepareGroupWelcomeRefresh` / `prepare_group_welcome_refresh` takes the local
identity, authenticated checkpoint and existing recipients' full public keys.
It produces only signed, recipient-encrypted welcomes with the current keys and
roster. It validates every recipient before producing an operation and includes
no invite token, old keys or invented admission/rekey references.
`assertGroupWelcomeRefreshCurrent` / `assert_group_welcome_refresh_current`
rejects release after expiry or a change to the checkpoint's keys or roster.
Both helpers refuse a removed sender or an unfinished membership rotation.
Both also refuse a sender whose checkpoint requires missing-history recovery.
Addition and refresh preparation accept an optional `recoveryChallenge`
argument in TypeScript or `recovery_challenge` in Python: exactly 32 bytes,
restricted to a single recipient per operation.

### Renewing delivery for the same admission

The library also provides `prepareGroupAdmissionRenewal` /
`prepare_group_admission_renewal` for an accepted admission whose original welcome
has expired, including a readmission followed by later rotations. It takes the
current private checkpoint, recipient public key, and the expected original
`{addId, addDigest}`. The member must still be present with that exact accepted
admission and a verified completing rekey. Preparation returns a signed,
recipient-encrypted welcome with current keys; it neither adds a member nor
rotates keys. `assertGroupAdmissionRenewalCurrent` /
`assert_group_admission_renewal_current` rechecks the admission, roster, keys and
expiry immediately before publication. Hosts still persist the exact operation
and finish replay before release. Maintained client retry actions use it for a
completed saved addition whose original delivery is stale. Python CLI/MCP
`group refresh`, browser **Refresh welcome**, and OpenClaw's reviewed `refresh`
action choose renewal for a recipient with a complete current admission. Founding
members and checkpoints without admission proof retain generic refresh behavior.
The terminal delegates its refresh and retry operations to Python. Full
pending-operation reconciliation remains under `qntm-qp22`.

Private checkpoints keep an `admissions` map keyed by current member ID. Each
entry identifies the accepted add ID, exact ciphertext digest and signed source
epoch, plus its first canonical completing rekey's ID and digest. Pending entries
have `completion: null` until rotation finishes. Later rotations retain the
completed record; a competing rekey restores the source map and removes
descendant admissions. Removal deletes that member's entry. The map is bounded
by the 128-member roster, with copies in the existing bounded rekey archive; it
does not depend on the 8,192-entry replay cache.

An authenticated removal of the local identity also records `removedAtEpoch`.
This local removal boundary survives restart, rewinds and subsequent readmission.
A removed receiver accepts a renewal only when its attested original admission
source epoch is strictly later than that saved removal. Advancing the renewal's
current epoch cannot make an older admission valid. A generic refresh still
cannot undo removal. Existing explicit addition/readmission behavior is unchanged.
The existing saved recovery challenge is required when recovery is pending;
renewal introduces no separate request, nonce or provisional membership step.

Old private checkpoints without these fields restore with unknown provenance
and an unknown removal boundary. Legacy controls without a signed source epoch
cannot establish either value. Renewal fails closed when the required evidence
is unknown. Signed welcomes carry completed current-member provenance so a newly
added member can later renew another member's delivery. This is an attestation by
the pinned current member, like the welcome roster; it is not an independent
historical proof. No old group roots or historical control ciphertext are sent.
Same-epoch welcomes can fill previously unknown entries but cannot silently
replace conflicting known provenance outside the existing recovery flow.

`createGroupSession` accepts trusted completed provenance as `options.admissions`;
Python exposes the matching `admissions=` keyword. Prefer
`groupSessionFromWelcome` / `group_session_from_welcome` when installing a welcome
so saved removal and recovery checks are preserved.

`checkGroupReplayCoverage` / `check_group_replay_coverage` takes the saved cursor,
captured replay head and every received sequence, including unreadable rows.
TypeScript `DropboxClient.receiveMessages` exposes these as `entries` (each with
`seq` and `envelope`) and `sequence` (the captured relay head), retaining the old
`messages` byte array. `subscribeMessages` accepts an asynchronous
`onReady(headSequence)` callback serialized after backlog and before live rows,
once per connection. Buffer backlog until that callback, validate its coverage,
then commit state and cursor atomically. Set `getCursor` to read durable progress
on reconnect; the transport callback alone does not establish group validity.
Missing sequences persist a recovery requirement with a random challenge;
later complete replay alone does not clear it. `checkExpiredGroupControl` /
`check_expired_group_control` recognizes expired authenticated controls with
available current keys without applying their authority. Hosts must retain and
recheck unreadable future-epoch controls when their keys become available.

`groupSessionFromWelcome` / `group_session_from_welcome` installs an already
opened, pinned welcome. It guards saved removal, older epochs and conflicting
same-epoch state. Clearing a recovery requirement also requires the signed
challenge and a sequence beyond the missing-history boundary. The signed replay
position must precede the welcome's relay sequence. Hosts check coverage and
replay from that signed position through the captured head before enabling
actions, including controls posted before the welcome; a later gap blocks again.
`requireGroupRecovery` / `require_group_recovery` lets a host persist another
detected missing-history boundary. These checks use transport sequences to
detect omissions, not to authenticate membership.

On bootstrap, pass the installed state, opened welcome, captured head and raw
`{seq, envelope}` entries to `checkGroupWelcomeReplay` /
`check_group_welcome_replay` **before** applying messages or dispatching agent
events. This checks coverage from the signed position and pauses for unknown
older-source ciphertext, even if expired. It uses the original welcome epoch,
not a later epoch reached during replay. Only exact signed addition/rekey hashes
exempt the expected earlier controls; copied message IDs are insufficient.
Older draft additions without those hashes may need a fresh current-member
welcome. On later batches, preflight all new and pending envelopes with
`checkGroupUnverifiableEpoch` / `check_group_unverifiable_epoch` before reducing
any message, then run normal authentication and expiry checks. A usable archive
or exact verified digest allows those checks to handle the older envelope.
Recovery replacement starts with a clean branch archive and replay set; hosts
must discard queued losing-branch plaintext before agent delivery.

`prepareGroupSessionRekey` / `prepare_group_session_rekey` lets any remaining
ordinary-group member finish an interrupted rotation. Unlike application sends,
rotation is allowed while `needsRekey` is set. The CLI/MCP `group rekey` path uses
this helper, saves the exact control and verifies replay before completion.
After that rotation, an existing member can refresh the newly added contact's
welcome. This does not automatically reconcile the original sender's unfinished
operation or authorize a removed sender to rotate keys.

The reducer implements QSP v1.1's lowest-message-ID rekey rule using at most 64
prior source-key/roster checkpoints, eligible for at most 24 hours and no longer
than the rekey's message lifetime. Those old keys authenticate only competing
rekeys, never old application or membership events. A delayed lower rekey
rewinds descendants and returns `rewound: true`; the host must replay retained
pending ciphertext against the winning branch. Missing historical keys require
recovery from a current contact, not disclosure of pre-admission keys.

Hosts still own bounded pending-ciphertext storage, transport sequencing,
uncertain-send reconciliation, concurrent writers, welcome installation and
readmission checks, and atomic persistence with the cursor and dispatch queue.
They must finish subscription replay before enabling actions. These helpers are
ordinary-group operations; accepted gateway groups continue through their
authenticated governance flow.

The private checkpoint contains the conversation and local identity IDs,
current group root, full member public keys and group metadata, exclusion and
rotation status, recovery boundary/reason/challenge, up to 8192 message
IDs/digests, current-member admission provenance, the local removal epoch, and
the bounded rekey archive (including its source admission maps).
It contains no message plaintext. It must receive the same private or encrypted
storage protection as identity keys. Archive eligibility expires by time, but
disk copies are pruned only when the host persists a successful receive update;
there is no background erasure job in the library. Backups can retain copies.
The private checkpoint is not uploaded as a record. Current keys, roster and
completed admission provenance are carried inside recipient-encrypted welcomes;
the relay stores that ciphertext. The local removal boundary, replay cache and
source-key archive stay local. No checkpoint fields become telemetry labels.

## Wire representation

A welcome is canonical CBOR with fields:

```
{v: 1, suite: "QSP-1", kind: "group_welcome",
 conv_id: bytes(16), msg_id: bytes(16), conv_epoch: uint,
 created_ts: uint, expiry_ts: uint, ciphertext: bytes}
```

The metadata fields follow the existing relay envelope shape. `kind` selects
recipient encryption instead of ordinary group encryption. The ciphertext is
the existing NaCl-box primitive (`sealSecret` / `seal_secret`) using the inviter
and recipient identities; no new cryptographic primitive is introduced.

The plaintext is canonical CBOR `{payload, signature}`. The signature covers
canonical CBOR of the complete payload:

```
{proto: "qntm/group-welcome/v1", envelope: <all outer fields except ciphertext>,
 inviter_ik_pk: bytes(32), recipient_ik_pk: bytes(32), group_key: bytes(32),
 group_state: <creator-first GroupGenesisBody snapshot>, replay_from_seq: uint,
 addition_id: bytes(16), rekey_id: bytes(16),
 addition_hash: bytes(32), rekey_hash: bytes(32)}
```

A refresh uses the same outer envelope and signature/box construction with
`proto: "qntm/group-refresh/v1"`. Its exact payload omits the addition/rekey IDs
and hashes; the signed domain identifies recovery of existing membership.
The hashes cover the complete canonical serialized control envelopes.
`openGroupWelcome` / `open_group_welcome` returns `purpose: "addition"` or
`purpose: "refresh"`; top-level admission references exist only for an addition.
Both payloads may include a signed, encrypted `admissions` map keyed by lowercase
member ID hex, with completed entries:

```
{add_id: bytes(16), add_hash: bytes(32), source_epoch: uint,
 rekey_id: bytes(16), rekey_hash: bytes(32)}
```

An addition's recipient entry must match its top-level control IDs and hashes,
with `source_epoch + 1` equal to the welcome epoch. A renewal uses
`proto: "qntm/group-renewal/v1"`, requires this map and the recipient's complete
entry, omits top-level control IDs/hashes, and opens as `purpose: "renewal"`.
Its historical rekey reference never determines current-epoch candidate order
or exempts old-source ciphertext from bootstrap checks. `removedAtEpoch` stays
local and is never included in the welcome.

Any payload may also contain `recovery_challenge: bytes(32)` inside its
signed and encrypted content. It is absent for ordinary welcomes. Opened data
exposes it as `recoveryChallenge` in TypeScript and `recovery_challenge` in Python.

The snapshot is bootstrap state, not a second genesis event. Signatures use the
shared strict Ed25519 profile. The separate signature is necessary: a recipient
can construct a valid box using the shared encryption key, but cannot sign a
different group state as the inviter. Recipients verify exact schemas, pins,
signed outer context, signatures, roster/key bindings and their own admission
before returning any state.

Welcomes are bounded to 64 KiB and 128 members, with names up to 256 UTF-8 bytes
and descriptions up to 4096. Addition epochs range from 1 through 2^32-1;
refreshes also support existing members at epoch zero. The maximum
lifetime is seven days; expiry is inclusive of its Unix second, matching normal
QSP messages. The client permits at most 600 seconds of future clock skew.
Normal relay retention still applies independently.

## Metadata and security boundaries

The relay can inspect its existing group ID, message ID, ordering, timestamps,
epoch, ciphertext size and transport metadata, plus the `group_welcome` kind.
It cannot read the recipient's identity, inviter's identity, roster, recovery
challenge, signed replay position, admission provenance or group key
from the welcome. This extension adds no metrics or recipient labels. A link
holder can see its group locator and inviter pin. Keeping the locator in a URL
fragment avoids including it in the normal HTTP request to the browser host;
opening the group subsequently exposes its ID to the relay.

Older-source headers are not independently authenticated to a newcomer. The
conservative recovery pause can therefore also be triggered by ordinary
in-flight older-epoch text or by ciphertext injected by someone who knows the
public locator. A later sender-attested position can pass that traffic, but
sustained injection can delay joining. This availability tradeoff grants no
membership authority and does not justify sharing older roots. The relay can
already withhold or fabricate a complete-looking replay; these checks do not
establish global membership consensus against that behavior.

Only newly generated admission keys enter welcomes. Older keys and invite
secrets are excluded. Removing a member requires a new rekey without a wrapping
for that identity; readmission creates another fresh epoch. This does not erase
previously learned keys or make archived NaCl boxes forward-secret against later
compromise of identity keys. This extension does not implement stranger-requested
entry or make the relay an admission authority.

Both library suites exercise real encrypted before/after traffic, signed-context
tampering, wrong recipients/pins, member-initiated addition and removal followed
by readmission. `cd client && npm run test:cross` additionally invokes a fresh
Python peer in both directions; install `python-dist` into that interpreter, or
set `QNTM_TEST_PYTHON` to an existing test environment. Relay acceptance exercises
the same welcome through the existing send/subscription path. Checkpoint tests
also exchange state between languages during addition, removal and competing
rekeys, and exercise restart, exact replay, invalid authority and archive expiry.
Recovery tests also cover reposted old welcomes, mismatched challenges, expired
controls, blocked CLI/MCP/guidance sends and hooks, and a real relay retention
cycle followed by CLI-to-TypeScript recovery and a reply.

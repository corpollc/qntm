# Contact addition and encrypted group welcomes

This unreleased extension implements the [add-contact design](design/group-membership.md)
in the Python CLI and MCP, with matching Python and TypeScript library operations.
Browser, terminal and OpenClaw interfaces, gateway-governed welcomes and complete
recovery across competing rekeys remain unfinished (`qntm-2g7v`). It is not part
of the published 0.6.1 packages or hosted browser.

The public link has no expiry, and contacts can open their links in a different
order from their additions. An added contact is already a member: later rekeys
include that identity, so their client can replay from its welcome to the current
epoch. The welcome itself has a seven-day maximum lifetime; relay retention may
also remove it or a needed rekey. Missing that delivery window does not end
membership. A member with current state can now send a new welcome containing
current keys with `group refresh`, without changing membership or rotating keys.

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
existing `group create` command without `--contact` retains legacy creation and
invite behavior; legacy creation delivery handling remains a migration follow-up.

For a still-admitted contact who missed the welcome's delivery window:

```bash
qntm group refresh GROUP_ID Colleague
# Share the returned group_link; the same inviter produces the same link.
```

The command verifies the recipient against the current local roster after relay
replay and saves the exact encrypted refresh for `group retry`. The receiver
distinguishes this signed refresh from an admission welcome: a refresh cannot
undo saved removal. A new, valid admission welcome is required for readmission.
Neither refresh nor admission can recover keys for an interval of exclusion.
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
receives. Wrong recipients, older epochs, conflicting keys and replayed welcomes
that would undo saved removal are rejected. Re-adding a removed contact creates
a fresh epoch; opening the resulting link preserves existing local history but
does not grant keys for the interval when that identity was absent.

This increment supports newly created ordinary groups and legacy profiles with
a complete, trusted local roster. It detects missing relay sequences after a
saved cursor or welcome, and expired authenticated controls for which it has
keys. It does not reconstruct missing legacy roster history, establish freshness
against a relay that fabricates a complete-looking replay, recover an addition
superseded by another rekey, or integrate gateway admission/governance.
A refresh requires a sender whose saved membership and keys are current;
completion of a relay subscription alone cannot establish that if needed
controls have expired. A saved operation that no
longer matches accepted state fails without releasing its welcome; `group retry`
does not yet resolve that conflict automatically. These are release gaps, not
additional admission steps.

## CLI local storage

For groups using this receiver, private `conversations.json` stores the current
keys and checkpoint, full roster, **decrypted message history**, relay cursor,
pending ciphertext and exact unfinished outgoing operation in one atomic update.
It also stores the recovery boundary, reason and challenge, and sequence receipts
for locally posted welcomes and text. Known own receipts can account for those
expired rows without treating an unknown missing control as harmless. Welcome
receipts are pruned when the receive cursor passes them; text receipts remain
with local history.
Contact names and public keys live in private `contacts.json`. File locks serialize
receive writes and individual group operations; revision checks reject stale
metadata writes that would erase receive progress.

Pending undecryptable ciphertext is limited to 256 messages and 4 MiB of decoded
wire data. Exceeding that bound fails the receive update without advancing its
saved cursor. Late-decrypted messages keep their original public relay sequence;
a private delivery order makes them available to hooks after catch-up.

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
Addition and refresh preparation accept an optional final `recoveryChallenge`
argument in TypeScript or `recovery_challenge` in Python: exactly 32 bytes,
restricted to a single recipient per operation.

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
challenge and a sequence beyond the missing-history boundary. Hosts must replay
everything after that welcome before enabling actions; a later gap blocks again.
`requireGroupRecovery` / `require_group_recovery` lets a host persist another
detected missing-history boundary. These checks use transport sequences to
detect omissions, not to authenticate membership.

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
IDs/digests, and the bounded rekey archive.
It contains no message plaintext. It must receive the same private or encrypted
storage protection as identity keys. Archive eligibility expires by time, but
disk copies are pruned only when the host persists a successful receive update;
there is no background erasure job in the library. Backups can retain copies.
None of this checkpoint is sent to the relay or added to telemetry.

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
 group_state: <creator-first GroupGenesisBody snapshot>,
 addition_id: bytes(16), rekey_id: bytes(16)}
```

A refresh uses the same outer envelope and signature/box construction with
`proto: "qntm/group-refresh/v1"`. Its exact payload omits `addition_id` and
`rekey_id`; the signed domain identifies recovery of existing membership.
`openGroupWelcome` / `open_group_welcome` returns `purpose: "addition"` or
`purpose: "refresh"`, and admission references exist only for an addition.
Either payload may also contain `recovery_challenge: bytes(32)` inside its
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
challenge or group key
from the welcome. This extension adds no metrics or recipient labels. A link
holder can see its group locator and inviter pin. Keeping the locator in a URL
fragment avoids including it in the normal HTTP request to the browser host;
opening the group subsequently exposes its ID to the relay.

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

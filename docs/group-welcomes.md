# Contact addition and encrypted group welcomes

This extension implements the library layer of the
[add-contact design](design/group-membership.md). It is unreleased. Python and
TypeScript can prepare an addition, open a welcome and replay authenticated
ordinary-group state; the complete client interface, durable delivery/recovery
orchestration and gateway-governed flows remain tracked
in `qntm-2g7v`. These APIs do not by themselves make the contact-add journey
available in the browser, terminal, CLI or OpenClaw.

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
rotation status, up to 8192 message IDs/digests, and the bounded rekey archive.
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

The snapshot is bootstrap state, not a second genesis event. Signatures use the
shared strict Ed25519 profile. The separate signature is necessary: a recipient
can construct a valid box using the shared encryption key, but cannot sign a
different group state as the inviter. Recipients verify exact schemas, pins,
signed outer context, signatures, roster/key bindings and their own admission
before returning any state.

Welcomes are bounded to 64 KiB and 128 members, with names up to 256 UTF-8 bytes
and descriptions up to 4096. Epochs range from 1 through 2^32-1. The maximum
lifetime is seven days; expiry is inclusive of its Unix second, matching normal
QSP messages. The client permits at most 600 seconds of future clock skew.
Normal relay retention still applies independently.

## Metadata and security boundaries

The relay can inspect its existing group ID, message ID, ordering, timestamps,
epoch, ciphertext size and transport metadata, plus the `group_welcome` kind.
It cannot read the recipient's identity, inviter's identity, roster or group key
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

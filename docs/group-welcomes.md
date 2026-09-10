# Contact addition and encrypted group welcomes

This extension implements the library layer of the
[add-contact design](design/group-membership.md). It is unreleased. Python and
TypeScript can prepare an addition and open a welcome; the complete client
interface, durable transition/recovery and gateway-governed flows remain tracked
in `qntm-2g7v`. These APIs do not by themselves make the contact-add journey
available in the browser, terminal, CLI or OpenClaw.

## Library operation

`prepareGroupAddition` / `prepare_group_addition` takes the local identity,
conversation, trusted local `GroupState` and the new contacts' public keys. It
validates the complete roster and administrator before returning an operation
containing the encrypted `group_add`, a fresh-key `group_rekey`, one sealed
welcome per added contact, and the resulting local state. It never mutates the
supplied checkpoint. An existing noncreator administrator can add contacts;
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
tampering, wrong recipients/pins, noncreator administrators and removal followed
by readmission. `cd client && npm run test:cross` additionally invokes a fresh
Python peer in both directions; install `python-dist` into that interpreter, or
set `QNTM_TEST_PYTHON` to an existing test environment. Relay acceptance exercises
the same welcome through the existing send/subscription path.

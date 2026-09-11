# QSP v1.2 — current-epoch group bootstrap

This additive extension retains QSP v1.0/v1.1 envelope encryption, signatures,
legacy invitations and numeric `PROTOCOL_VERSION = 1`. It defines a distinct
recipient-sealed group invitation. Older clients reject this token rather than
interpreting it as an epoch-zero invitation. Rekey winner selection remains
QSP v1.1 section 1.8: the lowest valid message ID wins.

## Recipient-sealed current-epoch invitation

The existing immutable group creator may issue this invitation to a public key
already in the authenticated current roster, after the admission rekey completes.
An invitation does not admit a participant, rotate keys, appoint an administrator
or replace the creator. A noncreator administrator may still perform ordinary
membership operations; this extension does not introduce delegation certificates
for issuing creator-endorsed snapshots.

The token is unpadded base64url of canonical CBOR:

```
{v: 1, type: "qntm.group.join", creator_ik_pk: bytes(32),
 recipient_ik_pk: bytes(32), sealed: bytes, signature: bytes(64)}
```

`signature` is an existing QSP Ed25519 signature over canonical CBOR of the other
five fields. `sealed` is the existing `sealSecret`/`seal_secret` primitive, using
the creator identity private key and recipient public key. It encrypts canonical
CBOR:

```
{v: 1, conv_id: bytes(16), conv_epoch: uint, group_key: bytes(32),
 rekey_id: bytes(16), group_state: GroupGenesisBody,
 issued_at: uint, expires_at: uint}
```

`conv_epoch` is positive and at most 2^32-1. `group_key` is the current epoch's
root/group key, with epoch AEAD/nonce keys derived using QSP v1.1 section 1.2.
`rekey_id` identifies the verified canonical rekey establishing that epoch.
No prior epoch keys or legacy invite secret are included.

`group_state` uses the existing genesis body schema as a creator-endorsed roster
snapshot, not a new group-genesis message. Its first member is the creator, with
admin role; other members are ordered by bytewise key ID. There are 1–128 unique
members with valid public-key/key-ID bindings. The recipient must be listed.
Group names are at most 256 UTF-8 bytes and descriptions at most 4096. Role and
member provenance retain their existing meanings. The outer token is at most
65536 decoded bytes; cleartext is at most 49152 bytes. Unknown fields are rejected.

Recipients verify size/schema, creator signature, intended recipient and sealed
payload before any local mutation. They validate conversation and creator against
existing trusted context when available. A token received out of band establishes
initial creator trust by the same external trust decision as a legacy invitation;
a self-contained signature alone is not proof of an unrelated company's identity.

`issued_at` allows at most 300 seconds future skew; `expires_at` must be later,
no more than 30 days after issuance, and unexpired at import. Expiration governs
invitation use, not the lifetime of an imported group or participant-held records.

An existing workspace must not be silently replaced or rolled backwards. An
older invitation is rejected; identical current keys are idempotent. A refreshed
creator-signed invitation for the same epoch may change the active key only when
its rekey ID is lower than the previously recorded winner. Preserve the prior
key solely for private archived-message verification. A higher-epoch refresh must
retain creator identity and verify the admitted recipient in the new snapshot.
Never re-enable an explicitly excluded participant by silently applying a token.

## Epoch-bound control bodies

New group genesis/add/remove/rekey bodies include `group_epoch`, equal to the
outer source epoch. It is inside the ordinary signed body hash. This additive
field leaves legacy signature verification compatible. Current-epoch snapshot
imports require it for subsequent membership controls; an absent or mismatched
field cannot alter their roster. Legacy signed control IDs unknown to a joining
participant therefore cannot be re-encrypted at another epoch to replay authority.
Existing saved legacy controls remain verifiable as archive and initial legacy
bootstrap; their old keys are never distributed to a newly admitted member.

## Competing rekeys and retained history

A candidate is valid only after ordinary envelope/signature verification under
its source epoch and membership authorization against the authenticated roster
at that source transition. Its target must be source+1 and wrapped recipients
must match that roster exactly. Choose the lexicographically lowest valid
16-byte message ID; delivery order and replay duplicates must not affect the
winner. Unwrap the winner with the existing recipient primitive and derive its
epoch keys normally. A losing candidate must not authorize members or messages.

Clients retain signed originals and enough prior key/roster context to reconsider
a late candidate. Old keys may authenticate rekey candidates and previously saved
history; they never authorize newly received old-epoch text or files. If a lower
winner invalidates a descendant branch, preserve saved history, rewind active
key/roster state to the selected transition and replay available authenticated
controls along the winning branch. Keep still-unread ciphertext bounded while
waiting for its required key; invalid ciphertext must not grant authority.

A member admitted through a current-epoch snapshot deliberately lacks the previous
epoch key. If its selected bootstrap branch is later superseded, it needs a fresh
creator-sealed invitation for the canonical branch; it must not recover by asking
for previous epoch keys. Missing archival proof also requires this refresh or an
explicit participant-held recovery. This boundary follows from excluding history
keys and is not resolved by weakening signature or epoch checks.

## Creator replacement

The creator remains immutable. Company owners who have independent authority to
replace that identity establish a successor group with the intended creator and
participants, verify its identities through their agreed authority process, and
retain the old group as an archive. Possession of an old conversation invitation
or a service engagement alone does not authorize changing company authority.
This extension does not automatically rebind an application's canonical channel.

## Interoperability vectors

The v1.0/v1.1 shared vectors remain unchanged; regenerate them with the repository
spec workflow to verify that this extension does not alter existing primitives.
New signed/sealed current-epoch bootstrap and competing-rekey vectors are shared
between TypeScript and Python tests. Both suites must reject wrong creator,
recipient, conversation, expiration, roster and signature; prove no old-history
key disclosure; and converge when valid candidates arrive in opposite orders.

Participant-local receive journals preserve each recovered envelope's original
relay sequence. Hook delivery cursors use a separate monotonic local order so a
message decrypted after a later rekey is delivered once even if its relay
sequence precedes messages already consumed. This is local journal metadata,
not an extension to the signed message or exported receive-event schema.

## Legacy bearer invitations

QSP v1.0 section 12.2 remains the epoch-zero invitation policy. Before rotation,
a valid signed application message encrypted with the bearer invitation keys may
introduce its sender into a client's conversation participant list. This local
observation does not appoint a group administrator, change the immutable creator,
or authorize membership control messages. Group controls continue to require
their existing authenticated authority. Once rotated or imported from a current-
epoch invitation, application messages require the authenticated roster. Pending
rotation, exclusion and recovery states continue to pause application traffic.

## Accepted gateway control delegation

The [gateway invitation handshake](gateway-invitations.md) activates a gateway
for API workflows. Membership-control delegation additionally requires that the
signed promotion came from an existing group administrator. An administrator's
initial legacy promotion may bind ordinary participants, preserving all existing
roles and the immutable creator; a later promotion must match the current roster.
The gateway is never itself a voting member or administrator and cannot appoint
administrators or remove the creator.

A gateway invited by an ordinary participant has no blanket group-control
authority. To apply a membership proposal, the receiver independently verifies
the original proposal and latest approval/withdrawal envelopes in relay order,
the nested proposal and approval signatures, the exact conversation, source
epoch, target gateway, roster and requested membership change. Approval requires
both the proposal's threshold and a strict majority of that roster, including
an existing administrator's affirmative authorization. The administrator's
signature pins any initial legacy roster expansion. A gateway-signed applied
marker does not substitute for these approvals. This proof permits only the
matching membership event and its immediate next-epoch rekey. Transport expiry
never erases an already received signed withdrawal. Live authorization checks
proposal expiry against the receiver's current clock, not a gateway's timestamp.
Older local gateway records may supply learned keys only as a candidate legacy
roster; the same administrator and majority proof must authenticate any expansion.

Rekey resolution accepts an optional explicitly authorized control signer from
these contexts. Signature, source epoch, exact recipient roster and canonical
message-ID selection remain mandatory. A caller must never set that signer from
an unverified message, ordinary tool acceptance or a discovered endpoint.

# Group membership: add a contact, share a link

Decision recorded September 9, 2026. This is the agreed product direction;
automatic welcome delivery in the client interfaces is not yet implemented.
The unreleased [library helpers](../group-welcomes.md) prepare the encrypted
addition/rekey/welcome operation, parse public group locator links, and replay
ordinary-group membership through matching private Python/TypeScript checkpoints.

## Contact addition

The normal flow starts with a known identity in the address book:

1. A participant selects a contact and chooses **Add to group**. The client
   applies the group's existing membership rules to that operation.
2. Once the addition is authorized, the clients establish a fresh encryption
   epoch and publish a signed welcome sealed to the contact's verified public
   key. The welcome binds the group, recipient and resulting membership state.
3. The participant shares a link locating the group. The added contact opens it
   with their existing identity; their client retrieves and decrypts the welcome.

Adding the contact is the admission decision. Opening the link connects their
client to the group they already belong to. The link carries no group keys, and
forwarding it does not give another identity access.

The welcome travels through the group's existing relay stream, in an envelope
that the recipient can decrypt independently of ordinary group encryption.
Wrapping it inside a group-encrypted message would prevent the new member from
opening it. The relay transports ciphertext; clients authenticate the inviter
and membership state. This flow does not require a gateway.

Newly added members receive no earlier epoch keys. Removal excludes an identity
from subsequent key delivery. Catch-up for an existing, still-admitted member is
distinct from a new addition and must not restore access to a removed identity.

Existing legacy invite links retain their current bearer-capability semantics.
This decision does not make those links key-free or change released behavior.
Implementation and client parity are tracked in `qntm-2g7v`.

## Exploration not being pursued

We explored a **stranger requesting entry** mechanic, with a separate request
handshake and pending membership. It does not make sense for the current product
flow, so we are not pursuing it now. It is not a prerequisite for adding a
contact, and there is no stranger-entry endpoint or pending-membership state to
implement as part of this work.

The associated experimental bearer token disclosed existing group keys before
admission. That was a design error. Its APIs, exports, fixtures and dedicated CI
were removed in `083d59d`, reverting prototype `8082ea1`; the prototype was never
merged into main, published or deployed. Do not revive it as a join mechanism.
The existing gateway invitation and signed-acceptance protocol is a separate,
implemented feature and is unaffected by this decision.

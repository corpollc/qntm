# Participant gateway invitations

Ordinary conversations need no gateway registration. Any participant may invite a compatible gateway, including a self-hosted one. Setup is complete when the gateway accepts in the encrypted conversation.

1. The client calls `POST /v1/invitations` with a random 16-byte hex `invitation_id` and the participant's canonical base64url Ed25519 `inviter_public_key`. The gateway returns its public key, KID, invitation ID, and a ten-minute expiry. This candidate has no conversation keys and reserves no conversation ID.
2. The participant posts a signed `gate.promote` invitation. It names the gateway identity, conversation ID and epoch, approval policy and participant roster, and `keys_hash = SHA-256(canonical-CBOR(access))`. Here `access` contains `conv_id`, `conv_aead_key`, `conv_nonce_key`, and `conv_epoch`, with keys in canonical base64url.
3. The participant sends `POST /v1/promote` with `invitation_id`, `inviter_public_key`, and a `sealed` NaCl box authenticated by the participant and encrypted for the gateway. Its UTF-8 JSON contains the four access fields plus `invitation_msg_id` and `invitation_seq`.
4. The gateway reads the actual invitation from its configured relay, decrypts it, and verifies the inviter's signature, key commitment, gateway identity, epoch, roster and policy. Supplying keys to HTTP alone cannot activate a gateway.
5. The gateway durably saves and posts a signed `gate.accept` message naming the exact invitation message ID and `invitation_hash = SHA-256(exact signed UTF-8 invitation body)`, conversation, epoch and gateway identity. Only after the relay acknowledges this acceptance does the gateway execute requests. Clients activate only after independently verifying the matching acceptance in chat.

AIM displays **Waiting for gateway** and offers **Retry gateway invitation** until acceptance is verified. The CLI uses:

```sh
qntm gate-promote -c CONVERSATION --gateway-url https://your-gateway.example --threshold 2
qntm recv CONVERSATION
```

The CLI reports `status: waiting` after delivering the invitation; receiving `gate.accept` updates the local gateway state. Repeating a pending invitation retries the saved encrypted capsule. Expired candidates can be replaced. A relay failure leaves no active conversation state; the durable outbox retries the same signed acceptance envelope and message ID. Original bootstrap retries cannot overwrite current keys after rekeying.

Candidates are scoped by inviter public key and invitation ID, rather than conversation ID. One invalid candidate cannot reserve another participant's conversation. Multiple gateways may be invited independently; `gateway_kid` is included in new signed request and governance-proposal hashes, and votes and credentials address that gateway. New gateway instances ignore actions targeting another key.

The membership boundary follows qntm's bearer-invite model: a keyholder who can post a signed, encrypted invitation may invite a gateway. The initial roster is that participant's signed assertion; this is not an independent proof that every listed person consented. The gateway itself explicitly consents through its signed acceptance. Approval quorum and subsequent membership changes remain governed in chat.

Transport discovery identifies the gateway offered by the selected HTTPS endpoint. The gateway receives current conversation decryption keys and can read messages decryptable with them. This protocol does not add an operator approval authority or make the gateway blind to the conversation it joins.

The old plaintext-key `/v1/promote` request and operator promotion token are superseded. Existing active Durable Objects remain compatible with their stored policies; updated setup uses a separate invitation namespace. New clients and gateway code must ship together.

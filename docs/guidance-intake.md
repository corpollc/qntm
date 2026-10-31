# Recipient-sealed guidance intake

`guidance.sealed.v1` is an application body type carried by ordinary qntm messages.
It lets a published guidance provider receive first contact without giving every
requester access to other requests. It does not change ordinary message framing.

The public provider record contains its category, recipient public key and key ID,
relay URL, intake conversation ID and public intake invitation. The client checks
that the invitation's creator and conversation match the pinned provider. Public
intake keys are intentionally public; they provide transport compatibility, not
request confidentiality. The recipient's identity private key is never published.

To submit, the sender creates a fresh direct follow-up invitation and serializes:

```json
{
  "domain": "qntm.guidance.request.v1",
  "category": "ethical",
  "recipient_key_id": "32 lowercase hex characters",
  "request_id": "follow-up conversation ID in lowercase hex",
  "reply_invite": "private direct invitation token",
  "question": "The reviewed question",
  "context": "The reviewed optional context"
}
```

The sender seals these UTF-8 JSON bytes with the existing qntm NaCl box helper,
using its identity private key and the provider's pinned identity public key.
The resulting `nonce || ciphertext` is base64url encoded. Those ASCII bytes are
the complete body of a signed `guidance.sealed.v1` qntm message in the public
intake conversation. Clients retain the follow-up keys before attempting delivery.

The recipient first verifies and decrypts the outer qntm message, then opens the
box using the authenticated sender public key. It checks the exact payload fields,
domain, category, recipient key ID and text bounds. The reply invitation must be
direct, name that same sender as creator and have the `request_id` conversation ID.
The intake and reply conversation IDs must differ. This prevents a request from
substituting an unrelated follow-up destination. Services must additionally deduplicate
by provider category, authenticated sender key and request ID.

Questions have a 4,000-character limit; context has an 8,000-character limit.
Maintained senders trim surrounding whitespace and use a seven-day envelope TTL.
Receivers reject expired, malformed, oversized or unauthenticated messages.
The outer sender identity, timing and sizes remain visible to intake participants.
Box encryption is static-key encryption; it does not claim forward secrecy.

The TypeScript exports are `guidanceIntake`, `createGuidanceIntake`,
`openGuidanceIntake`, and `CORPO_GUIDANCE_PROVIDERS`. Python provides corresponding
helpers in `qntm.guidance_inbox`. These helpers perform no network request or model
assessment. CLI, MCP and browser hosts retain the explicit prepare/review/send flow.

Corpo's listening service, credentials and Grok bot configuration are operated
separately and are not shipped in either client library. Its bot triages requests
for the Corpo team; it does not automatically advise requesters or file reports.

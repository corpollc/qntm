# TypeScript gateway workflows

`@corpollc/qntm` provides typed builders, parsers, encrypted-message helpers, and history summaries for gateway requests, approvals, disapprovals, sealed credentials, and governance. Browser and Node hosts use the same wire formats as the Python CLI and the gateway Worker.

The library does not own a daemon, a review screen, or a credential store. Your application owns user or agent permissions, trusted conversation state, persistence, subscriptions, and delivery retries. It should present the complete target URL, method, payload, credential destination, and approval requirement before asking someone to authorize an action.

## Complete admission first

Use `GateClient.createInvitation`, `createGatewayInviteBody`, and `sealGatewayBootstrap` for admission. Post the signed invitation to the conversation, then submit its sealed bootstrap material with `GateClient.promote`. HTTP success is advisory. Activate the gateway only after `matchesGatewayAcceptance` verifies its signed `gate.accept` message against the exact invitation message ID and text. See [gateway invitations](gateway-invitations.md).

Construct a `GatewayContext` from that accepted identity and verified current conversation state:

| Field | Meaning |
| --- | --- |
| `conversationId` | Canonical 32-character lowercase hex conversation ID |
| `epoch` | Current conversation epoch |
| `gateway.kid`, `gateway.publicKey` | Accepted gateway identity, encoded as canonical base64url |
| `participants` | Current participant key IDs mapped to public keys, both base64url; excludes the gateway |
| `floor` | Current minimum request threshold |
| `rules` | Current service/endpoint/method threshold rules |

Never derive trusted context from the request being reviewed. Apply authenticated membership and rekey events in relay order. Only gateway-authored `gov.applied` messages update gateway policy. A new request freezes the complete current roster and requires at least the configured floor and matching rule threshold. Governance requires a strict majority of current participants, independently of the request floor. Callers can raise either threshold.

`allowLegacyUnbound: true` explicitly permits verifying old requests and proposals without a gateway ID. New builders always include the configured gateway ID. New integrations should leave this option unset.

## Build and send

The following fragment assumes the host already has `identity`, `conversation`, `context`, and a `DropboxClient` named `relay`:

```ts
import { createGateRequestBody, createGatewayMessage, serializeEnvelope } from '@corpollc/qntm'

const request = createGateRequestBody(identity, context, {
  service: 'httpbin',
  endpoint: '/post',
  verb: 'POST',
  targetUrl: 'https://httpbin.org/post',
  payload: { data: 'Hello from TypeScript' },
  requiredApprovals: 2,
})
const envelope = createGatewayMessage(identity, conversation, request, context)
await relay.postMessage(conversation.id, serializeEnvelope(envelope))
```

Persist the exact envelope before sending if your host needs restart recovery. Retry those saved bytes after an uncertain send outcome; creating another request produces another operation ID. Request IDs can be supplied explicitly through `requestId`.

Use `createGateSecretBody` to seal a credential to `context.gateway.publicKey`. Its JSON `encrypted_blob` is base64url. It accepts a service, value, header name/template, optional secret ID, and optional TTL in seconds. For the hosted gateway, even an unauthenticated API needs a configured service entry; the README uses a harmless demonstration header. An expired credential must be provisioned again.

## Review and vote

`parseGatewayBody(bodyType, bytesOrText)` validates a supported body's shape and preserves its fields. It does **not** authenticate the sender or authorize an operation. It rejects mismatched body types, malformed encodings, duplicate signer IDs, and unsupported `gate.config`/`gate.revoke` mutations.

For a received wire envelope, use `decryptGatewayMessage(envelope, conversation, context, references)`. It authenticates the ciphertext and associated data, then verifies the envelope signature and sender key, conversation and epoch bindings, participant eligibility, nested request/proposal signatures, and approval signatures. If your host already decrypted the message, pass the unmodified `decryptMessage` result to `verifyGatewayMessage(message, context, references)`; a caller-constructed object with `verified: true` is not proof of AEAD authentication. Gateway result, execution, expiry, invalidation, acceptance, and applied-policy events must come from the configured gateway. Approval and disapproval messages require the referenced request or proposal. Acceptance requires the verified invitation's exact ID and text.

For a reviewed request, call `createGateApprovalBody(identity, context, request)` or `createGateDisapprovalBody(identity, context, request)`. Pass `{ request }` when encrypting or verifying the resulting message. Approval construction rejects expired requests, stale rosters, wrong contexts, and invalid signatures. Disapproval relies on the enclosing signed envelope, as in the existing protocol.

For governance, use `createGatewayProposalBody` with `floor_change`, `rules_change`, `member_add`, or `member_remove`. The corresponding vote builders are `createGatewayProposalApprovalBody` and `createGatewayProposalDisapprovalBody`; pass `{ proposal }` as the reference. Python's explicit `null` fields and TypeScript's absent fields are preserved during signature reconstruction.

## Interpret history

Keep events returned by `verifyGatewayMessage` in authenticated relay order. Sender timestamps do not determine vote order. `findGateRequest` and `findGatewayProposal` locate subjects; `scanGateRequest` and `scanGatewayProposal` summarize them. Repeated envelope IDs are deduplicated, conflicting IDs are rejected, each eligible signer has one effective vote, and the last vote wins. The subject author's signature counts as the first approval. A changed roster invalidates a pending subject; trusted terminal records remain historical facts.

`approved` means the local verified transcript has enough approvals. It does not mean the gateway accepted or executed the request, or that a usable credential exists. `executed`, `applied`, and `invalidated` come from authenticated gateway events; results are separate from approval counts. Check the status before interpreting the counts.

Verification uses the context current when the message is processed. To reverify historical envelopes after a reload, retain the corresponding verified membership/policy/epoch state. The library does not reconstruct all historical state from untrusted JSON or restore a serialized `VerifiedGatewayEvent` as an authentication guarantee. Applications that persist derived events must protect and validate that storage themselves.

## Coverage and boundaries

Tests exercise encrypted envelope roundtrips, altered signatures, forged terminal events, different conversations and epochs, removed signers, stale rosters, expiry, duplicate delivery, last-vote behavior, credential sealing, and nullable Python governance fields. Real browser/Python/TypeScript journeys cover approved execution, policy and membership changes, key rotation, negative authorization, and gateway restart recovery.

The terminal UI and OpenClaw plugin still need their own gateway action interfaces. These helpers provide a shared implementation for that work; they do not install host-specific tools or grant an agent permission to invoke them.

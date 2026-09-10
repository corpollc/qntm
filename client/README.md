# @corpollc/qntm

TypeScript client library for the qntm secure messaging protocol.

## Install

```bash
npm install @corpollc/qntm
```

## What it includes

- Identity generation and key IDs
- Invite creation and acceptance
- Encrypted message create/decrypt helpers
- Group membership and rekey helpers
- Gate request, approval, and secret helpers
- Typed gateway/governance builders, authenticated-message verification, and history summaries
- Dropbox relay client for browser or Node runtimes
- Continuous subscriptions and portable `ReceiveEvent` / `createReceiveEvent` helpers

## Basic usage

```ts
import { generateIdentity, DropboxClient } from '@corpollc/qntm'

const identity = generateIdentity()
const dropbox = new DropboxClient('https://inbox.qntm.corpo.llc')
```

For the protocol specification, see `docs/QSP-v1.1.md` in the main repository.

QSP and charter verification share a strict Ed25519 profile. Use
`isValidEd25519PublicKey` and `verifyEd25519Signature` from `@corpollc/qntm/crypto`
for the same acceptance rules in host code. See
[signature validation](https://github.com/corpollc/qntm/blob/main/docs/signature-validation.md)
for malformed-key rejection, compatibility and shared cross-language vectors.

`DropboxClient.subscribeMessages` delivers replay and live envelopes with automatic
reconnects. Persist each event before resolving `onMessage`; a rejection causes
replay before later messages can advance progress. `createReceiveEvent` converts a
verified decrypted message into the same versioned event exposed by the Python
library and CLI hooks. Storage, hook delivery, and turn scheduling remain owned by
the application. See [receive hooks and language boundaries](https://github.com/corpollc/qntm/blob/main/docs/receive-hooks.md).

## Gateway workflows

Use `createGateRequestBody`, `createGateApprovalBody`, `createGateSecretBody`, and
`createGatewayProposalBody` with a verified `GatewayContext`. `createGatewayMessage`
encrypts the matching body type; `verifyGatewayMessage` checks authenticated senders
and signatures. History helpers summarize unique votes and gateway terminal events.
See the [TypeScript gateway guide](https://github.com/corpollc/qntm/blob/main/docs/typescript-gateway.md)
for admission, disapproval, governance, legacy compatibility, and host responsibilities.

## Experimental charter support

Import `@corpollc/qntm/charter` for self-charters, parent/threshold governance,
namespace statements, signed transitions, and verification of registrar log/map
proofs. The [Go reference server and runnable example](https://github.com/corpollc/qntm/blob/main/charter-registry/README.md)
exercise the same unratified v0.2 draft. The [public experimental registry and trusted pin](https://github.com/corpollc/qntm/blob/main/docs/charter-operations.md) are available at `https://charter.qntm.corpo.llc`. Independent witnesses remain unimplemented. The ordinary client import does not opt into charter APIs.

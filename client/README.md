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
- Dropbox relay client for browser or Node runtimes
- Continuous subscriptions and portable `ReceiveEvent` / `createReceiveEvent` helpers

## Basic usage

```ts
import { generateIdentity, DropboxClient } from '@corpollc/qntm'

const identity = generateIdentity()
const dropbox = new DropboxClient('https://inbox.qntm.corpo.llc')
```

For the protocol specification, see `docs/QSP-v1.1.md` in the main repository.

`DropboxClient.subscribeMessages` delivers replay and live envelopes with automatic
reconnects. Persist each event before resolving `onMessage`; a rejection causes
replay before later messages can advance progress. `createReceiveEvent` converts a
verified decrypted message into the same versioned event exposed by the Python
library and CLI hooks. Storage, hook delivery, and turn scheduling remain owned by
the application. See [receive hooks and language boundaries](https://github.com/corpollc/qntm/blob/main/docs/receive-hooks.md).

## Experimental charter support

Import `@corpollc/qntm/charter` for self-charters, parent/threshold governance,
namespace statements, signed transitions, and verification of registrar log/map
proofs. The [Go reference server and runnable example](https://github.com/corpollc/qntm/blob/main/charter-registry/README.md)
exercise the same v0.2 draft. This draft is unratified; no public registry or
independent witnesses are included. The ordinary client import does not opt into
charter APIs.

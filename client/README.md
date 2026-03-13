# @qntm/client

TypeScript client library for the qntm secure messaging protocol.

## Install

```bash
npm install @qntm/client
```

## What it includes

- Identity generation and key IDs
- Invite creation and acceptance
- Encrypted message create/decrypt helpers
- Group membership and rekey helpers
- Gate request, approval, and secret helpers
- Dropbox relay client for browser or Node runtimes

## Basic usage

```ts
import { generateIdentity, DropboxClient } from '@qntm/client'

const identity = generateIdentity()
const dropbox = new DropboxClient('https://inbox.qntm.corpo.llc')
```

For the protocol specification, see `docs/QSP-v1.1.md` in the main repository.

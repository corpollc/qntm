# qntm NanoClaw Channel MVP

`nanoclaw-qntm` is the source-of-truth scaffold for the first qntm NanoClaw integration shipped through an external-remote install path.

It is intentionally shaped like NanoClaw:

- `src/types.ts` mirrors NanoClaw's channel/message types
- `src/channels/registry.ts` mirrors NanoClaw's channel registry
- `src/channels/qntm.ts` implements the qntm channel MVP

The initial MVP covers:

- `qntm:<conv-id>` JIDs
- `QNTM_RELAY_URL` and `QNTM_IDENTITY_DIR`
- relay-websocket subscriptions for registered qntm conversations
- outbound text replies
- self-message suppression
- cursor resume from persisted per-conversation sequence state
- cursor persistence under `store/qntm/cursors/`
- readable fallback text for non-text qntm bodies

## Intended Use

This package is not a NanoClaw plugin runtime. It is the implementation scaffold that should be copied into the external NanoClaw integration repo used by `/add-qntm`.

## Local Validation

```bash
cd nanoclaw-qntm
npm test
npm run typecheck
```

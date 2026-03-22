# qntm as a First-Class NanoClaw Messaging Channel

## Goal

Make `qntm` a first-class messaging channel for NanoClaw while conforming to NanoClaw's current channel model:

- host-side channel implementation under `src/channels/`
- setup via `/add-*` skill flow
- explicit group registration in SQLite
- agent replies routed through NanoClaw's existing `send_message` and outbound router

This should reuse qntm's existing transport and crypto libraries rather than porting OpenClaw's plugin runtime into NanoClaw.

## Findings From `~/src/nanoclaw`

### 1. NanoClaw channels are source integrations, not runtime plugins

NanoClaw expects each messaging integration to implement the `Channel` interface and self-register from `src/channels/<name>.ts`.

Relevant files:

- `src/types.ts`
- `src/channels/registry.ts`
- `src/channels/index.ts`
- `docs/SPEC.md`

That means a NanoClaw `qntm` integration should look like a normal NanoClaw channel skill, not like `openclaw-qntm/`.

### 2. The local Telegram skill exists, but the branch story is currently inconsistent

As of **March 22, 2026**:

- the local checkout includes `.claude/skills/add-telegram/SKILL.md`
- `docs/skills-as-branches.md` documents a branch-backed model with `skill/telegram`
- but `git ls-remote --heads origin 'refs/heads/skill/*' 'refs/heads/*telegram*'` showed only:
  - `skill/apple-container`
  - `skill/compact`
  - `skill/ollama-tool`
- and the current `add-telegram` skill merges from a separate remote repo, `qwibitai/nanoclaw-telegram`, not from `skill/telegram`

So NanoClaw appears to be mid-transition between two distribution models:

- documented target model: marketplace + `skill/*` branches
- current practical model for Telegram: local skill stub + external remote merge

This affects how `qntm` should be shipped.

### 3. qntm already has most of the transport pieces

`qntm` already contains a working OpenClaw channel plugin under `openclaw-qntm/`. The NanoClaw integration should reuse its transport logic where possible:

- identity loading from string/file/profile dir
- conversation resolution from invite or profile data
- relay websocket monitoring
- cursor persistence
- decrypt/parse inbound envelopes
- outbound `postMessage` text sends
- fallback formatting for non-text bodies

Relevant files:

- `openclaw-qntm/src/qntm.ts`
- `openclaw-qntm/src/monitor.ts`
- `openclaw-qntm/src/accounts.ts`
- `openclaw-qntm/src/setup-core.ts`
- `openclaw-qntm/src/state.ts`

The OpenClaw-specific parts should not be reused directly:

- `openclaw/plugin-sdk`
- OpenClaw runtime/session routing
- OpenClaw config schema and setup adapters

## What "First-Class" Should Mean

For NanoClaw, `qntm` is first-class if:

1. `/setup` and `/customize` can offer `/add-qntm`.
2. A user can connect NanoClaw to one or more qntm conversations without hand-editing TypeScript.
3. Registered qntm conversations behave like other NanoClaw groups.
4. `send_message` and normal agent replies go back to the correct qntm conversation.
5. `setup/verify.ts` reports qntm as configured.
6. qntm can coexist with WhatsApp, Telegram, Slack, or Discord in the same NanoClaw install.
7. The integration has automated tests and a documented setup flow.

## Recommended Integration Shape

### Channel identity

Use NanoClaw JIDs in the form:

```text
qntm:<conv-id>
```

This matches NanoClaw's channel-prefixed JID pattern and is also consistent with the existing OpenClaw qntm integration.

Folder names should follow the existing NanoClaw convention:

```text
qntm_<slug>
```

Examples:

- `qntm_main`
- `qntm_ops`
- `qntm_release-war-room`

### NanoClaw runtime model

The NanoClaw channel should:

- implement `Channel`
- read the registered groups map and subscribe only to registered `qntm:` conversations
- emit inbound messages through `onMessage(chatJid, message)`
- emit chat metadata through `onChatMetadata(...)`
- send outbound text via qntm `postMessage`
- ignore self-authored qntm messages
- persist relay cursors under NanoClaw-owned state

### Config model

Keep config minimal and compatible with NanoClaw's setup flow. Recommended inputs:

- `QNTM_RELAY_URL` with the current relay default
- `QNTM_IDENTITY_DIR` for a NanoClaw-owned or user-owned qntm profile directory

Optional later additions:

- `QNTM_IDENTITY_JSON`
- multi-account support
- per-conversation overrides

For NanoClaw MVP, `QNTM_IDENTITY_DIR` is the cleanest path because it lets the channel load:

- `identity.json`
- `conversations.json`

without inventing a second NanoClaw-specific conversation config format.

### Message model

MVP should support:

- inbound text messages
- outbound text replies
- multiple registered qntm conversations from one profile

Non-goals for MVP:

- media uploads
- typed `gate.*` authoring
- richer membership/governance UX
- qntm-native approval workflows inside NanoClaw

Non-text inbound qntm bodies should be surfaced as readable fallback text, for example:

```text
[gate.request] {...}
```

That preserves visibility without blocking the transport integration on deeper qntm protocol support.

## Implementation Plan

### Phase 0: Resolve Distribution Strategy

Before writing code, decide how the NanoClaw side will ship.

### Recommended

Adopt the documented NanoClaw target model:

- add `/add-qntm` as a feature skill
- ship the code on a `skill/qntm` branch
- expose the skill via the NanoClaw marketplace flow

### Fallback if upstream is not ready

Mirror the current Telegram reality:

- keep `/add-qntm` as a host-side skill on NanoClaw main
- have it merge from a dedicated external repo, such as `corpollc/nanoclaw-qntm`

### Recommendation

Prefer the branch-backed `skill/qntm` model, but explicitly plan for a temporary external-remote path if NanoClaw maintainers have not finished the branch migration.

This should be resolved first because it changes:

- skill instructions
- contributor workflow
- update path
- where the NanoClaw code ultimately lives

### Phase 1: Extract qntm-Reusable Helpers

Create or expose NanoClaw-usable helpers from the qntm repo so the NanoClaw channel does not need to duplicate OpenClaw-specific code.

Recommended reusable surface:

- `resolveQntmIdentity(...)`
- `loadQntmConversationFromDir(...)`
- `resolveInviteConversation(...)`
- `decodeQntmBody(...)`
- `sendQntmText(...)`
- cursor storage primitives or a tiny monitor helper that is not tied to OpenClaw runtime types

Target outcome:

- OpenClaw keeps its adapter layer
- NanoClaw gets a clean channel-facing helper layer
- transport logic has one authoritative home

If this extraction is too much for the first pass, copy the minimal helpers into the NanoClaw branch and then backfill the shared library cleanup after the channel works.

### Phase 2: Build the NanoClaw `qntm` Channel

In NanoClaw, add a new channel module:

```text
src/channels/qntm.ts
```

Responsibilities:

1. `registerChannel('qntm', factory)`
2. return `null` when qntm credentials are missing
3. on `connect()`, load identity/profile data and start one relay subscription per registered `qntm:` conversation
4. on inbound envelope:
   - decrypt
   - skip self-authored messages
   - map to NanoClaw `NewMessage`
   - emit metadata
5. on `sendMessage(jid, text)`, post encrypted qntm text to the matching conversation
6. persist per-conversation cursor state
7. implement `ownsJid()` using `qntm:` prefix

Recommended state location:

```text
store/qntm/
```

Suggested files:

- `store/qntm/cursors/<conv-id>.json`
- optionally `store/qntm/runtime.json`

Update NanoClaw barrel import:

```text
src/channels/index.ts
```

### Phase 3: Add the `/add-qntm` Skill

Create a NanoClaw feature skill that installs the channel and performs setup.

The skill should:

1. apply the qntm channel code using the chosen distribution model
2. ensure dependencies are installed
3. collect either:
   - an existing `QNTM_IDENTITY_DIR`, or
   - a qntm invite token to join into a NanoClaw-managed profile dir
4. write required env vars
5. discover the joined conversation id and label
6. register the conversation with `setup/index.ts --step register`
7. rebuild and verify

Recommended registration examples:

```bash
npx tsx setup/index.ts --step register -- \
  --jid "qntm:<conv-id>" \
  --name "<conversation-name>" \
  --folder "qntm_main" \
  --trigger "@${ASSISTANT_NAME}" \
  --channel qntm \
  --no-trigger-required \
  --is-main
```

or for secondary groups:

```bash
npx tsx setup/index.ts --step register -- \
  --jid "qntm:<conv-id>" \
  --name "<conversation-name>" \
  --folder "qntm_<slug>" \
  --trigger "@${ASSISTANT_NAME}" \
  --channel qntm
```

### Phase 4: Wire qntm Into NanoClaw Setup and Verification

Update NanoClaw setup surfaces so qntm is treated like the other messaging channels.

Expected changes:

- `/setup` offers qntm in the channel picker
- `/customize` can install qntm later
- `setup/verify.ts` reports qntm when configured
- docs mention qntm as a supported channel option

Likely NanoClaw touchpoints:

- `.claude/skills/setup/SKILL.md`
- `.claude/skills/customize/SKILL.md`
- `setup/verify.ts`
- `docs/SPEC.md`
- `README.md`

### Phase 5: Tests

### qntm repo

Add tests for any extracted reusable helpers.

Focus areas:

- identity/profile loading
- conversation lookup
- inbound body decoding
- outbound send envelope creation

### NanoClaw side

Add channel tests covering:

- factory returns `null` when qntm is unconfigured
- inbound text delivery
- self-message suppression
- non-text fallback formatting
- outbound text send
- cursor resume across reconnect
- `ownsJid('qntm:...')`

Use a mocked qntm client rather than a live relay for most coverage.

### Phase 6: Follow-On Work After MVP

Once the text transport path is stable, consider separate follow-up work for:

- qntm multi-account support
- better sender labels derived from conversation membership metadata
- media attachments
- qntm `gate.*` workflows as a dedicated skill or agent toolset
- qntm-specific container skill(s) for approval-oriented workflows
- richer setup flows for creating new conversations directly from NanoClaw

These should be separate issues. They are not required to make qntm first-class as a messaging channel.

## Acceptance Criteria

The first implementation is done when all of the following are true:

1. A NanoClaw user can run `/add-qntm`.
2. A registered `qntm:<conv-id>` conversation receives inbound messages in NanoClaw.
3. NanoClaw agent replies are delivered back to the same qntm conversation.
4. Multiple qntm conversations can coexist in one NanoClaw install.
5. `setup/verify.ts` reports qntm as configured.
6. The integration works without hand-editing NanoClaw source after the skill runs.
7. The transport path is covered by automated tests.

## Recommended Work Breakdown

1. Decide branch-backed skill vs external-remote skill.
2. Extract or stabilize shared qntm helper APIs.
3. Build the NanoClaw channel implementation.
4. Add `/add-qntm` setup skill.
5. Wire qntm into setup/customize/verify/docs.
6. Add tests.
7. Ship follow-up issues for non-MVP protocol features.

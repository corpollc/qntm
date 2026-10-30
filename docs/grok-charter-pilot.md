# Grok charter pilot

`scripts/grok_charter_bot.py` runs an on-demand terminal bot through the installed,
authenticated Grok CLI. It gives the bot a persistent qntm identity, publishes its
charter through the pinned public registrar, and creates signed informational
responses. It is not a resident qntm chat listener or an independent witness.

The pilot's purpose is to explain its charter and report on charter lifecycle
experiments. With self-governance, the agent key is the sole governor; no separate
human signature is required by the registry. The host holds that private key and
performs signing. Grok receives public charter data, the verified current state,
and the prompt. The model does not receive keys or tools. Protocol authority is
not proof of model independence or behavioral compliance.

## Run

From a checkout containing the pilot:

```sh
uv venv .venv
uv pip install --python .venv/bin/python -e ./python-dist
grok login
.venv/bin/python scripts/grok_charter_bot.py prepare --governance self --model grok-4.7
.venv/bin/python scripts/grok_charter_bot.py show
.venv/bin/python scripts/grok_charter_bot.py publish
.venv/bin/python scripts/grok_charter_bot.py ask 'Explain your purpose and who controls your governance.'
```

`prepare` writes a private identity and an exact signed founding record without
contacting the registry. It refuses to replace an existing bot. The default state
directory is `~/.qntm-bots/grok-charter`; put `--state-dir PATH` before the command
to use another directory. `show` prints only the public founding record.

`publish` without `--draft` permanently publishes the prepared charter. `ask`
authenticates the current chain, checks consistency against the saved checkpoint,
and invokes Grok. It returns the answer and a `draft-….json` filename. The prompt
and response remain local until an explicit publication command. They are sent
to Grok for inference, and the Grok CLI may retain its own session history.

Review that exact JSON file, then publish it if desired:

```sh
.venv/bin/python scripts/grok_charter_bot.py publish --draft draft-REPLACE_WITH_RETURNED_NAME.json
.venv/bin/python scripts/grok_charter_bot.py verify
```

Both the prompt and response become public, append-only history when published.
The script publishes only its founding record and informational statements in
the pilot namespace. Self-governance permits future governance changes through
the charter library; this initial terminal interface does not expose those
actions to the model.

## First live pilot

On October 30, 2026, Grok 4.7 produced the introduction for agent
`1c1cb643837112ec93c0e007c684eaec`. Its [public chain](https://charter.qntm.corpo.llc/v1/chain/1c1cb643837112ec93c0e007c684eaec)
contains a self-governing charter at sequence 0 and that introduction at sequence
1. A fresh Python process verified the agent chain, consistency with the retained
checkpoint, and the full four-entry registry snapshot. The two statement hashes
are `2b97830d5fd58a368b8a919aba90e26c47c829cfd0eaf1a02f461cebba8101ba`
and `6d549f6ecc2ebd0d9abf79fdeafaadc60ae49cee8a7f3fe02af1dc5ecf4d3dc9`.
This was a real authenticated Grok CLI run; no continuous listener was installed.

For proposed-action assessments across arbitrary JSON documents and parent/child
histories, use the [charter integration lab](charter-integration-lab.md). It adds
research, PII, MNPI, conflicting authority and uncertainty scenarios with cited
model judgments and separate cryptographic checks.

## Recovery and verification

Files use owner-only permissions, commands hold a local lock, and identity,
genesis and checkpoints are saved atomically. Keep a protected backup of the
whole state directory: it contains the bot's signing key. Losing it loses control
of a self-governed record. There is no automatic replacement key or reset command.

A failed POST may have committed. Rerun the same publication command: it first
reads and authenticates the chain, and reports success without reposting if that
exact statement is already present. A conflicting statement at the same sequence
is rejected; the original draft is preserved for review. Failed verification does
not advance the retained checkpoint. An informational response is validated
against current authority again before submission.

`verify` checks the complete agent chain, compares the retained checkpoint and
audits both roots of the full registry snapshot. The command can run in a fresh
process after restart. An old but valid checkpoint can still be served to a
first-time client; this pilot provides no independent witness or wall-clock
freshness guarantee.

## Tests

```sh
uv pip install --python .venv/bin/python pytest
(cd charter-registry && go build -o /tmp/qntm-grok-pilot-registry ./cmd/charter-registry)
QNTM_CHARTER_TEST_BINARY=/tmp/qntm-grok-pilot-registry .venv/bin/python -m pytest python-dist/tests/test_grok_charter_bot.py -q
```

The real Go test exercises publication, a lost acknowledgement after commit,
conflicting drafts, retained-checkpoint rollback rejection and server restart. Its
model reply is deterministic; it does not establish live Grok inference. The
remaining tests cover key persistence, self-governance authority, private storage,
concurrent access, and excluding keys/tools from model input. A real Grok run is a
separate live acceptance check.

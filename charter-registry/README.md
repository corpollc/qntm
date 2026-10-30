# Charter Registry reference server

This Go server implements the experimental [v0.2 draft](../specs/working-group/charter-registry.md): self-charters, agent-governed subagents, threshold governance, namespaced experiments, durable append-only storage, and verifiable log/map proofs. It is separate from the qntm relay and gateway. The draft is unratified and independent witnesses are not implemented. A public experimental deployment runs at **https://charter.qntm.corpo.llc**; see its [trusted pin, limits, monitoring and operations guide](../docs/charter-operations.md).

## Run locally

Requires Go 1.27.1 or newer (the module pins a patched standard library):

```sh
cd charter-registry
go run ./cmd/charter-registry --listen 127.0.0.1:8085 --data-dir ./data --registry localhost
```

The startup JSON prints the bound address, registry audience, and registrar public key. Distribute that public key through a trusted channel. Both maintained clients require an explicit pin; neither learns trust automatically from `/v1/info`.

The database contains the registrar's private signing seed and all accepted statements. The server creates its directory with mode 0700 and database with mode 0600, holds an exclusive process lock, and commits/fsyncs each statement before returning a receipt. Restarting preserves its identity and historical signed heads. Startup replays the stored history and rejects corruption or a different registry audience.

For a consistent backup, use the loopback-only admin listener (`--admin-listen 127.0.0.1:9085`) and fetch `/backup`, or stop the process before copying `data/registry.db`. The admin response includes the private signing key; never expose it publicly. Preserve the entire file, including metadata. Losing it loses both history and the registrar key. Do not replace a lost database with a new empty one under an existing trusted identity. Restoring an old backup can lose previously acknowledged writes; compare retained external checkpoints before serving it.

## TypeScript client

Build `client/` and import the opt-in `@corpollc/qntm/charter` subpath. Normal qntm imports do not opt into charter APIs.

```ts
import { generateIdentity } from '@corpollc/qntm';
import {
  CharterRegistryClient, createCharter, charterKey,
  createCharterStatement, signCharterStatement, charterAgentId,
  auditCharterSnapshot,
} from '@corpollc/qntm/charter';

// Supply a public key received through your trusted configuration channel.
const trust = { registry: 'localhost', registrar: configuredRegistrarKey };
const registry = new CharterRegistryClient('http://127.0.0.1:8085', trust);
const agent = generateIdentity(); // Persist securely if this agent will continue.
const charter = createCharter({
  registry: trust.registry,
  agent,
  governance: { keys: [charterKey(agent.publicKey)], threshold: 1 },
  agentRights: ['statement'],
  extensions: { 'studio.example': { interests: ['music', 'gardening'] } },
});
await registry.submit(charter);
const statement = signCharterStatement(createCharterStatement(charter, 'statement', {
  namespace: 'studio.example/preferences', data: { collaboration: 'welcome' },
}), agent);
await registry.submit(statement);
const { record, evidence } = await registry.chain(charterAgentId(agent.publicKey));
const checkpoint = evidence.heads;
auditCharterSnapshot(await registry.log(checkpoint), checkpoint, trust);
```

For a parent-governed child, put the parent's public key in `governance` and add its signature with `signCharterStatement(charter, parent)` before submission. The child still signs its own genesis. A threshold charter needs the required current governor signatures; a self-governing agent can satisfy both roles with one signature.

`chain()` verifies the pinned registrar signatures, range proof, full statement chain, and every authority transition. `submit()` verifies an inclusion receipt for the exact submitted envelope. `heads()` authenticates checkpoints. `consistency(older, newer)` proves append-only growth between retained checkpoints. `log()` only downloads snapshot entries: pass them to `auditCharterSnapshot()` to authenticate every chain and recompute both roots.

A signature proves a key made a statement. It does not prove compliance with that statement. A valid checkpoint can also be old: clients must retain checkpoints and apply their own freshness policy. Merkle proofs alone cannot detect a registrar maintaining isolated, internally consistent views. Independent witnesses or checkpoint gossip remain necessary for that threat.

## Python client

Install qntm v0.6.2 or later with `pip install 'qntm>=0.6.2'` and import `qntm.charter`. Normal messaging imports do not opt into charter behavior. Supply `configured_registry_url`, `configured_registry_id`, and `configured_registrar_key` from trusted local configuration. The key is a dictionary containing canonical `kid` and `pubkey` strings; see the [hosted registrar pin](../docs/charter-operations.md).

```python
from qntm import generate_identity
from qntm.charter import (
    CharterRegistryClient, audit_charter_snapshot, charter_agent_id, charter_key,
    create_charter, create_charter_statement, sign_charter_statement,
)

trust = {"registry": configured_registry_id, "registrar": configured_registrar_key}
agent = generate_identity()  # Persist privately if this agent will continue.
charter = create_charter(
    registry=trust["registry"], agent=agent,
    governance={"keys": [charter_key(agent["publicKey"])], "threshold": 1},
    extensions={"studio.example": {"interests": ["music", "gardening"]}},
)
with CharterRegistryClient(configured_registry_url, trust) as registry:
    receipt = registry.submit(charter)
    statement = sign_charter_statement(create_charter_statement(charter, "statement", {
        "namespace": "studio.example/preferences", "data": {"collaboration": "welcome"},
    }), agent)
    registry.submit(statement)
    result = registry.chain(charter_agent_id(agent["publicKey"]))
    checkpoint = result.evidence["heads"]
    registry.consistency(receipt["heads"], checkpoint)
    audit_charter_snapshot(registry.log(checkpoint), checkpoint, trust)
    assert result.record.sequence == 1
```

`create_charter()` adds the agent signature. For a parent-governed child, name the parent in `governance` and call `sign_charter_statement(charter, parent)` before submission. Add enough governor signatures to satisfy the current threshold. `governance=None` freezes a record at birth, including informational writes. Self-governance instead names the agent's own key as a governor.

`replay_charter_chain(chain, registry=..., agent_id=...)` authenticates an offline chain and returns a `CharterRecord` with snake-case attributes. Wire documents remain dictionaries using the same keys and canonical encodings as TypeScript and Go. Namespaced data has no implicit authority or merge behavior. Both libraries support all core statement types, governance commitments, operational-key declarations, successor/decommission statements, head/receipt/range/consistency verification, and full snapshot audits.

The synchronous transport has the same verified `submit`, `heads`, `chain`, `consistency`, and `log` operations as TypeScript. `heads(snapshot_size)` and `chain(agent_id, snapshot_size)` require the exact requested historical snapshot. `CharterRegistryError` exposes `status` and `code`; malformed authority/evidence raises `CharterError`. HTTP transport errors remain HTTPX exceptions. HTTPS is required except on loopback; redirects and automatic submission retries are disabled. The client uses HTTPX timeouts of 30 seconds and caps each decoded response at 32 MiB, both configurable at construction. Close it or use a context manager. After a lost submission response, inspect the authenticated chain before deciding whether to submit again.

`charter_json_bytes`, `canonicalize_charter_json`, and `parse_charter_json` implement the shared RFC 8785 wire domain with duplicate-key, Unicode, and nesting checks. JSON number tokens use binary64 rounding, matching `JSON.parse`. In-memory Python integers that cannot be represented exactly in binary64 are rejected; use strings for exact large numbers. Sequences, thresholds, and proof indices must remain safe integers. Public keys and signature points follow the same strict subgroup rules in all three implementations.

Clients do not silently save trust or checkpoints. Persist authenticated heads in your own private storage, enforce your freshness policy, and use `consistency()` when advancing them. A stale but correctly signed snapshot remains valid historical evidence. Independent witnesses and checkpoint gossip are still separate work.

## Reference HTTP profile

This transport makes the draft executable; it is not a ratified protocol. JSON bodies use the draft's canonical wire encodings. HTTPS is required by the client except for loopback development. Writes are authorized by statement signatures, with no operator admission token. Responses have `Cache-Control: no-store`.

| Endpoint | Result |
| --- | --- |
| `GET /healthz` | Process health |
| `GET /v1/info` | Audience, public key, draft version, limits, `witnessed: false` |
| `POST /v1/statements` | 201 after durable commit, with statement hash, log inclusion proof, signed heads |
| `GET /v1/heads?size=N` | Current or historical checkpoint |
| `GET /v1/chain/{agent_id}?size=N` | Complete chain plus membership/completeness or absence proof |
| `GET /v1/inclusion/{index}?size=N` | Zero-based log inclusion proof and checkpoint |
| `GET /v1/consistency?from=N&to=M` | Checkpoints and RFC 6962 consistency path |
| `GET /v1/log?size=N&from=0&limit=100` | Snapshot page, next offset, checkpoint; limit 1–1000 |

Omit `size`/`to` for the latest snapshot. Sizes and indices are canonical non-negative decimal safe integers. Errors are JSON `{error, message}`: 400 malformed input or bounds, 413 statement above 1 MiB, 422 invalid authority, 409 sequence conflict, 500 storage failure. Repeating an accepted submission returns 409; after an ambiguous network failure, retrieve and verify the chain to establish whether it committed. Never manufacture a replacement successor from an unverified head.

Both trees use RFC 6962 shape and SHA-256 domain separation: empty root `SHA256(empty)`, leaf `SHA256(0x00 || JCS(value))`, internal node `SHA256(0x01 || left_hash_bytes || right_hash_bytes)`. Log values are `{statement, received_at}` including the signature envelope. Map values are `{agent_id, seq, statement_hash}`, ordered by agent ID bytes then numeric sequence (equivalent to the draft's fixed-width big-endian sort key). The statement hash covers only its `signed` body.

Each append produces an epoch whose number, map size, and log size equal the global entry count. Signed log bodies are `{kind: "charter.log", registry, tree_size, root_hash, timestamp}`. Signed epoch bodies are `{kind: "charter.epoch", registry, epoch, map_size, map_root, log_size, log_root, timestamp}`. Each is wrapped as `{signed, kid, sig}` and signed over JCS bytes. Historical timestamps come from the last entry, or database creation time for an empty tree.

Inclusion paths list sibling hashes from leaf to root. A range proof carries the last map leaf at or before the queried agent and its immediate successor, each with index and inclusion path. Null witnesses denote tree boundaries. Presence plus the last leaf's sequence establishes the required chain length; statement hash links authenticate its interior. Full snapshot audits verify the sorted map matches the chronological log.

## Limits and deployment

This is a small reference registrar: it replays history and rebuilds trees in memory. Defaults limit accepted history to 2,000 entries and 16 MiB, with a 1 MiB request body limit and four concurrent HTTP requests. The hosted deployment adds Nginx throttling, exe.dev TLS, private Prometheus/Grafana monitoring, and daily consistent snapshots. See [operations](../docs/charter-operations.md) before changing these limits. Tree caching, multi-process replication, configurable CORS, independent witnesses, and automated registrar key rotation remain unimplemented. Keep loopback binding for local experiments. No dependency on the qntm gateway is required.

## Verification

```sh
cd charter-registry
go test -race ./...
go vet ./...
cd ../client
python3 -m pip install -e ../python-dist
npm ci
npm run build
npm test
npm run test:charter-server
```

Shared deterministic fixtures in `specs/test-vectors/charter-registry-v02.json` cover authority rules, strict Ed25519 key acceptance, and JCS interoperability in Python, TypeScript and Go. Regenerate with `node client/scripts/generate-charter-vectors.mjs` after building the client. The integration suite starts the real Go server, exchanges signed parent/child and threshold changes between Python and TypeScript, verifies historical proofs and snapshot audits from both clients, exercises competing writes, and kills/restarts the server to check persistence. It also executes the Python HTTP example above. Set `QNTM_CHARTER_PYTHON` when the installed Python client uses a non-default interpreter. Python unit tests run with `python -m pytest python-dist/tests` from the repository root.

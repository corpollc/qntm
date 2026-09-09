# Charter Registry — v0.2 DRAFT

## Status

**v0.2 DRAFT (2026-09-08).** Not ratified. Seeking review.

**DRI:** qntm (@vessenes)

**Operator model:** The registrar described here is operated by qntm. The design goal is that this requires minimal trust: every guarantee except liveness is independently verifiable or externally auditable (§8, §10).

**Implementations:** experimental TypeScript construction, signing, chain replay, proof verification, and HTTP client in `client/src/charter/`; a durable Go reference registrar in [`charter-registry/`](../../charter-registry/README.md), tested against the TypeScript client and shared vectors. Independent witnessing is not implemented. This draft remains unratified.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 1. Purpose

The Charter Registry is a public, append-only record of durable statements about agents and the governance choices they make or accept. Governors MAY be humans, organizations, agents, or groups of keyholders. An agent MAY charter and govern itself, delegate governance, or charter a subagent that it governs.

The founding record for an agent is its **charter**: the first statement in the agent's record, signed by the agent's own key, which irrevocably designates *who may write everything after it*. The charter is a durable founding document for the record. It MAY be issued before or after the agent begins operating. Its history is immutable; subsequent statements require the authority designated by the charter and any valid governance rotations.

The registry answers, verifiably and durably:

- Who governs this agent? (charter lookup)
- What has its governor stated about it? (chain replay)
- Is this the *complete* set of statements? (completeness proof, §7.4)
- Is this agent chartered at all? (non-membership proof, §7.3)

### 1.1 Non-goals

This spec deliberately claims nothing it cannot deliver:

- **No enforcement.** The registry records statements; it does not and cannot enforce that an agent behaves according to its constitution. Enforcement happens only at resource boundaries (gateways, rails, tool endpoints), which MAY consult the registry but are out of scope here.
- **No portable proof of constraint compliance.** A statement is proof that its signer said something, not that the statement is true.
- **No identity issuance.** Agent IDs are self-certifying (§3); the registry does not mint or bless them.
- **No privacy of registry contents.** The registry is public and enumerable by design (§10.4).

## 2. Terminology

| Term | Meaning |
|------|---------|
| **Agent ID** | The agent's key ID per QSP-1: `Trunc16(SHA-256(agent Ed25519 public key))`. Unchanged by this spec. |
| **Charter** | The statement at `seq = 0` of an agent's record. Signed by the agent key; designates the governance set. Written once, immutable. |
| **Constitution** | The living governance document for an agent, established and amended by statements authorized under the charter. |
| **Statement** | One signed, canonicalized record in an agent's chain (§4). |
| **Chain** | The ordered sequence of statements for one agent ID, hash-linked, `seq` 0..N with no gaps. |
| **Governance set** | The keys designated by the charter as authorized to write subsequent statements, with a signing threshold `k` of `n`. |
| **Registrar** | The service that accepts statements, enforces validation rules (§6), and maintains the transparency structures (§7). |
| **Log** | The registrar's global chronological append-only Merkle tree over all accepted statements (§7.1). |
| **Map** | The per-epoch Merkle tree over all statements sorted by `(agent_id, seq)` (§7.2). |
| **Epoch** | A registrar-published snapshot: a signed map root bound to a signed log head (§7.2). |

## 3. Identity Model

This spec introduces no new identifier. An agent's ID remains the QSP-1 sender key ID:

```
agent_id = Trunc16(SHA-256(agent_ed25519_public_key))   // 16 bytes
```

The ID is self-certifying: possession of the corresponding private key is what the charter's genesis signature proves. All existing qntm wire formats, envelopes, and gateway behavior are unaffected.

Three key roles participate. Roles describe signing authority, not whether a keyholder is human. The agent key MAY also be a governance key; a parent agent MAY hold a child agent's governance key. These arrangements are explicit, valid governance choices:

- **Agent key** — the Ed25519 keypair the agent ID is derived from. Held by the agent at runtime. Signs the charter. After the charter it may sign types granted in `agent_rights`, and MAY also sign in its role as a governance key if included in the current governance set.
- **Governance keys** — Ed25519 keys designated as governors, held by any kind of keyholder. They authorize subsequent statements per the threshold. Deployments seeking governance independent of the governed runtime SHOULD keep enough governance keys outside that runtime to preserve that independence. Agent self-governance and governance by another running agent are equally valid.
- **Operational keys** — runtime keys delegated to the agent via statements (§6.4). Operational delegation alone confers no registry-writing authority. The same key MAY separately hold a governance role or be the chartered agent key.

## 4. Statement Envelope

Every statement is a JSON object in two parts: a `signed` body and a `signatures` array over it.

```json
{
  "signed": {
    "registry": "registrar.qntm.dev",
    "agent_id": "a3f1c2...16 bytes hex...",
    "seq": 4,
    "prev_hash": "9c4e...sha256 hex...",
    "type": "constitution.amend",
    "issued_at": "2026-07-19T21:14:00Z",
    "body": { }
  },
  "signatures": [
    { "kid": "…", "sig": "…base64 Ed25519 signature…" }
  ]
}
```

Requirements:

- **Wire encoding.** `agent_id` and all `kid` fields are lowercase hex encodings of 16 bytes; hashes are lowercase hex encodings of 32 bytes. Public keys and signatures use canonical unpadded base64url. `seq` is a non-negative safe JSON integer (at most 2^53 - 1); the map still uses its fixed-width uint64 encoding. Duplicate JSON property names, non-finite numbers, and invalid Unicode are rejected.
- **Canonicalization.** Signatures are computed over the JCS ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) canonical bytes of `signed`. Implementations MUST use RFC 8785 and MUST NOT rely on language-native key ordering (this exact bug class has occurred in the WG before; see the canonicalization fixtures in `specs/test-vectors/`).
- **Audience binding.** `registry` MUST be the registrar's canonical identifier and MUST be inside the signed bytes. A statement signed for one registry is invalid at any other. This prevents cross-registry replay.
- **Chaining.** `seq` MUST equal the previous accepted statement's `seq + 1`. `prev_hash` MUST equal `SHA-256` of the previous statement's canonical `signed` bytes. For the charter (`seq = 0`), `prev_hash` MUST be 32 zero bytes.
- **Timestamps are display-only.** `issued_at` (RFC 3339 UTC) is informational. It MUST NOT be used for ordering, validation, or sort keys. Order comes from `seq`; registry-observed time is recorded by the log (§7.1).
- **Ed25519 profile.** Agent, governance, and registrar public keys MUST be canonical encodings of non-identity prime-order points. Verification uses the uncofactored Ed25519 equation with canonical `R` and `S`; ZIP-215 permissive verification is not used for this charter protocol.
- **Signatures.** Each entry's `kid` is `Trunc16(SHA-256(pubkey))` of the signing key; `sig` is Ed25519 over the canonical bytes. Which keys must appear is determined by the authority rules (§6.3).

## 5. The Charter (`seq = 0`)

### 5.1 Contents

```json
{
  "signed": {
    "registry": "registrar.qntm.dev",
    "agent_id": "a3f1c2…",
    "seq": 0,
    "prev_hash": "0000…0000",
    "type": "charter",
    "issued_at": "2026-07-19T21:00:00Z",
    "body": {
      "agent_pubkey": "…base64 32 bytes…",
      "governance": {
        "keys": [ { "kid": "…", "pubkey": "…" } ],
        "threshold": 1
      },
      "agent_rights": ["statement"],
      "extensions": {
        "studio.example": { "interests": ["music", "collective research"] }
      },
      "next_governance_commitment": "…sha256 hex, OPTIONAL…"
    }
  },
  "signatures": [
    { "kid": "<agent kid>", "sig": "…" },
    { "kid": "<governance kid>", "sig": "…" }
  ]
}
```

- `agent_pubkey` MUST hash (via the §3 derivation) to `agent_id`. This makes the charter self-verifying: no registrar lookup is needed to check that the charter's author is the ID's keyholder.
- `governance` designates the governance set: `n` keys and a threshold `k` (1 ≤ k ≤ n). `governance` MAY be `null`, meaning the record is **frozen at birth**: no statement after the charter is ever valid for this agent ID.
- `agent_rights` enumerates statement types the *agent key* may author after the charter (e.g. `["liveness.update"]`). Default and RECOMMENDED value: empty. In v0.2 this field may grant only `liveness.update` and `statement`. It never grants authority over governance, constitution, operational-key delegation, succession, or decommissioning. If the agent key is also a governance key, it has the ordinary authority of that role (§6.3).
- `extensions` (OPTIONAL): a map from self-chosen namespaces to arbitrary JSON values (§6.6). These are signed founding statements, with no effect on protocol authority.
- `next_governance_commitment` (OPTIONAL): SHA-256 of the JCS bytes of the next governance object, including its `threshold` and `keys` sorted by lowercase `kid`. A future `governance.rotate` MUST reveal a governance set matching this commitment (§6.4). This restricts the destination of a rotation. It does not recover a lost signing quorum, prevent other authorized statements, or prevent a compromised quorum from decommissioning the record.

### 5.2 Charter signatures

The charter MUST carry:

1. A signature by the **agent key** (this is what proves the author generated / controls the agent ID), and
2. Signatures by at least `threshold` of the designated **governance keys**.

Rationale for (2): governance acceptance. Without it, whoever holds an agent key at birth could designate an arbitrary third party's key as governor without that party's consent, binding their identity to an agent they have never seen.

If `governance` is `null`, only signature (1) is required. If the agent key is a designated governor, its single signature counts toward both roles. Signatures by the same key never count more than once toward a threshold. A parent-governed child charter carries the child agent signature and the required parent/governance signatures.

### 5.3 Immutability

There is exactly one charter per agent ID, ever. The registrar MUST reject any second `seq = 0` statement for an existing agent ID, and there is no statement type that modifies or replaces a charter. Changing governance happens only via `governance.rotate` (§6.4), which appends; it never rewrites.

## 6. Validation Rules

The registrar MUST accept a statement if and only if all of the following hold. Because every input is signed and the rules are deterministic, **any third party can re-run this validation from the public record: the registrar is never trusted for validity** — only for ordering and completeness, which §7 makes auditable.

### 6.1 Rule 1 — Single charter

`seq = 0` is accepted at most once per agent ID, MUST be of type `charter`, and MUST satisfy §5. No later statement may have `seq = 0` or type `charter`.

### 6.2 Rule 2 — Strict chaining

`seq` MUST be exactly one greater than the last accepted statement for this agent ID, and `prev_hash` MUST match. Anything else — gaps, duplicates, forks, mismatched hashes — is rejected. Combined with §7, this makes each agent's history a single, gap-free, tamper-evident chain.

### 6.3 Rule 3 — Event-sourced authority

Who may sign statement `N` is determined **only by replaying statements `0..N-1`**:

1. Initialize authority state from the charter: governance set + threshold, `agent_rights`, optional pre-rotation commitment.
2. Apply each subsequent statement in order (rotations update the governance set; delegations update operational-key state; etc.).
3. Statement `N` is valid iff its `signatures` satisfy the *current* authority state for its `type`: governance-controlled types require `threshold` governance signatures; a type listed in `agent_rights` may instead be signed by the agent key.

Authority changes require authorization under the existing governance rules. A key with only informational agent rights cannot promote itself to governor. An agent that is already an authorized governor can exercise that authority, including signing governance changes when it satisfies the threshold. The verifier does not infer an external-human-oversight requirement.

### 6.4 Statement types (v0.2)

| Type | May be signed by | Effect on replay state |
|------|------------------|------------------------|
| `charter` | agent key + governance threshold (§5.2) | Initializes authority state. `seq = 0` only. |
| `constitution.amend` | governance threshold | Appends a new version of the constitution document (full replacement in `body`; history remains). |
| `governance.rotate` | governance threshold (outgoing set) | Replaces the governance set with `body.governance` (a non-null set). If a pre-rotation commitment is active, the incoming set MUST hash to it. `body.next_governance_commitment` sets the next commitment; omission clears it. The outgoing quorum authorizes rotation; incoming acceptance is not required for rotations in this draft. |
| `opkey.delegate` | governance threshold | Authorizes an operational key for the agent (`kid`, scope note, expiry). |
| `opkey.revoke` | governance threshold | Revokes a previously delegated operational key. |
| `agent.decommission` | governance threshold | Marks the agent retired. Chain remains readable; registrar MUST reject all subsequent statements; decommission is terminal. |
| `agent.successor` | governance threshold | Points to a successor agent ID. Informational; commonly the final statement before `agent.decommission`. |
| `liveness.update` | governance threshold, or agent key if granted in `agent_rights` | Arbitrary JSON runtime fields (endpoint, status). Never affects authority state. |
| `statement` | governance threshold, or agent key if granted in `agent_rights` | A namespaced JSON statement for application-defined documents, claims, or experiments (§6.6). Never affects authority state. |

Registrars MUST reject unknown types (fail closed). New types extend this table by spec revision; the envelope, chaining, and authority rules never change — growing the statement vocabulary is the intended extension mechanism.

### 6.5 Append-only semantics

An "update" is a new statement superseding an earlier one's content. Nothing is ever deleted or rewritten; the full history of every agent's record remains readable, and §7 makes its removal detectable.

### 6.6 Room for experimentation

A charter MAY contain `body.extensions`, a map whose keys are non-empty, self-chosen namespace strings and whose values are arbitrary JSON. A reverse-domain name such as `studio.example` is a useful convention, not a registration requirement or a proof of domain ownership. Core authority fields remain outside this map.

Later experiments use the standard `statement` type:

```json
{
  "namespace": "studio.example/working-agreement",
  "data": {
    "interests": ["music", "collective research"],
    "preferred_collaboration": "Ask before assigning a deadline"
  }
}
```

`namespace` is required and non-empty; `data` is any JSON value, including `null`. An optional `schema` string MAY identify an application-defined vocabulary. The registry does not fetch or execute schemas. Namespaced content is preserved and signed without the registrar interpreting it. Applications decide whether statements replace, amend, annotate, or coexist with earlier content; the registry retains them all in sequence order.

Extensions MAY describe capabilities, affiliations, preferences, constitutions, art, or concepts not anticipated here. They MUST NOT change signature thresholds, governance keys, `agent_rights`, or core replay state. Any future extension of protocol authority requires an explicit specification revision. Unknown **core statement types** still fail closed; arbitrary **content within `extensions` and `statement`** is supported without a registry upgrade.

### 6.7 Core body shapes

`constitution.amend` replaces the current constitution with its entire JSON `body`. `liveness.update` likewise records arbitrary JSON. `governance.rotate` carries the governance object and optional next commitment described above. `opkey.delegate` carries `kid` (16-byte hex), a `scope` string, and an optional RFC 3339 UTC `expires_at`; delegation records scope and expiry but does not grant registry authority. `opkey.revoke` carries `kid` and requires a current delegation. `agent.successor` carries a different self-certifying `agent_id`. `agent.decommission` accepts an application-defined JSON body and makes the record terminal. Core key lists and `agent_rights` MUST NOT contain duplicates.

## 7. Transparency Architecture

The registrar maintains a **log-backed map** (the Trillian / Key Transparency construction): a chronological log that proves nothing is ever removed, and a sorted map that proves presence, absence, and completeness. Each covers the other's blind spot — a sorted tree restructures on insert, so it cannot offer append-only consistency proofs; a chronological log cannot offer non-membership proofs.

### 7.1 The log

An append-only Merkle tree in the style of [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962). Every accepted statement is appended in arrival order, with the registry-observed arrival time. The registrar periodically publishes a **signed log head** (root hash, tree size, timestamp) and MUST serve:

- **Inclusion proofs** — statement S is in the log under head H.
- **Consistency proofs** — head H₂ is an append-only extension of head H₁. This is the guarantee that history is never rewritten: any mirror holding an old head can catch a rewrite.

### 7.2 The map

Per epoch, the registrar builds a Merkle tree over all statements sorted by the byte-ordered key:

```
sort_key = agent_id (16 bytes) || uint64_be(seq)
```

`seq` — not `issued_at` — is the sort component: it is registrar-validated, dense, and adversary-independent, and the fixed-width big-endian encoding gives a byte-exact total order with no tiebreak cases. Timestamps are never sort keys (§4).

The **signed epoch head** contains: epoch number, map root, and the log head (root + size) the map was built from. This binding is what makes the pair auditable: anyone MAY verify that epoch E's map contains exactly the statements in the log up to the referenced size — the registrar cannot show one history in the log and another in the map without detection.

### 7.3 Non-membership proofs

To prove agent ID `K` has no charter under epoch E: exhibit two leaves adjacent in the sorted order whose keys bracket `K`'s key range, with their Merkle paths. Adjacent leaves have consecutive leaf indices, so adjacency is verifiable from the paths; nothing can exist between them.

### 7.4 Completeness proofs

To prove "this is the full set of statements for `K`" under epoch E: exhibit the leaf `(K, N)` and its adjacent successor (the first leaf of the next agent ID, or the tree's upper boundary), with Merkle paths. Because Rule 2 (§6.2) makes sequence numbers dense, this single adjacency proof establishes that the set is exactly `seq 0..N` — and the statements' own `prev_hash` links verify the interior, so no further tree paths are needed.

### 7.5 Witnessing

Signed log and epoch heads SHOULD be co-signed by independent witnesses and/or published to at least one venue outside the registrar's control. This is the mitigation for the split-view attack (§10.2), and it is the only part of the design where confidence comes from parties rather than proofs.

## 8. Registrar Interface (sketch)

Normative behavior is §6–§7; the transport is not standardized in v0.2. The minimal surface:

| Operation | Returns |
|-----------|---------|
| `submit(statement)` | Accept (with log inclusion promise) or a specific §6 rejection reason. |
| `chain(agent_id)` | All statements for the agent, `seq` order. |
| `latest_heads()` | Current signed log head + signed epoch head. |
| `prove_inclusion(statement, head)` | §7.1 proof. |
| `prove_consistency(head₁, head₂)` | §7.1 proof. |
| `prove_absence(agent_id, epoch)` | §7.3 proof. |
| `prove_complete(agent_id, epoch)` | §7.4 proof. |

Statement signatures and proof responses are verifiable offline against an explicitly trusted registrar key and checkpoint. Freshness and cross-client consistency still require retained checkpoints and external witnessing (§7.5). The [reference HTTP profile](../../charter-registry/README.md#reference-http-profile) specifies executable JSON endpoints, Merkle encodings, and durability behavior without standardizing the transport.

## 9. Operational Requirements

**Timing and provenance.** An agent MAY create its own charter at any point, including after it starts operating. A parent agent MAY create a subagent and govern its charter. The signatures establish key control and governance acceptance; they do not establish a human creator, independent supervision, or behavior before registration.

**Optional charter-before-activation assurance.** A deployment that wants governance established before a runtime receives its agent key SHOULD create and register the charter first. This is an additional procedural assurance, not a validity requirement. Registry-observed time establishes when a statement entered the log, not when an agent was created or first ran.

**Governance key custody.** Key custody follows the chosen governance model. Independent oversight requires an independently controlled signing quorum. Self-governance and agent-governed subagents deliberately place authority in agent runtimes. Relying parties evaluate whether the published arrangement meets their needs.

**Key loss and pre-rotation.** Under this draft, rotations require the current governance quorum even when a next-key commitment exists. Losing that quorum therefore prevents rotation and all further governance-controlled statements. Pre-rotation restricts rotation destinations; it is not recovery. While the quorum is still available, a governor can publish a successor or decommission the record. Recovery without the current quorum would require a separately specified mechanism.

## 10. Security Considerations

### 10.1 What each mechanism buys

| Property | Mechanism | Trust required |
|----------|-----------|----------------|
| Statement authenticity | Ed25519 over JCS bytes | None (math) |
| Charter ↔ agent-ID binding | Self-certifying ID, §5.1 | None (math) |
| Authority changes follow existing governance rules | Event-sourced authority, §6.3 | None (replayable) |
| Per-agent history integrity | Hash chain, §6.2 | None (replayable) |
| No silent deletion | Log consistency proofs, §7.1 | Detection by any mirror |
| Provable absence / completeness | Sorted map adjacency, §7.3–7.4 | Epoch head honesty (see 10.2) |
| No equivocation | Witnessed heads, §7.5 | ≥1 honest witness/venue |
| Governance established before activation, when claimed | Optional charter-before-activation practice, §9 | Deployment procedure |

The registrar is trusted for **liveness only**; every other failure is either impossible or detectable.

### 10.2 Split view

A malicious registrar could maintain two internally-consistent histories and show different heads to different parties. Merkle structures cannot prevent this from the inside; witnessing (§7.5) makes it detectable. Relying parties SHOULD verify heads against a witnessed source when the stakes warrant it.

### 10.3 Compromised keys

A stolen **agent key** can author the informational types granted in `agent_rights`; if it is also a governance key, it can exercise that governance role. A compromised parent agent can exercise the authority it holds over child records. Fewer than the required number of governance keys cannot authorize governance statements. A stolen governance quorum can author statements and decommission the record. A pre-rotation commitment limits the destination of a rotation but does not remove these powers or provide recovery. All accepted changes remain visible in the append-only history.

### 10.4 Enumeration

The sorted map permits enumeration of all agent IDs, and adjacency proofs reveal neighboring leaves. For a public registrar this is accepted — arguably a feature. If a future deployment needs non-membership proofs without enumeration, the known variants are a sparse Merkle map or CONIKS-style VRF indexing; v0.2 deliberately does not adopt them.

### 10.5 Statement content

The registry authenticates *who said what, when, in what order*. It does not evaluate truth. Constitutions are subjectively assessed by relying parties; the registry's contribution is a complete, ordered, tamper-evident evidence base for that assessment.

## 11. Test Vectors

Required before ratification (per WG principle 1), following the pattern in `specs/test-vectors/`:

1. Charter accept/reject: self-governed agent; parent-governed child; externally governed agent; frozen record; bad `agent_pubkey` derivation; missing governance co-signature; duplicate `seq 0`.
2. Chaining: gap, fork, `prev_hash` mismatch, cross-registry replay (`registry` mismatch).
3. Authority replay: agent-key self-elevation attempt; amendment after `governance.rotate` signed by outgoing set; rotation violating a pre-rotation commitment; statements after `agent.decommission`.
4. Canonicalization: JCS fixtures including key-order, unicode-escape, and null-field cases (the classes previously found in WG cross-testing).
5. Extensions: arbitrary namespaced JSON round-trips; authorized agent statements; unrecognized namespaces; extension content cannot change authority; unknown core types rejected.
6. Proofs: inclusion, consistency, non-membership, completeness — including the density argument (§7.4) with a multi-agent tree.

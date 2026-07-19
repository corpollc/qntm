# Charter Registry — v0.1 DRAFT

## Status

**v0.1 DRAFT (2026-07-19).** Not ratified. Seeking review.

**DRI:** qntm (@vessenes)

**Operator model:** The registrar described here is operated by qntm. The design goal is that this requires minimal trust: every guarantee except liveness is independently verifiable or externally auditable (§8, §10).

**Implementations:** none yet (spec-first draft; per WG principles, ratification requires running code).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 1. Purpose

The Charter Registry is a public, append-only record of durable statements about agents, written by the parties that govern them — not by the agents themselves.

The founding record for an agent is its **charter**: the first statement in the agent's record, signed by the agent's own key, which irrevocably designates *who may write everything after it*. The informal analogy is a birth certificate plus amendments: issued at creation, immutable history, and the subject cannot edit it.

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

Three key roles participate:

- **Agent key** — the Ed25519 keypair the agent ID is derived from. Held by the agent at runtime. Signs exactly one registry statement: the charter. After the charter, the agent key holds only whatever residual rights the charter explicitly grants it (§5.2), which MAY be none.
- **Governance keys** — Ed25519 keys held by the entity that caused the agent to be created (the "creator"). These SHOULD be kept cold and MUST NOT be deployed with the agent. They sign everything after the charter, per the threshold.
- **Operational keys** — runtime keys delegated to the agent via statements (§6.4). Out of band for registry writes; they never author statements.

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

- **Canonicalization.** Signatures are computed over the JCS ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) canonical bytes of `signed`. Implementations MUST use RFC 8785 and MUST NOT rely on language-native key ordering (this exact bug class has occurred in the WG before; see the canonicalization fixtures in `specs/test-vectors/`).
- **Audience binding.** `registry` MUST be the registrar's canonical identifier and MUST be inside the signed bytes. A statement signed for one registry is invalid at any other. This prevents cross-registry replay.
- **Chaining.** `seq` MUST equal the previous accepted statement's `seq + 1`. `prev_hash` MUST equal `SHA-256` of the previous statement's canonical `signed` bytes. For the charter (`seq = 0`), `prev_hash` MUST be 32 zero bytes.
- **Timestamps are display-only.** `issued_at` (RFC 3339 UTC) is informational. It MUST NOT be used for ordering, validation, or sort keys. Order comes from `seq`; registry-observed time is recorded by the log (§7.1).
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
      "agent_rights": [],
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
- `agent_rights` enumerates statement types the *agent key* may author after the charter (e.g. `["liveness.update"]`). Default and RECOMMENDED value: empty. The agent key can never hold rights over `charter.*`, `governance.*`, or `constitution.*` types regardless of this field (§6.3).
- `next_governance_commitment` (OPTIONAL, RECOMMENDED): SHA-256 of the *next* governance key set, kept cold — KERI-style pre-rotation. If present, a future `governance.rotate` MUST reveal a key set matching this commitment (§6.4). This bounds the damage of a governance-key compromise: a thief can author statements (visibly, in an append-only record) but cannot rotate governance to lock out the true holder.

### 5.2 Charter signatures

The charter MUST carry:

1. A signature by the **agent key** (this is what proves the author generated / controls the agent ID), and
2. Signatures by at least `threshold` of the designated **governance keys**.

Rationale for (2): governance acceptance. Without it, whoever holds an agent key at birth could designate an arbitrary third party's key as governor without that party's consent, binding their identity to an agent they have never seen.

If `governance` is `null`, only signature (1) is required.

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

This rule is what makes self-elevation impossible: a statement in which the agent grants itself rights would need governance signatures to validate. Produced with the agent key alone, it is not a "forgery to detect" — it is simply an invalid statement, whenever submitted.

### 6.4 Statement types (v0.1)

| Type | May be signed by | Effect on replay state |
|------|------------------|------------------------|
| `charter` | agent key + governance threshold (§5.2) | Initializes authority state. `seq = 0` only. |
| `constitution.amend` | governance threshold | Appends a new version of the constitution document (full replacement in `body`; history remains). |
| `governance.rotate` | governance threshold (outgoing set) | Replaces the governance set. If a pre-rotation commitment is active, the incoming set MUST hash to it, and the statement SHOULD include a new commitment. |
| `opkey.delegate` | governance threshold | Authorizes an operational key for the agent (`kid`, scope note, expiry). |
| `opkey.revoke` | governance threshold | Revokes a previously delegated operational key. |
| `agent.decommission` | governance threshold | Marks the agent retired. Chain remains readable; registrar MUST reject all subsequent statements except none — decommission is terminal. |
| `agent.successor` | governance threshold | Points to a successor agent ID. Informational; commonly the final statement before `agent.decommission`. |
| `liveness.update` | per `agent_rights` | Informational runtime fields (endpoint, status). Never affects authority state. |

Registrars MUST reject unknown types (fail closed). New types extend this table by spec revision; the envelope, chaining, and authority rules never change — growing the statement vocabulary is the intended extension mechanism.

### 6.5 Append-only semantics

An "update" is a new statement superseding an earlier one's content. Nothing is ever deleted or rewritten; the full history of every agent's record remains readable, and §7 makes its removal detectable.

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

Normative behavior is §6–§7; the transport is not standardized in v0.1. The minimal surface:

| Operation | Returns |
|-----------|---------|
| `submit(statement)` | Accept (with log inclusion promise) or a specific §6 rejection reason. |
| `chain(agent_id)` | All statements for the agent, `seq` order. |
| `latest_heads()` | Current signed log head + signed epoch head. |
| `prove_inclusion(statement, head)` | §7.1 proof. |
| `prove_consistency(head₁, head₂)` | §7.1 proof. |
| `prove_absence(agent_id, epoch)` | §7.3 proof. |
| `prove_complete(agent_id, epoch)` | §7.4 proof. |

All responses are verifiable offline; none require trusting the registrar.

## 9. Operational Requirements

**Charter before activation.** The one link in this design that is procedural rather than cryptographic: a charter is only as trustworthy as the practice of registering it **before the agent runs with its key**. Creators MUST generate the agent keypair, author and register the charter, and only then hand the key to the running agent. An agent whose key ran before its charter was registered could have chartered itself with a shill governor; nothing in the record distinguishes this case. Relying parties SHOULD treat the charter's position in the log (registry-observed time, §7.1) as the trustworthy "born at" mark for exactly this reason.

**Governance key custody.** Governance keys MUST NOT be deployed to agent runtimes. Pre-rotation commitments (§5.1) are RECOMMENDED for any governance key that charters more than one agent, since such a key's compromise is fleet-wide.

**Key loss.** A lost governance key with no pre-rotation path is unrecoverable by design; recovery mechanisms reintroduce a trusted party. The remedy is procedural: charter a successor agent and publish `agent.successor` / `agent.decommission` while the key is still held, or accept a frozen record.

## 10. Security Considerations

### 10.1 What each mechanism buys

| Property | Mechanism | Trust required |
|----------|-----------|----------------|
| Statement authenticity | Ed25519 over JCS bytes | None (math) |
| Charter ↔ agent-ID binding | Self-certifying ID, §5.1 | None (math) |
| No self-elevation by agents | Event-sourced authority, §6.3 | None (replayable) |
| Per-agent history integrity | Hash chain, §6.2 | None (replayable) |
| No silent deletion | Log consistency proofs, §7.1 | Detection by any mirror |
| Provable absence / completeness | Sorted map adjacency, §7.3–7.4 | Epoch head honesty (see 10.2) |
| No equivocation | Witnessed heads, §7.5 | ≥1 honest witness/venue |
| Genesis honesty | Charter-before-activation, §9 | Creator procedure |

The registrar is trusted for **liveness only**; every other failure is either impossible or detectable.

### 10.2 Split view

A malicious registrar could maintain two internally-consistent histories and show different heads to different parties. Merkle structures cannot prevent this from the inside; witnessing (§7.5) makes it detectable. Relying parties SHOULD verify heads against a witnessed source when the stakes warrant it.

### 10.3 Compromised keys

A stolen **agent key** post-charter can author at most the types in `agent_rights` (default: nothing) — datasheet integrity does not depend on the agent runtime's security, which is the point of the design. A stolen **governance key** (below threshold) is inert. A stolen governance *set* can author statements — visibly, in an append-only record — but with pre-rotation in force cannot permanently seize the record.

### 10.4 Enumeration

The sorted map permits enumeration of all agent IDs, and adjacency proofs reveal neighboring leaves. For a public registrar this is accepted — arguably a feature. If a future deployment needs non-membership proofs without enumeration, the known variants are a sparse Merkle map or CONIKS-style VRF indexing; v0.1 deliberately does not adopt them.

### 10.5 Statement content

The registry authenticates *who said what, when, in what order*. It does not evaluate truth. Constitutions are subjectively assessed by relying parties; the registry's contribution is a complete, ordered, tamper-evident evidence base for that assessment.

## 11. Test Vectors

Required before ratification (per WG principle 1), following the pattern in `specs/test-vectors/`:

1. Charter accept/reject: valid; bad `agent_pubkey` derivation; missing governance co-signature; duplicate `seq 0`.
2. Chaining: gap, fork, `prev_hash` mismatch, cross-registry replay (`registry` mismatch).
3. Authority replay: agent-key self-elevation attempt; amendment after `governance.rotate` signed by outgoing set; rotation violating a pre-rotation commitment; statements after `agent.decommission`.
4. Canonicalization: JCS fixtures including key-order, unicode-escape, and null-field cases (the classes previously found in WG cross-testing).
5. Proofs: inclusion, consistency, non-membership, completeness — including the density argument (§7.4) with a multi-agent tree.

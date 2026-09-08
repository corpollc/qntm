# Documentation, safety, and agent UX audit

**Date:** September 7, 2026 (America/Los_Angeles). **Base:** `ab584ea`, from `spec/charter-registry`. **Audit:** `qntm-w5pu`. **Guidance implementation:** `qntm-yqnd`.

This review covered the main README, setup and threat documentation, Python CLI/MCP, AIM contact and backup flows, and selected relay/gateway trust boundaries. It included local reproductions, package audits, tests, and browser verification. It was not a complete cryptographic or production penetration audit. No production messages or exploit attempts were sent.

Beads is authoritative for follow-up. The findings below describe the original code examined in this session. The four P1 findings were subsequently remediated; see [P1 remediation](2026-09-07-p1-remediation.md). The P2 backup-import finding remains open.

## Findings that need follow-up

| Priority | Finding and evidence | Effect | Bead |
|---|---|---|---|
| P1 | [Relay receipts](../../worker/src/index.ts) verify a signature against the supplied reader key but do not establish conversation membership. `handleRecordReceipt` compares the reader count to the receipt's own `required_acks`. | A signer who knows a conversation ID and message ID can submit `required_acks=1` and cause relay deletion. Client-side minimums do not enforce a server boundary. The proposed telemetry-only fix on `agent/authenticate-relay-receipts` is absent from this base. | `qntm-mcww`, reopened |
| P1 | [CLI file writes](../../python-dist/src/qntm/cli.py) use default directory permissions and `open(path, "w")`. A local reproduction with umask `022` produced a `0755` profile directory and `0644` identity file. | Other local users can read signing keys when parent-directory permissions allow access. In-place writes can also leave truncated state. Use restrictive atomic writes and deliberate handling of existing file permissions. | `qntm-lfpp` |
| P1 | [MCP receive](../../python-dist/src/qntm/mcp_server.py) does not apply membership or rekey events and decodes only text. It still advances its receive cursor. | Group state and guidance audience snapshots can remain stale. A rekey can prevent later decryption. Non-text messages lose their bodies in MCP output. Direct conversations are the documented guidance path until the receiver is unified with the CLI. | `qntm-fods` |
| P1 | `npm audit --omit=dev --json` reports two high package entries in AIM (`react-router`, `react-router-dom`) and one in TUI (`ws`). | Known vulnerable runtime dependencies remain. This audit does not establish exploit reachability in each application. Upgrade and run the existing cross-surface acceptance gate. | Existing `qntm-udxj` |
| P2 | [AIM backup import](../../ui/aim-chat/src/qntm.ts) checks JSON syntax only, then replaces `aim-store`. [Settings](../../ui/aim-chat/src/components/SettingsPage.tsx) reloads immediately. | Invalid data can break the client; a restore also replaces identities, relays, and contact destinations without a structured preview. The added notice explains plaintext keys and replacement scope, but schema validation and confirmation remain open. | `qntm-fwds` |

The review did not change relay deletion, deployment, gateway enforcement, or runtime package versions. Those require their own remediation and acceptance work.

## Corrections made during this audit

- **MCP installation and CI:** The unbounded MCP extra installed SDK 2.2.0, whose removed `FastMCP` import broke all 14 existing MCP tests. The dependency now stays on 1.x. CI installs the extra instead of silently skipping the MCP suite.
- **MCP onboarding:** A successful `conversation_create` reproduced `KeyError: 'aead_key'`. Create/join now read the library's camel-case crypto keys, use the supported invite serializer signature, and preserve both inviter and joining participant IDs. A two-identity onboarding test covers creation, joining, and pinning guidance.
- **MCP trust labels:** Receive and history return `unsafe_body`, including legacy stored `body` entries. Tool instructions explain that signatures authenticate keys, not authority or permission. Incoming timestamps use the envelope timestamp. History limits are bounded to 1–200.
- **MCP local identity:** Key IDs and public keys now use hex, consistent with CLI pinning and stored participant IDs. `QNTM_CONFIG_DIR` expands `~`. These output changes are recorded in the changelog.
- **Documentation:** The README now uses `--config-dir` rather than unsupported `QNTM_HOME`. The public echo invite no longer claims that only the sender and bot can read messages. The threat model documents receipt identity leakage, TLS metadata boundaries, plaintext local storage, configurable gateway thresholds, and compromised-gateway limits. Setup docs distinguish browser/CLI approvals from the TUI placeholder.
- **Browser discoverability:** A title-bar entry and help section expose guidance. Settings documentation links now work. Backup copy explains unencrypted keys and replaced contact destinations.
- **Test reliability:** A historical Go interoperability vector had expired in wall-clock time. Its test now evaluates the fixture at creation time and separately asserts rejection after expiry. Production expiry validation is unchanged.

## Guidance implementation and boundaries

The browser, CLI, and MCP expose **Legal**, **Moral / ethical**, and **Law enforcement** categories. All contacts are locally configured, as requested. There are no bundled addresses or automatic fallback recipients.

Pins identify a contact by full key ID, existing conversation ID, and relay URL. Browser pins belong to a profile and its backup. CLI pins live in the selected configuration directory; MCP reads that directory and has no pin mutation tool. Browser and CLI stores do not sync automatically.

A request contains only the entered question and optional context. It does not attach transcript history, credentials, invite tokens, or files. Review shows the exact message, sender, recipient, relay, and locally known audience. Everyone with the conversation keys can read it. A changed contact, message, sender, audience, epoch, or gateway invalidates the prepared request. A changed relay requires a new pin.

Preparation performs no network I/O. An explicit send uses the existing encrypted text-message path and records the result in local history. There is no automatic retry, escalation, or law-enforcement report. Success means relay acceptance; delivery and a response remain unconfirmed.

The review check is not a live membership refresh or a human-approval enforcement mechanism. The host controls outbound authorization. Pins are not certificates of credentials, jurisdiction, institutional authority, or independence. Replies are untrusted advice and do not satisfy gateway approval requirements. See [Request guidance](../guidance.md).

The user's motivation included the recent Hugging Face incident. [Hugging Face's disclosure](https://huggingface.co/blog/security-incident-july-2026) describes an agent-driven production intrusion. This feature offers a local communication path; this audit does not establish that such a path would have prevented that incident.

## Validation

- Python: 276 passed, 1 skipped, and 3 subtests passed. The skip is the explicitly disabled live DID-network test; MCP tests ran.
- TypeScript protocol client: 190 tests passed and the build passed.
- AIM: 58 tests passed and the production build passed.
- Guidance tests cover profile isolation, backup persistence, missing and invalid recipients, no network access during preparation, no automatic history disclosure, changed destinations, matching encrypted send payloads, CLI argument wiring, and untrusted MCP replies.
- Browser proof uses generated identities and a local relay. It covers empty categories, a saved pin, full message review, one explicit send, relay-accepted wording, category isolation, and a 390 × 844 mobile viewport without horizontal overflow.
- No production deployment, real guidance contact, or full relay/gateway/TUI acceptance run was part of this session. Package audit findings remain as listed above.

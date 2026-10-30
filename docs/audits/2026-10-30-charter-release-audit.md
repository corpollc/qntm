# QNTM charter release audit and remediation

The pre-release audit covered the maintained repository, including the optional
charter reminder, registry and chain verifiers, messaging libraries, gateway,
relay, Python CLI/MCP, browser, terminal, adapters and release workflows. The
baseline was commit `78712f5`. Claude Opus 5.5 and Grok 4.7 performed independent,
read-only reviews through their installed CLIs. Claude also completed a separate
coverage pass over clients, adapters and workflows. Both reviewers subsequently
reviewed the first remediation snapshot; their additional findings were triaged
into fixes and the tracked follow-ups below, with regression and runtime checks.
The final fixes were validated locally; the models did not review the final
release artifacts. The coordinator checked the
findings, implemented fixes and ran tests; the reviewers did not run tests.

This is a broad source audit with targeted inspection, not a claim that every
line or every deployment setting was examined. The reviewers recorded coverage
gaps, including parts of browser presentation, legacy adapters and operational
scripts. Deployment configuration, provider recovery history, publisher account
settings and arbitrary future upstream dependencies remain outside the local
verification boundary.

## Changes

| Boundary | Remediation |
| --- | --- |
| Gateway approval policy | Require positive safe integers for request/proposal thresholds, floors and rules before storage and again before applying legacy records. Missing, coercible and non-finite thresholds fail closed. |
| Gateway execution | Check durable execution intent before an external call; persist completion before relay publication. Known results are retained in an exact-envelope outbox and delivered on retry; unknown attempts remain blocked across restart. Maintenance resumes approved requests after relay recovery without requiring new chat traffic. Bound response bodies to 8 KiB and reject redirects carrying vault headers. |
| Gateway transitions | Transaction-bound message-ID journal and cursor prevent replayed votes; migration seeds protection from stored actions. Signed creation time and secret IDs prevent TTL extension. Membership state, applied markers, invalidations and exact ordered controls commit atomically. |
| Relay announcements | Derive new channel IDs from master public keys. Quarantine unbound legacy claims without mutation/delete authority. Serialize ownership and publication in the conversation Durable Object. Refuse registration over an existing conversation; deletion preserves a closed ownership tombstone and monotonic sequence. Remove retained data and batch KV cleanup. |
| Claude channel | Bind cached verified history to the exact serialized envelope hash; persist delivered IDs across restart. Include charter metadata and untrusted-content markers in channel notifications. |
| Group authority | Share authenticated group-control checks between the TypeScript session and AIM: pinned creator/admin authority, protected creator, exact rekey roster and source epoch. Persist authority state in host checkpoints. Gateway membership delegation requires a creator-signed invitation; active gateways exclude parallel standalone controls. Reject stale acceptance before adopting a verified roster. Ordinary chat cannot widen an authenticated roster. |
| Outbound group state | Block application messages while membership requires a rekey or access was removed. Python's guard covers CLI, MCP, guidance and gate/governance sends. Restore the `group retry` dispatcher. |
| Browser receive state | Refresh the live receive roster after accepted group controls and gateway admission, so later valid rekeys are checked against the authenticated membership and subsequent traffic remains decryptable. |
| Python announcements | Match relay domain-separated signature prehashes, register channels, send posting signatures and delete remotely before removing ownership keys. Repair create/subscribe record construction. |
| Entity verification | Require both DID-to-sender matching and a trusted explicit entity-binding verifier. Encode entity IDs, reject redirects, bound identity documents, and verify returned document IDs. |
| Defensive correctness | Refuse CLI identity overwrite; validate invitation byte types and conversation-ID lengths; bound echo replies so a large message cannot stop cursor progress. Use authenticated group public keys when inviting a gateway without requiring every founding member to send chat first. |
| Release credentials | Scope Cloudflare/vault secrets to the steps that use them. Give reusable CI read-only permissions; build artifacts in unprivileged jobs and publish those artifacts in dedicated privileged jobs. Pin the npm CLI and keep beta releases off stable channels. |
| Dependencies | Refresh audited npm lockfiles, use patched Worker tooling and scoped OpenClaw transitive overrides, update Python certifi/PyJWT and the Go toolchain. |

Chartering remains optional. The receiver derives `charter_info` from the verified
sender key ID and the fixed charter origin. This introduces no send-time HTTP
request or model call. Untrusted reserved fields are ignored and flagged; signed
message bodies are preserved. The reminder does not assert that a charter exists,
that its chain was fetched, or that an action complies with it.

## Verification

Validation includes fresh installs and complete npm dependency audits for nine
maintained packages; the locked Python runtime/MCP audit; Go race tests, vet and
vulnerability scanning; full Python suites on 3.10 and 3.12; TypeScript tests and
build; real Go/TypeScript/Python charter exchange; gateway and channel regressions;
browser and terminal tests/builds; OpenClaw checkpoint and native-host tests;
real Worker announcement and echo journeys; package build and installed-wheel
checks; workflow parsing and release-metadata checks.

The real announcement journey executes Python create, register, post, subscribe,
receive and delete against the Worker. Group tests establish a signed genesis
before testing authorized controls, and verify that unauthorized controls do not
mutate state. Gateway tests cover both unknown execution outcomes and failures
while publishing completed outcomes. Channel tests distinguish exact replay from
different ciphertext claiming the same message ID.

The optional live-network DID test is excluded from the Python suites. Local
test artifacts and reviewer transcripts are retained separately from this report;
raw model reasoning is not a release artifact. Public release tagging and
production validation remain separate.

| Local gate | Result |
| --- | --- |
| Python | Clean release suite on 3.12: 680 passed, 1 optional live-network skip, 3 subtests. Earlier 3.10 minimum-WebSockets audit: 702 passed including local pilot tests; final roster regression suite also checked on 3.10. |
| TypeScript library | 425 passed; build passed |
| Gateway Worker | 138 passed; typecheck passed |
| Browser | 118 unit tests, 21 Chromium journeys; build passed |
| Terminal | 27 passed; build passed |
| OpenClaw | 84 passed, typecheck/manifest and real native-host smoke passed |
| Cross-client acceptance | 24 long-running browser, CLI, terminal and native OpenClaw journeys; 4 README and 2 relay/Vite runtime journeys passed |
| 0.6.x message smoke | 16 bidirectional Python direct/group exchanges with v0.6.0–v0.6.3 archived sources, using invitations from either version; excludes mixed-version governance and old runtime/dependency environments |
| Claude channel | 5 passed; typecheck passed |
| Dependencies | Nine maintained npm graphs and locked Python runtime/MCP: zero reported advisories; Go 1.27.3 scan clean |
| Package/release | SemVer/PEP 440 metadata, seven release-tool tests, sdist/wheel validation, installed-wheel runtime, npm tarball and workflow checks passed |

The bot runner, model-driven scenario lab, recorded pilot outputs and their
23 tests are local experiments excluded from the release repository tree and
artifacts. Python source archives explicitly include package source and project
metadata; wheels and npm tarballs retain their package-only manifests. The
release branch starts from `main` without the pilot commits in its ancestry.

## Remaining boundaries

Issue tracking remains in beads, under audit `qntm-tdib`. Material follow-ups are
`qntm-uqug` (governed credential replacement/revocation), `qntm-7vpy` (legacy Python
approval review), `qntm-n1cd` (offline membership freshness and competing rekeys),
`qntm-htnu` (DID resolver egress policy), `qntm-4xah` (bounded journals/admission),
`qntm-1ml2` (secondary adapter/API parity), `qntm-esqm` (monotonic announcement
rotation), and `qntm-3twp` (operator reconciliation of unknown outcomes). Gateway queue
capacity and legacy recovery behavior are included in those follow-ups; saturation
fails closed and must not acknowledge a failed storage commit.

Any admitted participant can currently replace a gateway service credential;
request quorum does not govern that replacement. The unsupported revocation
claim has been removed from the documentation. Known gateway results retry
through a durable outbox. An outage extending past a signed notification's expiry
still needs operator recovery; the upstream
action will not be automatically executed again. General `did:web` resolution
still needs caller-controlled egress when handling untrusted identifiers.

The public charter registry is experimental and unwitnessed. Signed ancestry
provenance is distinct from semantic policy assessment; founding authorization
does not by itself prove perpetual parent control. These limitations are not
changed by the locally generated charter reminder. Source metadata is prepared
as `0.9.0-beta.1` (`0.9.0b1` for Python). No release tag, package publication or
production deployment is part of this audit work.

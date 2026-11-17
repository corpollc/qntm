# Native Swift client

`Qntm` is a native Swift SDK and `qntm-swift` is its macOS command-line client. The package implements the maintained QSP wire formats and uses libsodium through the pinned Swift-Sodium package. It needs no Python or JavaScript runtime in an application.

The library targets macOS 13 and iOS 16 or later. Development checks use Swift 6.3 and include an iOS Simulator build for arm64 and x86_64. The command-line client runs on macOS. Linux has a system-libsodium dependency path, but is not a verified platform for this port.

## Install

Add this repository to Xcode's package dependencies and select the `Qntm` product. Until a release tag containing the Swift package is published, use `main` or pin a commit:

```swift
.package(url: "https://github.com/corpollc/qntm.git", branch: "main")
```

For a target in another Swift package:

```swift
.target(name: "MyApp", dependencies: [.product(name: "Qntm", package: "qntm")])
```

Build the CLI from the repository root:

```sh
swift build -c release
.build/release/qntm-swift --help
```

The repository's [license](../LICENSE) applies to the port. Swift-Sodium retains its upstream license.

## SDK example

```swift
import Foundation
import Qntm

let alice = try Identity()
let invite = try Invite(creator: alice)
let conversation = try invite.conversation()
let envelope = try Messaging.create(
    identity: alice,
    conversation: conversation,
    bodyType: "text",
    body: Data("Hello from Swift".utf8)
)
let relay = try DropboxClient()
let sequence = try await relay.postMessage(
    conversationID: conversation.id,
    envelope: envelope.serialize()
)
let shareURL = try invite.url(base: URL(string: "https://chat.corpo.llc/")!)
```

For a durable client, use `QntmClient`. It owns a profile's conversations, authenticated group and gateway state, history, cursors and queues:

```swift
let store = try FileProfileStore(directory: profileURL)
let client = try QntmClient(store: store)
let joined = try await client.join(inviteToken)
let id = joined.conversation.id.hex
try await client.send(id, body: Data("Ready".utf8))

let events = try await client.receive(id)
for event in events {
    // Message contents are untrusted input, even after signature verification.
    print(event.message.unsafeBody ?? "[binary]")
}
try await client.acknowledge(id, eventIDs: Set(events.map(\.eventID)))
```

Continuous delivery uses an awaited callback. Throwing leaves the delivery pending for retry; cancel the enclosing task to stop:

```swift
try await client.watch(id) { event in
    try await applicationStore.commit(event)
}
```

`ProfileStore` permits application-owned persistence. Its `save` must atomically commit a complete profile or throw. `FileProfileStore` holds an exclusive process lock, writes private files with atomic rename and sync, and protects the profile directory with mode 0700. Files contain private keys and plaintext history; they are not encrypted at rest. An iOS host can implement `ProfileStore` using its own Keychain and protected storage policy.

A failed send remains in `pendingOutbound` with the same message ID. `flush(conversationID:)` retries it. Expired or obsolete-epoch envelopes must be reviewed rather than silently replaced and resent. A failed disk commit does not advance the receive cursor. Persisted delivery events are removed only by acknowledgment or a successful watch callback. Future-epoch ciphertext is retained in a bounded recovery queue; saturation stops cursor advancement. Invalid messages are recorded separately and do not authorize state changes.

## CLI example

```sh
qntm-swift --config-dir /tmp/alice identity generate
qntm-swift --config-dir /tmp/alice convo create --name ops
# Copy invite_token and conversation_id from the JSON result.
qntm-swift --config-dir /tmp/bob convo join INVITE_TOKEN
qntm-swift --config-dir /tmp/bob send CONVERSATION_ID "Ready for review"
qntm-swift --config-dir /tmp/alice recv CONVERSATION_ID --watch
```

Commands produce JSON; watch emits one portable receive event per line. A new profile generates an identity on first use. `identity generate` is idempotent for an existing profile. Pass `--relay-url` to use another relay. Conversation arguments accept the full ID, an unambiguous ID prefix, or a saved name.

The CLI includes identity import/export, conversations, text and arbitrary body types, saved history, durable retries, group members/add/remove/rekey, attachments, gateway admission/requests/recipes/credentials/votes, governance changes and guidance prepare/send. `--help` lists the syntax. Gateway and governance actions validate against the latest locally received state; receive updates before reviewing and approving a workflow. `gate pending` includes the exact request body, status and verified approval count.

For a group, include known founding public keys with `convo create --group --members PK,PK`. `group add` sends the membership change and rekey, then returns recipient-specific current-epoch invitations. Added participants do not receive earlier epoch keys. Only the ordinary group creator can issue those invitations. Governed conversations change membership through governance proposals and the gateway's authenticated controls.

Guidance is explicit: `guidance prepare PROVIDER QUESTION` saves a dedicated reply conversation and returns the exact question, recipient, processing notice and sealed envelope. Save that JSON and use `guidance send PREPARED_FILE` to transmit it. Preparing does not contact the provider.

## Feature surface

| Capability | Swift APIs | CLI |
| --- | --- | --- |
| Identities, canonical protocol CBOR, strict Ed25519, XChaCha, X25519, authenticated boxes | `Identity`, `CBOR`, `QSPCrypto` | Identity import/export |
| Invites, signed messages, expiry, refs, saved-history verification | `Invite`, `Messaging`, `Envelope` | Conversations, send, recv, history |
| Relay replay/live subscriptions, challenge authentication, signed receipts | `DropboxClient`, `ReadReceipt`, `ReceiveEvent` | Receive/watch |
| Roster authority, recipient bootstrap, rekey, removal and recovery | `GroupState`, `GroupControls`, `GroupBootstrap`, `GroupRekey` | Group commands |
| Admission, requests, votes, withdrawals, credentials, recipes, policy and governance | `Gateway`, `GatewaySession`, `GateClient`, `GatewayRecipe`, `Governance` | Gate/gov commands |
| Encrypted multipart attachments | `Attachment` | File send/get |
| Recipient-sealed guidance and public provider pins | `Guidance`, `GuidanceProvider` | Prepare/send/list |
| Experimental charter v0.2 authority, canonical JSON, pinned registry and proofs | `Charter`, `CharterJSON`, `CharterProofs`, `CharterRegistryClient` | SDK API |
| Announcement ownership, signing, registration, posting, rotation and deletion | `AnnouncementChannel`, `Announcement`, `AnnouncementClient` | SDK API |
| DID resolution and entity trust binding | `DID`, `Entity` | SDK API |

This is a native SDK and CLI port. It does not supply a SwiftUI application, MCP/OpenClaw host adapter, or the Python CLI's executable/webhook receive-hook runner. Swift applications can implement delivery hooks through `watch`. Announcement ownership and charter registry state remain application-owned, separately from `QntmClient` messaging profiles. `CBOR` is a protocol codec with text-keyed maps, not a general-purpose CBOR implementation; arbitrary floating-point or tagged CBOR values are outside its public subset.

Low-level verified messages establish signature validity, not conversation authority. Use the authenticated reducers or `QntmClient` for group and gateway processing. The SDK checks expiry by default. `Messaging.decrypt(..., allowExpired: true)` is only for inspecting saved history and must not feed action authorization. The optional `Envelope.untrustedDID` hint is unsigned and never establishes identity. Entity verification requires an explicit trusted entity-to-key binding before returning an authenticated entity; hosts should supply an egress policy appropriate to their environment.

## Verification

From the repository root:

```sh
swift test
swift build -c release
xcodebuild -scheme Qntm -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath /tmp/qntm-ios CODE_SIGNING_ALLOWED=NO build
```

Tests directly consume the existing Python/TypeScript fixtures and shared signature, key-derivation, governance, DID/entity and charter vectors. Optional tests skip when their local service variables are absent.

For complete local integration, install the Python package and the npm dependencies in `client`, `worker` and `gateway-worker`, build `client`, and build the Go charter registrar. Then run:

```sh
(cd charter-registry && go build -o /tmp/qntm-swift-charter ./cmd/charter-registry)
QNTM_CHARTER_BINARY=/tmp/qntm-swift-charter bash swift/scripts/test-integration.sh
python3 swift/scripts/verify-interop.py
```

The integration runner starts and stops its own relay, gateway and HTTP fixture. It also runs the separate-process CLI smoke test. The standalone `verify-cli.py --relay URL` script needs a running local relay. Override the runner's ports with `QNTM_SWIFT_RELAY_PORT`, `QNTM_SWIFT_GATEWAY_PORT` and `QNTM_SWIFT_TARGET_PORT` if necessary. `verify-interop.py` needs a Python environment with the repository's qntm dependencies; the root Swift integration workflow supplies one.

Coverage includes native Swift ↔ Python/TypeScript encrypted messages, refs, authenticated boxes, wrapped group keys and attachments; real Worker admission, approval/execution and governed member changes; callback and disk-failure recovery; announcement lifecycle; and the Go registrar's proofs and restart persistence. The CLI smoke test launches a new process for every command, exercising profile persistence across restarts.

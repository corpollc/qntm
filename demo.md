# qntm — End-to-End Encrypted Agent Messaging

*2026-02-14T15:23:00Z*

Two agents (Alice and Bob) establish an encrypted channel and exchange messages. Neither the drop box nor any intermediary can read the plaintext. Signatures prove sender identity inside the encryption layer.

Build the CLI: `go build -o /tmp/qntm ./cmd/qntm/`

---

## Section 1: Setup 🟢

Each agent has its own identity, stored in an isolated directory. A shared drop box directory simulates the untrusted relay.

```bash
$ rm -rf /tmp/alice /tmp/bob /tmp/charlie /tmp/qntm-dropbox
$ mkdir -p /tmp/alice /tmp/bob /tmp/charlie /tmp/qntm-dropbox
```

## Section 2: Identity Generation 🟢

Ed25519 keypair — the private key never leaves the keystore.

```bash
$ /tmp/qntm --config-dir /tmp/alice identity generate
```

```output
Generated new identity:
Key ID: WehREWP1AFXx6_z2A_aIvQ
Public Key: _-k6A-8Do41ZhDhHCNiNKVIt0FQ_AuaCVdSWKsMJomY
Saved to: /tmp/alice/identity.json
```

```bash
$ /tmp/qntm --config-dir /tmp/bob identity generate
```

```output
Generated new identity:
Key ID: p0GRyZxSuCpu7ZfRF0OoDQ
Public Key: mgflzaRjltokStQRY4lzfmZt4e7IhnZIdBAYRC6Pfoc
Saved to: /tmp/bob/identity.json
```

## Section 3: Identity Show 🟢

```bash
$ /tmp/qntm --config-dir /tmp/alice identity show
```

```output
Current identity:
Key ID: WehREWP1AFXx6_z2A_aIvQ
Public Key: _-k6A-8Do41ZhDhHCNiNKVIt0FQ_AuaCVdSWKsMJomY
```

## Section 4: Create Invite 🟢

The invite contains a shared secret delivered out-of-band. Both sides derive matching encryption keys via HKDF.

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox invite create --name "Alice-Bob Encrypted Chat"
```

```output
Created direct invite:
Name: Alice-Bob Encrypted Chat
Conversation ID: 9f30225e23d446a2e29ed29dce59142e
Invite Token: p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1At...
```

## Section 5: Accept Invite 🟢

Bob parses the invite URL, derives matching encryption keys, and joins the conversation.

```bash
$ /tmp/qntm --config-dir /tmp/bob --storage /tmp/qntm-dropbox invite accept "<invite-url>"
```

```output
Accepted direct invite:
Conversation ID: 9f30225e23d446a2e29ed29dce59142e
Participants: 2
```

Alice also accepts to store the conversation locally:

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox invite accept "<invite-url>"
```

```output
Accepted direct invite:
Conversation ID: 9f30225e23d446a2e29ed29dce59142e
Participants: 1
```

## Section 6: Send Message 🟢

The message is encrypted with XChaCha20-Poly1305, signed with the sender's Ed25519 key, and written to the shared drop box.

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox message send 9f30225e23d446a2e29ed29dce59142e "Hello Bob! This is Alice."
```

```output
Message sent to conversation 9f30225e23d446a2e29ed29dce59142e
Message ID: 80b757b96930698d1fa58314715604da
```

## Section 7: Receive Message 🟢

Bob reads from the drop box, decrypts the ciphertext, and verifies Alice's signature.

```bash
$ /tmp/qntm --config-dir /tmp/bob --storage /tmp/qntm-dropbox message receive 9f30225e23d446a2e29ed29dce59142e
```

```output
Conversation 9f30225e23d446a2e29ed29dce59142e (1 new messages):
  [59e8511163f50055] text: Hello Bob! This is Alice.

Received 1 total messages
```

## Section 8: Reply and Bidirectional Flow 🟢

Bob replies, Alice receives — proving bidirectional encrypted communication.

```bash
$ /tmp/qntm --config-dir /tmp/bob --storage /tmp/qntm-dropbox message send 9f30225e23d446a2e29ed29dce59142e "Hi Alice! Encryption working perfectly!"
```

```output
Message sent to conversation 9f30225e23d446a2e29ed29dce59142e
Message ID: 0c7c06d0ac3651a94906cc9ee437a65a
```

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox message receive 9f30225e23d446a2e29ed29dce59142e
```

```output
Conversation 9f30225e23d446a2e29ed29dce59142e (1 new messages):
  [a74191c99c52b82a] text: Hi Alice! Encryption working perfectly!

Received 1 total messages
```

## Section 9: Invite List 🟢

List all accepted conversations.

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox invite list
```

```output
Conversations (2):
  9f30225e23d446a2e29ed29dce59142e (direct) - 1 participants
  1c9b3844ab4e21cb0ddcd33700b41e4e (group) - 1 participants
```

## Section 10: Message List (Storage Stats) 🟢

Show storage stats for a conversation.

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox message list 9f30225e23d446a2e29ed29dce59142e
```

```output
Conversation 9f30225e23d446a2e29ed29dce59142e storage stats:
  Messages: 0
  Expired: 0
  Total size: 0 bytes
```

> Note: Messages show 0 because Bob already received (consumed) them from the drop box.

## Section 11: Message Receive All 🟢

Receive from all conversations at once (no conversation ID).

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox message receive
```

```output
No new messages
```

## Section 12: Group Create 🟢

Create a group conversation. `KeyID` now implements `encoding.TextMarshaler` (base64url, no padding), so `map[types.KeyID]*group.GroupMemberInfo` serializes correctly.

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage "local:/tmp/alice/store" group create "Engineers" "Engineering team"
```

```output
Created group 'Engineers':
Conversation ID: 15860f5d5e9576eaf9d162b420f134e7
Members: 1
```

## Section 13: Group List 🟢

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage "local:/tmp/alice/store" group list
```

```output
Group conversations (1):
  15860f5d5e9576eaf9d162b420f134e7: Engineers (1 members)
```

## Section 14: Group Add 🟢

Add a member by their public key. Group state persists correctly with the KeyID TextMarshaler fix.

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage "local:/tmp/alice/store" group add 15860f5d5e9576eaf9d162b420f134e7 KTdIm2CO5Kshex37AWbkKc9n5jGCQX2IRfTf7cmOltc
```

```output
Added member to group 15860f5d5e9576eaf9d162b420f134e7
```

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage "local:/tmp/alice/store" group list
```

```output
Group conversations (1):
  15860f5d5e9576eaf9d162b420f134e7: Engineers (2 members)
```

Alice can send messages to the group:

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage "local:/tmp/alice/store" message send 15860f5d5e9576eaf9d162b420f134e7 "Welcome to the Engineers group!"
```

```output
Message sent to conversation 15860f5d5e9576eaf9d162b420f134e7
Message ID: 7d86f670f5aa3ca7b2c61f999f428fd1
```

> Note: `group remove` is not yet implemented (qntm-3cl) and has been removed from the CLI (qntm-xrc). `group join` requires an invite URL flow.

## Section 15: Error Handling 🟢

### Invalid invite (CBOR parsing rejects garbage)

```bash
$ /tmp/qntm --config-dir /tmp/bob invite accept "https://example.com/qntm#invalid-base64" 2>&1 || true
```

```output
Error: failed to parse invite: failed to unmarshal invite: cbor: UTF-8 text string length 15750820170734182123 is too large, causing integer overflow
```

### Invalid conversation ID

```bash
$ /tmp/qntm --config-dir /tmp/alice message send "invalid-conv-id" "test" 2>&1 || true
```

```output
Error: invalid conversation ID format
```

### Missing identity

```bash
$ /tmp/qntm --config-dir /tmp/nonexistent identity show 2>&1 || true
```

```output
Error: failed to load identity: identity not found (run 'qntm identity generate' first): open /tmp/nonexistent/identity.json: no such file or directory
```

## Section 16: Unsafe Development Commands 🟢

Unsafe commands require the `--unsafe` flag.

### Without flag (rejected)

```bash
$ /tmp/qntm unsafe test 2>&1 || true
```

```output
Error: unsafe commands require --unsafe flag
```

### With flag (self-test passes)

```bash
$ /tmp/qntm --unsafe unsafe test
```

```output
Running unsafe development tests...
✓ Identity generation test passed
  Test Key ID: MtRGMR6Zv8GAdBwlK9MkMg
✓ Invite creation test passed
  Test Conversation ID: 1d23b611c066223657d8aaac8231b569
✓ Message creation test passed
  Test Message ID: 699184095c9cdc641b3a1e3d746055ed
All unsafe development tests passed!
```

## Section 17: Identity Import/Export 🔴

> **Not implemented (qntm-ty5).** Commands removed from CLI until implemented. Previously returned stub errors; now hidden from help output to avoid confusion (qntm-xrc).

## Section 18: Full Test Suite 🟢

```bash
$ go test ./... 2>&1 | grep -E "(ok|FAIL)"
```

```output
ok  	github.com/corpo/qntm          0.012s
ok  	github.com/corpo/qntm/crypto   0.004s
ok  	github.com/corpo/qntm/dropbox  0.930s
ok  	github.com/corpo/qntm/group    0.662s
ok  	github.com/corpo/qntm/identity 0.005s
ok  	github.com/corpo/qntm/invite   0.003s
ok  	github.com/corpo/qntm/message  0.003s
ok  	github.com/corpo/qntm/security 0.002s
```

> All 8 packages pass. Group serialization works end-to-end after the KeyID TextMarshaler fix (qntm-b0e).

## Section 19: HTTP Drop Box Client 🟡

> **Not demoed live (qntm-yng).** The `--dropbox-url` flag and `dropbox/http.go` HTTP client exist and are unit-tested, but require a running drop box server. The Cloudflare Worker at `worker/` has `PLACEHOLDER_KV_ID` and is not yet deployed (qntm-tmq).

## Section 20: Cleanup

```bash
$ rm -rf /tmp/alice /tmp/bob /tmp/charlie /tmp/qntm-dropbox
```

---

# qntm-gate — Stateless Multisig API Gateway

*2026-02-14T19:27:00Z*

Three signers (Alice, Bob, Carol) govern API access through threshold authorization. The gate server is **stateless** — it stores no pending requests or collected signatures. Authorization state lives in the qntm group conversation. On each execution trigger, the gate scans the conversation, verifies Ed25519 signatures, and executes if the threshold is met.

Build: `go build -o /tmp/qntm ./cmd/qntm/ && go build -o /tmp/echo-server ./cmd/echo-server/`

Start servers:
```bash
$ /tmp/echo-server -port 19090 &
$ /tmp/qntm gate serve --port 18080 &
```

---

## Section 21: Gate — Identity Setup 🟢

Each signer has their own Ed25519 identity (reusing the same qntm identity system).

```bash
$ rm -rf /tmp/gate-alice /tmp/gate-bob /tmp/gate-carol
$ mkdir -p /tmp/gate-alice /tmp/gate-bob /tmp/gate-carol
$ /tmp/qntm --config-dir /tmp/gate-alice identity generate
```

```output
Generated new identity:
Key ID: vDRFeIKZGW41eObhBkRe8Q
Public Key: B887u8YkzbvOuonJg7OIxHEBAe5MlXMPpGWulSJkwz0
Saved to: /tmp/gate-alice/identity.json
```

```bash
$ /tmp/qntm --config-dir /tmp/gate-bob identity generate
```

```output
Generated new identity:
Key ID: rUNk5mv9dGfHCE8r7LnBUA
Public Key: Fz-Jo_ew7suwykUXbEJHzGADY7034VgAiJwH3hpB2HI
Saved to: /tmp/gate-bob/identity.json
```

```bash
$ /tmp/qntm --config-dir /tmp/gate-carol identity generate
```

```output
Generated new identity:
Key ID: bLC-bB5DeABGTAslH3INsg
Public Key: s13__xqfcGShyouW2tyTaRVjtXsB-07iWQ0uQGoS1_g
Saved to: /tmp/gate-carol/identity.json
```

## Section 22: Gate — Org Creation 🟢

Create an organization with 3 signers. Threshold rules: GET requires 1-of-3 (read-only = low risk), POST requires 2-of-3 (writes = consensus needed).

```bash
$ curl -s -X POST http://localhost:18080/v1/orgs -H 'Content-Type: application/json' -d '{
  "id": "demo-org",
  "signers": [
    {"kid": "vDRFeIKZGW41eObhBkRe8Q", "public_key": "B887u8YkzbvOuonJg7OIxHEBAe5MlXMPpGWulSJkwz0=", "label": "alice"},
    {"kid": "rUNk5mv9dGfHCE8r7LnBUA", "public_key": "Fz+Jo/ew7suwykUXbEJHzGADY7034VgAiJwH3hpB2HI=", "label": "bob"},
    {"kid": "bLC-bB5DeABGTAslH3INsg", "public_key": "s13//xqfcGShyouW2tyTaRVjtXsB+07iWQ0uQGoS1/g=", "label": "carol"}
  ],
  "rules": [
    {"service": "echo", "endpoint": "*", "verb": "GET", "m": 1, "n": 3},
    {"service": "echo", "endpoint": "*", "verb": "POST", "m": 2, "n": 3}
  ]
}'
```

```output
{"id":"demo-org","signers":[{"kid":"vDRFeIKZGW41eObhBkRe8Q","public_key":"B887u8YkzbvOuonJg7OIxHEBAe5MlXMPpGWulSJkwz0=","label":"alice"},{"kid":"rUNk5mv9dGfHCE8r7LnBUA","public_key":"Fz+Jo/ew7suwykUXbEJHzGADY7034VgAiJwH3hpB2HI=","label":"bob"},{"kid":"bLC-bB5DeABGTAslH3INsg","public_key":"s13//xqfcGShyouW2tyTaRVjtXsB+07iWQ0uQGoS1/g=","label":"carol"}],"rules":[{"service":"echo","endpoint":"*","verb":"GET","m":1,"n":3},{"service":"echo","endpoint":"*","verb":"POST","m":2,"n":3}],"credentials":{}}
```

## Section 23: Gate — Add Credential 🟢

Store the target service's API key. The credential never appears in logs or responses — it's only injected at execution time.

```bash
$ curl -s -X POST http://localhost:18080/v1/orgs/demo-org/credentials -H 'Content-Type: application/json' -d '{
  "id": "echo-api-key", "service": "echo", "value": "sk_live_demo_key_2026",
  "header_name": "Authorization", "header_value": "Bearer {value}",
  "description": "Echo server test API key"
}'
```

```output
{"id":"echo-api-key","status":"credential added"}
```

## Section 24: Gate — 1-of-3 Authorization (GET balance) 🟢

Alice alone can check a balance — GET requires only 1 signer. The request is posted as a `gate.request` message to the org's conversation. The gate scans, verifies the signature, and auto-executes since the threshold (1-of-3) is met immediately.

```bash
$ echo '{"request_id":"demo-get-1","verb":"GET","target_endpoint":"/balance","target_service":"echo","target_url":"http://localhost:19090/balance","payload":null}' | \
  /tmp/qntm --config-dir /tmp/gate-alice gate request submit demo-org --gate-url http://localhost:18080
```

```output
{
  "org_id": "demo-org",
  "request_id": "demo-get-1",
  "verb": "GET",
  "target_endpoint": "/balance",
  "target_service": "echo",
  "status": "executed",
  "signature_count": 1,
  "signer_kids": ["vDRFeIKZGW41eObhBkRe8Q"],
  "threshold": 1,
  "execution_result": {
    "status_code": 200,
    "content_type": "application/json",
    "content_length": 95
  }
}
```

> **Key point:** Alice's request message was posted to the conversation → gate scanned → threshold met (1/1) → gate injected the API credential → echo received the auth header. The response body is **redacted** from `execution_result` to prevent credential reflection. No server-side state was stored — the conversation message IS the record.

## Section 25: Gate — 2-of-3 Authorization (POST transfer) 🟢

Alice submits a wire transfer as a `gate.request` message. The gate scans and returns pending — POST requires 2-of-3.

```bash
$ echo '{"request_id":"demo-post-1","verb":"POST","target_endpoint":"/transfer","target_service":"echo","target_url":"http://localhost:19090/transfer","payload":{"amount":5000,"recipient":"acme-corp"}}' | \
  /tmp/qntm --config-dir /tmp/gate-alice gate request submit demo-org --gate-url http://localhost:18080
```

```output
{
  "org_id": "demo-org",
  "request_id": "demo-post-1",
  "status": "pending",
  "signature_count": 1,
  "signer_kids": ["vDRFeIKZGW41eObhBkRe8Q"],
  "threshold": 2
}
```

Bob reviews and posts a `gate.approval` message:

```bash
$ echo '{"verb":"POST","target_endpoint":"/transfer","target_service":"echo","payload":{"amount":5000,"recipient":"acme-corp"}}' | \
  /tmp/qntm --config-dir /tmp/gate-bob gate request approve demo-org demo-post-1 --gate-url http://localhost:18080
```

```output
{
  "org_id": "demo-org",
  "request_id": "demo-post-1",
  "status": "executed",
  "signature_count": 2,
  "signer_kids": ["vDRFeIKZGW41eObhBkRe8Q", "rUNk5mv9dGfHCE8r7LnBUA"],
  "threshold": 2,
  "execution_result": {
    "status_code": 200,
    "content_type": "application/json",
    "content_length": 142
  }
}
```

> **Key point:** Alice's request message (1/2) → gate scans conversation → pending. Bob's approval message (2/2) → gate re-scans → threshold met → credential injected → POST forwarded. The gate stored nothing — both messages live in the conversation. The response body is redacted to prevent credential reflection.

Alternatively, execution can be triggered explicitly:

```bash
$ /tmp/qntm gate execute demo-org demo-post-1 --gate-url http://localhost:18080
```

> This calls `POST /v1/orgs/demo-org/execute/demo-post-1`, which scans the conversation and executes if the threshold is met. Useful for polling or agent-triggered execution.

## Section 26: Gate — Expiration (5s TTL) 🟢

Submit a request with a 5-second TTL. Wait for it to expire. Approval after expiry is rejected — the gate scans the conversation and checks `expires_at` from the original request message.

```bash
$ EXPIRES=$(date -u -v+5S +"%Y-%m-%dT%H:%M:%SZ")
$ echo '{"request_id":"demo-expire-1","verb":"POST","target_endpoint":"/dangerous","target_service":"echo","target_url":"http://localhost:19090/dangerous","payload":{"action":"delete-all"},"expires_at":"'$EXPIRES'"}' | \
  /tmp/qntm --config-dir /tmp/gate-alice gate request submit demo-org --gate-url http://localhost:18080
```

```output
{
  "request_id": "demo-expire-1",
  "status": "pending",
  "expires_at": "2026-02-14T15:45:02Z",
  "threshold": 2
}
```

```bash
$ sleep 6
$ echo '{"verb":"POST","target_endpoint":"/dangerous","target_service":"echo","payload":{"action":"delete-all"}}' | \
  /tmp/qntm --config-dir /tmp/gate-bob gate request approve demo-org demo-expire-1 --gate-url http://localhost:18080 2>&1 || true
```

```output
{"error":"request \"demo-expire-1\" has expired"}
```

```bash
$ /tmp/qntm gate request status demo-org demo-expire-1 --gate-url http://localhost:18080
```

```output
{"status":"expired","found":true,"expired":true}
```

> **Key point:** The request message in the conversation has `expires_at`. The gate checks this on every scan — no timers, no cleanup. Bob's approval was cryptographically valid but the gate rejected it because the request message's expiration had passed.

## Section 27: Gate — Bad Signature Rejection 🟢

A request signed with the wrong key is rejected immediately.

```bash
$ curl -s -X POST http://localhost:18080/v1/orgs/demo-org/requests -H 'Content-Type: application/json' -d '{
  "request_id": "bad-sig-1", "verb": "GET", "target_endpoint": "/test",
  "target_service": "echo", "target_url": "http://localhost:19090/test",
  "payload": null, "requester_kid": "vDRFeIKZGW41eObhBkRe8Q",
  "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}'
```

```output
{"error":"signature verification failed: invalid request signature"}
```

## Section 28: Gate — Unknown Org / Duplicate Request 🟢

```bash
$ curl -s http://localhost:18080/v1/orgs/nonexistent
```

```output
{"error":"org \"nonexistent\" not found"}
```

Duplicate request IDs are rejected (replay protection per spec §11):

```output
{"error":"request \"demo-get-1\" already exists (replay protection)"}
```

## Section 29: Gate — Full Test Suite 🟢

```bash
$ go test ./gate/ -v 2>&1 | grep -E "(PASS|FAIL|✅)"
```

```output
--- PASS: TestSignVerifyRequest (0.00s)
--- PASS: TestSignVerifyApproval (0.00s)
--- PASS: TestLookupThreshold (0.00s)
--- PASS: TestOrgStore (0.00s)
    gate_test.go:145: ✅ ScanConversation threshold met
--- PASS: TestScanConversation_ThresholdMet (0.00s)
    gate_test.go:182: ✅ ScanConversation threshold not met (1/2)
--- PASS: TestScanConversation_ThresholdNotMet (0.00s)
    gate_test.go:219: ✅ ScanConversation expired request
--- PASS: TestScanConversation_Expired (0.00s)
    gate_test.go:257: ✅ ScanConversation bad signature rejected
--- PASS: TestScanConversation_BadSignature (0.00s)
    gate_test.go:300: ✅ ScanConversation duplicate signer counted once
--- PASS: TestScanConversation_DuplicateSigner (0.00s)
    gate_test.go:316: ✅ ScanConversation request not found
--- PASS: TestScanConversation_NotFound (0.00s)
    gate_test.go:390: ✅ 2-of-3 echo integration passed (stateless)
--- PASS: TestIntegration_2of3_Echo (0.01s)
    gate_test.go:437: ✅ 1-of-2 auto-execute passed (stateless)
--- PASS: TestIntegration_1of2_AutoExecute (0.00s)
    gate_test.go:504: ✅ Expiration test passed (2s TTL, stateless)
--- PASS: TestIntegration_Expiration (3.01s)
    gate_test.go:543: ✅ Bad signature rejected (stateless)
--- PASS: TestIntegration_BadSignature (0.00s)
    gate_test.go:554: ✅ Unknown org returns 404
--- PASS: TestIntegration_UnknownOrg (0.00s)
    gate_test.go:594: ✅ Duplicate request rejected (replay protection, stateless)
--- PASS: TestIntegration_DuplicateRequest (0.00s)
    gate_test.go:659: ✅ Explicit execute endpoint passed (stateless)
--- PASS: TestIntegration_ExplicitExecute (0.00s)
ok  	github.com/corpo/qntm/gate	3.438s
```

```bash
$ go test ./... 2>&1 | grep -E "(ok|FAIL)"
```

```output
ok  	github.com/corpo/qntm          0.342s
ok  	github.com/corpo/qntm/crypto   0.454s
ok  	github.com/corpo/qntm/dropbox  0.714s
ok  	github.com/corpo/qntm/gate     3.846s
ok  	github.com/corpo/qntm/group    1.381s
ok  	github.com/corpo/qntm/handle   1.525s
ok  	github.com/corpo/qntm/identity 1.041s
ok  	github.com/corpo/qntm/invite   1.705s
ok  	github.com/corpo/qntm/message  1.771s
ok  	github.com/corpo/qntm/naming   1.824s
ok  	github.com/corpo/qntm/registry 1.833s
ok  	github.com/corpo/qntm/security 1.654s
ok  	github.com/corpo/qntm/shortref 1.526s
```

> All 13 packages pass. Gate tests include 6 ScanConversation unit tests (threshold met/not met, expired, bad sig, duplicate signer, not found) + 7 HTTP integration tests (2-of-3, 1-of-2 auto-execute, expiration, bad sig, unknown org, replay protection, explicit execute endpoint). The gate server is fully stateless — no pending requests map, no mutex for request state, no cleanup timers.

## Section 30: Gate — Cleanup

```bash
$ pkill -f echo-server; pkill -f "qntm gate serve"
$ rm -rf /tmp/gate-alice /tmp/gate-bob /tmp/gate-carol
```

---

## Section 31: Group Rekey — Member Addition with Epoch Tracking 🟢

When a member is added, a rekey is issued advancing the epoch. New members can only decrypt from their join epoch onward.

```bash
$ rm -rf /tmp/alice /tmp/bob /tmp/charlie /tmp/qntm-dropbox
$ mkdir -p /tmp/alice /tmp/bob /tmp/charlie /tmp/qntm-dropbox
$ /tmp/qntm --config-dir /tmp/alice identity generate
```

```output
Generated new identity:
Key ID: tk3JLdXmDSXfmL7dwSDKVA
Public Key: ydiiX-M0Qd2iAEOKzmaHiUUG7EMdGLKxqpVGWTWK130
Saved to: /tmp/alice/identity.json
```

```bash
$ /tmp/qntm --config-dir /tmp/bob identity generate
$ /tmp/qntm --config-dir /tmp/charlie identity generate
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox group create "rekey-demo" "Testing group rekey"
```

```output
Created group 'rekey-demo':
Conversation ID: fc029f20ffc8ec6cd6839bacad58329c
Members: 1
```

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox group add fc029f20ffc8ec6cd6839bacad58329c ntnDISBZOo-FgMzYK2yWClEOOmNCW9Rt2u9KfoakM8Q
```

```output
Added member to group fc029f20ffc8ec6cd6839bacad58329c
Group rekeyed to epoch 1
```

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox group add fc029f20ffc8ec6cd6839bacad58329c HE3Qv2d8UVez95ICkCjqcBt9jMFh201bv03cLIw62MY
```

```output
Added member to group fc029f20ffc8ec6cd6839bacad58329c
Group rekeyed to epoch 2
```

> Each member addition advances the epoch. The new group key is wrapped per-recipient using Ed25519→X25519 + ephemeral DH + XChaCha20-Poly1305 (~80 bytes per recipient).

## Section 32: Group Rekey — Member Removal (Cryptographic Exclusion) 🟢

When a member is removed, a rekey excludes their `kid` from `wrapped_keys`. They can read the rekey message (encrypted under the old epoch) but cannot derive the new key.

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox message send fc029f20ffc8ec6cd6839bacad58329c "Hello everyone at epoch 2!"
```

```output
Message sent to conversation fc029f20ffc8ec6cd6839bacad58329c
Message ID: 3a8dbf75461e417de10aa0bdf4dbe1bb
```

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox group remove fc029f20ffc8ec6cd6839bacad58329c -- fCswEC4yB0_PmIelrWItiw
```

```output
Removed member fCswEC4yB0_PmIelrWItiw from group fc029f20ffc8ec6cd6839bacad58329c
Group rekeyed to epoch 3
```

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox message send fc029f20ffc8ec6cd6839bacad58329c "Secret: Charlie can't see this"
```

```output
Message sent to conversation fc029f20ffc8ec6cd6839bacad58329c
Message ID: 20c8bd524fc0a2c5f913b785f90ded33
```

> Charlie is cryptographically excluded. The rekey message is encrypted under epoch 2 (readable by all). But the new group key for epoch 3 is only wrapped for Alice and Bob. Charlie cannot derive `k_group_new` and therefore cannot decrypt any epoch 3+ messages.

## Section 33: Epoch Tracking in Messages 🟢

Every outer envelope carries `conv_epoch`, binding the message to the epoch key used for encryption. The AAD includes `conv_epoch` to prevent epoch-confusion attacks.

```bash
$ /tmp/qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox group rekey fc029f20ffc8ec6cd6839bacad58329c
```

```output
Group fc029f20ffc8ec6cd6839bacad58329c rekeyed to epoch 4
```

> Manual rekey rotates the group key without changing membership — useful for periodic key rotation or after suspected compromise.

## Section 34: Group Rekey — Unit Tests 🟢

```bash
$ cd ~/src/corpo/qntm && go test ./crypto/... -v -run "Epoch|Wrap|X25519" 2>&1 | head -20
```

```output
=== RUN   TestDeriveEpochKeys_Epoch0_BackwardCompat
--- PASS: TestDeriveEpochKeys_Epoch0_BackwardCompat (0.00s)
=== RUN   TestDeriveEpochKeys_DifferentEpochs
--- PASS: TestDeriveEpochKeys_DifferentEpochs (0.00s)
=== RUN   TestDeriveEpochKeys_Deterministic
--- PASS: TestDeriveEpochKeys_Deterministic (0.00s)
=== RUN   TestWrapUnwrapKey
--- PASS: TestWrapUnwrapKey (0.00s)
=== RUN   TestWrapKey_DifferentRecipients
--- PASS: TestWrapKey_DifferentRecipients (0.00s)
=== RUN   TestWrapKey_WrongKID
--- PASS: TestWrapKey_WrongKID (0.00s)
=== RUN   TestX25519Conversion
--- PASS: TestX25519Conversion (0.00s)
PASS
```

```bash
$ go test ./group/... -v -run "Rekey|Apply" 2>&1 | head -20
```

```output
=== RUN   TestRekey_FullFlow
--- PASS: TestRekey_FullFlow (0.00s)
=== RUN   TestRekey_ConflictResolution
--- PASS: TestRekey_ConflictResolution (0.00s)
=== RUN   TestApplyRekey_GracePeriod
--- PASS: TestApplyRekey_GracePeriod (0.00s)
=== RUN   TestRekey_RekeyBodySerialization
--- PASS: TestRekey_RekeyBodySerialization (0.00s)
PASS
```

> The full rekey flow test creates a 3-member group, issues a rekey excluding one member, verifies the excluded member cannot unwrap the new key, and confirms the remaining members can encrypt/decrypt under the new epoch.

---

## Section 35: Handle Registry 🟢

Start the registry server, register handles, and look up commitments.

```bash
$ rm -rf /tmp/alice-h /tmp/bob-h /tmp/qntm-dropbox-h /tmp/registry-data
$ mkdir -p /tmp/alice-h /tmp/bob-h /tmp/qntm-dropbox-h /tmp/registry-data
$ /tmp/qntm --config-dir /tmp/registry-data registry serve --addr :8420 &
```

```output
Registry server listening on :8420
```

```bash
$ /tmp/qntm --config-dir /tmp/alice-h identity generate
$ /tmp/qntm --config-dir /tmp/alice-h registry register alice --registry-url http://localhost:8420
```

```output
Generated new identity:
Key ID: Og0kfUm1eyjnatobxCb5xw
Public Key: TfnkgUi31u_Se9nDcJ4Ue8_V9VoxQHUYC8DJB8t14jY
Saved to: /tmp/alice-h/identity.json
Handle registered: alice
Salt (stored locally): d101dd9e42937bd8...
```

```bash
$ /tmp/qntm --config-dir /tmp/bob-h identity generate
$ /tmp/qntm --config-dir /tmp/bob-h registry register bob --registry-url http://localhost:8420
```

```output
Generated new identity:
Key ID: o_hy0WLWKoynOxlawZAccA
Public Key: 0luJVAYk7QxT3YeS5_WIs1cWWmkicdR-vzd1Nxtl7uA
Saved to: /tmp/bob-h/identity.json
Handle registered: bob
Salt (stored locally): 10ea1b7a1aa9b9e0...
```

```bash
$ /tmp/qntm --config-dir /tmp/alice-h handle show
$ /tmp/qntm --config-dir /tmp/bob-h handle show
```

```output
Handle: alice
Handle: bob
```

> Registry enforces uniqueness, generates 32-byte salts for brute-force resistance, computes `H(CBOR({handle, ik_pk, salt}))` commitments, and discards the salt after returning it to the client. All mutations require Ed25519 signatures.

## Section 36: Local Naming 🟢

Assign local nicknames to identities and conversations. Names are never transmitted.

```bash
$ /tmp/qntm --config-dir /tmp/alice-h name set 3a0d247d49b57b28e76ada1bc426f9c7 "My Identity"
$ /tmp/qntm --config-dir /tmp/alice-h name list
```

```output
Named 3a0d247d... → My Identity
Identities:
  3a0d247d... → My Identity
```

```bash
$ /tmp/qntm --config-dir /tmp/alice-h name remove "My Identity"
$ /tmp/qntm --config-dir /tmp/alice-h name list
```

```output
Removed identity name: My Identity
No names set
```

> Display priority: local name > revealed handle > short ref > full kid. Names stored in `names.json`, never shared.

## Section 37: Handle Reveal 🟢

Reveal your handle to conversation participants. Sends a signed reveal message containing handle + salt so recipients can verify against the registry commitment.

```bash
$ /tmp/qntm --config-dir /tmp/alice-h --storage /tmp/qntm-dropbox handle reveal 6a3ba7badd1620f6321b0ade9b6a480c
```

```output
Handle revealed in conversation 6a3ba7ba...
```

## Section 38: Name Conversations 🟢

Assign local nicknames to conversations (never transmitted).

```bash
$ /tmp/qntm --config-dir /tmp/alice-h --storage /tmp/qntm-dropbox name conv 6a3ba7badd1620f6321b0ade9b6a480c "Handle Test Group"
```

```output
Named conversation 6a3ba7ba... → Handle Test Group
```

```bash
$ /tmp/qntm --config-dir /tmp/alice-h --storage /tmp/qntm-dropbox name list
```

```output
Conversations:
  6a3ba7ba... → Handle Test Group
```

## Section 39: Short References 🟢

Use shortest unique hex prefix (minimum 3 chars) to refer to any known ID.

```bash
$ /tmp/qntm --config-dir /tmp/alice-h ref 3a0
```

```output
3a0d247d49b57b28e76ada1bc426f9c7
```

> Trie-based resolution over all known kids and conversation IDs. Ambiguous prefixes prompt for more characters.

## Section 40: Integrated Naming — QoL Display & Input 🟢

Names, handles, and short refs are now used everywhere — not just in `name` commands. Commands accept names/short refs as input and display them in output.

### Before (raw hex everywhere):
```
Conversation 6a3ba7badd1620f6321b0ade9b6a480c (1 new messages):
  [3a0d247d49b57b28] text: Hello!
Message sent to conversation 6a3ba7badd1620f6321b0ade9b6a480c
```

### After (names + short refs):
```bash
$ /tmp/qntm --config-dir /tmp/alice-h name conv 6a3ba7badd1620f6321b0ade9b6a480c "Handle Test Group"
$ /tmp/qntm --config-dir /tmp/alice-h name set 3a0d247d49b57b28e76ada1bc426f9c7 "Bob"
```

```bash
# Send using conversation name instead of hex ID
$ /tmp/qntm --config-dir /tmp/alice-h --storage /tmp/qntm-dropbox-h message send "Handle Test Group" "Hello from Alice!"
```

```output
Message sent to Handle Test Group (6a3)
Message ID: abc123...
```

```bash
# Receive shows sender names and conversation names
$ /tmp/qntm --config-dir /tmp/bob-h --storage /tmp/qntm-dropbox-h message receive
```

```output
Handle Test Group (6a3) (1 new messages):
  [Bob (3a0)] text: Hello from Alice!

Received 1 total messages
```

```bash
# Group list shows member names (with --verbose)
$ /tmp/qntm --config-dir /tmp/alice-h --storage /tmp/qntm-dropbox-h group list --verbose
```

```output
Group conversations (1):
  Handle Test Group (6a3): Engineers (2 members)
    - Alice (59e)
    - Bob (3a0)
```

```bash
# Invite list shows conversation names
$ /tmp/qntm --config-dir /tmp/alice-h invite list
```

```output
Conversations (2):
  Handle Test Group (6a3) (group) - 2 participants
  Alice-Bob DM (9f3) (direct) - 2 participants
```

```bash
# Identity show displays local name
$ /tmp/qntm --config-dir /tmp/alice-h identity show
```

```output
Current identity:
Key ID: My Identity (3a0)
Public Key: TfnkgUi31u_Se9nDcJ4Ue8_V9VoxQHUYC8DJB8t14jY
```

> **Display priority:** local name > revealed handle (@handle) > shortest unique prefix > full hex ID. All commands that accept conversation IDs or KIDs now also accept local names and short hex prefixes (minimum 3 chars).

## Section 41: Unit Tests (Handles/Naming/Shortref/Display) 🟢

```bash
$ cd ~/src/corpo/qntm && go test ./shortref/... ./registry/... ./handle/... ./naming/... -v 2>&1 | tail -30
```

```output
--- PASS: TestTrieBasic (0.00s)
--- PASS: TestTrieMinPrefix (0.00s)
--- PASS: TestTrieAmbiguity (0.00s)
--- PASS: TestResolveExact (0.00s)
--- PASS: TestResolveAmbiguous (0.00s)
--- PASS: TestRemove (0.00s)
--- PASS: TestCaseInsensitive (0.00s)
PASS
ok  	github.com/corpo/qntm/shortref
--- PASS: TestRegisterAndLookup (0.00s)
--- PASS: TestUniqueness (0.00s)
--- PASS: TestBadSignature (0.00s)
--- PASS: TestChange (0.00s)
--- PASS: TestDelete (0.00s)
--- PASS: TestCommitmentScheme (0.00s)
--- PASS: TestNotFound (0.00s)
PASS
ok  	github.com/corpo/qntm/registry
--- PASS: TestVerifyReveal (0.00s)
--- PASS: TestStoreReveal (0.00s)
--- PASS: TestStoreMyHandle (0.00s)
--- PASS: TestStoreCommitment (0.00s)
PASS
ok  	github.com/corpo/qntm/handle
--- PASS: TestSetAndGet (0.00s)
--- PASS: TestNameCollision (0.00s)
--- PASS: TestRemove (0.00s)
--- PASS: TestRemoveNotFound (0.00s)
--- PASS: TestConversationNames (0.00s)
--- PASS: TestListIdentities (0.00s)
--- PASS: TestResolveByName (0.00s)
--- PASS: TestNewStoreCreatesDir (0.00s)
PASS
ok  	github.com/corpo/qntm/naming
```

> All 19 tests pass across 4 new packages: shortref, registry, handle, naming.

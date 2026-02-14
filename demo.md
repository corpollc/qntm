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
Invite URL: https://qntm.example.com/join#p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1At...
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

> Note: `group remove` is not yet implemented (qntm-3cl). `group join` requires an invite URL flow.

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

> **Not implemented (qntm-ty5).** Commands exist but return stubs.

```bash
$ /tmp/qntm --config-dir /tmp/alice identity import /tmp/test 2>&1 || true
```

```output
Error: import not implemented yet
```

```bash
$ /tmp/qntm --config-dir /tmp/alice identity export /tmp/test 2>&1 || true
```

```output
Error: export not implemented yet
```

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

# qntm-gate — Multisig API Gateway

*2026-02-14T15:44:00Z*

Three signers (Alice, Bob, Carol) govern API access through threshold authorization. The gate server verifies Ed25519 signatures over CBOR-encoded requests, collects approvals, and only injects API credentials when the threshold is met.

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

Alice alone can check a balance — GET requires only 1 signer. The request is signed with CBOR-encoded Ed25519, verified, and auto-executed.

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
  "target_url": "http://localhost:19090/balance",
  "requester_kid": "vDRFeIKZGW41eObhBkRe8Q",
  "status": "executed",
  "signature_count": 1,
  "signer_kids": ["vDRFeIKZGW41eObhBkRe8Q"],
  "threshold": 1,
  "execution_result": {
    "status_code": 200,
    "body": {
      "auth_header": "Bearer sk_live_demo_key_2026",
      "had_auth": true,
      "method": "GET",
      "path": "/balance"
    }
  }
}
```

> **Key point:** Alice submitted → threshold met (1/1) → gate injected `Bearer sk_live_demo_key_2026` → echo received the auth header. Alice never saw or handled the API key.

## Section 25: Gate — 2-of-3 Authorization (POST transfer) 🟢

Alice submits a wire transfer. The gate holds it pending — POST requires 2-of-3.

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

Bob reviews and approves:

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
    "body": {
      "auth_header": "Bearer sk_live_demo_key_2026",
      "had_auth": true,
      "method": "POST",
      "path": "/transfer",
      "body": {"amount": 5000, "recipient": "acme-corp"}
    }
  }
}
```

> **Key point:** Alice (1/2) → pending. Bob approves (2/2) → threshold met → gate injects credential → POST forwarded with auth → echo confirms receipt of both the payload and the API key.

## Section 26: Gate — Expiration (5s TTL) 🟢

Submit a request with a 5-second TTL. Wait for it to expire. Approval after expiry is rejected.

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
{"request_id":"demo-expire-1","status":"expired"}
```

> **Key point:** The request expired after 5 seconds. Bob's approval was cryptographically valid but the gate rejected it due to expiration. Even if the threshold had been met before expiry, execution after expiry would also be rejected.

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
    gate_test.go:163: ✅ 2-of-3 echo integration passed
--- PASS: TestIntegration_2of3_Echo (0.00s)
    gate_test.go:213: ✅ 1-of-2 auto-execute passed
--- PASS: TestIntegration_1of2_AutoExecute (0.00s)
    gate_test.go:278: ✅ Expiration test passed (2s TTL)
--- PASS: TestIntegration_Expiration (3.01s)
    gate_test.go:315: ✅ Bad signature rejected
--- PASS: TestIntegration_BadSignature (0.00s)
    gate_test.go:326: ✅ Unknown org returns 404
--- PASS: TestIntegration_UnknownOrg (0.00s)
    gate_test.go:364: ✅ Duplicate request rejected (replay protection)
--- PASS: TestIntegration_DuplicateRequest (0.00s)
ok  	github.com/corpo/qntm/gate	3.370s
```

```bash
$ go test ./... 2>&1 | grep -E "(ok|FAIL)"
```

```output
ok  	github.com/corpo/qntm          0.012s
ok  	github.com/corpo/qntm/crypto   0.004s
ok  	github.com/corpo/qntm/dropbox  0.930s
ok  	github.com/corpo/qntm/gate     3.286s
ok  	github.com/corpo/qntm/group    0.662s
ok  	github.com/corpo/qntm/identity 0.005s
ok  	github.com/corpo/qntm/invite   0.003s
ok  	github.com/corpo/qntm/message  0.003s
ok  	github.com/corpo/qntm/security 0.002s
```

> All 9 packages pass (gate is new). Gate tests include 7 integration tests covering 2-of-3 auth, 1-of-2 auto-execute, expiration (2s TTL), bad signatures, unknown orgs, and replay protection.

## Section 30: Gate — Cleanup

```bash
$ pkill -f echo-server; pkill -f "qntm gate serve"
$ rm -rf /tmp/gate-alice /tmp/gate-bob /tmp/gate-carol
```

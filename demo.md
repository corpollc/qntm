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

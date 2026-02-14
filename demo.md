# qntm — End-to-End Encrypted Agent Messaging

*2026-02-13T04:30:00Z*

Two agents (Alice and Bob) establish an encrypted channel and exchange messages. Neither the drop box nor any intermediary can read the plaintext. Signatures prove sender identity inside the encryption layer.

Build the CLI: `cd ~/src/corpo/qntm && go build ./cmd/qntm`

## 1. Create separate keystores

Each agent has its own identity, stored in an isolated directory.

```bash
rm -rf /tmp/alice /tmp/bob /tmp/charlie
mkdir -p /tmp/alice /tmp/bob /tmp/charlie
```

## 2. Alice generates her identity

Ed25519 keypair — the private key never leaves her keystore.

```bash
./qntm --config-dir /tmp/alice identity generate
```

```output
Generated new identity:
Key ID: RkBZmoxoKGp5noUnzkituw
Public Key: f1uRQma2TyljmDMmDZJCFIjFTyVYdNTuq4BPdMOl4nY
Saved to: /tmp/alice/identity.json
```

## 3. Bob generates his identity

```bash
./qntm --config-dir /tmp/bob identity generate
```

```output
Generated new identity:
Key ID: EY5qe8tYhzT-ztJ59MHVFA
Public Key: lwPaJ4lQ8KKaZDo2V7RqN5hi7wpO8pNC5HKkChcsg4o
Saved to: /tmp/bob/identity.json
```

## 4. Verify separate identities

```bash
./qntm --config-dir /tmp/alice identity show
```

```output
Current identity:
Key ID: RkBZmoxoKGp5noUnzkituw
Public Key: f1uRQma2TyljmDMmDZJCFIjFTyVYdNTuq4BPdMOl4nY
```

```bash
./qntm --config-dir /tmp/bob identity show
```

```output
Current identity:
Key ID: EY5qe8tYhzT-ztJ59MHVFA
Public Key: lwPaJ4lQ8KKaZDo2V7RqN5hi7wpO8pNC5HKkChcsg4o
```

## 5. Alice creates an invite

The invite contains a shared secret delivered out-of-band (iMessage, Signal, etc). Both sides derive matching encryption keys via HKDF.

```bash
./qntm --config-dir /tmp/alice invite create --name "Alice-Bob Encrypted Chat"
```

```output
Created direct invite:
Name: Alice-Bob Encrypted Chat
Conversation ID: def7200506179ce54ea5716da681d542
Invite URL: https://qntm.example.com/join#p2F2AWR0eXBlZmRpcm...
```

Bob would accept with: `./qntm --config-dir /tmp/bob invite accept <invite-url>`

## 6. Full integration test — bidirectional encrypted messaging

The integration test proves the complete flow: separate keystores → key generation → invite → key derivation → encrypt → send → receive → decrypt → verify signature — in both directions.

```bash
go test -v -run TestMultiAccountMessaging 2>&1 | grep -E "(✅|📨|📬|💌|🔑|🔐|🎉|Message:|Received:)"
```

```output
🔑 Alice keystore: /tmp/.../alice
🔑 Bob keystore: /tmp/.../bob
✅ Key derivation successful - Alice and Bob have matching encryption keys
💌 Alice sends first message...
   Message: Hello Bob! This is Alice. Can you receive this encrypted message?
📬 Bob receives Alice's message...
✅ Bob successfully decrypted and verified Alice's message
   Received: Hello Bob! This is Alice. Can you receive this encrypted message?
✅ Security policy check passed
💌 Bob sends reply to Alice...
   Message: Hi Alice! Yes, I received your message loud and clear. The encryption is working perfectly!
📬 Alice receives Bob's reply...
✅ Alice successfully decrypted and verified Bob's reply
   Received: Hi Alice! Yes, I received your message loud and clear. The encryption is working perfectly!
📨 Alice sending message 3...
   ✅ Received and verified: Let's test multiple messages. This is message #2 f...
📨 Bob sending message 4...
   ✅ Received and verified: Great idea! This is Bob's message #2. Crypto holdi...
📨 Alice sending message 5...
   ✅ Received and verified: Perfect! Message #3 from Alice. How about we test ...
📨 Bob sending message 6...
   ✅ Received and verified: Absolutely! Message #3 from Bob. The XChaCha20-Pol...
📨 Alice sending message 7...
   ✅ Received and verified: Final message from Alice. This has been a great te...
🎉 All 7 messages exchanged successfully across separate keystores!
📊 Final stats: 7 messages, 2 identities, 1 conversation, 0 failures
```

## 7. Error handling

Invalid invite — CBOR parsing rejects garbage input:

```bash
./qntm --config-dir /tmp/bob invite accept "https://example.com/qntm#invalid-base64" 2>&1 || true
```

```output
Error: failed to parse invite: failed to unmarshal invite: cbor: UTF-8 text string length 15750820170734182123 is too large, causing integer overflow
```

Invalid conversation ID:

```bash
./qntm --config-dir /tmp/alice message send "invalid-conv-id" "test" 2>&1 || true
```

```output
Error: invalid conversation ID format
```

Missing identity:

```bash
./qntm --config-dir /tmp/nonexistent identity show 2>&1 || true
```

```output
Error: failed to load identity: identity not found (run 'qntm identity generate' first)
```

## 8. Full test suite

All packages — crypto, identity, invite, message, group, dropbox, security:

```bash
go test ./... 2>&1 | grep -E "(ok|FAIL)"
```

```output
ok  	github.com/corpo/qntm          0.012s
ok  	github.com/corpo/qntm/crypto   0.004s
ok  	github.com/corpo/qntm/dropbox  0.003s
ok  	github.com/corpo/qntm/group    0.002s
ok  	github.com/corpo/qntm/identity 0.005s
ok  	github.com/corpo/qntm/invite   0.003s
ok  	github.com/corpo/qntm/message  0.003s
ok  	github.com/corpo/qntm/security 0.002s
```

## 9. Cleanup

```bash
rm -rf /tmp/alice /tmp/bob /tmp/charlie
```

```output
(clean)
```

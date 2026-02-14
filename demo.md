# qntm — End-to-End Encrypted Agent Messaging

*2026-02-14T13:30:00Z*

Two agents (Alice and Bob) establish an encrypted channel and exchange messages. Neither the drop box nor any intermediary can read the plaintext. Signatures prove sender identity inside the encryption layer.

Build the CLI: `cd ~/src/corpo/qntm && go build ./cmd/qntm`

## 1. Create separate keystores

Each agent has its own identity, stored in an isolated directory. A shared drop box directory simulates the untrusted relay.

```bash
rm -rf /tmp/alice /tmp/bob /tmp/charlie /tmp/qntm-dropbox
mkdir -p /tmp/alice /tmp/bob /tmp/charlie /tmp/qntm-dropbox
```

## 2. Alice generates her identity

Ed25519 keypair — the private key never leaves her keystore.

```bash
./qntm --config-dir /tmp/alice identity generate
```

```output
Generated new identity:
Key ID: qYcBLo-42ji9kK_NYGp1AA
Public Key: XQL5pvPm97KypuuNatwB07c_ox1lqg4DmM-xfHTs8ug
Saved to: /tmp/alice/identity.json
```

## 3. Bob generates his identity

```bash
./qntm --config-dir /tmp/bob identity generate
```

```output
Generated new identity:
Key ID: N67jJgdMkH761ZZMILCdrA
Public Key: EqotWkwylBS6_0NwmXmXrPRFx6l9afeiUZTW75ONK1o
Saved to: /tmp/bob/identity.json
```

## 4. Verify separate identities

```bash
./qntm --config-dir /tmp/alice identity show
```

```output
Current identity:
Key ID: qYcBLo-42ji9kK_NYGp1AA
Public Key: XQL5pvPm97KypuuNatwB07c_ox1lqg4DmM-xfHTs8ug
```

```bash
./qntm --config-dir /tmp/bob identity show
```

```output
Current identity:
Key ID: N67jJgdMkH761ZZMILCdrA
Public Key: EqotWkwylBS6_0NwmXmXrPRFx6l9afeiUZTW75ONK1o
```

## 5. Alice creates an invite

The invite contains a shared secret delivered out-of-band (iMessage, Signal, etc). Both sides derive matching encryption keys via HKDF.

```bash
./qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox invite create --name "Alice-Bob Encrypted Chat"
```

```output
Created direct invite:
Name: Alice-Bob Encrypted Chat
Conversation ID: c7e0e18659e141aea548e053e2959d61
Invite URL: https://qntm.example.com/join#p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1At...
```

## 6. Bidirectional encrypted messaging via CLI

The full flow: Bob accepts the invite → Alice sends → Bob receives and decrypts → Bob replies → Alice receives and decrypts. All through the CLI using a shared drop box directory (`--storage /tmp/qntm-dropbox`).

### 6a. Bob accepts the invite

Bob parses the invite URL, derives matching encryption keys, and joins the conversation.

```bash
./qntm --config-dir /tmp/bob --storage /tmp/qntm-dropbox invite accept "https://qntm.example.com/join#p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUMfg4YZZ4UGupUjgU-KVnWFraW52aXRlX3NhbHRYIJ9uXLyYuMj8uhiYjPStpXV9SD6kytCZQWt0SB7EwoSRbWludml0ZV9zZWNyZXRYIAj5nr8hcfPGyyBW3t33_4D6CXbRDsDZh2_yhsCG0tDLbWludml0ZXJfaWtfcGtYIF0C-abz5veysqbrjWrcAdO3P6MdZaoOA5jPsXx07PLo"
```

```output
Accepted direct invite:
Conversation ID: c7e0e18659e141aea548e053e2959d61
Participants: 2
```

Alice also accepts her own invite to store the conversation locally:

```bash
./qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox invite accept "https://qntm.example.com/join#p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUMfg4YZZ4UGupUjgU-KVnWFraW52aXRlX3NhbHRYIJ9uXLyYuMj8uhiYjPStpXV9SD6kytCZQWt0SB7EwoSRbWludml0ZV9zZWNyZXRYIAj5nr8hcfPGyyBW3t33_4D6CXbRDsDZh2_yhsCG0tDLbWludml0ZXJfaWtfcGtYIF0C-abz5veysqbrjWrcAdO3P6MdZaoOA5jPsXx07PLo"
```

```output
Accepted direct invite:
Conversation ID: c7e0e18659e141aea548e053e2959d61
Participants: 1
```

### 6b. Alice sends a message

The message is encrypted with XChaCha20-Poly1305, signed with Alice's Ed25519 key, and written to the shared drop box.

```bash
./qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox message send c7e0e18659e141aea548e053e2959d61 "Hello Bob! This is Alice. Can you receive this encrypted message?"
```

```output
Message sent to conversation c7e0e18659e141aea548e053e2959d61
Message ID: 2fee3564adbd811d4500e2c2f1664029
```

### 6c. Bob receives and decrypts

Bob reads from the drop box, decrypts the ciphertext, and verifies Alice's signature.

```bash
./qntm --config-dir /tmp/bob --storage /tmp/qntm-dropbox message receive c7e0e18659e141aea548e053e2959d61
```

```output
Conversation c7e0e18659e141aea548e053e2959d61 (1 new messages):
  [a987012e8fb8da38] text: Hello Bob! This is Alice. Can you receive this encrypted message?

Received 1 total messages
```

### 6d. Bob replies

```bash
./qntm --config-dir /tmp/bob --storage /tmp/qntm-dropbox message send c7e0e18659e141aea548e053e2959d61 "Hi Alice! Yes, I received your message. The encryption is working perfectly!"
```

```output
Message sent to conversation c7e0e18659e141aea548e053e2959d61
Message ID: 4cc1ff298f2ebfb1267e0b1f696bffb7
```

### 6e. Alice receives Bob's reply

```bash
./qntm --config-dir /tmp/alice --storage /tmp/qntm-dropbox message receive c7e0e18659e141aea548e053e2959d61
```

```output
Conversation c7e0e18659e141aea548e053e2959d61 (1 new messages):
  [37aee326074c907e] text: Hi Alice! Yes, I received your message. The encryption is working perfectly!

Received 1 total messages
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

The integration test (`TestMultiAccountMessaging`) also validates the full bidirectional flow programmatically:

```bash
go test -v -run TestMultiAccountMessaging 2>&1 | tail -5
```

```output
🎉 All 7 messages exchanged successfully across separate keystores!
📊 Final stats: 7 messages, 2 identities, 1 conversation, 0 failures
--- PASS: TestMultiAccountMessaging (0.01s)
PASS
ok  	github.com/corpo/qntm	0.012s
```

## 9. Cleanup

```bash
rm -rf /tmp/alice /tmp/bob /tmp/charlie /tmp/qntm-dropbox
```

```output
(clean)
```

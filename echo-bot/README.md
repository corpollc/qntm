# qntm Echo Bot 🔒🤖

A proof-of-concept bot that echoes encrypted messages, demonstrating that qntm's end-to-end encryption works in real-time.

## Try it now

```bash
# Install qntm and generate your identity
uvx qntm identity generate

# Join the echo bot conversation
uvx qntm convo join "p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUEgFVlTbS7D2TsYwibcOG_RraW52aXRlX3NhbHRYIFzWXq0HBDoqiG69PubwksJ2KYD9PfmSjiN7uDx7WJphbWludml0ZV9zZWNyZXRYIOoxcOzsn50VZ-E6F1kLwxHcrTK40f4BoU60McQCY4lJbWludml0ZXJfaWtfcGtYIKStglMb1FebJrKMxFfr90mWtlfhCKMYF4oYyy9HO1Z_" --name "Your Name"

# Send an encrypted message
uvx qntm send 48055654db4bb0f64ec63089b70e1bf4 "Hello, echo bot!"

# Receive the encrypted echo
uvx qntm recv 48055654db4bb0f64ec63089b70e1bf4
```

You'll see the bot echo your message back, encrypted end-to-end. The relay never sees plaintext.

## Running the bot

```bash
python3 echo-bot/bot.py
```

The bot polls the relay every 5 seconds for new messages and echoes them back with a 🔒 prefix.

## How it works

1. The echo bot has its own cryptographic identity (`echo-bot/.qntm/identity.json`)
2. It creates/owns a conversation that anyone can join via invite token
3. On each poll, it receives new messages, decrypts them locally, and sends back an encrypted echo
4. The relay only ever sees ciphertext — it cannot read your messages or the echoes

## Architecture

```
You (qntm CLI)          qntm Relay (CF Worker)          Echo Bot
    |                          |                            |
    |--- encrypted msg ------->|                            |
    |                          |--- encrypted msg --------->|
    |                          |                            | (decrypt, echo)
    |                          |<--- encrypted echo --------|
    |<--- encrypted echo ------|                            |
```

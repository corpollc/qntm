#!/usr/bin/env python3
"""Fresh bidirectional Swift/Python/TypeScript protocol verification.

Run with a Python environment containing python-dist's dependencies, after npm ci
in client. Fixture keys are synthetic test identities and outputs live in a temp dir.
"""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python-dist/src"))


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value):
    return base64.b64decode(value, validate=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-path", type=Path, default=ROOT)
    args = parser.parse_args()
    from qntm.cbor import marshal_canonical, unmarshal
    from qntm.identity import generate_identity, validate_identity, base64url_encode
    from qntm.invite import create_invite, invite_to_token, invite_from_url, derive_conversation_keys, create_conversation
    from qntm.message import create_message, decrypt_message, serialize_envelope, deserialize_envelope
    from qntm.crypto import QSP1Suite
    from qntm.gate import seal_secret, open_secret
    from qntm.attachment import prepare_attachment, assemble_attachment, AttachmentContext
    from qntm.announce import channel_id, derive_announce_keys, verify_register_signature
    from qntm.did import resolve_did_to_ed25519

    suite = QSP1Suite()
    def encode_identity(identity):
        return marshal_canonical({"private_key": identity["privateKey"], "public_key": identity["publicKey"], "key_id": identity["keyID"]})
    def decode_identity(encoded):
        raw = unmarshal(unb64(encoded))
        result = {"privateKey": raw["private_key"], "publicKey": raw["public_key"], "keyID": raw["key_id"]}
        validate_identity(result)
        return result

    with tempfile.TemporaryDirectory(prefix="qntm-swift-interop-") as temporary:
        directory = Path(temporary)
        env = dict(os.environ, QNTM_SWIFT_INTEROP_OUTPUT=str(directory / "swift.json"))
        subprocess.run(["swift", "test", "--package-path", str(args.package_path), "--filter", "InteropTests.testEmitSwiftFixture"], env=env, check=True, cwd=ROOT)
        fixture = json.loads((directory / "swift.json").read_text())
        sender = decode_identity(fixture["identity_b64"])
        recipient = decode_identity(fixture["recipient_b64"])
        invite = invite_from_url(fixture["invite_token"])
        conversation = create_conversation(invite, derive_conversation_keys(invite))
        message = decrypt_message(deserialize_envelope(unb64(fixture["envelope_b64"])), conversation)
        assert message["inner"]["body"] == unb64(fixture["plaintext_b64"])
        assert message["inner"]["refs"] == [bytes(range(16))]
        assert open_secret(recipient["privateKey"], sender["publicKey"], unb64(fixture["sealed_b64"])) == message["inner"]["body"]
        assert suite.unwrap_key_for_recipient(unb64(fixture["wrapped_b64"]), recipient["privateKey"], recipient["keyID"], conversation["id"]) == bytes.fromhex(fixture["group_key_hex"])
        attachment = fixture["attachment"]
        context = AttachmentContext(conversation["id"], 0, sender["publicKey"])
        assert assemble_attachment(unb64(attachment["body_b64"]), context, [unb64(part) for part in attachment["parts_b64"]]) == unb64(attachment["plaintext_b64"])
        announce = fixture["announcement"]
        assert channel_id(sender["publicKey"]).hex() == announce["conversation_id"]
        assert derive_announce_keys(bytes.fromhex(announce["invite_secret"]), bytes.fromhex(announce["conversation_id"]))["root"].hex() == announce["root_key"]
        assert verify_register_signature(sender["publicKey"], announce["name"], announce["conversation_id"], base64url_encode(recipient["publicKey"]), announce["register_signature"])
        assert suite.verify(recipient["publicKey"], hashlib.sha256(fixture["envelope_b64"].encode()).digest(), bytes.fromhex(announce["envelope_signature"]))
        assert resolve_did_to_ed25519(fixture["did"]) == sender["publicKey"]

        sender, recipient = generate_identity(), generate_identity()
        invite = create_invite(sender)
        conversation = create_conversation(invite, derive_conversation_keys(invite))
        plaintext = "Python → Swift fixture 👋".encode()
        group_key = bytes(range(32))
        envelope = create_message(sender, conversation, "text", plaintext, refs=[bytes(range(16))])
        file_bytes = bytes(index % 251 for index in range(33000))
        attachment = prepare_attachment(sender, conversation, file_bytes, "python.bin")
        peer = {"identity_b64": b64(encode_identity(sender)), "recipient_b64": b64(encode_identity(recipient)),
                "invite_token": invite_to_token(invite), "envelope_b64": b64(serialize_envelope(envelope)),
                "plaintext_b64": b64(plaintext), "sealed_b64": b64(seal_secret(sender["privateKey"], recipient["publicKey"], plaintext)),
                "wrapped_b64": b64(suite.wrap_key_for_recipient(group_key, recipient["publicKey"], recipient["keyID"], conversation["id"])),
                "group_key_hex": group_key.hex(),
                "attachment": {"body_b64": b64(attachment.body), "parts_b64": [b64(part) for part in attachment.envelopes], "plaintext_b64": b64(file_bytes)}}
        (directory / "python.json").write_text(json.dumps(peer))
        subprocess.run(["npm", "run", "build", "--prefix", "client"], check=True, cwd=ROOT)
        subprocess.run(["node", "--input-type=module", "-", str(ROOT), str(directory)], input=NODE, text=True, check=True, cwd=ROOT)
        env = dict(os.environ, QNTM_SWIFT_INTEROP_INPUT=str(directory))
        subprocess.run(["swift", "test", "--package-path", str(args.package_path), "--filter", "InteropTests.testReadPeerFixtures"], env=env, check=True, cwd=ROOT)
        class IdentityFixture(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/ok")
                    self.end_headers()
                    return
                body = b"x" * (256 * 1024 + 1) if self.path in ("/large", "/stream-large") else b'{"id":"example"}'
                self.send_response(200)
                if self.path != "/stream-large":
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), IdentityFixture)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env = dict(os.environ, QNTM_SWIFT_TEST_IDENTITY_HTTP=f"http://127.0.0.1:{server.server_port}")
            subprocess.run(["swift", "test", "--package-path", str(args.package_path), "--filter", "DIDTests.testHTTPBoundsAndRedirects"], env=env, check=True, cwd=ROOT)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        print("PASS: Swift ↔ Python and Swift ↔ TypeScript messages, refs, identity imports, NaCl secrets, rekey wraps and multipart attachments; Swift announcement signatures and DID verified by Python; bounded identity HTTP and redirect refusal.")


NODE = r'''
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
const [root, directory] = process.argv.slice(2);
const q = await import(pathToFileURL(path.join(root, 'client/dist/index.js')).href);
const b64 = value => Buffer.from(value).toString('base64');
const bytes = value => new Uint8Array(Buffer.from(value, 'base64'));
const f = JSON.parse(fs.readFileSync(path.join(directory, 'swift.json'), 'utf8'));
const sender = q.deserializeIdentity(bytes(f.identity_b64));
const recipient = q.deserializeIdentity(bytes(f.recipient_b64));
const invite = q.inviteFromURL(f.invite_token);
const conversation = q.createConversation(invite, q.deriveConversationKeys(invite));
const message = q.decryptMessage(q.deserializeEnvelope(bytes(f.envelope_b64)), conversation);
assert.equal(b64(message.inner.body), f.plaintext_b64);
assert.equal(b64(message.inner.refs[0]), b64(new Uint8Array(Array.from({length:16},(_,i)=>i))));
assert.equal(b64(q.openSecret(recipient.privateKey, sender.publicKey, bytes(f.sealed_b64))), f.plaintext_b64);
const suite = new q.QSP1Suite();
assert.equal(Buffer.from(suite.unwrapKeyForRecipient(bytes(f.wrapped_b64), recipient.privateKey, recipient.keyID, conversation.id)).toString('hex'), f.group_key_hex);
const context = { conversationId: conversation.id, epoch: 0, senderPublicKey: sender.publicKey };
assert.equal(b64(q.assembleAttachment(bytes(f.attachment.body_b64), context, f.attachment.parts_b64.map(bytes))), f.attachment.plaintext_b64);
const a = q.generateIdentity(), b = q.generateIdentity();
const invitation = q.createInvite(a, 'direct');
const conv = q.createConversation(invitation, q.deriveConversationKeys(invitation));
const plaintext = new TextEncoder().encode('TypeScript → Swift fixture 👋');
const envelope = q.createMessage(a, conv, 'text', plaintext, [new Uint8Array(Array.from({length:16},(_,i)=>i))]);
const group = new Uint8Array(Array.from({length:32},(_,i)=>i));
const file = new Uint8Array(Array.from({length:33000},(_,i)=>i%251));
const attachment = q.prepareAttachment(a, conv, file, 'typescript.bin');
const output = { identity_b64:b64(q.serializeIdentity(a)), recipient_b64:b64(q.serializeIdentity(b)),
 invite_token:q.inviteToToken(invitation), envelope_b64:b64(q.serializeEnvelope(envelope)), plaintext_b64:b64(plaintext),
 sealed_b64:b64(q.sealSecret(a.privateKey,b.publicKey,plaintext)), wrapped_b64:b64(suite.wrapKeyForRecipient(group,b.publicKey,b.keyID,conv.id)),
 group_key_hex:Buffer.from(group).toString('hex'), attachment:{body_b64:b64(attachment.body),parts_b64:attachment.envelopes.map(b64),plaintext_b64:b64(file)}};
fs.writeFileSync(path.join(directory,'typescript.json'),JSON.stringify(output));
'''

if __name__ == "__main__":
    main()

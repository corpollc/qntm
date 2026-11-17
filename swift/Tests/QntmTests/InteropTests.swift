import XCTest

@testable import Qntm

/// Exported private keys are newly generated synthetic test identities, never profile keys.
final class InteropTests: XCTestCase {
  func testEmitSwiftFixture() throws {
    guard let path = ProcessInfo.processInfo.environment["QNTM_SWIFT_INTEROP_OUTPUT"] else {
      throw XCTSkip("Interop fixture export is explicitly enabled by verify-interop.py")
    }
    let sender = try Identity(seed: Data((1...32).map(UInt8.init)))
    let recipient = try Identity(seed: Data((33...64).map(UInt8.init)))
    let invite = try Invite(creator: sender)
    let conversation = try invite.conversation()
    let plaintext = Data("Native Swift ↔ Python ↔ TypeScript\n\u{feff}retained".utf8)
    let refs: [CBOR] = [.bytes(Data((0..<16).map(UInt8.init)))]
    let envelope = try Messaging.create(
      identity: sender, conversation: conversation, bodyType: "text", body: plaintext, refs: refs)
    let groupKey = Data(repeating: 42, count: 32)
    let attachmentData = Data((0..<33_000).map { UInt8($0 % 251) })
    let attachment = try Attachment.prepare(
      identity: sender, parent: conversation, data: attachmentData, name: "interop.bin")
    let channel = try AnnouncementChannel(
      name: "swift-interop", master: sender, posting: recipient,
      inviteSecret: Data(repeating: 19, count: 32))
    let fixture: [String: Any] = [
      "test_only": true, "source": "swift",
      "identity_b64": try sender.serialize().base64EncodedString(),
      "recipient_b64": try recipient.serialize().base64EncodedString(),
      "invite_token": try invite.token(),
      "envelope_b64": try envelope.serialize().base64EncodedString(),
      "plaintext_b64": plaintext.base64EncodedString(),
      "sealed_b64": try QSPCrypto.sealSecret(
        senderPrivateKey: sender.privateKey, recipientPublicKey: recipient.publicKey,
        plaintext: plaintext
      ).base64EncodedString(),
      "wrapped_b64": try QSPCrypto.wrapKey(
        groupKey, recipientPublicKey: recipient.publicKey, recipientKeyID: recipient.keyID,
        conversationID: conversation.id
      ).base64EncodedString(),
      "group_key_hex": groupKey.hex,
      "attachment": [
        "body_b64": attachment.body.base64EncodedString(),
        "parts_b64": attachment.envelopes.map { $0.base64EncodedString() },
        "plaintext_b64": attachmentData.base64EncodedString(),
      ],
      "announcement": [
        "name": channel.name, "conversation_id": channel.conversation.id.hex,
        "invite_secret": channel.inviteSecret.hex,
        "root_key": channel.conversation.keys.root.hex,
        "register_signature": try Announcement.signRegistration(channel: channel),
        "envelope_signature": try Announcement.signEnvelope(
          posting: recipient, envelope: envelope.serialize()),
      ],
      "did": try DID.fromPublicKey(sender.publicKey),
    ]
    try JSONSerialization.data(withJSONObject: fixture, options: [.sortedKeys]).write(
      to: URL(fileURLWithPath: path), options: .atomic)
  }

  func testReadPeerFixtures() throws {
    guard let directory = ProcessInfo.processInfo.environment["QNTM_SWIFT_INTEROP_INPUT"] else {
      throw XCTSkip("Peer fixture verification is enabled by verify-interop.py")
    }
    struct Fixture: Decodable {
      struct File: Decodable {
        let body_b64: String
        let parts_b64: [String]
        let plaintext_b64: String
      }
      let identity_b64: String
      let recipient_b64: String
      let invite_token: String
      let envelope_b64: String
      let plaintext_b64: String
      let sealed_b64: String
      let wrapped_b64: String
      let group_key_hex: String
      let attachment: File
    }
    for name in ["python", "typescript"] {
      let fixture = try JSONDecoder().decode(
        Fixture.self,
        from: Data(
          contentsOf: URL(fileURLWithPath: directory).appendingPathComponent(name + ".json")))
      let decode: (String) throws -> Data = { try XCTUnwrap(Data(base64Encoded: $0)) }
      let sender = try Identity(serialized: decode(fixture.identity_b64))
      let recipient = try Identity(serialized: decode(fixture.recipient_b64))
      let conversation = try Invite(tokenOrURL: fixture.invite_token).conversation()
      let message = try Messaging.decrypt(
        Envelope(serialized: decode(fixture.envelope_b64)), conversation: conversation)
      XCTAssertEqual(message.body, try decode(fixture.plaintext_b64), name)
      XCTAssertEqual(message.refs, [.bytes(Data((0..<16).map(UInt8.init)))], name)
      XCTAssertEqual(
        try QSPCrypto.openSecret(
          recipientPrivateKey: recipient.privateKey, senderPublicKey: sender.publicKey,
          sealed: decode(fixture.sealed_b64)), message.body, name)
      XCTAssertEqual(
        try QSPCrypto.unwrapKey(
          decode(fixture.wrapped_b64), recipientPrivateKey: recipient.privateKey,
          recipientKeyID: recipient.keyID, conversationID: conversation.id),
        try Data(hex: fixture.group_key_hex), name)
      let context = try AttachmentContext(
        conversationID: conversation.id, epoch: conversation.currentEpoch,
        senderPublicKey: sender.publicKey)
      XCTAssertEqual(
        try Attachment.assemble(
          decode(fixture.attachment.body_b64), context: context,
          envelopes: fixture.attachment.parts_b64.map(decode)),
        try decode(fixture.attachment.plaintext_b64), name)
    }
  }
}

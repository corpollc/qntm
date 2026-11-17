import XCTest

@testable import Qntm

final class AttachmentTests: XCTestCase {
  func testPythonAndTypeScriptFixtures() throws {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    struct Fixture: Decodable {
      let plaintext_b64: String
      let parent_invite_token: String
      let parent_envelope_b64: String
      let parts_b64: [String]
    }
    for name in ["attachment-python.json", "attachment-typescript.json"] {
      let fixture = try JSONDecoder().decode(
        Fixture.self, from: Data(contentsOf: root.appendingPathComponent("client/tests/\(name)")))
      let parent = try Invite(tokenOrURL: fixture.parent_invite_token).conversation()
      let envelope = try Envelope(
        serialized: XCTUnwrap(Data(base64Encoded: fixture.parent_envelope_b64)))
      let message = try Messaging.decrypt(envelope, conversation: parent, allowExpired: true)
      let context = try AttachmentContext(message: message)
      let parts = try fixture.parts_b64.map { try XCTUnwrap(Data(base64Encoded: $0)) }
      let assembled = try Attachment.assemble(
        message.body, context: context, envelopes: parts.reversed(), now: envelope.createdAt)
      XCTAssertEqual(assembled, Data(base64Encoded: fixture.plaintext_b64), name)
      XCTAssertThrowsError(
        try Attachment.assemble(
          message.body, context: context, envelopes: Array(parts.dropLast()),
          now: envelope.createdAt))
      let descriptor = try Attachment.parse(message.body, context: context)
      XCTAssertThrowsError(
        try Attachment.assemble(
          message.body, context: context, envelopes: parts, now: descriptor.expiresAt + 1))
    }
  }

  func testPrepareAndTampering() throws {
    let identity = try Identity()
    let parent = try Invite(creator: identity, type: .group).conversation()
    let context = try AttachmentContext(
      conversationID: parent.id, epoch: parent.currentEpoch, senderPublicKey: identity.publicKey)
    for size in [0, 1, 32_768, 32_769, 70_000] {
      let data = Data((0..<size).map { UInt8($0 % 251) })
      let prepared = try Attachment.prepare(
        identity: identity, parent: parent, data: data, name: "CON.txt")
      XCTAssertEqual(prepared.descriptor.name, "_CON.txt")
      XCTAssertEqual(
        try Attachment.assemble(prepared.body, context: context, envelopes: prepared.envelopes),
        data)
      var tampered = prepared.envelopes
      tampered[0][tampered[0].startIndex] ^= 1
      XCTAssertThrowsError(
        try Attachment.assemble(prepared.body, context: context, envelopes: tampered))
    }
    XCTAssertThrowsError(
      try Attachment.prepare(identity: identity, parent: parent, data: Data(), name: "../../secret")
    )
    XCTAssertThrowsError(
      try Attachment.prepare(
        identity: identity, parent: parent, data: Data(), name: "file",
        mediaType: "text/html; charset=utf-8"))
    XCTAssertEqual(Attachment.sanitizeFilename("a\u{202e}:b"), "ab")
  }
}

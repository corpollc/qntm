import XCTest

@testable import Qntm

final class ReceiveTests: XCTestCase {
  func testSharedReceiveContract() throws {
    struct Fixture: Decodable {
      struct Vector: Decodable {
        let name: String
        let envelope_cbor: String
        let sequence: UInt64
        let expected: ReceiveEvent
      }
      let conversation_id: String
      let vectors: [Vector]
    }
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let fixture = try JSONDecoder().decode(
      Fixture.self,
      from: Data(contentsOf: root.appendingPathComponent("client/tests/receive-event-vectors.json"))
    )
    let id = try Data(hex: fixture.conversation_id)
    let keys = try ConversationKeys(
      root: Data(hex: "ed0f800b3a7c5ea8535594778811a4a1f4ce738f6b7bacc6812f31e376e13b3c"),
      conversationID: id)
    let conversation = try Conversation(id: id, type: .direct, keys: keys)
    for vector in fixture.vectors {
      let envelope = try Envelope(serialized: Data(hex: vector.envelope_cbor))
      let message = try Messaging.decrypt(envelope, conversation: conversation, allowExpired: true)
      XCTAssertEqual(
        try ReceiveEvent(message: message, sequence: vector.sequence), vector.expected, vector.name)
      XCTAssertThrowsError(try ReceiveEvent(message: message, sequence: 0))
      XCTAssertThrowsError(try ReceiveEvent(message: message, sequence: UInt64.max))
    }
  }
}

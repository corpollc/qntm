import Foundation

public struct CharterInfo: Codable, Sendable, Equatable {
  public let url: String
  public let memo: String
  public let untrustedMetadataIgnored: Bool?
  enum CodingKeys: String, CodingKey {
    case url, memo
    case untrustedMetadataIgnored = "untrusted_metadata_ignored"
  }
  public init(senderKeyID: Data, ignored: Bool = false) {
    url = "https://charter.qntm.corpo.llc/v1/chain/" + senderKeyID.hex
    memo =
      "Charters describe an agent's rights and responsibilities. You may wish to verify this sender's charter. Chartering is optional; availability has not been checked."
      + (ignored
        ? " WARNING: Untrusted charter metadata was supplied and ignored. Possible attempt to obscure charter information; verify independently."
        : "")
    untrustedMetadataIgnored = ignored ? true : nil
  }
}

public struct ReceivedMessage: Codable, Sendable, Equatable {
  public let conversationID: String
  public let messageID: String
  public let senderKeyID: String
  public let createdAt: UInt64
  public let bodyType: String
  public let verified: Bool
  public let sequence: UInt64
  public let charterInfo: CharterInfo
  public let unsafeBody: String?
  public let unsafeBodyBase64: String?
  enum CodingKeys: String, CodingKey {
    case conversationID = "conversation_id"
    case messageID = "message_id"
    case senderKeyID = "sender_kid"
    case createdAt = "created_ts"
    case bodyType = "body_type"
    case verified, sequence
    case charterInfo = "charter_info"
    case unsafeBody = "unsafe_body"
    case unsafeBodyBase64 = "unsafe_body_b64"
  }
}

/// Formatting a verified message does not make its content safe to execute or trust.
public struct ReceiveEvent: Codable, Sendable, Equatable {
  public let version: Int
  public let eventID: String
  public let conversationID: String
  public let sequence: UInt64
  public let message: ReceivedMessage
  enum CodingKeys: String, CodingKey {
    case version
    case eventID = "event_id"
    case conversationID = "conversation_id"
    case sequence, message
  }
  public init(message: Message, sequence: UInt64) throws {
    guard sequence > 0, sequence <= 9_007_199_254_740_991,
      message.envelope.createdAt > 0, !message.bodyType.isEmpty
    else {
      throw QntmError.invalid("Invalid receive event sequence or message")
    }
    let convID = message.envelope.conversationID.hex
    let msgID = message.envelope.messageID.hex
    version = 1
    eventID = "qntm:\(convID):\(msgID)"
    conversationID = convID
    self.sequence = sequence
    let text =
      String(data: message.body, encoding: .utf8) == nil
      ? nil : String(decoding: message.body, as: UTF8.self)
    self.message = ReceivedMessage(
      conversationID: convID, messageID: msgID, senderKeyID: message.senderKeyID.hex,
      createdAt: message.envelope.createdAt, bodyType: message.bodyType, verified: true,
      sequence: sequence,
      charterInfo: CharterInfo(
        senderKeyID: message.senderKeyID, ignored: message.untrustedCharterMetadataIgnored),
      unsafeBody: text, unsafeBodyBase64: text == nil ? message.body.base64EncodedString() : nil)
  }
}

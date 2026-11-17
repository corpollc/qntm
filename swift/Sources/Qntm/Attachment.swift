import Foundation

public struct AttachmentContext: Sendable, Equatable {
  public let conversationID: Data
  public let epoch: UInt32
  public let senderPublicKey: Data
  public init(conversationID: Data, epoch: UInt32, senderPublicKey: Data) throws {
    guard conversationID.count == 16, QSPCrypto.isValidPublicKey(senderPublicKey) else {
      throw QntmError.invalid("Invalid attachment context")
    }
    self.conversationID = conversationID
    self.epoch = epoch
    self.senderPublicKey = senderPublicKey
  }
  public init(message: Message) throws {
    guard message.bodyType == Attachment.bodyType || message.bodyType == "blobref" else {
      throw QntmError.invalid("Attachment requires a verified blobref parent")
    }
    try self.init(
      conversationID: message.envelope.conversationID, epoch: message.envelope.epoch,
      senderPublicKey: message.senderPublicKey)
  }
}

public struct AttachmentDescriptor: Codable, Sendable, Equatable {
  public struct Part: Codable, Sendable, Equatable {
    public let messageID: String
    public let sha256: String
    enum CodingKeys: String, CodingKey {
      case messageID = "message_id"
      case sha256
    }
  }
  public let type: String
  public let name: String
  public let mediaType: String
  public let size: Int
  public let sha256: String
  public let parentConversationID: String
  public let parentEpoch: UInt32
  public let inviteToken: String
  public let expiresAt: UInt64
  public let parts: [Part]
  enum CodingKeys: String, CodingKey {
    case type, name
    case mediaType = "media_type"
    case size, sha256
    case parentConversationID = "parent_conv_id"
    case parentEpoch = "parent_epoch"
    case inviteToken = "invite_token"
    case expiresAt = "expires_ts"
    case parts
  }
}

public struct PreparedAttachment: Sendable {
  public let descriptor: AttachmentDescriptor
  public let body: Data
  public let envelopes: [Data]
  /// Import a persisted send attempt. Validation runs again before upload.
  public init(body: Data, envelopes: [Data], context: AttachmentContext) throws {
    descriptor = try Attachment.parse(body, context: context)
    self.body = body
    self.envelopes = envelopes
  }
}

public enum Attachment {
  public static let bodyType = "qntm.attachment.v1"
  public static let partBytes = 32_768
  public static let maxBytes = 8 * 1024 * 1024
  public static let maxParts = 256
  public static let maxDescriptorBytes = 48 * 1024
  private static let reservedNames: Set<String> = Set(["CON", "PRN", "AUX", "NUL"])
    .union((1...9).map { "COM\($0)" }).union((1...9).map { "LPT\($0)" })

  public static func sanitizeFilename(_ name: String) -> String {
    let scalars = name.unicodeScalars.filter {
      $0.properties.generalCategory != .format && !(0x80...0x9f).contains($0.value) && $0 != ":"
    }
    let clean = String(String.UnicodeScalarView(scalars))
    return isReserved(clean) ? "_" + clean.trimmingCharacters(in: .whitespaces) : clean
  }

  /// Context must come from an authenticated parent whose group policy has been accepted.
  public static func parse(_ body: Data, context: AttachmentContext) throws -> AttachmentDescriptor
  {
    guard body.count <= maxDescriptorBytes,
      let raw = try JSONSerialization.jsonObject(with: body) as? [String: Any],
      Set(raw.keys)
        == Set([
          "type", "name", "media_type", "size", "sha256", "parent_conv_id", "parent_epoch",
          "invite_token", "expires_ts", "parts",
        ]),
      let rawParts = raw["parts"] as? [[String: Any]],
      rawParts.allSatisfy({ Set($0.keys) == Set(["message_id", "sha256"]) })
    else {
      throw QntmError.invalid("Invalid attachment descriptor fields")
    }
    let descriptor = try JSONDecoder().decode(AttachmentDescriptor.self, from: body)
    guard descriptor.type == bodyType,
      validLabel(descriptor.name, maxBytes: 255), !isReserved(descriptor.name),
      ![".", ".."].contains(descriptor.name),
      descriptor.name.rangeOfCharacter(from: CharacterSet(charactersIn: "/\\:")) == nil,
      validLabel(descriptor.mediaType, maxBytes: 120),
      descriptor.mediaType.range(
        of: "^[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+$", options: .regularExpression) != nil,
      (0...maxBytes).contains(descriptor.size),
      validHex(descriptor.sha256, count: 64), validHex(descriptor.parentConversationID, count: 32),
      descriptor.expiresAt > 0, descriptor.expiresAt <= 9_007_199_254_740_991,
      descriptor.parentConversationID == context.conversationID.hex,
      descriptor.parentEpoch == context.epoch,
      descriptor.inviteToken.utf8.count <= 2048,
      descriptor.inviteToken.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil
    else {
      throw QntmError.invalid("Invalid attachment descriptor or parent binding")
    }
    let invite = try Invite(tokenOrURL: descriptor.inviteToken)
    guard invite.type == .direct, invite.inviterPublicKey == context.senderPublicKey,
      invite.conversationID != context.conversationID,
      descriptor.parts.count == max(1, (descriptor.size + partBytes - 1) / partBytes),
      descriptor.parts.count <= maxParts,
      Set(descriptor.parts.map(\.messageID)).count == descriptor.parts.count,
      descriptor.parts.allSatisfy({
        validHex($0.messageID, count: 32) && validHex($0.sha256, count: 64)
      })
    else {
      throw QntmError.invalid("Attachment sender, channel or part mismatch")
    }
    return descriptor
  }

  /// Persist the exact returned wires before network writes; publish the parent last.
  public static func prepare(
    identity: Identity, parent: Conversation, data: Data, name: String,
    mediaType: String = "application/octet-stream", now: UInt64 = unixSeconds()
  ) throws -> PreparedAttachment {
    guard data.count <= maxBytes else {
      throw QntmError.invalid("Attachments are limited to 8 MiB")
    }
    let invite = try Invite(creator: identity)
    let conversation = try invite.conversation()
    var wires: [Data] = []
    var parts: [AttachmentDescriptor.Part] = []
    var expiration = UInt64.max
    for index in 0..<max(1, (data.count + partBytes - 1) / partBytes) {
      let lower = index * partBytes
      let chunk = data.subdata(in: lower..<min(lower + partBytes, data.count))
      let payload = try CBOR.map([
        "v": .unsigned(1), "index": .unsigned(UInt64(index)), "data": .bytes(chunk),
      ]).encode()
      let envelope = try Messaging.create(
        identity: identity, conversation: conversation, bodyType: "blob.part", body: payload,
        now: now)
      let wire = try envelope.serialize()
      wires.append(wire)
      parts.append(.init(messageID: envelope.messageID.hex, sha256: QSPCrypto.hash(wire).hex))
      expiration = min(expiration, envelope.expiresAt)
    }
    let descriptor = AttachmentDescriptor(
      type: bodyType, name: sanitizeFilename(name), mediaType: mediaType,
      size: data.count, sha256: QSPCrypto.hash(data).hex, parentConversationID: parent.id.hex,
      parentEpoch: parent.currentEpoch, inviteToken: try invite.token(), expiresAt: expiration,
      parts: parts)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let body = try encoder.encode(descriptor)
    let context = try AttachmentContext(
      conversationID: parent.id, epoch: parent.currentEpoch, senderPublicKey: identity.publicKey)
    return try PreparedAttachment(body: body, envelopes: wires, context: context)
  }

  public static func assemble(
    _ body: Data, context: AttachmentContext, envelopes: [Data],
    now: UInt64 = unixSeconds()
  ) throws -> Data {
    let descriptor = try parse(body, context: context)
    guard now <= descriptor.expiresAt else {
      throw QntmError.invalid("Attachment has expired; ask its sender to resend")
    }
    guard envelopes.count <= 512, envelopes.allSatisfy({ $0.count <= 65_536 }) else {
      throw QntmError.invalid("Attachment replay exceeds limits")
    }
    var wires: [String: Data] = [:]
    for wire in envelopes { wires[QSPCrypto.hash(wire).hex] = wire }
    let conversation = try Invite(tokenOrURL: descriptor.inviteToken).conversation()
    var result = Data()
    var expiration = UInt64.max
    for (index, part) in descriptor.parts.enumerated() {
      guard let wire = wires[part.sha256] else {
        throw QntmError.invalid("Attachment parts are missing or expired")
      }
      let envelope = try Envelope(serialized: wire, now: now)
      guard envelope.messageID.hex == part.messageID, envelope.epoch == 0,
        envelope.expiresAt >= descriptor.expiresAt
      else { throw QntmError.invalid("Attachment part identity mismatch") }
      let message = try Messaging.decrypt(envelope, conversation: conversation, now: now)
      guard message.bodyType == "blob.part", message.senderPublicKey == context.senderPublicKey,
        let payload = try CBOR.decode(message.body).mapValue,
        Set(payload.keys) == Set(["v", "index", "data"]),
        payload["v"]?.uintValue == 1, payload["index"]?.uintValue == UInt64(index),
        let chunk = payload["data"]?.bytesValue,
        chunk.count == min(partBytes, descriptor.size - index * partBytes)
      else {
        throw QntmError.invalid("Attachment part sender, order or size mismatch")
      }
      result.append(chunk)
      expiration = min(expiration, envelope.expiresAt)
    }
    guard expiration == descriptor.expiresAt, result.count == descriptor.size,
      QSPCrypto.hash(result).hex == descriptor.sha256
    else { throw QntmError.invalid("Attachment hash or expiry mismatch") }
    return result
  }

  public static func upload(
    _ prepared: PreparedAttachment, context: AttachmentContext, relay: DropboxClient
  ) async throws {
    let descriptor = try parse(prepared.body, context: context)
    guard prepared.envelopes.count == descriptor.parts.count else {
      throw QntmError.invalid("Saved attachment parts do not match descriptor")
    }
    _ = try assemble(prepared.body, context: context, envelopes: prepared.envelopes)
    let conversationID = try Invite(tokenOrURL: descriptor.inviteToken).conversationID
    for wire in prepared.envelopes {
      _ = try await relay.postMessage(conversationID: conversationID, envelope: wire)
    }
  }

  public static func download(_ body: Data, context: AttachmentContext, relay: DropboxClient)
    async throws -> Data
  {
    let descriptor = try parse(body, context: context)
    let conversationID = try Invite(tokenOrURL: descriptor.inviteToken).conversationID
    let replay = try await relay.receiveMessages(conversationID: conversationID, maxMessages: 512)
    return try assemble(body, context: context, envelopes: replay.messages)
  }

  private static func isReserved(_ name: String) -> Bool {
    reservedNames.contains(
      String(name.split(separator: ".", omittingEmptySubsequences: false).first ?? "")
        .trimmingCharacters(in: .whitespaces).uppercased())
  }
  private static func validHex(_ string: String, count: Int) -> Bool {
    string.utf8.count == count
      && string.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
  }
  private static func validLabel(_ label: String, maxBytes: Int) -> Bool {
    !label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && label.utf8.count <= maxBytes
      && label.unicodeScalars.allSatisfy {
        $0.value > 0x1f && !(0x7f...0x9f).contains($0.value)
          && $0.properties.generalCategory != .format
      }
  }
}

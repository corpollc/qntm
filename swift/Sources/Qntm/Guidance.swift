import Foundation

public struct GuidanceProvider: Codable, Sendable, Equatable {
  public enum Category: String, Codable, Sendable {
    case legal, ethical
    case lawEnforcement = "law_enforcement"
  }
  public let id: String
  public let category: Category
  public let name: String
  public let kind: String
  public let offer: String
  public let delivery: String
  public let recipientKeyID: String
  public let recipientPublicKey: String
  public let conversationID: String
  public let intakeInvite: String
  public let relayURL: String

  public init(
    id: String, category: Category, name: String, offer: String, recipientKeyID: String,
    recipientPublicKey: String, conversationID: String, intakeInvite: String, relayURL: String
  ) {
    self.id = id
    self.category = category
    self.name = name
    self.kind = "organization"
    self.offer = offer
    self.delivery = "sealed_intake_v1"
    self.recipientKeyID = recipientKeyID
    self.recipientPublicKey = recipientPublicKey
    self.conversationID = conversationID
    self.intakeInvite = intakeInvite
    self.relayURL = relayURL
  }
  enum CodingKeys: String, CodingKey {
    case id, category, name, kind, offer, delivery
    case recipientKeyID = "recipient_key_id"
    case recipientPublicKey = "recipient_public_key"
    case conversationID = "conversation_id"
    case intakeInvite = "intake_invite"
    case relayURL = "relay_url"
  }

  public func intakeConversation() throws -> Conversation {
    guard kind == "organization", delivery == "sealed_intake_v1", recipientPublicKey.count == 64,
      recipientKeyID.count == 32, conversationID.count == 32,
      recipientPublicKey == recipientPublicKey.lowercased(),
      recipientKeyID == recipientKeyID.lowercased(),
      conversationID == conversationID.lowercased(), let relay = URLComponents(string: relayURL),
      relay.scheme == "https", relay.host != nil, relay.user == nil, relay.password == nil
    else {
      throw QntmError.invalid("Invalid guidance provider")
    }
    let publicKey = try Data(hex: recipientPublicKey)
    let invite = try Invite(tokenOrURL: intakeInvite)
    guard invite.type == .direct, invite.conversationID == (try Data(hex: conversationID)),
      invite.inviterPublicKey == publicKey,
      Data(QSPCrypto.hash(publicKey).prefix(16)) == (try Data(hex: recipientKeyID))
    else {
      throw QntmError.invalid("Guidance provider key or intake mismatch")
    }
    return try invite.conversation()
  }
}

public struct PreparedGuidance: Sendable {
  public let envelope: Envelope
  public let replyInvite: Invite
  public let replyConversation: Conversation
  public let requestID: String
  public let question: String
  public let context: String
  public let provider: GuidanceProvider
  public var processingNotice: String { Guidance.processingNotice }
}

public struct ReceivedGuidance: Sendable {
  public let requestID: String
  public let question: String
  public let context: String
  public let senderPublicKey: Data
  public let senderKeyID: Data
  public let replyInvite: Invite
  public let message: Message
}

public enum Guidance {
  public static let bodyType = "guidance.sealed.v1"
  public static let processingNotice =
    "Free guidance provided by Corpo. Requests are processed by Grok for triage and may be passed to the Corpo team. No automated substantive advice or response is promised."

  /// Pure preparation for explicit user review. This function never performs network I/O.
  public static func prepare(
    identity: Identity, provider: GuidanceProvider, question: String, context: String = "",
    now: UInt64 = unixSeconds()
  ) throws -> PreparedGuidance {
    let intake = try provider.intakeConversation()
    let question = question.trimmingCharacters(in: .whitespacesAndNewlines)
    let context = context.trimmingCharacters(in: .whitespacesAndNewlines)
    try validateText(question: question, context: context)
    let recipient = try Data(hex: provider.recipientPublicKey)
    let reply = try Invite(creator: identity)
    var replyConversation = try reply.conversation()
    let recipientID = Data(QSPCrypto.hash(recipient).prefix(16))
    if !replyConversation.participants.contains(recipientID) {
      replyConversation.participants.append(recipientID)
    }
    let payload = GuidancePayload(
      domain: "qntm.guidance.request.v1", category: provider.category.rawValue,
      recipientKeyID: provider.recipientKeyID, requestID: reply.conversationID.hex,
      replyInvite: try reply.token(), question: question, context: context)
    let encoded = try JSONEncoder().encode(payload)
    let sealed = try QSPCrypto.sealSecret(
      senderPrivateKey: identity.privateKey, recipientPublicKey: recipient, plaintext: encoded)
    let envelope = try Messaging.create(
      identity: identity, conversation: intake, bodyType: bodyType,
      body: Data(sealed.base64URL.utf8), ttl: 7 * 86_400, now: now)
    return PreparedGuidance(
      envelope: envelope, replyInvite: reply, replyConversation: replyConversation,
      requestID: payload.requestID, question: question, context: context, provider: provider)
  }

  public static func open(
    identity: Identity, provider: GuidanceProvider, envelope: Envelope,
    now: UInt64 = unixSeconds()
  ) throws -> ReceivedGuidance {
    guard identity.publicKey.hex == provider.recipientPublicKey,
      envelope.ciphertext.count <= 100_000
    else {
      throw QntmError.invalid("Invalid guidance recipient or request size")
    }
    let message = try Messaging.decrypt(
      envelope, conversation: provider.intakeConversation(), now: now)
    guard message.bodyType == bodyType, let body = String(data: message.body, encoding: .utf8)
    else {
      throw QntmError.invalid("Expected sealed guidance request")
    }
    let raw = try QSPCrypto.openSecret(
      recipientPrivateKey: identity.privateKey,
      senderPublicKey: message.senderPublicKey, sealed: Data.fromBase64URL(body))
    return try decodePayload(raw, provider: provider, message: message)
  }

  /// Reopens a sender's own prepared request so displayed review fields can be bound to its ciphertext.
  public static func inspectPrepared(
    identity: Identity, provider: GuidanceProvider, envelope: Envelope, now: UInt64 = unixSeconds()
  ) throws -> ReceivedGuidance {
    let message = try Messaging.decrypt(
      envelope, conversation: provider.intakeConversation(), now: now)
    guard message.senderPublicKey == identity.publicKey, message.bodyType == bodyType,
      let body = message.text
    else { throw QntmError.invalid("Prepared guidance belongs to another sender") }
    let raw = try QSPCrypto.openSecret(
      recipientPrivateKey: identity.privateKey,
      senderPublicKey: Data(hex: provider.recipientPublicKey), sealed: Data.fromBase64URL(body))
    return try decodePayload(raw, provider: provider, message: message)
  }

  private static func decodePayload(_ raw: Data, provider: GuidanceProvider, message: Message)
    throws -> ReceivedGuidance
  {
    guard raw.count <= 60_000,
      let fields = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
      Set(fields.keys)
        == Set([
          "domain", "category", "recipient_key_id", "request_id", "reply_invite", "question",
          "context",
        ])
    else {
      throw QntmError.invalid("Invalid guidance payload")
    }
    let value = try JSONDecoder().decode(GuidancePayload.self, from: raw)
    guard value.domain == "qntm.guidance.request.v1", value.category == provider.category.rawValue,
      value.recipientKeyID == provider.recipientKeyID, value.replyInvite.utf8.count <= 2048
    else {
      throw QntmError.invalid("Invalid guidance payload binding")
    }
    try validateText(question: value.question, context: value.context)
    let reply = try Invite(tokenOrURL: value.replyInvite)
    guard reply.type == .direct, reply.inviterPublicKey == message.senderPublicKey,
      value.requestID == reply.conversationID.hex, value.requestID != provider.conversationID
    else {
      throw QntmError.invalid("Guidance reply destination does not match sender")
    }
    return ReceivedGuidance(
      requestID: value.requestID, question: value.question, context: value.context,
      senderPublicKey: message.senderPublicKey, senderKeyID: message.senderKeyID,
      replyInvite: reply, message: message)
  }

  private static func validateText(question: String, context: String) throws {
    guard !question.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      question.unicodeScalars.count <= 4000, context.unicodeScalars.count <= 8000
    else {
      throw QntmError.invalid(
        "Guidance requires a question of 1–4,000 characters and context of at most 8,000 characters"
      )
    }
  }
}

private struct GuidancePayload: Codable {
  let domain: String
  let category: String
  let recipientKeyID: String
  let requestID: String
  let replyInvite: String
  let question: String
  let context: String
  enum CodingKeys: String, CodingKey {
    case domain, category, question, context
    case recipientKeyID = "recipient_key_id"
    case requestID = "request_id"
    case replyInvite = "reply_invite"
  }
}

extension Guidance {
  public static let corpoProviders: [GuidanceProvider] = [
    GuidanceProvider(
      id: "corpo_legal", category: .legal, name: "Corpo", offer: "Free guidance provided by Corpo",
      recipientKeyID: "bc20e1568ca3cd5aa80a7a81f95f8b3c",
      recipientPublicKey: "a2189cabe0632decacd6d16c1a63d7ef5a6adf61e6d1b24abb8539a1955f7753",
      conversationID: "72c82e3426ef5e1b6502dde090e5c56e",
      intakeInvite:
        "p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUHLILjQm714bZQLd4JDlxW5raW52aXRlX3NhbHRYIPx_UtwirCqHPR9pyPN6ULEo9pxjDzLLb3UIQKIuBplLbWludml0ZV9zZWNyZXRYIGmEO0yO4FCeYFaf2HhbBpi6ezlSl4ZBqucgiQxFhGdfbWludml0ZXJfaWtfcGtYIKIYnKvgYy3srNbRbBpj1-9aat9h5tGySruFOaGVX3dT",
      relayURL: "https://inbox.qntm.corpo.llc"),
    GuidanceProvider(
      id: "corpo_ethical", category: .ethical, name: "Corpo",
      offer: "Free guidance provided by Corpo", recipientKeyID: "866ca8cb6ec1931bbcdda6af110e14d8",
      recipientPublicKey: "01480909dac77b4f4d2192df8d03a5af062c2316ececafc88ca7d3d27489040e",
      conversationID: "c6324365ac31f0b033e6ea8c20cd99f3",
      intakeInvite:
        "p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUMYyQ2WsMfCwM-bqjCDNmfNraW52aXRlX3NhbHRYIDfv0cv8ITAu0l-fn8KRr6r2k2OKnWb7rHP0d7Y__3UebWludml0ZV9zZWNyZXRYIAgRATyY9or8-9vD_tUWtm7R63Mz2DjN0Eu0Nb9mMNa7bWludml0ZXJfaWtfcGtYIAFICQnax3tPTSGS340Dpa8GLCMW7OyvyIyn09J0iQQO",
      relayURL: "https://inbox.qntm.corpo.llc"),
    GuidanceProvider(
      id: "corpo_law_enforcement", category: .lawEnforcement, name: "Corpo",
      offer: "Free guidance provided by Corpo", recipientKeyID: "cedf2498fa167378bc03202537c8ff27",
      recipientPublicKey: "de7ff1af68a3e8ccc2d8eeb78066ad322bcad5dcf0e698fc3ed78c1b97946bb3",
      conversationID: "a7b7ff1b5fa0b7808850aff88e36647b",
      intakeInvite:
        "p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUKe3_xtfoLeAiFCv-I42ZHtraW52aXRlX3NhbHRYIHKWWA3tK0V16vtWLXdaEvBpjAiXYziyM7lC8pEKFDGmbWludml0ZV9zZWNyZXRYIHHihDnL0ajBeGeqeOYZecggn2Z8nfd_bX9MDQIQFXEcbWludml0ZXJfaWtfcGtYIN5_8a9oo-jMwtjut4BmrTIrytXc8OaY_D7XjBuXlGuz",
      relayURL: "https://inbox.qntm.corpo.llc"),
  ]
}

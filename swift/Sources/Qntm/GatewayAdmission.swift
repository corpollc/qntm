import Foundation

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

public struct GatewayInvitation: Sendable {
  public let invitationID: String
  public let inviterPublicKey: Data
  public let gatewayPublicKey: Data
  public let expiresAt: UInt64
  public var gatewayKeyID: String { QSPCrypto.hash(gatewayPublicKey).prefix(16).base64URL }
  public init(
    invitationID: String, inviterPublicKey: Data, gatewayPublicKey: Data, expiresAt: UInt64
  ) throws {
    _ = try gateHex(.string(invitationID), "invitation ID", count: 16)
    try gateRequire(
      QSPCrypto.isValidPublicKey(inviterPublicKey) && QSPCrypto.isValidPublicKey(gatewayPublicKey)
        && expiresAt > 0, "Invalid invitation")
    self.invitationID = invitationID
    self.inviterPublicKey = inviterPublicKey
    self.gatewayPublicKey = gatewayPublicKey
    self.expiresAt = expiresAt
  }
}
extension Gateway {
  public static func access(_ conversation: Conversation) -> GatewayJSON {
    .object([
      ("conv_id", .string(conversation.id.hex)),
      ("conv_aead_key", .string(conversation.keys.aeadKey.base64URL)),
      ("conv_nonce_key", .string(conversation.keys.nonceKey.base64URL)),
      ("conv_epoch", .uint(UInt64(conversation.currentEpoch))),
    ])
  }
  public static func accessHash(_ conversation: Conversation) throws -> String {
    QSPCrypto.hash(try access(conversation).cbor().encode()).hex
  }
  public static func createInvitationBody(
    invitation: GatewayInvitation, conversation: Conversation, participants: [String: Data],
    floor: UInt64, groupCreatorKeyID: Data? = nil
  ) throws -> GatewayBody {
    try gateRequire(
      conversation.type == .direct || conversation.type == .group,
      "Gateway requires direct or group conversation")
    let context = try GatewayContext(
      conversationID: conversation.id.hex, epoch: conversation.currentEpoch,
      gatewayPublicKey: invitation.gatewayPublicKey, participants: participants, floor: floor,
      rules: [ThresholdRule(m: floor)])
    try gateRequire(
      participants[QSPCrypto.hash(invitation.inviterPublicKey).prefix(16).base64URL]
        == invitation.inviterPublicKey && floor <= participants.count, "Invalid inviter or floor")
    var json = GatewayJSON.object([
      ("type", .string("gate.promote")), ("invitation_id", .string(invitation.invitationID)),
      ("conv_id", .string(context.conversationID)),
      ("conversation_type", .string(conversation.type.rawValue)),
      ("conv_epoch", .uint(UInt64(context.epoch))), ("gateway_kid", .string(context.gatewayKeyID)),
      ("gateway_public_key", .string(invitation.gatewayPublicKey.base64URL)),
      ("expires_at", .uint(invitation.expiresAt)),
      ("keys_hash", .string(try accessHash(conversation))),
      (
        "participants",
        .object(
          participants.sorted { $0.key < $1.key }.map {
            GatewayJSON.Field($0.key, .string($0.value.base64URL))
          })
      ), ("rules", .array(context.rules.map(\.json))), ("floor", .uint(floor)),
    ])
    if conversation.type == .group {
      guard let creator = groupCreatorKeyID ?? conversation.participants.first,
        participants[creator.base64URL] != nil
      else { throw QntmError.invalid("Missing group creator") }
      json = json.setting("group_creator_kid", .string(creator.base64URL))
    }
    return try GatewayBody(type: "gate.promote", json: json)
  }
  public static func sealBootstrap(
    identity: Identity, invitation: GatewayInvitation, conversation: Conversation,
    invitationMessageID: Data, sequence: UInt64
  ) throws -> GatewayJSON {
    try gateRequire(
      identity.publicKey == invitation.inviterPublicKey && invitationMessageID.count == 16,
      "Bootstrap inviter mismatch")
    let material = access(conversation).setting(
      "invitation_msg_id", .string(invitationMessageID.hex)
    ).setting("invitation_seq", .uint(sequence))
    let sealed = try QSPCrypto.sealSecret(
      senderPrivateKey: identity.privateKey, recipientPublicKey: invitation.gatewayPublicKey,
      plaintext: material.encoded())
    return .object([
      ("invitation_id", .string(invitation.invitationID)),
      ("inviter_public_key", .string(identity.publicKey.base64URL)),
      ("sealed", .string(sealed.base64URL)),
    ])
  }
  public static func matchesAcceptance(
    _ body: GatewayBody, senderKeyID: String, invitation: Message
  ) throws -> Bool {
    let invite = try GatewayBody(type: invitation.bodyType, data: invitation.body)
    return try matchesAcceptance(
      body, senderKeyID: senderKeyID, invitationBody: invite,
      invitationMessageID: invitation.envelope.messageID.hex, invitationData: invitation.body)
  }
  static func matchesAcceptance(
    _ body: GatewayBody, senderKeyID: String, invitationBody: GatewayBody,
    invitationMessageID: String, invitationData: Data
  ) throws -> Bool {
    guard
      invitationBody.type == .promote && body.type == .accept
        && senderKeyID == invitationBody["gateway_kid"]?.string
    else { return false }
    for field in ["gateway_kid", "gateway_public_key", "invitation_id", "conv_id", "conv_epoch"] {
      if body[field] != invitationBody[field] { return false }
    }
    return body["invitation_msg_id"]?.string == invitationMessageID
      && body["invitation_hash"]?.string == QSPCrypto.hash(invitationData).hex
  }
}

private final class GatewayNoRedirect: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
  func urlSession(
    _ session: URLSession, task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
    completionHandler: @escaping @Sendable (URLRequest?) -> Void
  ) { completionHandler(nil) }
}
/// HTTP admission client. HTTP success never activates a gateway; verify gate.accept in chat.
public struct GateClient: Sendable {
  public let baseURL: URL
  public let timeout: TimeInterval
  public init(baseURL: URL, timeout: TimeInterval = 30) throws {
    _ = try Gateway.validateTargetURL(baseURL.absoluteString)
    try gateRequire(timeout > 0 && timeout <= 300, "Gateway timeout must be 0...300 seconds")
    self.baseURL = baseURL
    self.timeout = timeout
  }
  public func request(path: String, body: GatewayJSON? = nil) async throws -> GatewayJSON {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = timeout
    configuration.timeoutIntervalForResource = timeout
    let session = URLSession(
      configuration: configuration, delegate: GatewayNoRedirect(), delegateQueue: nil)
    defer { session.invalidateAndCancel() }
    var request = URLRequest(url: baseURL.appendingPathComponent(path))
    request.timeoutInterval = timeout
    if let body {
      request.httpMethod = "POST"
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")
      request.httpBody = try body.encoded()
    }
    #if canImport(Darwin)
      let (bytes, response) = try await session.bytes(for: request)
      var data = Data()
      for try await byte in bytes {
        try gateRequire(data.count < 65_536, "Gateway response exceeds 64 KiB")
        data.append(byte)
      }
    #else
      let (data, response) = try await session.data(for: request)
      try gateRequire(data.count <= 65_536, "Gateway response exceeds 64 KiB")
    #endif
    guard let response = response as? HTTPURLResponse, (200..<300).contains(response.statusCode)
    else { throw QntmError.transport("Gateway HTTP request failed") }
    return try GatewayJSON(data: data)
  }
  public func createInvitation(identity: Identity, invitationID: String = QSPCrypto.random(16).hex)
    async throws -> GatewayInvitation
  {
    let reply = try await request(
      path: "v1/invitations",
      body: .object([
        ("inviter_public_key", .string(identity.publicKey.base64URL)),
        ("invitation_id", .string(invitationID)),
      ]))
    let invitation = try GatewayInvitation(
      invitationID: gateText(reply["invitation_id"], "invitation ID"),
      inviterPublicKey: gateBytes(reply["inviter_public_key"], "inviter", count: 32),
      gatewayPublicKey: gateBytes(reply["gateway_public_key"], "gateway", count: 32),
      expiresAt: gateUInt(reply["expires_at"], "expiry", min: 1))
    try gateRequire(
      invitation.invitationID == invitationID && invitation.inviterPublicKey == identity.publicKey
        && reply["gateway_kid"]?.string == invitation.gatewayKeyID,
      "Gateway invitation response mismatch")
    return invitation
  }
  public func promote(_ bootstrap: GatewayJSON) async throws -> GatewayJSON {
    try await request(path: "v1/promote", body: bootstrap)
  }
  public func health() async throws -> GatewayJSON { try await request(path: "health") }
}

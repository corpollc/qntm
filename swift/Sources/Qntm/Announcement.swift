import Foundation

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

/// Keep this ownership material private and persist it before registering the channel.
public struct AnnouncementChannel: Sendable {
  public let name: String
  public let master: Identity
  public let posting: Identity
  public let inviteSecret: Data
  public let conversation: Conversation

  public init(
    name: String, master: Identity? = nil, posting: Identity? = nil, inviteSecret: Data? = nil
  ) throws {
    guard !name.isEmpty, name.utf16.count <= 64 else {
      throw QntmError.invalid("Channel name must contain 1–64 UTF-16 code units")
    }
    let master = try master ?? Identity()
    let posting = try posting ?? Identity()
    let secret = inviteSecret ?? QSPCrypto.random(32)
    self.name = name
    self.master = master
    self.posting = posting
    self.inviteSecret = secret
    conversation = try Announcement.conversation(
      id: Announcement.channelID(masterPublicKey: master.publicKey), inviteSecret: secret,
      name: name)
  }

  public init(serialized: Data) throws {
    guard let map = try CBOR.decode(serialized).mapValue else {
      throw QntmError.invalid("Invalid announcement owner record")
    }
    try self.init(
      name: map.requireString("name"), master: Identity(serialized: map.requireBytes("master")),
      posting: Identity(serialized: map.requireBytes("posting")),
      inviteSecret: map.requireBytes("invite_secret", count: 32))
  }

  public func serialize() throws -> Data {
    try CBOR.map([
      "name": .text(name), "master": .bytes(master.serialize()),
      "posting": .bytes(posting.serialize()), "invite_secret": .bytes(inviteSecret),
    ]).encode()
  }
}

public enum Announcement {
  public static func channelID(masterPublicKey: Data) throws -> Data {
    guard QSPCrypto.isValidPublicKey(masterPublicKey) else {
      throw QntmError.invalid("Invalid channel master public key")
    }
    return QSPCrypto.hash(Data("qntm-announce-v1|id|\(masterPublicKey.base64URL)".utf8)).prefix(16)
  }

  public static func conversation(id: Data, inviteSecret: Data, name: String? = nil) throws
    -> Conversation
  {
    guard id.count == 16, inviteSecret.count == 32 else {
      throw QntmError.invalid("Invalid announcement invitation")
    }
    let prk = QSPCrypto.hkdfExtract(salt: id, input: inviteSecret)
    let root = try QSPCrypto.hkdfExpand(key: prk, info: Data("qntm/qsp/v1/root".utf8) + id)
    return try Conversation(
      id: id, type: .announce, keys: ConversationKeys(root: root, conversationID: id), name: name)
  }

  public static func signRegistration(channel: AnnouncementChannel) throws -> String {
    try sign(
      privateKey: channel.master.privateKey,
      content:
        "qntm-announce-v1|register|\(channel.name)|\(channel.conversation.id.hex)|\(channel.posting.publicKey.base64URL)"
    )
  }
  public static func verifyRegistration(
    masterPublicKey: Data, name: String, conversationID: Data, postingPublicKey: Data,
    signature: Data
  ) -> Bool {
    guard (try? channelID(masterPublicKey: masterPublicKey)) == conversationID,
      QSPCrypto.isValidPublicKey(postingPublicKey)
    else { return false }
    return QSPCrypto.verify(
      publicKey: masterPublicKey,
      message: QSPCrypto.hash(
        Data(
          "qntm-announce-v1|register|\(name)|\(conversationID.hex)|\(postingPublicKey.base64URL)"
            .utf8)), signature: signature)
  }
  public static func signDeletion(master: Identity, conversationID: Data) throws -> String {
    guard try channelID(masterPublicKey: master.publicKey) == conversationID else {
      throw QntmError.invalid("Channel is not owned by this master")
    }
    return try sign(
      privateKey: master.privateKey, content: "qntm-announce-v1|delete|\(conversationID.hex)")
  }
  /// The current relay rotation format has no signed generation; callers must avoid replaying old rotations.
  public static func signRotation(master: Identity, conversationID: Data, newPostingPublicKey: Data)
    throws -> String
  {
    guard try channelID(masterPublicKey: master.publicKey) == conversationID,
      QSPCrypto.isValidPublicKey(newPostingPublicKey)
    else { throw QntmError.invalid("Invalid channel rotation") }
    return try sign(
      privateKey: master.privateKey,
      content: "qntm-announce-v1|rotate|\(conversationID.hex)|\(newPostingPublicKey.base64URL)")
  }
  public static func signEnvelope(posting: Identity, envelope: Data) throws -> String {
    try sign(privateKey: posting.privateKey, content: envelope.base64EncodedString())
  }
  public static func verifyEnvelope(postingPublicKey: Data, envelope: Data, signature: Data) -> Bool
  {
    QSPCrypto.verify(
      publicKey: postingPublicKey,
      message: QSPCrypto.hash(Data(envelope.base64EncodedString().utf8)), signature: signature)
  }
  private static func sign(privateKey: Data, content: String) throws -> String {
    try QSPCrypto.sign(privateKey: privateKey, message: QSPCrypto.hash(Data(content.utf8))).hex
  }
}

public struct AnnouncementInfo: Decodable, Sendable {
  public let name: String
  public let conversationID: String
  public let postingPublicKey: String
  enum CodingKeys: String, CodingKey {
    case name
    case conversationID = "conv_id"
    case postingPublicKey = "posting_pk"
  }
}

public struct AnnouncementClient: Sendable {
  public let relay: DropboxClient
  private let session: URLSession
  public init(baseURL: URL = DropboxClient.defaultURL, session: URLSession = .shared) throws {
    relay = try DropboxClient(baseURL: baseURL, session: session)
    self.session = session
  }
  public func register(_ channel: AnnouncementChannel) async throws {
    _ = try await request(
      action: "register",
      fields: [
        "name": channel.name, "conv_id": channel.conversation.id.hex,
        "master_pk": channel.master.publicKey.base64URL,
        "posting_pk": channel.posting.publicKey.base64URL,
        "sig": Announcement.signRegistration(channel: channel),
      ])
  }
  public func rotate(conversationID: Data, master: Identity, newPosting: Identity) async throws {
    _ = try await request(
      action: "rotate",
      fields: [
        "conv_id": conversationID.hex, "master_pk": master.publicKey.base64URL,
        "new_posting_pk": newPosting.publicKey.base64URL,
        "sig": Announcement.signRotation(
          master: master, conversationID: conversationID, newPostingPublicKey: newPosting.publicKey),
      ])
  }
  public func delete(conversationID: Data, master: Identity) async throws {
    _ = try await request(
      action: "delete",
      fields: [
        "conv_id": conversationID.hex, "master_pk": master.publicKey.base64URL,
        "sig": Announcement.signDeletion(master: master, conversationID: conversationID),
      ])
  }
  public func info(conversationID: Data) async throws -> AnnouncementInfo {
    guard conversationID.count == 16 else {
      throw QntmError.invalid("Invalid announcement channel ID")
    }
    let data = try await request(
      action: "info", fields: ["conv_id": conversationID.hex], method: "GET")
    let info = try JSONDecoder().decode(AnnouncementInfo.self, from: data)
    guard info.conversationID == conversationID.hex,
      QSPCrypto.isValidPublicKey(try Data.fromBase64URL(info.postingPublicKey))
    else { throw QntmError.transport("Invalid announcement channel information") }
    return info
  }
  public func post(envelope: Data, channel: AnnouncementChannel) async throws -> UInt64 {
    try await relay.postMessage(
      conversationID: channel.conversation.id, envelope: envelope,
      announcementSignature: Announcement.signEnvelope(posting: channel.posting, envelope: envelope)
    )
  }
  private func request(action: String, fields: [String: String], method: String = "POST")
    async throws -> Data
  {
    guard var components = URLComponents(url: relay.baseURL, resolvingAgainstBaseURL: false) else {
      throw QntmError.invalid("Invalid relay URL")
    }
    components.path = "/v1/announce/" + action
    components.query = nil
    components.fragment = nil
    if method == "GET" {
      components.queryItems = fields.map { URLQueryItem(name: $0.key, value: $0.value) }
    }
    guard let url = components.url else { throw QntmError.invalid("Invalid relay URL") }
    var request = URLRequest(url: url, timeoutInterval: 30)
    request.httpMethod = method
    if method == "POST" {
      request.httpBody = try JSONEncoder().encode(fields)
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    }
    let (data, response) = try await session.data(for: request)
    guard let response = response as? HTTPURLResponse, (200..<300).contains(response.statusCode),
      data.count <= 96 * 1024
    else {
      throw QntmError.transport("Announcement request failed")
    }
    return data
  }
}

import Foundation

public struct Identity: Sendable, Equatable {
  public let privateKey: Data
  public let publicKey: Data
  public let keyID: Data
  public init(seed: Data? = nil) throws {
    let pair = try QSPCrypto.identity(seed: seed ?? QSPCrypto.random(32))
    privateKey = pair.privateKey
    publicKey = pair.publicKey
    keyID = QSPCrypto.hash(publicKey).prefix(16)
  }
  public init(serialized: Data) throws {
    guard let m = try CBOR.decode(serialized).mapValue else {
      throw QntmError.invalid("Invalid identity")
    }
    let sk = try m.requireBytes("private_key", count: 64)
    try self.init(seed: sk.prefix(32))
    guard privateKey == sk, publicKey == (try m.requireBytes("public_key", count: 32)),
      keyID == (try m.requireBytes("key_id", count: 16))
    else { throw QntmError.invalid("Identity key mismatch") }
  }
  public func serialize() throws -> Data {
    try CBOR.map([
      "private_key": .bytes(privateKey), "public_key": .bytes(publicKey), "key_id": .bytes(keyID),
    ]).encode()
  }
}

public enum ConversationType: String, Codable, Sendable { case direct, group, announce }

public struct ConversationKeys: Codable, Sendable, Equatable {
  public let root: Data
  public let aeadKey: Data
  public let nonceKey: Data
  public init(root: Data, conversationID: Data, epoch: UInt32 = 0) throws {
    guard root.count == 32, conversationID.count == 16 else {
      throw QntmError.invalid("Invalid conversation key material")
    }
    self.root = root
    let prefix = epoch == 0 ? "qntm/qsp/v1/" : "qntm/qsp/v1.1/"
    let suffix =
      conversationID
      + (epoch == 0
        ? Data() : Data((0..<4).reversed().map { UInt8(truncatingIfNeeded: epoch >> ($0 * 8)) }))
    aeadKey = try QSPCrypto.hkdfExpand(key: root, info: Data((prefix + "aead").utf8) + suffix)
    nonceKey = try QSPCrypto.hkdfExpand(key: root, info: Data((prefix + "nonce").utf8) + suffix)
  }
}

public struct Conversation: Codable, Sendable, Equatable {
  public var id: Data
  public var type: ConversationType
  public var keys: ConversationKeys
  public var participants: [Data]
  public var currentEpoch: UInt32
  public var name: String?
  public var inviteToken: String?
  public init(
    id: Data, type: ConversationType, keys: ConversationKeys, participants: [Data] = [],
    currentEpoch: UInt32 = 0, name: String? = nil, inviteToken: String? = nil
  ) throws {
    guard id.count == 16, participants.allSatisfy({ $0.count == 16 }) else {
      throw QntmError.invalid("Invalid conversation")
    }
    self.id = id
    self.type = type
    self.keys = keys
    self.participants = participants
    self.currentEpoch = currentEpoch
    self.name = name
    self.inviteToken = inviteToken
  }
  public func validate() throws {
    guard id.count == 16, participants.allSatisfy({ $0.count == 16 }),
      keys == (try ConversationKeys(root: keys.root, conversationID: id, epoch: currentEpoch))
    else { throw QntmError.invalid("Invalid conversation state") }
  }
}

public struct Invite: Sendable {
  public let conversationID: Data
  public let inviterPublicKey: Data
  public let salt: Data
  public let secret: Data
  public let type: ConversationType
  public init(creator: Identity, type: ConversationType = .direct) throws {
    guard type != .announce else {
      throw QntmError.invalid("Announcement channels use a separate invitation")
    }
    conversationID = QSPCrypto.random(16)
    inviterPublicKey = creator.publicKey
    salt = QSPCrypto.random(32)
    secret = QSPCrypto.random(32)
    self.type = type
  }
  public init(tokenOrURL: String) throws {
    let token: String
    if let url = URLComponents(string: tokenOrURL), url.scheme != nil {
      guard let fragment = url.fragment, !fragment.isEmpty else {
        throw QntmError.invalid("Invite URL needs a fragment")
      }
      token = fragment
    } else {
      token = tokenOrURL
    }
    try self.init(serialized: Data.fromBase64URL(token))
  }
  public init(serialized: Data) throws {
    guard let m = try CBOR.decode(serialized).mapValue, try m.requireUInt("v") == 1,
      try m.requireString("suite") == "QSP-1",
      let type = ConversationType(rawValue: try m.requireString("type")), type != .announce
    else { throw QntmError.invalid("Unsupported invite") }
    conversationID = try m.requireBytes("conv_id", count: 16)
    inviterPublicKey = try m.requireBytes("inviter_ik_pk", count: 32)
    salt = try m.requireBytes("invite_salt")
    secret = try m.requireBytes("invite_secret", count: 32)
    guard (16...32).contains(salt.count), QSPCrypto.isValidPublicKey(inviterPublicKey) else {
      throw QntmError.invalid("Invalid invite key/salt")
    }
    self.type = type
  }
  public func serialize() throws -> Data {
    try CBOR.map([
      "v": .unsigned(1), "suite": .text("QSP-1"), "type": .text(type.rawValue),
      "conv_id": .bytes(conversationID), "inviter_ik_pk": .bytes(inviterPublicKey),
      "invite_salt": .bytes(salt), "invite_secret": .bytes(secret),
    ]).encode()
  }
  public func token() throws -> String { try serialize().base64URL }
  public func url(base: URL) throws -> URL {
    guard var parts = URLComponents(url: base, resolvingAgainstBaseURL: false), parts.scheme != nil
    else { throw QntmError.invalid("Invalid invite base URL") }
    parts.query = nil
    parts.fragment = try token()
    guard let result = parts.url else { throw QntmError.invalid("Invalid invite URL") }
    return result
  }
  public func conversation() throws -> Conversation {
    let root = try QSPCrypto.hkdfExpand(
      key: QSPCrypto.hkdfExtract(salt: salt, input: secret),
      info: Data("qntm/qsp/v1/root".utf8) + conversationID)
    return try Conversation(
      id: conversationID, type: type,
      keys: ConversationKeys(root: root, conversationID: conversationID),
      participants: [QSPCrypto.hash(inviterPublicKey).prefix(16)], inviteToken: token())
  }
}

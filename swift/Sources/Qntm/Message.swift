import Foundation

public struct Envelope: Sendable, Equatable {
  public let conversationID: Data
  public let messageID: Data
  public let createdAt: UInt64
  public let expiresAt: UInt64
  public let epoch: UInt32
  public let ciphertext: Data
  public let aadHash: Data?
  /// Unsigned discovery hint. It never establishes identity or entity authority.
  public let untrustedDID: String?
  let untrustedCharterMetadataIgnored: Bool
  public init(serialized: Data, now: UInt64 = unixSeconds()) throws {
    guard let m = try CBOR.decode(serialized).mapValue, try m.requireUInt("v") == 1,
      try m.requireString("suite") == "QSP-1"
    else { throw QntmError.invalid("Unsupported envelope") }
    conversationID = try m.requireBytes("conv_id", count: 16)
    messageID = try m.requireBytes("msg_id", count: 16)
    createdAt = try m.requireUInt("created_ts")
    expiresAt = try m.requireUInt("expiry_ts")
    guard let epoch = UInt32(exactly: try m.requireUInt("conv_epoch")) else {
      throw QntmError.invalid("Invalid epoch")
    }
    self.epoch = epoch
    ciphertext = try m.requireBytes("ciphertext")
    aadHash = m["aad_hash"] == nil ? nil : try m.requireBytes("aad_hash", count: 32)
    if let hint = m["did"], hint != .null {
      guard let text = hint.stringValue else { throw QntmError.invalid("DID hint must be text") }
      untrustedDID = text
    } else {
      untrustedDID = nil
    }
    untrustedCharterMetadataIgnored = m["charter_info"] != nil
    try validate(now: now)
  }
  init(
    conversationID: Data, messageID: Data, createdAt: UInt64, expiresAt: UInt64, epoch: UInt32,
    ciphertext: Data, aadHash: Data?, untrustedDID: String? = nil
  ) {
    self.conversationID = conversationID
    self.messageID = messageID
    self.createdAt = createdAt
    self.expiresAt = expiresAt
    self.epoch = epoch
    self.ciphertext = ciphertext
    self.aadHash = aadHash
    self.untrustedDID = untrustedDID
    self.untrustedCharterMetadataIgnored = false
  }
  var aad: [String: CBOR] {
    [
      "v": .unsigned(1), "suite": .text("QSP-1"), "conv_id": .bytes(conversationID),
      "msg_id": .bytes(messageID), "created_ts": .unsigned(createdAt),
      "expiry_ts": .unsigned(expiresAt), "conv_epoch": .unsigned(UInt64(epoch)),
    ]
  }
  public func serialize() throws -> Data {
    var m = aad
    m["ciphertext"] = .bytes(ciphertext)
    if let aadHash { m["aad_hash"] = .bytes(aadHash) }
    if let untrustedDID { m["did"] = .text(untrustedDID) }
    return try CBOR.map(m).encode()
  }
  public func validate(now: UInt64 = unixSeconds()) throws {
    guard conversationID.count == 16, messageID.count == 16, createdAt > 0,
      createdAt <= 9_007_199_254_740_991, expiresAt <= 9_007_199_254_740_991,
      expiresAt > createdAt, createdAt <= now || createdAt - now <= 600,
      (16...65536).contains(ciphertext.count), aadHash == nil || aadHash?.count == 32
    else { throw QntmError.invalid("Invalid message envelope") }
  }
}

/// A signature-verified message. Constructed exclusively by Messaging.decrypt.
public struct Message: Sendable, Equatable {
  public let envelope: Envelope
  public let senderPublicKey: Data
  public let senderKeyID: Data
  public let bodyType: String
  public let body: Data
  public let refs: [CBOR]
  public let signature: Data
  public let untrustedCharterMetadataIgnored: Bool
  public var text: String? {
    String(data: body, encoding: .utf8) == nil ? nil : String(decoding: body, as: UTF8.self)
  }
}

public enum Messaging {
  public static func verifySignature(_ message: Message) -> Bool {
    guard message.senderKeyID == QSPCrypto.hash(message.senderPublicKey).prefix(16),
      let signable = try? signable(
        envelope: message.envelope, senderKeyID: message.senderKeyID, bodyType: message.bodyType,
        body: message.body, refs: message.refs)
    else { return false }
    return QSPCrypto.verify(
      publicKey: message.senderPublicKey, message: signable, signature: message.signature)
  }
  public static func create(
    identity: Identity, conversation: Conversation, bodyType: String, body: Data, refs: [CBOR] = [],
    ttl: UInt64 = 2_592_000, now: UInt64 = unixSeconds(), untrustedDID: String? = nil
  ) throws -> Envelope {
    try conversation.validate()
    guard !bodyType.isEmpty, ttl > 0, now > 0, now <= 9_007_199_254_740_991,
      ttl <= 9_007_199_254_740_991 - now
    else { throw QntmError.invalid("Invalid message type/TTL") }
    var body = body
    if conversation.type == .group,
      ["group_genesis", "group_add", "group_remove", "group_rekey"].contains(bodyType)
    {
      guard var control = try CBOR.decode(body).mapValue else {
        throw QntmError.invalid("Invalid group control body")
      }
      control["group_epoch"] = .unsigned(UInt64(conversation.currentEpoch))
      body = try CBOR.map(control).encode()
    }
    let messageID = QSPCrypto.random(16)
    let skeleton = Envelope(
      conversationID: conversation.id, messageID: messageID, createdAt: now, expiresAt: now + ttl,
      epoch: conversation.currentEpoch, ciphertext: Data(), aadHash: nil)
    let signature = try QSPCrypto.sign(
      privateKey: identity.privateKey,
      message: signable(
        envelope: skeleton, senderKeyID: identity.keyID, bodyType: bodyType, body: body, refs: refs)
    )
    var inner: [String: CBOR] = [
      "sender_ik_pk": .bytes(identity.publicKey), "sender_kid": .bytes(identity.keyID),
      "body_type": .text(bodyType), "body": .bytes(body), "sig_alg": .text("Ed25519"),
      "signature": .bytes(signature),
    ]
    if !refs.isEmpty { inner["refs"] = .array(refs) }
    let aad = try CBOR.map(skeleton.aad).encode()
    let ciphertext = try QSPCrypto.encrypt(
      key: conversation.keys.aeadKey,
      nonce: QSPCrypto.hmac(key: conversation.keys.nonceKey, data: messageID).prefix(24),
      plaintext: CBOR.map(inner).encode(), aad: aad)
    let envelope = Envelope(
      conversationID: conversation.id, messageID: messageID, createdAt: now, expiresAt: now + ttl,
      epoch: conversation.currentEpoch, ciphertext: ciphertext, aadHash: QSPCrypto.hash(aad),
      untrustedDID: untrustedDID)
    try envelope.validate(now: now)
    return envelope
  }
  public static func decrypt(
    _ envelope: Envelope, conversation: Conversation, allowExpired: Bool = false,
    now: UInt64 = unixSeconds()
  ) throws -> Message {
    try conversation.validate()
    try envelope.validate(now: now)
    guard allowExpired || now <= envelope.expiresAt else {
      throw QntmError.invalid("Message expired")
    }
    guard envelope.conversationID == conversation.id, envelope.epoch == conversation.currentEpoch
    else { throw QntmError.invalid("Conversation or epoch mismatch") }
    let aad = try CBOR.map(envelope.aad).encode()
    guard envelope.aadHash == nil || envelope.aadHash == QSPCrypto.hash(aad) else {
      throw QntmError.invalid("AAD hash mismatch")
    }
    let plaintext = try QSPCrypto.decrypt(
      key: conversation.keys.aeadKey,
      nonce: QSPCrypto.hmac(key: conversation.keys.nonceKey, data: envelope.messageID).prefix(24),
      ciphertext: envelope.ciphertext, aad: aad)
    guard let inner = try CBOR.decode(plaintext).mapValue else {
      throw QntmError.invalid("Invalid inner message")
    }
    let pk = try inner.requireBytes("sender_ik_pk", count: 32)
    let kid = try inner.requireBytes("sender_kid", count: 16)
    let signature = try inner.requireBytes("signature", count: 64)
    let type = try inner.requireString("body_type")
    let body = try inner.requireBytes("body")
    guard try inner.requireString("sig_alg") == "Ed25519", !type.isEmpty,
      kid == QSPCrypto.hash(pk).prefix(16)
    else { throw QntmError.invalid("Invalid inner identity or type") }
    if inner["msg_id"] != nil { _ = try inner.requireBytes("msg_id", count: 16) }
    let refs: [CBOR]
    if let field = inner["refs"] {
      guard let values = field.arrayValue else { throw QntmError.invalid("Invalid message refs") }
      refs = values
    } else {
      refs = []
    }
    guard
      QSPCrypto.verify(
        publicKey: pk,
        message: try signable(
          envelope: envelope, senderKeyID: kid, bodyType: type, body: body, refs: refs),
        signature: signature)
    else { throw QntmError.crypto("Invalid message signature") }
    return Message(
      envelope: envelope, senderPublicKey: pk, senderKeyID: kid, bodyType: type, body: body,
      refs: refs, signature: signature,
      untrustedCharterMetadataIgnored: envelope.untrustedCharterMetadataIgnored
        || inner["charter_info"] != nil)
  }
  private static func signable(
    envelope: Envelope, senderKeyID: Data, bodyType: String, body: Data, refs: [CBOR]
  ) throws -> Data {
    var content: [String: CBOR] = ["body_type": .text(bodyType), "body": .bytes(body)]
    if !refs.isEmpty { content["refs"] = .array(refs) }
    return try CBOR.map([
      "proto": .text("qntm/qsp/v1"), "suite": .text("QSP-1"),
      "conv_id": .bytes(envelope.conversationID), "msg_id": .bytes(envelope.messageID),
      "created_ts": .unsigned(envelope.createdAt), "expiry_ts": .unsigned(envelope.expiresAt),
      "sender_kid": .bytes(senderKeyID),
      "body_hash": .bytes(QSPCrypto.hash(CBOR.map(content).encode())),
    ]).encode()
  }
}

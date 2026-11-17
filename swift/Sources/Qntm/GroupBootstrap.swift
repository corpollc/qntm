import Foundation

public struct CurrentEpochBootstrap: Sendable {
  public let conversation: Conversation
  public let state: GroupState
  public let creatorPublicKey: Data
  public let rekeyID: Data
  public let issuedAt: UInt64
  public let expiresAt: UInt64
}

public enum GroupBootstrap {
  public static let maximumAge: UInt64 = 30 * 86_400
  private static let type = "qntm.group.join"

  public static func isCurrentEpochInvite(_ token: String) -> Bool { (try? parse(token)) != nil }

  public static func inspect(_ token: String) throws -> (
    creatorPublicKey: Data, recipientPublicKey: Data
  ) {
    let value = try parse(token)
    try verify(value)
    return (try value.requireBytes("creator_ik_pk"), try value.requireBytes("recipient_ik_pk"))
  }

  public static func create(
    identity: Identity, conversation: Conversation, state: GroupState,
    recipientPublicKey: Data, rekeyID: Data, issuedAt: UInt64 = unixSeconds(),
    ttl: UInt64 = maximumAge
  ) throws -> String {
    guard conversation.type == .group, state.creatorKeyID == identity.keyID,
      state.isAdmin(identity.keyID)
    else {
      throw QntmError.invalid(
        "Only the existing group creator may issue a current-epoch invitation")
    }
    guard conversation.currentEpoch > 0, rekeyID.count == 16, conversation.id.count == 16,
      conversation.keys.root.count == 32, QSPCrypto.isValidPublicKey(recipientPublicKey),
      (1...maximumAge).contains(ttl), issuedAt <= 9_007_199_254_740_991 - ttl
    else {
      throw QntmError.invalid("Invalid current-epoch invitation")
    }
    try validateSnapshot(state, creator: identity.publicKey, recipient: recipientPublicKey)
    let plaintext = try CBOR.map([
      "v": .unsigned(1), "conv_id": .bytes(conversation.id),
      "conv_epoch": .unsigned(UInt64(conversation.currentEpoch)),
      "group_key": .bytes(conversation.keys.root),
      "rekey_id": .bytes(rekeyID), "group_state": state.snapshotValue,
      "issued_at": .unsigned(issuedAt), "expires_at": .unsigned(issuedAt + ttl),
    ]).encode()
    guard plaintext.count <= 49_152 else { throw QntmError.invalid("Group invitation too large") }
    var value: [String: CBOR] = [
      "v": .unsigned(1), "type": .text(type), "creator_ik_pk": .bytes(identity.publicKey),
      "recipient_ik_pk": .bytes(recipientPublicKey),
      "sealed": .bytes(
        try QSPCrypto.sealSecret(
          senderPrivateKey: identity.privateKey, recipientPublicKey: recipientPublicKey,
          plaintext: plaintext)),
    ]
    value["signature"] = .bytes(
      try QSPCrypto.sign(privateKey: identity.privateKey, message: CBOR.map(value).encode()))
    let encoded = try CBOR.map(value).encode()
    guard encoded.count <= 65_536 else { throw QntmError.invalid("Group invitation too large") }
    return encoded.base64URL
  }

  public static func open(
    identity: Identity, token: String, conversationID: Data? = nil,
    creatorPublicKey: Data? = nil, allowExpired: Bool = false,
    now: UInt64 = unixSeconds()
  ) throws -> CurrentEpochBootstrap {
    let outer = try parse(token)
    let creator = try outer.requireBytes("creator_ik_pk", count: 32)
    guard try outer.requireBytes("recipient_ik_pk", count: 32) == identity.publicKey else {
      throw QntmError.invalid("This invitation is sealed to another participant")
    }
    guard creatorPublicKey == nil || creatorPublicKey == creator else {
      throw QntmError.invalid("Invitation creator mismatch")
    }
    try verify(outer)
    let plaintext = try QSPCrypto.openSecret(
      recipientPrivateKey: identity.privateKey, senderPublicKey: creator,
      sealed: outer.requireBytes("sealed"))
    guard plaintext.count <= 49_152, let value = try CBOR.decode(plaintext).mapValue else {
      throw QntmError.invalid("Invalid current-epoch invitation")
    }
    try groupFields(
      value,
      [
        "v", "conv_id", "conv_epoch", "group_key", "rekey_id", "group_state", "issued_at",
        "expires_at",
      ])
    let id = try value.requireBytes("conv_id", count: 16)
    let epoch = try value.requireUInt("conv_epoch")
    let root = try value.requireBytes("group_key", count: 32)
    let rekeyID = try value.requireBytes("rekey_id", count: 16)
    let issuedAt = try value.requireUInt("issued_at")
    let expiresAt = try value.requireUInt("expires_at")
    guard value["v"] == .unsigned(1), (1...UInt64(UInt32.max)).contains(epoch),
      issuedAt <= 9_007_199_254_740_991,
      expiresAt <= 9_007_199_254_740_991, issuedAt <= now.addingReportingOverflow(300).partialValue,
      expiresAt > issuedAt, expiresAt - issuedAt <= maximumAge,
      let snapshot = value["group_state"]
    else { throw QntmError.invalid("Invalid current-epoch invitation") }
    guard allowExpired || expiresAt > now else {
      throw QntmError.invalid("Current-epoch invitation expired")
    }
    guard conversationID == nil || conversationID == id else {
      throw QntmError.invalid("Invitation belongs to a different conversation")
    }
    let state = try GroupState(cbor: snapshot, canonicalOrder: true)
    try validateSnapshot(state, creator: creator, recipient: identity.publicKey)
    let conversation = try Conversation(
      id: id, type: .group,
      keys: ConversationKeys(root: root, conversationID: id, epoch: UInt32(epoch)),
      participants: state.memberIDs, currentEpoch: UInt32(epoch), name: state.groupName)
    return CurrentEpochBootstrap(
      conversation: conversation, state: state, creatorPublicKey: creator,
      rekeyID: rekeyID, issuedAt: issuedAt, expiresAt: expiresAt)
  }

  private static func validateSnapshot(_ state: GroupState, creator: Data, recipient: Data) throws {
    guard state.hasImmutableCreator, state.members[state.creatorKeyID]?.publicKey == creator,
      state.isAdmin(state.creatorKeyID),
      state.members.values.contains(where: { $0.publicKey == recipient })
    else {
      throw QntmError.invalid("Invitation recipient has not been admitted or creator mismatch")
    }
  }
  private static func parse(_ token: String) throws -> [String: CBOR] {
    let fragment: String
    if token.contains("://") {
      guard let value = URLComponents(string: token)?.fragment, !value.isEmpty else {
        throw QntmError.invalid("Missing invitation fragment")
      }
      fragment = value
    } else {
      fragment = token
    }
    guard !fragment.isEmpty, fragment.utf8.count <= 87_382 else {
      throw QntmError.invalid("Invalid group invitation size")
    }
    let raw = try Data.fromBase64URL(fragment)
    guard raw.count <= 65_536, let value = try CBOR.decode(raw).mapValue else {
      throw QntmError.invalid("Invalid group invitation")
    }
    try groupFields(
      value, ["v", "type", "creator_ik_pk", "recipient_ik_pk", "sealed", "signature"])
    guard value["v"] == .unsigned(1), value["type"] == .text(type),
      QSPCrypto.isValidPublicKey(try value.requireBytes("creator_ik_pk", count: 32)),
      QSPCrypto.isValidPublicKey(try value.requireBytes("recipient_ik_pk", count: 32)),
      try value.requireBytes("signature", count: 64).count == 64,
      try value.requireBytes("sealed").count >= 40
    else { throw QntmError.invalid("Invalid group invitation fields") }
    return value
  }
  private static func verify(_ value: [String: CBOR]) throws {
    var unsigned = value
    unsigned.removeValue(forKey: "signature")
    guard
      try QSPCrypto.verify(
        publicKey: value.requireBytes("creator_ik_pk"), message: CBOR.map(unsigned).encode(),
        signature: value.requireBytes("signature"))
    else { throw QntmError.invalid("Invalid group invitation signature") }
  }
}

public struct RekeyResolution: Sendable {
  public let envelope: Envelope
  public let conversation: Conversation?
  public var excluded: Bool { conversation == nil }
}

public struct RekeyUnwrapError: Error, Sendable {
  public let recoveryRequired = true
  public init() {}
}

public enum GroupRekey {
  /// Selects the lowest authenticated ID before unwrapping. A corrupt winner never falls back to a later candidate.
  public static func resolve(
    identity: Identity, source: Conversation, roster: GroupState, wires: [Data],
    authorizedControlSigner: Data? = nil, allowExpired: Bool = false,
    now: UInt64 = unixSeconds()
  ) throws -> RekeyResolution? {
    guard source.type == .group, source.currentEpoch < UInt32.max, wires.count <= 512,
      (1...128).contains(roster.members.count)
    else { throw QntmError.invalid("Invalid rekey source") }
    let recipients = Set(roster.memberIDs.map(\.base64URL))
    var winner: (envelope: Envelope, wrapped: [String: CBOR])?
    for wire in wires {
      do {
        guard !wire.isEmpty, wire.count <= 65_536 else { continue }
        let envelope = try Envelope(serialized: wire, now: now)
        guard envelope.epoch == source.currentEpoch, envelope.conversationID == source.id else {
          continue
        }
        let message = try Messaging.decrypt(
          envelope, conversation: source, allowExpired: allowExpired, now: now)
        guard message.bodyType == "group_rekey",
          roster.members[message.senderKeyID]?.publicKey == message.senderPublicKey
            || authorizedControlSigner == message.senderPublicKey,
          let body = try CBOR.decode(message.body).mapValue,
          body["new_conv_epoch"] == .unsigned(UInt64(source.currentEpoch) + 1),
          body["group_epoch"] == nil
            || body["group_epoch"] == .unsigned(UInt64(source.currentEpoch)),
          let wrapped = body["wrapped_keys"]?.mapValue, Set(wrapped.keys) == recipients,
          wrapped.values.allSatisfy({ $0.bytesValue != nil })
        else { continue }
        if winner == nil || envelope.messageID.lexicographicallyPrecedes(winner!.envelope.messageID)
        {
          winner = (envelope, wrapped)
        }
      } catch { continue }
    }
    guard let winner else { return nil }
    guard let wrapped = winner.wrapped[identity.keyID.base64URL]?.bytesValue else {
      return RekeyResolution(envelope: winner.envelope, conversation: nil)
    }
    let root: Data
    do {
      root = try QSPCrypto.unwrapKey(
        wrapped, recipientPrivateKey: identity.privateKey,
        recipientKeyID: identity.keyID, conversationID: source.id)
      guard root.count == 32 else { throw RekeyUnwrapError() }
    } catch { throw RekeyUnwrapError() }
    var next = source
    next.currentEpoch += 1
    next.keys = try ConversationKeys(
      root: root, conversationID: source.id, epoch: next.currentEpoch)
    next.participants = roster.memberIDs
    return RekeyResolution(envelope: winner.envelope, conversation: next)
  }
}

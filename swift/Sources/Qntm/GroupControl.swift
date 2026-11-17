import Foundation

public struct GroupControlState: Equatable, Codable, Sendable {
  public let creatorKeyID: Data
  public private(set) var roster: GroupState?
  public fileprivate(set) var needsRekey: Bool
  public fileprivate(set) var removed: Bool
  public fileprivate(set) var recoveryRequired: Bool
  public let requiresEpochBinding: Bool
  fileprivate var appliedIDs: Set<Data> = []
  fileprivate var rekeys: [GroupRekeyCheckpoint] = []

  public init(creatorKeyID: Data, roster: GroupState? = nil, requiresEpochBinding: Bool = false)
    throws
  {
    guard creatorKeyID.count == 16, roster == nil || roster?.creatorKeyID == creatorKeyID else {
      throw QntmError.invalid("Invalid group control creator")
    }
    self.creatorKeyID = creatorKeyID
    self.roster = roster
    self.needsRekey = false
    self.removed = false
    self.recoveryRequired = false
    self.requiresEpochBinding = requiresEpochBinding
  }

  public init(bootstrap: CurrentEpochBootstrap) throws {
    try self.init(
      creatorKeyID: bootstrap.state.creatorKeyID, roster: bootstrap.state,
      requiresEpochBinding: true)
  }

  public init(gatewayParticipants: [String: Data], anchorKeyID: Data) throws {
    try self.init(
      creatorKeyID: anchorKeyID,
      roster: GroupState(gatewayParticipants: gatewayParticipants, anchorKeyID: anchorKeyID))
  }

  public mutating func quarantine() { recoveryRequired = true }
  public mutating func markNeedsRekey() { needsRekey = true }
  fileprivate mutating func setRoster(_ value: GroupState) { roster = value }
}

private struct GroupRekeyCheckpoint: Equatable, Codable, Sendable {
  let source: Conversation
  let roster: GroupState
  let appliedIDs: Set<Data>
  let gatewayPublicKey: Data?
  var winnerID: Data
}

public struct GroupTransition: Sendable {
  public let conversation: Conversation
  public let state: GroupControlState
  public var participants: [String: String] { state.roster?.participantPublicKeys ?? [:] }
}

public enum GroupControls {
  public static let bodyTypes: Set<String> = [
    "group_genesis", "group_add", "group_remove", "group_rekey",
  ]

  /// Accepts only authenticated messages. A gateway key must come from independently verified admission and governance.
  /// Persist the returned state and conversation together; on RekeyUnwrapError, quarantine the previous state.
  public static func apply(
    message: Message, conversation: Conversation, identity: Identity, state: GroupControlState,
    gatewayPublicKey: Data? = nil, now: UInt64 = unixSeconds()
  ) throws -> GroupTransition {
    guard conversation.type == .group || (conversation.type == .direct && gatewayPublicKey != nil),
      bodyTypes.contains(message.bodyType), !state.recoveryRequired,
      message.envelope.conversationID == conversation.id, now <= message.envelope.expiresAt
    else {
      throw QntmError.invalid("Invalid or expired group control context")
    }
    // Reauthenticate against this conversation; Message values from another decryption context grant no authority.
    if message.envelope.epoch != conversation.currentEpoch {
      return try applyCompetingRekey(
        message: message, conversation: conversation, identity: identity, state: state, now: now)
    }
    let verified = try Messaging.decrypt(message.envelope, conversation: conversation, now: now)
    guard verified == message, !state.appliedIDs.contains(message.envelope.messageID) else {
      throw QntmError.invalid("Group control already applied or mismatched")
    }
    let delegated = gatewayPublicKey == message.senderPublicKey
    let sender = message.senderKeyID
    switch message.bodyType {
    case "group_genesis":
      guard gatewayPublicKey == nil, state.roster == nil, conversation.currentEpoch == 0,
        sender == state.creatorKeyID
      else {
        throw QntmError.invalid("Untrusted or repeated group genesis")
      }
    case "group_add", "group_remove":
      guard delegated || (gatewayPublicKey == nil && state.roster?.isAdmin(sender) == true) else {
        throw QntmError.invalid(
          "Only a group administrator or authorized gateway may change membership")
      }
    case "group_rekey":
      guard delegated || (gatewayPublicKey == nil && state.roster?.isMember(sender) == true) else {
        throw QntmError.invalid("Unauthorized group rekey sender")
      }
    default: throw QntmError.invalid("Unknown group control")
    }
    guard let body = try CBOR.decode(message.body).mapValue else {
      throw QntmError.invalid("Invalid group body")
    }
    let epochValue = CBOR.unsigned(UInt64(message.envelope.epoch))
    guard body["group_epoch"] == nil || body["group_epoch"] == epochValue,
      !state.requiresEpochBinding || body["group_epoch"] == epochValue
    else {
      throw QntmError.invalid("Group control is not signed for this epoch")
    }
    var next = state
    var nextConversation = conversation
    if message.bodyType == "group_genesis" {
      guard let values = body["founding_members"]?.arrayValue else {
        throw QntmError.invalid("Missing founding members")
      }
      let members = try checkedMembers(values, sender: sender)
      guard members.first?.keyID == state.creatorKeyID, members.first?.role == .admin else {
        throw QntmError.invalid("Genesis does not match creator")
      }
      next.setRoster(
        try GroupState(
          groupName: body.requireString("group_name"),
          description: body.requireString("description"),
          createdAt: body.requireUInt("created_at"), foundingMembers: members))
    } else {
      guard var roster = state.roster else {
        throw QntmError.invalid("Authenticated roster required")
      }
      switch message.bodyType {
      case "group_add":
        guard let values = body["new_members"]?.arrayValue else {
          throw QntmError.invalid("Missing added members")
        }
        let members = try checkedMembers(values, sender: sender)
        guard
          !delegated
            || members.allSatisfy({ $0.role == .member && $0.publicKey != gatewayPublicKey })
        else {
          throw QntmError.invalid("Gateway cannot appoint administrators or itself")
        }
        try roster.add(members)
        next.needsRekey = true
      case "group_remove":
        guard let values = body["removed_members"]?.arrayValue else {
          throw QntmError.invalid("Missing removed members")
        }
        let removed = try values.map { value -> Data in
          guard let bytes = value.bytesValue, bytes.count == 16 else {
            throw QntmError.invalid("Invalid removed key")
          }
          return bytes
        }
        try roster.remove(removed)
        next.needsRekey = true
        next.removed = state.removed || removed.contains(identity.keyID)
      case "group_rekey":
        var rekeySource = conversation
        rekeySource.type = .group
        guard
          let result = try GroupRekey.resolve(
            identity: identity, source: rekeySource, roster: roster,
            wires: [message.envelope.serialize()], authorizedControlSigner: gatewayPublicKey,
            now: now)
        else {
          throw QntmError.invalid("Rekey recipients do not match authenticated roster")
        }
        next.rekeys.append(
          GroupRekeyCheckpoint(
            source: conversation, roster: roster, appliedIDs: state.appliedIDs,
            gatewayPublicKey: gatewayPublicKey, winnerID: result.envelope.messageID))
        next.removed = state.removed || result.excluded
        if var updated = result.conversation {
          updated.type = conversation.type
          nextConversation = updated
        }
        next.needsRekey = false
      default: throw QntmError.invalid("Unknown group control")
      }
      next.setRoster(roster)
    }
    next.appliedIDs.insert(message.envelope.messageID)
    nextConversation.participants = next.roster?.memberIDs ?? conversation.participants
    return GroupTransition(conversation: nextConversation, state: next)
  }

  /// Older epoch data is considered only for competing rekeys, never as new application traffic.
  public static func decryptForReceive(
    _ envelope: Envelope, conversation: Conversation, state: GroupControlState,
    now: UInt64 = unixSeconds()
  ) throws -> Message {
    guard !state.recoveryRequired, !state.removed else {
      throw QntmError.invalid("Conversation removed or requires recovery")
    }
    if envelope.epoch == conversation.currentEpoch {
      return try Messaging.decrypt(envelope, conversation: conversation, now: now)
    }
    guard envelope.epoch < conversation.currentEpoch,
      let old = state.rekeys.first(where: { $0.source.currentEpoch == envelope.epoch })
    else {
      throw QntmError.invalid("Message is not in current epoch")
    }
    let message = try Messaging.decrypt(envelope, conversation: old.source, now: now)
    guard message.bodyType == "group_rekey" else {
      throw QntmError.invalid("Old-epoch application message")
    }
    return message
  }

  private static func checkedMembers(_ rows: [CBOR], sender: Data) throws -> [GroupMember] {
    guard (1...128).contains(rows.count) else {
      throw QntmError.invalid("Invalid membership count")
    }
    let members = try rows.map { try GroupMember(cbor: $0) }
    guard Set(members.map(\.keyID)).count == members.count,
      members.allSatisfy({ $0.addedBy == sender })
    else {
      throw QntmError.invalid("Invalid group member binding")
    }
    return members
  }

  private static func applyCompetingRekey(
    message: Message, conversation: Conversation, identity: Identity,
    state: GroupControlState, now: UInt64
  ) throws -> GroupTransition {
    guard message.bodyType == "group_rekey", message.envelope.epoch < conversation.currentEpoch,
      let checkpoint = state.rekeys.first(where: {
        $0.source.currentEpoch == message.envelope.epoch
      }),
      message.envelope.messageID.lexicographicallyPrecedes(checkpoint.winnerID)
    else {
      throw QntmError.invalid("Stale, future, or superseded group control")
    }
    let authenticated = try Messaging.decrypt(
      message.envelope, conversation: checkpoint.source, now: now)
    if state.requiresEpochBinding {
      guard let body = try CBOR.decode(authenticated.body).mapValue,
        body["group_epoch"] == .unsigned(UInt64(checkpoint.source.currentEpoch))
      else {
        throw QntmError.invalid("Competing rekey is not signed for this epoch")
      }
    }
    var rekeySource = checkpoint.source
    rekeySource.type = .group
    guard
      let result = try GroupRekey.resolve(
        identity: identity, source: rekeySource, roster: checkpoint.roster,
        wires: [message.envelope.serialize()], authorizedControlSigner: checkpoint.gatewayPublicKey,
        now: now)
    else {
      throw QntmError.invalid("Unauthorized competing rekey")
    }
    var next = state
    next.rekeys.removeAll { $0.source.currentEpoch >= checkpoint.source.currentEpoch }
    var replacement = checkpoint
    replacement.winnerID = result.envelope.messageID
    next.rekeys.append(replacement)
    next.appliedIDs = checkpoint.appliedIDs
    next.appliedIDs.insert(result.envelope.messageID)
    next.setRoster(checkpoint.roster)
    next.removed = result.excluded
    next.needsRekey = false
    var nextConversation = result.conversation ?? conversation
    nextConversation.type = conversation.type
    return GroupTransition(conversation: nextConversation, state: next)
  }
}

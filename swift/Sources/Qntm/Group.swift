import Foundation

public struct GroupMember: Equatable, Codable, Sendable {
  public enum Role: String, Codable, Sendable { case admin, member }
  public let keyID: Data
  public let publicKey: Data
  public let role: Role
  public let addedAt: UInt64
  public let addedBy: Data

  public init(publicKey: Data, role: Role = .member, addedAt: UInt64 = unixSeconds(), addedBy: Data)
    throws
  {
    guard QSPCrypto.isValidPublicKey(publicKey), addedBy.count == 16,
      addedAt <= 9_007_199_254_740_991
    else {
      throw QntmError.invalid("Invalid group member")
    }
    self.publicKey = publicKey
    self.keyID = Data(QSPCrypto.hash(publicKey).prefix(16))
    self.role = role
    self.addedAt = addedAt
    self.addedBy = addedBy
  }

  init(cbor: CBOR, exactFields: Bool = false) throws {
    guard let map = cbor.mapValue else { throw QntmError.invalid("Invalid group member") }
    if exactFields {
      try groupFields(map, ["key_id", "public_key", "role", "added_at", "added_by"])
    }
    guard let role = Role(rawValue: try map.requireString("role")) else {
      throw QntmError.invalid("Invalid group role")
    }
    try self.init(
      publicKey: map.requireBytes("public_key", count: 32), role: role,
      addedAt: map.requireUInt("added_at"), addedBy: map.requireBytes("added_by", count: 16))
    guard try map.requireBytes("key_id", count: 16) == keyID else {
      throw QntmError.invalid("Group member key ID mismatch")
    }
  }

  var cbor: CBOR {
    .map([
      "key_id": .bytes(keyID), "public_key": .bytes(publicKey), "role": .text(role.rawValue),
      "added_at": .unsigned(addedAt), "added_by": .bytes(addedBy),
    ])
  }
}

public struct GroupState: Equatable, Codable, Sendable {
  public private(set) var groupName: String
  public private(set) var description: String
  public private(set) var createdAt: UInt64
  public private(set) var creatorKeyID: Data
  public private(set) var members: [Data: GroupMember]
  public let hasImmutableCreator: Bool

  public init(
    groupName: String, description: String = "", creator: Identity,
    foundingMemberKeys: [Data] = [], now: UInt64 = unixSeconds()
  ) throws {
    var members = [
      try GroupMember(
        publicKey: creator.publicKey, role: .admin, addedAt: now, addedBy: creator.keyID)
    ]
    var seen = Set([creator.keyID])
    for key in foundingMemberKeys {
      let member = try GroupMember(publicKey: key, addedAt: now, addedBy: creator.keyID)
      if seen.insert(member.keyID).inserted { members.append(member) }
    }
    try self.init(
      groupName: groupName, description: description, createdAt: now, foundingMembers: members)
  }

  init(
    groupName: String, description: String, createdAt: UInt64, foundingMembers: [GroupMember],
    hasImmutableCreator: Bool = true
  ) throws {
    guard groupName.utf8.count <= 256, description.utf8.count <= 4096,
      createdAt <= 9_007_199_254_740_991, (1...128).contains(foundingMembers.count),
      !hasImmutableCreator || foundingMembers.first?.role == .admin,
      Set(foundingMembers.map(\.keyID)).count == foundingMembers.count
    else {
      throw QntmError.invalid("Invalid group roster")
    }
    self.groupName = groupName
    self.description = description
    self.createdAt = createdAt
    self.creatorKeyID = foundingMembers[0].keyID
    self.members = Dictionary(uniqueKeysWithValues: foundingMembers.map { ($0.keyID, $0) })
    self.hasImmutableCreator = hasImmutableCreator
  }

  /// Builds a role-neutral roster only from independently accepted direct-conversation gateway membership.
  public init(gatewayParticipants: [String: Data], anchorKeyID: Data) throws {
    guard gatewayParticipants[anchorKeyID.base64URL] != nil else {
      throw QntmError.invalid("Gateway roster anchor is missing")
    }
    var rows: [GroupMember] = []
    for (kid, publicKey) in gatewayParticipants {
      let member = try GroupMember(publicKey: publicKey, addedAt: 0, addedBy: anchorKeyID)
      guard member.keyID.base64URL == kid else {
        throw QntmError.invalid("Gateway roster key ID mismatch")
      }
      rows.append(member)
    }
    rows.sort { left, right in
      if left.keyID == anchorKeyID { return right.keyID != anchorKeyID }
      if right.keyID == anchorKeyID { return false }
      return left.keyID.lexicographicallyPrecedes(right.keyID)
    }
    try self.init(
      groupName: "", description: "", createdAt: 0, foundingMembers: rows,
      hasImmutableCreator: false)
  }

  public func validate() throws {
    guard (1...128).contains(members.count), creatorKeyID.count == 16,
      !hasImmutableCreator || members[creatorKeyID]?.role == .admin
    else { throw QntmError.invalid("Invalid stored group roster") }
    for (kid, member) in members {
      let validated = try GroupMember(cbor: member.cbor)
      guard kid == validated.keyID else { throw QntmError.invalid("Stored roster key mismatch") }
    }
  }

  /// Imports a local trusted snapshot. Peer snapshots must first pass GroupBootstrap.open.
  public init(snapshot: Data) throws {
    try self.init(cbor: CBOR.decode(snapshot))
  }

  init(cbor: CBOR, canonicalOrder: Bool = false) throws {
    guard let map = cbor.mapValue, let rows = map["founding_members"]?.arrayValue else {
      throw QntmError.invalid("Invalid group snapshot")
    }
    if canonicalOrder {
      try groupFields(map, ["group_name", "description", "created_at", "founding_members"])
    }
    let members = try rows.map { try GroupMember(cbor: $0, exactFields: canonicalOrder) }
    try self.init(
      groupName: map.requireString("group_name"), description: map.requireString("description"),
      createdAt: map.requireUInt("created_at"), foundingMembers: members)
    if canonicalOrder {
      let rest = Array(members.dropFirst().map(\.keyID))
      guard rest == rest.sorted(by: { $0.lexicographicallyPrecedes($1) }) else {
        throw QntmError.invalid("Noncanonical group snapshot order")
      }
    }
  }

  public func isMember(_ keyID: Data) -> Bool { members[keyID] != nil }
  public func isAdmin(_ keyID: Data) -> Bool { members[keyID]?.role == .admin }
  public var participantPublicKeys: [String: String] {
    Dictionary(
      uniqueKeysWithValues: members.values.map { ($0.keyID.base64URL, $0.publicKey.base64URL) })
  }
  public var memberIDs: [Data] { orderedMembers.map(\.keyID) }
  public var orderedMembers: [GroupMember] {
    members.values.sorted {
      if $0.keyID == creatorKeyID { return $1.keyID != creatorKeyID }
      if $1.keyID == creatorKeyID { return false }
      return $0.keyID.lexicographicallyPrecedes($1.keyID)
    }
  }
  public func snapshot() throws -> Data { try snapshotValue.encode() }
  var snapshotValue: CBOR {
    .map([
      "group_name": .text(groupName), "description": .text(description),
      "created_at": .unsigned(createdAt),
      "founding_members": .array(orderedMembers.map(\.cbor)),
    ])
  }

  mutating func add(_ added: [GroupMember]) throws {
    guard !added.isEmpty, members.count + added.count <= 128,
      Set(added.map(\.keyID)).count == added.count,
      added.allSatisfy({ members[$0.keyID] == nil })
    else { throw QntmError.invalid("Duplicate or excessive membership") }
    for member in added { members[member.keyID] = member }
  }
  mutating func remove(_ removed: [Data]) throws {
    guard !removed.isEmpty, removed.count <= 128, Set(removed).count == removed.count,
      removed.allSatisfy({ (!hasImmutableCreator || $0 != creatorKeyID) && members[$0] != nil })
    else {
      throw QntmError.invalid("Invalid member removal; creator requires a successor group")
    }
    for key in removed { members.removeValue(forKey: key) }
  }
}

public enum GroupBodies {
  public static func genesis(state: GroupState) throws -> Data { try state.snapshot() }
  public static func add(identity: Identity, publicKeys: [Data], now: UInt64 = unixSeconds()) throws
    -> Data
  {
    guard (1...128).contains(publicKeys.count) else {
      throw QntmError.invalid("Invalid member count")
    }
    let members = try publicKeys.map {
      try GroupMember(publicKey: $0, addedAt: now, addedBy: identity.keyID)
    }
    guard Set(members.map(\.keyID)).count == members.count else {
      throw QntmError.invalid("Duplicate member")
    }
    return try CBOR.map(["added_at": .unsigned(now), "new_members": .array(members.map(\.cbor))])
      .encode()
  }
  public static func remove(keyIDs: [Data], reason: String = "", now: UInt64 = unixSeconds()) throws
    -> Data
  {
    guard (1...128).contains(keyIDs.count), keyIDs.allSatisfy({ $0.count == 16 }),
      Set(keyIDs).count == keyIDs.count
    else {
      throw QntmError.invalid("Invalid removed member IDs")
    }
    return try CBOR.map([
      "removed_at": .unsigned(now), "reason": .text(reason),
      "removed_members": .array(keyIDs.map(CBOR.bytes)),
    ]).encode()
  }
  public static func rekey(conversation: Conversation, roster: GroupState) throws -> (
    body: Data, groupKey: Data
  ) {
    guard conversation.type == .group, conversation.currentEpoch < UInt32.max else {
      throw QntmError.invalid("Invalid rekey epoch")
    }
    let key = QSPCrypto.random(32)
    var wrapped: [String: CBOR] = [:]
    for member in roster.orderedMembers {
      wrapped[member.keyID.base64URL] = .bytes(
        try QSPCrypto.wrapKey(
          key, recipientPublicKey: member.publicKey,
          recipientKeyID: member.keyID, conversationID: conversation.id))
    }
    let body = try CBOR.map([
      "new_conv_epoch": .unsigned(UInt64(conversation.currentEpoch) + 1),
      "wrapped_keys": .map(wrapped),
    ]).encode()
    return (body, key)
  }
}

func groupFields(_ map: [String: CBOR], _ names: Set<String>) throws {
  guard Set(map.keys) == names else { throw QntmError.invalid("Unexpected group fields") }
}

import Foundation

private struct GatewaySignedRecord: Codable, Sendable {
  let envelope: Data
  let senderPublicKey: Data
  let senderKeyID: Data
  let bodyType: String
  let body: Data
  let refs: Data
  let signature: Data
  init(_ message: Message) throws {
    envelope = try message.envelope.serialize()
    senderPublicKey = message.senderPublicKey
    senderKeyID = message.senderKeyID
    bodyType = message.bodyType
    body = message.body
    refs = try CBOR.array(message.refs).encode()
    signature = message.signature
  }
  func message() throws -> Message {
    let envelope = try Envelope(serialized: envelope)
    guard let refs = try CBOR.decode(refs).arrayValue else {
      throw QntmError.invalid("Invalid stored references")
    }
    let message = Message(
      envelope: envelope, senderPublicKey: senderPublicKey, senderKeyID: senderKeyID,
      bodyType: bodyType, body: body, refs: refs, signature: signature,
      untrustedCharterMetadataIgnored: false)
    try gateRequire(Messaging.verifySignature(message), "Invalid stored gateway message signature")
    return message
  }
}
private struct GatewayMembershipAuthorization: Codable, Sendable {
  let proposalID: String
  let proposal: Data
  let sourceEpoch: UInt32
  let expectedParticipants: [String: Data]
}
private struct GatewayEventRecord: Codable, Sendable {
  let signed: GatewaySignedRecord
  let context: GatewayContext
  let request: Data?
  let proposal: Data?
  let invitation: GatewaySignedRecord?
  init(message: Message, context: GatewayContext, references: GatewayReferences) throws {
    signed = try GatewaySignedRecord(message)
    self.context = context
    request = try references.request?.encoded()
    proposal = try references.proposal?.encoded()
    invitation = try references.invitation.map(GatewaySignedRecord.init)
  }
  func verify() throws -> VerifiedGatewayEvent {
    let refs = try GatewayReferences(
      request: request.map { try GatewayBody(type: "gate.request", data: $0) },
      proposal: proposal.map { try GatewayBody(type: "gov.propose", data: $0) },
      invitation: invitation?.message())
    return try Gateway.verify(signed.message(), context: context, references: refs)
  }
}

/// Durable local checkpoint. Decode only from the host's private trusted profile storage.
/// Stored messages are signature-checked again on decode; current policy remains host state.
public struct GatewaySession: Codable, Sendable {
  public private(set) var context: GatewayContext?
  public private(set) var accepted = false
  public private(set) var membershipAuthority = false
  public private(set) var participants: [String: Data]
  public private(set) var events: [VerifiedGatewayEvent] = []
  private var invitation: GatewaySignedRecord?
  private var records: [GatewayEventRecord] = []
  private var pendingMembership: GatewayMembershipAuthorization?
  private var usedMembershipProposals: Set<String> = []
  private var appliedProposals: Set<String> = []
  public var gatewayAuthorityPublicKey: Data? {
    accepted && membershipAuthority ? context?.gatewayPublicKey : nil
  }
  public init(participants: [String: Data] = [:]) throws {
    if !participants.isEmpty {
      _ = try gateParticipants(
        .object(participants.map { GatewayJSON.Field($0.key, .string($0.value.base64URL)) }))
    }
    self.participants = participants
  }
  private enum CodingKeys: String, CodingKey {
    case context, accepted, membershipAuthority, participants, invitation, records,
      pendingMembership, usedMembershipProposals, appliedProposals
  }
  public init(from decoder: any Decoder) throws {
    let c = try decoder.container(keyedBy: CodingKeys.self)
    context = try c.decodeIfPresent(GatewayContext.self, forKey: .context)
    accepted = try c.decode(Bool.self, forKey: .accepted)
    membershipAuthority = try c.decode(Bool.self, forKey: .membershipAuthority)
    participants = try c.decode([String: Data].self, forKey: .participants)
    invitation = try c.decodeIfPresent(GatewaySignedRecord.self, forKey: .invitation)
    records = try c.decode([GatewayEventRecord].self, forKey: .records)
    pendingMembership = try c.decodeIfPresent(
      GatewayMembershipAuthorization.self, forKey: .pendingMembership)
    usedMembershipProposals =
      try c.decodeIfPresent(Set<String>.self, forKey: .usedMembershipProposals) ?? []
    appliedProposals = try c.decodeIfPresent(Set<String>.self, forKey: .appliedProposals) ?? []
    try gateRequire(
      records.count <= 4096 && (!accepted || context != nil), "Invalid gateway checkpoint")
    if !participants.isEmpty {
      _ = try gateParticipants(
        .object(participants.map { GatewayJSON.Field($0.key, .string($0.value.base64URL)) }))
    }
    try context?.validate()
    if let invitation { _ = try invitation.message() }
    events = try records.map { try $0.verify() }
  }
  public func encode(to encoder: any Encoder) throws {
    var c = encoder.container(keyedBy: CodingKeys.self)
    try c.encodeIfPresent(context, forKey: .context)
    try c.encode(accepted, forKey: .accepted)
    try c.encode(membershipAuthority, forKey: .membershipAuthority)
    try c.encode(participants, forKey: .participants)
    try c.encodeIfPresent(invitation, forKey: .invitation)
    try c.encode(records, forKey: .records)
    try c.encodeIfPresent(pendingMembership, forKey: .pendingMembership)
    try c.encode(usedMembershipProposals, forKey: .usedMembershipProposals)
    try c.encode(appliedProposals, forKey: .appliedProposals)
  }
  public mutating func updateMembership(participants: [String: Data], epoch: UInt32) throws {
    _ = try gateParticipants(
      .object(participants.map { GatewayJSON.Field($0.key, .string($0.value.base64URL)) }))
    var next = context
    next?.participants = participants
    next?.epoch = epoch
    try next?.validate()
    self.participants = participants
    context = next
  }
  /// Must run on the same staged checkpoint as GroupControls.apply and updateMembership.
  /// A gateway signature alone does not authorize changing the group roster.
  public mutating func prepareGroupControl(
    message: Message, conversation: Conversation, groupState: GroupControlState?,
    now: UInt64 = unixSeconds()
  ) throws -> Data? {
    guard accepted else { return nil }
    guard membershipAuthority, let context else {
      throw QntmError.invalid("Gateway lacks group membership authority")
    }
    try gateRequire(
      message.senderPublicKey == context.gatewayPublicKey
        && message.envelope.conversationID == conversation.id && now <= message.envelope.expiresAt
        && Messaging.verifySignature(message), "Invalid delegated group sender")
    if message.bodyType == "group_rekey" {
      guard let pendingMembership else {
        throw QntmError.invalid("Gateway rekey requires an approved membership transition")
      }
      try gateRequire(
        message.envelope.epoch == pendingMembership.sourceEpoch
          && participants == pendingMembership.expectedParticipants,
        "Rekey differs from governed membership")
      return context.gatewayPublicKey
    }
    try gateRequire(
      ["group_add", "group_remove"].contains(message.bodyType) && pendingMembership == nil
        && groupState?.needsRekey != true && groupState?.removed != true
        && groupState?.recoveryRequired != true && message.envelope.epoch == context.epoch,
      "Invalid governed membership transition")
    guard let control = try CBOR.decode(message.body).mapValue else {
      throw QntmError.invalid("Invalid group control body")
    }
    for event in events where event.body.type == .propose {
      let proposal = event.body
      let id = try gateText(proposal["proposal_id"], "proposal ID")
      if usedMembershipProposals.contains(id) { continue }
      let isAdd = message.bodyType == "group_add"
      if proposal["proposal_type"]?.string != (isAdd ? "member_add" : "member_remove") { continue }
      var expected = participants
      if isAdd {
        guard let actual = control["new_members"]?.arrayValue,
          let proposed = proposal["proposed_members"]?.array, actual.count == proposed.count
        else { continue }
        var actualKeys: [String: Data] = [:]
        for value in actual {
          guard let member = value.mapValue else { throw QntmError.invalid("Invalid added member") }
          let kid = try member.requireBytes("key_id", count: 16)
          let pk = try member.requireBytes("public_key", count: 32)
          try gateRequire(
            try member.requireString("role") == "member" && QSPCrypto.hash(pk).prefix(16) == kid
              && actualKeys[kid.base64URL] == nil && kid.base64URL != context.gatewayKeyID,
            "Invalid governed member")
          actualKeys[kid.base64URL] = pk
        }
        let proposedKeys = try Dictionary(
          uniqueKeysWithValues: proposed.map {
            (
              try gateText($0["kid"], "member ID"),
              try gateBytes($0["public_key"], "member key", count: 32)
            )
          })
        if actualKeys != proposedKeys { continue }
        try gateRequire(
          actualKeys.keys.allSatisfy { participants[$0] == nil },
          "Governance cannot add existing members")
        expected.merge(actualKeys) { _, new in new }
      } else {
        guard let actual = control["removed_members"]?.arrayValue else { continue }
        let actualKids = try actual.map { value -> String in
          guard let kid = value.bytesValue, kid.count == 16 else {
            throw QntmError.invalid("Invalid removed member")
          }
          return kid.base64URL
        }
        let proposed = try gateRoster(proposal["removed_member_kids"])
        if Set(actualKids) != Set(proposed) || actualKids.count != proposed.count { continue }
        try gateRequire(
          !(groupState?.roster?.hasImmutableCreator == true
            && actualKids.contains(groupState?.creatorKeyID.base64URL ?? ""))
            && actualKids.allSatisfy { participants[$0] != nil }, "Invalid governed removal")
        for kid in actualKids { expected.removeValue(forKey: kid) }
      }
      guard
        let summary = try Gateway.scan(
          events: events, context: context, id: id, proposal: true, now: now),
        summary.status == .approved
      else { continue }
      if let roster = groupState?.roster, roster.hasImmutableCreator {
        try gateRequire(
          roster.members.values.contains {
            roster.isAdmin($0.keyID) && summary.votes[$0.keyID.base64URL] == true
          }, "Governed membership requires an administrator approval")
      }
      try gateRequire(!expected.isEmpty && expected.count <= 128, "Invalid resulting group size")
      pendingMembership = try GatewayMembershipAuthorization(
        proposalID: id, proposal: proposal.encoded(), sourceEpoch: context.epoch,
        expectedParticipants: expected)
      usedMembershipProposals.insert(id)
      return context.gatewayPublicKey
    }
    throw QntmError.invalid("Group control has no matching approved membership proposal")
  }
  public mutating func discover(_ message: Message) throws {
    try gateRequire(!accepted, "Cannot discover participants after gateway admission")
    if let known = participants[message.senderKeyID.base64URL] {
      try gateRequire(known == message.senderPublicKey, "Known participant key changed")
    }
    participants[message.senderKeyID.base64URL] = message.senderPublicKey
  }
  @discardableResult public mutating func receive(
    message: Message, conversation: Conversation, groupState: GroupControlState? = nil,
    now: UInt64 = unixSeconds()
  ) throws -> VerifiedGatewayEvent? {
    guard message.bodyType.hasPrefix("gate.") || message.bodyType.hasPrefix("gov.") else {
      return nil
    }
    try gateRequire(
      now <= message.envelope.expiresAt && message.envelope.conversationID == conversation.id
        && message.envelope.epoch == conversation.currentEpoch
        && Messaging.verifySignature(message), "Invalid gateway receive context")
    if let existing = events.first(where: { $0.messageID == message.envelope.messageID.hex }) {
      try gateRequire(
        existing.body == GatewayBody(type: message.bodyType, data: message.body)
          && existing.senderKeyID == message.senderKeyID.base64URL, "Conflicting gateway replay")
      return nil
    }
    var next = self
    let body = try GatewayBody(type: message.bodyType, data: message.body)
    let sender = message.senderKeyID.base64URL
    let reference: GatewayReferences
    if body.type == .promote {
      try gateRequire(
        !accepted && groupState?.needsRekey != true && groupState?.removed != true
          && groupState?.recoveryRequired != true, "Conversation cannot invite a gateway")
      try gateRequire(
        body["conv_id"]?.string == conversation.id.hex
          && body["conv_epoch"]?.integer == UInt64(conversation.currentEpoch)
          && body["keys_hash"]?.string == Gateway.accessHash(conversation)
          && gateUInt(body["expires_at"], "invitation expiry") >= now, "Stale gateway invitation")
      let invited = try gateParticipants(body["participants"])
      try gateRequire(
        invited[sender] == message.senderPublicKey, "Inviter not in invitation roster")
      for (kid, key) in participants {
        try gateRequire(invited[kid] == key, "Invitation changes known participant")
      }
      for kid in conversation.participants {
        try gateRequire(invited[kid.base64URL] != nil, "Invitation omits known participant")
      }
      if let type = body["conversation_type"] {
        try gateRequire(
          type.string == conversation.type.rawValue, "Invitation changes conversation type")
      }
      if conversation.type == .group || groupState != nil {
        guard let groupState else {
          throw QntmError.invalid("Authenticated group state required for promotion")
        }
        try gateRequire(
          message.senderKeyID == groupState.creatorKeyID
            || groupState.roster?.isAdmin(message.senderKeyID) == true,
          "Only a group administrator may promote a gateway")
        if let creator = body["group_creator_kid"] {
          try gateRequire(
            creator.string == groupState.creatorKeyID.base64URL, "Invitation changes group creator")
        }
        if let roster = groupState.roster {
          let known = roster.participantPublicKeys
          try gateRequire(
            Set(known.keys) == Set(invited.keys)
              && known.allSatisfy { invited[$0.key]?.base64URL == $0.value },
            "Invitation changes authenticated group roster")
        }
      }
      next.context = try GatewayContext(
        conversationID: conversation.id.hex, epoch: conversation.currentEpoch,
        gatewayPublicKey: gateBytes(body["gateway_public_key"], "gateway key", count: 32),
        participants: invited, floor: gateUInt(body["floor"], "floor", min: 1),
        rules: ThresholdRule.parse(body["rules"]))
      next.membershipAuthority = conversation.type == .direct || groupState != nil
      next.invitation = try GatewaySignedRecord(message)
      reference = GatewayReferences()
    } else {
      guard let context, let invitation else {
        throw QntmError.invalid("Gateway event has no verified invitation")
      }
      try gateRequire(body.type == .accept || accepted, "Gateway has not accepted invitation")
      reference = try GatewayReferences(
        request: body["request_id"]?.string.flatMap {
          try Gateway.findSubject(events: events, conversationID: context.conversationID, id: $0)
        },
        proposal: body["proposal_id"]?.string.flatMap {
          try Gateway.findSubject(
            events: events, conversationID: context.conversationID, id: $0, proposal: true)
        }, invitation: invitation.message())
    }
    guard let receiptContext = next.context else {
      throw QntmError.invalid("Missing gateway context")
    }
    let event = try Gateway.verify(message, context: receiptContext, references: reference)
    if body.type == .accept {
      guard let invitation = next.invitation else { throw QntmError.invalid("Missing invitation") }
      let invite = try GatewayBody(type: "gate.promote", data: invitation.body)
      try gateRequire(
        message.envelope.createdAt <= gateUInt(invite["expires_at"], "expiry")
          && invite["keys_hash"]?.string == Gateway.accessHash(conversation)
          && groupState?.needsRekey != true && groupState?.removed != true
          && groupState?.recoveryRequired != true, "Gateway invitation is stale")
      for (kid, key) in participants {
        try gateRequire(
          receiptContext.participants[kid] == key, "Gateway acceptance changes known member")
      }
      if let roster = groupState?.roster {
        try gateRequire(
          Set(roster.participantPublicKeys.keys) == Set(receiptContext.participants.keys),
          "Gateway acceptance changes group roster")
      }
      next.accepted = true
      next.participants = receiptContext.participants
    } else if body.type == .applied {
      let proposalID = try gateText(body["proposal_id"], "proposal ID")
      try gateRequire(!appliedProposals.contains(proposalID), "Governance proposal already applied")
      let membership = ["member_add", "member_remove"].contains(body["proposal_type"]?.string ?? "")
      let proposal: GatewayBody
      if membership {
        guard let pending = pendingMembership, pending.proposalID == proposalID else {
          throw QntmError.invalid("Membership application has no authorized group transition")
        }
        proposal = try GatewayBody(type: "gov.propose", data: pending.proposal)
        try gateRequire(
          UInt64(receiptContext.epoch) == UInt64(pending.sourceEpoch) + 1
            && receiptContext.participants == pending.expectedParticipants,
          "Membership application precedes authorized rekey")
      } else {
        guard let referenced = reference.proposal,
          let summary = try Gateway.scan(
            events: events, context: receiptContext, id: proposalID, proposal: true, now: now),
          summary.status == .approved
        else { throw QntmError.invalid("Governance application lacks approved proposal") }
        proposal = referenced
      }
      try gateRequire(
        proposal["proposal_type"] == body["proposal_type"], "Applied proposal type mismatch")
      for (proposed, applied) in [
        ("proposed_floor", "applied_floor"), ("proposed_rules", "applied_rules"),
        ("proposed_members", "applied_members"), ("removed_member_kids", "removed_member_kids"),
      ] {
        try gateRequire(
          (proposal[proposed] ?? .null) == (body[applied] ?? .null),
          "Applied policy differs from signed proposal")
      }
      next.appliedProposals.insert(proposalID)
      if membership { next.pendingMembership = nil }
      var changed = receiptContext
      switch body["proposal_type"]?.string {
      case "floor_change": changed.floor = try gateUInt(body["applied_floor"], "floor", min: 1)
      case "rules_change": changed.rules = try ThresholdRule.parse(body["applied_rules"])
      case "member_add":
        try gateRequire(
          groupState == nil || membershipAuthority, "Gateway lacks membership authority")
        for member in body["applied_members"]?.array ?? [] {
          let pk = try gateBytes(member["public_key"], "member key", count: 32)
          let kid = QSPCrypto.hash(pk).prefix(16).base64URL
          try gateRequire(
            kid != changed.gatewayKeyID
              && (next.participants[kid] == nil || next.participants[kid] == pk),
            "Invalid applied member")
          next.participants[kid] = pk
        }
      case "member_remove":
        try gateRequire(
          groupState == nil || membershipAuthority, "Gateway lacks membership authority")
        for kid in try gateRoster(body["removed_member_kids"]) {
          try gateRequire(
            groupState?.roster?.hasImmutableCreator != true
              || kid != groupState?.creatorKeyID.base64URL, "Gateway cannot remove group creator")
          next.participants.removeValue(forKey: kid)
        }
      default: throw QntmError.invalid("Invalid applied proposal")
      }
      changed.participants = next.participants
      try changed.validate()
      next.context = changed
    }
    next.events.append(event)
    next.records.append(
      try GatewayEventRecord(message: message, context: receiptContext, references: reference))
    if next.events.count > 4096 {
      next.events.removeFirst()
      next.records.removeFirst()
    }
    self = next
    return event
  }
}

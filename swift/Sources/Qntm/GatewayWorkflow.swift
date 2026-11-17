import Foundation

public struct GatewayReferences: Sendable {
  public var request: GatewayBody?
  public var proposal: GatewayBody?
  public var invitation: Message?
  public init(request: GatewayBody? = nil, proposal: GatewayBody? = nil, invitation: Message? = nil)
  {
    self.request = request
    self.proposal = proposal
    self.invitation = invitation
  }
}
public struct VerifiedGatewayEvent: Sendable, Equatable {
  public let body: GatewayBody
  public let senderKeyID: String
  public let conversationID: String
  public let epoch: UInt32
  public let messageID: String
  public let createdAt: UInt64
  fileprivate init(body: GatewayBody, message: Message) {
    self.body = body
    senderKeyID = message.senderKeyID.base64URL
    conversationID = message.envelope.conversationID.hex
    epoch = message.envelope.epoch
    messageID = message.envelope.messageID.hex
    createdAt = message.envelope.createdAt
  }
}
public enum GatewayWorkflowStatus: String, Sendable {
  case pending, approved, executed, applied, expired, invalidated
}
public struct GatewayWorkflowState: Sendable {
  public let subject: GatewayBody
  public var status: GatewayWorkflowStatus
  public let threshold: UInt64
  public var votes: [String: Bool]
  public var result: GatewayBody?
  public var approvalCount: Int { votes.values.filter { $0 }.count }
}

extension Gateway {
  public static func verify(
    _ message: Message, context: GatewayContext, references: GatewayReferences = GatewayReferences()
  ) throws -> VerifiedGatewayEvent {
    try context.validate()
    try gateRequire(
      message.envelope.conversationID.hex == context.conversationID
        && message.envelope.epoch == context.epoch, "Envelope differs from gateway context")
    let body = try GatewayBody(type: message.bodyType, data: message.body)
    let sender = message.senderKeyID.base64URL
    if body.type.gatewayOnly {
      try gateRequire(
        sender == context.gatewayKeyID && message.senderPublicKey == context.gatewayPublicKey,
        "Event is not from configured gateway")
    } else {
      try gateRequire(
        context.participants[sender] == message.senderPublicKey,
        "Sender is not a current participant")
    }
    if body["conv_id"] != nil { try assertBinding(body, context: context) }
    if let kid = body["gateway_kid"] {
      try gateRequire(kid.string == context.gatewayKeyID, "Gateway ID mismatch")
    }
    for field in ["signer_kid", "sender_kid"] {
      if let value = body[field] {
        try gateRequire(value.string == sender, "Body sender differs from envelope sender")
      }
    }
    switch body.type {
    case .request: try assertRequest(body, context: context)
    case .propose: try Governance.assertProposal(body, context: context)
    case .approval, .disapproval, .proposalApproval, .proposalDisapproval:
      let proposal = body.type == .proposalApproval || body.type == .proposalDisapproval
      let key = proposal ? "proposal_id" : "request_id"
      guard let subject = proposal ? references.proposal : references.request,
        subject[key] == body[key]
      else { throw QntmError.invalid("Matching signed workflow required") }
      if proposal {
        try Governance.assertProposal(subject, context: context)
      } else {
        try assertRequest(subject, context: context)
      }
      try gateRequire(
        try gateRoster(subject["eligible_signer_kids"]).contains(sender), "Ineligible voter")
      if body.type == .approval || body.type == .proposalApproval {
        try gateRequire(
          QSPCrypto.verify(
            publicKey: message.senderPublicKey, message: try voteSignable(subject).encode(),
            signature: try gateBytes(body["signature"], "vote signature", count: 64)),
          "Invalid approval signature")
      }
    case .promote:
      try gateRequire(
        body["conv_epoch"]?.integer == UInt64(context.epoch)
          && gateParticipants(body["participants"]) == context.participants,
        "Invitation changes epoch or participants")
    case .accept:
      guard let invitation = references.invitation else {
        throw QntmError.invalid("Verified invitation required")
      }
      try gateRequire(
        try matchesAcceptance(body, senderKeyID: sender, invitation: invitation),
        "Acceptance does not match invitation")
    default: break
    }
    return VerifiedGatewayEvent(body: body, message: message)
  }
  public static func decrypt(
    _ envelope: Envelope, conversation: Conversation, context: GatewayContext,
    references: GatewayReferences = GatewayReferences(), now: UInt64 = unixSeconds()
  ) throws -> VerifiedGatewayEvent {
    try gateRequire(
      conversation.id.hex == context.conversationID && conversation.currentEpoch == context.epoch,
      "Conversation differs from gateway context")
    return try verify(
      Messaging.decrypt(envelope, conversation: conversation, now: now), context: context,
      references: references)
  }
  public static func createMessage(
    identity: Identity, conversation: Conversation, body: GatewayBody, context: GatewayContext,
    references: GatewayReferences = GatewayReferences(), ttl: UInt64 = 2_592_000,
    now: UInt64 = unixSeconds()
  ) throws -> Envelope {
    try gateRequire(
      conversation.id.hex == context.conversationID && conversation.currentEpoch == context.epoch,
      "Conversation differs from gateway context")
    let envelope = try Messaging.create(
      identity: identity, conversation: conversation, bodyType: body.type.rawValue,
      body: body.encoded(), ttl: ttl, now: now)
    _ = try verify(
      Messaging.decrypt(envelope, conversation: conversation, now: now), context: context,
      references: references)
    return envelope
  }
  static func orderedHistory(_ events: [VerifiedGatewayEvent], conversationID: String) throws
    -> [VerifiedGatewayEvent]
  {
    var seen: [String: VerifiedGatewayEvent] = [:]
    var result: [VerifiedGatewayEvent] = []
    for event in events where event.conversationID == conversationID {
      if let previous = seen[event.messageID] {
        try gateRequire(previous == event, "Conflicting gateway message ID")
        continue
      }
      seen[event.messageID] = event
      result.append(event)
    }
    return result
  }
  public static func findSubject(
    events: [VerifiedGatewayEvent], conversationID: String, id: String, proposal: Bool = false
  ) throws -> GatewayBody? {
    var found: GatewayBody?
    for event in try orderedHistory(events, conversationID: conversationID)
    where event.body.type == (proposal ? .propose : .request)
      && event.body[proposal ? "proposal_id" : "request_id"]?.string == id
    {
      try gateRequire(found == nil || found == event.body, "Ambiguous workflow ID")
      found = event.body
    }
    return found
  }
  /// Summary only. Approval does not assert the gateway executed the external action.
  public static func scan(
    events: [VerifiedGatewayEvent], context: GatewayContext, id: String, proposal: Bool = false,
    now: UInt64 = unixSeconds()
  ) throws -> GatewayWorkflowState? {
    try context.validate()
    let history = try orderedHistory(events, conversationID: context.conversationID)
    guard
      let subject = try findSubject(
        events: history, conversationID: context.conversationID, id: id, proposal: proposal),
      let start = history.firstIndex(where: { $0.body == subject })
    else { return nil }
    let threshold = max(
      try gateUInt(subject["required_approvals"], "threshold"),
      proposal
        ? context.governanceQuorum
        : context.requestThreshold(
          service: try gateText(subject["target_service"], "service"),
          endpoint: try gateText(subject["target_endpoint"], "endpoint"),
          verb: try gateText(subject["verb"], "verb"), targetURL: subject["target_url"]?.string))
    var state = GatewayWorkflowState(
      subject: subject, status: .pending, threshold: threshold, votes: [:], result: nil)
    let key = proposal ? "proposal_id" : "request_id"
    for event in history[start...]
    where event.body[key]?.string == id && event.senderKeyID == context.gatewayKeyID {
      if event.body.type == .result { state.result = event.body }
      if state.status == .pending {
        if event.body.type == (proposal ? .proposalInvalidated : .invalidated) {
          state.status = .invalidated
        } else if proposal && event.body.type == .applied {
          state.status = .applied
        } else if !proposal && [.result, .executed].contains(event.body.type) {
          state.status = .executed
        }
      }
    }
    if state.status != .pending { return state }
    if (try? assertBinding(subject, context: context)) == nil
      || (try? assertRoster(subject, context: context)) == nil
    {
      state.status = .invalidated
      return state
    }
    if now >= (try gateTime(subject["expires_at"])) {
      state.status = .expired
      return state
    }
    let author = history[start].senderKeyID
    if context.participants[author] != nil { state.votes[author] = true }
    for event in history.dropFirst(start + 1)
    where event.body[key]?.string == id && context.participants[event.senderKeyID] != nil
      && event.body["conv_id"]?.string == context.conversationID
      && event.body["signer_kid"]?.string == event.senderKeyID
    {
      if event.body.type == (proposal ? .proposalApproval : .approval) {
        state.votes[event.senderKeyID] = true
      }
      if event.body.type == (proposal ? .proposalDisapproval : .disapproval) {
        state.votes[event.senderKeyID] = false
      }
    }
    if state.approvalCount >= threshold { state.status = .approved }
    return state
  }
}

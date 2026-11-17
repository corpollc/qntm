import Foundation

/// Owns profile transactions, authenticated receive state and durable outbound retries.
public actor QntmClient {
  private var profile: Profile
  private let store: any ProfileStore
  private var sending: Set<String> = []
  private var receiving: Set<String> = []
  public init(store: any ProfileStore, identity: Identity? = nil, relayURL: URL? = nil) throws {
    self.store = store
    if var saved = try store.load() {
      if let identity, identity != (try saved.identity) {
        throw QntmError.invalid("Profile already has a different identity")
      }
      if let relayURL { saved.relayURL = relayURL }
      try saved.validate()
      profile = saved
    } else {
      profile = try Profile(
        identity: identity ?? Identity(), relayURL: relayURL ?? DropboxClient.defaultURL)
    }
    try store.save(profile)
  }
  public func identity() throws -> Identity { try profile.identity }
  public func snapshot() -> Profile { profile }
  public func conversation(_ id: String) throws -> SavedConversation {
    if let saved = profile.conversations[id] { return saved }
    let matches = profile.conversations.values.filter {
      $0.conversation.name == id || $0.conversation.id.hex.hasPrefix(id)
    }
    guard matches.count == 1, let result = matches.first else {
      throw QntmError.invalid("Conversation not found or ambiguous")
    }
    return result
  }
  private func commit(_ next: Profile) throws {
    try store.save(next)
    profile = next
  }
  private func save(_ saved: SavedConversation) throws {
    var next = profile
    next.conversations[saved.conversation.id.hex] = saved
    try commit(next)
  }
  public func createConversation(
    name: String? = nil, type: ConversationType = .direct, memberPublicKeys: [Data] = []
  ) async throws -> SavedConversation {
    let id = try identity()
    let invite = try Invite(creator: id, type: type)
    var conv = try invite.conversation()
    conv.name = name
    var saved = try SavedConversation(
      conversation: conv, members: [id.keyID.base64URL: id.publicKey])
    if type == .group {
      let roster = try GroupState(
        groupName: name ?? "Group", creator: id, foundingMemberKeys: memberPublicKeys)
      saved.group = try GroupControlState(creatorKeyID: id.keyID, requiresEpochBinding: true)
      let genesis = try Messaging.create(
        identity: id, conversation: conv, bodyType: "group_genesis",
        body: GroupBodies.genesis(state: roster))
      saved.pendingOutbound.append(try genesis.serialize())
    }
    try save(saved)
    if type == .group { _ = try await flush(conversationID: conv.id.hex) }
    return try conversation(conv.id.hex)
  }
  public func join(_ tokenOrURL: String, name: String? = nil) throws -> SavedConversation {
    let token = URLComponents(string: tokenOrURL)?.fragment ?? tokenOrURL
    var saved: SavedConversation
    if GroupBootstrap.isCurrentEpochInvite(token) {
      let bootstrap = try GroupBootstrap.open(identity: identity(), token: token)
      saved = try SavedConversation(
        conversation: bootstrap.conversation, group: try GroupControlState(bootstrap: bootstrap),
        members: Dictionary(
          uniqueKeysWithValues: bootstrap.state.orderedMembers.map {
            ($0.keyID.base64URL, $0.publicKey)
          }))
      saved.lastRekeyID = bootstrap.rekeyID
    } else {
      let invite = try Invite(tokenOrURL: tokenOrURL)
      let conv = try invite.conversation()
      saved = try SavedConversation(
        conversation: conv,
        group: conv.type == .group
          ? try GroupControlState(creatorKeyID: QSPCrypto.hash(invite.inviterPublicKey).prefix(16))
          : nil,
        members: [
          QSPCrypto.hash(invite.inviterPublicKey).prefix(16).base64URL: invite.inviterPublicKey
        ])
    }
    if var existing = profile.conversations[saved.conversation.id.hex] {
      guard GroupBootstrap.isCurrentEpochInvite(token) else { return existing }
      guard !existing.gateway.accepted, existing.group?.removed != true,
        existing.group?.creatorKeyID == saved.group?.creatorKeyID,
        saved.conversation.currentEpoch >= existing.conversation.currentEpoch
      else {
        throw QntmError.invalid(
          "Invitation cannot replace this conversation authority or roll back its epoch")
      }
      if saved.conversation.currentEpoch == existing.conversation.currentEpoch {
        let sameKeys = saved.conversation.keys == existing.conversation.keys
        let lowerRekey =
          saved.lastRekeyID.map { new in
            existing.lastRekeyID.map { new.lexicographicallyPrecedes($0) } ?? false
          } ?? false
        guard existing.group?.needsRekey != true, existing.group?.roster == saved.group?.roster,
          sameKeys || lowerRekey
        else {
          throw QntmError.invalid("Conflicting current-epoch invitation")
        }
      }
      let previousName = existing.conversation.name
      existing.conversation = saved.conversation
      existing.group = saved.group
      existing.members = saved.members
      existing.gateway = saved.gateway
      existing.lastRekeyID = saved.lastRekeyID
      existing.conversation.name = name ?? previousName
      try replayPending(&existing)
      try save(existing)
      return existing
    }
    saved.conversation.name = name
    try save(saved)
    return saved
  }
  public func rename(_ id: String, name: String) throws {
    var s = try conversation(id)
    s.conversation.name = name
    try save(s)
  }
  public func send(_ id: String, bodyType: String = "text", body: Data, ttl: UInt64 = 2_592_000)
    async throws -> Envelope
  {
    var saved = try conversation(id)
    let cid = saved.conversation.id.hex
    try beginSending(cid)
    defer { sending.remove(cid) }
    try authorizeSend(bodyType: bodyType, saved: saved)
    let envelope = try Messaging.create(
      identity: identity(), conversation: saved.conversation, bodyType: bodyType, body: body,
      ttl: ttl)
    if bodyType.hasPrefix("gate.") || bodyType.hasPrefix("gov.")
      || GroupControls.bodyTypes.contains(bodyType)
    {
      // Validate against a copy before putting a control on the relay.
      var preview = saved
      try apply(try Messaging.decrypt(envelope, conversation: saved.conversation), to: &preview)
    }
    saved.pendingOutbound.append(try envelope.serialize())
    try save(saved)
    _ = try await drain(cid)
    if let failure = try conversation(cid).failedOutbound?.last(where: {
      $0.messageID == envelope.messageID.hex
    }) {
      throw QntmError.invalid(failure.reason)
    }
    return envelope
  }

  private func authorizeSend(bodyType: String, saved: SavedConversation) throws {
    guard saved.group?.removed != true, saved.group?.recoveryRequired != true,
      saved.group?.needsRekey != true || bodyType == "group_rekey"
    else { throw QntmError.invalid("Group requires recovery or rekey before sending") }
    if saved.gateway.accepted {
      guard saved.gateway.participants[try identity().keyID.base64URL] != nil else {
        throw QntmError.invalid("Local identity has been removed from the gateway conversation")
      }
    }
    if let roster = saved.group?.roster {
      guard roster.isMember(try identity().keyID) else {
        throw QntmError.invalid("Local identity is not a group member")
      }
    }
  }

  private func beginSending(_ cid: String) throws {
    guard sending.insert(cid).inserted else {
      throw QntmError.invalid("A send is already in progress for this conversation")
    }
  }

  @discardableResult public func flush(conversationID: String) async throws -> [UInt64] {
    let cid = try conversation(conversationID).conversation.id.hex
    try beginSending(cid)
    defer { sending.remove(cid) }
    return try await drain(cid)
  }

  private func drain(_ cid: String) async throws -> [UInt64] {
    let relay = try DropboxClient(baseURL: profile.relayURL)
    let localSenderID = try identity().keyID.hex
    var sequences: [UInt64] = []
    while true {
      var beforeSend = try conversation(cid)
      guard let wire = beforeSend.pendingOutbound.first else { break }
      let envelope = try Envelope(serialized: wire)
      if beforeSend.receivedIDs.contains(envelope.messageID.hex),
        let event = beforeSend.history.first(where: {
          $0.message.messageID == envelope.messageID.hex && $0.message.senderKeyID == localSenderID
        })
      {
        // A previous POST reached the relay and its echo was committed before retry.
        beforeSend.pendingOutbound.removeFirst()
        try save(beforeSend)
        sequences.append(event.sequence)
        continue
      }
      guard beforeSend.group?.recoveryRequired != true else {
        throw QntmError.invalid("Recover the group before retrying pending sends")
      }
      let sentMessage: Message
      do {
        sentMessage = try Messaging.decrypt(envelope, conversation: beforeSend.conversation)
        try authorizeSend(bodyType: sentMessage.bodyType, saved: beforeSend)
        var preview = beforeSend
        try applyTransition(sentMessage, to: &preview)
      } catch {
        let failure = FailedOutbound(
          messageID: envelope.messageID.hex, wire: wire, reason: String(describing: error))
        beforeSend.rejectFirstOutbound(failure)
        try save(beforeSend)
        continue
      }
      let sequence = try await relay.postMessage(
        conversationID: beforeSend.conversation.id, envelope: wire)
      // Receiving can run during the HTTP request. Re-read the committed state.
      var saved = try conversation(cid)
      var controlError: String?
      if !saved.receivedIDs.contains(envelope.messageID.hex) {
        var transitioned = saved
        do {
          try apply(sentMessage, to: &transitioned)
          saved = transitioned
        } catch {
          controlError = String(describing: error)
          saved.rejected.append(
            RejectedEnvelope(
              sequence: sequence,
              reason: "Sent message state update failed: " + String(describing: error)))
        }
        saved.receivedIDs.insert(envelope.messageID.hex)
        try saved.recordHistory(sentMessage, sequence: sequence, deliver: false)
      }
      saved.pendingOutbound.removeAll { $0 == wire }
      try save(saved)
      sequences.append(sequence)
      if let controlError {
        throw QntmError.invalid(
          "Message was accepted by relay at sequence \(sequence), but local state changed: \(controlError)"
        )
      }
    }
    return sequences
  }
  public func receive(_ id: String) async throws -> [ReceiveEvent] {
    let saved = try conversation(id)
    let cid = saved.conversation.id.hex
    guard receiving.insert(cid).inserted else {
      throw QntmError.invalid("Conversation already has a receiver")
    }
    defer { receiving.remove(cid) }
    let relay = try DropboxClient(baseURL: profile.relayURL)
    let batch = try await relay.receiveMessages(
      conversationID: saved.conversation.id, fromSequence: saved.cursor, identity: identity())
    for entry in batch.entries { try ingest(entry, conversationID: cid) }
    var latest = try conversation(cid)
    latest.cursor = max(latest.cursor, batch.sequence)
    try save(latest)
    return latest.pendingDelivery
  }
  public func acknowledge(_ id: String, eventIDs: Set<String>) throws {
    var saved = try conversation(id)
    saved.pendingDelivery.removeAll { eventIDs.contains($0.eventID) }
    try replayPending(&saved)
    try save(saved)
  }
  public func watch(
    _ id: String, onError: (@Sendable (String) async -> Void)? = nil,
    onEvent: @escaping @Sendable (ReceiveEvent) async throws -> Void
  ) async throws {
    let saved = try conversation(id)
    let cid = saved.conversation.id.hex
    guard receiving.insert(cid).inserted else {
      throw QntmError.invalid("Conversation already has a receiver")
    }
    defer { receiving.remove(cid) }
    let relay = try DropboxClient(baseURL: profile.relayURL)
    try await relay.subscribeMessages(
      conversationID: saved.conversation.id, identity: identity(),
      getCursor: {
        try await self.deliver(cid, onEvent: onEvent)
        return try await self.conversation(cid).cursor
      }, onError: onError,
      onMessage: { entry in
        try await self.ingest(entry, conversationID: cid)
        try await self.deliver(cid, onEvent: onEvent)
      })
  }
  private func deliver(_ id: String, onEvent: @Sendable (ReceiveEvent) async throws -> Void)
    async throws
  {
    while let event = try conversation(id).pendingDelivery.first {
      try await onEvent(event)
      try acknowledge(id, eventIDs: [event.eventID])
    }
  }
  private func decrypt(_ envelope: Envelope, saved: SavedConversation) throws -> Message {
    if let group = saved.group {
      return try GroupControls.decryptForReceive(
        envelope, conversation: saved.conversation, state: group)
    }
    return try Messaging.decrypt(envelope, conversation: saved.conversation)
  }
  private func apply(_ message: Message, to saved: inout SavedConversation) throws {
    var next = saved
    try applyTransition(message, to: &next)
    saved = next
  }

  private func applyTransition(_ message: Message, to saved: inout SavedConversation) throws {
    let bodyType = message.bodyType
    saved.historyKeys[message.senderKeyID.base64URL] = message.senderPublicKey
    if bodyType == Attachment.bodyType {
      _ = try Attachment.parse(message.body, context: AttachmentContext(message: message))
    }
    if GroupControls.bodyTypes.contains(bodyType) {
      guard let state = saved.group else {
        throw QntmError.invalid("Group control outside a group")
      }
      let authority = try saved.gateway.prepareGroupControl(
        message: message, conversation: saved.conversation, groupState: state)
      let result = try GroupControls.apply(
        message: message, conversation: saved.conversation, identity: identity(), state: state,
        gatewayPublicKey: authority)
      saved.conversation = result.conversation
      saved.group = result.state
      saved.members = Dictionary(
        uniqueKeysWithValues: (result.state.roster?.orderedMembers ?? []).map {
          ($0.keyID.base64URL, $0.publicKey)
        })
      try saved.gateway.updateMembership(
        participants: saved.members, epoch: saved.conversation.currentEpoch)
      if bodyType == "group_rekey", !result.state.recoveryRequired {
        saved.lastRekeyID = message.envelope.messageID
      }
    } else if bodyType.hasPrefix("gate.") || bodyType.hasPrefix("gov.") {
      let previousMembers = saved.gateway.participants
      _ = try saved.gateway.receive(
        message: message, conversation: saved.conversation, groupState: saved.group)
      if saved.gateway.accepted {
        saved.members = saved.gateway.participants
        if saved.conversation.type == .direct, saved.group == nil {
          guard let anchor = saved.conversation.participants.first else {
            throw QntmError.invalid("Missing direct conversation anchor")
          }
          saved.group = try GroupControlState(
            gatewayParticipants: saved.members, anchorKeyID: anchor)
        }
        saved.conversation.participants = try saved.members.keys.sorted().map {
          try Data.fromBase64URL($0)
        }
        if previousMembers != saved.members { saved.group?.markNeedsRekey() }
      }
    } else if saved.gateway.accepted {
      guard
        saved.gateway.participants[message.senderKeyID.base64URL] == message.senderPublicKey
          || saved.gateway.context?.gatewayPublicKey == message.senderPublicKey
      else { throw QntmError.invalid("Message sender is outside the gateway conversation") }
    } else if let roster = saved.group?.roster {
      guard roster.isMember(message.senderKeyID), saved.group?.removed != true else {
        throw QntmError.invalid("Message sender is outside the current group")
      }
    } else if saved.conversation.type == .direct {
      saved.members[message.senderKeyID.base64URL] = message.senderPublicKey
      if !saved.conversation.participants.contains(message.senderKeyID) {
        saved.conversation.participants.append(message.senderKeyID)
      }
      try saved.gateway.updateMembership(
        participants: saved.members, epoch: saved.conversation.currentEpoch)
    } else {
      throw QntmError.invalid("Authenticated group roster is required")
    }
  }
  private func ingest(_ entry: SubscriptionMessage, conversationID: String) throws {
    var saved = try conversation(conversationID)
    guard entry.sequence > saved.cursor else { return }
    guard saved.pendingDelivery.count < 10_000 else {
      throw QntmError.invalid(
        "Receive delivery queue is full; acknowledge events before continuing")
    }
    do {
      let envelope = try Envelope(serialized: entry.envelope)
      guard envelope.conversationID == saved.conversation.id else {
        throw QntmError.invalid("Wrong conversation in relay delivery")
      }
      if !saved.receivedIDs.contains(envelope.messageID.hex) {
        if envelope.epoch > saved.conversation.currentEpoch {
          try saved.retainFuture(envelope, entry: entry)
        } else {
          let message = try decrypt(envelope, saved: saved)
          try apply(message, to: &saved)
          try saved.recordHistory(message, sequence: entry.sequence, deliver: true)
          saved.receivedIDs.insert(envelope.messageID.hex)
          try replayPending(&saved)
        }
      }
    } catch is RekeyUnwrapError {
      saved.group?.quarantine()
      saved.rejected.append(
        RejectedEnvelope(sequence: entry.sequence, reason: "Rekey requires recovery"))
    } catch {
      // Retain invalid delivery evidence without allowing it to poison subsequent messages.
      saved.rejected.append(
        RejectedEnvelope(sequence: entry.sequence, reason: String(describing: error)))
    }
    if saved.rejected.count > 1024 { saved.rejected.removeFirst(saved.rejected.count - 1024) }
    saved.cursor = entry.sequence
    try save(saved)
  }
  private func replayPending(_ saved: inout SavedConversation) throws {
    var waiting: [SavedEnvelope] = []
    let now = unixSeconds()
    for entry in saved.pendingInbound where entry.expiresAt >= now {
      if saved.pendingDelivery.count >= 10_000 || saved.group?.recoveryRequired == true {
        waiting.append(entry)
        continue
      }
      let envelope = try Envelope(serialized: entry.wire)
      if envelope.epoch > saved.conversation.currentEpoch {
        waiting.append(entry)
        continue
      }
      do {
        let message = try decrypt(envelope, saved: saved)
        if saved.receivedIDs.contains(envelope.messageID.hex) { continue }
        try apply(message, to: &saved)
        try saved.recordHistory(message, sequence: entry.sequence, deliver: true)
        saved.receivedIDs.insert(envelope.messageID.hex)
      } catch is RekeyUnwrapError {
        saved.group?.quarantine()
        saved.rejected.append(
          RejectedEnvelope(sequence: entry.sequence, reason: "Rekey requires recovery"))
      } catch {
        saved.rejected.append(
          RejectedEnvelope(sequence: entry.sequence, reason: String(describing: error)))
      }
    }
    saved.pendingInbound = waiting
  }
  public func rekey(_ id: String) async throws -> Envelope {
    let saved = try conversation(id)
    guard let roster = saved.group?.roster, !saved.gateway.accepted else {
      throw QntmError.invalid("Ordinary group roster required; gateway membership uses governance")
    }
    let body = try GroupBodies.rekey(conversation: saved.conversation, roster: roster).body
    return try await send(id, bodyType: "group_rekey", body: body)
  }
  public func addMembers(_ id: String, publicKeys: [Data]) async throws -> [String: String] {
    let initial = try conversation(id)
    guard initial.group?.creatorKeyID == (try identity()).keyID, !initial.gateway.accepted else {
      throw QntmError.invalid("Only the ordinary group creator can add members and issue welcomes")
    }
    _ = try await send(
      id, bodyType: "group_add", body: GroupBodies.add(identity: identity(), publicKeys: publicKeys)
    )
    let envelope = try await rekey(id)
    let saved = try conversation(id)
    guard let roster = saved.group?.roster else { throw QntmError.invalid("Missing group roster") }
    var invitations: [String: String] = [:]
    for key in publicKeys {
      invitations[key.base64URL] = try GroupBootstrap.create(
        identity: identity(), conversation: saved.conversation, state: roster,
        recipientPublicKey: key, rekeyID: envelope.messageID)
    }
    return invitations
  }
  public func removeMembers(_ id: String, keyIDs: [Data], reason: String = "") async throws {
    _ = try await send(
      id, bodyType: "group_remove", body: GroupBodies.remove(keyIDs: keyIDs, reason: reason))
    _ = try await rekey(id)
  }
  public func downloadAttachment(_ id: String, messageID: String) async throws -> Data {
    let saved = try conversation(id)
    guard let event = saved.history.first(where: { $0.message.messageID == messageID }),
      [Attachment.bodyType, "blobref"].contains(event.message.bodyType),
      let text = event.message.unsafeBody
    else { throw QntmError.invalid("Attachment message not found") }
    let body = Data(text.utf8)
    let relay = try DropboxClient(baseURL: profile.relayURL)
    let context: AttachmentContext
    if let epoch = saved.attachmentEpochs?[messageID] {
      let senderID = try Data(hex: event.message.senderKeyID).base64URL
      guard let sender = saved.historyKeys[senderID] ?? saved.members[senderID] else {
        throw QntmError.invalid("Attachment sender key unavailable")
      }
      context = try AttachmentContext(
        conversationID: saved.conversation.id, epoch: epoch, senderPublicKey: sender)
    } else {
      // Older profiles kept the accepted body and sequence, but omitted the envelope epoch.
      guard event.sequence > 0 else { throw QntmError.invalid("Invalid attachment sequence") }
      let batch = try await relay.receiveMessages(
        conversationID: saved.conversation.id,
        fromSequence: event.sequence - 1, identity: identity())
      guard let entry = batch.entries.first(where: { $0.sequence == event.sequence }) else {
        throw QntmError.invalid(
          "Original attachment envelope unavailable; ask the sender to resend")
      }
      let envelope = try Envelope(serialized: entry.envelope)
      let source =
        envelope.epoch == saved.conversation.currentEpoch
        ? saved.conversation : saved.group?.historicalSource(epoch: envelope.epoch)
      guard let source else { throw QntmError.invalid("Original attachment epoch key unavailable") }
      let message = try Messaging.decrypt(envelope, conversation: source, allowExpired: true)
      guard try ReceiveEvent(message: message, sequence: entry.sequence) == event else {
        throw QntmError.invalid("Original attachment envelope differs from saved history")
      }
      context = try AttachmentContext(message: message)
      var latest = try conversation(saved.conversation.id.hex)
      latest.rememberAttachment(message)
      try save(latest)
    }
    return try await Attachment.download(body, context: context, relay: relay)
  }
  public func sendAttachment(
    _ id: String, data: Data, name: String, mediaType: String = "application/octet-stream"
  ) async throws -> Envelope {
    let saved = try conversation(id)
    try authorizeSend(bodyType: Attachment.bodyType, saved: saved)
    let identity = try identity()
    let prepared = try Attachment.prepare(
      identity: identity, parent: saved.conversation, data: data, name: name, mediaType: mediaType)
    try await Attachment.upload(
      prepared,
      context: AttachmentContext(
        conversationID: saved.conversation.id, epoch: saved.conversation.currentEpoch,
        senderPublicKey: identity.publicKey), relay: DropboxClient(baseURL: profile.relayURL))
    guard try conversation(id).conversation.currentEpoch == saved.conversation.currentEpoch else {
      throw QntmError.invalid("Group changed during upload; prepare attachment again")
    }
    return try await send(id, bodyType: Attachment.bodyType, body: prepared.body)
  }
}

extension QntmClient {
  public func gatewayContext(_ id: String) throws -> GatewayContext {
    let saved = try conversation(id)
    guard saved.gateway.accepted, let context = saved.gateway.context else {
      throw QntmError.invalid("Gateway has not accepted this conversation")
    }
    try context.validate()
    return context
  }
  public func promoteGateway(_ id: String, gatewayURL: URL, threshold: UInt64) async throws
    -> GatewayInvitation
  {
    let service = try GateClient(baseURL: gatewayURL)
    let identity = try identity()
    let invitation = try await service.createInvitation(identity: identity)
    let saved = try conversation(id)
    let body = try Gateway.createInvitationBody(
      invitation: invitation, conversation: saved.conversation, participants: saved.members,
      floor: threshold, groupCreatorKeyID: saved.group?.creatorKeyID)
    let envelope = try await send(id, bodyType: "gate.promote", body: body.encoded())
    guard
      let event = try conversation(id).history.last(where: {
        $0.message.messageID == envelope.messageID.hex
      })
    else { throw QntmError.invalid("Missing invitation send acknowledgment") }
    let bootstrap = try Gateway.sealBootstrap(
      identity: identity, invitation: invitation, conversation: saved.conversation,
      invitationMessageID: envelope.messageID, sequence: event.sequence)
    _ = try await service.promote(bootstrap)
    return invitation
  }
  public func sendGateway(_ id: String, body: GatewayBody) async throws -> Envelope {
    try await send(id, bodyType: body.type.rawValue, body: body.encoded())
  }
  public func vote(_ id: String, workflowID: String, approve: Bool, proposal: Bool = false)
    async throws -> Envelope
  {
    let saved = try conversation(id)
    let context = try gatewayContext(id)
    guard
      let subject = try Gateway.findSubject(
        events: saved.gateway.events, conversationID: context.conversationID, id: workflowID,
        proposal: proposal)
    else { throw QntmError.invalid("Verified workflow not found") }
    let vote = try Gateway.createVote(
      identity: identity(), context: context, subject: subject, approve: approve)
    return try await sendGateway(id, body: vote)
  }
  public func prepareGuidance(provider: GuidanceProvider, question: String, context: String = "")
    throws -> PreparedGuidance
  {
    let prepared = try Guidance.prepare(
      identity: identity(), provider: provider, question: question, context: context)
    let saved = try SavedConversation(
      conversation: prepared.replyConversation,
      members: [try identity().keyID.base64URL: identity().publicKey])
    try save(saved)
    return prepared
  }
}

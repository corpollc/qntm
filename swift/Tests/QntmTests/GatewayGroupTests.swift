import XCTest

@testable import Qntm

@MainActor final class GatewayGroupTests: XCTestCase {
  func testDelegatedControlRequiresExactVotesAndRekey() throws {
    let alice = try Identity()
    let bob = try Identity()
    let gateway = try Identity()
    let outsider = try Identity()
    let invite = try Invite(creator: alice, type: .group)
    let conversation = try invite.conversation()
    let roster = try GroupState(
      groupName: "governed", creator: alice, foundingMemberKeys: [bob.publicKey])
    let group = try GroupControlState(
      creatorKeyID: alice.keyID, roster: roster, requiresEpochBinding: true)
    let participants = [alice.keyID.base64URL: alice.publicKey, bob.keyID.base64URL: bob.publicKey]
    let context = try GatewayContext(
      conversationID: conversation.id.hex, epoch: 0, gatewayPublicKey: gateway.publicKey,
      participants: participants, floor: 2, rules: [ThresholdRule(m: 2)])
    let invitation = try GatewayInvitation(
      invitationID: String(repeating: "45", count: 16), inviterPublicKey: alice.publicKey,
      gatewayPublicKey: gateway.publicKey, expiresAt: unixSeconds() + 600)
    let body = try Gateway.createInvitationBody(
      invitation: invitation, conversation: conversation, participants: participants, floor: 2,
      groupCreatorKeyID: alice.keyID)
    let wire = try Gateway.createMessage(
      identity: alice, conversation: conversation, body: body, context: context)
    let promotion = try Messaging.decrypt(wire, conversation: conversation)
    var session = try GatewaySession(participants: participants)
    _ = try session.receive(message: promotion, conversation: conversation, groupState: group)
    let acceptance = try GatewayBody(
      type: "gate.accept",
      json: .object([
        ("type", .string("gate.accept")), ("invitation_id", .string(invitation.invitationID)),
        ("invitation_msg_id", .string(wire.messageID.hex)),
        ("invitation_hash", .string(QSPCrypto.hash(promotion.body).hex)),
        ("conv_id", .string(conversation.id.hex)), ("conv_epoch", .number(0)),
        ("gateway_kid", .string(context.gatewayKeyID)),
        ("gateway_public_key", .string(gateway.publicKey.base64URL)),
      ]))
    _ = try session.receive(
      message: Messaging.decrypt(
        Gateway.createMessage(
          identity: gateway, conversation: conversation, body: acceptance, context: context,
          references: GatewayReferences(invitation: promotion)), conversation: conversation),
      conversation: conversation, groupState: group)
    let proposal = try Governance.createProposal(
      identity: alice, context: context, change: .addMembers([outsider.publicKey]))
    _ = try session.receive(
      message: Messaging.decrypt(
        Gateway.createMessage(
          identity: alice, conversation: conversation, body: proposal, context: context),
        conversation: conversation), conversation: conversation, groupState: group)
    let add = try Messaging.decrypt(
      Messaging.create(
        identity: gateway, conversation: conversation, bodyType: "group_add",
        body: GroupBodies.add(identity: gateway, publicKeys: [outsider.publicKey])),
      conversation: conversation)
    XCTAssertThrowsError(
      try session.prepareGroupControl(message: add, conversation: conversation, groupState: group))
    let approval = try Gateway.createVote(
      identity: bob, context: context, subject: proposal, approve: true)
    _ = try session.receive(
      message: Messaging.decrypt(
        Gateway.createMessage(
          identity: bob, conversation: conversation, body: approval, context: context,
          references: GatewayReferences(proposal: proposal)), conversation: conversation),
      conversation: conversation, groupState: group)
    let unauthorized = try Messaging.decrypt(
      Messaging.create(
        identity: gateway, conversation: conversation, bodyType: "group_add",
        body: GroupBodies.add(identity: gateway, publicKeys: [Identity().publicKey])),
      conversation: conversation)
    XCTAssertThrowsError(
      try session.prepareGroupControl(
        message: unauthorized, conversation: conversation, groupState: group))
    let authority = try session.prepareGroupControl(
      message: add, conversation: conversation, groupState: group)
    XCTAssertEqual(authority, gateway.publicKey)
    let transition = try GroupControls.apply(
      message: add, conversation: conversation, identity: alice, state: group,
      gatewayPublicKey: authority)
    try session.updateMembership(
      participants: Dictionary(
        uniqueKeysWithValues: try XCTUnwrap(transition.state.roster).orderedMembers.map {
          ($0.keyID.base64URL, $0.publicKey)
        }), epoch: 0)
    XCTAssertThrowsError(
      try session.prepareGroupControl(
        message: add, conversation: conversation, groupState: transition.state))
    let restored = try JSONDecoder().decode(
      GatewaySession.self, from: JSONEncoder().encode(session))
    XCTAssertEqual(restored.participants.count, 3)
  }

  func testLiveGroupedGovernanceThroughDurableActor() async throws {
    try await runGovernanceJourney(type: .group)
  }
  func testLiveDirectGovernanceThroughDurableActor() async throws {
    try await runGovernanceJourney(type: .direct)
  }
  private func runGovernanceJourney(type: ConversationType) async throws {
    guard
      let gateway = ProcessInfo.processInfo.environment["QNTM_TEST_GATEWAY_URL"].flatMap(
        URL.init(string:)),
      let relay = ProcessInfo.processInfo.environment["QNTM_TEST_RELAY_URL"].flatMap(
        URL.init(string:))
    else { throw XCTSkip("Set local gateway and relay URLs") }
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let alice = try QntmClient(
      store: FileProfileStore(directory: directory.appendingPathComponent("alice")), relayURL: relay
    )
    let bob = try QntmClient(
      store: FileProfileStore(directory: directory.appendingPathComponent("bob")), relayURL: relay)
    let aliceID = try await alice.identity()
    let bobID = try await bob.identity()
    let charlie = try Identity()
    let initial = try await alice.createConversation(
      name: "governed", type: type, memberPublicKeys: [bobID.publicKey])
    let id = initial.conversation.id.hex
    _ = try await bob.join(XCTUnwrap(initial.conversation.inviteToken))
    _ = try await bob.receive(id)
    if type == .direct {
      _ = try await bob.send(id, body: Data("discover Bob".utf8))
      _ = try await alice.receive(id)
    }
    _ = try await alice.promoteGateway(id, gatewayURL: gateway, threshold: 2)
    var accepted = false
    for _ in 0..<100 {
      _ = try await alice.receive(id)
      _ = try await bob.receive(id)
      let a = try await alice.conversation(id)
      let b = try await bob.conversation(id)
      accepted = a.gateway.accepted && b.gateway.accepted
      if accepted { break }
      try await Task.sleep(for: .milliseconds(100))
    }
    XCTAssertTrue(accepted)
    let context = try await alice.gatewayContext(id)
    let proposal = try Governance.createProposal(
      identity: aliceID, context: context, change: .addMembers([charlie.publicKey]))
    _ = try await alice.send(id, bodyType: proposal.type.rawValue, body: proposal.encoded())
    _ = try await bob.receive(id)
    _ = try await bob.vote(
      id, workflowID: gateText(proposal["proposal_id"], "ID"), approve: true, proposal: true)
    for _ in 0..<100 {
      _ = try await alice.receive(id)
      _ = try await bob.receive(id)
      if try await alice.conversation(id).conversation.currentEpoch == 1 { break }
      try await Task.sleep(for: .milliseconds(100))
    }
    let added = try await alice.conversation(id)
    XCTAssertEqual(added.conversation.currentEpoch, 1, String(describing: added.rejected))
    XCTAssertEqual(added.group?.roster?.members.count, 3)
    XCTAssertEqual(added.gateway.participants.count, 3)
    let removal = try Governance.createProposal(
      identity: aliceID, context: XCTUnwrap(added.gateway.context),
      change: .removeMembers([bobID.keyID]))
    _ = try await alice.send(id, bodyType: removal.type.rawValue, body: removal.encoded())
    _ = try await bob.receive(id)
    _ = try await bob.vote(
      id, workflowID: gateText(removal["proposal_id"], "ID"), approve: true, proposal: true)
    for _ in 0..<100 {
      _ = try await alice.receive(id)
      _ = try await bob.receive(id)
      if try await alice.conversation(id).conversation.currentEpoch == 2 { break }
      try await Task.sleep(for: .milliseconds(100))
    }
    let removed = try await alice.conversation(id)
    let removedBob = try await bob.conversation(id)
    XCTAssertEqual(removed.conversation.currentEpoch, 2, String(describing: removed.rejected))
    XCTAssertEqual(removed.group?.roster?.members.count, 2)
    XCTAssertNil(removed.gateway.participants[bobID.keyID.base64URL])
    XCTAssertTrue(removedBob.group?.removed == true)
    do {
      _ = try await bob.send(id, body: Data("must not send".utf8))
      XCTFail("Removed member sent")
    } catch {}
    let restored = try JSONDecoder().decode(
      Profile.self, from: JSONEncoder().encode(await alice.snapshot()))
    try restored.validate()
    XCTAssertEqual(restored.conversations[id]?.conversation.currentEpoch, 2)
  }
}

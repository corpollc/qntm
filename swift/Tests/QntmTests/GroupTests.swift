import XCTest

@testable import Qntm

final class GroupTests: XCTestCase {
  let now: UInt64 = 1_780_000_000

  func fixture() throws -> (
    Identity, Identity, Identity, Conversation, GroupState, GroupControlState
  ) {
    let creator = try Identity(seed: Data(repeating: 1, count: 32))
    let member = try Identity(seed: Data(repeating: 2, count: 32))
    let stranger = try Identity(seed: Data(repeating: 3, count: 32))
    let conversation = try Invite(creator: creator, type: .group).conversation()
    let roster = try GroupState(
      groupName: "Test", creator: creator, foundingMemberKeys: [member.publicKey], now: now)
    let initial = try GroupControlState(creatorKeyID: creator.keyID)
    let envelope = try Messaging.create(
      identity: creator, conversation: conversation, bodyType: "group_genesis",
      body: GroupBodies.genesis(state: roster), now: now)
    let transition = try GroupControls.apply(
      message: Messaging.decrypt(envelope, conversation: conversation, now: now),
      conversation: conversation, identity: creator, state: initial, now: now)
    return (creator, member, stranger, transition.conversation, roster, transition.state)
  }

  func testGroupAuthorityAndAtomicity() throws {
    let (creator, member, stranger, conversation, roster, state) = try fixture()
    XCTAssertTrue(roster.isAdmin(creator.keyID))
    XCTAssertFalse(roster.isAdmin(member.keyID))
    let unauthorized = try Messaging.create(
      identity: member, conversation: conversation, bodyType: "group_add",
      body: GroupBodies.add(identity: member, publicKeys: [stranger.publicKey], now: now), now: now)
    XCTAssertThrowsError(
      try GroupControls.apply(
        message: Messaging.decrypt(unauthorized, conversation: conversation, now: now),
        conversation: conversation, identity: creator, state: state, now: now))
    XCTAssertEqual(state.roster, roster)
    let add = try Messaging.create(
      identity: creator, conversation: conversation, bodyType: "group_add",
      body: GroupBodies.add(identity: creator, publicKeys: [stranger.publicKey], now: now), now: now
    )
    let added = try GroupControls.apply(
      message: Messaging.decrypt(add, conversation: conversation, now: now),
      conversation: conversation, identity: creator, state: state, now: now)
    XCTAssertTrue(added.state.needsRekey)
    XCTAssertTrue(added.state.roster!.isMember(stranger.keyID))
    XCTAssertThrowsError(
      try GroupControls.apply(
        message: Messaging.decrypt(add, conversation: conversation, now: now),
        conversation: added.conversation, identity: creator, state: added.state, now: now))
    let removeCreator = try Messaging.create(
      identity: creator, conversation: conversation, bodyType: "group_remove",
      body: GroupBodies.remove(keyIDs: [creator.keyID], now: now), now: now)
    XCTAssertThrowsError(
      try GroupControls.apply(
        message: Messaging.decrypt(removeCreator, conversation: conversation, now: now),
        conversation: conversation, identity: member, state: state, now: now))
  }

  func testRekeyExcludesRemovedRecipientAndWelcomesOnlyAdmittedMember() throws {
    let (creator, member, stranger, conversation, _, state) = try fixture()
    let remove = try Messaging.create(
      identity: creator, conversation: conversation, bodyType: "group_remove",
      body: GroupBodies.remove(keyIDs: [member.keyID], now: now), now: now)
    let removed = try GroupControls.apply(
      message: Messaging.decrypt(remove, conversation: conversation, now: now),
      conversation: conversation, identity: creator, state: state, now: now)
    let rekey = try GroupBodies.rekey(conversation: conversation, roster: removed.state.roster!)
    let envelope = try Messaging.create(
      identity: creator, conversation: conversation, bodyType: "group_rekey", body: rekey.body,
      now: now)
    let result = try XCTUnwrap(
      GroupRekey.resolve(
        identity: member, source: conversation, roster: removed.state.roster!,
        wires: [envelope.serialize()], now: now))
    XCTAssertTrue(result.excluded)
    let updated = try GroupControls.apply(
      message: Messaging.decrypt(envelope, conversation: conversation, now: now),
      conversation: conversation, identity: creator, state: removed.state, now: now)
    XCTAssertEqual(updated.conversation.currentEpoch, 1)
    XCTAssertFalse(updated.state.needsRekey)
    XCTAssertThrowsError(
      try GroupBootstrap.create(
        identity: creator, conversation: updated.conversation, state: updated.state.roster!,
        recipientPublicKey: stranger.publicKey, rekeyID: envelope.messageID, issuedAt: now))
    XCTAssertThrowsError(
      try GroupBootstrap.create(
        identity: creator, conversation: updated.conversation, state: updated.state.roster!,
        recipientPublicKey: member.publicKey, rekeyID: envelope.messageID, issuedAt: now))
  }

  func testCurrentEpochBootstrapAndOldHistoryIsolation() throws {
    let (creator, member, stranger, original, roster, _) = try fixture()
    let rekey = try GroupBodies.rekey(conversation: original, roster: roster)
    let envelope = try Messaging.create(
      identity: creator, conversation: original, bodyType: "group_rekey", body: rekey.body, now: now
    )
    let current = try XCTUnwrap(
      GroupRekey.resolve(
        identity: creator, source: original, roster: roster,
        wires: [envelope.serialize()], now: now)?.conversation)
    let token = try GroupBootstrap.create(
      identity: creator, conversation: current, state: roster,
      recipientPublicKey: member.publicKey, rekeyID: envelope.messageID, issuedAt: now, ttl: 600)
    let routing = try GroupBootstrap.inspect(token)
    XCTAssertEqual(routing.creatorPublicKey, creator.publicKey)
    let joined = try GroupBootstrap.open(
      identity: member, token: token, conversationID: original.id,
      creatorPublicKey: creator.publicKey, now: now)
    XCTAssertEqual(joined.conversation.keys, current.keys)
    XCTAssertEqual(joined.state, roster)
    XCTAssertNil(joined.conversation.inviteToken)
    XCTAssertThrowsError(try GroupBootstrap.open(identity: stranger, token: token, now: now))
    XCTAssertThrowsError(
      try GroupBootstrap.open(
        identity: member, token: token, creatorPublicKey: stranger.publicKey, now: now))
    XCTAssertThrowsError(try GroupBootstrap.open(identity: member, token: token, now: now + 600))
    let old = try Messaging.create(
      identity: creator, conversation: original, bodyType: "text", body: Data("old".utf8), now: now)
    XCTAssertThrowsError(try Messaging.decrypt(old, conversation: joined.conversation, now: now))
    let fresh = try Messaging.create(
      identity: creator, conversation: current, bodyType: "text", body: Data("new".utf8), now: now)
    XCTAssertEqual(
      try Messaging.decrypt(fresh, conversation: joined.conversation, now: now).text, "new")
  }

  func testCompetingRekeysConvergeAndOldApplicationMessagesAreRejected() throws {
    let (creator, member, _, conversation, roster, initial) = try fixture()
    let candidates = try (0..<2).map { _ in
      try Messaging.create(
        identity: creator, conversation: conversation, bodyType: "group_rekey",
        body: GroupBodies.rekey(conversation: conversation, roster: roster).body, now: now)
    }.sorted { $0.messageID.lexicographicallyPrecedes($1.messageID) }
    let wires = try candidates.map { try $0.serialize() }
    let expected = try XCTUnwrap(
      GroupRekey.resolve(
        identity: member, source: conversation, roster: roster, wires: wires, now: now))
    XCTAssertEqual(
      try GroupRekey.resolve(
        identity: creator, source: conversation, roster: roster, wires: wires.reversed(), now: now)?
        .conversation?.keys,
      expected.conversation?.keys)
    let lateFirst = try GroupControls.apply(
      message: Messaging.decrypt(candidates[1], conversation: conversation, now: now),
      conversation: conversation, identity: member, state: initial, now: now)
    let lower = try GroupControls.decryptForReceive(
      candidates[0], conversation: lateFirst.conversation, state: lateFirst.state, now: now)
    let converged = try GroupControls.apply(
      message: lower, conversation: lateFirst.conversation, identity: member,
      state: lateFirst.state, now: now)
    XCTAssertEqual(converged.conversation.keys, expected.conversation?.keys)
    let removal = try Messaging.create(
      identity: creator, conversation: lateFirst.conversation, bodyType: "group_remove",
      body: GroupBodies.remove(keyIDs: [member.keyID]), now: now)
    let afterRemoval = try GroupControls.apply(
      message: Messaging.decrypt(removal, conversation: lateFirst.conversation, now: now),
      conversation: lateFirst.conversation, identity: creator, state: lateFirst.state, now: now)
    let rotation = try Messaging.create(
      identity: creator, conversation: afterRemoval.conversation,
      bodyType: "group_rekey",
      body: GroupBodies.rekey(
        conversation: afterRemoval.conversation,
        roster: XCTUnwrap(afterRemoval.state.roster)
      ).body, now: now)
    let afterRotation = try GroupControls.apply(
      message: Messaging.decrypt(rotation, conversation: afterRemoval.conversation, now: now),
      conversation: afterRemoval.conversation, identity: creator, state: afterRemoval.state,
      now: now)
    for latest in [afterRemoval, afterRotation] {
      let conflict = try GroupControls.apply(
        message: lower, conversation: latest.conversation,
        identity: creator, state: latest.state, now: now)
      XCTAssertTrue(conflict.state.recoveryRequired)
      XCTAssertEqual(conflict.conversation, latest.conversation)
      XCTAssertEqual(conflict.state.roster, latest.state.roster)
      XCTAssertEqual(conflict.state.needsRekey, latest.state.needsRekey)
    }
    let oldText = try Messaging.create(
      identity: creator, conversation: conversation, bodyType: "text", body: Data("late".utf8),
      now: now)
    XCTAssertThrowsError(
      try GroupControls.decryptForReceive(
        oldText, conversation: converged.conversation, state: converged.state, now: now))
  }

  func testDelegatedDirectMembershipHasNoInventedAdministratorOrImmutableCreator() throws {
    let alice = try Identity()
    let bob = try Identity()
    let gateway = try Identity()
    let conversation = try Invite(creator: alice).conversation()
    let state = try GroupControlState(
      gatewayParticipants: [
        alice.keyID.base64URL: alice.publicKey, bob.keyID.base64URL: bob.publicKey,
      ],
      anchorKeyID: alice.keyID)
    XCTAssertFalse(state.roster!.isAdmin(alice.keyID))
    let removal = try Messaging.create(
      identity: gateway, conversation: conversation, bodyType: "group_remove",
      body: GroupBodies.remove(keyIDs: [alice.keyID], now: now), now: now)
    let message = try Messaging.decrypt(removal, conversation: conversation, now: now)
    XCTAssertThrowsError(
      try GroupControls.apply(
        message: message, conversation: conversation, identity: bob, state: state, now: now))
    let removed = try GroupControls.apply(
      message: message, conversation: conversation, identity: bob,
      state: state, gatewayPublicKey: gateway.publicKey, now: now)
    XCTAssertFalse(removed.state.roster!.isMember(alice.keyID))
    try removed.state.roster!.validate()
    var rekeySource = conversation
    rekeySource.type = .group
    let rekey = try Messaging.create(
      identity: gateway, conversation: conversation, bodyType: "group_rekey",
      body: GroupBodies.rekey(conversation: rekeySource, roster: removed.state.roster!).body,
      now: now)
    let updated = try GroupControls.apply(
      message: Messaging.decrypt(rekey, conversation: conversation, now: now),
      conversation: conversation, identity: bob, state: removed.state,
      gatewayPublicKey: gateway.publicKey, now: now)
    XCTAssertEqual(updated.conversation.type, .direct)
    XCTAssertEqual(updated.conversation.currentEpoch, 1)
    try updated.conversation.validate()
    let next = try Messaging.create(
      identity: bob, conversation: updated.conversation, bodyType: "text",
      body: Data("current".utf8), now: now)
    XCTAssertEqual(
      try Messaging.decrypt(next, conversation: updated.conversation, now: now).text, "current")
  }

  func testSharedPythonAndTypeScriptBootstrapFixtures() throws {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent()
    for language in ["python", "typescript"] {
      let data = try Data(
        contentsOf: root.appendingPathComponent("client/tests/group-bootstrap-\(language).json"))
      let fixture = try JSONDecoder().decode(BootstrapFixture.self, from: data)
      let identity = try Identity(seed: Data(hex: fixture.member.privateKey).prefix(32))
      let id = try Data(hex: fixture.source.id)
      let joined = try GroupBootstrap.open(
        identity: identity, token: fixture.token, conversationID: id,
        creatorPublicKey: Data(hex: fixture.owner.publicKey), now: fixture.at + 1)
      XCTAssertEqual(joined.conversation.keys.root.hex, fixture.root, language)
      let source = try Conversation(
        id: id, type: .group,
        keys: ConversationKeys(root: Data(hex: fixture.source.keys.root), conversationID: id))
      let roster = try GroupState(snapshot: XCTUnwrap(Data(base64Encoded: fixture.roster_b64)))
      let wires = try fixture.wires.map { try XCTUnwrap(Data(base64Encoded: $0)) }
      for order in [wires, wires.reversed()] {
        let result = try XCTUnwrap(
          GroupRekey.resolve(
            identity: identity, source: source, roster: roster, wires: order,
            allowExpired: true, now: fixture.at + 1))
        XCTAssertEqual(result.envelope.messageID.hex, fixture.winner_id, language)
        XCTAssertEqual(result.conversation?.keys.root.hex, fixture.root, language)
      }
    }
  }
}

private struct BootstrapFixture: Decodable {
  struct Person: Decodable {
    let privateKey: String
    let publicKey: String
  }
  struct Source: Decodable {
    struct Keys: Decodable { let root: String }
    let id: String
    let keys: Keys
  }
  let at: UInt64
  let owner: Person
  let member: Person
  let token: String
  let source: Source
  let roster_b64: String
  let wires: [String]
  let winner_id: String
  let root: String
}

import XCTest

@testable import Qntm

@MainActor final class ProfileRecoveryTests: XCTestCase {
  func testRecoveryRetainsHistoryAndCursorAndRejectsAuthorityRollback() async throws {
    let creator = try Identity()
    let member = try Identity()
    let impostor = try Identity()
    let original = try Invite(creator: creator, type: .group).conversation()
    let roster = try GroupState(
      groupName: "Recovery", creator: creator, foundingMemberKeys: [member.publicKey])
    let epochOne = try epoch(original, number: 1)
    let initial = try saved(
      identity: member, creator: creator, conversation: epochOne, roster: roster)
    let store = RecoveryProfileStore(initial.profile)
    let client = try QntmClient(store: store)
    let current = try epoch(original, number: 2)
    let token = try GroupBootstrap.create(
      identity: creator, conversation: current, state: roster,
      recipientPublicKey: member.publicKey, rekeyID: Data(repeating: 128, count: 16))
    let restored = try await client.join(token)
    XCTAssertEqual(restored.conversation.keys, current.keys)
    XCTAssertEqual(restored.conversation.name, "Saved name")
    XCTAssertFalse(restored.group!.recoveryRequired)
    XCTAssertEqual(restored.cursor, 11)
    XCTAssertEqual(restored.history.map(\.eventID), [initial.event.eventID])
    XCTAssertEqual(restored.pendingDelivery.map(\.eventID), [initial.event.eventID])
    let oldToken = try GroupBootstrap.create(
      identity: creator, conversation: epochOne, state: roster,
      recipientPublicKey: member.publicKey, rekeyID: Data(repeating: 1, count: 16))
    do {
      _ = try await client.join(oldToken)
      XCTFail("Older epoch restored")
    } catch {}
    let falseRoster = try GroupState(
      groupName: "False", creator: impostor, foundingMemberKeys: [member.publicKey])
    let falseToken = try GroupBootstrap.create(
      identity: impostor, conversation: current, state: falseRoster,
      recipientPublicKey: member.publicKey, rekeyID: Data(repeating: 1, count: 16))
    do {
      _ = try await client.join(falseToken)
      XCTFail("Creator replaced")
    } catch {}
    let final = try await client.conversation(original.id.hex)
    XCTAssertEqual(final.group?.creatorKeyID, creator.keyID)
    XCTAssertEqual(final.conversation.keys, current.keys)
    let persisted = try XCTUnwrap(store.load())
    try persisted.validate()
    XCTAssertEqual(persisted.conversations[original.id.hex]?.cursor, 11)
  }

  func testSameEpochRecoverySelectsOnlyLowerCanonicalRekey() async throws {
    let creator = try Identity()
    let member = try Identity()
    let original = try Invite(creator: creator, type: .group).conversation()
    let roster = try GroupState(
      groupName: "Recovery", creator: creator, foundingMemberKeys: [member.publicKey])
    let first = try epoch(original, number: 1)
    var initial = try saved(identity: member, creator: creator, conversation: first, roster: roster)
      .profile
    initial.conversations[original.id.hex]?.lastRekeyID = Data(repeating: 100, count: 16)
    let client = try QntmClient(store: RecoveryProfileStore(initial))
    let competing = try epoch(original, number: 1)
    let higher = try GroupBootstrap.create(
      identity: creator, conversation: competing, state: roster,
      recipientPublicKey: member.publicKey, rekeyID: Data(repeating: 101, count: 16))
    do {
      _ = try await client.join(higher)
      XCTFail("Higher competing rekey won")
    } catch {}
    let lower = try GroupBootstrap.create(
      identity: creator, conversation: competing, state: roster,
      recipientPublicKey: member.publicKey, rekeyID: Data(repeating: 99, count: 16))
    let result = try await client.join(lower)
    XCTAssertEqual(result.conversation.keys, competing.keys)
    XCTAssertEqual(result.lastRekeyID, Data(repeating: 99, count: 16))
    XCTAssertFalse(result.group!.recoveryRequired)
  }

  private func epoch(_ source: Conversation, number: UInt32) throws -> Conversation {
    var result = source
    result.currentEpoch = number
    result.keys = try ConversationKeys(
      root: QSPCrypto.random(32), conversationID: source.id, epoch: number)
    return result
  }
  private func saved(
    identity: Identity, creator: Identity, conversation: Conversation, roster: GroupState
  ) throws -> (profile: Profile, event: ReceiveEvent) {
    var conversation = conversation
    conversation.name = "Saved name"
    var control = try GroupControlState(
      creatorKeyID: creator.keyID, roster: roster, requiresEpochBinding: true)
    control.quarantine()
    var saved = try SavedConversation(
      conversation: conversation, group: control,
      members: Dictionary(
        uniqueKeysWithValues: roster.orderedMembers.map { ($0.keyID.base64URL, $0.publicKey) }))
    let envelope = try Messaging.create(
      identity: creator, conversation: conversation, bodyType: "text", body: Data("saved".utf8))
    let event = try ReceiveEvent(
      message: Messaging.decrypt(envelope, conversation: conversation), sequence: 11)
    saved.history = [event]
    saved.pendingDelivery = [event]
    saved.cursor = 11
    var profile = try Profile(identity: identity)
    profile.conversations[conversation.id.hex] = saved
    return (profile, event)
  }
}

private final class RecoveryProfileStore: ProfileStore, @unchecked Sendable {
  private let lock = NSLock()
  private var profile: Profile
  init(_ profile: Profile) { self.profile = profile }
  func load() throws -> Profile? {
    lock.lock()
    defer { lock.unlock() }
    return profile
  }
  func save(_ profile: Profile) throws {
    lock.lock()
    defer { lock.unlock() }
    self.profile = profile
  }
}

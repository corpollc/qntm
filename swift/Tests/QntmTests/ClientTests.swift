import XCTest

@testable import Qntm

final class ClientTests: XCTestCase, @unchecked Sendable {
  func testPrivateAtomicStoreAndExclusiveLock() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try FileProfileStore(directory: directory)
    let identity = try Identity()
    let profile = try Profile(identity: identity)
    try store.save(profile)
    XCTAssertEqual(try store.load()?.identity, identity)
    XCTAssertThrowsError(try FileProfileStore(directory: directory))
    let attributes = try FileManager.default.attributesOfItem(
      atPath: directory.appendingPathComponent("profile.json").path)
    XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    let bad = directory.appendingPathComponent("symlink")
    try FileManager.default.createSymbolicLink(at: bad, withDestinationURL: directory)
    XCTAssertThrowsError(try FileProfileStore(directory: bad))
  }
  func testDurableClientGroupJourney() async throws {
    guard let address = ProcessInfo.processInfo.environment["QNTM_SWIFT_TEST_RELAY"],
      let relay = URL(string: address)
    else { throw XCTSkip("Set QNTM_SWIFT_TEST_RELAY for local Worker journey") }
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let alice = try QntmClient(
      store: FileProfileStore(directory: directory.appendingPathComponent("alice")), relayURL: relay
    )
    let bob = try QntmClient(
      store: FileProfileStore(directory: directory.appendingPathComponent("bob")), relayURL: relay)
    let charlie = try QntmClient(
      store: FileProfileStore(directory: directory.appendingPathComponent("charlie")),
      relayURL: relay)
    let bobID = try await bob.identity()
    let charlieID = try await charlie.identity()
    let group = try await alice.createConversation(
      name: "test", type: .group, memberPublicKeys: [bobID.publicKey])
    let cid = group.conversation.id.hex
    _ = try await bob.join(XCTUnwrap(group.conversation.inviteToken))
    _ = try await bob.receive(cid)
    _ = try await bob.send(cid, body: Data("before admission".utf8))
    _ = try await alice.receive(cid)
    let welcomes = try await alice.addMembers(cid, publicKeys: [charlieID.publicKey])
    _ = try await bob.receive(cid)
    _ = try await charlie.join(XCTUnwrap(welcomes[charlieID.publicKey.base64URL]))
    _ = try await charlie.receive(cid)
    let charlieBefore = try await charlie.conversation(cid)
    XCTAssertFalse(charlieBefore.history.contains { $0.message.unsafeBody == "before admission" })
    _ = try await bob.send(cid, body: Data("after admission".utf8))
    let received = try await charlie.receive(cid)
    XCTAssertTrue(received.contains { $0.message.unsafeBody == "after admission" })
    try await charlie.acknowledge(cid, eventIDs: Set(received.map(\.eventID)))
    let empty = try await charlie.receive(cid)
    XCTAssertTrue(empty.isEmpty)
    try await alice.removeMembers(cid, keyIDs: [bobID.keyID])
    _ = try await bob.receive(cid)
    do {
      _ = try await bob.send(cid, body: Data("removed".utf8))
      XCTFail("Removed member sent")
    } catch {}
    _ = try await charlie.receive(cid)
    _ = try await charlie.send(cid, body: Data("still admitted".utf8))
    let aliceReceived = try await alice.receive(cid)
    XCTAssertTrue(aliceReceived.contains { $0.message.unsafeBody == "still admitted" })
    let state = try await alice.conversation(cid)
    XCTAssertEqual(state.conversation.currentEpoch, 2)
    let restored = try JSONDecoder().decode(
      Profile.self, from: JSONEncoder().encode(await alice.snapshot()))
    try restored.validate()
    XCTAssertEqual(restored.conversations[cid]?.conversation.currentEpoch, 2)
  }
}

private final class FailingProfileStore: ProfileStore, @unchecked Sendable {
  private let lock = NSLock()
  private var profile: Profile?
  private var fail = false
  func failNextSave() {
    lock.lock()
    defer { lock.unlock() }
    fail = true
  }
  func load() throws -> Profile? {
    lock.lock()
    defer { lock.unlock() }
    return profile
  }
  func save(_ value: Profile) throws {
    lock.lock()
    defer { lock.unlock() }
    if fail {
      fail = false
      throw QntmError.invalid("Injected disk failure")
    }
    profile = value
  }
}
private actor DeliveryAttempts {
  var attempts = 0
  func next() -> Int {
    attempts += 1
    return attempts
  }
}
extension ClientTests {
  func testStoreFailureDoesNotAcknowledgeAndWatchRetriesDelivery() async throws {
    guard let address = ProcessInfo.processInfo.environment["QNTM_SWIFT_TEST_RELAY"],
      let url = URL(string: address)
    else { throw XCTSkip("Set QNTM_SWIFT_TEST_RELAY") }
    let store = FailingProfileStore()
    let receiver = try QntmClient(store: store, relayURL: url)
    let sender = try Identity()
    let invite = try Invite(creator: sender)
    let conversation = try invite.conversation()
    _ = try await receiver.join(invite.token())
    let relay = try DropboxClient(baseURL: url)
    let envelope = try Messaging.create(
      identity: sender, conversation: conversation, bodyType: "text", body: Data("retry me".utf8))
    _ = try await relay.postMessage(conversationID: conversation.id, envelope: envelope.serialize())
    store.failNextSave()
    do {
      _ = try await receiver.receive(conversation.id.hex)
      XCTFail("Injected failure must surface")
    } catch {}
    let before = try await receiver.conversation(conversation.id.hex)
    XCTAssertEqual(before.cursor, 0)
    let delivery = try await receiver.receive(conversation.id.hex)
    XCTAssertEqual(delivery.count, 1)
    let attempts = DeliveryAttempts()
    let delivered = expectation(description: "Durable callback retries")
    let watching = Task {
      try await receiver.watch(conversation.id.hex) { event in
        XCTAssertEqual(event.message.unsafeBody, "retry me")
        if await attempts.next() == 1 { throw QntmError.invalid("Consumer failed") }
        delivered.fulfill()
      }
    }
    await fulfillment(of: [delivered], timeout: 10)
    watching.cancel()
    _ = try? await watching.value
    let after = try await receiver.conversation(conversation.id.hex)
    XCTAssertTrue(after.pendingDelivery.isEmpty)
    XCTAssertEqual(after.history.count, 1)
  }
}

import XCTest

@testable import Qntm

final class AnnouncementTests: XCTestCase {
  func testOwnershipAndSignatures() throws {
    let channel = try AnnouncementChannel(name: "announcements")
    let restored = try AnnouncementChannel(serialized: channel.serialize())
    XCTAssertEqual(channel.master, restored.master)
    XCTAssertEqual(channel.conversation, restored.conversation)
    let subscriber = try Announcement.conversation(
      id: channel.conversation.id, inviteSecret: channel.inviteSecret)
    XCTAssertEqual(subscriber.keys, channel.conversation.keys)
    let signature = try Data(hex: Announcement.signRegistration(channel: channel))
    XCTAssertTrue(
      Announcement.verifyRegistration(
        masterPublicKey: channel.master.publicKey, name: channel.name,
        conversationID: channel.conversation.id, postingPublicKey: channel.posting.publicKey,
        signature: signature))
    XCTAssertFalse(
      Announcement.verifyRegistration(
        masterPublicKey: channel.master.publicKey, name: "changed",
        conversationID: channel.conversation.id, postingPublicKey: channel.posting.publicKey,
        signature: signature))
    XCTAssertThrowsError(
      try Announcement.signDeletion(master: Identity(), conversationID: channel.conversation.id))
  }

  @MainActor
  func testLocalRelayChannelLifecycle() async throws {
    guard let configured = ProcessInfo.processInfo.environment["QNTM_SWIFT_TEST_RELAY"],
      let url = URL(string: configured)
    else {
      throw XCTSkip("Set QNTM_SWIFT_TEST_RELAY to run announcement Worker tests")
    }
    let client = try AnnouncementClient(baseURL: url)
    let channel = try AnnouncementChannel(name: "swift-lifecycle")
    try await client.register(channel)
    let info = try await client.info(conversationID: channel.conversation.id)
    XCTAssertEqual(info.postingPublicKey, channel.posting.publicKey.base64URL)
    let message = try Messaging.create(
      identity: channel.posting, conversation: channel.conversation, bodyType: "text",
      body: Data("announcement".utf8))
    let sequence = try await client.post(envelope: message.serialize(), channel: channel)
    XCTAssertEqual(sequence, 1)
    do {
      _ = try await client.relay.postMessage(
        conversationID: channel.conversation.id, envelope: message.serialize())
      XCTFail("Unsigned post accepted")
    } catch {}
    let newPosting = try Identity()
    try await client.rotate(
      conversationID: channel.conversation.id, master: channel.master, newPosting: newPosting)
    let rotated = try AnnouncementChannel(
      name: channel.name, master: channel.master, posting: newPosting,
      inviteSecret: channel.inviteSecret)
    let second = try Messaging.create(
      identity: newPosting, conversation: rotated.conversation, bodyType: "text",
      body: Data("rotated".utf8))
    let secondSequence = try await client.post(envelope: second.serialize(), channel: rotated)
    XCTAssertEqual(secondSequence, 2)
    do {
      _ = try await client.post(envelope: second.serialize(), channel: channel)
      XCTFail("Old posting key accepted")
    } catch {}
    try await client.delete(conversationID: channel.conversation.id, master: channel.master)
    do {
      _ = try await client.info(conversationID: channel.conversation.id)
      XCTFail("Deleted channel remains open")
    } catch {}
    do {
      try await client.register(channel)
      XCTFail("Deleted channel tombstone reused")
    } catch {}
  }
}

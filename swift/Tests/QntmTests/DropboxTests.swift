import XCTest

@testable import Qntm

final class DropboxTests: XCTestCase {
  func testSubscriptionURLAndReceipt() throws {
    let identity = try Identity(seed: Data(repeating: 7, count: 32))
    let conversation = Data(repeating: 1, count: 16)
    let message = Data(repeating: 2, count: 16)
    let relay = try DropboxClient(
      baseURL: XCTUnwrap(URL(string: "https://example.com/old?secret=old#fragment")))
    let url = try relay.subscriptionURL(
      conversationID: conversation, fromSequence: 42, identity: identity)
    let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
    XCTAssertEqual(components.scheme, "wss")
    XCTAssertEqual(components.path, "/v1/subscribe")
    XCTAssertNil(components.fragment)
    XCTAssertEqual(components.queryItems?.map(\.name), ["conv_id", "from_seq", "pub_key"])
    XCTAssertThrowsError(
      try relay.subscriptionURL(conversationID: Data(), fromSequence: 0, identity: nil))
    XCTAssertThrowsError(
      try relay.subscriptionURL(
        conversationID: conversation, fromSequence: UInt64.max, identity: nil))
    let receipt = try ReadReceipt(
      identity: identity, conversationID: conversation, messageID: message,
      readTimestamp: 1_800_000_000_000)
    let signable =
      "qntm-receipt-v1|\(conversation.hex)|\(message.hex)|\(identity.keyID.hex)|1800000000000|1"
    XCTAssertTrue(
      QSPCrypto.verify(
        publicKey: identity.publicKey, message: Data(signable.utf8),
        signature: try Data.fromBase64URL(receipt.signature)))
    XCTAssertFalse(
      QSPCrypto.verify(
        publicKey: identity.publicKey, message: Data((signable + "x").utf8),
        signature: try Data.fromBase64URL(receipt.signature)))
    XCTAssertThrowsError(try DropboxClient(baseURL: XCTUnwrap(URL(string: "file:///tmp/relay"))))
  }
}

private actor DeliveryProbe {
  private(set) var attempts: [UInt64] = []
  private(set) var cursor: UInt64 = 0
  private var failed = false
  func receive(_ entry: SubscriptionMessage) throws {
    attempts.append(entry.sequence)
    if entry.sequence == 2 && !failed {
      failed = true
      throw QntmError.invalid("Simulated durable delivery failure")
    }
    cursor = entry.sequence
  }
}

extension DropboxTests {
  @MainActor
  func testLocalRelayRoundTripAndRecovery() async throws {
    guard let configured = ProcessInfo.processInfo.environment["QNTM_SWIFT_TEST_RELAY"],
      let url = URL(string: configured)
    else {
      throw XCTSkip("Set QNTM_SWIFT_TEST_RELAY to a local running relay Worker")
    }
    let relay = try DropboxClient(baseURL: url)
    let identity = try Identity()
    let conversation = try Invite(creator: identity).conversation()
    var sent: [Envelope] = []
    for number in 1...3 {
      let envelope = try Messaging.create(
        identity: identity, conversation: conversation, bodyType: "text",
        body: Data("Swift \(number)".utf8))
      let seq = try await relay.postMessage(
        conversationID: conversation.id, envelope: envelope.serialize())
      XCTAssertEqual(seq, UInt64(number))
      sent.append(envelope)
    }
    let replay = try await relay.receiveMessages(
      conversationID: conversation.id, identity: identity)
    XCTAssertEqual(replay.entries.map(\.sequence), [1, 2, 3])
    XCTAssertEqual(replay.sequence, 3)
    XCTAssertEqual(
      try Messaging.decrypt(Envelope(serialized: replay.messages[0]), conversation: conversation)
        .text, "Swift 1")
    let empty = try await relay.receiveMessages(conversationID: conversation.id, fromSequence: 3)
    XCTAssertTrue(empty.messages.isEmpty)
    XCTAssertEqual(empty.sequence, 3)
    let receipt = try ReadReceipt(
      identity: identity, conversationID: conversation.id, messageID: sent[0].messageID)
    let response = try await relay.submitReceipt(receipt)
    XCTAssertTrue(response.recorded)
    XCTAssertFalse(response.deleted)

    let attachment = try Attachment.prepare(
      identity: identity, parent: conversation, data: Data(repeating: 42, count: 33_000),
      name: "sample.bin")
    let context = try AttachmentContext(
      conversationID: conversation.id, epoch: conversation.currentEpoch,
      senderPublicKey: identity.publicKey)
    try await Attachment.upload(attachment, context: context, relay: relay)
    let downloaded = try await Attachment.download(attachment.body, context: context, relay: relay)
    XCTAssertEqual(downloaded, Data(repeating: 42, count: 33_000))

    let probe = DeliveryProbe()
    let watcher = Task {
      try await relay.subscribeMessages(
        conversationID: conversation.id, identity: identity,
        getCursor: { await probe.cursor }, onMessage: { try await probe.receive($0) })
    }
    for _ in 0..<100 {
      if await probe.cursor == 3 { break }
      try await Task.sleep(nanoseconds: 50_000_000)
    }
    watcher.cancel()
    do {
      try await watcher.value
      XCTFail("Subscription must throw cancellation")
    } catch is CancellationError {}
    let cursor = await probe.cursor
    let attempts = await probe.attempts
    XCTAssertEqual(cursor, 3)
    XCTAssertEqual(
      attempts, [1, 2, 2, 3], "Failed callback must replay before any later event is acknowledged")
  }
}

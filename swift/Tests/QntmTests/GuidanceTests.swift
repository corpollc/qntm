import XCTest

@testable import Qntm

final class GuidanceTests: XCTestCase {
  func testPublicProvidersMatchPinnedIntakeKeys() throws {
    XCTAssertEqual(Guidance.corpoProviders.count, 3)
    for provider in Guidance.corpoProviders {
      XCTAssertEqual(try provider.intakeConversation().id.hex, provider.conversationID)
    }
  }

  func testOnlyRecipientReadsQuestionAndReplyIsBoundToSender() throws {
    let now: UInt64 = 1_780_000_000
    let recipient = try Identity()
    let sender = try Identity()
    let outsider = try Identity()
    let invite = try Invite(creator: recipient)
    let provider = GuidanceProvider(
      id: "test", category: .ethical, name: "Test", offer: "Test guidance",
      recipientKeyID: recipient.keyID.hex, recipientPublicKey: recipient.publicKey.hex,
      conversationID: invite.conversationID.hex, intakeInvite: try invite.token(),
      relayURL: "https://relay.example")
    let prepared = try Guidance.prepare(
      identity: sender, provider: provider, question: " Question? ", context: " Context ", now: now)
    XCTAssertEqual(prepared.question, "Question?")
    XCTAssertNotEqual(prepared.requestID, provider.conversationID)
    let ordinary = try Messaging.decrypt(
      prepared.envelope, conversation: invite.conversation(), now: now)
    XCTAssertFalse(ordinary.text?.contains("Question?") ?? true)
    let opened = try Guidance.open(
      identity: recipient, provider: provider, envelope: prepared.envelope, now: now)
    let reviewed = try Guidance.inspectPrepared(
      identity: sender, provider: provider, envelope: prepared.envelope, now: now)
    XCTAssertEqual(reviewed.question, opened.question)
    XCTAssertEqual(reviewed.context, opened.context)
    XCTAssertEqual(reviewed.requestID, opened.requestID)
    XCTAssertThrowsError(
      try Guidance.inspectPrepared(
        identity: outsider, provider: provider, envelope: prepared.envelope, now: now))
    XCTAssertEqual(opened.question, "Question?")
    XCTAssertEqual(opened.context, "Context")
    XCTAssertEqual(opened.replyInvite.inviterPublicKey, sender.publicKey)
    XCTAssertEqual(opened.requestID, prepared.requestID)
    XCTAssertThrowsError(
      try Guidance.open(
        identity: outsider, provider: provider, envelope: prepared.envelope, now: now))
    XCTAssertThrowsError(
      try Guidance.prepare(identity: sender, provider: provider, question: " ", now: now))
    XCTAssertThrowsError(
      try Guidance.prepare(
        identity: sender, provider: provider, question: String(repeating: "a", count: 4001),
        now: now))
  }
}

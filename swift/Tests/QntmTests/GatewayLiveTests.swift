import XCTest

@testable import Qntm

@MainActor final class GatewayLiveTests: XCTestCase {
  func testLocalWorkerAdmissionApprovalAndExecution() async throws {
    guard let gatewayAddress = ProcessInfo.processInfo.environment["QNTM_TEST_GATEWAY_URL"],
      let relayAddress = ProcessInfo.processInfo.environment["QNTM_TEST_RELAY_URL"],
      let targetAddress = ProcessInfo.processInfo.environment["QNTM_TEST_GATEWAY_TARGET_URL"]
    else { throw XCTSkip("Set local gateway, relay and fixture target URLs") }
    let alice = try Identity()
    let bob = try Identity()
    let conversation = try Invite(creator: alice).conversation()
    let relay = try DropboxClient(baseURL: XCTUnwrap(URL(string: relayAddress)))
    let client = try GateClient(baseURL: XCTUnwrap(URL(string: gatewayAddress)))
    let invitation = try await client.createInvitation(identity: alice)
    let participants = [alice.keyID.base64URL: alice.publicKey, bob.keyID.base64URL: bob.publicKey]
    let context = try GatewayContext(
      conversationID: conversation.id.hex, epoch: 0, gatewayPublicKey: invitation.gatewayPublicKey,
      participants: participants, floor: 2, rules: [ThresholdRule(m: 2)])
    let promotion = try Gateway.createInvitationBody(
      invitation: invitation, conversation: conversation, participants: participants, floor: 2)
    let wire = try Gateway.createMessage(
      identity: alice, conversation: conversation, body: promotion, context: context)
    let seq = try await relay.postMessage(
      conversationID: conversation.id, envelope: wire.serialize())
    _ = try await client.promote(
      Gateway.sealBootstrap(
        identity: alice, invitation: invitation, conversation: conversation,
        invitationMessageID: wire.messageID, sequence: seq))
    var session = try GatewaySession(participants: participants)
    var cursor: UInt64 = 0
    let deadline = Date().addingTimeInterval(30)
    while !session.accepted && Date() < deadline {
      let batch = try await relay.receiveMessages(
        conversationID: conversation.id, fromSequence: cursor)
      for entry in batch.entries {
        _ = try session.receive(
          message: Messaging.decrypt(
            Envelope(serialized: entry.envelope), conversation: conversation),
          conversation: conversation)
      }
      cursor = batch.sequence
      if !session.accepted { try await Task.sleep(for: .milliseconds(100)) }
    }
    XCTAssertTrue(session.accepted)
    let secret = try Gateway.createSecret(
      identity: alice, context: context, service: "swift-local", value: Data("native-swift".utf8),
      allowedOrigins: [targetAddress], headerName: "X-Qntm-Demo", headerTemplate: "{value}")
    _ = try await relay.postMessage(
      conversationID: conversation.id,
      envelope: Gateway.createMessage(
        identity: alice, conversation: conversation, body: secret, context: context
      ).serialize())
    let request = try Gateway.createRequest(
      identity: alice, context: context, service: "swift-local", endpoint: "/", verb: "POST",
      targetURL: targetAddress + "/", payload: .object([("from", .string("swift"))]))
    _ = try await relay.postMessage(
      conversationID: conversation.id,
      envelope: Gateway.createMessage(
        identity: alice, conversation: conversation, body: request, context: context
      ).serialize())
    let approval = try Gateway.createVote(
      identity: bob, context: context, subject: request, approve: true)
    _ = try await relay.postMessage(
      conversationID: conversation.id,
      envelope: Gateway.createMessage(
        identity: bob, conversation: conversation, body: approval, context: context,
        references: GatewayReferences(request: request)
      ).serialize())
    var result: GatewayBody?
    let executionDeadline = Date().addingTimeInterval(30)
    while result == nil && Date() < executionDeadline {
      let batch = try await relay.receiveMessages(
        conversationID: conversation.id, fromSequence: cursor)
      for entry in batch.entries {
        if let event = try session.receive(
          message: Messaging.decrypt(
            Envelope(serialized: entry.envelope), conversation: conversation),
          conversation: conversation), event.body.type == .result
        {
          result = event.body
        }
      }
      cursor = batch.sequence
      if result == nil { try await Task.sleep(for: .milliseconds(100)) }
    }
    XCTAssertEqual(result?["status_code"]?.integer, 200)
    let response = try GatewayJSON(data: Data(XCTUnwrap(result?["body"]?.string).utf8))
    XCTAssertEqual(response["credential"]?.string, "native-swift")
    XCTAssertEqual(response["received"]?.string, #"{"from":"swift"}"#)
    let restored = try JSONDecoder().decode(
      GatewaySession.self, from: JSONEncoder().encode(session))
    XCTAssertEqual(
      try Gateway.scan(
        events: restored.events, context: XCTUnwrap(restored.context),
        id: gateText(request["request_id"], "ID"))?.status, .executed)
  }
}

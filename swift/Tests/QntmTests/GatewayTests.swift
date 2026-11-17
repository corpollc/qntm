import XCTest

@testable import Qntm

final class GatewayTests: XCTestCase {
  private var root: URL {
    URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent()
  }
  private func fixture(_ path: String) throws -> GatewayJSON {
    try GatewayJSON(data: Data(contentsOf: root.appendingPathComponent(path)))
  }
  private func setup() throws -> (Identity, Identity, Identity, Conversation, GatewayContext) {
    let alice = try Identity(seed: Data(repeating: 1, count: 32))
    let bob = try Identity(seed: Data(repeating: 2, count: 32))
    let gate = try Identity(seed: Data(repeating: 3, count: 32))
    let conversation = try Invite(creator: alice).conversation()
    let context = try GatewayContext(
      conversationID: conversation.id.hex, epoch: 0, gatewayPublicKey: gate.publicKey,
      participants: [alice.keyID.base64URL: alice.publicKey, bob.keyID.base64URL: bob.publicKey],
      floor: 2, rules: [ThresholdRule(m: 2)])
    return (alice, bob, gate, conversation, context)
  }
  func testOrderedJSONAndPayloadHash() throws {
    let raw = Data(
      #"{"z":1,"a":{"second":2,"first":1},"text":"/é","n":1e-7,"m":0.000001,"large":1e20}"#.utf8)
    let value = try GatewayJSON(data: raw)
    XCTAssertEqual(
      String(decoding: try value.encoded(), as: UTF8.self),
      #"{"z":1,"a":{"second":2,"first":1},"text":"/é","n":1e-7,"m":0.000001,"large":100000000000000000000}"#
    )
    XCTAssertThrowsError(try GatewayJSON(data: Data(#"{"a":1,"a":2}"#.utf8)))
    XCTAssertThrowsError(try GatewayJSON(data: Data("[1,]".utf8)))
    XCTAssertEqual(try Gateway.payloadHash(.null), QSPCrypto.hash(Data()))
  }
  func testSharedThresholdVectors() throws {
    for vector in try XCTUnwrap(fixture("specs/test-vectors/gateway-thresholds.json").array) {
      let rules = try ThresholdRule.parse(vector["rules"])
      let result = Gateway.lookupThreshold(
        rules: rules, service: try gateText(vector["service"], "service"),
        endpoint: try gateText(vector["endpoint"], "endpoint"),
        verb: try gateText(vector["verb"], "verb"), targetURL: vector["target_url"]?.string)
      if let index = vector["expected_index"]?.integer {
        XCTAssertEqual(result, rules[Int(index)], vector["name"]?.string ?? "")
      } else {
        XCTAssertNil(result)
      }
    }
  }
  func testSharedGovernanceNullAndAbsentHashes() throws {
    for vector in try XCTUnwrap(fixture("specs/test-vectors/governance-optional-fields.json").array)
    {
      let raw = try XCTUnwrap(vector["body"]).setting(
        "signer_kid", .string(Data(repeating: 1, count: 16).base64URL)
      ).setting("signature", .string(Data(repeating: 0, count: 64).base64URL))
      let body = try GatewayBody(type: "gov.propose", json: raw)
      XCTAssertEqual(try Governance.proposalHash(body).hex, vector["hash_hex"]?.string)
    }
  }
  func testRequestVoteWithdrawalAndWrongOuterSender() throws {
    let (alice, bob, _, conversation, context) = try setup()
    let request = try Gateway.createRequest(
      identity: alice, context: context, service: "httpbin", endpoint: "/anything", verb: "POST",
      targetURL: "https://httpbin.org/anything",
      payload: .object([("z", .number(2)), ("a", .string("hello"))]), requestID: "swift-request")
    let wire = try Gateway.createMessage(
      identity: alice, conversation: conversation, body: request, context: context)
    let requestEvent = try Gateway.decrypt(wire, conversation: conversation, context: context)
    let approval = try Gateway.createVote(
      identity: bob, context: context, subject: request, approve: true)
    let voteWire = try Gateway.createMessage(
      identity: bob, conversation: conversation, body: approval, context: context,
      references: GatewayReferences(request: request))
    let voteEvent = try Gateway.decrypt(
      voteWire, conversation: conversation, context: context,
      references: GatewayReferences(request: request))
    var history = [requestEvent, voteEvent, voteEvent]
    XCTAssertEqual(
      try Gateway.scan(events: history, context: context, id: "swift-request")?.status, .approved)
    XCTAssertEqual(
      try Gateway.scan(events: history, context: context, id: "swift-request")?.approvalCount, 2)
    let withdrawal = try Gateway.createVote(
      identity: bob, context: context, subject: request, approve: false)
    history.append(
      try Gateway.decrypt(
        Gateway.createMessage(
          identity: bob, conversation: conversation, body: withdrawal, context: context,
          references: GatewayReferences(request: request)), conversation: conversation,
        context: context, references: GatewayReferences(request: request)))
    XCTAssertEqual(
      try Gateway.scan(events: history, context: context, id: "swift-request")?.status, .pending)
    XCTAssertThrowsError(
      try Gateway.createMessage(
        identity: alice, conversation: conversation, body: approval, context: context,
        references: GatewayReferences(request: request)))
    var changed = context
    changed.participants.removeValue(forKey: bob.keyID.base64URL)
    XCTAssertEqual(
      try Gateway.scan(events: history, context: changed, id: "swift-request")?.status, .invalidated
    )
    let modified = try GatewayBody(
      type: "gate.request", json: request.json.setting("payload", .string("tampered")))
    XCTAssertThrowsError(try Gateway.assertRequest(modified, context: context))
  }
  func testAdmissionAndDurableReverification() throws {
    let (alice, bob, gate, conversation, context) = try setup()
    let invitation = try GatewayInvitation(
      invitationID: String(repeating: "12", count: 16), inviterPublicKey: alice.publicKey,
      gatewayPublicKey: gate.publicKey, expiresAt: unixSeconds() + 600)
    let promote = try Gateway.createInvitationBody(
      invitation: invitation, conversation: conversation, participants: context.participants,
      floor: 2)
    let promoteWire = try Gateway.createMessage(
      identity: alice, conversation: conversation, body: promote, context: context)
    let promoteMessage = try Messaging.decrypt(promoteWire, conversation: conversation)
    var session = try GatewaySession(participants: context.participants)
    _ = try session.receive(message: promoteMessage, conversation: conversation)
    XCTAssertFalse(session.accepted)
    let acceptance = try GatewayBody(
      type: "gate.accept",
      json: .object([
        ("type", .string("gate.accept")), ("invitation_id", .string(invitation.invitationID)),
        ("invitation_msg_id", .string(promoteWire.messageID.hex)),
        ("invitation_hash", .string(QSPCrypto.hash(promoteMessage.body).hex)),
        ("conv_id", .string(conversation.id.hex)), ("conv_epoch", .number(0)),
        ("gateway_kid", .string(context.gatewayKeyID)),
        ("gateway_public_key", .string(gate.publicKey.base64URL)),
      ]))
    let accepted = try Gateway.createMessage(
      identity: gate, conversation: conversation, body: acceptance, context: context,
      references: GatewayReferences(invitation: promoteMessage))
    _ = try session.receive(
      message: Messaging.decrypt(accepted, conversation: conversation), conversation: conversation)
    XCTAssertTrue(session.accepted)
    XCTAssertEqual(session.gatewayAuthorityPublicKey, gate.publicKey)
    let restored = try JSONDecoder().decode(
      GatewaySession.self, from: JSONEncoder().encode(session))
    XCTAssertEqual(restored.events, session.events)
    XCTAssertEqual(restored.participants[bob.keyID.base64URL], bob.publicKey)
    var stored = try XCTUnwrap(
      JSONSerialization.jsonObject(with: JSONEncoder().encode(session)) as? [String: Any])
    var records = try XCTUnwrap(stored["records"] as? [[String: Any]])
    var record = records[0]
    var signed = try XCTUnwrap(records[0]["signed"] as? [String: Any])
    signed["body"] = try promote.json.setting("floor", .number(1)).encoded().base64EncodedString()
    record["signed"] = signed
    records[0] = record
    stored["records"] = records
    XCTAssertThrowsError(
      try JSONDecoder().decode(
        GatewaySession.self, from: JSONSerialization.data(withJSONObject: stored)))
    let bootstrap = try Gateway.sealBootstrap(
      identity: alice, invitation: invitation, conversation: conversation,
      invitationMessageID: promoteWire.messageID, sequence: 4)
    let material = try GatewayJSON(
      data: QSPCrypto.openSecret(
        recipientPrivateKey: gate.privateKey, senderPublicKey: alice.publicKey,
        sealed: gateBytes(bootstrap["sealed"], "sealed")))
    XCTAssertEqual(material["conv_aead_key"]?.string, conversation.keys.aeadKey.base64URL)
  }
  func testOriginAndPathPolicy() throws {
    XCTAssertEqual(
      try Gateway.normalizeOrigin("https://API.OpenAI.com:443/"), "https://api.openai.com")
    XCTAssertEqual(try Gateway.normalizeOrigin("http://localhost:9090"), "http://localhost:9090")
    for target in [
      "https://127.0.0.1/", "https://10.0.0.1/", "https://[::ffff:127.0.0.1]/",
      "https://[64:ff9b::a00:1]/", "https://metadata.google.internal/",
      "https://example.com/a/../b", "https://example.com/%2e%2e/b", "https://user@example.com/",
      "http://example.com/", "https://2130706433/", "https://127.1/", "https://example.com/#x",
    ] { XCTAssertThrowsError(try Gateway.validateTargetURL(target), target) }
    XCTAssertTrue(Gateway.pathnameMatchesEndpoint("/api/v1/chat", endpoint: "/chat"))
    XCTAssertFalse(Gateway.pathnameMatchesEndpoint("/billing/chat", endpoint: "/chat"))
  }
}

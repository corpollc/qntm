import XCTest

@testable import Qntm

final class EntityTests: XCTestCase {
  func testSharedEntityVectorAndIdentifierBinding() throws {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let raw =
      try JSONSerialization.jsonObject(
        with: Data(
          contentsOf: root.appendingPathComponent("specs/test-vectors/entity-verification.json")))
      as! [String: Any]
    let vectors = try XCTUnwrap(raw["vectors"] as? [[String: Any]])
    for vector in vectors {
      let id = try XCTUnwrap(vector["entity_id"] as? String)
      let data = try JSONSerialization.data(withJSONObject: XCTUnwrap(vector["expected_response"]))
      let result = try EntityVerification(json: data, expectedEntityID: id)
      XCTAssertTrue(result.isActive)
      XCTAssertEqual(result.authorityCeiling, ["hold_assets"])
      XCTAssertThrowsError(try EntityVerification(json: data, expectedEntityID: "wrong"))
    }
    XCTAssertEqual(
      try Entity.verificationURL(entityID: "a/b?x=1").absoluteString,
      "https://api.corpo.llc/api/v1/entities/a%2Fb%3Fx%3D1/verify")
  }
  @MainActor
  func testSenderRequiresTrustedEntityAuthorization() async throws {
    let identity = try Identity()
    let did = try DID.fromPublicKey(identity.publicKey)
    let entity = try EntityVerification(
      json: Data(
        "{\"entity_id\":\"test\",\"name\":\"Test\",\"status\":\"active\",\"entity_type\":\"example\"}"
          .utf8), expectedEntityID: "test")
    let result = try await Entity.verifySender(
      senderKeyID: identity.keyID, did: did, entityID: "test",
      resolveDID: { try XCTUnwrap(DID.resolveKey($0).ed25519PublicKey) },
      lookupEntity: { _ in entity },
      verifyBinding: { _, key, _ in key == identity.publicKey })
    XCTAssertEqual(result.publicKey, identity.publicKey)
    do {
      _ = try await Entity.verifySender(
        senderKeyID: identity.keyID, did: did, entityID: "test",
        resolveDID: { _ in identity.publicKey }, lookupEntity: { _ in entity },
        verifyBinding: { _, _, _ in false })
      XCTFail("Unbound active entity accepted")
    } catch {}
    do {
      _ = try await Entity.verifySender(
        senderKeyID: Data(repeating: 0, count: 16), did: did, entityID: "test",
        resolveDID: { _ in identity.publicKey }, lookupEntity: { _ in entity },
        verifyBinding: { _, _, _ in true })
      XCTFail("Wrong sender accepted")
    } catch {}
  }
}

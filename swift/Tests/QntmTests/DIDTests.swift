import XCTest

@testable import Qntm

final class DIDTests: XCTestCase {
  func testSharedDIDVectors() throws {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let raw =
      try JSONSerialization.jsonObject(
        with: Data(
          contentsOf: root.appendingPathComponent("specs/test-vectors/did-resolution.json")))
      as! [String: Any]
    let vectors = try XCTUnwrap(raw["vectors"] as? [[String: Any]])
    for vector in vectors {
      guard let did = vector["did"] as? String else { continue }
      if let document = vector["did_document"] as? [String: Any] {
        let parsed = try DIDDocument(
          json: JSONSerialization.data(withJSONObject: document), expectedID: did)
        if let expected = vector["expected_public_key_hex"] as? String {
          XCTAssertEqual(parsed.ed25519PublicKey?.hex, expected)
        } else if vector["expected_error"] != nil {
          XCTAssertNil(parsed.ed25519PublicKey)
        }
      } else if did.hasPrefix("did:key:") {
        if vector["expected_error"] != nil {
          XCTAssertThrowsError(try DID.resolveKey(did))
        } else {
          let document = try DID.resolveKey(did)
          XCTAssertEqual(
            document.ed25519PublicKey?.hex, vector["expected_public_key_hex"] as? String)
          XCTAssertEqual(try DID.fromPublicKey(XCTUnwrap(document.ed25519PublicKey)), did)
        }
      }
    }
  }
  func testWebURLPolicyAndKeyEncodings() throws {
    XCTAssertEqual(
      try DID.webURL("did:web:example.com").absoluteString,
      "https://example.com/.well-known/did.json")
    XCTAssertEqual(
      try DID.webURL("did:web:example.com%3A8443:users:alice").absoluteString,
      "https://example.com:8443/users/alice/did.json")
    XCTAssertEqual(
      try DID.webURL("did:web:example.com:é").absoluteString, "https://example.com/%C3%A9/did.json")
    for did in [
      "did:web:localhost", "did:web:127.0.0.1", "did:web:10.1.2.3", "did:web:169.254.1.1",
      "did:web:192.168.1.1", "did:web:2130706433", "did:web:0x7f000001", "did:web:example.com:..",
      "did:web:example.com:%2Fetc", "did:web:example.com:%252f", "did:web:example.com:",
      "did:web:example.com%40evil.com", "did:web:example.com%3A0", "did:web:example.com%3A65536",
      "did:web:example.com%0a", "did:web:%5B%3A%3A1%5D", "did:web:%5B%3A%3Affff%3A127.0.0.1%5D",
      "did:web:%5B100%3A%3A1%5D", "did:web:%5B2001%3Adb8%3A%3A1%5D", "did:web:%5B2002%3A%3A1%5D",
      "did:web:192.0.2.1",
    ] {
      XCTAssertThrowsError(try DID.webURL(did), did)
    }
    let identity = try Identity()
    let json: [String: Any] = [
      "id": "did:web:example.com",
      "verificationMethod": [
        [
          "type": "Ed25519VerificationKey2018",
          "publicKeyJwk": [
            "kty": "OKP", "crv": "Ed25519", "x": identity.publicKey.base64URL + "=",
          ],
        ]
      ], "service": [["type": "Qntm", "serviceEndpoint": "https://example.com/qntm"]],
    ]
    let bytes = try JSONSerialization.data(withJSONObject: json)
    let document = try DIDDocument(json: bytes, expectedID: "did:web:example.com")
    XCTAssertEqual(document.ed25519PublicKey, identity.publicKey)
    XCTAssertEqual(document.serviceEndpoint(type: "Qntm"), "https://example.com/qntm")
    XCTAssertThrowsError(try DIDDocument(json: bytes, expectedID: "did:web:attacker.com"))
    XCTAssertThrowsError(try DID.base58Decode(String(repeating: "1", count: 65)))
  }
  @MainActor
  func testHTTPBoundsAndRedirects() async throws {
    guard let base = ProcessInfo.processInfo.environment["QNTM_SWIFT_TEST_IDENTITY_HTTP"],
      let url = URL(string: base)
    else {
      throw XCTSkip("Set QNTM_SWIFT_TEST_IDENTITY_HTTP to the local identity fixture server")
    }
    let data = try await IdentityDocumentRequest.read(
      url: url.appendingPathComponent("ok"), timeout: 3, accept: "application/json")
    XCTAssertEqual(String(decoding: data, as: UTF8.self), "{\"id\":\"example\"}")
    for path in ["redirect", "large", "stream-large"] {
      do {
        _ = try await IdentityDocumentRequest.read(
          url: url.appendingPathComponent(path), timeout: 3, accept: "application/json")
        XCTFail("Accepted \(path)")
      } catch {}
    }
  }
}

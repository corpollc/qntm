import XCTest

@testable import Qntm

final class CoreTests: XCTestCase {
  func testRoundTrip() throws {
    let alice = try Identity()
    let bob = try Identity()
    let invite = try Invite(creator: alice)
    let conv = try invite.conversation()
    let wire = try Messaging.create(
      identity: alice, conversation: conv, bodyType: "text", body: Data("hello".utf8))
    XCTAssertEqual(
      try Messaging.decrypt(Envelope(serialized: wire.serialize()), conversation: conv).text,
      "hello")
    let sealed = try QSPCrypto.sealSecret(
      senderPrivateKey: alice.privateKey, recipientPublicKey: bob.publicKey,
      plaintext: Data("secret".utf8))
    XCTAssertEqual(
      try QSPCrypto.openSecret(
        recipientPrivateKey: bob.privateKey, senderPublicKey: alice.publicKey, sealed: sealed),
      Data("secret".utf8))
  }
}

extension CoreTests {
  private func fixture(_ relative: String) throws -> [String: Any] {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    return try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent(relative)))
        as? [String: Any])
  }
  func testStrictSignatureSharedVectors() throws {
    let rows = try XCTUnwrap(
      fixture("specs/test-vectors/ed25519-verification.json")["cases"] as? [[String: Any]])
    for row in rows {
      let name = try XCTUnwrap(row["name"] as? String)
      let pk = try Data(hex: XCTUnwrap(row["public_key_hex"] as? String))
      XCTAssertEqual(QSPCrypto.isValidPublicKey(pk), row["key_valid"] as? Bool, name)
      XCTAssertEqual(
        QSPCrypto.verify(
          publicKey: pk, message: try Data(hex: XCTUnwrap(row["message_hex"] as? String)),
          signature: try Data(hex: XCTUnwrap(row["signature_hex"] as? String))),
        row["valid"] as? Bool, name)
    }
  }
  func testSharedCryptoVectors() throws {
    let v = try fixture("client/tests/vectors.json")
    func map(_ key: String) throws -> [String: String] {
      try XCTUnwrap(v[key] as? [String: String])
    }
    func bytes(_ m: [String: String], _ key: String) throws -> Data {
      try Data(hex: XCTUnwrap(m[key]))
    }
    let identity = try Identity(seed: Data(hex: XCTUnwrap(v["seed"] as? String)))
    let i = try map("identity_vectors")
    XCTAssertEqual(identity.publicKey.hex, i["public_key"])
    XCTAssertEqual(identity.keyID.hex, i["key_id"])
    XCTAssertEqual(try Identity(serialized: identity.serialize()), identity)
    let d = try map("key_derivation")
    let root = try QSPCrypto.hkdfExpand(
      key: QSPCrypto.hkdfExtract(salt: bytes(d, "invite_salt"), input: bytes(d, "invite_secret")),
      info: Data("qntm/qsp/v1/root".utf8) + bytes(d, "conv_id"))
    XCTAssertEqual(root.hex, d["root_key"])
    let keys = try ConversationKeys(root: root, conversationID: bytes(d, "conv_id"))
    XCTAssertEqual(keys.aeadKey.hex, d["aead_key"])
    XCTAssertEqual(keys.nonceKey.hex, d["nonce_key"])
    let s = try map("signing_vector")
    XCTAssertEqual(
      try QSPCrypto.sign(privateKey: identity.privateKey, message: bytes(s, "message")).hex,
      s["signature"])
    let h = try map("hash_vector")
    XCTAssertEqual(try QSPCrypto.hash(bytes(h, "input")).hex, h["output"])
    let n = try map("nonce_vector")
    XCTAssertEqual(
      try QSPCrypto.hmac(key: bytes(n, "nonce_key"), data: bytes(n, "msg_id")).prefix(24).hex,
      n["nonce"])
    let a = try map("aead_vector")
    XCTAssertEqual(
      try QSPCrypto.encrypt(
        key: bytes(a, "key"), nonce: bytes(a, "nonce"), plaintext: bytes(a, "plaintext"),
        aad: bytes(a, "aad")
      ).hex, a["ciphertext"])
  }
  func testCBORAndMalformedInputs() throws {
    XCTAssertEqual(try CBOR.decode(CBOR.text("\u{feff}x").encode()), .text("\u{feff}x"))
    let canonical = try CBOR.map(["bb": .unsigned(2), "a": .unsigned(1), "ccc": .unsigned(3)])
      .encode()
    XCTAssertEqual(canonical.hex, "a3616101626262026363636303")
    XCTAssertEqual(try CBOR.decode(canonical).encode(), canonical)
    for hex in ["a2616101616102", "0102", "5affffffff", "81", "61ff", "9f01ff"] {
      XCTAssertThrowsError(try CBOR.decode(Data(hex: hex)), hex)
    }
    XCTAssertThrowsError(try Data.fromBase64URL("AB"))
    XCTAssertThrowsError(try Identity(seed: Data(repeating: 0, count: 31)))
    let id = try Identity()
    var serialized = try XCTUnwrap(CBOR.decode(id.serialize()).mapValue)
    serialized["public_key"] = .bytes(QSPCrypto.random(32))
    XCTAssertThrowsError(try Identity(serialized: CBOR.map(serialized).encode()))
  }
  func testTimeBindingAndTampering() throws {
    let id = try Identity()
    let conv = try Invite(creator: id).conversation()
    let envelope = try Messaging.create(
      identity: id, conversation: conv, bodyType: "text", body: Data(), ttl: 10, now: 1_000)
    XCTAssertNoThrow(try Messaging.decrypt(envelope, conversation: conv, now: 1_010))
    XCTAssertThrowsError(try Messaging.decrypt(envelope, conversation: conv, now: 1_011))
    XCTAssertNoThrow(
      try Messaging.decrypt(envelope, conversation: conv, allowExpired: true, now: 1_011))
    var hinted = try XCTUnwrap(CBOR.decode(envelope.serialize()).mapValue)
    hinted["did"] = .text("did:web:untrusted.example")
    let hintedEnvelope = try Envelope(serialized: CBOR.map(hinted).encode(), now: 1_000)
    XCTAssertEqual(hintedEnvelope.untrustedDID, "did:web:untrusted.example")
    XCTAssertNoThrow(try Messaging.decrypt(hintedEnvelope, conversation: conv, now: 1_000))
    var map = try XCTUnwrap(CBOR.decode(envelope.serialize()).mapValue)
    map["conv_epoch"] = .unsigned(1)
    XCTAssertThrowsError(
      try Messaging.decrypt(
        Envelope(serialized: CBOR.map(map).encode(), now: 1_000), conversation: conv, now: 1_000))
    var ciphertext = envelope.ciphertext
    ciphertext[0] ^= 1
    map["conv_epoch"] = .unsigned(0)
    map["ciphertext"] = .bytes(ciphertext)
    XCTAssertThrowsError(
      try Messaging.decrypt(
        Envelope(serialized: CBOR.map(map).encode(), now: 1_000), conversation: conv, now: 1_000))
    XCTAssertThrowsError(
      try Messaging.create(identity: id, conversation: conv, bodyType: "text", body: Data(), ttl: 0)
    )
    let invite = try Invite(creator: id)
    let url = try invite.url(base: XCTUnwrap(URL(string: "https://example.test/?invite=old")))
    XCTAssertNil(URLComponents(url: url, resolvingAgainstBaseURL: false)?.query)
    XCTAssertEqual(try Invite(tokenOrURL: url.absoluteString).serialize(), try invite.serialize())
  }
}

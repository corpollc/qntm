import Clibsodium
import Foundation

/// Native libsodium primitives with the qntm strict signing-key profile.
public enum QSPCrypto {
  private static let initialized: Bool = sodium_init() >= 0
  private static let identityPoint: [UInt8] = [1] + Array(repeating: 0, count: 31)
  private static let order: [UInt8] =
    [
      0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
      0x14,
    ] + Array(repeating: 0, count: 15) + [0x10]

  public static func random(_ count: Int) -> Data {
    precondition(initialized && count >= 0)
    var bytes = [UInt8](repeating: 0, count: count)
    randombytes_buf(&bytes, count)
    return Data(bytes)
  }
  public static func hash(_ data: Data) -> Data {
    var output = [UInt8](repeating: 0, count: 32)
    crypto_hash_sha256(&output, Array(data), UInt64(data.count))
    return Data(output)
  }
  public static func hmac(key: Data, data: Data) -> Data {
    var state = crypto_auth_hmacsha256_state()
    var output = [UInt8](repeating: 0, count: 32)
    crypto_auth_hmacsha256_init(&state, Array(key), key.count)
    crypto_auth_hmacsha256_update(&state, Array(data), UInt64(data.count))
    crypto_auth_hmacsha256_final(&state, &output)
    return Data(output)
  }
  public static func hkdfExtract(salt: Data, input: Data) -> Data { hmac(key: salt, data: input) }
  public static func hkdfExpand(key: Data, info: Data, count: Int = 32) throws -> Data {
    guard count >= 0, count <= 255 * 32 else { throw QntmError.invalid("HKDF output length") }
    var output = Data()
    var previous = Data()
    for i in 0..<((count + 31) / 32) {
      previous = hmac(key: key, data: previous + info + Data([UInt8(i + 1)]))
      output += previous
    }
    return output.prefix(count)
  }
  static func identity(seed: Data) throws -> (publicKey: Data, privateKey: Data) {
    guard initialized, seed.count == 32 else {
      throw QntmError.invalid("Identity seed must be 32 bytes")
    }
    var pk = [UInt8](repeating: 0, count: 32)
    var sk = [UInt8](repeating: 0, count: 64)
    guard crypto_sign_seed_keypair(&pk, &sk, Array(seed)) == 0 else {
      throw QntmError.crypto("Identity generation failed")
    }
    return (Data(pk), Data(sk))
  }
  public static func isValidPublicKey(_ key: Data) -> Bool {
    guard key.count == 32, crypto_core_ed25519_is_valid_point(Array(key)) == 1 else { return false }
    var scalar = order
    scalar[0] -= 1
    var multiple = [UInt8](repeating: 0, count: 32)
    var sum = multiple
    return crypto_scalarmult_ed25519_noclamp(&multiple, scalar, Array(key)) == 0
      && crypto_core_ed25519_add(&sum, multiple, Array(key)) == 0 && sum == identityPoint
  }
  public static func sign(privateKey: Data, message: Data) throws -> Data {
    guard privateKey.count == 64 else { throw QntmError.invalid("Signing key must be 64 bytes") }
    let pair = try identity(seed: privateKey.prefix(32))
    guard pair.privateKey == privateKey else {
      throw QntmError.invalid("Signing key public half mismatch")
    }
    var signature = [UInt8](repeating: 0, count: 64)
    guard
      crypto_sign_detached(
        &signature, nil, Array(message), UInt64(message.count), Array(privateKey)) == 0
    else { throw QntmError.crypto("Signing failed") }
    return Data(signature)
  }
  public static func verify(publicKey: Data, message: Data, signature: Data) -> Bool {
    guard isValidPublicKey(publicKey), signature.count == 64 else { return false }
    let r = Array(signature.prefix(32))
    let s = Array(signature.suffix(32))
    guard r == identityPoint || isValidPublicKey(Data(r)),
      s.reversed().lexicographicallyPrecedes(order.reversed())
    else { return false }
    let input = Data(r) + publicKey + message
    var digest = [UInt8](repeating: 0, count: 64)
    var k = [UInt8](repeating: 0, count: 32)
    crypto_hash_sha512(&digest, Array(input), UInt64(input.count))
    crypto_core_ed25519_scalar_reduce(&k, digest)
    var sb = identityPoint
    var ka = identityPoint
    var expected = identityPoint
    if s.contains(where: { $0 != 0 }), crypto_scalarmult_ed25519_base_noclamp(&sb, s) != 0 {
      return false
    }
    if k.contains(where: { $0 != 0 }),
      crypto_scalarmult_ed25519_noclamp(&ka, k, Array(publicKey)) != 0
    {
      return false
    }
    guard crypto_core_ed25519_add(&expected, r, ka) == 0 else { return false }
    return sb == expected
  }
  public static func encrypt(key: Data, nonce: Data, plaintext: Data, aad: Data = Data()) throws
    -> Data
  {
    guard key.count == 32, nonce.count == 24 else {
      throw QntmError.invalid("Invalid AEAD key/nonce")
    }
    var output = [UInt8](repeating: 0, count: plaintext.count + 16)
    guard
      crypto_aead_xchacha20poly1305_ietf_encrypt(
        &output, nil, Array(plaintext), UInt64(plaintext.count), Array(aad), UInt64(aad.count), nil,
        Array(nonce), Array(key)) == 0
    else { throw QntmError.crypto("Encryption failed") }
    return Data(output)
  }
  public static func decrypt(key: Data, nonce: Data, ciphertext: Data, aad: Data = Data()) throws
    -> Data
  {
    guard key.count == 32, nonce.count == 24, ciphertext.count >= 16 else {
      throw QntmError.invalid("Invalid AEAD key/nonce/ciphertext")
    }
    var output = [UInt8](repeating: 0, count: max(1, ciphertext.count - 16))
    guard
      crypto_aead_xchacha20poly1305_ietf_decrypt(
        &output, nil, nil, Array(ciphertext), UInt64(ciphertext.count), Array(aad),
        UInt64(aad.count), Array(nonce), Array(key)) == 0
    else { throw QntmError.crypto("Ciphertext authentication failed") }
    return Data(output.prefix(ciphertext.count - 16))
  }
  public static func x25519PublicKey(_ ed25519: Data) throws -> Data {
    guard isValidPublicKey(ed25519) else { throw QntmError.invalid("Invalid signing public key") }
    var output = [UInt8](repeating: 0, count: 32)
    guard crypto_sign_ed25519_pk_to_curve25519(&output, Array(ed25519)) == 0 else {
      throw QntmError.crypto("Public key conversion failed")
    }
    return Data(output)
  }
  public static func x25519PrivateKey(_ ed25519: Data) throws -> Data {
    guard ed25519.count == 64 else { throw QntmError.invalid("Invalid private key") }
    let pair = try identity(seed: ed25519.prefix(32))
    guard pair.privateKey == ed25519 else { throw QntmError.invalid("Private key mismatch") }
    var output = [UInt8](repeating: 0, count: 32)
    guard crypto_sign_ed25519_sk_to_curve25519(&output, Array(ed25519)) == 0 else {
      throw QntmError.crypto("Private key conversion failed")
    }
    return Data(output)
  }
  public static func x25519SharedSecret(privateKey: Data, publicKey: Data) throws -> Data {
    guard privateKey.count == 32, publicKey.count == 32 else {
      throw QntmError.invalid("Invalid X25519 key")
    }
    var output = [UInt8](repeating: 0, count: 32)
    guard crypto_scalarmult_curve25519(&output, Array(privateKey), Array(publicKey)) == 0 else {
      throw QntmError.crypto("Invalid X25519 peer")
    }
    return Data(output)
  }
  public static func sealSecret(senderPrivateKey: Data, recipientPublicKey: Data, plaintext: Data)
    throws -> Data
  {
    let sk = try x25519PrivateKey(senderPrivateKey)
    let pk = try x25519PublicKey(recipientPublicKey)
    let nonce = random(24)
    var ciphertext = [UInt8](repeating: 0, count: plaintext.count + 16)
    guard
      crypto_box_easy(
        &ciphertext, Array(plaintext), UInt64(plaintext.count), Array(nonce), Array(pk), Array(sk))
        == 0
    else { throw QntmError.crypto("Secret encryption failed") }
    return nonce + Data(ciphertext)
  }
  public static func openSecret(recipientPrivateKey: Data, senderPublicKey: Data, sealed: Data)
    throws -> Data
  {
    guard sealed.count >= 40 else { throw QntmError.invalid("Truncated sealed secret") }
    let sk = try x25519PrivateKey(recipientPrivateKey)
    let pk = try x25519PublicKey(senderPublicKey)
    var plaintext = [UInt8](repeating: 0, count: max(1, sealed.count - 40))
    guard
      crypto_box_open_easy(
        &plaintext, Array(sealed.dropFirst(24)), UInt64(sealed.count - 24),
        Array(sealed.prefix(24)), Array(pk), Array(sk)) == 0
    else { throw QntmError.crypto("Secret authentication failed") }
    return Data(plaintext.prefix(sealed.count - 40))
  }
  public static func wrapKey(
    _ key: Data, recipientPublicKey: Data, recipientKeyID: Data, conversationID: Data
  ) throws -> Data {
    guard key.count == 32, recipientKeyID == hash(recipientPublicKey).prefix(16),
      conversationID.count == 16
    else { throw QntmError.invalid("Invalid key wrap parameters") }
    let ephemeral = random(32)
    var epk = [UInt8](repeating: 0, count: 32)
    guard crypto_scalarmult_curve25519_base(&epk, Array(ephemeral)) == 0 else {
      throw QntmError.crypto("Ephemeral generation failed")
    }
    let shared = try x25519SharedSecret(
      privateKey: ephemeral, publicKey: x25519PublicKey(recipientPublicKey))
    let wk = try hkdfExpand(
      key: hkdfExtract(salt: conversationID, input: shared),
      info: Data("qntm/qsp/v1.1/wrap".utf8) + recipientKeyID)
    let nonce = random(24)
    return try CBOR.map([
      "ek_pk": .bytes(Data(epk)), "nonce": .bytes(nonce),
      "ct": .bytes(encrypt(key: wk, nonce: nonce, plaintext: key)),
    ]).encode()
  }
  public static func unwrapKey(
    _ wrapped: Data, recipientPrivateKey: Data, recipientKeyID: Data, conversationID: Data
  ) throws -> Data {
    guard let map = try CBOR.decode(wrapped).mapValue, conversationID.count == 16,
      recipientKeyID
        == hash(try identity(seed: recipientPrivateKey.prefix(32)).publicKey).prefix(16)
    else { throw QntmError.invalid("Invalid key wrap") }
    let shared = try x25519SharedSecret(
      privateKey: x25519PrivateKey(recipientPrivateKey),
      publicKey: map.requireBytes("ek_pk", count: 32))
    let wk = try hkdfExpand(
      key: hkdfExtract(salt: conversationID, input: shared),
      info: Data("qntm/qsp/v1.1/wrap".utf8) + recipientKeyID)
    let key = try decrypt(
      key: wk, nonce: map.requireBytes("nonce", count: 24),
      ciphertext: map.requireBytes("ct", count: 48))
    return key
  }
}

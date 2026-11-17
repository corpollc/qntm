import Foundation

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif
#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

public struct DIDDocument: Sendable {
  public let id: String
  public let ed25519PublicKey: Data?
  private let endpoints: [String: String]

  public init(json: Data, expectedID: String? = nil) throws {
    guard json.count <= 256 * 1024,
      let object = try JSONSerialization.jsonObject(with: json) as? [String: Any],
      let id = object["id"] as? String, expectedID == nil || id == expectedID,
      let methods = (object["verificationMethod"] ?? []) as? [Any],
      let services = (object["service"] ?? []) as? [Any]
    else { throw QntmError.invalid("Invalid DID document or identifier mismatch") }
    self.id = id
    var publicKey: Data?
    for value in methods {
      guard let method = value as? [String: Any], let type = method["type"] as? String,
        type.contains("Ed25519")
      else { continue }
      var candidates: [Data] = []
      if let multibase = method["publicKeyMultibase"] as? String, multibase.hasPrefix("z"),
        let bytes = try? DID.base58Decode(String(multibase.dropFirst()))
      {
        if bytes.count == 34, bytes.prefix(2) == Data([0xed, 0x01]) {
          candidates.append(Data(bytes.dropFirst(2)))
        }
        if bytes.count == 32 { candidates.append(bytes) }
      }
      if let base58 = method["publicKeyBase58"] as? String,
        let bytes = try? DID.base58Decode(base58)
      {
        candidates.append(bytes)
      }
      if let jwk = method["publicKeyJwk"] as? [String: Any], jwk["kty"] as? String == "OKP",
        jwk["crv"] as? String == "Ed25519",
        let x = jwk["x"] as? String, x.utf8.count <= 64,
        x.range(of: "^[A-Za-z0-9_-]+={0,2}$", options: .regularExpression) != nil,
        let bytes = try? Data.fromBase64URL(String(x.prefix(while: { $0 != "=" })))
      {
        candidates.append(bytes)
      }
      if let valid = candidates.first(where: QSPCrypto.isValidPublicKey) {
        publicKey = valid
        break
      }
    }
    ed25519PublicKey = publicKey
    var endpoints: [String: String] = [:]
    for value in services {
      if let service = value as? [String: Any], let type = service["type"] as? String,
        let endpoint = service["serviceEndpoint"] as? String, endpoints[type] == nil
      {
        endpoints[type] = endpoint
      }
    }
    self.endpoints = endpoints
  }
  public func serviceEndpoint(type: String) -> String? { endpoints[type] }
}

public enum DID {
  private static let alphabet = Array(
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)

  public static func fromPublicKey(_ publicKey: Data) throws -> String {
    guard QSPCrypto.isValidPublicKey(publicKey) else {
      throw QntmError.invalid("Invalid DID signing key")
    }
    return "did:key:z" + base58Encode(Data([0xed, 0x01]) + publicKey)
  }
  public static func resolveKey(_ did: String) throws -> DIDDocument {
    guard did.hasPrefix("did:key:z") else {
      throw QntmError.invalid("Unsupported DID key encoding")
    }
    let bytes = try base58Decode(String(did.dropFirst(9)))
    guard bytes.count == 34, bytes.prefix(2) == Data([0xed, 0x01]),
      QSPCrypto.isValidPublicKey(Data(bytes.dropFirst(2)))
    else {
      throw QntmError.invalid("DID key must contain a valid Ed25519 key")
    }
    let method: [String: String] = [
      "id": did + "#" + did.dropFirst(8), "type": "Ed25519VerificationKey2020", "controller": did,
      "publicKeyMultibase": String(did.dropFirst(8)),
    ]
    let json = try JSONSerialization.data(withJSONObject: [
      "id": did, "verificationMethod": [method],
    ])
    return try DIDDocument(json: json, expectedID: did)
  }
  public static func webURL(_ did: String) throws -> URL {
    guard did.hasPrefix("did:web:"), did.utf8.count <= 4096, !hasControls(did) else {
      throw QntmError.invalid("Invalid did:web identifier")
    }
    let parts = did.dropFirst(8).split(separator: ":", omittingEmptySubsequences: false).map(
      String.init)
    guard let rawAuthority = parts.first, let authority = rawAuthority.removingPercentEncoding,
      !authority.isEmpty, !hasControls(authority), !authority.contains("%"),
      authority.rangeOfCharacter(from: CharacterSet(charactersIn: "/\\@?#")) == nil,
      !authority.hasSuffix(":"), var components = URLComponents(string: "https://" + authority),
      let rawHost = components.host, !rawHost.isEmpty,
      components.user == nil, components.password == nil, components.path.isEmpty,
      components.query == nil, components.fragment == nil,
      components.port == nil || (1...65535).contains(components.port!)
    else { throw QntmError.invalid("Invalid did:web authority") }
    let host = rawHost.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    guard host != "localhost", !host.hasSuffix(".localhost"), !host.hasSuffix(".local"),
      !host.contains(".."), !host.hasPrefix("."), !host.hasSuffix("."), isAllowedHost(host)
    else {
      throw QntmError.invalid("Disallowed did:web host")
    }
    var paths: [String] = []
    for part in parts.dropFirst() {
      guard let decoded = part.removingPercentEncoding, !decoded.isEmpty, !hasControls(decoded),
        !decoded.contains("%"), ![".", ".."].contains(decoded),
        decoded.rangeOfCharacter(from: CharacterSet(charactersIn: "/\\?#")) == nil
      else { throw QntmError.invalid("Invalid did:web path") }
      let allowed = CharacterSet.urlPathAllowed.subtracting(CharacterSet(charactersIn: "/\\?#%"))
      guard let encoded = decoded.addingPercentEncoding(withAllowedCharacters: allowed) else {
        throw QntmError.invalid("Invalid did:web path encoding")
      }
      paths.append(encoded)
    }
    components.percentEncodedPath =
      paths.isEmpty ? "/.well-known/did.json" : "/" + paths.joined(separator: "/") + "/did.json"
    guard let url = components.url else { throw QntmError.invalid("Invalid did:web URL") }
    return url
  }

  /// A hostname check does not pin DNS. Hosts needing egress control should supply their network policy.
  public static func resolve(
    _ did: String, timeout: TimeInterval = 10,
    authorizeURL: (@Sendable (URL) async throws -> Void)? = nil
  ) async throws -> DIDDocument {
    if did.hasPrefix("did:key:") { return try resolveKey(did) }
    let url = try webURL(did)
    try await authorizeURL?(url)
    let data = try await IdentityDocumentRequest.read(
      url: url, timeout: timeout, accept: "application/did+json, application/json")
    return try DIDDocument(json: data, expectedID: did)
  }
  public static func resolvePublicKey(
    _ did: String, timeout: TimeInterval = 10,
    authorizeURL: (@Sendable (URL) async throws -> Void)? = nil
  ) async throws -> Data {
    let document = try await resolve(did, timeout: timeout, authorizeURL: authorizeURL)
    guard let key = document.ed25519PublicKey else {
      throw QntmError.invalid("DID document has no valid Ed25519 key")
    }
    return key
  }

  static func base58Decode(_ string: String) throws -> Data {
    let input = Array(string.utf8)
    guard (1...64).contains(input.count) else {
      throw QntmError.invalid("Invalid base58 key length")
    }
    var output: [UInt8] = []
    for character in input {
      guard let digit = alphabet.firstIndex(of: character) else {
        throw QntmError.invalid("Invalid base58 character")
      }
      var carry = digit
      for index in output.indices {
        carry += Int(output[index]) * 58
        output[index] = UInt8(carry & 255)
        carry >>= 8
      }
      while carry > 0 {
        output.append(UInt8(carry & 255))
        carry >>= 8
      }
    }
    let zeros = input.prefix(while: { $0 == 49 }).count
    return Data(repeating: 0, count: zeros) + Data(output.reversed())
  }
  private static func base58Encode(_ bytes: Data) -> String {
    var digits: [UInt8] = []
    for byte in bytes {
      var carry = Int(byte)
      for index in digits.indices {
        carry += Int(digits[index]) * 256
        digits[index] = UInt8(carry % 58)
        carry /= 58
      }
      while carry > 0 {
        digits.append(UInt8(carry % 58))
        carry /= 58
      }
    }
    let zeros = bytes.prefix(while: { $0 == 0 }).count
    return String(
      decoding: Array(repeating: UInt8(49), count: zeros)
        + digits.reversed().map { alphabet[Int($0)] }, as: UTF8.self)
  }
  private static func hasControls(_ value: String) -> Bool {
    value.unicodeScalars.contains {
      CharacterSet.whitespacesAndNewlines.contains($0) || $0.value < 32
        || (0x7f...0x9f).contains($0.value)
    }
  }
  private static func isAllowedHost(_ host: String) -> Bool {
    var v4 = in_addr()
    if inet_pton(AF_INET, host, &v4) == 1 {
      let bytes = withUnsafeBytes(of: v4) { Array($0) }
      return publicIPv4(bytes)
    }
    var v6 = in6_addr()
    if inet_pton(AF_INET6, host, &v6) == 1 {
      let b = withUnsafeBytes(of: v6) { Array($0) }
      if b.prefix(10).allSatisfy({ $0 == 0 }), b[10] == 255, b[11] == 255 {
        return publicIPv4(Array(b.suffix(4)))
      }
      if b.allSatisfy({ $0 == 0 }) || (b.prefix(15).allSatisfy({ $0 == 0 }) && b[15] == 1) {
        return false
      }
      guard b[0] & 0xe0 == 0x20 else { return false }
      if b[0] == 0x20 && b[1] == 2 { return false }
      if b[0] == 0x3f && b[1] == 0xff && b[2] & 0xf0 == 0 { return false }
      if b[0] == 0x20 && b[1] == 1 {
        if b[2] == 0x0d && b[3] == 0xb8 { return false }
        if b[2] < 2 {
          let exactService =
            b[2] == 0 && b[3] == 1 && b[4..<15].allSatisfy({ $0 == 0 }) && [1, 2].contains(b[15])
          let assignedRange =
            b[2] == 0
            && (b[3] == 3 || (b[3] == 4 && b[4] == 1 && b[5] == 0x12) || b[3] & 0xf0 == 0x20
              || b[3] & 0xf0 == 0x30)
          return exactService || assignedRange
        }
      }
      return true
    }
    if host.contains(":") { return false }
    return !host.split(separator: ".").allSatisfy {
      $0.allSatisfy(\.isNumber) || $0.lowercased().hasPrefix("0x")
    }
  }
  private static func publicIPv4(_ b: [UInt8]) -> Bool {
    guard b.count == 4 else { return false }
    return b[0] != 0 && b[0] != 10 && b[0] != 127 && b[0] < 224
      && !(b[0] == 169 && b[1] == 254) && !(b[0] == 172 && (16...31).contains(b[1]))
      && !(b[0] == 192 && b[1] == 168) && !(b[0] == 100 && (64...127).contains(b[1]))
      && !(b[0] == 192 && b[1] == 0 && (b[2] == 2 || (b[2] == 0 && ![9, 10].contains(b[3]))))
      && !(b[0] == 198 && (18...19).contains(b[1]))
      && !(b[0] == 198 && b[1] == 51 && b[2] == 100) && !(b[0] == 203 && b[1] == 0 && b[2] == 113)
  }
}

/// Per-request delegate bounds bytes while receiving and refuses every redirect.
final class IdentityDocumentRequest: NSObject, URLSessionDataDelegate, @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Data, Error>?
  private var buffer = Data()
  private var session: URLSession?
  private var cancelled = false
  static let maxBytes = 256 * 1024

  static func read(url: URL, timeout: TimeInterval, accept: String) async throws -> Data {
    guard timeout > 0, timeout <= 120 else {
      throw QntmError.invalid("Invalid identity document timeout")
    }
    let reader = IdentityDocumentRequest()
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        reader.start(url: url, timeout: timeout, accept: accept, continuation: continuation)
      }
    } onCancel: {
      reader.finish(.failure(CancellationError()))
    }
  }
  private func start(
    url: URL, timeout: TimeInterval, accept: String, continuation: CheckedContinuation<Data, Error>
  ) {
    lock.lock()
    if cancelled {
      lock.unlock()
      continuation.resume(throwing: CancellationError())
      return
    }
    self.continuation = continuation
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = timeout
    configuration.timeoutIntervalForResource = timeout
    let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    self.session = session
    var request = URLRequest(url: url)
    request.setValue(accept, forHTTPHeaderField: "Accept")
    request.setValue("qntm-swift/1.0", forHTTPHeaderField: "User-Agent")
    let task = session.dataTask(with: request)
    lock.unlock()
    task.resume()
  }
  private func finish(_ result: Result<Data, Error>) {
    lock.lock()
    cancelled = true
    let continuation = self.continuation
    self.continuation = nil
    let session = self.session
    self.session = nil
    lock.unlock()
    session?.invalidateAndCancel()
    continuation?.resume(with: result)
  }
  func urlSession(
    _ session: URLSession, task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void
  ) { completionHandler(nil) }
  func urlSession(
    _ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
    completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
  ) {
    guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
      response.expectedContentLength <= Int64(Self.maxBytes)
    else {
      completionHandler(.cancel)
      finish(.failure(QntmError.transport("Identity document HTTP status or size rejected")))
      return
    }
    completionHandler(.allow)
  }
  func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
    lock.lock()
    let exceeds = data.count > Self.maxBytes - buffer.count
    if !exceeds { buffer.append(data) }
    lock.unlock()
    if exceeds { finish(.failure(QntmError.transport("Identity document exceeds size limit"))) }
  }
  func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
    lock.lock()
    let data = buffer
    lock.unlock()
    if let error { finish(.failure(error)) } else { finish(.success(data)) }
  }
}

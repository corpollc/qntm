import Foundation

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

public struct CharterRegistryError: Error, Sendable {
  public let status: Int
  public let code: String
  public let message: String
}

/// Opt-in registry transport. Trust pins are caller supplied and never learned from the server.
public struct CharterRegistryClient: Sendable {
  public static let maximumResponseBytes = 32 * 1024 * 1024
  public let baseURL: URL
  public let trust: CharterTrust

  public init(baseURL: URL, trust: CharterTrust) throws {
    guard let parts = URLComponents(url: baseURL, resolvingAgainstBaseURL: false),
      let host = parts.host,
      parts.scheme == "https"
        || (parts.scheme == "http" && ["localhost", "127.0.0.1", "::1", "[::1]"].contains(host)),
      parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil
    else {
      throw QntmError.invalid(
        "Registry requires HTTPS without credentials, query or fragment; HTTP is allowed on loopback"
      )
    }
    self.baseURL = baseURL
    self.trust = trust
  }

  public func heads(size: UInt64? = nil) async throws -> CharterHeads {
    let value = try await request("/v1/heads" + sizeQuery(size))
    let heads = try CharterHeads(json: value, trust: trust)
    try checkSize(heads, size)
    return heads
  }
  public func submit(_ statement: CharterStatement) async throws -> CharterJSON {
    let receipt = try await request("/v1/statements", method: "POST", body: statement.json)
    try CharterProofs.verifyReceipt(receipt, statement: statement, trust: trust)
    return receipt
  }
  public func chain(agentID: String, size: UInt64? = nil) async throws -> (
    record: CharterRecord?, evidence: CharterJSON
  ) {
    _ = try charterHex(.string(agentID), count: 16)
    let evidence = try await request("/v1/chain/" + agentID + sizeQuery(size))
    let record = try CharterProofs.verifyChainResponse(evidence, trust: trust, agentID: agentID)
    guard let rawHeads = evidence["heads"] else { throw QntmError.invalid("Missing chain heads") }
    try checkSize(CharterHeads(json: rawHeads, trust: trust), size)
    return (record, evidence)
  }
  public func consistency(older: CharterHeads, newer: CharterHeads) async throws -> [String] {
    _ = try CharterHeads(json: older.json, trust: trust)
    _ = try CharterHeads(json: newer.json, trust: trust)
    let result = try await request("/v1/consistency?from=\(older.treeSize)&to=\(newer.treeSize)")
    let proof = try CharterProofs.hashes(result["proof"])
    try CharterProofs.verifyConsistency(older: older, newer: newer, proof: proof)
    return proof
  }
  public func log(heads: CharterHeads) async throws -> [CharterJSON] {
    _ = try CharterHeads(json: heads.json, trust: trust)
    var entries: [CharterJSON] = []
    while UInt64(entries.count) < heads.treeSize {
      let page = try await request(
        "/v1/log?size=\(heads.treeSize)&from=\(entries.count)&limit=1000")
      guard let batch = page["entries"]?.array else {
        throw QntmError.invalid("Missing snapshot page")
      }
      let from = try charterUInt(page["from"])
      let next = try charterUInt(page["next"])
      guard from == UInt64(entries.count), next == from + UInt64(batch.count), next > from,
        next <= heads.treeSize
      else {
        throw QntmError.invalid("Invalid log pagination")
      }
      entries.append(contentsOf: batch)
    }
    return entries
  }
  private func sizeQuery(_ size: UInt64?) throws -> String {
    guard let size else { return "" }
    guard size <= 9_007_199_254_740_991 else { throw QntmError.invalid("Invalid snapshot size") }
    return "?size=\(size)"
  }
  private func checkSize(_ heads: CharterHeads, _ size: UInt64?) throws {
    try charterCheck(size == nil || heads.treeSize == size, "Wrong snapshot size")
  }
  private func request(_ path: String, method: String = "GET", body: CharterJSON? = nil)
    async throws -> CharterJSON
  {
    let base =
      baseURL.absoluteString.hasSuffix("/")
      ? String(baseURL.absoluteString.dropLast()) : baseURL.absoluteString
    guard let url = URL(string: base + path) else {
      throw QntmError.invalid("Invalid registry request URL")
    }
    var request = URLRequest(url: url, timeoutInterval: 30)
    request.httpMethod = method
    if let body {
      request.httpBody = try CharterJSONCodec.canonicalize(body)
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    }
    let transfer = CharterHTTPTransfer(limit: Self.maximumResponseBytes)
    let (data, response) = try await transfer.run(request)
    let value = try CharterJSONCodec.parse(data)
    guard (200..<300).contains(response.statusCode) else {
      throw CharterRegistryError(
        status: response.statusCode, code: value["error"]?.string ?? "http_error",
        message: value["message"]?.string ?? "Registry HTTP \(response.statusCode)")
    }
    return value
  }
}

private final class CharterHTTPTransfer: NSObject, URLSessionDataDelegate, @unchecked Sendable {
  private let lock = NSLock()
  private let limit: Int
  private var task: URLSessionDataTask?
  private var session: URLSession?
  private var continuation: CheckedContinuation<(Data, HTTPURLResponse), Error>?
  private var body = Data()
  private var response: HTTPURLResponse?
  private var failure: Error?
  private var cancelled = false

  init(limit: Int) { self.limit = limit }
  func run(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        lock.lock()
        if cancelled {
          lock.unlock()
          continuation.resume(throwing: CancellationError())
          return
        }
        self.continuation = continuation
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 30
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        self.session = session
        let task = session.dataTask(with: request)
        self.task = task
        lock.unlock()
        task.resume()
      }
    } onCancel: {
      self.cancel()
    }
  }
  private func cancel() {
    lock.lock()
    cancelled = true
    let task = task
    lock.unlock()
    task?.cancel()
  }
  func urlSession(
    _ session: URLSession, task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void
  ) {
    lock.lock()
    failure = QntmError.transport("Registry redirects are forbidden")
    lock.unlock()
    completionHandler(nil)
  }
  func urlSession(
    _ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
    completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
  ) {
    lock.lock()
    guard let response = response as? HTTPURLResponse,
      response.expectedContentLength <= Int64(limit)
    else {
      failure = QntmError.transport("Registry response exceeds limit or is not HTTP")
      lock.unlock()
      completionHandler(.cancel)
      return
    }
    self.response = response
    lock.unlock()
    completionHandler(.allow)
  }
  func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
    lock.lock()
    if body.count > limit - data.count {
      failure = QntmError.transport("Registry response exceeds 32 MiB limit")
      lock.unlock()
      dataTask.cancel()
      return
    }
    body.append(data)
    lock.unlock()
  }
  func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
    lock.lock()
    let continuation = continuation
    self.continuation = nil
    let failure = failure ?? error
    let response = response
    let data = body
    self.task = nil
    self.session = nil
    lock.unlock()
    session.finishTasksAndInvalidate()
    if let failure {
      continuation?.resume(throwing: failure)
    } else if let response {
      continuation?.resume(returning: (data, response))
    } else {
      continuation?.resume(throwing: QntmError.transport("Missing registry response"))
    }
  }
}

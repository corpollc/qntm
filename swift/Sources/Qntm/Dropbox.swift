import Foundation

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

public struct SubscriptionMessage: Sendable, Equatable {
  public let sequence: UInt64
  public let envelope: Data
}

public struct ReceiveResult: Sendable {
  public let entries: [SubscriptionMessage]
  public let sequence: UInt64
  public var messages: [Data] { entries.map(\.envelope) }
}

public struct ReadReceipt: Codable, Sendable {
  public let proto: String
  public let conversationID: String
  public let messageID: String
  public let readerKeyID: String
  public let readerPublicKey: String
  public let readTimestamp: UInt64
  public let requiredAcknowledgments: Int
  public let signature: String
  enum CodingKeys: String, CodingKey {
    case proto
    case conversationID = "conv_id"
    case messageID = "msg_id"
    case readerKeyID = "reader_kid"
    case readerPublicKey = "reader_ik_pk"
    case readTimestamp = "read_ts"
    case requiredAcknowledgments = "required_acks"
    case signature = "sig"
  }
  public init(
    identity: Identity, conversationID: Data, messageID: Data,
    requiredAcknowledgments: Int = 1,
    readTimestamp: UInt64 = UInt64(Date().timeIntervalSince1970 * 1000)
  ) throws {
    guard conversationID.count == 16, messageID.count == 16,
      requiredAcknowledgments > 0, requiredAcknowledgments <= 256,
      readTimestamp > 0, readTimestamp <= 9_007_199_254_740_991
    else {
      throw QntmError.invalid("Invalid receipt fields")
    }
    proto = "qntm-receipt-v1"
    self.conversationID = conversationID.hex
    self.messageID = messageID.hex
    readerKeyID = identity.keyID.hex
    readerPublicKey = identity.publicKey.base64URL
    self.readTimestamp = readTimestamp
    self.requiredAcknowledgments = requiredAcknowledgments
    let signable =
      "\(proto)|\(conversationID.hex)|\(messageID.hex)|\(readerKeyID)|\(readTimestamp)|\(requiredAcknowledgments)"
    signature = try QSPCrypto.sign(privateKey: identity.privateKey, message: Data(signable.utf8))
      .base64URL
  }
}

public struct ReceiptResponse: Codable, Sendable {
  public let recorded: Bool
  public let deleted: Bool
  public let receipts: Int
  public let requiredAcknowledgments: Int
  enum CodingKeys: String, CodingKey {
    case recorded, deleted, receipts
    case requiredAcknowledgments = "required_acks"
  }
}

/// Stateless relay transport. Durable cursor ownership stays with the application.
public struct DropboxClient: Sendable {
  public static let defaultURL = URL(string: "https://inbox.qntm.corpo.llc")!
  public let baseURL: URL
  private let session: URLSession
  private static let maxSafeInteger: UInt64 = 9_007_199_254_740_991

  public init(baseURL: URL = Self.defaultURL, session: URLSession = .shared) throws {
    guard ["http", "https"].contains(baseURL.scheme?.lowercased() ?? ""),
      baseURL.host != nil, baseURL.user == nil, baseURL.password == nil
    else {
      throw QntmError.invalid("Relay URL must be HTTP or HTTPS without credentials")
    }
    self.baseURL = baseURL
    self.session = session
  }

  public func postMessage(
    conversationID: Data, envelope: Data, announcementSignature: String? = nil
  ) async throws -> UInt64 {
    let parsed = try Envelope(serialized: envelope)
    guard conversationID.count == 16, parsed.conversationID == conversationID,
      envelope.count <= 96 * 1024
    else {
      throw QntmError.invalid("Envelope does not belong to relay conversation")
    }
    struct Body: Encodable {
      let conversationID: String
      let envelopeBase64: String
      let messageID: String
      let announcementSignature: String?
      enum CodingKeys: String, CodingKey {
        case conversationID = "conv_id"
        case envelopeBase64 = "envelope_b64"
        case messageID = "msg_id"
        case announcementSignature = "announce_sig"
      }
    }
    struct Result: Decodable { let seq: UInt64 }
    let data = try await post(
      path: "/v1/send",
      body: Body(
        conversationID: conversationID.hex,
        envelopeBase64: envelope.base64EncodedString(), messageID: parsed.messageID.hex,
        announcementSignature: announcementSignature))
    let result = try JSONDecoder().decode(Result.self, from: data)
    guard result.seq > 0, result.seq <= Self.maxSafeInteger else {
      throw QntmError.transport("Invalid relay sequence")
    }
    return result.seq
  }

  public func submitReceipt(_ receipt: ReadReceipt) async throws -> ReceiptResponse {
    try JSONDecoder().decode(
      ReceiptResponse.self, from: await post(path: "/v1/receipt", body: receipt))
  }

  /// Replay until the relay's ready marker. The returned cursor is committed only by the caller.
  public func receiveMessages(
    conversationID: Data, fromSequence: UInt64 = 0,
    maxMessages: Int = 10_000, timeout: TimeInterval = 30,
    identity: Identity? = nil
  ) async throws -> ReceiveResult {
    guard maxMessages > 0, maxMessages <= 100_000, timeout > 0, timeout <= 300 else {
      throw QntmError.invalid("Invalid replay limits")
    }
    let socket = try makeSocket(
      conversationID: conversationID, fromSequence: fromSequence, identity: identity)
    socket.resume()
    let timer = Task {
      do { try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000)) } catch { return }
      socket.cancel(with: .goingAway, reason: nil)
    }
    defer {
      timer.cancel()
      socket.cancel(with: .normalClosure, reason: nil)
    }
    return try await withTaskCancellationHandler {
      var entries: [SubscriptionMessage] = []
      var cursor = fromSequence
      var controls = 0
      while true {
        try Task.checkCancellation()
        switch try await readFrame(socket) {
        case .message(let entry):
          guard entries.count < maxMessages, entry.sequence > cursor else {
            throw QntmError.transport("Replay exceeds limit or contains nonincreasing sequence")
          }
          entries.append(entry)
          cursor = entry.sequence
        case .ready(let head):
          return ReceiveResult(entries: entries, sequence: max(cursor, head))
        case .challenge(let challenge):
          try await authenticate(socket, challenge: challenge, identity: identity)
          controls += 1
        case .control: controls += 1
        }
        guard controls <= 32 else { throw QntmError.transport("Excessive relay control frames") }
      }
    } onCancel: {
      socket.cancel(with: .goingAway, reason: nil)
    }
  }

  /// Run until task cancellation. A throwing callback reconnects without acknowledging its message.
  public func subscribeMessages(
    conversationID: Data, fromSequence: UInt64 = 0, identity: Identity? = nil,
    getCursor: (@Sendable () async throws -> UInt64)? = nil,
    onError: (@Sendable (String) async -> Void)? = nil,
    onReconnect: (@Sendable (Int, TimeInterval) async -> Void)? = nil,
    onMessage: @escaping @Sendable (SubscriptionMessage) async throws -> Void
  ) async throws {
    _ = try subscriptionURL(
      conversationID: conversationID, fromSequence: fromSequence, identity: identity)
    var cursor = fromSequence
    var attempt = 0
    while !Task.isCancelled {
      do {
        if let getCursor { cursor = try await getCursor() }
        let socket = try makeSocket(
          conversationID: conversationID, fromSequence: cursor, identity: identity)
        socket.resume()
        defer { socket.cancel(with: .normalClosure, reason: nil) }
        try await withTaskCancellationHandler {
          while true {
            try Task.checkCancellation()
            switch try await readFrame(socket) {
            case .message(let entry):
              guard entry.sequence > cursor else {
                throw QntmError.transport("Nonincreasing subscription sequence")
              }
              try await onMessage(entry)
              cursor = entry.sequence
              attempt = 0
            case .challenge(let challenge):
              try await authenticate(socket, challenge: challenge, identity: identity)
            case .ready, .control: break
            }
          }
        } onCancel: {
          socket.cancel(with: .goingAway, reason: nil)
        }
      } catch {
        try Task.checkCancellation()
        await onError?(String(describing: error))
        attempt += 1
        let delay = min(30.0, pow(2.0, Double(min(attempt - 1, 5))))
        await onReconnect?(attempt, delay)
        try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
      }
    }
    throw CancellationError()
  }

  func subscriptionURL(conversationID: Data, fromSequence: UInt64, identity: Identity?) throws
    -> URL
  {
    guard conversationID.count == 16, fromSequence <= Self.maxSafeInteger,
      var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)
    else {
      throw QntmError.invalid("Invalid subscription conversation or cursor")
    }
    components.scheme = baseURL.scheme == "https" ? "wss" : "ws"
    components.path = "/v1/subscribe"
    components.fragment = nil
    components.queryItems = [
      URLQueryItem(name: "conv_id", value: conversationID.hex),
      URLQueryItem(name: "from_seq", value: String(fromSequence)),
    ]
    if let identity {
      components.queryItems?.append(URLQueryItem(name: "pub_key", value: identity.publicKey.hex))
    }
    guard let url = components.url else { throw QntmError.invalid("Invalid subscription URL") }
    return url
  }

  private func makeSocket(conversationID: Data, fromSequence: UInt64, identity: Identity?) throws
    -> URLSessionWebSocketTask
  {
    let task = session.webSocketTask(
      with: try subscriptionURL(
        conversationID: conversationID, fromSequence: fromSequence, identity: identity))
    task.maximumMessageSize = 100_000
    return task
  }

  private enum Frame {
    case message(SubscriptionMessage)
    case ready(UInt64)
    case challenge(Data)
    case control
  }
  private func readFrame(_ socket: URLSessionWebSocketTask) async throws -> Frame {
    let raw = try await socket.receive()
    let data: Data
    switch raw {
    case .string(let string): data = Data(string.utf8)
    case .data(let bytes): data = bytes
    @unknown default: throw QntmError.transport("Unsupported relay frame")
    }
    guard data.count <= 100_000 else { throw QntmError.transport("Relay frame exceeds limit") }
    struct Wire: Decodable {
      let type: String
      let seq: UInt64?
      let headSequence: UInt64?
      let envelopeBase64: String?
      let challengeHex: String?
      enum CodingKeys: String, CodingKey {
        case type, seq
        case headSequence = "head_seq"
        case envelopeBase64 = "envelope_b64"
        case challengeHex = "challenge_hex"
      }
    }
    let wire = try JSONDecoder().decode(Wire.self, from: data)
    switch wire.type {
    case "message":
      guard let seq = wire.seq, seq > 0, seq <= Self.maxSafeInteger,
        let encoded = wire.envelopeBase64, let envelope = Data(base64Encoded: encoded),
        envelope.count <= 73_728
      else { throw QntmError.transport("Invalid relay message") }
      return .message(SubscriptionMessage(sequence: seq, envelope: envelope))
    case "ready":
      guard let seq = wire.headSequence, seq <= Self.maxSafeInteger else {
        throw QntmError.transport("Invalid relay head")
      }
      return .ready(seq)
    case "auth_challenge":
      guard let hex = wire.challengeHex else {
        throw QntmError.transport("Invalid authentication challenge")
      }
      let challenge = try Data(hex: hex)
      guard challenge.count == 32 else {
        throw QntmError.transport("Invalid authentication challenge")
      }
      return .challenge(challenge)
    case "auth_failed": throw QntmError.transport("Relay authentication failed")
    case "pong", "auth_ok": return .control
    default: throw QntmError.transport("Unknown relay frame type")
    }
  }

  private func authenticate(_ socket: URLSessionWebSocketTask, challenge: Data, identity: Identity?)
    async throws
  {
    guard let identity else {
      throw QntmError.transport("Relay requested an unconfigured identity")
    }
    struct Response: Encodable {
      let type = "auth_response"
      let signatureHex: String
      enum CodingKeys: String, CodingKey {
        case type
        case signatureHex = "signature_hex"
      }
    }
    let signature = try QSPCrypto.sign(privateKey: identity.privateKey, message: challenge)
    let bytes = try JSONEncoder().encode(Response(signatureHex: signature.hex))
    try await socket.send(.string(String(decoding: bytes, as: UTF8.self)))
  }

  private func post<T: Encodable>(path: String, body: T) async throws -> Data {
    guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
      throw QntmError.invalid("Invalid relay URL")
    }
    components.path = path
    components.query = nil
    components.fragment = nil
    guard let url = components.url else { throw QntmError.invalid("Invalid relay URL") }
    var request = URLRequest(url: url, timeoutInterval: 30)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try JSONEncoder().encode(body)
    let (data, response) = try await session.data(for: request)
    guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
      data.count <= 96 * 1024
    else {
      throw QntmError.transport("Relay request failed or returned an oversized response")
    }
    return data
  }
}

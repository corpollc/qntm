import Foundation

func gateRequire(_ condition: Bool, _ reason: String) throws {
  if !condition { throw QntmError.invalid(reason) }
}
func gateText(_ value: GatewayJSON?, _ name: String, max: Int = 4096) throws -> String {
  guard let text = value?.string, !text.isEmpty, text.utf8.count <= max else {
    throw QntmError.invalid("Invalid \(name)")
  }
  return text
}
func gateUInt(_ value: GatewayJSON?, _ name: String, min: UInt64 = 0) throws -> UInt64 {
  guard let n = value?.integer, n >= min else { throw QntmError.invalid("Invalid \(name)") }
  return n
}
func gateBytes(_ value: GatewayJSON?, _ name: String, count: Int? = nil) throws -> Data {
  let text = try gateText(value, name, max: 2_000_000)
  let data = try Data.fromBase64URL(text)
  try gateRequire(
    data.base64URL == text && (count == nil || data.count == count), "Invalid \(name)")
  return data
}
func gateHex(_ value: GatewayJSON?, _ name: String, count: Int) throws -> String {
  let text = try gateText(value, name)
  let data = try Data(hex: text)
  try gateRequire(data.count == count && data.hex == text, "Invalid \(name)")
  return text
}
func gateTime(_ value: GatewayJSON?) throws -> UInt64 {
  let text = try gateText(value, "timestamp")
  let formatter = ISO8601DateFormatter()
  formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
  var date = formatter.date(from: text)
  if date == nil {
    formatter.formatOptions = [.withInternetDateTime]
    date = formatter.date(from: text)
  }
  guard let seconds = date?.timeIntervalSince1970, seconds >= 0, seconds <= 9_007_199_254_740_991
  else { throw QntmError.invalid("Invalid timestamp") }
  return UInt64(seconds)
}
func gateDate(_ seconds: UInt64) -> GatewayJSON {
  .string(ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: Double(seconds))))
}
func gateRoster(_ value: GatewayJSON?) throws -> [String] {
  guard let items = value?.array, !items.isEmpty, items.count <= 128 else {
    throw QntmError.invalid("Invalid signer roster")
  }
  let result = try items.map { try gateBytes($0, "signer key ID", count: 16).base64URL }
  try gateRequire(Set(result).count == result.count, "Duplicate signer")
  return result
}
func gateParticipants(_ value: GatewayJSON?) throws -> [String: Data] {
  guard let fields = value?.fields, !fields.isEmpty, fields.count <= 128 else {
    throw QntmError.invalid("Invalid participants")
  }
  var result: [String: Data] = [:]
  for field in fields {
    let pk = try gateBytes(field.value, "participant public key", count: 32)
    try gateRequire(
      QSPCrypto.isValidPublicKey(pk) && QSPCrypto.hash(pk).prefix(16).base64URL == field.key,
      "Participant key ID mismatch")
    result[field.key] = pk
  }
  return result
}

public struct ThresholdRule: Sendable, Equatable, Codable {
  public let service: String, endpoint: String, verb: String
  public let m: UInt64
  public let n: UInt64?
  public init(
    service: String = "*", endpoint: String = "*", verb: String = "*", m: UInt64, n: UInt64? = nil
  ) throws {
    try gateRequire(
      m > 0 && m <= 128 && (n == nil || (n! > 0 && n! <= 128)), "Invalid threshold rule")
    self.service = service
    self.endpoint = endpoint
    self.verb = verb
    self.m = m
    self.n = n
  }
  var json: GatewayJSON {
    var value = GatewayJSON.object([
      ("service", .string(service)), ("endpoint", .string(endpoint)), ("verb", .string(verb)),
      ("m", .uint(m)),
    ])
    if let n { value = value.setting("n", .uint(n)) }
    return value
  }
  static func parse(_ value: GatewayJSON?) throws -> [ThresholdRule] {
    guard let values = value?.array else { throw QntmError.invalid("Invalid rules") }
    return try values.map { v in
      guard let service = v["service"]?.string, let endpoint = v["endpoint"]?.string,
        let verb = v["verb"]?.string
      else { throw QntmError.invalid("Invalid rule") }
      return try ThresholdRule(
        service: service, endpoint: endpoint, verb: verb,
        m: gateUInt(v["m"], "rule threshold", min: 1),
        n: v["n"].map { try gateUInt($0, "rule size", min: 1) })
    }
  }
}

/// Trusted current policy, established by signed admission or explicit host configuration.
public struct GatewayContext: Sendable, Equatable, Codable {
  public var conversationID: String
  public var epoch: UInt32
  public var gatewayPublicKey: Data
  public var participants: [String: Data]
  public var floor: UInt64
  public var rules: [ThresholdRule]
  public var allowLegacyUnbound: Bool
  public var gatewayKeyID: String { QSPCrypto.hash(gatewayPublicKey).prefix(16).base64URL }
  public init(
    conversationID: String, epoch: UInt32, gatewayPublicKey: Data, participants: [String: Data],
    floor: UInt64, rules: [ThresholdRule], allowLegacyUnbound: Bool = false
  ) throws {
    self.conversationID = conversationID
    self.epoch = epoch
    self.gatewayPublicKey = gatewayPublicKey
    self.participants = participants
    self.floor = floor
    self.rules = rules
    self.allowLegacyUnbound = allowLegacyUnbound
    try validate()
  }
  public func validate() throws {
    _ = try gateHex(.string(conversationID), "conversation ID", count: 16)
    try gateRequire(QSPCrypto.isValidPublicKey(gatewayPublicKey), "Invalid gateway public key")
    _ = try gateParticipants(
      .object(
        participants.sorted { $0.key < $1.key }.map {
          GatewayJSON.Field($0.key, .string($0.value.base64URL))
        }))
    try gateRequire(
      participants[gatewayKeyID] == nil && floor > 0 && floor <= 128, "Invalid gateway policy")
    _ = try ThresholdRule.parse(.array(rules.map(\.json)))
  }
  public var governanceQuorum: UInt64 { UInt64(participants.count / 2 + 1) }
  public func requestThreshold(
    service: String, endpoint: String, verb: String, targetURL: String? = nil
  ) -> UInt64 {
    max(
      floor,
      Gateway.lookupThreshold(
        rules: rules, service: service, endpoint: endpoint, verb: verb, targetURL: targetURL)?.m
        ?? 1)
  }
  func signer(_ identity: Identity) throws -> String {
    try validate()
    let kid = identity.keyID.base64URL
    try gateRequire(participants[kid] == identity.publicKey, "Signer is not a current participant")
    return kid
  }
}

public enum GatewayBodyType: String, Sendable, CaseIterable {
  case request = "gate.request"
  case approval = "gate.approval"
  case disapproval = "gate.disapproval"
  case secret = "gate.secret"
  case executed = "gate.executed"
  case result = "gate.result"
  case expired = "gate.expired"
  case invalidated = "gate.invalidated"
  case promote = "gate.promote"
  case accept = "gate.accept"
  case propose = "gov.propose"
  case proposalApproval = "gov.approve"
  case proposalDisapproval = "gov.disapprove"
  case applied = "gov.applied"
  case proposalInvalidated = "gov.invalidated"
  var gatewayOnly: Bool {
    [.accept, .executed, .result, .expired, .invalidated, .applied, .proposalInvalidated].contains(
      self)
  }
}

/// Parsed wire body. Parsing proves shape; Gateway.verify proves sender and policy authority.
public struct GatewayBody: Sendable, Equatable {
  public let type: GatewayBodyType
  public let json: GatewayJSON
  public subscript(_ key: String) -> GatewayJSON? { json[key] }
  public init(type: String, data: Data) throws {
    try self.init(type: type, json: GatewayJSON(data: data))
  }
  public init(type: String, json: GatewayJSON) throws {
    guard let kind = GatewayBodyType(rawValue: type), json.fields != nil,
      json["type"]?.string == type
    else { throw QntmError.invalid("Unsupported or mismatched gateway body") }
    self.type = kind
    self.json = json
    try validate()
  }
  public func encoded() throws -> Data { try json.encoded() }
  func validate() throws {
    if let kid = self["gateway_kid"] { _ = try gateBytes(kid, "gateway ID", count: 16) }
    switch type {
    case .request, .approval, .disapproval, .propose, .proposalApproval, .proposalDisapproval:
      _ = try gateHex(self["conv_id"], "conversation ID", count: 16)
      _ = try gateText(
        self[
          type == .request || type == .approval || type == .disapproval
            ? "request_id" : "proposal_id"], "workflow ID", max: 256)
      _ = try gateBytes(self["signer_kid"], "signer ID", count: 16)
      if type != .disapproval && type != .proposalDisapproval {
        _ = try gateBytes(self["signature"], "signature", count: 64)
      }
      if type == .request || type == .propose {
        let roster = try gateRoster(self["eligible_signer_kids"])
        let threshold = try gateUInt(self["required_approvals"], "required approvals", min: 1)
        try gateRequire(threshold <= roster.count, "Threshold exceeds signer count")
        _ = try gateTime(self["expires_at"])
      }
      if type == .request {
        let verb = try gateText(self["verb"], "verb")
        let endpoint = try gateText(self["target_endpoint"], "endpoint")
        try gateRequire(
          verb.range(of: "^[A-Z]+$", options: .regularExpression) != nil, "Invalid HTTP verb")
        _ = try gateText(self["target_service"], "service")
        let target = try Gateway.validateTargetURL(
          gateText(self["target_url"], "target URL", max: 16384))
        try gateRequire(
          Gateway.pathnameMatchesEndpoint(target.path, endpoint: endpoint),
          "Target URL path differs from endpoint")
        if let recipe = self["recipe_name"] { _ = try gateText(recipe, "recipe name") }
        if let arguments = self["arguments"], arguments != .null {
          guard let fields = arguments.fields, fields.allSatisfy({ $0.value.string != nil }) else {
            throw QntmError.invalid("Invalid recipe arguments")
          }
        }
      }
      if type == .propose { try Governance.validateFields(json, applied: false) }
    case .secret:
      for field in ["secret_id", "service", "header_name", "header_template"] {
        _ = try gateText(self[field], field)
      }
      guard let originValues = self["allowed_origins"]?.array,
        originValues.allSatisfy({ $0.string != nil })
      else { throw QntmError.invalid("Invalid allowed origins") }
      _ = try Gateway.normalizeOrigins(originValues.compactMap(\.string))
      _ = try gateBytes(self["sender_kid"], "sender ID", count: 16)
      try gateRequire(
        try gateBytes(self["encrypted_blob"], "encrypted blob").count >= 40,
        "Invalid sealed credential")
      let header = try gateText(self["header_name"], "header")
      let template = try gateText(self["header_template"], "header template")
      try gateRequire(
        header.range(of: "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$", options: .regularExpression) != nil
          && !template.contains("\r") && !template.contains("\n") && template.contains("{value}"),
        "Invalid credential header")
      if let ttl = self["ttl"] { _ = try gateUInt(ttl, "credential TTL") }
    case .executed, .result, .invalidated, .proposalInvalidated:
      _ = try gateText(
        self[type == .proposalInvalidated ? "proposal_id" : "request_id"], "workflow ID", max: 256)
      if type == .executed {
        _ = try gateTime(self["executed_at"])
        _ = try gateUInt(self["execution_status_code"], "status code")
      }
      if type == .result {
        _ = try gateUInt(self["status_code"], "status code")
        for field in ["body", "content_type"] {
          if let value = self[field] {
            try gateRequire(value.string != nil, "Invalid result field")
          }
        }
      }
      if type == .invalidated || type == .proposalInvalidated {
        _ = try gateTime(self["invalidated_at"])
        _ = try gateText(self["message"], "message")
      }
    case .expired:
      for field in ["secret_id", "service", "message"] { _ = try gateText(self[field], field) }
      _ = try gateTime(self["expired_at"])
    case .applied:
      _ = try gateText(self["proposal_id"], "proposal ID", max: 256)
      _ = try gateTime(self["applied_at"])
      try Governance.validateFields(json, applied: true)
    case .promote, .accept:
      _ = try gateHex(self["conv_id"], "conversation ID", count: 16)
      _ = try gateHex(self["invitation_id"], "invitation ID", count: 16)
      try gateRequire(try gateUInt(self["conv_epoch"], "epoch") <= UInt32.max, "Invalid epoch")
      let pk = try gateBytes(self["gateway_public_key"], "gateway public key", count: 32)
      try gateRequire(
        QSPCrypto.isValidPublicKey(pk)
          && QSPCrypto.hash(pk).prefix(16).base64URL == self["gateway_kid"]?.string,
        "Invalid gateway identity")
      if type == .promote {
        _ = try gateUInt(self["expires_at"], "invitation expiry", min: 1)
        _ = try gateHex(self["keys_hash"], "key commitment", count: 32)
        let participants = try gateParticipants(self["participants"])
        let floor = try gateUInt(self["floor"], "floor", min: 1)
        try gateRequire(
          participants[QSPCrypto.hash(pk).prefix(16).base64URL] == nil
            && floor <= participants.count, "Invalid invitation roster")
        _ = try ThresholdRule.parse(self["rules"])
        if let kind = self["conversation_type"] {
          try gateRequire(
            ["direct", "group"].contains(kind.string ?? ""), "Invalid conversation type")
        }
        if let creator = self["group_creator_kid"] {
          _ = try gateBytes(creator, "group creator", count: 16)
        }
      } else {
        _ = try gateHex(self["invitation_msg_id"], "invitation message ID", count: 16)
        _ = try gateHex(self["invitation_hash"], "invitation hash", count: 32)
      }
    }
  }
}

public enum Gateway {
  public static func payloadHash(_ payload: GatewayJSON?) throws -> Data {
    QSPCrypto.hash(payload == nil || payload == .null ? Data() : try payload!.encoded())
  }
  public static func requestSignable(_ body: GatewayBody) throws -> CBOR {
    try gateRequire(body.type == .request, "Expected gate.request")
    var fields: [String: CBOR] = [:]
    for key in [
      "conv_id", "request_id", "verb", "target_endpoint", "target_service", "target_url",
      "eligible_signer_kids", "required_approvals",
    ] {
      guard let value = body[key] else { throw QntmError.invalid("Missing request field") }
      fields[key] = try value.cbor()
    }
    if let gateway = body["gateway_kid"] { fields["gateway_kid"] = try gateway.cbor() }
    fields["expires_at_unix"] = .unsigned(try gateTime(body["expires_at"]))
    fields["payload_hash"] = .bytes(try payloadHash(body["payload"]))
    return .map(fields)
  }
  public static func requestHash(_ body: GatewayBody) throws -> Data {
    QSPCrypto.hash(try requestSignable(body).encode())
  }
  public static func assertRequest(_ body: GatewayBody, context: GatewayContext) throws {
    try context.validate()
    try body.validate()
    try assertBinding(body, context: context)
    try assertRoster(body, context: context)
    try gateRequire(body.type == .request, "Expected request")
    let threshold = context.requestThreshold(
      service: try gateText(body["target_service"], "service"),
      endpoint: try gateText(body["target_endpoint"], "endpoint"),
      verb: try gateText(body["verb"], "verb"), targetURL: body["target_url"]?.string)
    try gateRequire(
      try gateUInt(body["required_approvals"], "threshold") >= threshold,
      "Request threshold below current policy")
    guard let key = context.participants[try gateText(body["signer_kid"], "signer")] else {
      throw QntmError.invalid("Unknown request author")
    }
    try gateRequire(
      QSPCrypto.verify(
        publicKey: key, message: try requestSignable(body).encode(),
        signature: try gateBytes(body["signature"], "signature", count: 64)),
      "Invalid request signature")
  }
  static func assertBinding(_ body: GatewayBody, context: GatewayContext) throws {
    try gateRequire(
      body["conv_id"]?.string == context.conversationID
        && (body["gateway_kid"]?.string == context.gatewayKeyID
          || (body["gateway_kid"] == nil && context.allowLegacyUnbound)),
      "Gateway/conversation binding mismatch")
  }
  static func assertRoster(_ body: GatewayBody, context: GatewayContext) throws {
    try gateRequire(
      Set(try gateRoster(body["eligible_signer_kids"])) == Set(context.participants.keys),
      "Signer roster differs from current policy")
  }
  public static func createRequest(
    identity: Identity, context: GatewayContext, service: String, endpoint: String, verb: String,
    targetURL: String, payload: GatewayJSON? = nil, requiredApprovals: UInt64 = 1,
    lifetime: UInt64 = 3600, requestID: String = UUID().uuidString.lowercased(),
    now: UInt64 = unixSeconds()
  ) throws -> GatewayBody {
    let signer = try context.signer(identity)
    try gateRequire(
      lifetime > 0 && lifetime <= 9_007_199_254_740_991 && now <= 9_007_199_254_740_991 - lifetime,
      "Invalid request lifetime")
    var json = GatewayJSON.object([
      ("type", .string("gate.request")), ("gateway_kid", .string(context.gatewayKeyID)),
      ("conv_id", .string(context.conversationID)), ("request_id", .string(requestID)),
      ("verb", .string(verb)), ("target_endpoint", .string(endpoint)),
      ("target_service", .string(service)), ("target_url", .string(targetURL)),
      ("expires_at", gateDate(now + lifetime)), ("signer_kid", .string(signer)),
      ("signature", .string(Data(repeating: 0, count: 64).base64URL)),
      ("eligible_signer_kids", .array(context.participants.keys.sorted().map(GatewayJSON.string))),
      (
        "required_approvals",
        .uint(
          max(
            requiredApprovals,
            context.requestThreshold(
              service: service, endpoint: endpoint, verb: verb, targetURL: targetURL)))
      ),
    ])
    if let payload { json = json.setting("payload", payload) }
    let unsigned = try GatewayBody(type: "gate.request", json: json)
    json = json.setting(
      "signature",
      .string(
        try QSPCrypto.sign(
          privateKey: identity.privateKey, message: requestSignable(unsigned).encode()
        ).base64URL))
    let body = try GatewayBody(type: "gate.request", json: json)
    try assertRequest(body, context: context)
    return body
  }
  public static func createVote(
    identity: Identity, context: GatewayContext, subject: GatewayBody, approve: Bool,
    now: UInt64 = unixSeconds()
  ) throws -> GatewayBody {
    let signer = try context.signer(identity)
    let proposal = subject.type == .propose
    if proposal {
      try Governance.assertProposal(subject, context: context)
    } else {
      try assertRequest(subject, context: context)
    }
    try gateRequire(!approve || now < gateTime(subject["expires_at"]), "Workflow has expired")
    let kind =
      proposal
      ? (approve ? "gov.approve" : "gov.disapprove")
      : (approve ? "gate.approval" : "gate.disapproval")
    let idKey = proposal ? "proposal_id" : "request_id"
    let id = try gateText(subject[idKey], "workflow ID")
    var json = GatewayJSON.object([
      ("type", .string(kind)), ("gateway_kid", .string(context.gatewayKeyID)),
      ("conv_id", .string(context.conversationID)), (idKey, .string(id)),
      ("signer_kid", .string(signer)),
    ])
    if approve {
      json = json.setting(
        "signature",
        .string(
          try QSPCrypto.sign(
            privateKey: identity.privateKey, message: voteSignable(subject).encode()
          ).base64URL))
    }
    return try GatewayBody(type: kind, json: json)
  }
  static func voteSignable(_ subject: GatewayBody) throws -> CBOR {
    let proposal = subject.type == .propose
    return .map([
      "conv_id": .text(try gateText(subject["conv_id"], "conversation ID")),
      proposal ? "proposal_id" : "request_id": .text(
        try gateText(subject[proposal ? "proposal_id" : "request_id"], "workflow ID")),
      proposal ? "proposal_hash" : "request_hash": .bytes(
        try proposal ? Governance.proposalHash(subject) : requestHash(subject)),
    ])
  }
  public static func createSecret(
    identity: Identity, context: GatewayContext, service: String, value: Data,
    allowedOrigins: [String]? = nil, headerName: String = "Authorization",
    headerTemplate: String = "Bearer {value}", secretID: String = UUID().uuidString.lowercased(),
    ttl: UInt64? = nil
  ) throws -> GatewayBody {
    let signer = try context.signer(identity)
    let origins = try resolveServiceOrigins(service, explicit: allowedOrigins)
    let sealed = try QSPCrypto.sealSecret(
      senderPrivateKey: identity.privateKey, recipientPublicKey: context.gatewayPublicKey,
      plaintext: value)
    var json = GatewayJSON.object([
      ("type", .string("gate.secret")), ("gateway_kid", .string(context.gatewayKeyID)),
      ("secret_id", .string(secretID)), ("service", .string(service)),
      ("allowed_origins", .array(origins.map(GatewayJSON.string))),
      ("header_name", .string(headerName)), ("header_template", .string(headerTemplate)),
      ("encrypted_blob", .string(sealed.base64URL)), ("sender_kid", .string(signer)),
    ])
    if let ttl { json = json.setting("ttl", .uint(ttl)) }
    return try GatewayBody(type: "gate.secret", json: json)
  }
}

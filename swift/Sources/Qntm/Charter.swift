import Foundation

public struct CharterKey: Equatable, Sendable {
  public let keyID: String
  public let publicKey: Data
  public init(publicKey: Data) throws {
    guard QSPCrypto.isValidPublicKey(publicKey) else {
      throw QntmError.invalid("Invalid charter signing key")
    }
    self.publicKey = publicKey
    self.keyID = Data(QSPCrypto.hash(publicKey).prefix(16)).hex
  }
  init(json: CharterJSON) throws {
    _ = try charterObject(json, allowed: ["kid", "pubkey"])
    try self.init(publicKey: charterBytes(json["pubkey"], count: 32))
    try charterCheck(try charterHex(json["kid"], count: 16) == keyID, "Charter key ID mismatch")
  }
  public var json: CharterJSON {
    .object([("kid", .string(keyID)), ("pubkey", .string(publicKey.base64URL))])
  }
}

public struct CharterGovernance: Equatable, Sendable {
  public let keys: [CharterKey]
  public let threshold: Int
  public init(keys: [CharterKey], threshold: Int) throws {
    guard !keys.isEmpty, (1...keys.count).contains(threshold),
      Set(keys.map(\.keyID)).count == keys.count
    else {
      throw QntmError.invalid("Invalid charter governance threshold or keys")
    }
    self.keys = keys
    self.threshold = threshold
  }
  init(json: CharterJSON) throws {
    _ = try charterObject(json, allowed: ["keys", "threshold"])
    guard let keys = json["keys"]?.array else { throw QntmError.invalid("Missing governance keys") }
    let threshold = try charterUInt(json["threshold"])
    guard threshold <= UInt64(Int.max) else {
      throw QntmError.invalid("Invalid governance threshold")
    }
    try self.init(keys: keys.map { try CharterKey(json: $0) }, threshold: Int(threshold))
  }
  public var json: CharterJSON {
    .object([("keys", .array(keys.map(\.json))), ("threshold", .uint(UInt64(threshold)))])
  }
  public func commitment() throws -> String {
    let sorted = try CharterGovernance(
      keys: keys.sorted { $0.keyID < $1.keyID }, threshold: threshold)
    return QSPCrypto.hash(try CharterJSONCodec.canonicalize(sorted.json)).hex
  }
}

public enum CharterStatementType: String, Sendable, CaseIterable {
  case charter
  case constitutionAmend = "constitution.amend"
  case governanceRotate = "governance.rotate"
  case operationalKeyDelegate = "opkey.delegate"
  case operationalKeyRevoke = "opkey.revoke"
  case decommission = "agent.decommission"
  case successor = "agent.successor"
  case liveness = "liveness.update"
  case statement
}
public enum CharterAgentRight: String, Sendable {
  case liveness = "liveness.update"
  case statement
}

public struct CharterStatement: Equatable, Sendable {
  public let json: CharterJSON
  public let signed: CharterJSON
  public let registry: String
  public let agentID: String
  public let sequence: UInt64
  public let previousHash: String
  public let type: CharterStatementType
  public let issuedAt: String
  public let body: CharterJSON
  public let signatures: [CharterSignature]

  public init(data: Data) throws { try self.init(json: CharterJSONCodec.parse(data)) }
  public init(json: CharterJSON) throws {
    _ = try CharterJSONCodec.canonicalize(json)
    try Self.safeIntegers(json)
    _ = try charterObject(json, allowed: ["signed", "signatures"])
    guard let signed = json["signed"], let signatures = json["signatures"]?.array else {
      throw QntmError.invalid("Missing charter signed body")
    }
    _ = try charterObject(
      signed, allowed: ["registry", "agent_id", "seq", "prev_hash", "type", "issued_at", "body"])
    self.registry = try charterText(signed["registry"])
    self.agentID = try charterHex(signed["agent_id"], count: 16)
    self.sequence = try charterUInt(signed["seq"])
    self.previousHash = try charterHex(signed["prev_hash"], count: 32)
    self.issuedAt = try charterTimestamp(signed["issued_at"])
    guard let type = CharterStatementType(rawValue: try charterText(signed["type"])),
      let body = signed["body"]
    else {
      throw QntmError.invalid("Unknown charter type or missing body")
    }
    self.type = type
    self.body = body
    self.signed = signed
    self.signatures = try signatures.map { try CharterSignature(json: $0) }
    guard Set(self.signatures.map(\.keyID)).count == self.signatures.count else {
      throw QntmError.invalid("Duplicate signature key")
    }
    self.json = json
  }
  public func encoded() throws -> Data { try CharterJSONCodec.canonicalize(json) }
  public func hash() throws -> String {
    QSPCrypto.hash(try CharterJSONCodec.canonicalize(signed)).hex
  }
  public func signing(with identity: Identity) throws -> CharterStatement {
    let key = try CharterKey(publicKey: identity.publicKey)
    let bytes = try CharterJSONCodec.canonicalize(signed)
    let signature = try QSPCrypto.sign(privateKey: identity.privateKey, message: bytes)
    guard QSPCrypto.verify(publicKey: identity.publicKey, message: bytes, signature: signature)
    else { throw QntmError.invalid("Identity key mismatch") }
    let signatures =
      self.signatures.filter { $0.keyID != key.keyID } + [
        CharterSignature(keyID: key.keyID, signature: signature)
      ]
    return try CharterStatement(
      json: .object([("signed", signed), ("signatures", .array(signatures.map(\.json)))]))
  }
  public func next(
    type: CharterStatementType, body: CharterJSON, issuedAt: String = Charter.timestamp()
  ) throws -> CharterStatement {
    guard type != .charter, sequence < 9_007_199_254_740_991 else {
      throw QntmError.invalid("Invalid next statement")
    }
    return try Charter.statement(
      registry: registry, agentID: agentID, sequence: sequence + 1, previousHash: hash(),
      type: type, issuedAt: issuedAt, body: body)
  }
  private static func safeIntegers(_ value: CharterJSON) throws {
    switch value {
    case .number(let n):
      if n.rounded() == n && abs(n) > 9_007_199_254_740_991 {
        throw QntmError.invalid("Charter statement contains unsafe integer")
      }
    case .array(let xs): for x in xs { try safeIntegers(x) }
    case .object(let fs): for f in fs { try safeIntegers(f.value) }
    default: break
    }
  }
}

public struct CharterSignature: Equatable, Sendable {
  public let keyID: String
  public let signature: Data
  init(keyID: String, signature: Data) {
    self.keyID = keyID
    self.signature = signature
  }
  init(json: CharterJSON) throws {
    _ = try charterObject(json, allowed: ["kid", "sig"])
    self.keyID = try charterHex(json["kid"], count: 16)
    self.signature = try charterBytes(json["sig"], count: 64)
  }
  var json: CharterJSON {
    .object([("kid", .string(keyID)), ("sig", .string(signature.base64URL))])
  }
}

public struct CharterRecord: Sendable {
  public let registry: String
  public let agentID: String
  public let agentPublicKey: Data
  public fileprivate(set) var sequence: UInt64
  public fileprivate(set) var headHash: String
  public let charter: CharterJSON
  public fileprivate(set) var governance: CharterGovernance?
  public let agentRights: Set<CharterAgentRight>
  public fileprivate(set) var nextGovernanceCommitment: String?
  public fileprivate(set) var constitution: CharterJSON?
  public fileprivate(set) var liveness: CharterJSON?
  public fileprivate(set) var operationalKeys: [String: CharterJSON] = [:]
  public fileprivate(set) var successor: String?
  public fileprivate(set) var decommissioned = false
  public fileprivate(set) var statements: [CharterJSON] = []
}

public enum Charter {
  public static let draftVersion = "0.2"
  public static let genesisHash = String(repeating: "0", count: 64)
  public static func timestamp() -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: Date())
  }
  public static func create(
    registry: String, agent: Identity, governance: CharterGovernance?,
    agentRights: [CharterAgentRight] = [], extensions: CharterJSON? = nil,
    nextGovernanceCommitment: String? = nil, issuedAt: String = timestamp()
  ) throws -> CharterStatement {
    var body: CharterJSON = .object([
      ("agent_pubkey", .string(agent.publicKey.base64URL)),
      ("governance", governance?.json ?? .null),
      ("agent_rights", .array(agentRights.map { .string($0.rawValue) })),
    ])
    if let extensions { body = body.setting("extensions", extensions) }
    if let nextGovernanceCommitment {
      body = body.setting("next_governance_commitment", .string(nextGovernanceCommitment))
    }
    let key = try CharterKey(publicKey: agent.publicKey)
    _ = try validateBody(body, agentID: key.keyID)
    return try statement(
      registry: registry, agentID: key.keyID, sequence: 0, previousHash: genesisHash,
      type: .charter, issuedAt: issuedAt, body: body
    ).signing(with: agent)
  }
  static func statement(
    registry: String, agentID: String, sequence: UInt64, previousHash: String,
    type: CharterStatementType, issuedAt: String, body: CharterJSON
  ) throws -> CharterStatement {
    try CharterStatement(
      json: .object([
        (
          "signed",
          .object([
            ("registry", .string(registry)), ("agent_id", .string(agentID)),
            ("seq", .uint(sequence)), ("prev_hash", .string(previousHash)),
            ("type", .string(type.rawValue)),
            ("issued_at", .string(issuedAt)), ("body", body),
          ])
        ), ("signatures", .array([])),
      ]))
  }

  public static func replay(_ chain: [CharterStatement], registry: String, agentID: String) throws
    -> CharterRecord
  {
    _ = try charterText(.string(registry))
    _ = try charterHex(.string(agentID), count: 16)
    guard !chain.isEmpty else { throw QntmError.invalid("Empty charter chain") }
    var state: CharterRecord?
    for statement in chain {
      try charterCheck(
        statement.registry == registry && statement.agentID == agentID,
        "Registry or agent audience mismatch")
      try charterCheck(
        statement.sequence == (state.map { $0.sequence + 1 } ?? 0), "Charter sequence gap or replay"
      )
      try charterCheck(
        statement.previousHash == (state?.headHash ?? genesisHash), "Previous charter hash mismatch"
      )
      try charterCheck(state?.decommissioned != true, "Decommissioned record is terminal")
      let authority: CharterAuthority
      if let state {
        try charterCheck(statement.type != .charter, "Charter cannot be replaced")
        guard let governance = state.governance else {
          throw QntmError.invalid("Record frozen at birth")
        }
        authority = CharterAuthority(
          agent: state.agentPublicKey, governance: governance, rights: state.agentRights,
          commitment: state.nextGovernanceCommitment)
      } else {
        try charterCheck(statement.type == .charter, "First statement must be a charter")
        authority = try validateBody(statement.body, agentID: agentID)
      }
      var authorized = Dictionary(
        uniqueKeysWithValues: (authority.governance?.keys ?? []).map { ($0.keyID, $0.publicKey) })
      authorized[agentID] = authority.agent
      var valid = Set<String>()
      let bytes = try CharterJSONCodec.canonicalize(statement.signed)
      for signature in statement.signatures {
        guard let key = authorized[signature.keyID],
          QSPCrypto.verify(publicKey: key, message: bytes, signature: signature.signature)
        else {
          throw QntmError.invalid("Invalid signature or key outside current authority")
        }
        valid.insert(signature.keyID)
      }
      let governed =
        authority.governance.map { set in
          set.keys.filter { valid.contains($0.keyID) }.count >= set.threshold
        } ?? false
      if state == nil {
        try charterCheck(valid.contains(agentID), "Charter requires agent signature")
        try charterCheck(
          authority.governance == nil || governed, "Charter requires governance acceptance")
        state = CharterRecord(
          registry: registry, agentID: agentID, agentPublicKey: authority.agent,
          sequence: 0, headHash: try statement.hash(), charter: statement.body,
          governance: authority.governance,
          agentRights: authority.rights, nextGovernanceCommitment: authority.commitment)
        continue
      }
      let agentAllowed =
        CharterAgentRight(rawValue: statement.type.rawValue).map {
          authority.rights.contains($0) && valid.contains(agentID)
        } ?? false
      try charterCheck(governed || agentAllowed, "Statement lacks current governing authority")
      guard var current = state else { throw QntmError.invalid("Missing charter state") }
      let body = statement.body
      switch statement.type {
      case .constitutionAmend: current.constitution = body
      case .liveness: current.liveness = body
      case .statement:
        _ = try charterObject(body)
        let namespace = try charterText(body["namespace"])
        guard let data = body["data"] else {
          throw QntmError.invalid("Namespaced statement missing data")
        }
        var row: CharterJSON = .object([
          ("seq", .uint(statement.sequence)), ("namespace", .string(namespace)), ("data", data),
        ])
        if let schema = body["schema"] {
          row = row.setting("schema", .string(try charterText(schema)))
        }
        current.statements.append(row)
      case .governanceRotate:
        _ = try charterObject(body)
        guard let raw = body["governance"] else {
          throw QntmError.invalid("Missing rotated governance")
        }
        let governance = try CharterGovernance(json: raw)
        if let commitment = current.nextGovernanceCommitment {
          try charterCheck(
            try governance.commitment() == commitment, "Governance rotation commitment mismatch")
        }
        current.governance = governance
        current.nextGovernanceCommitment = try body["next_governance_commitment"].map {
          try charterHex($0, count: 32)
        }
      case .operationalKeyDelegate:
        _ = try charterObject(body)
        let kid = try charterHex(body["kid"], count: 16)
        let scope = try charterText(body["scope"])
        var delegated: CharterJSON = .object([("scope", .string(scope))])
        if let expiry = body["expires_at"] {
          delegated = delegated.setting("expires_at", .string(try charterTimestamp(expiry)))
        }
        current.operationalKeys[kid] = delegated
      case .operationalKeyRevoke:
        _ = try charterObject(body)
        let kid = try charterHex(body["kid"], count: 16)
        try charterCheck(
          current.operationalKeys.removeValue(forKey: kid) != nil, "Operational key not delegated")
      case .successor:
        _ = try charterObject(body)
        let successor = try charterHex(body["agent_id"], count: 16)
        try charterCheck(successor != agentID, "Successor must be a different agent")
        current.successor = successor
      case .decommission: current.decommissioned = true
      case .charter: throw QntmError.invalid("Repeated charter")
      }
      current.sequence = statement.sequence
      current.headHash = try statement.hash()
      state = current
    }
    guard let state else { throw QntmError.invalid("Empty charter chain") }
    return state
  }

  private struct CharterAuthority {
    let agent: Data
    let governance: CharterGovernance?
    let rights: Set<CharterAgentRight>
    let commitment: String?
  }
  private static func validateBody(_ body: CharterJSON, agentID: String) throws -> CharterAuthority
  {
    _ = try charterObject(body)
    let agent = try charterBytes(body["agent_pubkey"], count: 32)
    try charterCheck(try CharterKey(publicKey: agent).keyID == agentID, "Agent key mismatch")
    guard let governanceValue = body["governance"], let rightsValues = body["agent_rights"]?.array
    else {
      throw QntmError.invalid("Missing charter governance or rights")
    }
    let governance = governanceValue == .null ? nil : try CharterGovernance(json: governanceValue)
    let rights = try rightsValues.map { value -> CharterAgentRight in
      guard let right = CharterAgentRight(rawValue: try charterText(value)) else {
        throw QntmError.invalid("Invalid agent right")
      }
      return right
    }
    try charterCheck(Set(rights).count == rights.count, "Duplicate agent right")
    let commitment = try body["next_governance_commitment"].map { try charterHex($0, count: 32) }
    if let extensions = body["extensions"] {
      for field in try charterObject(extensions) { _ = try charterText(.string(field.key)) }
    }
    return CharterAuthority(
      agent: agent, governance: governance, rights: Set(rights), commitment: commitment)
  }
}

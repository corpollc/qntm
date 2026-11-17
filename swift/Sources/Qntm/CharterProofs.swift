import Foundation

public struct CharterTrust: Sendable {
  public let registry: String
  public let registrar: CharterKey
  public init(registry: String, registrar: CharterKey) throws {
    guard !registry.isEmpty else { throw QntmError.invalid("Registry pin is empty") }
    self.registry = registry
    self.registrar = registrar
  }
}

public struct CharterHeads: Sendable {
  public let json: CharterJSON
  public let log: CharterJSON
  public let epoch: CharterJSON
  public let treeSize: UInt64
  public let rootHash: String
  public let mapSize: UInt64
  public let mapRoot: String
  public let registry: String

  /// Authenticates signed heads using an independently configured registrar pin.
  public init(json: CharterJSON, trust: CharterTrust) throws {
    _ = try CharterJSONCodec.canonicalize(json)
    guard let signedLog = json["log"], let signedEpoch = json["epoch"],
      let log = signedLog["signed"], let epoch = signedEpoch["signed"]
    else { throw QntmError.invalid("Missing registrar heads") }
    for head in [signedLog, signedEpoch] {
      guard let signed = head["signed"] else { throw QntmError.invalid("Missing signed head") }
      try charterCheck(
        signed["registry"] == .string(trust.registry)
          && head["kid"] == .string(trust.registrar.keyID), "Head audience or key mismatch")
      try charterCheck(
        try QSPCrypto.verify(
          publicKey: trust.registrar.publicKey,
          message: CharterJSONCodec.canonicalize(signed),
          signature: charterBytes(head["sig"], count: 64)), "Invalid registrar signature")
      _ = try charterTimestamp(signed["timestamp"])
    }
    try charterCheck(
      log["kind"] == .string("charter.log") && epoch["kind"] == .string("charter.epoch"),
      "Head domain mismatch")
    let treeSize = try charterUInt(log["tree_size"])
    let mapSize = try charterUInt(epoch["map_size"])
    let root = try charterHex(log["root_hash"], count: 32)
    let mapRoot = try charterHex(epoch["map_root"], count: 32)
    try charterCheck(
      try charterUInt(epoch["epoch"]) == mapSize && charterUInt(epoch["log_size"]) == treeSize
        && mapSize == treeSize,
      "Epoch/log size mismatch")
    try charterCheck(
      try charterHex(epoch["log_root"], count: 32) == root
        && epoch["timestamp"] == log["timestamp"], "Epoch/log root mismatch")
    if treeSize == 0 {
      try charterCheck(
        root == CharterProofs.emptyHash && mapRoot == CharterProofs.emptyHash,
        "Invalid empty tree roots")
    }
    self.json = json
    self.log = log
    self.epoch = epoch
    self.treeSize = treeSize
    self.rootHash = root
    self.mapSize = mapSize
    self.mapRoot = mapRoot
    self.registry = trust.registry
  }
}

public enum CharterProofs {
  static let emptyHash = QSPCrypto.hash(Data()).hex

  public static func verifyInclusion(_ proof: CharterJSON, heads: CharterHeads) throws {
    guard let entry = proof["entry"] else { throw QntmError.invalid("Missing log entry") }
    _ = try charterTimestamp(entry["received_at"])
    try charterCheck(
      try inclusionRoot(
        hash: leaf(entry), index: charterUInt(proof["index"]), count: heads.treeSize,
        siblings: hashes(proof["siblings"])) == heads.rootHash, "Log inclusion proof mismatch")
  }

  public static func verifyConsistency(older: CharterHeads, newer: CharterHeads, proof: [String])
    throws
  {
    try charterCheck(
      older.registry == newer.registry && older.treeSize <= newer.treeSize && proof.count <= 54,
      "Invalid consistency range")
    if older.treeSize == 0 {
      try charterCheck(
        older.rootHash == emptyHash && proof.isEmpty
          && (newer.treeSize != 0 || newer.rootHash == emptyHash), "Invalid empty consistency proof"
      )
      return
    }
    var used = 0
    func take() throws -> String {
      guard used < proof.count else { throw QntmError.invalid("Truncated consistency proof") }
      let value = proof[used]
      used += 1
      _ = try charterHex(.string(value), count: 32)
      return value
    }
    func visit(_ old: UInt64, _ new: UInt64, _ complete: Bool) throws -> (String, String) {
      if old == new {
        let hash = try complete ? older.rootHash : take()
        return (hash, hash)
      }
      let split = split(new)
      if old <= split {
        let (a, b) = try visit(old, split, complete)
        return (a, try node(b, take()))
      }
      let (a, b) = try visit(old - split, new - split, false)
      let left = try take()
      return (try node(left, a), try node(left, b))
    }
    let (oldRoot, newRoot) = try visit(older.treeSize, newer.treeSize, true)
    try charterCheck(
      used == proof.count && oldRoot == older.rootHash && newRoot == newer.rootHash,
      "Consistency proof mismatch")
  }

  public static func verifyChainResponse(
    _ response: CharterJSON, trust: CharterTrust, agentID: String
  ) throws -> CharterRecord? {
    _ = try charterHex(.string(agentID), count: 16)
    guard let rawHeads = response["heads"], let proof = response["proof"],
      let chain = response["chain"]?.array,
      case .bool(let present)? = proof["present"]
    else { throw QntmError.invalid("Invalid charter chain response") }
    let heads = try CharterHeads(json: rawHeads, trust: trust)
    try charterCheck(proof["agent_id"] == .string(agentID), "Range proof audience mismatch")
    guard let leftValue = proof["left"], let rightValue = proof["right"] else {
      throw QntmError.invalid("Missing range boundaries")
    }
    let left = leftValue == .null ? nil : try witness(leftValue, heads: heads)
    let right = rightValue == .null ? nil : try witness(rightValue, heads: heads)
    switch (left, right) {
    case (nil, nil):
      try charterCheck(heads.mapSize == 0 && heads.mapRoot == emptyHash, "Missing range witnesses")
    case (nil, let right?): try charterCheck(right.index == 0, "Invalid lower range boundary")
    case (let left?, nil):
      try charterCheck(
        heads.mapSize > 0 && left.index == heads.mapSize - 1, "Invalid upper range boundary")
    case (let left?, let right?):
      try charterCheck(left.index + 1 == right.index, "Range witnesses not adjacent")
    }
    if let right { try charterCheck(right.agentID > agentID, "Invalid successor boundary") }
    if !present {
      try charterCheck(
        chain.isEmpty && (left == nil || left!.agentID < agentID), "Invalid non-membership proof")
      return nil
    }
    guard let left, left.agentID == agentID, UInt64(chain.count) == left.sequence + 1 else {
      throw QntmError.invalid("Incomplete charter chain")
    }
    let record = try Charter.replay(
      chain.map { try CharterStatement(json: $0) }, registry: trust.registry, agentID: agentID)
    try charterCheck(record.headHash == left.statementHash, "Chain head does not match map")
    return record
  }

  public static func verifyReceipt(
    _ receipt: CharterJSON, statement: CharterStatement, trust: CharterTrust
  ) throws {
    guard let rawHeads = receipt["heads"], let inclusion = receipt["inclusion"],
      let includedStatement = inclusion["entry"]?["statement"]
    else { throw QntmError.invalid("Invalid charter receipt") }
    let heads = try CharterHeads(json: rawHeads, trust: trust)
    try charterCheck(
      try statement.registry == trust.registry
        && receipt["statement_hash"] == .string(statement.hash())
        && charterUInt(receipt["index"]) == charterUInt(inclusion["index"])
        && CharterJSONCodec.canonicalize(includedStatement) == statement.encoded(),
      "Receipt for a different statement")
    try verifyInclusion(inclusion, heads: heads)
  }

  public static func auditSnapshot(entries: [CharterJSON], heads: CharterHeads, trust: CharterTrust)
    throws
  {
    _ = try CharterHeads(json: heads.json, trust: trust)
    try charterCheck(UInt64(entries.count) == heads.treeSize, "Snapshot log length mismatch")
    var chains: [String: [CharterStatement]] = [:]
    var map: [(agent: String, sequence: UInt64, value: CharterJSON)] = []
    let log = try entries.map { entry -> String in
      _ = try charterTimestamp(entry["received_at"])
      guard let raw = entry["statement"] else {
        throw QntmError.invalid("Missing snapshot statement")
      }
      let statement = try CharterStatement(json: raw)
      chains[statement.agentID, default: []].append(statement)
      let value: CharterJSON = .object([
        ("agent_id", .string(statement.agentID)), ("seq", .uint(statement.sequence)),
        ("statement_hash", .string(try statement.hash())),
      ])
      map.append((statement.agentID, statement.sequence, value))
      return try leaf(entry)
    }
    for (agent, chain) in chains {
      _ = try Charter.replay(chain, registry: trust.registry, agentID: agent)
    }
    map.sort { $0.agent == $1.agent ? $0.sequence < $1.sequence : $0.agent < $1.agent }
    try charterCheck(
      try root(log) == heads.rootHash && root(map.map { try leaf($0.value) }) == heads.mapRoot,
      "Snapshot log/map mismatch")
  }

  static func hashes(_ value: CharterJSON?) throws -> [String] {
    guard let values = value?.array else { throw QntmError.invalid("Invalid Merkle path") }
    return try values.map { try charterHex($0, count: 32) }
  }
  private static func leaf(_ value: CharterJSON) throws -> String {
    QSPCrypto.hash(Data([0]) + (try CharterJSONCodec.canonicalize(value))).hex
  }
  private static func node(_ left: String, _ right: String) throws -> String {
    QSPCrypto.hash(Data([1]) + (try Data(hex: left)) + (try Data(hex: right))).hex
  }
  private static func split(_ count: UInt64) -> UInt64 {
    var result: UInt64 = 1
    while result * 2 < count { result *= 2 }
    return result
  }
  private static func root(_ values: [String]) throws -> String {
    if values.isEmpty { return emptyHash }
    if values.count == 1 { return values[0] }
    let split = Int(split(UInt64(values.count)))
    return try node(root(Array(values[..<split])), root(Array(values[split...])))
  }
  private static func inclusionRoot(hash: String, index: UInt64, count: UInt64, siblings: [String])
    throws -> String
  {
    try charterCheck(
      count > 0 && index < count && siblings.count <= 53, "Invalid inclusion index/path")
    var used = 0
    func visit(_ index: UInt64, _ count: UInt64) throws -> String {
      if count == 1 { return hash }
      let split = split(count)
      let child = try index < split ? visit(index, split) : visit(index - split, count - split)
      guard used < siblings.count else { throw QntmError.invalid("Truncated inclusion path") }
      let sibling = siblings[used]
      used += 1
      _ = try charterHex(.string(sibling), count: 32)
      return try index < split ? node(child, sibling) : node(sibling, child)
    }
    let root = try visit(index, count)
    try charterCheck(used == siblings.count, "Extra inclusion path elements")
    return root
  }
  private struct Witness {
    let agentID: String
    let sequence: UInt64
    let statementHash: String
    let index: UInt64
  }
  private static func witness(_ value: CharterJSON, heads: CharterHeads) throws -> Witness {
    guard let raw = value["leaf"] else { throw QntmError.invalid("Missing map leaf") }
    let agent = try charterHex(raw["agent_id"], count: 16)
    let sequence = try charterUInt(raw["seq"])
    let hash = try charterHex(raw["statement_hash"], count: 32)
    let index = try charterUInt(value["index"])
    try charterCheck(
      try inclusionRoot(
        hash: leaf(raw), index: index, count: heads.mapSize, siblings: hashes(value["siblings"]))
        == heads.mapRoot,
      "Map inclusion proof mismatch")
    return Witness(agentID: agent, sequence: sequence, statementHash: hash, index: index)
  }
}

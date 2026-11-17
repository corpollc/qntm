import XCTest

@testable import Qntm

final class CharterTests: XCTestCase {
  private func vectors() throws -> CharterJSON {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent()
    return try CharterJSONCodec.parse(
      Data(contentsOf: root.appendingPathComponent("specs/test-vectors/charter-registry-v02.json")))
  }

  func testAllSharedAuthorityVectors() throws {
    for row in try XCTUnwrap(vectors()["cases"]?.array) {
      let name = try XCTUnwrap(row["name"]?.string)
      let replay = { () throws -> CharterRecord in
        let chain = try XCTUnwrap(row["chain"]?.array).map { try CharterStatement(json: $0) }
        return try Charter.replay(
          chain, registry: XCTUnwrap(row["registry"]?.string),
          agentID: XCTUnwrap(row["agent_id"]?.string))
      }
      if row["valid"] == .bool(true) {
        XCTAssertEqual(try replay().headHash, row["head_hash"]?.string, name)
      } else {
        XCTAssertThrowsError(try replay(), name)
      }
    }
  }

  func testAllSharedCanonicalJSONVectors() throws {
    for row in try XCTUnwrap(vectors()["json"]?.array) {
      let name = try XCTUnwrap(row["name"]?.string)
      let input = try XCTUnwrap(row["input"]?.string)
      let canonical = { () throws -> String in
        String(
          decoding: try CharterJSONCodec.canonicalize(CharterJSONCodec.parse(Data(input.utf8))),
          as: UTF8.self)
      }
      if row["canonical"] == .null {
        XCTAssertThrowsError(try canonical(), name)
      } else {
        XCTAssertEqual(try canonical(), row["canonical"]?.string, name)
      }
    }
  }

  func testConstructionSignaturesRotationAndFrozenCharter() throws {
    let agent = try Identity()
    let governor = try Identity()
    let nextGovernor = try Identity()
    let governance = try CharterGovernance(
      keys: [CharterKey(publicKey: governor.publicKey)], threshold: 1)
    let nextGovernance = try CharterGovernance(
      keys: [CharterKey(publicKey: nextGovernor.publicKey)], threshold: 1)
    let genesis = try Charter.create(
      registry: "example", agent: agent, governance: governance,
      agentRights: [.statement], nextGovernanceCommitment: nextGovernance.commitment()
    ).signing(with: governor)
    let experiment = try genesis.next(
      type: .statement, body: .object([("namespace", .string("example.test")), ("data", .null)])
    ).signing(with: agent)
    let rotation = try experiment.next(
      type: .governanceRotate, body: .object([("governance", nextGovernance.json)])
    ).signing(with: governor)
    let amended = try rotation.next(type: .constitutionAmend, body: .string("Constitution"))
      .signing(with: nextGovernor)
    let result = try Charter.replay(
      [genesis, experiment, rotation, amended], registry: "example", agentID: genesis.agentID)
    XCTAssertEqual(result.sequence, 3)
    XCTAssertEqual(result.constitution, .string("Constitution"))
    XCTAssertEqual(result.governance, nextGovernance)
    XCTAssertEqual(try genesis.signing(with: governor).signatures.count, 2)
    let frozen = try Charter.create(registry: "example", agent: agent, governance: nil)
    let attempted = try frozen.next(
      type: .statement, body: .object([("namespace", .string("x")), ("data", .null)])
    ).signing(with: agent)
    XCTAssertThrowsError(
      try Charter.replay([frozen, attempted], registry: "example", agentID: frozen.agentID))
  }

  func testPinnedProofsReceiptRangeAndSnapshot() throws {
    let agent = try Identity()
    let registrar = try Identity()
    let trust = try CharterTrust(
      registry: "test", registrar: CharterKey(publicKey: registrar.publicKey))
    let statement = try Charter.create(
      registry: "test", agent: agent, governance: nil, issuedAt: "2026-09-08T12:00:00Z")
    let time = CharterJSON.string("2026-09-08T12:00:01Z")
    let entry: CharterJSON = .object([("statement", statement.json), ("received_at", time)])
    let map: CharterJSON = .object([
      ("agent_id", .string(statement.agentID)), ("seq", .uint(0)),
      ("statement_hash", .string(try statement.hash())),
    ])
    func leaf(_ value: CharterJSON) throws -> String {
      QSPCrypto.hash(Data([0]) + (try CharterJSONCodec.canonicalize(value))).hex
    }
    let log: CharterJSON = .object([
      ("kind", .string("charter.log")), ("registry", .string("test")), ("tree_size", .uint(1)),
      ("root_hash", .string(try leaf(entry))), ("timestamp", time),
    ])
    let epoch: CharterJSON = .object([
      ("kind", .string("charter.epoch")), ("registry", .string("test")), ("epoch", .uint(1)),
      ("map_size", .uint(1)), ("map_root", .string(try leaf(map))), ("log_size", .uint(1)),
      ("log_root", .string(try leaf(entry))), ("timestamp", time),
    ])
    func sign(_ value: CharterJSON) throws -> CharterJSON {
      .object([
        ("signed", value), ("kid", .string(trust.registrar.keyID)),
        (
          "sig",
          .string(
            try QSPCrypto.sign(
              privateKey: registrar.privateKey, message: CharterJSONCodec.canonicalize(value)
            ).base64URL)
        ),
      ])
    }
    let rawHeads: CharterJSON = .object([("log", try sign(log)), ("epoch", try sign(epoch))])
    let heads = try CharterHeads(json: rawHeads, trust: trust)
    let inclusion: CharterJSON = .object([
      ("entry", entry), ("index", .uint(0)), ("siblings", .array([])),
    ])
    let receipt: CharterJSON = .object([
      ("index", .uint(0)), ("statement_hash", .string(try statement.hash())),
      ("inclusion", inclusion), ("heads", rawHeads),
    ])
    try CharterProofs.verifyReceipt(receipt, statement: statement, trust: trust)
    try CharterProofs.auditSnapshot(entries: [entry], heads: heads, trust: trust)
    try CharterProofs.verifyConsistency(older: heads, newer: heads, proof: [])
    let witness: CharterJSON = .object([
      ("leaf", map), ("index", .uint(0)), ("siblings", .array([])),
    ])
    let proof: CharterJSON = .object([
      ("agent_id", .string(statement.agentID)), ("present", .bool(true)), ("left", witness),
      ("right", .null),
    ])
    let response: CharterJSON = .object([
      ("chain", .array([statement.json])), ("proof", proof), ("heads", rawHeads),
    ])
    XCTAssertEqual(
      try CharterProofs.verifyChainResponse(response, trust: trust, agentID: statement.agentID)?
        .headHash, try statement.hash())
    let wrongTrust = try CharterTrust(
      registry: "test", registrar: CharterKey(publicKey: Identity().publicKey))
    XCTAssertThrowsError(try CharterHeads(json: rawHeads, trust: wrongTrust))
    XCTAssertThrowsError(
      try CharterProofs.verifyInclusion(inclusion.setting("index", .uint(1)), heads: heads))
    XCTAssertThrowsError(
      try CharterProofs.verifyConsistency(
        older: heads, newer: heads, proof: [String(repeating: "0", count: 64)]))
    XCTAssertThrowsError(
      try CharterProofs.auditSnapshot(
        entries: [entry.setting("received_at", .string("2026-09-08T12:00:02Z"))], heads: heads,
        trust: trust))
  }
}

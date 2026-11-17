import XCTest

@testable import Qntm

@MainActor final class CharterLiveTests: XCTestCase {
  func testGoRegistrarRoundTripProofsAndRestart() async throws {
    guard let binary = ProcessInfo.processInfo.environment["QNTM_CHARTER_BINARY"] else {
      throw XCTSkip("Set QNTM_CHARTER_BINARY to the built Go reference registrar")
    }
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
      "qntm-swift-charter-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    func start() throws -> (Process, CharterRegistryClient) {
      let process = Process()
      let pipe = Pipe()
      process.executableURL = URL(fileURLWithPath: binary)
      process.arguments = [
        "--listen", "127.0.0.1:0", "--data-dir", directory.path, "--registry", "swift.interop",
      ]
      process.standardOutput = pipe
      process.standardError = FileHandle.standardError
      try process.run()
      var line = Data()
      while let next = try pipe.fileHandleForReading.read(upToCount: 1), !next.isEmpty {
        if next == Data([10]) { break }
        line.append(next)
        guard line.count < 16_384 else {
          process.terminate()
          throw QntmError.invalid("Registrar startup output too large")
        }
      }
      let info = try CharterJSONCodec.parse(line)
      let address = try XCTUnwrap(info["listen"]?.string)
      let registrar = try CharterKey(json: XCTUnwrap(info["registrar"]))
      let trust = try CharterTrust(registry: "swift.interop", registrar: registrar)
      return (
        process,
        try CharterRegistryClient(
          baseURL: XCTUnwrap(URL(string: "http://" + address)), trust: trust)
      )
    }
    var (process, client) = try start()
    defer {
      if process.isRunning {
        process.terminate()
        process.waitUntilExit()
      }
    }
    let empty = try await client.heads()
    XCTAssertEqual(empty.treeSize, 0)
    let absent = try await client.chain(agentID: String(repeating: "0", count: 32))
    XCTAssertNil(absent.record)
    var agents: [(Identity, CharterStatement)] = []
    let governor = try Identity()
    let governance = try CharterGovernance(
      keys: [CharterKey(publicKey: governor.publicKey)], threshold: 1)
    for _ in 0..<2 {
      let identity = try Identity()
      let genesis = try Charter.create(
        registry: "swift.interop", agent: identity, governance: governance,
        agentRights: [.statement],
        extensions: .object([("example", .array([.number(1e-7), .number(333333333.33333329)]))])
      ).signing(with: governor)
      _ = try await client.submit(genesis)
      agents.append((identity, genesis))
    }
    for _ in 0..<2 {
      for index in agents.indices {
        let next = try agents[index].1.next(
          type: .statement,
          body: .object([
            ("namespace", .string("swift.interop")),
            ("data", .object([("2", .uint(2)), ("10", .uint(10)), ("unicode", .string("🎨"))])),
          ])
        ).signing(with: agents[index].0)
        _ = try await client.submit(next)
        agents[index].1 = next
      }
    }
    let heads = try await client.heads()
    XCTAssertEqual(heads.treeSize, 6)
    try CharterProofs.auditSnapshot(
      entries: await client.log(heads: heads), heads: heads, trust: client.trust)
    var history: [CharterHeads] = []
    for size in 0...heads.treeSize {
      history.append(try await client.heads(size: size))
      for (_, statement) in agents {
        _ = try await client.chain(agentID: statement.agentID, size: size)
      }
    }
    for from in history.indices {
      for to in from..<history.count {
        _ = try await client.consistency(older: history[from], newer: history[to])
      }
    }
    let first = agents[0].1
    let current = try await client.chain(agentID: first.agentID)
    XCTAssertEqual(current.record?.headHash, try first.hash())
    do {
      _ = try await client.submit(first)
      XCTFail("Duplicate sequence accepted")
    } catch let error as CharterRegistryError { XCTAssertEqual(error.status, 409) }
    let oldTrust = client.trust
    process.terminate()
    process.waitUntilExit()
    (process, client) = try start()
    XCTAssertEqual(client.trust.registrar, oldTrust.registrar)
    let after = try await client.heads()
    XCTAssertEqual(after.json, heads.json)
    let restored = try await client.chain(agentID: first.agentID)
    XCTAssertEqual(restored.record?.sequence, 2)
  }
}

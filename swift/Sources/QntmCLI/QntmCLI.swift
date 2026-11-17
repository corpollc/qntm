import Foundation
import Qntm

#if canImport(Darwin)
  import Darwin
#else
  import Glibc
#endif

struct Arguments {
  var values: [String]
  mutating func flag(_ name: String) -> Bool {
    guard let i = values.firstIndex(of: name) else { return false }
    values.remove(at: i)
    return true
  }
  mutating func option(_ name: String) throws -> String? {
    guard let i = values.firstIndex(of: name) else { return nil }
    guard i + 1 < values.count else { throw QntmError.invalid("Missing value for \(name)") }
    values.remove(at: i)
    return values.remove(at: i)
  }
  mutating func take(_ label: String) throws -> String {
    guard !values.isEmpty else {
      throw QntmError.invalid("Missing \(label); run qntm-swift --help")
    }
    return values.removeFirst()
  }
  mutating func number(_ name: String, default fallback: UInt64) throws -> UInt64 {
    guard let value = try option(name) else { return fallback }
    guard let number = UInt64(value) else {
      throw QntmError.invalid("\(name) must be a nonnegative integer")
    }
    return number
  }
  func finish() throws {
    guard values.isEmpty else {
      throw QntmError.invalid("Unexpected arguments: \(values.joined(separator: " "))")
    }
  }
}
private enum Output {
  static let lock = NSLock()
  static func write(_ object: Any) throws {
    let data = try JSONSerialization.data(
      withJSONObject: object, options: [.sortedKeys, .fragmentsAllowed])
    lock.lock()
    defer { lock.unlock() }
    FileHandle.standardOutput.write(data + Data([10]))
  }
  static func encode<T: Encodable>(_ value: T) throws -> Any {
    try JSONSerialization.jsonObject(with: JSONEncoder().encode(value))
  }
  static func result(_ data: Any) throws { try write(["ok": true, "data": data]) }
  static func envelope(_ value: Envelope) throws {
    try result([
      "conversation_id": value.conversationID.hex, "message_id": value.messageID.hex,
      "epoch": value.epoch,
    ])
  }
}

@main struct QntmCLI {
  static let help = """
    qntm-swift [--config-dir PATH] [--relay-url URL] COMMAND

    identity generate|show|export|import FILE
    convo create [--name NAME] [--group] [--members PK,PK]
    convo join TOKEN [--name NAME] | list | invite ID [--recipient PK] | rename ID NAME
    send ID TEXT [--body-type TYPE] [--ttl SECONDS] [--file PATH]
    recv ID [--watch]             JSON receive events; Ctrl-C stops watching
    history ID                   Saved verified messages
    retry ID                     Retry durable pending sends with the same IDs
    group members|rekey ID | add ID PK... | remove ID KID...
    file send ID PATH [--media-type MIME] | get ID MESSAGE_ID OUTPUT
    gate promote ID --gateway-url URL [--threshold N]
    gate request ID --service NAME --endpoint PATH --url URL [--verb GET] [--payload JSON]
    gate approve|disapprove ID REQUEST_ID | pending ID
    gate secret ID --service NAME --file PATH [--origin URL] [--header NAME] [--template FORMAT]
    gate recipes ID | run ID RECIPE [--arg NAME=VALUE]...
    gate send ID TYPE JSON_FILE   Validated gateway or governance body
    gov propose ID --floor N | --add PK,PK | --remove KID,KID | --rules JSON_FILE
    gov approve|disapprove ID PROPOSAL_ID | pending ID
    guidance list | prepare PROVIDER QUESTION [--context TEXT] | send PREPARED_FILE

    Public keys accept hex or base64url. Profiles are private, locked, atomic files.
    The library also exposes charter, announcements, DID/entity and protocol APIs.
    """
  static func main() async {
    do { try await run() } catch {
      try? Output.write(["ok": false, "error": String(describing: error)])
      exit(1)
    }
  }
  static func key(_ value: String, length: Int = 32) throws -> Data {
    let result = value.count == length * 2 ? try Data(hex: value) : try Data.fromBase64URL(value)
    guard result.count == length else { throw QntmError.invalid("Expected \(length)-byte key") }
    return result
  }
  static func run() async throws {
    var args = Arguments(values: Array(CommandLine.arguments.dropFirst()))
    if args.values.isEmpty || args.flag("--help") || args.flag("-h") {
      print(help)
      return
    }
    if args.flag("--version") {
      print("qntm-swift \(QntmVersion.version) (\(QntmVersion.specification))")
      return
    }
    let directory =
      try args.option("--config-dir")
      ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".qntm-swift").path
    let relay = try args.option("--relay-url").map { value -> URL in
      guard let url = URL(string: value) else { throw QntmError.invalid("Invalid relay URL") }
      return url
    }
    let command = try args.take("command")
    if command == "identity", args.values.first == "import" {
      _ = try args.take("import")
      let path = try args.take("identity file")
      try args.finish()
      let identity = try Identity(serialized: Data(contentsOf: URL(fileURLWithPath: path)))
      let client = try QntmClient(
        store: FileProfileStore(directory: URL(fileURLWithPath: directory)), identity: identity,
        relayURL: relay)
      try Output.result(publicIdentity(await client.identity()))
      return
    }
    let client = try QntmClient(
      store: FileProfileStore(directory: URL(fileURLWithPath: directory)), relayURL: relay)
    let identity = try await client.identity()
    switch command {
    case "identity":
      let operation = try args.take("identity operation")
      switch operation {
      case "generate", "show":
        try args.finish()
        try Output.result(publicIdentity(identity))
      case "export":
        let path = try args.take("output file")
        try args.finish()
        let fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
          throw QntmError.invalid("Cannot create identity export; destination must not exist")
        }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try handle.write(contentsOf: identity.serialize())
        try handle.synchronize()
        try Output.result(["path": path])
      default: throw QntmError.invalid("Unknown identity operation")
      }
    case "convo":
      switch try args.take("conversation operation") {
      case "create":
        let name = try args.option("--name")
        let group = args.flag("--group")
        let members =
          try args.option("--members")?.split(separator: ",").map { try key(String($0)) } ?? []
        try args.finish()
        let saved = try await client.createConversation(
          name: name, type: group ? .group : .direct, memberPublicKeys: members)
        try Output.result(conversationInfo(saved, includeInvite: true))
      case "join":
        let name = try args.option("--name")
        let token = try args.take("invite")
        try args.finish()
        try Output.result(conversationInfo(await client.join(token, name: name)))
      case "list":
        try args.finish()
        let profile = await client.snapshot()
        try Output.result([
          "conversations": profile.conversations.values.sorted {
            $0.conversation.id.hex < $1.conversation.id.hex
          }.map { conversationInfo($0) }
        ])
      case "rename":
        let cid = try args.take("conversation")
        let name = try args.take("name")
        try args.finish()
        try await client.rename(cid, name: name)
        try Output.result(["name": name])
      case "invite":
        let recipient = try args.option("--recipient")
        let saved = try await client.conversation(args.take("conversation"))
        try args.finish()
        let token: String
        if saved.conversation.currentEpoch > 0 {
          guard let recipient, let roster = saved.group?.roster, let rekeyID = saved.lastRekeyID
          else { throw QntmError.invalid("Current-epoch group invite requires --recipient") }
          token = try GroupBootstrap.create(
            identity: identity, conversation: saved.conversation, state: roster,
            recipientPublicKey: key(recipient), rekeyID: rekeyID)
        } else {
          token = try require(saved.conversation.inviteToken, "No stored invitation")
        }
        try Output.result(["invite_token": token, "invite_url": "https://chat.corpo.llc/#" + token])
      default: throw QntmError.invalid("Unknown conversation operation")
      }
    case "send":
      let type = try args.option("--body-type") ?? "text"
      let ttl = try args.number("--ttl", default: 2_592_000)
      let file = try args.option("--file")
      let cid = try args.take("conversation")
      let body: Data
      if let file {
        body = try Data(contentsOf: URL(fileURLWithPath: file))
      } else {
        body = Data(try args.take("message").utf8)
      }
      try args.finish()
      try Output.envelope(await client.send(cid, bodyType: type, body: body, ttl: ttl))
    case "recv":
      let watch = args.flag("--watch")
      let cid = try args.take("conversation")
      try args.finish()
      if watch {
        try await client.watch(
          cid, onError: { error in FileHandle.standardError.write(Data((error + "\n").utf8)) },
          onEvent: { event in try Output.write(Output.encode(event)) })
      } else {
        let events = try await client.receive(cid)
        try Output.result(["messages": events.map { try Output.encode($0.message) }])
        try await client.acknowledge(cid, eventIDs: Set(events.map(\.eventID)))
      }
    case "history":
      let cid = try args.take("conversation")
      try args.finish()
      try Output.result([
        "messages": try await client.conversation(cid).history.map { try Output.encode($0.message) }
      ])
    case "retry":
      let cid = try args.take("conversation")
      try args.finish()
      try Output.result(["sequences": await client.flush(conversationID: cid)])
    case "group":
      let operation = try args.take("group operation")
      let cid = try args.take("conversation")
      switch operation {
      case "members":
        try args.finish()
        let saved = try await client.conversation(cid)
        try Output.result([
          "members": saved.group?.roster?.orderedMembers.map {
            [
              "key_id": $0.keyID.hex, "public_key": $0.publicKey.base64URL,
              "role": $0.role.rawValue,
            ]
          } ?? []
        ])
      case "rekey":
        try args.finish()
        try Output.envelope(await client.rekey(cid))
      case "add":
        let keys = try args.values.map { try key($0) }
        guard !keys.isEmpty else { throw QntmError.invalid("Supply member keys") }
        try Output.result(["invitations": await client.addMembers(cid, publicKeys: keys)])
      case "remove":
        let keys = try args.values.map { try key($0, length: 16) }
        guard !keys.isEmpty else { throw QntmError.invalid("Supply member IDs") }
        try await client.removeMembers(cid, keyIDs: keys)
        try Output.result(["removed": keys.map(\.hex)])
      default: throw QntmError.invalid("Unknown group operation")
      }
    case "file": try await fileCommand(&args, client: client)
    case "gate", "gov":
      try await gatewayCommand(&args, client: client, governance: command == "gov")
    case "guidance": try await guidanceCommand(&args, client: client)
    default: throw QntmError.invalid("Unknown command: \(command)")
    }
  }
  static func require<T>(_ value: T?, _ message: String) throws -> T {
    guard let value else { throw QntmError.invalid(message) }
    return value
  }
  static func publicIdentity(_ identity: Identity) -> [String: String] {
    ["key_id": identity.keyID.hex, "public_key": identity.publicKey.base64URL]
  }
  static func conversationInfo(_ saved: SavedConversation, includeInvite: Bool = false) -> [String:
    Any]
  {
    var value: [String: Any] = [
      "conversation_id": saved.conversation.id.hex, "type": saved.conversation.type.rawValue,
      "epoch": saved.conversation.currentEpoch, "cursor": saved.cursor,
      "gateway_accepted": saved.gateway.accepted,
    ]
    if let name = saved.conversation.name { value["name"] = name }
    if includeInvite, let token = saved.conversation.inviteToken { value["invite_token"] = token }
    return value
  }
  static func fileCommand(_ args: inout Arguments, client: QntmClient) async throws {
    let operation = try args.take("file operation")
    let media = try args.option("--media-type") ?? "application/octet-stream"
    let cid = try args.take("conversation")
    if operation == "send" {
      let path = try args.take("file")
      try args.finish()
      try Output.envelope(
        await client.sendAttachment(
          cid, data: Data(contentsOf: URL(fileURLWithPath: path)),
          name: URL(fileURLWithPath: path).lastPathComponent, mediaType: media))
    } else if operation == "get" {
      let messageID = try args.take("message ID")
      let path = try args.take("output file")
      try args.finish()
      let saved = try await client.conversation(cid)
      let profile = await client.snapshot()
      let event = try require(
        saved.history.first {
          $0.message.messageID == messageID && $0.message.bodyType == Attachment.bodyType
        }, "Attachment message not found")
      let senderID = try Data(hex: event.message.senderKeyID)
      let gatewayKey = saved.gateway.context?.gatewayPublicKey
      let sender = try require(
        saved.historyKeys[senderID.base64URL] ?? saved.members[senderID.base64URL]
          ?? gatewayKey.flatMap { QSPCrypto.hash($0).prefix(16) == senderID ? $0 : nil },
        "Attachment sender key unavailable")
      let body = Data(try require(event.message.unsafeBody, "Invalid attachment body").utf8)
      let descriptor = try JSONDecoder().decode(AttachmentDescriptor.self, from: body)
      let context = try AttachmentContext(
        conversationID: saved.conversation.id, epoch: descriptor.parentEpoch,
        senderPublicKey: sender)
      let data = try await Attachment.download(
        body, context: context, relay: DropboxClient(baseURL: profile.relayURL))
      guard !FileManager.default.fileExists(atPath: path) else {
        throw QntmError.invalid("Output already exists")
      }
      try data.write(to: URL(fileURLWithPath: path), options: .withoutOverwriting)
      try Output.result(["path": path, "bytes": data.count])
    } else {
      throw QntmError.invalid("Unknown file operation")
    }
  }
  static func gatewayCommand(_ args: inout Arguments, client: QntmClient, governance: Bool)
    async throws
  {
    let operation = try args.take("gateway operation")
    let cid = try args.take("conversation")
    let identity = try await client.identity()
    if operation == "promote", !governance {
      let url = try require(
        args.option("--gateway-url").flatMap(URL.init(string:)), "Supply --gateway-url")
      let threshold = try args.number("--threshold", default: 2)
      try args.finish()
      let invitation = try await client.promoteGateway(cid, gatewayURL: url, threshold: threshold)
      try Output.result([
        "invitation_id": invitation.invitationID,
        "gateway_public_key": invitation.gatewayPublicKey.base64URL,
        "gateway_kid": invitation.gatewayKeyID,
      ])
      return
    }
    let context = try await client.gatewayContext(cid)
    switch operation {
    case "recipes" where !governance:
      try args.finish()
      let recipes = try GatewayRecipe.starterCatalog()
      try Output.result([
        "recipes": try recipes.keys.sorted().map { name in
          [
            "name": name,
            "recipe": try JSONSerialization.jsonObject(with: recipes[name]!.json.encoded()),
          ]
        }
      ])
    case "run" where !governance:
      let catalog = try args.option("--catalog")
      let name = try args.take("recipe")
      var arguments: [String: String] = [:]
      while let argument = try args.option("--arg") {
        let pair = argument.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        guard pair.count == 2 else { throw QntmError.invalid("Recipe arguments use NAME=VALUE") }
        arguments[String(pair[0])] = String(pair[1])
      }
      try args.finish()
      let recipes =
        try catalog.map {
          try GatewayRecipe.catalog(data: Data(contentsOf: URL(fileURLWithPath: $0)))
        } ?? GatewayRecipe.starterCatalog()
      let recipe = try require(recipes[name], "Unknown recipe")
      let body = try recipe.request(identity: identity, context: context, arguments: arguments)
      _ = try await client.sendGateway(cid, body: body)
      try Output.result(JSONSerialization.jsonObject(with: body.encoded()))
    case "approve", "disapprove":
      let workflow = try args.take("workflow ID")
      try args.finish()
      try Output.envelope(
        await client.vote(
          cid, workflowID: workflow, approve: operation == "approve", proposal: governance))
    case "pending":
      try args.finish()
      let saved = try await client.conversation(cid)
      let subjectType: GatewayBodyType = governance ? .propose : .request
      var workflows: [[String: Any]] = []
      for event in saved.gateway.events where event.body.type == subjectType {
        let id = try require(
          event.body[governance ? "proposal_id" : "request_id"]?.string, "Missing workflow ID")
        if let state = try Gateway.scan(
          events: saved.gateway.events, context: context, id: id, proposal: governance)
        {
          workflows.append([
            "id": id, "status": state.status.rawValue, "approvals": state.approvalCount,
            "required_approvals": state.threshold,
            "body": try JSONSerialization.jsonObject(with: state.subject.encoded()),
          ])
        }
      }
      try Output.result(["workflows": workflows])
    case "request" where !governance:
      let service = try require(args.option("--service"), "Supply --service")
      let endpoint = try require(args.option("--endpoint"), "Supply --endpoint")
      let url = try require(args.option("--url"), "Supply --url")
      let verb = try args.option("--verb") ?? "GET"
      let payload = try args.option("--payload").map { try GatewayJSON(data: Data($0.utf8)) }
      let threshold = try args.number("--threshold", default: 1)
      let lifetime = try args.number("--ttl", default: 3600)
      try args.finish()
      let body = try Gateway.createRequest(
        identity: identity, context: context, service: service, endpoint: endpoint, verb: verb,
        targetURL: url, payload: payload, requiredApprovals: threshold, lifetime: lifetime)
      _ = try await client.sendGateway(cid, body: body)
      try Output.result(JSONSerialization.jsonObject(with: body.encoded()))
    case "secret" where !governance:
      let service = try require(args.option("--service"), "Supply --service")
      let path = try require(args.option("--file"), "Supply --file containing credential value")
      let origins = try args.option("--origin").map { [$0] }
      let header = try args.option("--header") ?? "Authorization"
      let template = try args.option("--template") ?? "Bearer {value}"
      let ttl = try args.number("--ttl", default: 0)
      try args.finish()
      let body = try Gateway.createSecret(
        identity: identity, context: context, service: service,
        value: Data(contentsOf: URL(fileURLWithPath: path)), allowedOrigins: origins,
        headerName: header, headerTemplate: template, ttl: ttl)
      try Output.envelope(await client.sendGateway(cid, body: body))
    case "propose" where governance:
      let floor = try args.option("--floor")
      let add = try args.option("--add")
      let remove = try args.option("--remove")
      let rules = try args.option("--rules")
      guard [floor, add, remove, rules].compactMap({ $0 }).count == 1 else {
        throw QntmError.invalid("Specify exactly one governance change")
      }
      let change: GovernanceChange
      if let floor, let n = UInt64(floor) {
        change = .floor(n)
      } else if let add {
        change = .addMembers(try add.split(separator: ",").map { try key(String($0)) })
      } else if let remove {
        change = .removeMembers(
          try remove.split(separator: ",").map { try key(String($0), length: 16) })
      } else if let rules {
        change = .rules(
          try JSONDecoder().decode(
            [ThresholdRule].self, from: Data(contentsOf: URL(fileURLWithPath: rules))))
      } else {
        throw QntmError.invalid("Invalid floor")
      }
      try args.finish()
      let body = try Governance.createProposal(identity: identity, context: context, change: change)
      _ = try await client.sendGateway(cid, body: body)
      try Output.result(JSONSerialization.jsonObject(with: body.encoded()))
    case "send":
      let type = try args.take("body type")
      let path = try args.take("JSON file")
      try args.finish()
      let body = try GatewayBody(type: type, data: Data(contentsOf: URL(fileURLWithPath: path)))
      try Output.envelope(await client.sendGateway(cid, body: body))
    default: throw QntmError.invalid("Unknown gateway operation")
    }
  }
  static func guidanceCommand(_ args: inout Arguments, client: QntmClient) async throws {
    let operation = try args.take("guidance operation")
    let providers = Guidance.corpoProviders
    switch operation {
    case "list":
      try args.finish()
      try Output.result(["providers": try Output.encode(providers)])
    case "prepare":
      let context = try args.option("--context") ?? ""
      let providerID = try args.take("provider")
      let question = try args.take("question")
      try args.finish()
      let provider = try require(providers.first { $0.id == providerID }, "Unknown provider")
      let prepared = try await client.prepareGuidance(
        provider: provider, question: question, context: context)
      try Output.result([
        "provider": provider.id, "question": prepared.question, "context": prepared.context,
        "processing_notice": prepared.processingNotice, "recipient_key_id": provider.recipientKeyID,
        "request_id": prepared.requestID, "envelope": try prepared.envelope.serialize().base64URL,
      ])
    case "send":
      let path = try args.take("prepared JSON file")
      try args.finish()
      let raw = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path)))
      let outer = try require(raw as? [String: Any], "Invalid prepared guidance")
      let value = (outer["data"] as? [String: Any]) ?? outer
      let provider = try require(
        providers.first { $0.id == value["provider"] as? String }, "Unknown provider")
      let wire = try Data.fromBase64URL(require(value["envelope"] as? String, "Missing envelope"))
      let envelope = try Envelope(serialized: wire)
      let reviewed = try Guidance.inspectPrepared(
        identity: await client.identity(), provider: provider, envelope: envelope)
      guard value["question"] as? String == reviewed.question,
        value["context"] as? String == reviewed.context,
        value["request_id"] as? String == reviewed.requestID,
        value["recipient_key_id"] as? String == provider.recipientKeyID,
        value["processing_notice"] as? String == Guidance.processingNotice
      else {
        throw QntmError.invalid(
          "Review fields differ from the sealed guidance request; prepare it again")
      }
      let seq = try await DropboxClient(
        baseURL: require(URL(string: provider.relayURL), "Invalid provider relay")
      ).postMessage(conversationID: envelope.conversationID, envelope: wire)
      try Output.result(["sequence": seq, "request_id": value["request_id"] ?? NSNull()])
    default: throw QntmError.invalid("Unknown guidance operation")
    }
  }
}

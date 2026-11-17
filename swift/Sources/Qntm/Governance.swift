import Foundation

public enum GovernanceChange: Sendable, Equatable {
  case floor(UInt64)
  case rules([ThresholdRule])
  case addMembers([Data])
  case removeMembers([Data])
  var type: String {
    switch self {
    case .floor: "floor_change"
    case .rules: "rules_change"
    case .addMembers: "member_add"
    case .removeMembers: "member_remove"
    }
  }
}

public enum Governance {
  static func validateFields(_ json: GatewayJSON, applied: Bool) throws {
    let type = try gateText(json["proposal_type"], "proposal type")
    let names =
      applied
      ? ["applied_floor", "applied_rules", "applied_members", "removed_member_kids"]
      : ["proposed_floor", "proposed_rules", "proposed_members", "removed_member_kids"]
    guard
      let selected = ["floor_change", "rules_change", "member_add", "member_remove"].firstIndex(
        of: type)
    else { throw QntmError.invalid("Invalid proposal type") }
    for (index, key) in names.enumerated() {
      if index != selected {
        try gateRequire(json[key] == nil || json[key] == .null, "Unexpected proposal branch")
        continue
      }
      switch index {
      case 0: _ = try gateUInt(json[key], key, min: 1)
      case 1: _ = try ThresholdRule.parse(json[key])
      case 2:
        guard let members = json[key]?.array, !members.isEmpty, members.count <= 128 else {
          throw QntmError.invalid("Invalid proposed members")
        }
        var seen = Set<String>()
        for member in members {
          let pk = try gateBytes(member["public_key"], "member public key", count: 32)
          let kid = QSPCrypto.hash(pk).prefix(16).base64URL
          try gateRequire(
            QSPCrypto.isValidPublicKey(pk) && member["kid"]?.string == kid
              && seen.insert(kid).inserted, "Invalid or duplicate member")
        }
      default: _ = try gateRoster(json[key])
      }
    }
  }
  public static func proposalSignable(_ body: GatewayBody) throws -> CBOR {
    try gateRequire(body.type == .propose, "Expected governance proposal")
    var result: [String: CBOR] = [:]
    for key in [
      "conv_id", "proposal_id", "proposal_type", "eligible_signer_kids", "required_approvals",
    ] {
      guard let value = body[key] else { throw QntmError.invalid("Missing proposal field") }
      result[key] = try value.cbor()
    }
    for key in ["proposed_floor", "proposed_rules", "proposed_members", "removed_member_kids"] {
      result[key] = try body[key]?.cbor() ?? .undefined
    }
    if let gateway = body["gateway_kid"] { result["gateway_kid"] = try gateway.cbor() }
    result["expires_at_unix"] = .unsigned(try gateTime(body["expires_at"]))
    return .map(result)
  }
  public static func proposalHash(_ body: GatewayBody) throws -> Data {
    QSPCrypto.hash(try proposalSignable(body).encode())
  }
  public static func assertProposal(_ body: GatewayBody, context: GatewayContext) throws {
    try context.validate()
    try body.validate()
    try Gateway.assertBinding(body, context: context)
    try Gateway.assertRoster(body, context: context)
    try gateRequire(
      body.type == .propose
        && gateUInt(body["required_approvals"], "threshold") >= context.governanceQuorum,
      "Proposal threshold below current majority")
    guard let key = context.participants[try gateText(body["signer_kid"], "signer")] else {
      throw QntmError.invalid("Unknown proposal author")
    }
    try gateRequire(
      QSPCrypto.verify(
        publicKey: key, message: try proposalSignable(body).encode(),
        signature: try gateBytes(body["signature"], "signature", count: 64)),
      "Invalid proposal signature")
  }
  public static func createProposal(
    identity: Identity, context: GatewayContext, change: GovernanceChange,
    requiredApprovals: UInt64 = 1, lifetime: UInt64 = 3600,
    proposalID: String = UUID().uuidString.lowercased(), now: UInt64 = unixSeconds()
  ) throws -> GatewayBody {
    let signer = try context.signer(identity)
    try gateRequire(
      lifetime > 0 && lifetime <= 9_007_199_254_740_991 && now <= 9_007_199_254_740_991 - lifetime,
      "Invalid proposal lifetime")
    var json = GatewayJSON.object([
      ("type", .string("gov.propose")), ("gateway_kid", .string(context.gatewayKeyID)),
      ("conv_id", .string(context.conversationID)), ("proposal_id", .string(proposalID)),
      ("proposal_type", .string(change.type)),
      ("eligible_signer_kids", .array(context.participants.keys.sorted().map(GatewayJSON.string))),
      ("required_approvals", .uint(max(requiredApprovals, context.governanceQuorum))),
      ("expires_at", gateDate(now + lifetime)), ("signer_kid", .string(signer)),
      ("signature", .string(Data(repeating: 0, count: 64).base64URL)),
    ])
    switch change {
    case .floor(let floor): json = json.setting("proposed_floor", .uint(floor))
    case .rules(let rules): json = json.setting("proposed_rules", .array(rules.map(\.json)))
    case .addMembers(let keys):
      let members = try keys.map { pk -> GatewayJSON in
        let kid = QSPCrypto.hash(pk).prefix(16).base64URL
        try gateRequire(
          context.participants[kid] == nil && kid != context.gatewayKeyID,
          "Proposed member already exists or is gateway")
        return .object([("kid", .string(kid)), ("public_key", .string(pk.base64URL))])
      }
      json = json.setting("proposed_members", .array(members))
    case .removeMembers(let kids):
      try gateRequire(
        kids.count < context.participants.count
          && kids.allSatisfy { context.participants[$0.base64URL] != nil },
        "Cannot remove missing or every participant")
      json = json.setting("removed_member_kids", .array(kids.map { .string($0.base64URL) }))
    }
    let unsigned = try GatewayBody(type: "gov.propose", json: json)
    json = json.setting(
      "signature",
      .string(
        try QSPCrypto.sign(
          privateKey: identity.privateKey, message: proposalSignable(unsigned).encode()
        ).base64URL))
    let result = try GatewayBody(type: "gov.propose", json: json)
    try assertProposal(result, context: context)
    return result
  }
}

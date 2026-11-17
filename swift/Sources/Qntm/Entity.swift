import Foundation

/// An API status lookup. Active status alone does not bind a messaging key to this entity.
public struct EntityVerification: Codable, Sendable, Equatable {
  public let entityID: String
  public let name: String
  public let status: String
  public let entityType: String
  public let authorityCeiling: [String]
  public let verifiedAt: String
  public var isActive: Bool { status == "active" }
  enum CodingKeys: String, CodingKey {
    case entityID = "entity_id"
    case name, status
    case entityType = "entity_type"
    case authorityCeiling = "authority_ceiling"
    case verifiedAt = "verified_at"
  }
  public init(json: Data, expectedEntityID: String) throws {
    guard json.count <= IdentityDocumentRequest.maxBytes else {
      throw QntmError.invalid("Entity response exceeds size limit")
    }
    self = try JSONDecoder().decode(Self.self, from: json)
    guard entityID == expectedEntityID else {
      throw QntmError.invalid("Entity identifier mismatch")
    }
  }
  public init(from decoder: Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    entityID = try values.decode(String.self, forKey: .entityID)
    name = try values.decode(String.self, forKey: .name)
    status = try values.decode(String.self, forKey: .status)
    entityType = try values.decode(String.self, forKey: .entityType)
    authorityCeiling = try values.decodeIfPresent([String].self, forKey: .authorityCeiling) ?? []
    verifiedAt = try values.decodeIfPresent(String.self, forKey: .verifiedAt) ?? ""
  }
}

/// A sender whose key, active entity status and application-supplied authorization binding all passed.
public struct VerifiedSenderEntity: Sendable {
  public let did: String
  public let publicKey: Data
  public let entity: EntityVerification
  fileprivate init(did: String, publicKey: Data, entity: EntityVerification) {
    self.did = did
    self.publicKey = publicKey
    self.entity = entity
  }
}

public enum Entity {
  public static let defaultAPIBase = URL(string: "https://api.corpo.llc/api/v1")!
  public static func verificationURL(entityID: String, apiBase: URL = defaultAPIBase) throws -> URL
  {
    guard !entityID.isEmpty, entityID.utf8.count <= 1024,
      ["https", "http"].contains(apiBase.scheme?.lowercased() ?? ""), apiBase.host != nil,
      apiBase.user == nil, apiBase.password == nil,
      var components = URLComponents(url: apiBase, resolvingAgainstBaseURL: false),
      let encoded = entityID.addingPercentEncoding(withAllowedCharacters: .alphanumerics)
    else {
      throw QntmError.invalid("Invalid entity identifier or API base")
    }
    components.percentEncodedPath =
      components.percentEncodedPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
      .split(separator: "/").map(String.init).reduce("") { $0 + "/" + $1 } + "/entities/" + encoded
      + "/verify"
    components.query = nil
    components.fragment = nil
    guard let url = components.url else {
      throw QntmError.invalid("Invalid entity verification URL")
    }
    return url
  }
  public static func verify(
    _ entityID: String, apiBase: URL = defaultAPIBase, timeout: TimeInterval = 10
  ) async throws -> EntityVerification {
    let data = try await IdentityDocumentRequest.read(
      url: verificationURL(entityID: entityID, apiBase: apiBase), timeout: timeout,
      accept: "application/json")
    return try EntityVerification(json: data, expectedEntityID: entityID)
  }
  public static func verifySender(
    senderKeyID: Data, did: String, entityID: String,
    resolveDID: @Sendable (String) async throws -> Data,
    lookupEntity: @Sendable (String) async throws -> EntityVerification,
    verifyBinding: @Sendable (String, Data, EntityVerification) async throws -> Bool
  ) async throws -> VerifiedSenderEntity {
    guard senderKeyID.count == 16, !did.isEmpty else {
      throw QntmError.invalid("Sender verification requires a key ID and DID")
    }
    let publicKey = try await resolveDID(did)
    guard QSPCrypto.isValidPublicKey(publicKey), QSPCrypto.hash(publicKey).prefix(16) == senderKeyID
    else {
      throw QntmError.invalid("DID key does not match authenticated sender")
    }
    let entity = try await lookupEntity(entityID)
    guard entity.entityID == entityID, entity.isActive,
      try await verifyBinding(did, publicKey, entity)
    else { throw QntmError.invalid("Entity does not authorize this DID key") }
    return VerifiedSenderEntity(did: did, publicKey: publicKey, entity: entity)
  }
}

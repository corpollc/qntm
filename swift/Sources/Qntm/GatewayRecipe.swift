import Foundation

public struct GatewayRecipe: Sendable {
  public let name: String
  public let service: String
  public let verb: String
  public let endpoint: String
  public let targetURL: String
  public let json: GatewayJSON
  public init(name: String, json: GatewayJSON) throws {
    self.name = name
    self.json = json
    service = try gateText(json["service"], "recipe service")
    verb = try gateText(json["verb"], "recipe verb")
    endpoint = try gateText(json["endpoint"], "recipe endpoint")
    targetURL = try gateText(json["target_url"], "recipe target")
  }
  public static func catalog(data: Data) throws -> [String: GatewayRecipe] {
    let value = try GatewayJSON(data: data)
    guard let recipes = value["recipes"]?.fields else {
      throw QntmError.invalid("Invalid recipe catalog")
    }
    return try Dictionary(
      uniqueKeysWithValues: recipes.map {
        ($0.key, try GatewayRecipe(name: $0.key, json: $0.value))
      })
  }
  public struct Resolved: Sendable {
    public let endpoint: String
    public let targetURL: String
    public let payload: GatewayJSON?
  }
  public func resolve(arguments: [String: String] = [:]) throws -> Resolved {
    var arguments = arguments
    for kind in ["path_params", "query_params"] {
      for parameter in json[kind]?.array ?? [] {
        let name = try gateText(parameter["name"], "parameter name")
        if parameter["required"] == .bool(true) && arguments[name] == nil {
          guard let fallback = parameter["default"]?.string, !fallback.isEmpty else {
            throw QntmError.invalid("Missing required parameter \(name)")
          }
          arguments[name] = fallback
        }
      }
    }
    let allowed = CharacterSet(
      charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()")
    func escape(_ value: String) throws -> String {
      guard let result = value.addingPercentEncoding(withAllowedCharacters: allowed) else {
        throw QntmError.invalid("Cannot encode recipe parameter")
      }
      return result
    }
    func substitute(_ template: String) throws -> String {
      let regex = try NSRegularExpression(pattern: "\\{([^}]+)\\}")
      var result = template
      for match in regex.matches(in: template, range: NSRange(template.startIndex..., in: template))
        .reversed()
      {
        guard let keyRange = Range(match.range(at: 1), in: template),
          let range = Range(match.range, in: result)
        else { throw QntmError.invalid("Invalid template") }
        let key = String(template[keyRange])
        guard let value = arguments[key] else { continue }
        let decoded = value.removingPercentEncoding ?? value
        try gateRequire(
          !value.isEmpty && !decoded.contains("\0")
            && !decoded.split(whereSeparator: { $0 == "/" || $0 == "\\" }).contains(where: {
              $0 == "." || $0 == ".."
            }), "Invalid path parameter \(key)")
        result.replaceSubrange(range, with: try escape(value))
      }
      return result
    }
    let endpoint = try substitute(endpoint)
    var target = try substitute(targetURL)
    var query: [String] = []
    for parameter in json["query_params"]?.array ?? [] {
      let name = try gateText(parameter["name"], "parameter name")
      if let value = arguments[name] ?? parameter["default"]?.string {
        query.append(try escape(name) + "=" + escape(value))
      }
    }
    if !query.isEmpty {
      target += (target.contains("?") ? "&" : "?") + query.joined(separator: "&")
    }
    var payload: GatewayJSON?
    if ["POST", "PUT", "PATCH"].contains(verb.uppercased()), let schema = json["body_schema"],
      let fields = schema.fields
    {
      let names =
        schema["properties"]?.fields?.map(\.key)
        ?? fields.map(\.key).filter { !["type", "properties", "required"].contains($0) }
      let values = names.compactMap { name in
        arguments[name].map { GatewayJSON.Field(name, .string($0)) }
      }
      if !values.isEmpty { payload = .object(values) }
      for value in schema["required"]?.array ?? [] {
        let name = try gateText(value, "body parameter")
        try gateRequire(arguments[name] != nil, "Missing required body parameter \(name)")
      }
    }
    return Resolved(endpoint: endpoint, targetURL: target, payload: payload)
  }
  public func request(
    identity: Identity, context: GatewayContext, arguments: [String: String] = [:],
    lifetime: UInt64 = 3600, now: UInt64 = unixSeconds()
  ) throws -> GatewayBody {
    let resolved = try resolve(arguments: arguments)
    let body = try Gateway.createRequest(
      identity: identity, context: context, service: service, endpoint: resolved.endpoint,
      verb: verb, targetURL: resolved.targetURL, payload: resolved.payload, lifetime: lifetime,
      now: now)
    return try GatewayBody(
      type: "gate.request",
      json: body.json.setting("recipe_name", .string(name)).setting(
        "arguments",
        .object(
          arguments.sorted { $0.key < $1.key }.map { GatewayJSON.Field($0.key, .string($0.value)) })
      ))
  }
}

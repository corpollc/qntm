import Foundation

#if canImport(Darwin)
  import Darwin
#else
  import Glibc
#endif

extension Gateway {
  public static let knownServiceOrigins = [
    "github": "https://api.github.com", "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com", "gemini": "https://generativelanguage.googleapis.com",
    "stripe": "https://api.stripe.com", "hackernews": "https://hacker-news.firebaseio.com",
    "httpbin": "https://httpbin.org", "dadjokes": "https://icanhazdadjoke.com",
    "trivia": "https://opentdb.com", "dogs": "https://dog.ceo", "fun": "http://localhost:9090",
  ]
  static func blockedIPv4(_ b: [UInt8]) -> Bool {
    let a = b[0]
    let c = b[1]
    return a == 0 || a == 10 || a == 127 || (a == 100 && (64...127).contains(c))
      || (a == 169 && c == 254) || (a == 172 && (16...31).contains(c))
      || (a == 192 && (c == 168 || (c == 0 && b[2] == 0))) || (a == 198 && (c == 18 || c == 19))
      || a >= 224
  }
  public static func isBlockedOrPrivateHost(_ hostname: String) -> Bool {
    var host = hostname.lowercased()
    if host.hasSuffix(".") { host.removeLast() }
    if host.isEmpty || host == "localhost" || host.hasSuffix(".localhost")
      || host.hasSuffix(".internal")
      || host.range(of: "^(0x[0-9a-f]+|[0-9]+)$", options: .regularExpression) != nil
    {
      return true
    }
    if host.hasPrefix("[") && host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
    if host.contains(":") {
      var address = [UInt8](repeating: 0, count: 16)
      guard inet_pton(AF_INET6, host, &address) == 1 else { return true }
      if address.prefix(15).allSatisfy({ $0 == 0 }) && address[15] <= 1 { return true }
      if address[0] & 0xfe == 0xfc || (address[0] == 0xfe && address[1] & 0xc0 == 0x80)
        || address[0] == 0xff
      {
        return true
      }
      if address[0] == 1 && address[1..<8].allSatisfy({ $0 == 0 }) { return true }
      let mapped =
        address.prefix(10).allSatisfy({ $0 == 0 })
        && ((address[10] == 0xff && address[11] == 0xff) || (address[10] == 0 && address[11] == 0))
      let nat64 =
        Array(address.prefix(4)) == [0, 0x64, 0xff, 0x9b]
        && (address[4..<12].allSatisfy({ $0 == 0 }) || (address[4] == 0 && address[5] == 1))
      return (mapped || nat64) && blockedIPv4(Array(address.suffix(4)))
    }
    var address = [UInt8](repeating: 0, count: 4)
    if inet_pton(AF_INET, host, &address) == 1 { return blockedIPv4(address) }
    // Do not let URL parsers reinterpret octal, shortened, or hexadecimal IP literals.
    if host.split(separator: ".").allSatisfy({
      $0.allSatisfy(\.isNumber) || $0.lowercased().hasPrefix("0x")
    }) {
      return true
    }
    return !host.contains(".")
  }
  static func validatePath(_ path: String) throws {
    try gateRequire(path.hasPrefix("/") && !path.contains("\\"), "Invalid URL path")
    for segment in path.split(separator: "/", omittingEmptySubsequences: false) {
      guard let decoded = String(segment).removingPercentEncoding else {
        throw QntmError.invalid("Invalid URL escaping")
      }
      try gateRequire(
        !decoded.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 || $0 == "\\" })
          && !decoded.split(separator: "/", omittingEmptySubsequences: false).contains(where: {
            $0 == "." || $0 == ".."
          }), "Path traversal is not allowed")
    }
  }
  public static func validateTargetURL(_ raw: String) throws -> URL {
    try gateRequire(
      !raw.isEmpty && raw.utf8.count <= 16384
        && raw.trimmingCharacters(in: .whitespacesAndNewlines) == raw && !raw.contains("#")
        && !raw.contains("\\")
        && !raw.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
      "Invalid target URL")
    guard let parts = URLComponents(string: raw), let url = parts.url, let host = parts.host,
      parts.user == nil, parts.password == nil, parts.fragment == nil, let scheme = parts.scheme
    else { throw QntmError.invalid("Invalid target URL") }
    let path = parts.percentEncodedPath.isEmpty ? "/" : parts.percentEncodedPath
    try validatePath(path)
    if scheme == "http" {
      let authority =
        raw.dropFirst("http://".count).split(separator: "/", maxSplits: 1).first?.split(
          separator: "?", maxSplits: 1
        ).first.map(String.init) ?? ""
      try gateRequire(
        ["localhost", "127.0.0.1", "[::1]", "::1"].contains(host.lowercased())
          && authority.range(
            of: "^(localhost|127\\.0\\.0\\.1|\\[::1\\])(:[0-9]+)?$",
            options: [.regularExpression, .caseInsensitive]) != nil,
        "HTTP is limited to explicit loopback")
    } else {
      try gateRequire(
        scheme == "https" && !isBlockedOrPrivateHost(host), "Target must use HTTPS on a public host"
      )
    }
    if let port = parts.port { try gateRequire(port > 0 && port <= 65535, "Invalid port") }
    return url
  }
  public static func normalizeOrigin(_ raw: String) throws -> String {
    let url = try validateTargetURL(raw)
    guard var parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
      parts.path == "" || parts.path == "/", parts.query == nil
    else { throw QntmError.invalid("Origin cannot contain path or query") }
    parts.path = ""
    parts.host = parts.host?.lowercased()
    parts.scheme = parts.scheme?.lowercased()
    if (parts.scheme == "https" && parts.port == 443)
      || (parts.scheme == "http" && parts.port == 80)
    {
      parts.port = nil
    }
    guard let result = parts.string else { throw QntmError.invalid("Invalid origin") }
    return result
  }
  public static func normalizeOrigins(_ origins: [String]) throws -> [String] {
    try gateRequire((1...16).contains(origins.count), "Expected 1 to 16 allowed origins")
    var result: [String] = []
    for raw in origins {
      let origin = try normalizeOrigin(raw)
      if !result.contains(origin) { result.append(origin) }
    }
    return result
  }
  public static func resolveServiceOrigins(_ service: String, explicit: [String]? = nil) throws
    -> [String]
  {
    if let explicit, !explicit.isEmpty { return try normalizeOrigins(explicit) }
    let trimmed = service.trimmingCharacters(in: .whitespacesAndNewlines)
    if let origin = knownServiceOrigins[trimmed.lowercased()] { return [origin] }
    if trimmed.hasPrefix("https://") || trimmed.hasPrefix("http://") {
      return [try normalizeOrigin(trimmed)]
    }
    if trimmed.range(
      of: "^(localhost|127\\.0\\.0\\.1|\\[::1\\])(:[0-9]+)?$",
      options: [.regularExpression, .caseInsensitive]) != nil
    {
      return [try normalizeOrigin("http://" + trimmed)]
    }
    if trimmed.contains(".") { return [try normalizeOrigin("https://" + trimmed)] }
    throw QntmError.invalid("Unknown service; specify allowed origins")
  }
  public static func pathnameMatchesEndpoint(_ path: String, endpoint: String) -> Bool {
    guard endpoint.hasPrefix("/"),
      !endpoint.unicodeScalars.contains(where: {
        $0.value <= 32 || $0.value == 127 || "?#\\".unicodeScalars.contains($0)
      }), (try? validatePath(path)) != nil, (try? validatePath(endpoint)) != nil
    else { return false }
    if path == endpoint { return true }
    if endpoint == "/" || !path.hasSuffix(endpoint) { return false }
    return String(path.dropLast(endpoint.count)).range(
      of: "^(?:/(?:api|v[0-9]+(?:[._-]?[a-z0-9]+)?))+$",
      options: [.regularExpression, .caseInsensitive]) != nil
  }
  static func endpointScore(_ pattern: String, _ endpoint: String) -> Int? {
    if pattern.isEmpty || pattern == "*" { return 0 }
    if pattern == endpoint { return 5 }
    guard pattern.contains("{") else { return nil }
    var regex = "^"
    var index = pattern.startIndex
    var hasPlaceholder = false
    while index < pattern.endIndex {
      if pattern[index] == "{" {
        guard let end = pattern[index...].firstIndex(of: "}"),
          pattern.distance(from: index, to: end) > 1
        else { return nil }
        let name = pattern[pattern.index(after: index)..<end]
        guard !name.contains("/") && !name.contains("{") else { return nil }
        regex += "[^/]+"
        hasPlaceholder = true
        index = pattern.index(after: end)
      } else {
        if pattern[index] == "}" { return nil }
        regex += NSRegularExpression.escapedPattern(for: String(pattern[index]))
        index = pattern.index(after: index)
      }
    }
    return hasPlaceholder && endpoint.range(of: regex + "$", options: .regularExpression) != nil
      ? 3 : nil
  }
  public static func lookupThreshold(
    rules: [ThresholdRule], service: String, endpoint: String, verb: String,
    targetURL: String? = nil
  ) -> ThresholdRule? {
    func scored(_ endpoint: String) -> (ThresholdRule, Int)? {
      var best: (ThresholdRule, Int)?
      for rule in rules {
        let serviceWildcard = rule.service.isEmpty || rule.service == "*"
        let verbWildcard = rule.verb.isEmpty || rule.verb == "*"
        guard serviceWildcard || rule.service == service,
          verbWildcard || rule.verb.uppercased() == verb.uppercased(),
          let score = endpointScore(rule.endpoint, endpoint)
        else { continue }
        let total = (serviceWildcard ? 0 : 8) + score + (verbWildcard ? 0 : 1)
        if best == nil || total > best!.1 { best = (rule, total) }
      }
      return best
    }
    let first = scored(endpoint)
    guard let targetURL, let path = URLComponents(string: targetURL)?.percentEncodedPath,
      let second = scored(path)
    else { return first?.0 }
    guard let first else { return second.0 }
    return second.1 > first.1 || (second.1 == first.1 && second.0.m > first.0.m)
      ? second.0 : first.0
  }
}

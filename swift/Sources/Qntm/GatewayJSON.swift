import Foundation

/// JSON with ordered object members: gateway payload hashes preserve JSON member order.
public indirect enum GatewayJSON: Sendable, Equatable {
  case object([Field])
  case array([GatewayJSON])
  case string(String)
  case number(Double)
  case bool(Bool)
  case null
  public struct Field: Sendable, Equatable {
    public let key: String
    public let value: GatewayJSON
    public init(_ key: String, _ value: GatewayJSON) {
      self.key = key
      self.value = value
    }
  }
  public static func object(_ fields: [(String, GatewayJSON)]) -> GatewayJSON {
    .object(fields.map { Field($0.0, $0.1) })
  }
  public var string: String? { if case .string(let x) = self { x } else { nil } }
  public var integer: UInt64? {
    guard case .number(let x) = self, x.isFinite, x >= 0, x <= 9_007_199_254_740_991,
      x.rounded() == x
    else { return nil }
    return UInt64(x)
  }
  public var array: [GatewayJSON]? { if case .array(let x) = self { x } else { nil } }
  public var fields: [Field]? { if case .object(let x) = self { x } else { nil } }
  public subscript(_ key: String) -> GatewayJSON? { fields?.first { $0.key == key }?.value }
  public static func uint(_ value: UInt64) -> GatewayJSON { .number(Double(value)) }
  func setting(_ key: String, _ value: GatewayJSON) -> GatewayJSON {
    var result = fields ?? []
    if let index = result.firstIndex(where: { $0.key == key }) {
      result[index] = Field(key, value)
    } else {
      result.append(Field(key, value))
    }
    return .object(result)
  }
  public func encoded() throws -> Data { Data(try rendered().utf8) }
  private func rendered() throws -> String {
    switch self {
    case .null: return "null"
    case .bool(let x): return x ? "true" : "false"
    case .string(let x):
      let data = try JSONSerialization.data(
        withJSONObject: x, options: [.fragmentsAllowed, .withoutEscapingSlashes])
      return String(decoding: data, as: UTF8.self)
    case .number(let x):
      guard x.isFinite else { throw QntmError.invalid("Nonfinite JSON number") }
      if x == 0 { return "0" }
      var value = String(x).lowercased()
      if let e = value.firstIndex(of: "e") {
        let exponent = Int(value[value.index(after: e)...]) ?? 0
        var mantissa = String(value[..<e])
        if mantissa.hasSuffix(".0") { mantissa.removeLast(2) }
        if exponent >= -6 && exponent < 21 {
          let negative = mantissa.hasPrefix("-")
          let digits = mantissa.filter { $0.isNumber }
          let decimal =
            (mantissa.firstIndex(of: ".").map {
              mantissa.distance(from: mantissa.startIndex, to: $0)
            } ?? mantissa.count) - (negative ? 1 : 0) + exponent
          let sign = negative ? "-" : ""
          if decimal <= 0 { return sign + "0." + String(repeating: "0", count: -decimal) + digits }
          if decimal >= digits.count {
            return sign + digits + String(repeating: "0", count: decimal - digits.count)
          }
          let split = digits.index(digits.startIndex, offsetBy: decimal)
          return sign + digits[..<split] + "." + digits[split...]
        }
        return mantissa + "e" + (exponent >= 0 ? "+" : "") + String(exponent)
      }
      if value.hasSuffix(".0") { value.removeLast(2) }
      return value
    case .array(let values):
      return "[" + (try values.map { try $0.rendered() }).joined(separator: ",") + "]"
    case .object(let fields):
      guard Set(fields.map(\.key)).count == fields.count else {
        throw QntmError.invalid("Duplicate JSON key")
      }
      // ECMAScript enumerates canonical uint32 property names first.
      let indexed = fields.enumerated().sorted { a, b in
        let ai = UInt32(a.element.key).flatMap {
          String($0) == a.element.key && $0 < UInt32.max ? $0 : nil
        }
        let bi = UInt32(b.element.key).flatMap {
          String($0) == b.element.key && $0 < UInt32.max ? $0 : nil
        }
        if let ai, let bi { return ai < bi }
        if ai != nil { return true }
        if bi != nil { return false }
        return a.offset < b.offset
      }
      return "{"
        + (try indexed.map {
          try GatewayJSON.string($0.element.key).rendered() + ":" + $0.element.value.rendered()
        }).joined(separator: ",") + "}"
    }
  }
  public init(data: Data) throws {
    guard data.count <= 2_000_000 else { throw QntmError.invalid("Gateway JSON too large") }
    var parser = Parser(bytes: Array(data))
    self = try parser.parse(depth: 0)
    parser.space()
    guard parser.position == parser.bytes.count else {
      throw QntmError.invalid("Trailing JSON data")
    }
  }
  func cbor() throws -> CBOR {
    switch self {
    case .null: return .null
    case .bool(let x): return .bool(x)
    case .string(let x): return .text(x)
    case .number(let x):
      guard x.isFinite, x.rounded() == x, abs(x) <= 9_007_199_254_740_991 else {
        throw QntmError.invalid("Expected integer in signed gateway metadata")
      }
      return x >= 0 ? .unsigned(UInt64(x)) : .negative(Int64(x))
    case .array(let xs): return .array(try xs.map { try $0.cbor() })
    case .object(let fs):
      return .map(try Dictionary(uniqueKeysWithValues: fs.map { ($0.key, try $0.value.cbor()) }))
    }
  }
  private struct Parser {
    let bytes: [UInt8]
    var position = 0
    mutating func space() {
      while position < bytes.count && [9, 10, 13, 32].contains(bytes[position]) { position += 1 }
    }
    mutating func take(_ b: UInt8) -> Bool {
      space()
      if position < bytes.count && bytes[position] == b {
        position += 1
        return true
      }
      return false
    }
    mutating func parse(depth: Int) throws -> GatewayJSON {
      space()
      guard depth < 64, position < bytes.count else {
        throw QntmError.invalid("Invalid JSON nesting")
      }
      if take(123) {
        var fields: [Field] = []
        if take(125) { return .object(fields) }
        repeat {
          guard case .string(let key) = try parse(depth: depth + 1), take(58),
            !fields.contains(where: { $0.key == key })
          else { throw QntmError.invalid("Invalid JSON object") }
          fields.append(Field(key, try parse(depth: depth + 1)))
        } while take(44)
        guard take(125) else { throw QntmError.invalid("Unclosed JSON object") }
        return .object(fields)
      }
      if take(91) {
        var values: [GatewayJSON] = []
        if take(93) { return .array(values) }
        repeat { values.append(try parse(depth: depth + 1)) } while take(44)
        guard take(93) else { throw QntmError.invalid("Unclosed JSON array") }
        return .array(values)
      }
      let start = position
      if bytes[position] == 34 {
        position += 1
        var escaped = false
        while position < bytes.count {
          let b = bytes[position]
          position += 1
          if b == 34 && !escaped { break }
          if b == 92 && !escaped { escaped = true } else { escaped = false }
        }
      } else {
        while position < bytes.count && ![9, 10, 13, 32, 44, 93, 125].contains(bytes[position]) {
          position += 1
        }
      }
      let value = try JSONSerialization.jsonObject(
        with: Data(bytes[start..<position]), options: [.fragmentsAllowed])
      if let text = value as? String { return .string(text) }
      if value is NSNull { return .null }
      if let number = value as? NSNumber {
        if String(cString: number.objCType) == "c" { return .bool(number.boolValue) }
        return .number(number.doubleValue)
      }
      throw QntmError.invalid("Invalid JSON scalar")
    }
  }
}

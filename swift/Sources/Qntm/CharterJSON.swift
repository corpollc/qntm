import Foundation

/// The experimental charter uses RFC 8785 canonical JSON, independently of gateway payload ordering.
public typealias CharterJSON = GatewayJSON

public enum CharterJSONCodec {
  public static func parse(_ data: Data, maximumBytes: Int = 32 * 1024 * 1024) throws -> CharterJSON
  {
    guard data.count <= maximumBytes else { throw QntmError.invalid("Charter JSON too large") }
    var parser = Parser(bytes: Array(data))
    let value = try parser.value(depth: 0)
    parser.whitespace()
    guard parser.offset == parser.bytes.count else {
      throw QntmError.invalid("Trailing charter JSON")
    }
    return value
  }

  public static func canonicalize(_ value: CharterJSON) throws -> Data {
    Data(try render(value, depth: 0).utf8)
  }

  private static func render(_ value: CharterJSON, depth: Int) throws -> String {
    guard depth <= 128 else { throw QntmError.invalid("Charter JSON nesting exceeds 128 levels") }
    switch value {
    case .object(let fields):
      guard Set(fields.map { Data($0.key.utf8) }).count == fields.count else {
        throw QntmError.invalid("Duplicate charter JSON key")
      }
      let sorted = fields.sorted { $0.key.utf16.lexicographicallyPrecedes($1.key.utf16) }
      return "{"
        + (try sorted.map {
          try render(.string($0.key), depth: depth) + ":" + render($0.value, depth: depth + 1)
        }).joined(separator: ",") + "}"
    case .array(let values):
      return "[" + (try values.map { try render($0, depth: depth + 1) }).joined(separator: ",")
        + "]"
    default: return String(decoding: try value.encoded(), as: UTF8.self)
    }
  }

  private struct Parser {
    let bytes: [UInt8]
    var offset = 0
    mutating func whitespace() {
      while offset < bytes.count && [9, 10, 13, 32].contains(bytes[offset]) { offset += 1 }
    }
    mutating func consume(_ byte: UInt8) -> Bool {
      whitespace()
      if offset < bytes.count && bytes[offset] == byte {
        offset += 1
        return true
      }
      return false
    }
    mutating func value(depth: Int) throws -> CharterJSON {
      guard depth <= 128 else { throw QntmError.invalid("Charter JSON nesting exceeds 128 levels") }
      whitespace()
      guard offset < bytes.count else { throw QntmError.invalid("Truncated JSON") }
      if consume(123) {
        var fields: [GatewayJSON.Field] = []
        var keys = Set<Data>()
        if consume(125) { return .object(fields) }
        repeat {
          whitespace()
          guard offset < bytes.count, bytes[offset] == 34,
            case .string(let key) = try scalar(), consume(58), keys.insert(Data(key.utf8)).inserted
          else {
            throw QntmError.invalid("Invalid JSON object key")
          }
          fields.append(.init(key, try value(depth: depth + 1)))
        } while consume(44)
        guard consume(125) else { throw QntmError.invalid("Unclosed JSON object") }
        return .object(fields)
      }
      if consume(91) {
        var values: [CharterJSON] = []
        if consume(93) { return .array(values) }
        repeat { values.append(try value(depth: depth + 1)) } while consume(44)
        guard consume(93) else { throw QntmError.invalid("Unclosed JSON array") }
        return .array(values)
      }
      return try scalar()
    }
    mutating func scalar() throws -> CharterJSON {
      whitespace()
      guard offset < bytes.count else { throw QntmError.invalid("Missing JSON scalar") }
      let start = offset
      if bytes[offset] == 34 {
        offset += 1
        var escaped = false
        while offset < bytes.count {
          let byte = bytes[offset]
          offset += 1
          if byte == 34 && !escaped { break }
          if byte == 92 && !escaped { escaped = true } else { escaped = false }
        }
      } else {
        while offset < bytes.count && ![9, 10, 13, 32, 44, 93, 125].contains(bytes[offset]) {
          offset += 1
        }
      }
      let raw = Data(bytes[start..<offset])
      let value = try JSONSerialization.jsonObject(with: raw, options: [.fragmentsAllowed])
      if let text = value as? String { return .string(text) }
      if value is NSNull { return .null }
      if let number = value as? NSNumber {
        if String(cString: number.objCType) == "c" { return .bool(number.boolValue) }
        guard number.doubleValue.isFinite else { throw QntmError.invalid("Nonfinite JSON number") }
        return .number(number.doubleValue)
      }
      throw QntmError.invalid("Invalid JSON scalar")
    }
  }
}

func charterObject(_ value: CharterJSON?, allowed: Set<String>? = nil) throws -> [GatewayJSON.Field]
{
  guard let fields = value?.fields else { throw QntmError.invalid("Expected charter object") }
  if let allowed, !fields.allSatisfy({ allowed.contains($0.key) }) {
    throw QntmError.invalid("Unknown charter field")
  }
  return fields
}
func charterText(_ value: CharterJSON?) throws -> String {
  guard let text = value?.string, !text.isEmpty else {
    throw QntmError.invalid("Expected nonempty charter text")
  }
  return text
}
func charterUInt(_ value: CharterJSON?) throws -> UInt64 {
  guard let integer = value?.integer else { throw QntmError.invalid("Invalid charter integer") }
  return integer
}
func charterHex(_ value: CharterJSON?, count: Int) throws -> String {
  let text = try charterText(value)
  guard text.count == count * 2, text == text.lowercased(), (try? Data(hex: text).count) == count
  else {
    throw QntmError.invalid("Invalid charter identifier or hash")
  }
  return text
}
func charterBytes(_ value: CharterJSON?, count: Int) throws -> Data {
  let text = try charterText(value)
  let data = try Data.fromBase64URL(text)
  guard data.count == count, data.base64URL == text else {
    throw QntmError.invalid("Noncanonical charter base64url")
  }
  return data
}
func charterTimestamp(_ value: CharterJSON?) throws -> String {
  let text = try charterText(value)
  guard
    text.range(
      of: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z$", options: .regularExpression)
      != nil
  else {
    throw QntmError.invalid("Expected RFC 3339 UTC timestamp")
  }
  let formatter = ISO8601DateFormatter()
  formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
  var date = formatter.date(from: text)
  formatter.formatOptions = [.withInternetDateTime]
  if date == nil { date = formatter.date(from: text) }
  guard let date, formatter.string(from: date).prefix(19) == text.prefix(19) else {
    throw QntmError.invalid("Invalid calendar timestamp")
  }
  return text
}
func charterCheck(_ condition: Bool, _ message: String) throws {
  guard condition else { throw QntmError.invalid(message) }
}

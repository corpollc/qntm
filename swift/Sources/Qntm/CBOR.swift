import Foundation

public enum QntmError: Error, Sendable, CustomStringConvertible {
  case invalid(String)
  case crypto(String)
  case transport(String)
  public var description: String {
    switch self {
    case .invalid(let s), .crypto(let s), .transport(let s): return s
    }
  }
}

/// The finite, bounded CBOR subset used by QSP. Maps have text keys.
public indirect enum CBOR: Equatable, Sendable {
  case unsigned(UInt64)
  case negative(Int64)
  case bytes(Data)
  case text(String)
  case array([CBOR])
  case map([String: CBOR])
  case bool(Bool)
  case null, undefined

  public var mapValue: [String: CBOR]? { if case .map(let v) = self { v } else { nil } }
  public var bytesValue: Data? { if case .bytes(let v) = self { v } else { nil } }
  public var stringValue: String? { if case .text(let v) = self { v } else { nil } }
  public var uintValue: UInt64? { if case .unsigned(let v) = self { v } else { nil } }
  public var arrayValue: [CBOR]? { if case .array(let v) = self { v } else { nil } }

  public func encode() throws -> Data { try encoded(depth: 0) }
  private func encoded(depth: Int) throws -> Data {
    guard depth < 64 else { throw QntmError.invalid("CBOR nesting limit") }
    func head(_ major: UInt8, _ n: UInt64) -> Data {
      if n < 24 { return Data([major << 5 | UInt8(n)]) }
      let width = n <= 255 ? 1 : n <= 65535 ? 2 : n <= UInt32.max ? 4 : 8
      var result = Data([major << 5 | (width == 1 ? 24 : width == 2 ? 25 : width == 4 ? 26 : 27)])
      for i in (0..<width).reversed() { result.append(UInt8(truncatingIfNeeded: n >> (i * 8))) }
      return result
    }
    switch self {
    case .unsigned(let n): return head(0, n)
    case .negative(let n):
      guard n < 0 else { throw QntmError.invalid("CBOR negative integer must be negative") }
      return head(1, UInt64(-(n + 1)))
    case .bytes(let b): return head(2, UInt64(b.count)) + b
    case .text(let s):
      let b = Data(s.utf8)
      return head(3, UInt64(b.count)) + b
    case .array(let values):
      var result = head(4, UInt64(values.count))
      for value in values { result += try value.encoded(depth: depth + 1) }
      return result
    case .map(let values):
      let keys = values.keys.sorted {
        let a = Array($0.utf8)
        let b = Array($1.utf8)
        return a.count == b.count ? a.lexicographicallyPrecedes(b) : a.count < b.count
      }
      var result = head(5, UInt64(keys.count))
      for key in keys {
        result += try CBOR.text(key).encoded(depth: depth + 1)
        if let value = values[key] { result += try value.encoded(depth: depth + 1) }
      }
      return result
    case .bool(let b): return Data([b ? 0xf5 : 0xf4])
    case .null: return Data([0xf6])
    case .undefined: return Data([0xf7])
    }
  }

  public static func decode(_ data: Data) throws -> CBOR {
    guard data.count <= 32 * 1024 * 1024 else { throw QntmError.invalid("CBOR size limit") }
    let bytes = Array(data)
    var offset = 0
    func read(_ count: Int) throws -> ArraySlice<UInt8> {
      guard count >= 0, count <= bytes.count - offset else {
        throw QntmError.invalid("Truncated CBOR")
      }
      let start = offset
      offset += count
      return bytes[start..<offset]
    }
    func value(_ depth: Int) throws -> CBOR {
      guard depth < 64 else { throw QntmError.invalid("CBOR nesting limit") }
      let initial = try read(1).first!
      let major = initial >> 5
      let info = initial & 31
      if major == 7 {
        switch info {
        case 20: return .bool(false)
        case 21: return .bool(true)
        case 22: return .null
        case 23: return .undefined
        default: throw QntmError.invalid("Unsupported CBOR simple value")
        }
      }
      let n: UInt64
      if info < 24 {
        n = UInt64(info)
      } else {
        guard info <= 27 else { throw QntmError.invalid("Indefinite CBOR is unsupported") }
        n = try read(1 << Int(info - 24)).reduce(0) { ($0 << 8) | UInt64($1) }
      }
      switch major {
      case 0: return .unsigned(n)
      case 1:
        guard n <= UInt64(Int64.max) else { throw QntmError.invalid("CBOR integer overflow") }
        return .negative(-1 - Int64(n))
      case 2, 3:
        guard n <= UInt64(bytes.count - offset) else {
          throw QntmError.invalid("CBOR length exceeds input")
        }
        let b = Data(try read(Int(n)))
        if major == 2 { return .bytes(b) }
        guard String(data: b, encoding: .utf8) != nil else {
          throw QntmError.invalid("Invalid CBOR UTF-8")
        }
        return .text(String(decoding: b, as: UTF8.self))
      case 4, 5:
        guard n <= UInt64(bytes.count - offset), n <= 100_000 else {
          throw QntmError.invalid("CBOR collection limit")
        }
        if major == 4 { return .array(try (0..<Int(n)).map { _ in try value(depth + 1) }) }
        var map: [String: CBOR] = [:]
        for _ in 0..<n {
          guard case .text(let key) = try value(depth + 1), map[key] == nil else {
            throw QntmError.invalid("CBOR map requires unique text keys")
          }
          map[key] = try value(depth + 1)
        }
        return .map(map)
      default: throw QntmError.invalid("Unsupported CBOR tag/type")
      }
    }
    let result = try value(0)
    guard offset == bytes.count else { throw QntmError.invalid("Trailing CBOR data") }
    return result
  }
}

extension Dictionary where Key == String, Value == CBOR {
  public func requireBytes(_ key: String, count: Int? = nil) throws -> Data {
    guard let value = self[key]?.bytesValue, count == nil || value.count == count else {
      throw QntmError.invalid("Invalid byte field: \(key)")
    }
    return value
  }
  public func requireString(_ key: String) throws -> String {
    guard let value = self[key]?.stringValue else {
      throw QntmError.invalid("Invalid text field: \(key)")
    }
    return value
  }
  public func requireUInt(_ key: String) throws -> UInt64 {
    guard let value = self[key]?.uintValue else {
      throw QntmError.invalid("Invalid integer field: \(key)")
    }
    return value
  }
}

extension Data {
  public init(hex: String) throws {
    let chars = Array(hex.utf8)
    guard chars.count.isMultiple(of: 2) else { throw QntmError.invalid("Invalid hex length") }
    func nibble(_ c: UInt8) throws -> UInt8 {
      switch c {
      case 48...57: return c - 48
      case 65...70: return c - 55
      case 97...102: return c - 87
      default: throw QntmError.invalid("Invalid hex digit")
      }
    }
    self.init()
    for i in stride(from: 0, to: chars.count, by: 2) {
      append(try nibble(chars[i]) << 4 | nibble(chars[i + 1]))
    }
  }
  public var hex: String { map { String(format: "%02x", $0) }.joined() }
  public var base64URL: String {
    base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(
      of: "/", with: "_"
    ).replacingOccurrences(of: "=", with: "")
  }
  public static func fromBase64URL(_ text: String) throws -> Data {
    guard
      text.utf8.allSatisfy({
        (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45
          || $0 == 95
      }), text.count % 4 != 1
    else { throw QntmError.invalid("Invalid base64url") }
    let padded =
      text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
      + String(repeating: "=", count: (4 - text.count % 4) % 4)
    guard let data = Data(base64Encoded: padded), data.base64URL == text else {
      throw QntmError.invalid("Invalid base64url encoding")
    }
    return data
  }
}

public func unixSeconds() -> UInt64 { UInt64(max(0, Date().timeIntervalSince1970)) }

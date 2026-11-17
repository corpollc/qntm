import Foundation

#if canImport(Darwin)
  import Darwin
#else
  import Glibc
#endif

public struct SavedConversation: Codable, Sendable {
  public var conversation: Conversation
  public var cursor: UInt64 = 0
  public var group: GroupControlState?
  public var gateway: GatewaySession
  public var history: [ReceiveEvent] = []
  public var pendingDelivery: [ReceiveEvent] = []
  public var receivedIDs: Set<String> = []
  public var pendingOutbound: [Data] = []
  public var pendingInbound: [SavedEnvelope] = []
  public var rejected: [RejectedEnvelope] = []
  public var lastRekeyID: Data?
  public var members: [String: Data] = [:]
  public var historyKeys: [String: Data] = [:]
  public init(
    conversation: Conversation, group: GroupControlState? = nil, members: [String: Data] = [:]
  ) throws {
    self.conversation = conversation
    self.group = group
    self.members = members
    self.historyKeys = members
    gateway = try GatewaySession(participants: members)
  }
}
public struct SavedEnvelope: Codable, Sendable {
  public let sequence: UInt64
  public let wire: Data
}
public struct RejectedEnvelope: Codable, Sendable {
  public let sequence: UInt64
  public let reason: String
}

public struct Profile: Codable, Sendable {
  public let version: Int
  public let identityData: Data
  public var relayURL: URL
  public var conversations: [String: SavedConversation]
  public init(identity: Identity, relayURL: URL = DropboxClient.defaultURL) throws {
    version = 1
    identityData = try identity.serialize()
    self.relayURL = relayURL
    conversations = [:]
  }
  public var identity: Identity { get throws { try Identity(serialized: identityData) } }
  public func validate() throws {
    guard version == 1 else { throw QntmError.invalid("Unsupported profile version") }
    _ = try identity
    _ = try DropboxClient(baseURL: relayURL)
    for (id, saved) in conversations {
      guard id == saved.conversation.id.hex, saved.cursor <= 9_007_199_254_740_991 else {
        throw QntmError.invalid("Invalid profile conversation")
      }
      try saved.conversation.validate()
      if let roster = saved.group?.roster { try roster.validate() }
      for (kid, pk) in saved.members.merging(saved.historyKeys, uniquingKeysWith: { a, _ in a }) {
        guard QSPCrypto.isValidPublicKey(pk), kid == QSPCrypto.hash(pk).prefix(16).base64URL else {
          throw QntmError.invalid("Invalid stored member")
        }
      }
    }
  }
}

/// A profile transaction is a complete atomic snapshot. Implementations must not publish partial writes.
public protocol ProfileStore: Sendable {
  func load() throws -> Profile?
  func save(_ profile: Profile) throws
}

/// Holds an exclusive process lock until released. Profile files contain private keys and plaintext history.
public final class FileProfileStore: ProfileStore, @unchecked Sendable {
  public let directory: URL
  private let lockFD: Int32
  private let mutex = NSLock()
  public init(directory: URL) throws {
    self.directory = directory.standardizedFileURL
    let fm = FileManager.default
    try fm.createDirectory(
      at: self.directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let attrs = try fm.attributesOfItem(atPath: self.directory.path)
    guard attrs[.type] as? FileAttributeType == .typeDirectory else {
      throw QntmError.invalid("Profile directory must not be a symlink")
    }
    guard chmod(self.directory.path, 0o700) == 0 else {
      throw QntmError.invalid("Cannot protect profile directory")
    }
    lockFD = open(
      self.directory.appendingPathComponent("profile.lock").path, O_CREAT | O_RDWR | O_NOFOLLOW,
      0o600)
    guard lockFD >= 0 else { throw QntmError.invalid("Cannot open profile lock") }
    guard flock(lockFD, LOCK_EX | LOCK_NB) == 0 else {
      close(lockFD)
      throw QntmError.invalid("Profile is already open by another client")
    }
  }
  deinit { close(lockFD) }
  public func load() throws -> Profile? {
    mutex.lock()
    defer { mutex.unlock() }
    let path = directory.appendingPathComponent("profile.json")
    guard FileManager.default.fileExists(atPath: path.path) else { return nil }
    let fd = open(path.path, O_RDONLY | O_NOFOLLOW)
    guard fd >= 0 else { throw QntmError.invalid("Cannot read profile") }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    let profile = try JSONDecoder().decode(Profile.self, from: handle.readToEnd() ?? Data())
    try profile.validate()
    return profile
  }
  public func save(_ profile: Profile) throws {
    mutex.lock()
    defer { mutex.unlock() }
    try profile.validate()
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let bytes = try encoder.encode(profile)
    let tmp = directory.appendingPathComponent(".profile-\(UUID().uuidString).tmp").path
    let fd = open(tmp, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0o600)
    guard fd >= 0 else { throw QntmError.invalid("Cannot create profile transaction") }
    defer {
      close(fd)
      unlink(tmp)
    }
    try bytes.withUnsafeBytes { raw in
      var offset = 0
      while offset < raw.count {
        let count = write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
        if count < 0 && errno == EINTR { continue }
        guard count > 0 else { throw QntmError.invalid("Profile write failed") }
        offset += count
      }
    }
    guard fsync(fd) == 0, rename(tmp, directory.appendingPathComponent("profile.json").path) == 0
    else { throw QntmError.invalid("Profile commit failed") }
    let dirFD = open(directory.path, O_RDONLY)
    if dirFD >= 0 {
      defer { close(dirFD) }
      guard fsync(dirFD) == 0 else { throw QntmError.invalid("Profile directory sync failed") }
    }
  }
}

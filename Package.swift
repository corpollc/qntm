// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "Qntm",
  platforms: [.macOS(.v13), .iOS(.v16)],
  products: [
    .library(name: "Qntm", targets: ["Qntm"]),
    .executable(name: "qntm-swift", targets: ["QntmCLI"]),
  ],
  dependencies: [.package(url: "https://github.com/jedisct1/swift-sodium.git", exact: "0.11.0")],
  targets: [
    .target(
      name: "Qntm", dependencies: [.product(name: "Clibsodium", package: "swift-sodium")],
      path: "swift/Sources/Qntm", resources: [.copy("Resources/starter.json")]),
    .executableTarget(name: "QntmCLI", dependencies: ["Qntm"], path: "swift/Sources/QntmCLI"),
    .testTarget(name: "QntmTests", dependencies: ["Qntm"], path: "swift/Tests/QntmTests"),
  ]
)

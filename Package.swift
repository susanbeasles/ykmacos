// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "ykmacos", platforms: [.macOS("27.0")], products: [
    .library(name: "YKCore", targets: ["YKCore"]),
    .executable(name: "yk", targets: ["yk"])
], targets: [
    .target(name: "YKCore"),
    .target(name: "YKAppleSecurity", dependencies: ["YKCore"]),
    .executableTarget(name: "yk", dependencies: ["YKCore", "YKAppleSecurity"]),
    .testTarget(name: "YKCoreTests", dependencies: ["YKCore"])
])

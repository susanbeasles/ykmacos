import Foundation
import YKCore
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

let arguments = Array(CommandLine.arguments.dropFirst())
let command = arguments.first ?? "--help"
func emit<T: Encodable>(_ value: T) throws {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(value)
    FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data("\n".utf8))
}
switch command {
case "--help", "help":
    print("""
    yk — macOS YubiKey/SEP bridge (foundation preview)
    Usage:
      yk doctor [--json]       Report runtime readiness without changing state
      yk capabilities --json  Report implemented and pending capabilities
      yk --help               Show help
    Provisioning, signing, and encryption are pending; no device changes occur.
    """)
case "capabilities":
    try emit(["schemaVersion": "1", "release": "foundation-preview",
              "implemented": "runtime-diagnostics,provider-contracts,provisioning-state-machine",
              "pending": "native-discovery,init,signing,git,encryption,secrets,recovery-storage",
              "scope": "V1-local; remote-broker is V2"])
case "doctor":
    #if os(macOS)
    let report = Diagnostic(code: "YK_NATIVE_PROVIDER_PENDING", operation: "doctor", stage: "runtime",
        message: "macOS runtime detected. Hardware and entitlement probes are not implemented.",
        changed: false, retrySafe: true, nextAction: "Follow docs/mac-validation.md; do not infer device readiness.")
    #else
    let report = Diagnostic(code: "YK_PLATFORM_UNSUPPORTED", operation: "doctor", stage: "runtime",
        message: "Native operations require macOS 27 or later.", changed: false, retrySafe: true,
        nextAction: "Build and validate on a supported Mac.")
    #endif
    try emit(report)
    exit(2)
default:
    try emit(Diagnostic(code: "YK_COMMAND_UNAVAILABLE", operation: "cli", stage: "dispatch",
        message: "Command is unknown or not implemented in this preview.", changed: false,
        retrySafe: true, nextAction: "Run yk --help for implemented commands."))
    exit(2)
}

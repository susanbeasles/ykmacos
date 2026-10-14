import Foundation
import YKCore
import YKAppleSecurity
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
      yk doctor [--team TEAM] [--json]  Probe native readiness without changing state
      yk capabilities --json  Report implemented and pending capabilities
      yk identities list --json  Inspect public identity references without approval
      yk identities check --certificate SHA256 --token TOKEN --team TEAM --json
      yk identities test --certificate SHA256 --token TOKEN --team TEAM --json
      yk identities probe --certificate SHA256 --token TOKEN --team TEAM --json
      yk identities verify-receipt --receipt PATH --certificate SHA256 --token TOKEN --team TEAM --json
      yk signers enroll --certificate SHA256 --token TOKEN --team TEAM --receipt PATH --policy NEW_PATH --json
      yk signers accept|status --certificate SHA256 --token TOKEN --team TEAM --receipt PATH --policy PATH --policy-digest SHA256 --json
      yk signers verify --certificate SHA256 --token TOKEN --team TEAM --receipt PATH --policy PATH --json
      yk sep create --record NEW_ABSOLUTE_PATH --access user-presence --json
      yk sep inspect --record ABSOLUTE_PATH --json
      yk sep csr --record CREATED_RECORD_PATH --common-name NAME --output NEW_ABSOLUTE_PATH --json
      yk recovery init --inventory NEW_ABSOLUTE_PATH --json
      yk recovery report --inventory ABSOLUTE_PATH --json
      yk recovery plan --inventory ABSOLUTE_PATH --remove-device DEVICE_ID --json
      yk tokens list --json      List available CryptoTokenKit token identifiers
      yk --help               Show help
    Doctor and inventory queries are read-only. SEP creation and signer enrollment
    require explicit commands; signing authorization and encryption remain pending.
    """)
case "sep":
    let action = arguments.dropFirst().first ?? ""
    let flags = Array(arguments.dropFirst(2))
    var selected: [String: String] = [:]
    var cursor = 0
    var valid = true
    while cursor < flags.count {
        let flag = flags[cursor]
        if flag == "--json" { cursor += 1; continue }
        guard ["--record", "--access", "--common-name", "--output"].contains(flag), selected[flag] == nil,
              cursor + 1 < flags.count, !flags[cursor + 1].hasPrefix("--") else { valid = false; break }
        selected[flag] = flags[cursor + 1]; cursor += 2
    }
    let expectedFlags: Set<String>
    switch action {
    case "create": expectedFlags = ["--record", "--access"]
    case "inspect": expectedFlags = ["--record"]
    case "csr": expectedFlags = ["--record", "--common-name", "--output"]
    default: expectedFlags = []
    }
    guard valid, !expectedFlags.isEmpty, Set(selected.keys) == expectedFlags,
          let path = selected["--record"] else {
        try emit(Diagnostic(code: "YK_SEP_INPUT_REJECTED", operation: "sep", stage: "input",
            message: "Supply the exact arguments for sep create, inspect, or csr.", changed: false,
            retrySafe: true, nextAction: "Run yk --help.")); exit(2)
    }
    let report: Diagnostic
    switch action {
    case "create": report = SecureEnclaveKeys.create(recordPath: path, access: selected["--access"]!)
    case "inspect": report = SecureEnclaveKeys.inspect(recordPath: path)
    default: report = SecureEnclaveKeys.csr(recordPath: path, commonName: selected["--common-name"]!, output: selected["--output"]!)
    }
    try emit(report)
    if !["YK_SEP_KEY_CREATED", "YK_SEP_KEY_FOUND", "YK_SEP_CSR_SAVED"].contains(report.code) { exit(2) }
case "recovery":
    let action = arguments.dropFirst().first ?? ""
    let flags = Array(arguments.dropFirst(2))
    var selected: [String: String] = [:]
    var cursor = 0
    var valid = true
    while cursor < flags.count {
        let flag = flags[cursor]
        if flag == "--json" { cursor += 1; continue }
        guard ["--inventory", "--remove-device"].contains(flag), selected[flag] == nil,
              cursor + 1 < flags.count, !flags[cursor + 1].hasPrefix("--") else { valid = false; break }
        selected[flag] = flags[cursor + 1]; cursor += 2
    }
    guard valid, ["init", "report", "plan"].contains(action), let path = selected["--inventory"],
          (action == "plan" ? !(selected["--remove-device"] ?? "").isEmpty : selected["--remove-device"] == nil) else {
        try emit(Diagnostic(code: "YK_RECOVERY_INPUT_INVALID", operation: "recovery", stage: "input",
            message: "Supply an inventory path and, for plan, the exact device ID being removed.", changed: false,
            retrySafe: true, nextAction: "Run yk --help.")); exit(2)
    }
    do {
        if action == "init" {
            try RecoveryInventoryFile.create(path)
            try emit(Diagnostic(code: "YK_RECOVERY_INVENTORY_CREATED", operation: "recovery.init", stage: "inventory",
                message: "Empty public inventory created without overwriting existing files. Add resources before assessing coverage.",
                changed: true, retrySafe: false, nextAction: "Use docs/recovery-inventory.md to record coverage."))
        } else {
            let inventory = try RecoveryInventoryFile.load(path)
            if action == "plan", !inventory.resources.contains(where: {
                $0.primaryDeviceID == selected["--remove-device"] || $0.backups.contains { $0.id == selected["--remove-device"] }
            }) { throw RecoveryInventory.Failure.invalidInventory }
            let report = inventory.report(removing: selected["--remove-device"])
            try emit(report)
            if report.reviewRequired || inventory.resources.isEmpty { exit(2) }
        }
    } catch {
        try emit(Diagnostic(code: "YK_RECOVERY_INVENTORY_REJECTED", operation: "recovery." + action, stage: "inventory",
            message: "Inventory could not be safely read or created, its schema is invalid, or the selected device is absent. No hardware changes occurred.",
            changed: action == "init", retrySafe: action != "init", nextAction: "Inspect the inventory and file permissions; do not put credentials in this file."))
        exit(2)
    }
case "identities" where arguments.dropFirst().first == "list":
    let report = IdentityDiscovery.inspect()
    try emit(report)
    if report.diagnostics.contains(where: { $0.code == "YK_PLATFORM_UNSUPPORTED" || $0.code == "YK_IDENTITY_QUERY_FAILED" || $0.code == "YK_IDENTITY_RESULT_INVALID" }) { exit(2) }
case "signers" where ["enroll", "verify", "accept", "status"].contains(arguments.dropFirst().first ?? ""):
    let flags = Array(arguments.dropFirst(2))
    var selected: [String: String] = [:]
    var cursor = 0
    var valid = true
    while cursor < flags.count {
        let flag = flags[cursor]
        if flag == "--json" { cursor += 1; continue }
        guard ["--certificate", "--token", "--team", "--receipt", "--policy", "--policy-digest"].contains(flag),
              selected[flag] == nil, cursor + 1 < flags.count, !flags[cursor + 1].hasPrefix("--") else {
            valid = false; break
        }
        selected[flag] = flags[cursor + 1]; cursor += 2
    }
    guard valid, let certificateID = selected["--certificate"], let tokenID = selected["--token"],
          let teamID = selected["--team"], let receiptPath = selected["--receipt"], let policyPath = selected["--policy"],
          (try? IdentityChallenge(certificateID: certificateID, tokenID: tokenID, expectedTeamID: teamID, nonce: Data(count: 32))) != nil else {
        try emit(Diagnostic(code: "YK_INVALID_SELECTION", operation: "signers", stage: "input",
            message: "Supply exact certificate, token, Team ID, possession receipt and policy paths.", changed: false,
            retrySafe: true, nextAction: "Run yk --help."))
        exit(2)
    }
    let action = arguments.dropFirst().first
    if action == "accept" || action == "status" {
        let report = SignerPolicyAnchor.check(accept: action == "accept", path: policyPath, receiptPath: receiptPath,
            certificateID: certificateID, tokenID: tokenID, teamID: teamID,
            expectedDigest: selected["--policy-digest"] ?? "")
        try emit(report)
        exit(report.code == "YK_POLICY_ANCHOR_VERIFIED" ? 0 : 2)
    }
    guard selected["--policy-digest"] == nil else { exit(2) }
    if arguments.dropFirst().first == "enroll" {
        let report = IdentityPossession.test(certificateID: certificateID, tokenID: tokenID, expectedTeamID: teamID,
            receiptPath: policyPath, enrollmentReceiptPath: receiptPath)
        try emit(report)
        exit(report.enrolled ? 0 : 2)
    }
    let report = SignerPolicyVerification.verify(path: policyPath, receiptPath: receiptPath,
        certificateID: certificateID, tokenID: tokenID, teamID: teamID)
    try emit(report)
    exit(report.policyVerified ? 0 : 2)
case "identities" where ["check", "test", "probe", "verify-receipt"].contains(arguments.dropFirst().first ?? "") :
    // Exact selection prevents confusing a software reference with a token identity.
    let flags = Array(arguments.dropFirst(2))
    var selected: [String: String] = [:]
    var cursor = 0
    var valid = true
    while cursor < flags.count {
        let flag = flags[cursor]
        if flag == "--json" { cursor += 1; continue }
        guard ["--certificate", "--token", "--team", "--receipt"].contains(flag),
              selected[flag] == nil, cursor + 1 < flags.count,
              !flags[cursor + 1].hasPrefix("--") else { valid = false; break }
        selected[flag] = flags[cursor + 1]; cursor += 2
    }
    guard valid, let certificateID = selected["--certificate"],
          certificateID.count == 64, certificateID.allSatisfy({ "0123456789abcdef".contains($0) }),
          let tokenID = selected["--token"], !tokenID.isEmpty,
          let teamID = selected["--team"], teamID.count == 10,
          teamID.allSatisfy({ "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".contains($0) }) else {
        try emit(Diagnostic(code: "YK_INVALID_SELECTION", operation: "identities.check", stage: "input",
            message: "Supply exact lowercase certificate SHA-256, token ID and ten-character Team ID.",
            changed: false, retrySafe: true, nextAction: "Use identities list to select the certificate and token."))
        exit(2)
    }
    let operation = arguments.dropFirst().first
    if operation == "verify-receipt" {
        guard let path = selected["--receipt"] else { exit(2) }
        let report = PossessionReceiptVerification.verify(path: path, certificateID: certificateID, tokenID: tokenID, teamID: teamID)
        try emit(report)
        exit(report.code == "YK_RECEIPT_VERIFIED" ? 0 : 2)
    }
    if selected["--receipt"] != nil && operation != "test" { exit(2) }
    if ["test", "probe"].contains(arguments.dropFirst().first ?? "") {
        let report = IdentityPossession.test(certificateID: certificateID, tokenID: tokenID, expectedTeamID: teamID, probeOnly: arguments.dropFirst().first == "probe", receiptPath: selected["--receipt"])
        try emit(report)
        exit(report.signatureVerified || report.diagnostics.contains(where: { $0.code == "YK_REFERENCE_READY" }) ? 0 : 2)
    }
    let inventory = IdentityDiscovery.inspect()
    let candidates = inventory.identities.filter { $0.certificateID == certificateID && $0.tokenID == tokenID }
    var blockers: [String] = []
    if inventory.diagnostics.contains(where: { $0.code != "YK_IDENTITY_ELIGIBILITY_PENDING" }) {
        blockers.append("inventory-incomplete")
    }
    if candidates.count != 1 { blockers.append("selection-missing-or-ambiguous") }
    else if let evidence = candidates[0].certificate {
        blockers += evidence.blockers(expectedTeamID: teamID, requireToken: true, tokenID: tokenID, now: Date())
    } else { blockers.append("certificate-evidence-missing") }
    struct CheckReport: Encodable {
        let certificateID: String
        let tokenID: String
        let expectedTeamID: String
        let certificateChecksPassed: Bool
        let blockers: [String]
        let enrolled = false
        let hardwareOriginVerified = false
        let privateKeyOperationTested = false
        let revocationFreshness = "not-established-offline"
    }
    try emit(CheckReport(certificateID: certificateID, tokenID: tokenID, expectedTeamID: teamID,
        certificateChecksPassed: blockers.isEmpty, blockers: blockers))
    if !blockers.isEmpty { exit(2) }
case "tokens" where arguments.dropFirst().first == "list":
    #if os(macOS)
    try emit(IdentityDiscovery.availableTokenIDs())
    #else
    try emit(Diagnostic(code: "YK_PLATFORM_UNSUPPORTED", operation: "tokens.list", stage: "runtime", message: "Token discovery requires macOS.", changed: false, retrySafe: true, nextAction: "Run on macOS 27 or later."))
    exit(2)
    #endif
case "capabilities":
    try emit(["schemaVersion": "1", "release": "foundation-preview",
              "implemented": "native-readiness-probes,runtime-diagnostics,public-identity-query,certificate-checks,token-query,identity-possession,public-receipts,initial-signer-enrollment,sealed-signer-policy-verification,local-policy-acceptance,sep-key-generation,sep-key-inspection,sep-csr-generation,recovery-coverage-reporting,device-removal-planning,provider-contracts,provisioning-state-machine",
              "pending": "native-device-discovery,hardware-attestation,policy-revision-anchor,operation-authorization,init,application-signing,git,encryption,secrets,recovery-storage",
              "scope": "V1-local; remote-broker is V2"])
case "doctor":
    var team: String?
    var cursor = 1
    while cursor < arguments.count {
        if arguments[cursor] == "--json" { cursor += 1; continue }
        guard arguments[cursor] == "--team", team == nil, cursor + 1 < arguments.count,
              arguments[cursor + 1].count == 10,
              arguments[cursor + 1].allSatisfy({ "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".contains($0) }) else {
            try emit(Diagnostic(code: "YK_INVALID_SELECTION", operation: "doctor", stage: "input",
                message: "Supply only --json and an optional ten-character --team value.",
                changed: false, retrySafe: true, nextAction: "Run yk --help.")); exit(2)
        }
        team = arguments[cursor + 1]; cursor += 2
    }
    let report = NativeReadiness.inspect(expectedTeamID: team)
    try emit(report)
    exit(report.blockers.isEmpty ? 0 : 2)
default:
    try emit(Diagnostic(code: "YK_COMMAND_UNAVAILABLE", operation: "cli", stage: "dispatch",
        message: "Command is unknown or not implemented in this preview.", changed: false,
        retrySafe: true, nextAction: "Run yk --help for implemented commands."))
    exit(2)
}

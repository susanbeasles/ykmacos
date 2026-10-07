import Foundation

/// Read-only observations never grant signing authority or prove hardware origin.
public struct NativeReadinessReport: Encodable, Sendable {
    public let schemaVersion = 1
    public let platformSupported: Bool
    public let operatingSystem: String
    public let secureEnclaveAvailable: Bool
    public let connectedTokenCount: Int
    public let identityCount: Int
    public let connectedTokenIdentityCount: Int
    public let expectedTeamID: String?
    public let certificateCandidateCount: Int
    public let inventoryComplete: Bool
    public let readOnlyReady: Bool
    public let signingAuthorized = false
    public let privateKeyOperationTested = false
    public let hardwareOriginVerified = false
    public let changed = false
    public let blockers: [String]
    public let diagnostics: [Diagnostic]

    public init(platformSupported: Bool, operatingSystem: String, secureEnclaveAvailable: Bool,
                tokenIDs: [String], inventory: IdentityInventory, expectedTeamID: String?, now: Date) {
        self.platformSupported = platformSupported
        self.operatingSystem = operatingSystem
        self.secureEnclaveAvailable = secureEnclaveAvailable
        let connected = Set(tokenIDs)
        connectedTokenCount = connected.count
        identityCount = inventory.identities.count
        let associated = inventory.identities.filter { identity in
            identity.tokenID.map { connected.contains($0) } ?? false
        }
        connectedTokenIdentityCount = associated.count
        self.expectedTeamID = expectedTeamID
        certificateCandidateCount = expectedTeamID.map { team in
            associated.filter {
                $0.certificate?.blockers(expectedTeamID: team, requireToken: true,
                                        tokenID: $0.tokenID, now: now).isEmpty == true
            }.count
        } ?? 0
        diagnostics = inventory.diagnostics
        inventoryComplete = !diagnostics.contains { $0.code != "YK_IDENTITY_ELIGIBILITY_PENDING" }
        readOnlyReady = platformSupported && inventoryComplete
        var reasons: [String] = []
        if !platformSupported { reasons.append("macos-27-required") }
        if !inventoryComplete { reasons.append("identity-inventory-incomplete") }
        if connected.isEmpty { reasons.append("no-connected-cryptographic-token") }
        if !secureEnclaveAvailable { reasons.append("secure-enclave-unavailable") }
        if expectedTeamID != nil && certificateCandidateCount == 0 {
            reasons.append("no-connected-certificate-candidate-for-team")
        }
        blockers = reasons
    }
}

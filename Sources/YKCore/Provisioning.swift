import Foundation

public enum ProvisioningStage: String, Codable, Sendable {
    case planned, recoveryStaged, recoveryVerified, applying, hardwareVerified, committed, reconciliationRequired
}
public enum ProvisioningEvent: Sendable {
    case stageRecovery, verifyIndependentRecovery, beginChange, verifyHardware, commit, interrupt, rejectCredential
}
public enum ProvisioningFailure: String, Error, Codable, Sendable {
    case invalidTransition, recoveryCoverageUnknown, credentialRejected, reconciliationRequired
}
/// No credential values belong in this journal. Old/proposed values live in encrypted records.
public struct ProvisioningJournal: Codable, Sendable {
    public let operationID: UUID
    public let deviceID: String
    public let oldEncryptedRecordID: String?
    public let proposedEncryptedRecordID: String
    public private(set) var stage: ProvisioningStage
    public private(set) var independentRecoveryVerified: Bool
    public init(deviceID: String, oldEncryptedRecordID: String?, proposedEncryptedRecordID: String) {
        operationID = UUID(); self.deviceID = deviceID
        self.oldEncryptedRecordID = oldEncryptedRecordID
        self.proposedEncryptedRecordID = proposedEncryptedRecordID
        stage = .planned; independentRecoveryVerified = false
    }
    /// The caller must durably persist the returned journal BEFORE executing a hardware mutation.
    public mutating func advance(_ event: ProvisioningEvent) throws {
        if stage == .reconciliationRequired { throw ProvisioningFailure.reconciliationRequired }
        switch (stage, event) {
        case (.planned, .stageRecovery): stage = .recoveryStaged
        case (.recoveryStaged, .verifyIndependentRecovery):
            independentRecoveryVerified = true; stage = .recoveryVerified
        case (.recoveryVerified, .beginChange):
            guard independentRecoveryVerified else { throw ProvisioningFailure.recoveryCoverageUnknown }
            stage = .applying
        case (.applying, .verifyHardware): stage = .hardwareVerified
        case (.hardwareVerified, .commit): stage = .committed
        case (.applying, .interrupt), (.hardwareVerified, .interrupt): stage = .reconciliationRequired
        case (.applying, .rejectCredential):
            stage = .reconciliationRequired; throw ProvisioningFailure.credentialRejected
        default: throw ProvisioningFailure.invalidTransition
        }
    }
}

public enum CoverageStatus: String, Codable, Sendable { case unknown, configured, registered, tested, revoked }
public struct BackupCoverage: Codable, Sendable {
    public let resourceID: String
    public let deviceID: String
    public let status: CoverageStatus
    public var permitsDestructiveChange: Bool { status == .tested }
    public init(resourceID: String, deviceID: String, status: CoverageStatus) {
        self.resourceID = resourceID; self.deviceID = deviceID; self.status = status
    }
}

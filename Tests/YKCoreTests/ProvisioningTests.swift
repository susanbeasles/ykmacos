import XCTest
@testable import YKCore
final class ProvisioningTests: XCTestCase {
    func journal() -> ProvisioningJournal {
        ProvisioningJournal(deviceID: "test-device", oldEncryptedRecordID: "old", proposedEncryptedRecordID: "new")
    }
    func testCannotChangeBeforeRecovery() {
        var value = journal()
        XCTAssertThrowsError(try value.advance(.beginChange))
        XCTAssertEqual(value.stage, .planned)
    }
    func testCompleteSequence() throws {
        var value = journal()
        for event: ProvisioningEvent in [.stageRecovery, .verifyIndependentRecovery, .beginChange, .verifyHardware, .commit] {
            try value.advance(event)
        }
        XCTAssertEqual(value.stage, .committed)
    }
    func testInterruptionDoesNotAuthorizeRetry() throws {
        var value = journal()
        for event: ProvisioningEvent in [.stageRecovery, .verifyIndependentRecovery, .beginChange, .interrupt] { try value.advance(event) }
        XCTAssertEqual(value.stage, .reconciliationRequired)
        XCTAssertThrowsError(try value.advance(.beginChange))
        XCTAssertEqual(value.oldEncryptedRecordID, "old")
        XCTAssertEqual(value.proposedEncryptedRecordID, "new")
    }
    func testRejectedCredentialStopsWorkflow() throws {
        var value = journal()
        for event: ProvisioningEvent in [.stageRecovery, .verifyIndependentRecovery, .beginChange] { try value.advance(event) }
        XCTAssertThrowsError(try value.advance(.rejectCredential))
        XCTAssertEqual(value.stage, .reconciliationRequired)
        XCTAssertThrowsError(try value.advance(.verifyHardware))
    }
    func testOnlyTestedCoveragePermitsDestruction() {
        for status in [CoverageStatus.unknown, .configured, .registered, .revoked] {
            XCTAssertFalse(BackupCoverage(resourceID: "account", deviceID: "backup", status: status).permitsDestructiveChange)
        }
        XCTAssertTrue(BackupCoverage(resourceID: "account", deviceID: "backup", status: .tested).permitsDestructiveChange)
    }
}

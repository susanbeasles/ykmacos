import XCTest
@testable import YKCore
final class RecoveryInventoryTests: XCTestCase {
    func inventory(kind: String = "account", backup: String = "tested", alternative: String = "tested", independent: Bool = true) throws -> RecoveryInventory {
        let json = """
        {"schemaVersion":1,"resources":[{"id":"resource","kind":"\(kind)","primaryDeviceID":"primary","backups":[{"id":"backup","status":"\(backup)","independentOfPrimary":true,"independentOfMac":true}],"alternatives":[{"id":"offline-recovery","status":"\(alternative)","independentOfPrimary":true,"independentOfMac":\(independent)}]}]}
        """
        return try RecoveryInventory.decode(Data(json.utf8))
    }
    func testDeclaredCoverageNeverAuthorizesMutation() throws {
        let report = try inventory().report(removing: "primary")
        XCTAssertFalse(report.reviewRequired)
        XCTAssertFalse(report.destructiveChangeAuthorized)
        XCTAssertFalse(report.recoveryCryptographicallyVerified)
    }
    func testRegisteredBackupIsInsufficientForPrimaryRemoval() throws {
        XCTAssertTrue(try inventory(backup: "registered").report(removing: "primary").reviewRequired)
    }
    func testRemovingBackupCannotCountItAsRemainingCoverage() throws {
        XCTAssertEqual(try inventory().report(removing: "backup").entries[0].declaredTestedBackups, [])
    }
    func testMacBoundRecoveryFailsCriticalResources() throws {
        for kind in ["administrativeCredential", "encryptedData", "account", "replaceableAPIKey"] {
            XCTAssertTrue(try inventory(kind: kind, independent: false).report().reviewRequired)
        }
    }
    func testUnknownAndRevokedAlternativesFail() throws {
        for status in ["unknown", "configured", "registered", "revoked"] {
            XCTAssertTrue(try inventory(alternative: status).report().reviewRequired)
        }
    }
    func testUnknownFieldsAndVersionsRejected() {
        for json in ["{\"schemaVersion\":2,\"resources\":[]}", "{\"schemaVersion\":1,\"resources\":[],\"authority\":true}"] {
            XCTAssertThrowsError(try RecoveryInventory.decode(Data(json.utf8)))
        }
    }
    func testOversizedInputRejected() {
        XCTAssertThrowsError(try RecoveryInventory.decode(Data(count: 65537)))
    }
}

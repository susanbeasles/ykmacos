import XCTest
@testable import YKCore

final class NativeReadinessTests: XCTestCase {
    func testDisconnectedIdentityCannotBecomeCertificateCandidate() {
        let now = Date(timeIntervalSince1970: 1000)
        let evidence = CertificateAssessment(purposeMarker: "developer-id-application",
            subjectOrganizationalUnits: ["2VB7966G7R"], validFrom: now.addingTimeInterval(-100),
            validUntil: now.addingTimeInterval(100), publicKeyMatch: true,
            codeSigningTrust: true, appleDeveloperIDChainVerified: true)
        let inventory = IdentityInventory(identities: [SigningIdentity(certificateID: "certificate",
            subject: "Personal", source: "fixture", tokenID: "token", origin: .unverifiable,
            certificate: evidence)], diagnostics: [])
        let report = NativeReadinessReport(platformSupported: true, operatingSystem: "fixture",
            secureEnclaveAvailable: true, tokenIDs: ["different-token"], inventory: inventory,
            expectedTeamID: "2VB7966G7R", now: now)
        XCTAssertEqual(report.certificateCandidateCount, 0)
        XCTAssertTrue(report.blockers.contains("no-connected-certificate-candidate-for-team"))
        XCTAssertFalse(report.signingAuthorized)
        let connected = NativeReadinessReport(platformSupported: true, operatingSystem: "fixture",
            secureEnclaveAvailable: true, tokenIDs: ["token"], inventory: inventory,
            expectedTeamID: "2VB7966G7R", now: now)
        XCTAssertEqual(connected.certificateCandidateCount, 1)
        XCTAssertFalse(connected.signingAuthorized)
        XCTAssertFalse(connected.hardwareOriginVerified)
    }

    func testIncompleteInventoryCannotReportReadiness() {
        let diagnostic = Diagnostic(code: "YK_IDENTITY_QUERY_FAILED", operation: "identities.list",
            stage: "keychain", message: "fixture", changed: false, retrySafe: true, nextAction: "inspect")
        let report = NativeReadinessReport(platformSupported: true, operatingSystem: "fixture",
            secureEnclaveAvailable: true, tokenIDs: ["token"],
            inventory: IdentityInventory(identities: [], diagnostics: [diagnostic]),
            expectedTeamID: nil, now: Date())
        XCTAssertFalse(report.inventoryComplete)
        XCTAssertFalse(report.readOnlyReady)
        XCTAssertTrue(report.blockers.contains("identity-inventory-incomplete"))
    }
}

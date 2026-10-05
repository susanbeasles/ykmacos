import XCTest
@testable import YKCore
final class CertificateTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1000)
    func assessment(units: [String] = ["TEAM"], match: Bool? = true, trust: Bool = true, until: Date? = Date(timeIntervalSince1970: 2000)) -> CertificateAssessment {
        CertificateAssessment(purposeMarker: "developer-id-application", subjectOrganizationalUnits: units,
            validFrom: Date(timeIntervalSince1970: 0), validUntil: until, publicKeyMatch: match, codeSigningTrust: trust)
    }
    func testTrustDoesNotBypassAppleAnchorGate() {
        XCTAssertEqual(assessment().blockers(expectedTeamID: "TEAM", requireToken: true, tokenID: "piv", now: now), ["apple-anchor-verification-pending"])
    }
    func testWrongTeamFails() {
        XCTAssertTrue(assessment().blockers(expectedTeamID: "EMPLOYER", requireToken: false, tokenID: nil, now: now).contains("team-mismatch-or-ambiguous"))
    }
    func testUnknownKeyMatchFails() {
        XCTAssertTrue(assessment(match: nil).blockers(expectedTeamID: "TEAM", requireToken: false, tokenID: nil, now: now).contains("public-key-match-unverified"))
    }
    func testExpiryBoundaryFails() {
        XCTAssertTrue(assessment(until: now).blockers(expectedTeamID: "TEAM", requireToken: false, tokenID: nil, now: now).contains("certificate-outside-validity"))
    }
    func testMissingTokenAndTrustFail() {
        let reasons = assessment(trust: false).blockers(expectedTeamID: "TEAM", requireToken: true, tokenID: nil, now: now)
        XCTAssertTrue(reasons.contains("token-association-missing")); XCTAssertTrue(reasons.contains("code-signing-trust-failed"))
    }
    func testVerifiedChainPassesCertificateGates() {
        let evidence = CertificateAssessment(purposeMarker: "developer-id-application",
            subjectOrganizationalUnits: ["TEAM"], validFrom: Date(timeIntervalSince1970: 0),
            validUntil: Date(timeIntervalSince1970: 2000), publicKeyMatch: true,
            codeSigningTrust: true, appleDeveloperIDChainVerified: true)
        XCTAssertTrue(evidence.blockers(expectedTeamID: "TEAM", requireToken: true, tokenID: "piv", now: now).isEmpty)
        XCTAssertEqual(evidence.revocationFreshness, "not-established-offline")
        XCTAssertTrue(evidence.blockers(expectedTeamID: "OTHER", requireToken: true, tokenID: "piv", now: now).contains("team-mismatch-or-ambiguous"))
        XCTAssertTrue(evidence.blockers(expectedTeamID: "TEAM", requireToken: true, tokenID: nil, now: now).contains("token-association-missing"))
    }

}

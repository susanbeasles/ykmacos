import XCTest
@testable import YKCore
final class IdentityTests: XCTestCase {
    func item(_ source: String, token: String? = "piv", origin: KeyOrigin = .unverifiable) -> SigningIdentity {
        SigningIdentity(certificateID: "cert", subject: "subject", source: source, tokenID: token, origin: origin)
    }
    func testDuplicatesRetainAllSources() {
        let result = IdentityConsolidation.consolidate([item("file"), item("file"), item("data-protection")])
        XCTAssertEqual(result.count, 1)
        XCTAssertEqual(result[0].sources, ["data-protection", "file"])
        XCTAssertEqual(result[0].origin, .unverifiable)
    }
    func testHardwareAndUnassociatedReferenceRemainSeparate() {
        XCTAssertEqual(IdentityConsolidation.consolidate([item("file", token: nil), item("token")]).count, 2)
    }
    func testSeparateDevicesRemainSeparate() {
        XCTAssertEqual(IdentityConsolidation.consolidate([item("token", token: "one"), item("token", token: "two")]).count, 2)
    }
    func testConflictingOriginIsNotPromoted() {
        XCTAssertEqual(IdentityConsolidation.consolidate([item("file"), item("token", origin: .attestedGenerated)]).count, 2)
    }
    func testOrderIndependentAndIdempotent() {
        let input = [item("file"), item("data"), item("file", token: nil)]
        let result = IdentityConsolidation.consolidate(input)
        XCTAssertEqual(result, IdentityConsolidation.consolidate(Array(input.reversed())))
        XCTAssertEqual(result, IdentityConsolidation.consolidate(result))
    }
    func testInventoryDoesNotClaimEligibility() {
        let result = IdentityInventory(identities: [item("file"), item("data")], diagnostics: [])
        XCTAssertEqual(result.observationCount, 2)
        XCTAssertEqual(result.identities.count, 1)
        XCTAssertFalse(result.eligibilityVerified)
    }
}

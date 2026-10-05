import XCTest
@testable import YKCore
final class SignerPolicyTests: XCTestCase {
    let id = String(repeating: "a", count: 64)
    func policy() throws -> SignerPolicy {
        try SignerPolicy(certificateID: id, tokenID: "piv", expectedTeamID: "ABCDEFGHIJ",
            possessionReceiptDigest: String(repeating: "b", count: 64), nonce: Data(count: 32))
    }
    func testEnrollmentGrantsNoAuthorityOrRecovery() throws {
        let value = try policy()
        XCTAssertTrue(value.allowedOperations.isEmpty)
        XCTAssertEqual(value.backupCoverage, "unknown")
        XCTAssertEqual(value.keyOrigin, "unverifiable")
        XCTAssertEqual(try SignerPolicy.validate(value.message(), certificateID: id, tokenID: "piv", teamID: "ABCDEFGHIJ"), value)
    }
    func testPolicyCannotChangePinDomainRevisionOrAuthority() throws {
        let message = try policy().message()
        XCTAssertThrowsError(try SignerPolicy.validate(message, certificateID: id, tokenID: "other", teamID: "ABCDEFGHIJ"))
        XCTAssertThrowsError(try SignerPolicy.validate(message, certificateID: id, tokenID: "piv", teamID: "KLMNOPQRST"))
        for (old, new) in [("ykmacos.signer-enrollment.v1", "ykmacos.identity-possession.v1"),
                            ("\"revision\":1", "\"revision\":2"),
                            ("\"allowedOperations\":[]", "\"allowedOperations\":[\"sign\"]"),
                            ("\"backupCoverage\":\"unknown\"", "\"backupCoverage\":\"tested\"")] {
            let changed = Data(String(decoding: message, as: UTF8.self).replacingOccurrences(of: old, with: new).utf8)
            XCTAssertNotEqual(message, changed)
            XCTAssertThrowsError(try SignerPolicy.validate(changed, certificateID: id, tokenID: "piv", teamID: "ABCDEFGHIJ"))
        }
    }
    func testUnknownPolicyFieldRejected() throws {
        var body = try XCTUnwrap(JSONSerialization.jsonObject(with: policy().message()) as? [String: Any])
        body["extraAuthority"] = true
        let changed = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        XCTAssertThrowsError(try SignerPolicy.validate(changed, certificateID: id, tokenID: "piv", teamID: "ABCDEFGHIJ"))
    }
}

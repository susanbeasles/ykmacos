import XCTest
@testable import YKCore
final class ChallengeTests: XCTestCase {
    let certificate = String(repeating: "a", count: 64)
    func challenge(token: String = "piv", team: String = "ABCDEFGHIJ", nonce: UInt8 = 1) throws -> IdentityChallenge {
        try IdentityChallenge(certificateID: certificate, tokenID: token, expectedTeamID: team, nonce: Data(repeating: nonce, count: 32))
    }
    func testChallengeBindsSelectionAndNonce() throws {
        let message = try challenge().message()
        XCTAssertNotEqual(message, try challenge(token: "other").message())
        XCTAssertNotEqual(message, try challenge(team: "KLMNOPQRST").message())
        XCTAssertNotEqual(message, try challenge(nonce: 2).message())
        let other = try IdentityChallenge(certificateID: String(repeating: "b", count: 64), tokenID: "piv", expectedTeamID: "ABCDEFGHIJ", nonce: Data(repeating: 1, count: 32))
        XCTAssertNotEqual(message, try other.message())
        XCTAssertEqual(message, try challenge().message())
    }
    func testInvalidInputsRejected() {
        XCTAssertThrowsError(try IdentityChallenge(certificateID: certificate, tokenID: "piv", expectedTeamID: "ABCDEFGHIJ", nonce: Data(count: 31)))
        XCTAssertThrowsError(try IdentityChallenge(certificateID: "bad", tokenID: "piv", expectedTeamID: "ABCDEFGHIJ", nonce: Data(count: 32)))
        XCTAssertThrowsError(try challenge(token: ""))
        XCTAssertThrowsError(try challenge(team: "team"))
    }
}

import XCTest
@testable import YKCore
final class ReceiptTests: XCTestCase {
    func testReceiptBindsExactSelectionAndDomain() throws {
        let id = String(repeating: "a", count: 64)
        let message = try IdentityChallenge(certificateID: id, tokenID: "piv", expectedTeamID: "ABCDEFGHIJ", nonce: Data(count: 32)).message()
        let receipt = PossessionReceipt(certificateDER: Data([1]), message: message, signature: Data([2]), algorithm: "rsa-pkcs1v15-sha256")
        XCTAssertNoThrow(try receipt.validateMessage(certificateID: id, tokenID: "piv", teamID: "ABCDEFGHIJ"))
        XCTAssertThrowsError(try receipt.validateMessage(certificateID: id, tokenID: "other", teamID: "ABCDEFGHIJ"))
        let foreign = PossessionReceipt(certificateDER: Data([1]), message: Data(String(decoding: message, as: UTF8.self).replacingOccurrences(of: "ykmacos.identity-possession.v1", with: "other").utf8), signature: Data([2]), algorithm: "rsa-pkcs1v15-sha256")
        XCTAssertThrowsError(try foreign.validateMessage(certificateID: id, tokenID: "piv", teamID: "ABCDEFGHIJ"))
    }
}

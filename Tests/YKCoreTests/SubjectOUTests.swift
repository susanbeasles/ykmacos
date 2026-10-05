import XCTest
@testable import YKCore
final class SubjectOUTests: XCTestCase {
    func attribute(_ text: String) -> [UInt8] {
        let value = Array(text.utf8)
        let body: [UInt8] = [6,3,0x55,4,0x0b,0x0c,UInt8(value.count)] + value
        let sequence: [UInt8] = [0x30,UInt8(body.count)] + body
        return [0x31,UInt8(sequence.count)] + sequence
    }
    func name(_ values: [String]) -> Data {
        let body = values.flatMap(attribute)
        return Data([0x30, UInt8(body.count)] + body)
    }
    func testOUExtractedFromOID() throws {
        XCTAssertEqual(try SubjectOU.extract(name(["2VB7966G7R"])), ["2VB7966G7R"])
    }
    func testDuplicateOUNotHidden() throws {
        XCTAssertEqual(try SubjectOU.extract(name(["TEAM", "TEAM"])), ["TEAM", "TEAM"])
    }
    func testMultipleOUReported() throws {
        XCTAssertEqual(try SubjectOU.extract(name(["WORK", "PERSONAL"])), ["PERSONAL", "WORK"])
    }
    func testTruncatedDERRejected() {
        XCTAssertThrowsError(try SubjectOU.extract(Data(name(["TEAM"]).dropLast())))
    }
    func testIndefiniteLengthRejected() {
        XCTAssertThrowsError(try SubjectOU.extract(Data([0x30,0x80,0,0])))
    }
    func testOversizedSubjectRejected() {
        XCTAssertThrowsError(try SubjectOU.extract(Data(repeating: 0, count: 65537)))
    }
}

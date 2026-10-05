import Foundation
import XCTest
@testable import YKCore
#if canImport(CryptoKit)
import CryptoKit
#endif
final class CertificateRequestTests: XCTestCase {
    func testRejectsInvalidNamesAndPoints() {
        let point = Data([4]) + Data(count: 64)
        for name in ["", "bad\nname", String(repeating: "a", count: 257)] {
            XCTAssertThrowsError(try CertificateRequest.information(publicKey: point, commonName: name))
        }
        XCTAssertThrowsError(try CertificateRequest.information(publicKey: Data(count: 65), commonName: "test"))
        XCTAssertThrowsError(try CertificateRequest.information(publicKey: Data([4]), commonName: "test"))
    }
    func testNameChangesExactSignedBytes() throws {
        let point = Data([4]) + Data(count: 64)
        XCTAssertNotEqual(try CertificateRequest.information(publicKey: point, commonName: "one"),
            try CertificateRequest.information(publicKey: point, commonName: "two"))
    }
    func testIndependentOpenSSLVerification() throws {
        #if canImport(CryptoKit)
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/openssl") else { throw XCTSkip("OpenSSL unavailable") }
        // Disposable software fixture only; production uses SecKey inside the SEP.
        let key = P256.Signing.PrivateKey()
        for name in ["SEP test", String(repeating: "é", count: 128)] {
            let info = try CertificateRequest.information(publicKey: key.publicKey.x963Representation, commonName: name)
            let signature = try key.signature(for: info).derRepresentation
            let pem = try CertificateRequest.pem(information: info, signature: signature)
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            defer { try? FileManager.default.removeItem(at: directory) }
            let path = directory.appendingPathComponent("request.pem")
            try pem.write(to: path)
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
            process.arguments = ["req", "-in", path.path, "-verify", "-noout"]
            let output = Pipe(); process.standardError = output; process.standardOutput = output
            try process.run(); process.waitUntilExit()
            let message = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            XCTAssertEqual(process.terminationStatus, 0, message)
        }
        #else
        throw XCTSkip("CryptoKit unavailable")
        #endif
    }
}

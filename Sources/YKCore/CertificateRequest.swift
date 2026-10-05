import Foundation

/// Minimal PKCS #10 DER encoder for a P-256 key and one UTF-8 Common Name.
/// Never encodes private keys or requests application authority.
public enum CertificateRequest {
    public enum Failure: Error { case invalidInput }
    private static func element(_ tag: UInt8, _ body: Data) -> Data {
        var length = body.count
        var encodedLength: [UInt8] = []
        if length < 128 { encodedLength = [UInt8(length)] }
        else {
            while length > 0 { encodedLength.insert(UInt8(length & 255), at: 0); length >>= 8 }
            encodedLength.insert(0x80 | UInt8(encodedLength.count), at: 0)
        }
        return Data([tag] + encodedLength) + body
    }
    public static func validateCommonName(_ value: String) throws {
        guard !value.isEmpty, value.utf8.count <= 256,
              !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw Failure.invalidInput }
    }
    public static func information(publicKey: Data, commonName: String) throws -> Data {
        try validateCommonName(commonName)
        guard publicKey.count == 65, publicKey.first == 4 else { throw Failure.invalidInput }
        let cn = element(0x30, Data([0x06, 0x03, 0x55, 0x04, 0x03]) + element(0x0c, Data(commonName.utf8)))
        let subject = element(0x30, element(0x31, cn))
        // id-ecPublicKey and prime256v1; parameters must name the curve.
        let algorithms = Data([0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
            0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07])
        let spki = element(0x30, algorithms + element(0x03, Data([0]) + publicKey))
        return element(0x30, Data([0x02,0x01,0]) + subject + spki + Data([0xa0,0]))
    }
    public static func pem(information: Data, signature: Data) throws -> Data {
        guard information.count > 0, information.count <= 1024,
              signature.count >= 8, signature.count <= 80, signature.first == 0x30 else { throw Failure.invalidInput }
        // ecdsa-with-SHA256 has absent parameters.
        let algorithm = Data([0x30,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02])
        let der = element(0x30, information + algorithm + element(0x03, Data([0]) + signature))
        let base64 = Array(der.base64EncodedString())
        var lines: [String] = []
        for index in stride(from: 0, to: base64.count, by: 64) { lines.append(String(base64[index..<min(index + 64, base64.count)])) }
        return Data(("-----BEGIN CERTIFICATE REQUEST-----\n" + lines.joined(separator: "\n") + "\n-----END CERTIFICATE REQUEST-----\n").utf8)
    }
}

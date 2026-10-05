import Foundation
import Security

// Constructs PKCS#10 for an EXISTING SEP key. Does not generate, export or
// replace a private key, import a certificate, or submit anything to Apple.
enum SEPDeveloperCSR {
    enum Failure: Error { case invalidInput, notSecureEnclave, publicKey, signing(String), verification }
    private static func der(_ tag: UInt8, _ body: Data) -> Data {
        var result = Data([tag])
        if body.count < 128 { result.append(UInt8(body.count)) }
        else {
            var n = body.count, bytes: [UInt8] = []
            while n > 0 { bytes.insert(UInt8(n & 255), at: 0); n >>= 8 }
            result.append(0x80 | UInt8(bytes.count)); result.append(contentsOf: bytes)
        }
        result.append(body); return result
    }
    private static func sequence(_ parts: Data...) -> Data { der(0x30, parts.reduce(Data(), +)) }
    private static func oid(_ bytes: [UInt8]) -> Data { der(0x06, Data(bytes)) }
    static func make(key: SecKey, commonName: String, organization: String? = nil) throws -> Data {
        guard !commonName.isEmpty, commonName.utf8.count <= 256,
              !commonName.unicodeScalars.contains(where: { $0.value < 32 }) else { throw Failure.invalidInput }
        guard let attrs = SecKeyCopyAttributes(key) as? [String: Any],
              (attrs[kSecAttrTokenID as String] as? String) == (kSecAttrTokenIDSecureEnclave as String),
              (attrs[kSecAttrKeySizeInBits as String] as? Int) == 256,
              (attrs[kSecAttrKeyClass as String] as? String) == (kSecAttrKeyClassPrivate as String) else { throw Failure.notSecureEnclave }
        guard let publicKey = SecKeyCopyPublicKey(key) else { throw Failure.publicKey }
        var error: Unmanaged<CFError>?
        guard let exported = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?,
              exported.count == 65, exported.first == 4 else { throw Failure.publicKey }
        func rdn(_ attribute: UInt8, _ value: String) -> Data {
            der(0x31, sequence(oid([0x55, 0x04, attribute]), der(0x0c, Data(value.utf8))))
        }
        var names = rdn(3, commonName)
        if let organization {
            guard !organization.isEmpty, organization.utf8.count <= 256,
                  !organization.unicodeScalars.contains(where: { $0.value < 32 }) else { throw Failure.invalidInput }
            names.append(rdn(10, organization))
        }
        // id-ecPublicKey + prime256v1, X9.63 uncompressed public point.
        let algorithm = sequence(oid([0x2a,0x86,0x48,0xce,0x3d,0x02,0x01]), oid([0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07]))
        let spki = sequence(algorithm, der(0x03, Data([0]) + exported))
        // Version 0; attributes [0] IMPLICIT empty SET, required by PKCS#10.
        let request = sequence(der(0x02, Data([0])), der(0x30, names), spki, der(0xa0, Data()))
        let signingAlgorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(key, .sign, signingAlgorithm),
              let signature = SecKeyCreateSignature(key, signingAlgorithm, request as CFData, &error) as Data? else {
            throw Failure.signing(error?.takeRetainedValue().localizedDescription ?? "SEP signature unavailable")
        }
        guard SecKeyVerifySignature(publicKey, signingAlgorithm, request as CFData, signature as CFData, &error) else { throw Failure.verification }
        // ecdsa-with-SHA256 has ABSENT parameters (not ASN.1 NULL).
        let csr = sequence(request, sequence(oid([0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02])), der(0x03, Data([0]) + signature))
        return csr
    }
    static func pem(_ csr: Data) -> String {
        let base64 = csr.base64EncodedString()
        var lines: [String] = [], start = base64.startIndex
        while start < base64.endIndex {
            let end = base64.index(start, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            lines.append(String(base64[start..<end])); start = end
        }
        return "-----BEGIN CERTIFICATE REQUEST-----\n" + lines.joined(separator: "\n") + "\n-----END CERTIFICATE REQUEST-----\n"
    }
}

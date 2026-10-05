#if os(macOS)
import Foundation
import Security
import CryptoKit

/// Reviewed public certificates from https://www.apple.com/certificateauthority/.
/// Updates require a source change and release; user keychains cannot add anchors.
internal enum AppleDeveloperIDTrust {
    static let encodedCertificates: [String] = [
        "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",
    ]
    static let digests: [String] = [
        "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
        "7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f",
        "f16cd3c54c7f83cea4bf1a3e6a0819c8aaa8e4a1528fd144715f350643d2df3a",
    ]
    static func verify(_ leaf: SecCertificate) -> Bool {
        let certificates = encodedCertificates.compactMap { value -> SecCertificate? in
            guard let bytes = Data(base64Encoded: value) else { return nil }
            return SecCertificateCreateWithData(nil, bytes as CFData)
        }
        guard certificates.count == 3,
              let policy = SecPolicyCreateWithProperties(kSecPolicyAppleCodeSigning, nil) else { return false }
        var trust: SecTrust?
        let inputs = [leaf] + Array(certificates.dropFirst())
        guard SecTrustCreateWithCertificates(inputs as CFArray, policy, &trust) == errSecSuccess,
              let trust,
              SecTrustSetAnchorCertificates(trust, [certificates[0]] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil),
              let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              chain.count == 3 else { return false }
        func digest(_ certificate: SecCertificate) -> String {
            SHA256.hash(data: SecCertificateCopyData(certificate) as Data)
                .map { String(format: "%02x", $0) }.joined()
        }
        // Exact intermediate/root bytes, not names, constrain accepted issuance.
        return digest(chain[0]) == digest(leaf) &&
            digests.dropFirst().contains(digest(chain[1])) && digest(chain[2]) == digests[0]
    }
}
#endif

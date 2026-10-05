#if os(macOS)
import Foundation
import Security
import CryptoKit
import YKCore

internal enum SignedPublicEvidence {
    static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
    static func verify(certificateDER: Data, message: Data, signature: Data, algorithmName: String,
                       certificateID: String, teamID: String) -> Bool {
        guard certificateDER.count > 0, certificateDER.count <= 16384,
              message.count > 0, message.count <= 8192, signature.count > 0, signature.count <= 1024,
              digest(certificateDER) == certificateID,
              let certificate = SecCertificateCreateWithData(nil, certificateDER as CFData),
              let publicKey = SecCertificateCopyKey(certificate) else { return false }
        let algorithm: SecKeyAlgorithm
        switch algorithmName {
        case "rsa-pkcs1v15-sha256": algorithm = .rsaSignatureMessagePKCS1v15SHA256
        case "ecdsa-x962-sha256": algorithm = .ecdsaSignatureMessageX962SHA256
        default: return false
        }
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm),
              SecKeyVerifySignature(publicKey, algorithm, message as CFData, signature as CFData, nil) else { return false }
        let evidence = CertificateInspection.assess(certificate, key: nil)
        let checked = CertificateAssessment(purposeMarker: evidence.purposeMarker,
            subjectOrganizationalUnits: evidence.subjectOrganizationalUnits,
            validFrom: evidence.validFrom, validUntil: evidence.validUntil, publicKeyMatch: true,
            codeSigningTrust: evidence.codeSigningTrust, appleDeveloperIDChainVerified: evidence.appleDeveloperIDChainVerified)
        return checked.blockers(expectedTeamID: teamID, requireToken: false, tokenID: nil, now: Date()).isEmpty
    }
}
#endif

import Foundation
import YKCore
#if os(macOS)
import Security
#endif

public enum SignerPolicyVerification {
    public static func verify(path: String, receiptPath: String, certificateID: String, tokenID: String, teamID: String) -> SignerPolicyReport {
        func report(_ verified: Bool, _ digest: String?, _ message: String) -> SignerPolicyReport {
            SignerPolicyReport(policyVerified: verified, policyDigest: digest, certificateID: certificateID,
                tokenID: tokenID, expectedTeamID: teamID, diagnostics: [Diagnostic(
                    code: verified ? "YK_SIGNER_POLICY_VERIFIED" : "YK_SIGNER_POLICY_REJECTED",
                    operation: "signers.verify", stage: "policy", message: message, changed: false, retrySafe: true,
                    nextAction: "Initial signer enrollment grants no operations. Keep the explicit signer pin and policy digest independently; backup coverage, attestation and policy revision anchoring remain pending.")])
        }
        #if os(macOS)
        do {
            let data = try PublicReceiptFile.read(path)
            let sealed = try JSONDecoder().decode(SealedSignerPolicy.self, from: data)
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            guard try encoder.encode(sealed) == data else { return report(false, nil, "Noncanonical or unknown policy envelope fields rejected.") }
            let policy = try SignerPolicy.validate(sealed.message, certificateID: certificateID, tokenID: tokenID, teamID: teamID)
            let receipt = try PublicReceiptFile.read(receiptPath)
            guard SignedPublicEvidence.digest(receipt) == policy.possessionReceiptDigest,
                  PossessionReceiptVerification.verifyData(receipt, certificateID: certificateID, tokenID: tokenID, teamID: teamID),
                  SignedPublicEvidence.verify(certificateDER: sealed.certificateDER, message: sealed.message,
                    signature: sealed.signature, algorithmName: sealed.algorithm, certificateID: certificateID, teamID: teamID) else {
                return report(false, nil, "Policy signature, receipt binding, selected signer or current offline certificate checks failed.")
            }
            return report(true, SignedPublicEvidence.digest(data), "Initial signer enrollment and exact retained possession evidence verified. Operational authority is disabled.")
        } catch { return report(false, nil, "Policy or receipt could not be safely read or fails the closed schema.") }
        #else
        return report(false, nil, "Signer policy verification requires macOS.")
        #endif
    }
}

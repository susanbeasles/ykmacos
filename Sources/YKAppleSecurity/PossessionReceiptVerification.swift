import Foundation
import YKCore
#if os(macOS)
import Security
import CryptoKit
#endif
public enum PossessionReceiptVerification {
    public static func verify(path: String, certificateID: String, tokenID: String, teamID: String) -> Diagnostic {
        func report(_ code: String, _ message: String) -> Diagnostic {
            Diagnostic(code: code, operation: "identities.verify-receipt", stage: "receipt",
                message: message, changed: false, retrySafe: true,
                nextAction: "Receipt is historical public evidence only; enrollment, fresh possession and sealed-policy authorization remain separate.")
        }
        #if os(macOS)
        do {
            let data = try PublicReceiptFile.read(path)
            guard verifyData(data, certificateID: certificateID, tokenID: tokenID, teamID: teamID) else {
                return report("YK_RECEIPT_REJECTED", "Receipt signature, exact selection or current certificate checks failed.")
            }
            return report("YK_RECEIPT_VERIFIED", "Retained signature and exact selection verified offline. The token need not be connected; hardware origin and fresh revocation are not established.")
        } catch { return report("YK_RECEIPT_REJECTED", "Receipt cannot be safely read or fails format and exact-message validation.") }
        #else
        return report("YK_PLATFORM_UNSUPPORTED", "Receipt verification requires macOS.")
        #endif
    }
    #if os(macOS)
    internal static func verifyData(_ data: Data, certificateID: String, tokenID: String, teamID: String) -> Bool {
        do {
            let receipt = try JSONDecoder().decode(PossessionReceipt.self, from: data)
            try receipt.validateMessage(certificateID: certificateID, tokenID: tokenID, teamID: teamID)
            return SignedPublicEvidence.verify(certificateDER: receipt.certificateDER, message: receipt.message,
                signature: receipt.signature, algorithmName: receipt.algorithm, certificateID: certificateID, teamID: teamID)
        } catch { return false }
    }
    #endif

}

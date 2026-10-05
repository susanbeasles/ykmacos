import Foundation
import YKCore
#if os(macOS)
import Security
import LocalAuthentication
import CryptoKit
#endif

/// Public acceptance metadata only. No PINs, private keys or operational authority.
public enum SignerPolicyAnchor {
    public static func check(accept: Bool, path: String, receiptPath: String, certificateID: String,
                             tokenID: String, teamID: String, expectedDigest: String) -> Diagnostic {
        func result(_ code: String, _ message: String, changed: Bool = false) -> Diagnostic {
            Diagnostic(code: code, operation: accept ? "signers.accept" : "signers.status", stage: "anchor",
                message: message, changed: changed, retrySafe: !changed,
                nextAction: "Acceptance grants no operations. Preserve independent recovery; revision rollback protection and hardware attestation remain unestablished.")
        }
        guard expectedDigest.count == 64, expectedDigest.allSatisfy({ "0123456789abcdef".contains($0) }) else {
            return result("YK_POLICY_ANCHOR_REJECTED", "Supply the independently retained exact policy SHA-256 digest.")
        }
        let verified = SignerPolicyVerification.verify(path: path, receiptPath: receiptPath,
            certificateID: certificateID, tokenID: tokenID, teamID: teamID)
        guard verified.policyVerified, verified.policyDigest == expectedDigest else {
            return result("YK_POLICY_ANCHOR_REJECTED", "Policy verification or independently supplied digest comparison failed. Keychain was not changed.")
        }
        #if os(macOS)
        do {
            // Length-framed canonical selection avoids account-name collisions.
            let selection = try JSONSerialization.data(withJSONObject: [certificateID, tokenID, teamID], options: [])
            let account = SHA256.hash(data: selection).map { String(format: "%02x", $0) }.joined()
            let context = LAContext(); context.interactionNotAllowed = true
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "ykmacos.signer-policy-acceptance.v1",
                kSecAttrAccount as String: account,
                kSecUseDataProtectionKeychain as String: true,
                kSecAttrSynchronizable as String: false,
                kSecUseAuthenticationContext as String: context
            ]
            // Bind the selection as well as its digest inside the stored value.
            let value = try JSONSerialization.data(withJSONObject: ["schemaVersion": 1, "revision": 1,
                "certificateID": certificateID, "tokenID": tokenID, "teamID": teamID,
                "policyDigest": expectedDigest], options: [.sortedKeys])
            func read() -> (OSStatus, Data?) {
                var lookup = query
                lookup[kSecReturnData as String] = true
                lookup[kSecMatchLimit as String] = kSecMatchLimitOne
                var item: CFTypeRef?
                let status = SecItemCopyMatching(lookup as CFDictionary, &item)
                return (status, item as? Data)
            }
            let (status, stored) = read()
            if status == errSecSuccess {
                guard stored == value else { return result("YK_POLICY_ANCHOR_CONFLICT", "Existing acceptance differs. No replacement or deletion was attempted.") }
                return result("YK_POLICY_ANCHOR_VERIFIED", "Exact policy matches local acceptance. Operational authority remains disabled; this is not monotonic rollback protection.")
            }
            guard status == errSecItemNotFound else {
                return result("YK_POLICY_ANCHOR_UNAVAILABLE", "Keychain read failed with OSStatus \(status). No fallback storage was used.")
            }
            guard accept else { return result("YK_POLICY_ANCHOR_MISSING", "No local acceptance exists for this exact signer selection.") }
            var insertion = query
            insertion[kSecValueData as String] = value
            insertion[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let added = SecItemAdd(insertion as CFDictionary, nil)
            guard added == errSecSuccess || added == errSecDuplicateItem else {
                return result("YK_POLICY_ANCHOR_UNAVAILABLE", "Keychain insertion failed with OSStatus \(added). No fallback storage was used.")
            }
            let (checked, actual) = read()
            guard checked == errSecSuccess, actual == value else {
                return result("YK_POLICY_ANCHOR_CONFLICT", "Acceptance could not be reconciled after insertion. Inspect the Keychain before continuing.", changed: added == errSecSuccess)
            }
            return result("YK_POLICY_ANCHOR_VERIFIED", "Exact policy acceptance retained and verified. Operational authority remains disabled; this is not monotonic rollback protection.", changed: added == errSecSuccess)
        } catch { return result("YK_POLICY_ANCHOR_REJECTED", "Acceptance metadata could not be encoded.") }
        #else
        return result("YK_PLATFORM_UNSUPPORTED", "Policy acceptance requires macOS Keychain.")
        #endif
    }
}

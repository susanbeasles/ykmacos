import Foundation
import YKCore
#if os(macOS)
import Security
import CryptoKit
import CryptoTokenKit
import LocalAuthentication
#endif

/// Public inventory only: never signs, exports keys, or permits authentication UI.
public enum IdentityDiscovery {
    public static func inspect() -> IdentityInventory {
        #if os(macOS)
        var identities: [SigningIdentity] = []
        var diagnostics: [Diagnostic] = []
        for dataProtection in [false, true] {
            let source = dataProtection ? "data-protection-keychain" : "file-keychain-search-list"
            let authenticationContext = LAContext()
            authenticationContext.interactionNotAllowed = true
            var query: [String: Any] = [
                kSecClass as String: kSecClassIdentity,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecReturnRef as String: true,
                kSecUseAuthenticationContext as String: authenticationContext
            ]
            if dataProtection { query[kSecUseDataProtectionKeychain as String] = true }
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            if status == errSecItemNotFound { continue }
            guard status == errSecSuccess else {
                diagnostics.append(Diagnostic(code: "YK_IDENTITY_QUERY_FAILED", operation: "identities.list", stage: source,
                    message: "Public identity query returned OSStatus \(status). Inventory may be incomplete.",
                    changed: false, retrySafe: true, nextAction: "Check signing, entitlements and token availability; do not regenerate keys."))
                continue
            }
            guard let matches = result as? [SecIdentity] else {
                diagnostics.append(Diagnostic(code: "YK_IDENTITY_RESULT_INVALID", operation: "identities.list", stage: source,
                    message: "Unexpected identity result shape.", changed: false, retrySafe: true,
                    nextAction: "Report the sanitized diagnostic; do not modify the device."))
                continue
            }
            for identity in matches {
                var certificate: SecCertificate?
                guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else { continue }
                let der = SecCertificateCopyData(certificate) as Data
                let fingerprint = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
                var key: SecKey?
                let keyStatus = SecIdentityCopyPrivateKey(identity, &key)
                var tokenID: String?
                if keyStatus == errSecSuccess, let key,
                   let attributes = SecKeyCopyAttributes(key) as? [String: Any] {
                    tokenID = attributes[kSecAttrTokenID as String] as? String
                }
                identities.append(SigningIdentity(certificateID: fingerprint,
                    subject: (SecCertificateCopySubjectSummary(certificate) as String?) ?? "Unknown subject",
                    source: source, tokenID: tokenID, origin: .unverifiable,
                    certificate: CertificateInspection.assess(certificate, key: key)))
            }
        }
        diagnostics.append(Diagnostic(code: "YK_IDENTITY_ELIGIBILITY_PENDING", operation: "identities.list", stage: "inventory",
            message: "Certificate evidence is reported. Pinned Developer ID chain evidence is reported; signer enrollment and hardware attestation remain pending. Offline checks do not establish fresh revocation status.",
            changed: false, retrySafe: true, nextAction: "Complete eligibility verification before enrolling a signer."))
        return IdentityInventory(identities: identities, diagnostics: diagnostics)
        #else
        return IdentityInventory(identities: [], diagnostics: [Diagnostic(code: "YK_PLATFORM_UNSUPPORTED",
            operation: "identities.list", stage: "runtime", message: "Native identity discovery requires macOS.",
            changed: false, retrySafe: true, nextAction: "Run on macOS 27 or later.")])
        #endif
    }
    public static func availableTokenIDs() -> [String] {
        #if os(macOS)
        return TKTokenWatcher().tokenIDs.sorted()
        #else
        return []
        #endif
    }
}

import Foundation
import YKCore
#if os(macOS)
import Security
import CryptoKit
import LocalAuthentication
#endif

public enum IdentityPossession {
    /// Closed possession/enrollment messages only; no arbitrary payload, PIN handling or retries.
    public static func test(certificateID: String, tokenID: String, expectedTeamID: String, probeOnly: Bool = false, receiptPath: String? = nil, enrollmentReceiptPath: String? = nil) -> IdentityChallengeResult {
        var attempted = false
        var messageDigest: String?
        var algorithmName: String?
        let enrolling = enrollmentReceiptPath != nil
        func result(_ code: String, _ stage: String, _ message: String, verified: Bool = false) -> IdentityChallengeResult {
            IdentityChallengeResult(certificateID: certificateID, tokenID: tokenID, expectedTeamID: expectedTeamID,
                challengeDigest: messageDigest, algorithm: algorithmName, signingAttempted: attempted, signatureVerified: verified,
                diagnostics: [Diagnostic(code: code, operation: enrolling ? "signers.enroll" : "identities.test", stage: stage, message: message,
                    changed: attempted, retrySafe: !attempted,
                    nextAction: verified ? (enrolling ? "Initial enrollment retained with no operational authority. Backup coverage and attested origin remain unknown." : "Possession verified; enrollment and attested origin remain separate checks.") :
                        "Stop and inspect token state. Do not guess a PIN or automatically repeat the operation.")], enrolled: verified && enrolling)
        }
        #if os(macOS)
        // Validate before any query capable of authentication.
        guard (try? IdentityChallenge(certificateID: certificateID, tokenID: tokenID,
            expectedTeamID: expectedTeamID, nonce: Data(repeating: 0, count: 32))) != nil else {
            return result("YK_INVALID_SELECTION", "input", "Exact certificate, token and Team ID are required.")
        }
        var reservation: PublicReceiptFile.Reservation?
        var possessionDigest: String?
        if let enrollmentReceiptPath {
            guard !probeOnly, let receiptPath else { return result("YK_INVALID_SELECTION", "input", "Enrollment requires a new policy destination and an existing possession receipt.") }
            do {
                let retained = try PublicReceiptFile.read(enrollmentReceiptPath)
                guard PossessionReceiptVerification.verifyData(retained, certificateID: certificateID, tokenID: tokenID, teamID: expectedTeamID) else {
                    return result("YK_ENROLLMENT_RECEIPT_REJECTED", "receipt", "Retained possession evidence does not verify for the exact selected signer.")
                }
                possessionDigest = SignedPublicEvidence.digest(retained)
                reservation = try PublicReceiptFile.Reservation(receiptPath)
            } catch { return result("YK_ENROLLMENT_INPUT_REJECTED", "input", "Receipt or new policy destination could not be safely prepared.") }
        }
        if let receiptPath {
            guard !probeOnly else { return result("YK_INVALID_SELECTION", "input", "A probe cannot save signed evidence.") }
            do { try PublicReceiptFile.preflight(receiptPath) }
            catch { return result("YK_RECEIPT_DESTINATION_INVALID", "input", "Receipt destination must be new, absolute and inside an existing private, user-owned directory without symlink components.") }
        }
        let inventory = IdentityDiscovery.inspect()
        guard !inventory.diagnostics.contains(where: { $0.code != "YK_IDENTITY_ELIGIBILITY_PENDING" }) else {
            return result("YK_INVENTORY_INCOMPLETE", "inventory", "Inventory is incomplete; signing is blocked.")
        }
        let candidates = inventory.identities.filter { $0.certificateID == certificateID && $0.tokenID == tokenID }
        guard candidates.count == 1, let evidence = candidates[0].certificate,
              evidence.blockers(expectedTeamID: expectedTeamID, requireToken: true, tokenID: tokenID, now: Date()).isEmpty else {
            return result("YK_CERTIFICATE_CHECK_FAILED", "eligibility", "Selected identity failed certificate checks.")
        }
        // Locate references without interaction, then enable UI for only the selected reference.
        var selectedCertificate: SecCertificate?
        var selectedLabel: Data?
        for dataProtection in [false, true] {
            let context = LAContext(); context.interactionNotAllowed = true
            var query: [String: Any] = [kSecClass as String: kSecClassIdentity,
                kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnRef as String: true,
                kSecUseAuthenticationContext as String: context]
            if dataProtection { query[kSecUseDataProtectionKeychain as String] = true }
            var output: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &output)
            if status == errSecItemNotFound { continue }
            guard status == errSecSuccess, let identities = output as? [SecIdentity] else {
                return result("YK_REFERENCE_QUERY_FAILED", "selection", "Identity query failed; no signing attempted.")
            }
            for identity in identities {
                var certificate: SecCertificate?
                var key: SecKey?
                guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate,
                      SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key,
                      let attributes = SecKeyCopyAttributes(key) as? [String: Any],
                      attributes[kSecAttrTokenID as String] as? String == tokenID else { continue }
                let fingerprint = SHA256.hash(data: SecCertificateCopyData(certificate) as Data)
                    .map { String(format: "%02x", $0) }.joined()
                if fingerprint == certificateID {
                    guard let label = attributes[kSecAttrApplicationLabel as String] as? Data, !label.isEmpty else {
                        return result("YK_KEY_LABEL_MISSING", "selection", "Selected token key has no usable application label; lookup blocked.")
                    }
                    selectedCertificate = certificate; selectedLabel = label; break
                }
            }
            if selectedCertificate != nil { break }
        }
        guard let certificate = selectedCertificate, let selectedLabel else { return result("YK_REFERENCE_MISSING", "selection", "Selected token identity is unavailable.") }
        let context = LAContext()
        context.interactionNotAllowed = probeOnly
        context.localizedReason = "Verify possession of the selected ykmacos signing identity"
        defer { context.invalidate() }
        // CryptoTokenKit identities are synthesized certificate/key pairs. Look up the
        // underlying token key instead of re-querying a transient identity reference.
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrTokenID as String: tokenID, kSecAttrApplicationLabel as String: selectedLabel,
            kSecUseDataProtectionKeychain as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true, kSecUseAuthenticationContext as String: context]
        var output: CFTypeRef?
        let referenceStatus = SecItemCopyMatching(query as CFDictionary, &output)
        guard referenceStatus == errSecSuccess else {
            return result("YK_AUTH_REFERENCE_FAILED", "authentication", "Selected reference query returned OSStatus \(referenceStatus). No signing attempted.")
        }
        guard let keys = output as? [SecKey], keys.count == 1 else {
            return result("YK_AUTH_REFERENCE_SHAPE", "authentication", "Selected token-key query did not return exactly one key reference. No signing attempted.")
        }
        let key = keys[0]
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrTokenID as String] as? String == tokenID,
              attributes[kSecAttrApplicationLabel as String] as? Data == selectedLabel,
              SHA256.hash(data: SecCertificateCopyData(certificate) as Data).map({ String(format: "%02x", $0) }).joined() == certificateID,
              CertificateInspection.assess(certificate, key: key).blockers(expectedTeamID: expectedTeamID,
                requireToken: true, tokenID: tokenID, now: Date()).isEmpty,
              let publicKey = SecCertificateCopyKey(certificate) else {
            return result("YK_IDENTITY_CHANGED", "revalidation", "Exact identity no longer passes checks; signing blocked.")
        }
        if probeOnly {
            return result("YK_REFERENCE_READY", "revalidation", "Exact reference acquisition and certificate revalidation passed without authentication UI or signing.")
        }
        // Select once using public capabilities; never fall back after an attempted signature.
        let algorithms: [(SecKeyAlgorithm, String)] = [
            (.rsaSignatureMessagePKCS1v15SHA256, "rsa-pkcs1v15-sha256"),
            (.ecdsaSignatureMessageX962SHA256, "ecdsa-x962-sha256")]
        guard let (algorithm, name) = algorithms.first(where: {
            SecKeyIsAlgorithmSupported(key, .sign, $0.0) && SecKeyIsAlgorithmSupported(publicKey, .verify, $0.0)
        }) else { return result("YK_ALGORITHM_UNSUPPORTED", "capability", "No supported challenge signature algorithm.") }
        algorithmName = name
        var nonce = Data(count: 32)
        let randomStatus = nonce.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        guard randomStatus == errSecSuccess else { return result("YK_CHALLENGE_FAILED", "challenge", "Random generation failed.") }
        let message: Data
        do {
            if let possessionDigest {
                message = try SignerPolicy(certificateID: certificateID, tokenID: tokenID, expectedTeamID: expectedTeamID,
                    possessionReceiptDigest: possessionDigest, nonce: nonce).message()
            } else {
                message = try IdentityChallenge(certificateID: certificateID, tokenID: tokenID, expectedTeamID: expectedTeamID, nonce: nonce).message()
            }
        } catch { return result("YK_CHALLENGE_FAILED", "challenge", "Closed signing plan generation failed.") }
        messageDigest = SHA256.hash(data: message).map { String(format: "%02x", $0) }.joined()
        attempted = true
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, algorithm, message as CFData, &error) else {
            // Consume the error without exposing provider descriptions or credential details.
            _ = error?.takeRetainedValue()
            return result("YK_SIGNING_STOPPED", "sign", "One signing call failed or was cancelled; no retry was made. Token authentication state may have changed.")
        }
        guard SecKeyVerifySignature(publicKey, algorithm, message as CFData, signature, nil) else {
            return result("YK_SIGNATURE_INVALID", "verify", "Returned signature did not verify against the selected certificate.")
        }
        if let reservation {
            do {
                let sealed = SealedSignerPolicy(certificateDER: SecCertificateCopyData(certificate) as Data,
                    message: message, signature: signature as Data, algorithm: name)
                let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
                try reservation.commit(encoder.encode(sealed))
            } catch {
                return result("YK_ENROLLMENT_COMMIT_UNCERTAIN", "commit", "Policy signature verified, but publication failed or durability is uncertain. Preserve any record and reconcile; do not automatically sign again.")
            }
            return result("YK_SIGNER_ENROLLED", "commit", "Initial signer enrollment policy signed and retained with no operational authority.", verified: true)
        }
        if let receiptPath {
            do {
                let receipt = PossessionReceipt(certificateDER: SecCertificateCopyData(certificate) as Data,
                    message: message, signature: signature as Data, algorithm: name)
                let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
                try PublicReceiptFile.save(encoder.encode(receipt), to: receiptPath)
            } catch {
                return result("YK_RECEIPT_COMMIT_UNCERTAIN", "receipt", "Signature verified, but receipt publication failed or durability is uncertain. Preserve any output file; do not automatically repeat signing.")
            }
            return result("YK_RECEIPT_SAVED", "receipt", "Signed public possession evidence saved. This is not enrollment or policy authorization.", verified: true)
        }
        return result("YK_POSSESSION_VERIFIED", "verify", "Fresh challenge signature verified against the exact selected certificate. PIN/touch policy is controlled by the token and macOS.", verified: true)
        #else
        return result("YK_PLATFORM_UNSUPPORTED", "runtime", "Possession testing requires macOS.")
        #endif
    }
}

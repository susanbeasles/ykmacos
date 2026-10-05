import Foundation
import YKCore
#if os(macOS)
import Security
import LocalAuthentication
import CryptoKit
#endif

public enum SecureEnclaveKeys {
    struct Record: Codable {
        let schemaVersion: Int
        let domain: String
        let keyTag: String
        let access: String
        let stage: String
        let publicKey: Data?
    }
    private static func diagnostic(_ code: String, _ operation: String, _ message: String, changed: Bool = false) -> Diagnostic {
        Diagnostic(code: code, operation: operation, stage: "secure-enclave", message: message,
            changed: changed, retrySafe: !changed,
            nextAction: "Retain public key records. SEP keys cannot be recovered on another Mac; keep independent signing and recovery paths. No automatic retry or deletion occurs.")
    }
    #if os(macOS)
    private static func encode(_ record: Record) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(record)
    }
    private static func load(_ path: String) throws -> Record {
        let bytes = try PublicReceiptFile.read(path)
        let record = try JSONDecoder().decode(Record.self, from: bytes)
        guard record.schemaVersion == 1, record.domain == "ykmacos.sep-key.v1", record.access == "user-presence",
              record.keyTag.hasPrefix("me.vespoli.ykmacos.sep."),
              UUID(uuidString: String(record.keyTag.dropFirst("me.vespoli.ykmacos.sep.".count))) != nil,
              ["planned", "created"].contains(record.stage),
              (record.stage == "planned" ? record.publicKey == nil : (record.publicKey?.count == 65 && record.publicKey?.first == 4)) else { throw CertificateRequest.Failure.invalidInput }
        let a = try JSONSerialization.jsonObject(with: bytes) as? NSDictionary
        let b = try JSONSerialization.jsonObject(with: encode(record)) as? NSDictionary
        guard a == b else { throw CertificateRequest.Failure.invalidInput }
        return record
    }
    private static func lookup(_ record: Record, interactive: Bool) throws -> SecKey {
        let context = LAContext(); context.interactionNotAllowed = !interactive
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: Data(record.keyTag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: context,
            kSecReturnRef as String: true, kSecMatchLimit as String: kSecMatchLimitAll]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let keys = result as? [SecKey], keys.count == 1 else { throw CertificateRequest.Failure.invalidInput }
        return keys[0]
    }
    private static func publicBytes(_ key: SecKey) throws -> (SecKey, Data) {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String,
              let publicKey = SecKeyCopyPublicKey(key) else { throw CertificateRequest.Failure.invalidInput }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?,
              data.count == 65, data.first == 4 else { throw CertificateRequest.Failure.invalidInput }
        return (publicKey, data)
    }
    #endif
    public static func create(recordPath: String, access: String) -> Diagnostic {
        let operation = "sep.create"
        guard access == "user-presence" else { return diagnostic("YK_SEP_INPUT_REJECTED", operation, "Explicit --access user-presence is required. macOS may permit biometric or password authentication.") }
        #if os(macOS)
        var mutationStarted = false
        do {
            guard SecureEnclave.isAvailable else { return diagnostic("YK_SEP_UNAVAILABLE", operation, "Secure Enclave is unavailable. No software key was generated.") }
            let plan = try PublicReceiptFile.Reservation(recordPath)
            let completed = try PublicReceiptFile.Reservation(recordPath + ".created.json")
            let tag = "me.vespoli.ykmacos.sep." + UUID().uuidString.lowercased()
            let planned = Record(schemaVersion: 1, domain: "ykmacos.sep-key.v1", keyTag: tag, access: access, stage: "planned", publicKey: nil)
            mutationStarted = true
            try plan.commit(encode(planned))
            // Durable intent exists before the one key-creation request. Never retry automatically.
            mutationStarted = true
            var error: Unmanaged<CFError>?
            guard let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .userPresence], &error) else { throw CertificateRequest.Failure.invalidInput }
            let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256, kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecUseDataProtectionKeychain as String: true,
                kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
                    kSecAttrApplicationTag as String: Data(tag.utf8), kSecAttrAccessControl as String: control]]
            guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                let status = error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? 0
                return diagnostic("YK_SEP_CREATE_FAILED", operation, "Key creation returned error code \(status). Intent retained at \(recordPath). Inspect it before another creation request.", changed: true)
            }
            let (_, bytes) = try publicBytes(key)
            let reread = try lookup(planned, interactive: false)
            guard try publicBytes(reread).1 == bytes else { throw CertificateRequest.Failure.invalidInput }
            try completed.commit(encode(Record(schemaVersion: 1, domain: planned.domain, keyTag: tag, access: access, stage: "created", publicKey: bytes)))
            return diagnostic("YK_SEP_KEY_CREATED", operation, "Persistent P-256 SEP key re-read and public key verified. Public record: \(recordPath).created.json. No certificate was issued or authority granted.", changed: true)
        } catch {
            return diagnostic("YK_SEP_CREATE_INCOMPLETE", operation, "Creation or record publication did not complete. Inspect \(recordPath); any created key is retained. No fallback key, automatic retry, or deletion occurred.", changed: mutationStarted)
        }
        #else
        return diagnostic("YK_PLATFORM_UNSUPPORTED", operation, "Requires macOS.")
        #endif
    }
    public static func inspect(recordPath: String) -> Diagnostic {
        #if os(macOS)
        do {
            let record = try load(recordPath)
            let key = try lookup(record, interactive: false)
            let (_, bytes) = try publicBytes(key)
            guard record.publicKey == nil || record.publicKey == bytes else { throw CertificateRequest.Failure.invalidInput }
            let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            return diagnostic("YK_SEP_KEY_FOUND", "sep.inspect", "Exact SEP key reference found without signing. Public point SHA-256: \(digest). Record stage: \(record.stage). Public records alone grant no authority.")
        } catch { return diagnostic("YK_SEP_INSPECT_FAILED", "sep.inspect", "Exact SEP reference or public record could not be verified without UI. No signing, key creation, or deletion attempted.") }
        #else
        return diagnostic("YK_PLATFORM_UNSUPPORTED", "sep.inspect", "Requires macOS.")
        #endif
    }
    public static func csr(recordPath: String, commonName: String, output: String) -> Diagnostic {
        #if os(macOS)
        var signingStarted = false
        do {
            try CertificateRequest.validateCommonName(commonName)
            let record = try load(recordPath)
            guard record.stage == "created", let expected = record.publicKey else { throw CertificateRequest.Failure.invalidInput }
            let destination = try PublicReceiptFile.Reservation(output)
            let key = try lookup(record, interactive: true)
            let (publicKey, bytes) = try publicBytes(key)
            guard bytes == expected, SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256) else { throw CertificateRequest.Failure.invalidInput }
            let information = try CertificateRequest.information(publicKey: bytes, commonName: commonName)
            var error: Unmanaged<CFError>?
            signingStarted = true
            guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, information as CFData, &error) as Data? else {
                let status = error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? 0
                return diagnostic("YK_SEP_CSR_SIGN_FAILED", "sep.csr", "One signing request failed with error code \(status). No automatic retry.", changed: true)
            }
            guard SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256, information as CFData, signature as CFData, &error) else { throw CertificateRequest.Failure.invalidInput }
            try destination.commit(CertificateRequest.pem(information: information, signature: signature))
            return diagnostic("YK_SEP_CSR_SAVED", "sep.csr", "PKCS #10 CSR signature verified and public PEM saved to \(output). CA acceptance, certificate import, and codesign compatibility remain separate checks.", changed: true)
        } catch { return diagnostic("YK_SEP_CSR_FAILED", "sep.csr", "CSR validation or publication failed. Key retained; no automatic signing retry or deletion occurred.", changed: signingStarted) }
        #else
        return diagnostic("YK_PLATFORM_UNSUPPORTED", "sep.csr", "Requires macOS.")
        #endif
    }
}

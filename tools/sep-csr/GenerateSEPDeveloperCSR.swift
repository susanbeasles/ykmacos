import Foundation
import Security

@main struct GenerateSEPDeveloperCSR {
    static func main() throws {
        let args = Array(CommandLine.arguments.dropFirst())
        guard args.count == 3, !args[0].isEmpty, !args[1].isEmpty else {
            throw NSError(domain: "ykmacos.sep-csr", code: 1, userInfo: [NSLocalizedDescriptionKey: "Usage: sep-developer-csr KEY_TAG COMMON_NAME OUTPUT.csr"])
        }
        let tag = Data(args[0].utf8)
        let output = URL(fileURLWithPath: args[2])
        guard !FileManager.default.fileExists(atPath: output.path) else {
            throw NSError(domain: "ykmacos.sep-csr", code: 2, userInfo: [NSLocalizedDescriptionKey: "Output exists; refusing replacement"])
        }
        var result: CFTypeRef?
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        let key: SecKey
        if status == errSecSuccess {
            key = result as! SecKey
            print("Reusing retained key for tag: \(args[0])")
        } else if status == errSecItemNotFound {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .userPresence], &error) else {
                throw error!.takeRetainedValue() as Error
            }
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: true,
                    kSecAttrApplicationTag as String: tag,
                    kSecAttrAccessControl as String: access
                ]
            ]
            guard let generated = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            key = generated
            print("Generated and retained P-256 key inside SEP. No fallback.")
        } else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        print("Authorize SEP signing when prompted. The key stays retained if CSR creation fails.")
        let csr = try SEPDeveloperCSR.make(key: key, commonName: args[1])
        let pem = Data(SEPDeveloperCSR.pem(csr).utf8)
        // Atomic exclusive output creation: never overwrite an existing request.
        try pem.write(to: output, options: .withoutOverwriting)
        print("Wrote CSR: \(output.path)")
        print("Keep key tag '\(args[0])' for pairing Apple's returned certificate.")
    }
}

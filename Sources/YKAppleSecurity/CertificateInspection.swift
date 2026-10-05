#if os(macOS)
import Foundation
import Security
import YKCore

internal enum CertificateInspection {
    static func assess(_ certificate: SecCertificate, key: SecKey?) -> CertificateAssessment {
        let appOID = "1.2.840.113635.100.6.1.13"
        let installerOID = "1.2.840.113635.100.6.1.14"
        let requested = [kSecOIDOrganizationalUnitName as String, kSecOIDX509V1ValidityNotBefore as String,
                         kSecOIDX509V1ValidityNotAfter as String, appOID, installerOID]
        let values = SecCertificateCopyValues(certificate, requested as CFArray, nil) as? [String: Any] ?? [:]
        func property(_ oid: String) -> Any? {
            (values[oid] as? [String: Any])?[kSecPropertyKeyValue as String]
        }
        func date(_ oid: String) -> Date? {
            if let date = property(oid) as? Date { return date }
            if let seconds = property(oid) as? NSNumber { return Date(timeIntervalSinceReferenceDate: seconds.doubleValue) }
            return nil
        }
        let units: [String]
        if let subjectDER = SecCertificateCopyNormalizedSubjectSequence(certificate) as Data? {
            units = (try? SubjectOU.extract(subjectDER)) ?? []
        } else { units = [] }
        let purpose: String
        if values[appOID] != nil && values[installerOID] == nil { purpose = "developer-id-application" }
        else if values[installerOID] != nil && values[appOID] == nil { purpose = "developer-id-installer" }
        else { purpose = "unknown-or-ambiguous" }
        var match: Bool?
        // Export PUBLIC representations only. No signing or private-key export occurs.
        if let key, let identityPublic = SecKeyCopyPublicKey(key), let certificatePublic = SecCertificateCopyKey(certificate),
           let identityBytes = SecKeyCopyExternalRepresentation(identityPublic, nil) as Data?,
           let certificateBytes = SecKeyCopyExternalRepresentation(certificatePublic, nil) as Data? {
            match = identityBytes == certificateBytes
        }
        var trust: SecTrust?
        var trusted = false
        if let policy = SecPolicyCreateWithProperties(kSecPolicyAppleCodeSigning, nil),
           SecTrustCreateWithCertificates(certificate, policy, &trust) == errSecSuccess, let trust,
           SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess {
            trusted = SecTrustEvaluateWithError(trust, nil)
        }
        return CertificateAssessment(purposeMarker: purpose, subjectOrganizationalUnits: units,
            validFrom: date(kSecOIDX509V1ValidityNotBefore as String), validUntil: date(kSecOIDX509V1ValidityNotAfter as String),
            publicKeyMatch: match, codeSigningTrust: trusted,
            appleDeveloperIDChainVerified: purpose == "developer-id-application" && AppleDeveloperIDTrust.verify(certificate))
    }
}
#endif

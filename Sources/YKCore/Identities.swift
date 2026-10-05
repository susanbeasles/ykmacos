import Foundation
public struct SigningIdentity: Codable, Sendable, Equatable {
    public let certificateID: String
    public let subject: String
    public let sources: [String]
    public let tokenID: String?
    public let origin: KeyOrigin
    public let certificate: CertificateAssessment?
    public init(certificateID: String, subject: String, source: String, tokenID: String?, origin: KeyOrigin, certificate: CertificateAssessment? = nil) {
        self.init(certificateID: certificateID, subject: subject, sources: [source], tokenID: tokenID, origin: origin, certificate: certificate)
    }
    public init(certificateID: String, subject: String, sources: [String], tokenID: String?, origin: KeyOrigin, certificate: CertificateAssessment? = nil) {
        self.certificateID = certificateID; self.subject = subject
        self.sources = Array(Set(sources)).sorted(); self.tokenID = tokenID; self.origin = origin; self.certificate = certificate
    }
}
public enum IdentityConsolidation {
    private struct Association: Hashable {
        let certificateID: String
        let tokenID: String?
        let subject: String
        let origin: KeyOrigin
        let certificate: CertificateAssessment?
    }
    /// A certificate exposed with no token remains distinct from the same certificate on a token.
    /// Conflicting subjects/origin evidence are never resolved by guessing.
    public static func consolidate(_ observations: [SigningIdentity]) -> [SigningIdentity] {
        var groups: [Association: Set<String>] = [:]
        for item in observations {
            let key = Association(certificateID: item.certificateID, tokenID: item.tokenID, subject: item.subject, origin: item.origin, certificate: item.certificate)
            groups[key, default: []].formUnion(item.sources)
        }
        return groups.map { key, sources in
            SigningIdentity(certificateID: key.certificateID, subject: key.subject,
                sources: Array(sources), tokenID: key.tokenID, origin: key.origin, certificate: key.certificate)
        }.sorted {
            if $0.certificateID != $1.certificateID { return $0.certificateID < $1.certificateID }
            if $0.tokenID != $1.tokenID {
                if $0.tokenID == nil { return true }
                if $1.tokenID == nil { return false }
                return $0.tokenID! < $1.tokenID!
            }
            if $0.subject != $1.subject { return $0.subject < $1.subject }
            return $0.origin.rawValue < $1.origin.rawValue
        }
    }
}
public struct IdentityInventory: Codable, Sendable {
    public let schemaVersion: Int
    public let observationCount: Int
    public let identities: [SigningIdentity]
    public let diagnostics: [Diagnostic]
    public let eligibilityVerified: Bool
    public init(identities: [SigningIdentity], diagnostics: [Diagnostic]) {
        schemaVersion = 3; observationCount = identities.count
        self.identities = IdentityConsolidation.consolidate(identities)
        self.diagnostics = diagnostics; eligibilityVerified = false
    }
}

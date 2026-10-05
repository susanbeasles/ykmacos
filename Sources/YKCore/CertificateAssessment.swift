import Foundation
/// Evidence, not an authorization decision or proof of Apple issuance.
public struct CertificateAssessment: Codable, Sendable, Equatable, Hashable {
    public let purposeMarker: String
    public let subjectOrganizationalUnits: [String]
    public let validFrom: Date?
    public let validUntil: Date?
    public let publicKeyMatch: Bool?
    public let codeSigningTrust: Bool
    public let trustNetworkFetchAllowed: Bool
    public let appleDeveloperIDChainVerified: Bool
    public let revocationFreshness: String
    public init(purposeMarker: String, subjectOrganizationalUnits: [String], validFrom: Date?, validUntil: Date?, publicKeyMatch: Bool?, codeSigningTrust: Bool, appleDeveloperIDChainVerified: Bool = false) {
        self.purposeMarker = purposeMarker; self.subjectOrganizationalUnits = subjectOrganizationalUnits.sorted()
        self.validFrom = validFrom; self.validUntil = validUntil; self.publicKeyMatch = publicKeyMatch
        self.codeSigningTrust = codeSigningTrust; trustNetworkFetchAllowed = false
        self.appleDeveloperIDChainVerified = appleDeveloperIDChainVerified
        revocationFreshness = "not-established-offline"
    }
    public func blockers(expectedTeamID: String, requireToken: Bool, tokenID: String?, now: Date) -> [String] {
        var reasons: [String] = []
        if purposeMarker != "developer-id-application" { reasons.append("purpose-mismatch") }
        if subjectOrganizationalUnits != [expectedTeamID] { reasons.append("team-mismatch-or-ambiguous") }
        if let from = validFrom, let until = validUntil {
            if from > now || until <= now || from >= until { reasons.append("certificate-outside-validity") }
        } else { reasons.append("validity-unknown") }
        if publicKeyMatch != true { reasons.append("public-key-match-unverified") }
        if !codeSigningTrust { reasons.append("code-signing-trust-failed") }
        if requireToken && tokenID == nil { reasons.append("token-association-missing") }
        if !appleDeveloperIDChainVerified { reasons.append("apple-anchor-verification-pending") }
        return reasons
    }
}

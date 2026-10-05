import Foundation

/// Only this closed, domain-separated message may be signed by the diagnostic.
public struct IdentityChallenge: Encodable, Sendable, Equatable {
    public let domain = "ykmacos.identity-possession.v1"
    public let certificateID: String
    public let tokenID: String
    public let expectedTeamID: String
    public let nonce: Data
    public init(certificateID: String, tokenID: String, expectedTeamID: String, nonce: Data) throws {
        guard certificateID.count == 64, certificateID.allSatisfy({ "0123456789abcdef".contains($0) }),
              !tokenID.isEmpty, expectedTeamID.count == 10,
              expectedTeamID.allSatisfy({ "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".contains($0) }),
              nonce.count == 32 else { throw ChallengeError.invalidInput }
        self.certificateID = certificateID; self.tokenID = tokenID
        self.expectedTeamID = expectedTeamID; self.nonce = nonce
    }
    public func message() throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }
    public enum ChallengeError: Error { case invalidInput }
}
public struct IdentityChallengeResult: Encodable, Sendable {
    public let certificateID: String
    public let tokenID: String
    public let expectedTeamID: String
    public let challengeDigest: String?
    public let algorithm: String?
    public let signingAttempted: Bool
    public let signatureVerified: Bool
    public let diagnostics: [Diagnostic]
    public let enrolled: Bool
    public let hardwareOriginVerified = false
    public let revocationFreshness = "not-established-offline"
    public init(certificateID: String, tokenID: String, expectedTeamID: String, challengeDigest: String?,
                algorithm: String?, signingAttempted: Bool, signatureVerified: Bool, diagnostics: [Diagnostic], enrolled: Bool = false) {
        self.certificateID = certificateID; self.tokenID = tokenID; self.expectedTeamID = expectedTeamID
        self.challengeDigest = challengeDigest; self.algorithm = algorithm
        self.signingAttempted = signingAttempted; self.signatureVerified = signatureVerified; self.diagnostics = diagnostics; self.enrolled = enrolled
    }
}

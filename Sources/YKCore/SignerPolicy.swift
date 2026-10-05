import Foundation

/// Closed initial enrollment policy. Operational authority is intentionally absent.
public struct SignerPolicy: Codable, Sendable, Equatable {
    public let schemaVersion: Int
    public let domain: String
    public let revision: Int
    public let certificateID: String
    public let tokenID: String
    public let expectedTeamID: String
    public let possessionReceiptDigest: String
    public let nonce: Data
    public let keyOrigin: String
    public let backupCoverage: String
    public let allowedOperations: [String]
    public init(certificateID: String, tokenID: String, expectedTeamID: String, possessionReceiptDigest: String, nonce: Data) throws {
        _ = try IdentityChallenge(certificateID: certificateID, tokenID: tokenID, expectedTeamID: expectedTeamID, nonce: nonce)
        guard possessionReceiptDigest.count == 64, possessionReceiptDigest.allSatisfy({ "0123456789abcdef".contains($0) }) else {
            throw IdentityChallenge.ChallengeError.invalidInput
        }
        schemaVersion = 1; domain = "ykmacos.signer-enrollment.v1"; revision = 1
        self.certificateID = certificateID; self.tokenID = tokenID; self.expectedTeamID = expectedTeamID
        self.possessionReceiptDigest = possessionReceiptDigest; self.nonce = nonce
        keyOrigin = "unverifiable"; backupCoverage = "unknown"; allowedOperations = []
    }
    public func message() throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }
    public static func validate(_ message: Data, certificateID: String, tokenID: String, teamID: String) throws -> SignerPolicy {
        guard message.count <= 8192 else { throw IdentityChallenge.ChallengeError.invalidInput }
        let decoded = try JSONDecoder().decode(SignerPolicy.self, from: message)
        let expected = try SignerPolicy(certificateID: certificateID, tokenID: tokenID, expectedTeamID: teamID,
            possessionReceiptDigest: decoded.possessionReceiptDigest, nonce: decoded.nonce)
        guard try expected.message() == message else { throw IdentityChallenge.ChallengeError.invalidInput }
        return expected
    }
}
public struct SealedSignerPolicy: Codable, Sendable {
    public let certificateDER: Data
    public let message: Data
    public let signature: Data
    public let algorithm: String
    public init(certificateDER: Data, message: Data, signature: Data, algorithm: String) {
        self.certificateDER = certificateDER; self.message = message; self.signature = signature; self.algorithm = algorithm
    }
}
public struct SignerPolicyReport: Encodable, Sendable {
    public let policyVerified: Bool
    public let enrolled: Bool
    public let policyDigest: String?
    public let certificateID: String
    public let tokenID: String
    public let expectedTeamID: String
    public let backupCoverage = "unknown"
    public let hardwareOriginVerified = false
    public let operationalAuthorityEnabled = false
    public let rollbackProtectionEstablished = false
    public let revocationFreshness = "not-established-offline"
    public let diagnostics: [Diagnostic]
    public init(policyVerified: Bool, policyDigest: String?, certificateID: String, tokenID: String, expectedTeamID: String, diagnostics: [Diagnostic]) {
        self.policyVerified = policyVerified; enrolled = policyVerified; self.policyDigest = policyDigest
        self.certificateID = certificateID; self.tokenID = tokenID; self.expectedTeamID = expectedTeamID; self.diagnostics = diagnostics
    }
}

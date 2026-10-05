import Foundation
/// Public evidence only; never an enrollment or policy authorization record.
public struct PossessionReceipt: Codable, Sendable {
    public let schemaVersion: Int
    public let certificateDER: Data
    public let message: Data
    public let signature: Data
    public let algorithm: String
    public init(certificateDER: Data, message: Data, signature: Data, algorithm: String) {
        schemaVersion = 1; self.certificateDER = certificateDER; self.message = message
        self.signature = signature; self.algorithm = algorithm
    }
    public func validateMessage(certificateID: String, tokenID: String, teamID: String) throws {
        guard schemaVersion == 1, certificateDER.count <= 16384, signature.count <= 1024,
              message.count <= 4096,
              let body = try JSONSerialization.jsonObject(with: message) as? [String: Any],
              let nonceText = body["nonce"] as? String, let nonce = Data(base64Encoded: nonceText) else {
            throw IdentityChallenge.ChallengeError.invalidInput
        }
        let expected = try IdentityChallenge(certificateID: certificateID, tokenID: tokenID, expectedTeamID: teamID, nonce: nonce)
        // Exact bytes reject unknown fields, duplicate keys, foreign domain and selection.
        guard try expected.message() == message else { throw IdentityChallenge.ChallengeError.invalidInput }
    }
}

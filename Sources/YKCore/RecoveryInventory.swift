import Foundation

/// Public inventory only. User declarations never become authorization evidence.
public struct RecoveryInventory: Codable, Sendable {
    public let schemaVersion: Int
    public let resources: [Resource]
    public struct Resource: Codable, Sendable {
        public let id: String
        public let kind: Kind
        public let primaryDeviceID: String
        public let backups: [Route]
        public let alternatives: [Route]
    }
    public enum Kind: String, Codable, Sendable {
        case account, administrativeCredential, encryptedData, replaceableAPIKey
    }
    public struct Route: Codable, Sendable {
        public let id: String
        public let status: CoverageStatus
        public let independentOfPrimary: Bool
        public let independentOfMac: Bool
    }
    public enum Failure: Error { case invalidInventory }
    public static func decode(_ data: Data) throws -> Self {
        guard data.count > 0, data.count <= 65536 else { throw Failure.invalidInventory }
        let value = try JSONDecoder().decode(Self.self, from: data)
        // Reject unknown fields through structural round-trip comparison. This inventory is not signed policy.
        let original = try JSONSerialization.jsonObject(with: data)
        let encoded = try JSONEncoder().encode(value)
        let restored = try JSONSerialization.jsonObject(with: encoded)
        guard let a = original as? NSDictionary, let b = restored as? NSDictionary, a == b,
              value.schemaVersion == 1, value.resources.count <= 256 else { throw Failure.invalidInventory }
        var ids = Set<String>()
        func validID(_ id: String) -> Bool {
            !id.isEmpty && id.utf8.count <= 256 && !id.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        }
        for resource in value.resources {
            guard validID(resource.id), ids.insert(resource.id).inserted, validID(resource.primaryDeviceID),
                  resource.backups.count <= 32, resource.alternatives.count <= 32 else { throw Failure.invalidInventory }
            var routes = Set<String>()
            for route in resource.backups + resource.alternatives {
                guard validID(route.id), routes.insert(route.id).inserted,
                      route.id != resource.primaryDeviceID else { throw Failure.invalidInventory }
            }
        }
        return value
    }
    public func report(removing deviceID: String? = nil) -> Report {
        let entries = resources.sorted { $0.id < $1.id }.map { resource -> Entry in
            let affected = deviceID == nil || resource.primaryDeviceID == deviceID || resource.backups.contains { $0.id == deviceID }
            let backups = resource.backups.filter { $0.id != deviceID && $0.status == .tested && $0.independentOfPrimary }
            let alternatives = resource.alternatives.filter {
                $0.id != deviceID && $0.status == .tested && $0.independentOfPrimary && $0.independentOfMac
            }
            var blockers: [String] = []
            switch resource.kind {
            case .account:
                if alternatives.isEmpty { blockers.append("tested-independent-account-alternative-missing") }
            case .administrativeCredential, .encryptedData:
                if alternatives.isEmpty { blockers.append("verified-independent-recovery-material-missing") }
            case .replaceableAPIKey:
                if alternatives.isEmpty { blockers.append("independent-provider-access-for-reissue-missing") }
            }
            if deviceID != nil && resource.primaryDeviceID == deviceID && backups.isEmpty {
                blockers.append("remaining-tested-backup-device-missing")
            }
            return Entry(resourceID: resource.id, kind: resource.kind, affected: affected,
                declaredTestedBackups: backups.map(\.id).sorted(),
                declaredTestedAlternatives: alternatives.map(\.id).sorted(), blockers: affected ? blockers : [])
        }
        return Report(schemaVersion: 1, removingDeviceID: deviceID, entries: entries,
            reviewRequired: entries.isEmpty || entries.contains { $0.affected && !$0.blockers.isEmpty })
    }
    public struct Entry: Codable, Sendable {
        public let resourceID: String
        public let kind: Kind
        public let affected: Bool
        public let declaredTestedBackups: [String]
        public let declaredTestedAlternatives: [String]
        public let blockers: [String]
    }
    public struct Report: Encodable, Sendable {
        public let schemaVersion: Int
        public let removingDeviceID: String?
        public let entries: [Entry]
        public let reviewRequired: Bool
        public let evidenceSource = "user-declared-inventory"
        public let recoveryCryptographicallyVerified = false
        public let destructiveChangeAuthorized = false
    }
}

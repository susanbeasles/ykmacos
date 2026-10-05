import Foundation
public enum HardwareCapability: String, Codable, Sendable { case piv, fido2, oath, openpgp, otp, secureEnclave }
public enum KeyOrigin: String, Codable, Sendable, Hashable { case attestedGenerated, imported, unverifiable }
public struct DeviceInventory: Codable, Sendable {
    public let providerID: String
    public let deviceID: String
    public let firmware: String
    public let capabilities: Set<HardwareCapability>
    public init(providerID: String, deviceID: String, firmware: String, capabilities: Set<HardwareCapability>) {
        self.providerID = providerID; self.deviceID = deviceID; self.firmware = firmware; self.capabilities = capabilities
    }
}
/// Providers must implement read-only discovery separately from credential mutations.
public protocol HardwareProvider: Sendable {
    var providerID: String { get }
    func inspect() async throws -> [DeviceInventory]
}
public struct ProviderRegistry: Sendable {
    private let providers: [any HardwareProvider]
    public init(_ providers: [any HardwareProvider]) throws {
        guard Set(providers.map(\.providerID)).count == providers.count else { throw RegistryError.duplicateProvider }
        self.providers = providers
    }
    public func inspect() async throws -> [DeviceInventory] {
        var devices: [DeviceInventory] = []
        for provider in providers { devices += try await provider.inspect() }
        return devices
    }
    public enum RegistryError: Error { case duplicateProvider }
}
public struct Diagnostic: Codable, Sendable {
    public let code: String
    public let operation: String
    public let stage: String
    public let message: String
    public let changed: Bool
    public let retrySafe: Bool
    public let nextAction: String
    public init(code: String, operation: String, stage: String, message: String, changed: Bool, retrySafe: Bool, nextAction: String) {
        self.code = code; self.operation = operation; self.stage = stage; self.message = message
        self.changed = changed; self.retrySafe = retrySafe; self.nextAction = nextAction
    }
}

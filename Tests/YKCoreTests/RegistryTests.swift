import XCTest
@testable import YKCore
private struct FixtureProvider: HardwareProvider {
    let providerID: String
    func inspect() async throws -> [DeviceInventory] {
        [DeviceInventory(providerID: providerID, deviceID: "fixture", firmware: "test", capabilities: [.piv])]
    }
}
final class RegistryTests: XCTestCase {
    func testDuplicateProvidersRejected() {
        XCTAssertThrowsError(try ProviderRegistry([FixtureProvider(providerID: "same"), FixtureProvider(providerID: "same")]))
    }
    func testMultipleModulesDiscoverIndependently() async throws {
        let registry = try ProviderRegistry([FixtureProvider(providerID: "one"), FixtureProvider(providerID: "two")])
        let devices = try await registry.inspect()
        XCTAssertEqual(devices.map(\.providerID), ["one", "two"])
    }
}

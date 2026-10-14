import Foundation
import YKCore
#if os(macOS)
import CryptoKit
#endif

public enum NativeReadiness {
    public static func inspect(expectedTeamID: String? = nil) -> NativeReadinessReport {
        #if os(macOS)
        let supported = ProcessInfo.processInfo.isOperatingSystemAtLeast(
            OperatingSystemVersion(majorVersion: 27, minorVersion: 0, patchVersion: 0))
        let enclaveAvailable = SecureEnclave.isAvailable
        #else
        let supported = false
        let enclaveAvailable = false
        #endif
        return NativeReadinessReport(platformSupported: supported,
            operatingSystem: ProcessInfo.processInfo.operatingSystemVersionString,
            secureEnclaveAvailable: enclaveAvailable,
            tokenIDs: IdentityDiscovery.availableTokenIDs(), inventory: IdentityDiscovery.inspect(),
            expectedTeamID: expectedTeamID, now: Date())
    }
}

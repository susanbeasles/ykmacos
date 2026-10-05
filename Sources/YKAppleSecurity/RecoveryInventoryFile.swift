import Foundation
import YKCore

public enum RecoveryInventoryFile {
    public static func load(_ path: String) throws -> RecoveryInventory {
        #if os(macOS)
        return try RecoveryInventory.decode(PublicReceiptFile.read(path))
        #else
        throw RecoveryInventory.Failure.invalidInventory
        #endif
    }
    public static func create(_ path: String) throws {
        #if os(macOS)
        try PublicReceiptFile.save(Data("{\"schemaVersion\":1,\"resources\":[]}\n".utf8), to: path)
        #else
        throw RecoveryInventory.Failure.invalidInventory
        #endif
    }
}

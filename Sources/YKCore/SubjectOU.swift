import Foundation
/// Bounded DER Name reader for OU (2.5.4.11). Never derives identity from display text.
public enum SubjectOU {
    public enum Failure: Error { case malformed, unsupportedString }
    private struct Element { let tag: UInt8; let bytes: [UInt8] }
    private static func elements(_ bytes: [UInt8]) throws -> [Element] {
        var offset = 0
        var result: [Element] = []
        while offset < bytes.count {
            guard result.count < 128, offset + 2 <= bytes.count else { throw Failure.malformed }
            let tag = bytes[offset]; offset += 1
            let first = bytes[offset]; offset += 1
            var length = Int(first)
            if first & 0x80 != 0 {
                let count = Int(first & 0x7f)
                guard count > 0, count <= 3, offset + count <= bytes.count, bytes[offset] != 0 else { throw Failure.malformed }
                length = 0
                for _ in 0..<count { length = (length << 8) | Int(bytes[offset]); offset += 1 }
                guard length >= 128 else { throw Failure.malformed }
            }
            guard length <= bytes.count - offset else { throw Failure.malformed }
            result.append(Element(tag: tag, bytes: Array(bytes[offset..<offset+length])))
            offset += length
        }
        return result
    }
    public static func extract(_ data: Data) throws -> [String] {
        guard data.count <= 65536 else { throw Failure.malformed }
        let outer = try elements(Array(data))
        guard outer.count == 1, outer[0].tag == 0x30 else { throw Failure.malformed }
        var values: [String] = []
        for set in try elements(outer[0].bytes) {
            guard set.tag == 0x31 else { throw Failure.malformed }
            for attribute in try elements(set.bytes) {
                guard attribute.tag == 0x30 else { throw Failure.malformed }
                let pair = try elements(attribute.bytes)
                guard pair.count == 2, pair[0].tag == 0x06 else { throw Failure.malformed }
                guard pair[0].bytes == [0x55, 0x04, 0x0b] else { continue }
                let value = pair[1]
                let text: String?
                switch value.tag {
                case 0x0c: text = String(bytes: value.bytes, encoding: .utf8)
                case 0x13, 0x16: text = String(bytes: value.bytes, encoding: .ascii)
                case 0x1e: text = String(data: Data(value.bytes), encoding: .utf16BigEndian)
                default: throw Failure.unsupportedString
                }
                guard let text, !text.isEmpty else { throw Failure.malformed }
                values.append(text)
            }
        }
        // Preserve duplicate OUs: ambiguity must not disappear through deduplication.
        return values.sorted()
    }
}

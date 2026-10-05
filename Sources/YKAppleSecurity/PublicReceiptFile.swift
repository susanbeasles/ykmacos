#if os(macOS)
import Foundation
import Darwin

/// Descriptor-relative, no-overwrite publication of bounded public evidence.
internal enum PublicReceiptFile {
    enum Failure: Error { case invalidPath, io, invalidFile }
    static func parent(_ path: String) throws -> (Int32, String) {
        guard path.hasPrefix("/"), !path.utf8.contains(0) else { throw Failure.invalidPath }
        let parts = path.split(separator: "/", omittingEmptySubsequences: false).dropFirst().map(String.init)
        guard !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { throw Failure.invalidPath }
        var descriptor = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard descriptor >= 0 else { throw Failure.io }
        for component in parts.dropLast() {
            let next = openat(descriptor, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            close(descriptor)
            guard next >= 0 else { throw Failure.io }
            descriptor = next
        }
        return (descriptor, parts.last!)
    }
    static func preflight(_ path: String) throws {
        let (directory, name) = try parent(path); defer { close(directory) }
        var info = stat()
        guard fstat(directory, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o022 == 0 else { throw Failure.invalidPath }
        var target = stat()
        guard fstatat(directory, name, &target, AT_SYMLINK_NOFOLLOW) == -1, errno == ENOENT else { throw Failure.invalidPath }
    }
    static func save(_ data: Data, to path: String) throws {
        guard data.count <= 65536 else { throw Failure.invalidFile }
        let (directory, name) = try parent(path); defer { close(directory) }
        var info = stat()
        guard fstat(directory, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o022 == 0 else { throw Failure.invalidPath }
        let temporary = ".yk-receipt-" + UUID().uuidString
        let file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard file >= 0 else { throw Failure.io }
        defer { close(file); unlinkat(directory, temporary, 0) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw Failure.io }
                offset += count
            }
        }
        guard fsync(file) == 0 else { throw Failure.io }
        // linkat publishes atomically and fails if the destination already exists.
        guard linkat(directory, temporary, directory, name, 0) == 0 else { throw Failure.io }
        guard fsync(directory) == 0 else { throw Failure.io }
    }
    /// Keeps the reviewed destination directory open throughout authentication.
    final class Reservation {
        let path: String
        let directory: Int32
        let name: String
        let device: dev_t
        let inode: ino_t
        init(_ path: String) throws {
            try PublicReceiptFile.preflight(path)
            let (directory, name) = try PublicReceiptFile.parent(path)
            var info = stat()
            guard fstat(directory, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o022 == 0 else {
                close(directory); throw Failure.invalidPath
            }
            self.path = path; self.directory = directory; self.name = name
            device = info.st_dev; inode = info.st_ino
        }
        deinit { close(directory) }
        func commit(_ data: Data) throws {
            guard data.count > 0, data.count <= 65536 else { throw Failure.invalidFile }
            // Detect replacement of any path component before publication.
            let (current, currentName) = try PublicReceiptFile.parent(path)
            defer { close(current) }
            var info = stat()
            guard currentName == name, fstat(current, &info) == 0,
                  info.st_dev == device, info.st_ino == inode,
                  info.st_uid == getuid(), info.st_mode & 0o022 == 0 else { throw Failure.invalidPath }
            let temporary = ".yk-policy-" + UUID().uuidString
            let file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
            guard file >= 0 else { throw Failure.io }
            defer { close(file); unlinkat(directory, temporary, 0) }
            try data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = Darwin.write(file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw Failure.io }
                    offset += count
                }
            }
            guard fsync(file) == 0, linkat(directory, temporary, directory, name, 0) == 0 else { throw Failure.io }
            // The descriptor, not a newly resolved path, determines the commit resource.
            guard fsync(directory) == 0 else { throw Failure.io }
        }
    }
    static func read(_ path: String) throws -> Data {
        let (directory, name) = try parent(path); defer { close(directory) }
        let file = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw Failure.io }; defer { close(file) }
        var info = stat()
        guard fstat(file, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == getuid(), info.st_nlink == 1, info.st_mode & 0o077 == 0,
              info.st_size > 0, info.st_size <= 65536 else { throw Failure.invalidFile }
        var data = Data(count: Int(info.st_size))
        try data.withUnsafeMutableBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.read(file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw Failure.io }
                offset += count
            }
        }
        var after = stat()
        guard fstat(file, &after) == 0, after.st_size == info.st_size,
              after.st_mtimespec.tv_sec == info.st_mtimespec.tv_sec,
              after.st_mtimespec.tv_nsec == info.st_mtimespec.tv_nsec else { throw Failure.invalidFile }
        return data
    }
}
#endif

import Foundation
import Darwin

// VZ cannot create through an fd. Its only writable namespace is a freshly created
// 0700 directory whose dev/inode and fixed child name are journaled before VZ runs.
// Before ready is durable, that child is disposable operation output (including a
// partially created store after SIGKILL). Other names and unknown finals are never removed.
final class EFIPreparer {
    struct Intent: Codable {
        let version: Int; let instance: UUID; let namespace: String
        let inode: UInt64; let device: Int32; let child: String
    }
    struct Owner: Codable {
        let version: Int; let instance: UUID; let inode: UInt64; let device: Int32; let bytes: Int64
    }
    let directory: PrivateDirectory
    let instance: UUID
    let checkpoint: ((String) throws -> Void)?
    init(directory: PrivateDirectory, instance: UUID, checkpoint: ((String) throws -> Void)?) {
        self.directory = directory; self.instance = instance; self.checkpoint = checkpoint
    }
    func prepare(create: (URL) throws -> Void) throws -> URL {
        let final = directory.url.appendingPathComponent("efi-vars")
        var intent = try directory.read("efi-prepare.json", as: Intent.self)
        if let intent { try validate(intent) }
        if let owner = try directory.read("efi-owner.json", as: Owner.self) {
            guard owner.version == 1, owner.instance == instance, owner.bytes > 0 else { throw HostError.unsafeState }
            if let existing = try directory.info("efi-vars") {
                try validate(existing, owner)
                if let intent { try finish(intent, owner: owner) }
                return final
            }
            guard let intent, let temporary = try namespace(intent) else { throw HostError.unsafeState }
            try publish(intent, temporary: temporary, owner: owner)
            return final
        }
        guard try directory.info("efi-vars") == nil else { throw HostError.unsafeState }
        if intent == nil {
            let name = ".efi-\(UUID().uuidString)"
            guard mkdirat(directory.fd, name, 0o700) == 0 else { throw HostError.unsafeState }
            try directory.sync()
            let temporary = try PrivateDirectory(url: directory.url.appendingPathComponent(name), create: false)
            var s = stat(); guard fstat(temporary.fd, &s) == 0 else { throw HostError.unsafeState }
            intent = Intent(version: 1, instance: instance, namespace: name, inode: UInt64(s.st_ino), device: s.st_dev, child: "store")
            try directory.record("efi-prepare.json", intent!)
        }
        guard let intent, let temporary = try namespace(intent) else { throw HostError.unsafeState }
        // Only the fixed child in this durably registered, exclusive namespace can
        // be incomplete VZ output. We never attempt to repair an existing final.
        if let partial = try temporary.info(intent.child, requiredMode: nil) {
            guard partial.st_mode & 0o7000 == 0 else { throw HostError.unsafeState }
            guard unlinkat(temporary.fd, intent.child, 0) == 0 else { throw HostError.unsafeState }
            try temporary.sync()
        }
        try checkpoint?("efi-intent")
        _ = try namespace(intent) // Revalidate the path before calling the path-based API.
        try create(temporary.url.appendingPathComponent(intent.child))
        try checkpoint?("efi-created")
        guard let before = try temporary.info(intent.child, requiredMode: nil), before.st_size > 0 else { throw HostError.unsafeState }
        let fd = openat(temporary.fd, intent.child, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw HostError.unsafeState }; defer { close(fd) }
        var created = stat()
        guard fstat(fd, &created) == 0, created.st_dev == before.st_dev, created.st_ino == before.st_ino,
              created.st_mode & S_IFMT == S_IFREG, created.st_uid == getuid(), created.st_nlink == 1,
              fchmod(fd, 0o600) == 0, fsync(fd) == 0 else { throw HostError.unsafeState }
        try temporary.sync()
        let owner = Owner(version: 1, instance: instance, inode: UInt64(created.st_ino), device: created.st_dev, bytes: created.st_size)
        try directory.record("efi-owner.json", owner)
        try checkpoint?("efi-ready")
        try publish(intent, temporary: temporary, owner: owner)
        return final
    }
    private func validate(_ intent: Intent) throws {
        guard intent.version == 1, intent.instance == instance, intent.child == "store",
              intent.namespace.hasPrefix(".efi-"), UUID(uuidString: String(intent.namespace.dropFirst(5))) != nil,
              !intent.namespace.contains("/") else { throw HostError.unsafeState }
    }
    private func namespace(_ intent: Intent) throws -> PrivateDirectory? {
        var entry = stat()
        if fstatat(directory.fd, intent.namespace, &entry, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return nil }; throw HostError.unsafeState
        }
        guard entry.st_mode & S_IFMT == S_IFDIR, entry.st_mode & 0o7777 == 0o700,
              entry.st_uid == getuid(), UInt64(entry.st_ino) == intent.inode, entry.st_dev == intent.device else { throw HostError.unsafeState }
        let opened = try PrivateDirectory(url: directory.url.appendingPathComponent(intent.namespace), create: false)
        var pinned = stat()
        guard fstat(opened.fd, &pinned) == 0, pinned.st_ino == entry.st_ino, pinned.st_dev == entry.st_dev else { throw HostError.unsafeState }
        return opened
    }
    private func validate(_ s: stat, _ owner: Owner) throws {
        guard UInt64(s.st_ino) == owner.inode, s.st_dev == owner.device, s.st_size == owner.bytes else { throw HostError.unsafeState }
    }
    private func publish(_ intent: Intent, temporary: PrivateDirectory, owner: Owner) throws {
        guard try namespace(intent) != nil else { throw HostError.unsafeState }
        try checkpoint?("efi-before-publish-check")
        guard let before = try temporary.info(intent.child) else { throw HostError.unsafeState }
        try validate(before, owner)
        try checkpoint?("efi-before-rename")
        guard renameatx_np(temporary.fd, intent.child, directory.fd, "efi-vars", UInt32(RENAME_EXCL)) == 0 else { throw HostError.unsafeState }
        try temporary.sync(); try directory.sync()
        try checkpoint?("efi-published")
        try finish(intent, owner: owner)
    }
    private func finish(_ intent: Intent, owner: Owner) throws {
        guard let final = try directory.info("efi-vars") else { throw HostError.unsafeState }
        try validate(final, owner)
        if let temporary = try namespace(intent) {
            guard try temporary.info(intent.child, requiredMode: nil) == nil else { throw HostError.unsafeState }
            // rmdir refuses unexpected children; no recursive cleanup is permitted.
            guard unlinkat(directory.fd, intent.namespace, AT_REMOVEDIR) == 0 else { throw HostError.unsafeState }
            try directory.sync()
        }
        _ = try directory.info("efi-prepare.json")
        guard unlinkat(directory.fd, "efi-prepare.json", 0) == 0 else { throw HostError.unsafeState }
        try directory.sync()
    }
}

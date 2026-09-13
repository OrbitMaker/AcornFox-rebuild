import Foundation
import CryptoKit
import Darwin

enum HostError: LocalizedError {
    case unsafeState, missing(String), invalid(String), busy
    var errorDescription: String? {
        switch self {
        case .unsafeState: return "已有内容已保留，暂时不能继续。请重试。"
        case .missing: return "准备所需的内容不完整，请重试。"
        case .invalid: return "暂时没有完成，已有内容已保留。请重试。"
        case .busy: return "正在处理，请稍候再试。"
        }
    }
    static let retryMessage = "暂时没有完成，请重试。"
    static let notStoppedMessage = "还没有停止，已有内容已保留。请稍后再点“停止”。"
    static func userMessage(for error: Error) -> String {
        (error as? HostError)?.errorDescription ?? retryMessage
    }
    static func userMessage(forInternalMessage message: String) -> String {
        let stopFailures: Set<String> = [
            "本机服务暂时不能安全停止，仍在运行。请稍后重试。",
            "关机请求未被接受，本机服务仍在运行。请稍后重试。",
            "本机服务尚未完成关机，已继续保留运行状态。请稍后再试，勿直接结束进程。"
        ]
        if stopFailures.contains(message) { return notStoppedMessage }
        let safeMessages = [HostError.unsafeState, .missing(""), .invalid(""), .busy].compactMap(\.errorDescription)
        if safeMessages.contains(message) { return message }
        return retryMessage
    }
}
struct Resource: Codable { let path: String; let sha256: String; let size: UInt64 }
struct Manifest: Codable {
    let baseRawSHA256: String; let baseRawBytes: UInt64; let candidateBindingSHA256: String
    let files: [Resource]; let bootstrapHelperSHA256: String?
    init(baseRawSHA256: String, baseRawBytes: UInt64, candidateBindingSHA256: String, files: [Resource], bootstrapHelperSHA256: String? = nil) {
        self.baseRawSHA256 = baseRawSHA256; self.baseRawBytes = baseRawBytes; self.candidateBindingSHA256 = candidateBindingSHA256
        self.files = files; self.bootstrapHelperSHA256 = bootstrapHelperSHA256
    }
}

// All mutable paths are resolved relative to pinned, non-symlink directory handles.
final class PrivateDirectory {
    let fd: Int32
    let url: URL
    init(url: URL, create: Bool = true) throws {
        guard url.path.hasPrefix("/") else { throw HostError.unsafeState }
        var current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard current >= 0 else { throw HostError.unsafeState }
        defer { if current >= 0 { close(current) } }
        let parts = url.path.split(separator: "/").map(String.init)
        guard !parts.isEmpty else { throw HostError.unsafeState }
        for (index, part) in parts.enumerated() {
            guard part != ".", part != ".." else { throw HostError.unsafeState }
            let last = index == parts.count - 1
            if last && create && mkdirat(current, part, 0o700) != 0 && errno != EEXIST { throw HostError.unsafeState }
            let next = openat(current, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw HostError.unsafeState }
            var s = stat()
            guard fstat(next, &s) == 0, (s.st_uid == 0 || s.st_uid == getuid()),
                  (s.st_mode & 0o022 == 0 || (s.st_uid == 0 && s.st_mode & S_ISVTX != 0)),
                  !last || (s.st_uid == getuid() && s.st_mode & 0o7777 == 0o700) else { close(next); throw HostError.unsafeState }
            close(current); current = next
        }
        fd = current; current = -1; self.url = url
    }
    init(parent: PrivateDirectory, name: String, create: Bool = true) throws {
        guard !name.contains("/"), name != ".", name != ".." else { throw HostError.unsafeState }
        if create && mkdirat(parent.fd, name, 0o700) != 0 && errno != EEXIST { throw HostError.unsafeState }
        let next = openat(parent.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard next >= 0 else { throw HostError.unsafeState }
        var s = stat()
        guard fstat(next, &s) == 0, s.st_uid == getuid(), s.st_mode & 0o7777 == 0o700, s.st_mode & S_IFMT == S_IFDIR else {
            close(next); throw HostError.unsafeState
        }
        self.fd = next
        self.url = parent.url.appendingPathComponent(name, isDirectory: true)
    }
    deinit { close(fd) }
    func info(_ name: String, requiredMode: mode_t? = 0o600) throws -> stat? {
        guard !name.contains("/"), name != ".", name != ".." else { throw HostError.unsafeState }
        var s = stat()
        if fstatat(fd, name, &s, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return nil }; throw HostError.unsafeState
        }
        guard s.st_mode & S_IFMT == S_IFREG, s.st_uid == getuid(), (requiredMode == nil || s.st_mode & 0o7777 == requiredMode!), s.st_nlink == 1 else { throw HostError.unsafeState }
        return s
    }
    func openFile(_ name: String, flags: Int32 = O_RDONLY) throws -> Int32 {
        guard let before = try info(name) else { throw HostError.missing(name) }
        let file = openat(fd, name, flags | O_NOFOLLOW | O_CLOEXEC)
        var after = stat()
        guard file >= 0, fstat(file, &after) == 0, before.st_dev == after.st_dev, before.st_ino == after.st_ino else {
            if file >= 0 { close(file) }; throw HostError.unsafeState
        }
        return file
    }
    func create(_ name: String) throws -> Int32 {
        let file = openat(fd, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw HostError.unsafeState }; return file
    }
    func sync() throws { guard fsync(fd) == 0 else { throw HostError.unsafeState } }
    func read<T: Decodable>(_ name: String, as: T.Type) throws -> T? {
        guard try info(name) != nil else { return nil }
        let file = try openFile(name); let handle = FileHandle(fileDescriptor: file, closeOnDealloc: true)
        guard let data = try handle.read(upToCount: 65537), data.count <= 65536 else { throw HostError.unsafeState }
        do { return try JSONDecoder().decode(T.self, from: data) } catch { throw HostError.invalid(name) }
    }
    // Metadata publication is atomic and never overwrites an existing record.
    func record<T: Encodable>(_ name: String, _ value: T) throws {
        try writeNew(name, data: JSONEncoder().encode(value))
    }
    func writeNew(_ name: String, data: Data) throws {
        let temp = ".record-\(UUID().uuidString)"
        let file = try create(temp); defer { close(file) }
        try Self.write(data, to: file)
        guard fsync(file) == 0 else { throw HostError.unsafeState }
        guard renameatx_np(fd, temp, fd, name, UInt32(RENAME_EXCL)) == 0 else { throw HostError.unsafeState }
        try sync()
    }
    static func write(_ data: Data, to file: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw HostError.unsafeState }; offset += count
            }
        }
    }
}
final class PrivateState {
    let root: URL
    let directory: PrivateDirectory
    init(root: URL? = nil) throws {
        let base = root ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/AcornFox")
        directory = try PrivateDirectory(url: base); self.root = base
    }
    func child(_ name: String) throws -> URL {
        guard !name.contains("/"), name != ".", name != ".." else { throw HostError.unsafeState }
        let url = root.appendingPathComponent(name, isDirectory: true)
        _ = try PrivateDirectory(url: url); return url
    }
}

// Retain this object until the VM has stopped. Separate opens conflict even in one process.
final class InstanceLock {
    private let fd: Int32
    init(directory: PrivateDirectory) throws {
        if try directory.info("instance.lock") == nil {
            let created = openat(directory.fd, "instance.lock", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            if created >= 0 { close(created); try directory.sync() }
            else if errno != EEXIST { throw HostError.unsafeState }
        }
        let file = try directory.openFile("instance.lock", flags: O_RDWR)
        guard flock(file, LOCK_EX | LOCK_NB) == 0 else { close(file); throw HostError.busy }
        fd = file
    }
    deinit { flock(fd, LOCK_UN); close(fd) }
}

final class DiskPreparer {
    struct Instance: Codable { let version: Int; let id: UUID }
    struct Preparation: Codable { let version: Int; let instance: UUID; let temporary: String; let inode: UInt64; let device: Int32 }
    struct Owner: Codable { let version: Int; let instance: UUID; let inode: UInt64; let device: Int32; let virtualBytes: UInt64; let baseSHA256: String; let baseBytes: UInt64 }
    let state: PrivateState
    let vm: PrivateDirectory
    private let lock: InstanceLock
    private let instance: Instance
    var instanceID: UUID { instance.id }
    private let preparationLock = NSLock()
    // Test interruption points deliberately leave durable state, just like process termination.
    var checkpoint: ((String) throws -> Void)?

    private init(state: PrivateState, lock: InstanceLock, vm: PrivateDirectory) throws {
        self.state = state
        self.lock = lock
        self.vm = vm
        if let saved = try vm.read("instance.json", as: Instance.self) {
            guard saved.version == 1 else { throw HostError.unsafeState }; instance = saved
        } else {
            guard try vm.info("guest.raw") == nil, try vm.info("disk-owner.json") == nil, try vm.info("prepare.json") == nil,
                  try vm.info(InstalledReceiptStore.filename) == nil, try vm.info("machine-id") == nil, try vm.info("efi-owner.json") == nil else { throw HostError.unsafeState }
            instance = Instance(version: 1, id: UUID()); try vm.record("instance.json", instance)
        }
        for name in ["machine-id", "efi-vars"] { _ = try vm.info(name) }
    }

    convenience init(
        state: PrivateState,
        rootPreflight: ((PrivateDirectory) throws -> Void)? = nil,
        vmPreflight: ((PrivateDirectory, Bool) throws -> Void)? = nil
    ) throws {
        var pathStat = stat()
        guard lstat(state.root.path, &pathStat) == 0, pathStat.st_mode & S_IFMT == S_IFDIR else {
            throw HostError.unsafeState
        }
        var rootFDStat = stat()
        guard fstat(state.directory.fd, &rootFDStat) == 0,
              rootFDStat.st_dev == pathStat.st_dev, rootFDStat.st_ino == pathStat.st_ino else {
            throw HostError.unsafeState
        }

        let lock = try InstanceLock(directory: state.directory)
        try rootPreflight?(state.directory)

        var vmStat = stat()
        let vmExisted = fstatat(state.directory.fd, "vm", &vmStat, AT_SYMLINK_NOFOLLOW) == 0
        let vm = try PrivateDirectory(parent: state.directory, name: "vm", create: true)
        try vmPreflight?(vm, vmExisted)

        try self.init(state: state, lock: lock, vm: vm)
    }

    convenience init(state: PrivateState) throws {
        try self.init(state: state, rootPreflight: nil, vmPreflight: nil)
    }

    static func open(
        state: PrivateState,
        rootPreflight: ((PrivateDirectory) throws -> Void)? = nil,
        vmPreflight: ((PrivateDirectory, Bool) throws -> Void)? = nil
    ) throws -> DiskPreparer {
        try DiskPreparer(state: state, rootPreflight: rootPreflight, vmPreflight: vmPreflight)
    }
    func openExistingDisk() throws -> URL {
        guard let owner = try vm.read("disk-owner.json", as: Owner.self), owner.version == 1, owner.instance == instance.id,
              owner.baseBytes > 0, owner.virtualBytes >= owner.baseBytes, owner.virtualBytes <= UInt64(Int64.max), validHash(owner.baseSHA256),
              try vm.info("prepare.json") == nil, let disk = try vm.info("guest.raw") else { throw HostError.unsafeState }
        try validate(disk, owner: owner)
        return vm.url.appendingPathComponent("guest.raw")
    }
    func prepare(gzip: URL, manifest: Manifest, virtualBytes: UInt64 = 40 * 1024 * 1024 * 1024) throws -> URL {
        guard preparationLock.try() else { throw HostError.busy }
        defer { preparationLock.unlock() }
        let final = vm.url.appendingPathComponent("guest.raw")
        let journal = try vm.read("prepare.json", as: Preparation.self)
        let owner = try vm.read("disk-owner.json", as: Owner.self)
        if let owner {
            guard owner.version == 1, owner.instance == instance.id, owner.baseBytes > 0,
                  owner.virtualBytes >= owner.baseBytes, owner.virtualBytes <= UInt64(Int64.max), validHash(owner.baseSHA256) else { throw HostError.unsafeState }
            if let disk = try vm.info("guest.raw") {
                try validate(disk, owner: owner)
                if let journal { try validate(journal); guard journal.inode == owner.inode, journal.device == owner.device, try vm.info(journal.temporary) == nil else { throw HostError.unsafeState }; try removeJournal() }
                return final // User modifications are preserved; never compare a registered disk with base hash.
            }
            guard let journal else { throw HostError.unsafeState }
            try validate(journal)
            guard let temp = try vm.info(journal.temporary) else { throw HostError.unsafeState }
            try validate(temp, owner: owner)
            guard journal.inode == owner.inode, journal.device == owner.device else { throw HostError.unsafeState }
            try publish(journal, owner: owner); return final
        }
        guard try vm.info("guest.raw") == nil else { throw HostError.unsafeState }
        if let journal {
            try validate(journal)
            if let temp = try vm.info(journal.temporary) {
                guard UInt64(temp.st_ino) == journal.inode, temp.st_dev == journal.device else { throw HostError.unsafeState }
                guard unlinkat(vm.fd, journal.temporary, 0) == 0 else { throw HostError.unsafeState }
                try vm.sync()
            }
            try removeJournal()
        }
        guard manifest.baseRawBytes > 0, manifest.baseRawBytes <= virtualBytes, virtualBytes <= UInt64(Int64.max),
              validHash(manifest.baseRawSHA256),
              let resource = manifest.files.first(where: { $0.path == "base.raw.gz" }), validHash(resource.sha256) else { throw HostError.invalid("base manifest") }
        let input = Darwin.open(gzip.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard input >= 0 else { throw HostError.missing("base.raw.gz") }; defer { close(input) }
        var inputStat = stat()
        guard fstat(input, &inputStat) == 0, inputStat.st_mode & S_IFMT == S_IFREG, inputStat.st_nlink == 1,
              inputStat.st_size >= 0, UInt64(inputStat.st_size) == resource.size else { throw HostError.invalid("base.raw.gz") }
        let source = FileHandle(fileDescriptor: input, closeOnDealloc: false)
        var compressedHash = SHA256()
        while let data = try source.read(upToCount: 1 << 20), !data.isEmpty { compressedHash.update(data: data) }
        guard hex(compressedHash) == resource.sha256, lseek(input, 0, SEEK_SET) == 0 else { throw HostError.invalid("base.raw.gz") }
        let name = ".prepare-\(UUID().uuidString).raw"
        let file = try vm.create(name); defer { close(file) }
        var tempStat = stat(); guard fstat(file, &tempStat) == 0 else { throw HostError.unsafeState }
        let preparation = Preparation(version: 1, instance: instance.id, temporary: name, inode: UInt64(tempStat.st_ino), device: tempStat.st_dev)
        try vm.record("prepare.json", preparation)
        try checkpoint?("journal")
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/gzip"); process.arguments = ["-dc"]
        let output = Pipe(); process.standardInput = source; process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run()
        defer { try? output.fileHandleForReading.close(); if process.isRunning { process.terminate(); process.waitUntilExit() } }
        var hash = SHA256(); var bytes: UInt64 = 0
        while let data = try output.fileHandleForReading.read(upToCount: 1 << 20), !data.isEmpty {
            guard UInt64(data.count) <= manifest.baseRawBytes - bytes else { throw HostError.invalid("base.raw length") }
            bytes += UInt64(data.count); hash.update(data: data); try PrivateDirectory.write(data, to: file)
        }
        process.waitUntilExit()
        guard process.terminationStatus == 0, bytes == manifest.baseRawBytes, hex(hash) == manifest.baseRawSHA256 else { throw HostError.invalid("base.raw") }
        guard ftruncate(file, off_t(virtualBytes)) == 0, fsync(file) == 0 else { throw HostError.unsafeState }
        let record = Owner(version: 1, instance: instance.id, inode: preparation.inode, device: preparation.device, virtualBytes: virtualBytes, baseSHA256: manifest.baseRawSHA256, baseBytes: manifest.baseRawBytes)
        try vm.record("disk-owner.json", record)
        try checkpoint?("owner")
        try publish(preparation, owner: record)
        return final
    }
    func prepareEFI(create: (URL) throws -> Void) throws -> URL {
        guard preparationLock.try() else { throw HostError.busy }
        defer { preparationLock.unlock() }
        return try EFIPreparer(directory: vm, instance: instance.id, checkpoint: checkpoint).prepare(create: create)
    }
    func prepareSeed(resources: URL, manifest: Manifest) throws -> PreparedSeed {
        guard preparationLock.try() else { throw HostError.busy }
        defer { preparationLock.unlock() }
        return try SeedPreparer(vm: vm, instance: instance.id).prepare(resources: resources, manifest: manifest)
    }
    private func validHash(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
    private func hex(_ hash: SHA256) -> String { hash.finalize().map { String(format: "%02x", $0) }.joined() }
    private func validate(_ s: stat, owner: Owner) throws {
        guard UInt64(s.st_ino) == owner.inode, s.st_dev == owner.device, s.st_size >= 0, UInt64(s.st_size) == owner.virtualBytes else { throw HostError.unsafeState }
    }
    private func validate(_ journal: Preparation) throws {
        guard journal.version == 1, journal.instance == instance.id,
              journal.temporary.range(of: "^\\.prepare-[0-9A-Fa-f-]{36}\\.raw$", options: .regularExpression) != nil,
              UUID(uuidString: String(journal.temporary.dropFirst(9).dropLast(4))) != nil else { throw HostError.unsafeState }
    }
    private func publish(_ journal: Preparation, owner: Owner) throws {
        try validate(journal)
        guard journal.inode == owner.inode, journal.device == owner.device else { throw HostError.unsafeState }
        try checkpoint?("before-publish-check")
        guard let before = try vm.info(journal.temporary) else { throw HostError.unsafeState }
        try validate(before, owner: owner)
        try checkpoint?("before-rename")
        guard renameatx_np(vm.fd, journal.temporary, vm.fd, "guest.raw", UInt32(RENAME_EXCL)) == 0 else { throw HostError.unsafeState }
        try vm.sync(); try checkpoint?("published")
        guard let after = try vm.info("guest.raw") else { throw HostError.unsafeState }
        try validate(after, owner: owner)
        try removeJournal()
    }
    private func removeJournal() throws {
        _ = try vm.info("prepare.json")
        guard unlinkat(vm.fd, "prepare.json", 0) == 0 else { throw HostError.unsafeState }; try vm.sync()
    }
}

import Foundation
import CryptoKit
import Darwin

// Read-only facts from the fixed root verifier; setup readiness is probed separately.
struct CurrentBackendEvidence: Codable, Equatable {
    let schema: Int
    let instance: UUID
    let instanceProtocol: Int
    let binding: String
    let helperSHA256: String
    let release: String
    let sourceCommit: String
    let finalEvidenceSHA256: String
    func validate(instance expected: UUID, binding expectedBinding: String, instanceProtocol expectedProtocol: Int) throws {
        guard schema == 1, instance == expected, instanceProtocol == 1, instanceProtocol == expectedProtocol,
              binding == expectedBinding, InstallationRecord.isSHA(binding), InstallationRecord.isSHA(helperSHA256),
              InstallationRecord.isSHA(finalEvidenceSHA256), sourceCommit.range(of: "^[0-9a-f]{40}$", options: .regularExpression) != nil,
              release.range(of: "^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$", options: .regularExpression) != nil else { throw HostError.unsafeState }
    }
}
struct InstallationRecord: Codable {
    let schema: Int
    let instance: UUID
    let instanceProtocol: Int
    let bootstrapManifestSHA256: String
    let bootstrapBinding: String
    let bootstrapHelperSHA256: String
    let phase: String
    let evidence: CurrentBackendEvidence?
    let readyState: String?
    let seedReceiptSHA256: String?
    let identityFiles: [String: String]?
    static func isSHA(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
}

// Future Go bridge implementations must authenticate the controller snapshot
// before returning. There is deliberately no production implementation, JSON
// decoder, CLI flag or permissive default for update authority in this package.
protocol InstalledContextAuthority: AnyObject {
    // The future bridge must consult a live opaque HostStartupBasis (or its
    // authenticated IPC equivalent), verify its instance/protocol and slot seal,
    // and reject a closed lease. It must never return cached JSON fields.
    func authenticatedBinding(instance: UUID, initialBinding: String, instanceProtocol: Int) throws -> String
    func close()
}
struct InstalledInstanceContext {
    let instance: UUID
    let instanceProtocol: Int
    let expectedBackendBinding: String
    fileprivate let receiptSHA256: String
    fileprivate let authority: InstalledContextAuthority?
    fileprivate init(instance: UUID, instanceProtocol: Int, expectedBackendBinding: String, receiptSHA256: String, authority: InstalledContextAuthority?) {
        self.instance = instance; self.instanceProtocol = instanceProtocol
        self.expectedBackendBinding = expectedBackendBinding; self.receiptSHA256 = receiptSHA256; self.authority = authority
    }
    func closeAuthority() { authority?.close() }
}

// One host installation record; it is not a host-update state machine. The
// preparing record exists before disk creation, and only real ready evidence
// can atomically replace it with the initial ready receipt. It is never rebased
// to a newer backend binding by this store.
final class InstalledReceiptStore {
    static let filename = "host-installation.json"
    let directory: PrivateDirectory
    let instance: UUID
    var checkpoint: ((String) throws -> Void)?
    init(directory: PrivateDirectory, instance: UUID) { self.directory = directory; self.instance = instance }
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private func bytes(_ name: String, in location: PrivateDirectory? = nil) throws -> Data {
        let location = location ?? directory
        let handle = FileHandle(fileDescriptor: try location.openFile(name), closeOnDealloc: true)
        guard let data = try handle.read(upToCount: 65537), data.count <= 65536 else { throw HostError.unsafeState }
        return data
    }
    private func verifyInstance() throws {
        guard let saved = try directory.read("instance.json", as: DiskPreparer.Instance.self), saved.version == 1, saved.id == instance else { throw HostError.unsafeState }
    }
    func load() throws -> InstallationRecord? {
        try verifyInstance()
        guard let record = try directory.read(Self.filename, as: InstallationRecord.self) else { return nil }
        guard record.schema == 1, record.instance == instance, record.instanceProtocol == 1,
              InstallationRecord.isSHA(record.bootstrapManifestSHA256), InstallationRecord.isSHA(record.bootstrapBinding),
              InstallationRecord.isSHA(record.bootstrapHelperSHA256) else { throw HostError.unsafeState }
        switch record.phase {
        case "preparing":
            guard record.evidence == nil, record.readyState == nil, record.seedReceiptSHA256 == nil, record.identityFiles == nil else { throw HostError.unsafeState }
        case "ready":
            guard let evidence = record.evidence, let seed = record.seedReceiptSHA256, InstallationRecord.isSHA(seed),
                  record.readyState == "initialized" || record.readyState == "uninitialized", let identities = record.identityFiles,
                  Set(identities.keys) == Set(["disk-owner.json", "machine-id", "efi-owner.json", "ssh-known-hosts"]),
                  identities.values.allSatisfy(InstallationRecord.isSHA) else { throw HostError.unsafeState }
            try evidence.validate(instance: instance, binding: record.bootstrapBinding, instanceProtocol: record.instanceProtocol)
            guard evidence.helperSHA256 == record.bootstrapHelperSHA256 else { throw HostError.unsafeState }
        default: throw HostError.unsafeState
        }
        return record
    }
    static func manifestFingerprint(_ manifest: Manifest) throws -> String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return Self.hash(try encoder.encode(manifest))
    }
    func authorizeBootstrap(manifest: Manifest) throws {
        try Resources.validateManifest(manifest)
        let digest = try Self.manifestFingerprint(manifest)
        if let saved = try load() {
            guard saved.phase == "preparing", saved.bootstrapManifestSHA256 == digest,
                  saved.bootstrapBinding == manifest.candidateBindingSHA256, saved.bootstrapHelperSHA256 == manifest.bootstrapHelperSHA256 else { throw HostError.unsafeState }
            return
        }
        // A missing receipt on a pre-existing disk/seed is never a fresh install.
        for name in ["guest.raw", "disk-owner.json", "prepare.json", "machine-id", "efi-vars", "efi-owner.json"] {
            guard try directory.info(name) == nil else { throw HostError.unsafeState }
        }
        var seed = stat()
        guard fstatat(directory.fd, "seed", &seed, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else { throw HostError.unsafeState }
        let record = InstallationRecord(schema: 1, instance: instance, instanceProtocol: 1, bootstrapManifestSHA256: digest,
            bootstrapBinding: manifest.candidateBindingSHA256, bootstrapHelperSHA256: manifest.bootstrapHelperSHA256!, phase: "preparing",
            evidence: nil, readyState: nil, seedReceiptSHA256: nil, identityFiles: nil)
        try directory.record(Self.filename, record)
        try checkpoint?("preparing-written")
    }
    func requireBootstrap(manifest: Manifest) throws -> InstallationRecord {
        guard let record = try load(), record.phase == "preparing", record.bootstrapManifestSHA256 == (try Self.manifestFingerprint(manifest)),
              record.bootstrapBinding == manifest.candidateBindingSHA256, record.bootstrapHelperSHA256 == manifest.bootstrapHelperSHA256 else { throw HostError.unsafeState }
        return record
    }
    private func identityHashes() throws -> [String: String] {
        var values: [String: String] = [:]
        for name in ["disk-owner.json", "machine-id", "efi-owner.json", "ssh-known-hosts"] { values[name] = Self.hash(try bytes(name)) }
        guard try directory.info("prepare.json") == nil, try directory.info("efi-prepare.json") == nil,
              let owner = try directory.read("disk-owner.json", as: DiskPreparer.Owner.self), owner.version == 1, owner.instance == instance,
              let disk = try directory.info("guest.raw"), UInt64(disk.st_ino) == owner.inode, disk.st_dev == owner.device,
              disk.st_size > 0, UInt64(disk.st_size) == owner.virtualBytes,
              let efi = try directory.read("efi-owner.json", as: EFIPreparer.Owner.self), efi.version == 1, efi.instance == instance,
              let variableStore = try directory.info("efi-vars"), UInt64(variableStore.st_ino) == efi.inode,
              variableStore.st_dev == efi.device, variableStore.st_size == efi.bytes else { throw HostError.unsafeState }
        return values
    }
    func completeBootstrap(manifest: Manifest, evidence: CurrentBackendEvidence, readyState: String) throws {
        if let complete = try load(), complete.phase == "ready" {
            guard complete.bootstrapManifestSHA256 == (try Self.manifestFingerprint(manifest)), complete.bootstrapBinding == manifest.candidateBindingSHA256,
                  complete.bootstrapHelperSHA256 == manifest.bootstrapHelperSHA256, evidence.helperSHA256 == complete.bootstrapHelperSHA256,
                  readyState == "initialized" || readyState == "uninitialized" else { throw HostError.unsafeState }
            try evidence.validate(instance: instance, binding: complete.bootstrapBinding, instanceProtocol: complete.instanceProtocol)
            _ = try openSavedSeed(record: complete)
            return // Lost caller acknowledgement reuses the same immutable receipt.
        }
        let before = try requireBootstrap(manifest: manifest)
        try evidence.validate(instance: instance, binding: before.bootstrapBinding, instanceProtocol: before.instanceProtocol)
        guard evidence.helperSHA256 == before.bootstrapHelperSHA256, readyState == "initialized" || readyState == "uninitialized" else { throw HostError.unsafeState }
        let seed = try SeedPreparer(vm: directory, instance: instance).openExisting(instanceProtocol: before.instanceProtocol, bootstrapManifestSHA256: before.bootstrapManifestSHA256)
        guard let seedSHA = seed.receiptSHA256 else { throw HostError.unsafeState }
        let identities = try identityHashes()
        let old = try bytes(Self.filename)
        let next = InstallationRecord(schema: 1, instance: instance, instanceProtocol: before.instanceProtocol,
            bootstrapManifestSHA256: before.bootstrapManifestSHA256, bootstrapBinding: before.bootstrapBinding,
            bootstrapHelperSHA256: before.bootstrapHelperSHA256, phase: "ready", evidence: evidence, readyState: readyState,
            seedReceiptSHA256: seedSHA, identityFiles: identities)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(next), temporary = ".installation-\(UUID().uuidString)"
        let fd = try directory.create(temporary); defer { close(fd) }
        try PrivateDirectory.write(data, to: fd)
        guard fsync(fd) == 0 else { throw HostError.unsafeState }
        try checkpoint?("ready-temp-synced")
        guard try bytes(Self.filename) == old else { throw HostError.unsafeState }
        // Only the exact known preparing record is replaced; the instance lock
        // serializes host writes. Both sides of this transition are valid states.
        guard renameat(directory.fd, temporary, directory.fd, Self.filename) == 0 else { throw HostError.unsafeState }
        try checkpoint?("ready-published")
        try directory.sync()
        guard try bytes(Self.filename) == data else { throw HostError.unsafeState }
    }
    func context(authority: InstalledContextAuthority? = nil) throws -> InstalledInstanceContext {
        guard let record = try load(), record.phase == "ready" else { throw HostError.unsafeState }
        _ = try openSavedSeed(record: record)
        let expected = try authority?.authenticatedBinding(instance: instance, initialBinding: record.bootstrapBinding, instanceProtocol: record.instanceProtocol) ?? record.bootstrapBinding
        guard InstallationRecord.isSHA(expected) else { throw HostError.unsafeState }
        return InstalledInstanceContext(instance: instance, instanceProtocol: record.instanceProtocol,
            expectedBackendBinding: expected, receiptSHA256: Self.hash(try bytes(Self.filename)), authority: authority)
    }
    func validate(_ context: InstalledInstanceContext) throws -> PreparedSeed {
        guard context.instance == instance, context.instanceProtocol == 1, InstallationRecord.isSHA(context.expectedBackendBinding),
              Self.hash(try bytes(Self.filename)) == context.receiptSHA256, let record = try load(), record.phase == "ready" else { throw HostError.unsafeState }
        if let authority = context.authority {
            guard try authority.authenticatedBinding(instance: instance, initialBinding: record.bootstrapBinding, instanceProtocol: record.instanceProtocol) == context.expectedBackendBinding else { throw HostError.unsafeState }
        } else if context.expectedBackendBinding != record.bootstrapBinding { throw HostError.unsafeState }
        return try openSavedSeed(record: record)
    }
    private func openSavedSeed(record: InstallationRecord) throws -> PreparedSeed {
        guard try identityHashes() == record.identityFiles else { throw HostError.unsafeState }
        return try SeedPreparer(vm: directory, instance: instance).openExisting(expectedReceiptSHA256: record.seedReceiptSHA256, instanceProtocol: record.instanceProtocol, bootstrapManifestSHA256: record.bootstrapManifestSHA256)
    }
}

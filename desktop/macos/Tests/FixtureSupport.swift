import Foundation
import CryptoKit
import Virtualization

// Real local file transactions, gzip, keys and ISO. Candidate/backend content
// is synthetic; no test starts a VM or claims an actual installation.
final class MacBootstrapFixture {
    let root: URL
    let resources: Resources
    let preparer: DiskPreparer
    let store: InstalledReceiptStore
    init(root: URL) throws {
        self.root = root
        _ = try PrivateDirectory(url: root)
        let resourceDirectory = try PrivateDirectory(url: root.appendingPathComponent("resources"))
        let candidateDirectory = try PrivateDirectory(url: resourceDirectory.url.appendingPathComponent("candidate"))
        let raw = Data("fixture base blocks".utf8)
        let gzip = try SeedPreparer.run("/usr/bin/gzip", ["-n", "-c"], input: raw)
        var elf = Data(repeating: 0, count: 128); elf.replaceSubrange(0..<6, with: [0x7f,0x45,0x4c,0x46,2,1]); elf[18] = 0xb7
        var assets = ["base.raw.gz": gzip, "acornfox-guest-bridge": elf]
        for name in ["candidate.tar.gz", "candidate-binding.json", "candidate-binding.sha256", "bundle-manifest.sha256", "build-record.json", "release-manifest.json"] {
            assets["candidate/" + name] = Data("fixture \(name)".utf8)
        }
        for (name, data) in assets {
            if name.hasPrefix("candidate/") { try candidateDirectory.writeNew(String(name.dropFirst(10)), data: data) }
            else { try resourceDirectory.writeNew(name, data: data) }
        }
        let files = assets.keys.sorted().map { Resource(path: $0, sha256: InstalledReceiptStore.hash(assets[$0]!), size: UInt64(assets[$0]!.count)) }
        let manifest = Manifest(baseRawSHA256: InstalledReceiptStore.hash(raw), baseRawBytes: UInt64(raw.count),
            candidateBindingSHA256: InstalledReceiptStore.hash(assets["candidate/candidate-binding.json"]!), files: files, bootstrapHelperSHA256: String(repeating: "d", count: 64))
        try resourceDirectory.writeNew("resource-manifest.json", data: JSONEncoder().encode(manifest))
        resources = try Resources(root: resourceDirectory.url); try resources.verify()
        preparer = try DiskPreparer(state: PrivateState(root: root.appendingPathComponent("state")))
        store = InstalledReceiptStore(directory: preparer.vm, instance: preparer.instanceID)
        try store.authorizeBootstrap(manifest: manifest)
    }
    func prepareLocalFiles() throws -> PreparedSeed {
        _ = try preparer.prepare(gzip: resources.root.appendingPathComponent("base.raw.gz"), manifest: resources.manifest, virtualBytes: 1024 * 1024)
        let seed = try preparer.prepareSeed(resources: resources.root, manifest: resources.manifest)
        if try preparer.vm.info("machine-id") == nil { try preparer.vm.writeNew("machine-id", data: VZGenericMachineIdentifier().dataRepresentation) }
        _ = try preparer.prepareEFI { _ = try VZEFIVariableStore(creatingVariableStoreAt: $0, options: []) }
        if try preparer.vm.info("ssh-known-hosts") == nil { try preparer.vm.writeNew("ssh-known-hosts", data: Data("fixture-known-host".utf8)) }
        return seed
    }
    func evidence(binding: String? = nil, helperSHA256: String? = nil) -> CurrentBackendEvidence {
        CurrentBackendEvidence(schema: 1, instance: preparer.instanceID, instanceProtocol: 1,
            binding: binding ?? resources.manifest.candidateBindingSHA256, helperSHA256: helperSHA256 ?? resources.manifest.bootstrapHelperSHA256!,
            release: "release-0.1.0-test.1", sourceCommit: String(repeating: "1", count: 40), finalEvidenceSHA256: String(repeating: "e", count: 64))
    }
    func complete() throws -> PreparedSeed {
        let seed = try prepareLocalFiles()
        try store.completeBootstrap(manifest: resources.manifest, evidence: evidence(), readyState: "uninitialized")
        return seed
    }
}

import Foundation
import CryptoKit
import Darwin

@main struct InstalledInstanceTests {
    static func require(_ value: @autoclosure () throws -> Bool, _ label: String) throws { if try !value() { throw NSError(domain: label, code: 1) } }
    static func reject(_ operation: () throws -> Void) throws { var failed = false; do { try operation() } catch { failed = true }; try require(failed, "expected refusal") }
    final class FixtureAuthority: InstalledContextAuthority {
        let instance: UUID, initial: String, next: String
        var closed = false
        init(instance: UUID, initial: String, next: String) { self.instance = instance; self.initial = initial; self.next = next }
        func authenticatedBinding(instance: UUID, initialBinding: String, instanceProtocol: Int) throws -> String {
            guard !closed, instance == self.instance, initialBinding == initial, instanceProtocol == 1 else { throw HostError.unsafeState }; return next
        }
        func close() { closed = true }
    }
    static func main() throws {
        if CommandLine.arguments.count == 4 && CommandLine.arguments[1] == "interrupt-receipt" {
            let fixture = try MacBootstrapFixture(root: URL(fileURLWithPath: CommandLine.arguments[2]))
            _ = try fixture.prepareLocalFiles()
            fixture.store.checkpoint = { if $0 == CommandLine.arguments[3] { kill(getpid(), SIGKILL) } }
            try fixture.store.completeBootstrap(manifest: fixture.resources.manifest, evidence: fixture.evidence(), readyState: "uninitialized")
            exit(3)
        }
        let root = URL(fileURLWithPath: "/private/tmp/acornfox-existing-tests-\(UUID().uuidString)")
        _ = try PrivateDirectory(url: root); defer { try? FileManager.default.removeItem(at: root) }
        let fixture = try MacBootstrapFixture(root: root.appendingPathComponent("valid"))
        try require(try fixture.store.load()?.phase == "preparing", "intent precedes disk effects")
        try require(try fixture.preparer.vm.info("guest.raw") == nil, "no disk before preparing record")
        try reject { _ = try fixture.store.context() }
        let seed = try fixture.prepareLocalFiles()
        let bootstrapSeed = SeedPreparer(vm: fixture.preparer.vm, instance: fixture.preparer.instanceID)
        _ = try bootstrapSeed.openExisting(instanceProtocol: 1, bootstrapManifestSHA256: InstalledReceiptStore.manifestFingerprint(fixture.resources.manifest))
        try reject { _ = try bootstrapSeed.openExisting(instanceProtocol: 1, bootstrapManifestSHA256: String(repeating: "0", count: 64)) }
        try reject { try fixture.store.completeBootstrap(manifest: fixture.resources.manifest, evidence: fixture.evidence(), readyState: "not-ready") }
        try require(try fixture.store.load()?.phase == "preparing", "failed readiness cannot create completion receipt")
        try fixture.store.completeBootstrap(manifest: fixture.resources.manifest, evidence: fixture.evidence(), readyState: "uninitialized")
        let receiptPath = fixture.preparer.vm.url.appendingPathComponent(InstalledReceiptStore.filename)
        let originalReceipt = try Data(contentsOf: receiptPath)
        let oldContext = try fixture.store.context()
        let originalSeed = try Data(contentsOf: seed.isoURL)
        let originalKey = try Data(contentsOf: seed.privateKeyURL)
        let disk = try FileHandle(forUpdating: fixture.preparer.vm.url.appendingPathComponent("guest.raw"))
        try disk.write(contentsOf: Data("USER-DATA".utf8)); try disk.synchronize(); try disk.close()
        // Remove the current App's entire resources. Existing-instance opening
        // must use persisted identity/files, not an App template or base image.
        try FileManager.default.removeItem(at: fixture.resources.root)
        _ = try fixture.preparer.openExistingDisk()
        _ = try fixture.store.validate(oldContext)
        var commands: [[String]] = []
        let ready = try Provisioner.verifyInstalled(context: oldContext, store: fixture.store, execute: { arguments in
            commands.append(arguments); return try JSONEncoder().encode(fixture.evidence())
        }, probe: { "initialized" })
        try require(ready == "initialized" && commands == [["verify-current"]], "normal existing path never calls install/upload/recover")
        try require(try Data(contentsOf: receiptPath) == originalReceipt, "bootstrap receipt immutable")
        try require(try Data(contentsOf: seed.isoURL) == originalSeed && Data(contentsOf: seed.privateKeyURL) == originalKey, "seed and key unchanged without App resources")
        let checkDisk = try FileHandle(forReadingFrom: fixture.preparer.vm.url.appendingPathComponent("guest.raw"))
        try require(try checkDisk.read(upToCount: 9) == Data("USER-DATA".utf8), "user disk writes retained"); try checkDisk.close()
        print("PASS preparing precedes effects; ready evidence required; existing open ignores current App resources and preserves files")

        let nextBinding = String(repeating: "b", count: 64)
        try reject {
            _ = try Provisioner.verifyInstalled(context: oldContext, store: fixture.store, execute: { _ in try JSONEncoder().encode(fixture.evidence(binding: nextBinding, helperSHA256: String(repeating: "f", count: 64))) }, probe: { "initialized" })
        }
        let authority = FixtureAuthority(instance: fixture.preparer.instanceID, initial: fixture.resources.manifest.candidateBindingSHA256, next: nextBinding)
        let updatedContext = try fixture.store.context(authority: authority)
        commands.removeAll()
        _ = try Provisioner.verifyInstalled(context: updatedContext, store: fixture.store, execute: { args in
            commands.append(args); return try JSONEncoder().encode(fixture.evidence(binding: nextBinding, helperSHA256: String(repeating: "f", count: 64)))
        }, probe: { "initialized" })
        try require(commands == [["verify-current"]] && Data(contentsOf: receiptPath) == originalReceipt, "trusted new binding accepted without bootstrap rebase")
        authority.close()
        try reject { _ = try fixture.store.validate(updatedContext) }
        let shortLease = FixtureAuthority(instance: fixture.preparer.instanceID, initial: fixture.resources.manifest.candidateBindingSHA256, next: nextBinding)
        let shortContext = try fixture.store.context(authority: shortLease)
        try reject { _ = try Provisioner.verifyInstalled(context: shortContext, store: fixture.store, execute: { _ in try JSONEncoder().encode(fixture.evidence(binding: nextBinding, helperSHA256: String(repeating: "f", count: 64))) }, probe: { shortLease.close(); return "initialized" }) }
        print("PASS authenticated new binding supports old host; no authority/closed lease refuses; bootstrap facts remain fixed")

        try FileManager.default.removeItem(at: receiptPath)
        try reject { _ = try fixture.store.context() }
        try reject { try fixture.store.authorizeBootstrap(manifest: fixture.resources.manifest) }
        try require(try Data(contentsOf: seed.isoURL) == originalSeed, "missing receipt does not recreate existing seed")
        try fixture.preparer.vm.writeNew(InstalledReceiptStore.filename, data: Data("broken".utf8))
        try reject { _ = try fixture.store.context() }
        try reject { try fixture.store.authorizeBootstrap(manifest: fixture.resources.manifest) }
        try require(try Data(contentsOf: receiptPath) == Data("broken".utf8), "corrupt receipt retained")
        print("PASS missing/corrupt ready receipt cannot fall back to installation")

        let legacy = try MacBootstrapFixture(root: root.appendingPathComponent("legacy"))
        let legacySeed = try legacy.complete()
        let seedOwner = legacySeed.isoURL.deletingLastPathComponent().appendingPathComponent("seed-owner.json")
        let original = try Data(contentsOf: seedOwner)
        var object = try JSONSerialization.jsonObject(with: original) as! [String: Any]
        object.removeValue(forKey: "instanceProtocol"); object["version"] = 1
        let handle = try FileHandle(forWritingTo: seedOwner); try handle.truncate(atOffset: 0); try handle.write(contentsOf: JSONSerialization.data(withJSONObject: object)); try handle.close()
        try reject { _ = try legacy.store.context() }
        try require(try Data(contentsOf: seedOwner) != original, "unsupported old seed was not silently rewritten")
        print("PASS unsupported pre-release seed protocol refused without migration")
        for stage in ["ready-temp-synced", "ready-published"] {
            let target = root.appendingPathComponent("crash-" + stage)
            let child = Process(); child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0]); child.arguments = ["interrupt-receipt", target.path, stage]
            try child.run(); child.waitUntilExit()
            try require(child.terminationReason == .uncaughtSignal && child.terminationStatus == SIGKILL, "receipt writer was interrupted")
            let resources = try Resources(root: target.appendingPathComponent("resources")); try resources.verify()
            let reopened = try DiskPreparer(state: PrivateState(root: target.appendingPathComponent("state")))
            let store = InstalledReceiptStore(directory: reopened.vm, instance: reopened.instanceID)
            let evidence = CurrentBackendEvidence(schema: 1, instance: reopened.instanceID, instanceProtocol: 1, binding: resources.manifest.candidateBindingSHA256,
                helperSHA256: resources.manifest.bootstrapHelperSHA256!, release: "release-0.1.0-test.1", sourceCommit: String(repeating: "1", count: 40), finalEvidenceSHA256: String(repeating: "e", count: 64))
            if stage == "ready-temp-synced" { try require(try store.load()?.phase == "preparing", "unpublished receipt preserves authorized preparation"); try store.authorizeBootstrap(manifest: resources.manifest) }
            else { try require(try store.load()?.phase == "ready", "published receipt remains complete") }
            try store.completeBootstrap(manifest: resources.manifest, evidence: evidence, readyState: "uninitialized")
            _ = try store.context()
        }
        print("PASS real SIGKILL before/after ready publication preserves a valid receipt state and retries exactly")
        print("ALL INSTALLED INSTANCE TESTS PASSED")
    }
}

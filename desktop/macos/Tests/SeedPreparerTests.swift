import Foundation
import CryptoKit
import Darwin

@main struct SeedPreparerTests {
    static func require(_ value: @autoclosure () throws -> Bool, _ label: String) throws { if try !value() { throw NSError(domain: label, code: 1) } }
    static func rejects(_ work: () throws -> Void) throws { var failed = false; do { try work() } catch { failed = true }; try require(failed, "expected rejection") }
    static func main() throws {
        let base = URL(fileURLWithPath: "/private/tmp/acornfox-seed-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]); defer { try? FileManager.default.removeItem(at: base) }
        let resourceRoot = base.appendingPathComponent("resources"); try FileManager.default.createDirectory(at: resourceRoot, withIntermediateDirectories: false)
        var elf = Data(repeating: 0, count: 1024); elf.replaceSubrange(0..<6, with: [0x7f, 0x45, 0x4c, 0x46, 2, 1]); elf[18] = 0xb7
        let bridgeURL = resourceRoot.appendingPathComponent("acornfox-guest-bridge"); try elf.write(to: bridgeURL)
        let hash = SHA256.hash(data: elf).map { String(format: "%02x", $0) }.joined()
        let resource = Resource(path: "acornfox-guest-bridge", sha256: hash, size: UInt64(elf.count))
        let candidate = ["candidate.tar.gz", "candidate-binding.json", "candidate-binding.sha256", "bundle-manifest.sha256", "build-record.json", "release-manifest.json"].map { Resource(path: "candidate/" + $0, sha256: hash, size: 1) }
        let manifest = Manifest(baseRawSHA256: String(repeating: "a", count: 64), baseRawBytes: 1024, candidateBindingSHA256: String(repeating: "b", count: 64), files: [resource] + candidate, bootstrapHelperSHA256: hash)
        let disk = try DiskPreparer(state: PrivateState(root: base.appendingPathComponent("state")))
        let seed = try disk.prepareSeed(resources: resourceRoot, manifest: manifest)
        let before = try FileManager.default.attributesOfItem(atPath: seed.privateKeyURL.path)
        try require((before[.posixPermissions] as? NSNumber)?.intValue == 0o600, "private mode")
        let seedAgain = try disk.prepareSeed(resources: resourceRoot, manifest: manifest)
        let after = try FileManager.default.attributesOfItem(atPath: seedAgain.privateKeyURL.path)
        try require(before[.systemFileNumber] as? NSNumber == after[.systemFileNumber] as? NSNumber, "key not regenerated")
        let list = try SeedPreparer.run("/usr/bin/tar", ["-tf", seed.isoURL.path])
        let listing = String(decoding: list, as: UTF8.self)
        try require(!listing.contains("ssh-key"), "ISO contains no private file")
        let userdata = try SeedPreparer.run("/usr/bin/tar", ["-xOf", seed.isoURL.path, "./user-data"])
        let text = String(decoding: userdata, as: UTF8.self)
        try require(text.contains("name: af-host") && text.contains(seed.publicKey) && text.contains("encoding: gz+b64") && text.contains("com.acornfox.guest-bridge.service") && !text.contains("acornfox-guest-bridge.service") && !text.contains("NOPASSWD:ALL") && text.contains("NOPASSWD: /usr/local/sbin/acornfox-desktop-control"), "seed configuration")
        try require(!text.contains("PRIVATE KEY") && !text.contains("ssh-key"), "no private bytes in user data")
        try require(text.contains("manage_etc_hosts: localhost"), "cloud-init localhost mode for 127.0.1.1 mapping")
        try require(!text.contains("manage_etc_hosts: true"), "manage_etc_hosts true forbidden to avoid rewriting full hosts file")
        let meta = try SeedPreparer.run("/usr/bin/tar", ["-xOf", seed.isoURL.path, "./meta-data"])
        let metaText = String(decoding: meta, as: UTF8.self)
        try require(metaText.contains(seed.instanceID.uuidString.lowercased()), "persistent ID")
        try require(metaText.contains("local-hostname: acornfox"), "authoritative local-hostname acornfox in meta-data")
        print("PASS real ssh-keygen and hdiutil seed; reentry preserves identity; ISO contains only public startup data")
        let legacy = try DiskPreparer(state: PrivateState(root: base.appendingPathComponent("legacy-state")))
        let legacySeed = try legacy.prepareSeed(resources: resourceRoot, manifest: manifest)
        let config = try SeedPreparer.controlConfig(instance: legacySeed.instanceID, manifest: manifest)
        let oldTemplate = SeedPreparer.userData(publicKey: "seed-public-key", bridge: Data(), config: config, instance: legacySeed.instanceID)
            .replacingOccurrences(of: "com.acornfox.guest-bridge.service", with: "acornfox-guest-bridge.service")
        let oldInputHash = SHA256.hash(data: config + Data(oldTemplate.utf8)).map { String(format: "%02x", $0) }.joined()
        let receiptURL = legacySeed.isoURL.deletingLastPathComponent().appendingPathComponent("seed-owner.json")
        var receipt = try JSONSerialization.jsonObject(with: Data(contentsOf: receiptURL)) as! [String: Any]
        receipt["configurationSHA256"] = oldInputHash
        let oldReceipt = try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys])
        let receiptHandle = try FileHandle(forWritingTo: receiptURL)
        try receiptHandle.truncate(atOffset: 0); try receiptHandle.write(contentsOf: oldReceipt); try receiptHandle.close()
        let originalISO = try Data(contentsOf: legacySeed.isoURL)
        let originalKey = try Data(contentsOf: legacySeed.privateKeyURL)
        try rejects { _ = try legacy.prepareSeed(resources: resourceRoot, manifest: manifest) }
        try require(try Data(contentsOf: legacySeed.isoURL) == originalISO, "old input ISO retained")
        try require(try Data(contentsOf: legacySeed.privateKeyURL) == originalKey, "old input identity retained")
        try require(try Data(contentsOf: receiptURL) == oldReceipt, "old input receipt not rewritten")
        print("PASS old unit namespace is a different seed input; existing ISO/key/receipt are not rewritten")
        let wrong = Manifest(baseRawSHA256: String(repeating: "c", count: 64), baseRawBytes: 1024, candidateBindingSHA256: manifest.candidateBindingSHA256, files: [resource] + candidate, bootstrapHelperSHA256: hash)
        try rejects { _ = try disk.prepareSeed(resources: resourceRoot, manifest: wrong) }
        let duplicate = Manifest(baseRawSHA256: manifest.baseRawSHA256, baseRawBytes: 1024, candidateBindingSHA256: manifest.candidateBindingSHA256, files: [resource, resource] + candidate, bootstrapHelperSHA256: hash)
        try rejects { _ = try disk.prepareSeed(resources: resourceRoot, manifest: duplicate) }
        try Data("corrupt".utf8).write(to: bridgeURL)
        try rejects { _ = try disk.prepareSeed(resources: resourceRoot, manifest: manifest) }
        try elf.write(to: bridgeURL)
        print("PASS changed base and invalid bridge resources rejected")
        let pub = seed.privateKeyURL.appendingPathExtension("pub")
        let handle = try FileHandle(forWritingTo: pub); try handle.truncate(atOffset: 0); try handle.write(contentsOf: Data("broken".utf8)); try handle.close()
        try rejects { _ = try disk.prepareSeed(resources: resourceRoot, manifest: manifest) }
        try require(try Data(contentsOf: pub) == Data("broken".utf8), "corrupt key never overwritten")
        print("PASS corrupt existing key retained")
        print("ALL SEED TESTS PASSED")
    }
}

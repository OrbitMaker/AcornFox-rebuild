import Foundation
import CryptoKit
import Darwin

@main struct NativeInstanceProvisionerTests {
    static func require(_ value: @autoclosure () throws -> Bool, _ label: String) throws {
        if try !value() { throw NSError(domain: label, code: 1) }
    }

    static func reject(_ operation: () throws -> Void) throws {
        var failed = false
        do { try operation() } catch { failed = true }
        try require(failed, "expected refusal")
    }

    static func createSecureDirectory(at url: URL) throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        guard chmod(url.path, 0o700) == 0 else { throw HostError.unsafeState }
    }

    static func writeSecureFile(data: Data, to url: URL, mode: mode_t = 0o600) throws {
        try data.write(to: url)
        guard chmod(url.path, mode) == 0 else { throw HostError.unsafeState }
    }

    struct FileSnapshot: Equatable {
        let relativePath: String
        let size: UInt64
        let sha256: String
    }

    static func takeSnapshot(at root: URL) throws -> [FileSnapshot] {
        guard FileManager.default.fileExists(atPath: root.path) else { return [] }
        let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey], options: [])
        var results: [FileSnapshot] = []
        while let fileURL = enumerator?.nextObject() as? URL {
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: fileURL.path, isDirectory: &isDir), !isDir.boolValue {
                let relative = fileURL.path.replacingOccurrences(of: root.path + "/", with: "")
                let data = try Data(contentsOf: fileURL)
                let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
                results.append(FileSnapshot(relativePath: relative, size: UInt64(data.count), sha256: hash))
            }
        }
        return results.sorted(by: { $0.relativePath < $1.relativePath })
    }

    static func main() throws {
        let tempBase = URL(fileURLWithPath: "/private/tmp/acornfox-native-identity-tests-\(UUID().uuidString)")
        try createSecureDirectory(at: tempBase)
        defer { try? FileManager.default.removeItem(at: tempBase) }

        // Test 1: Deterministic UUID mapping and uppercase normalization
        do {
            let lowerUUIDStr = "e621e1f8-c36c-495a-93fc-0c247a3e6e5f"
            let upperUUIDStr = "E621E1F8-C36C-495A-93FC-0C247A3E6E5F"
            let mixedUUIDStr = "e621E1f8-C36c-495A-93fc-0C247a3e6E5f"

            guard let uuid = UUID(uuidString: lowerUUIDStr) else {
                throw NSError(domain: "invalid test uuid", code: 1)
            }

            let expectedInput = "mac-managed:" + lowerUUIDStr
            let expectedDigest = SHA256.hash(data: Data(expectedInput.utf8)).map { String(format: "%02x", $0) }.joined()

            let shaFromUUID = NativeInstanceProvisioner.deriveCoreInstanceID(from: uuid)
            let shaFromLower = try NativeInstanceProvisioner.deriveCoreInstanceID(from: lowerUUIDStr)
            let shaFromUpper = try NativeInstanceProvisioner.deriveCoreInstanceID(from: upperUUIDStr)
            let shaFromMixed = try NativeInstanceProvisioner.deriveCoreInstanceID(from: mixedUUIDStr)

            try require(shaFromUUID == expectedDigest, "shaFromUUID matches expected digest")
            try require(shaFromLower == expectedDigest, "shaFromLower matches expected digest")
            try require(shaFromUpper == expectedDigest, "shaFromUpper matches expected digest")
            try require(shaFromMixed == expectedDigest, "shaFromMixed matches expected digest")

            try require(try NativeInstanceProvisioner.normalizeUUID(upperUUIDStr) == lowerUUIDStr, "normalizeUUID lowercases uppercase")
            try require(try NativeInstanceProvisioner.normalizeUUID(mixedUUIDStr) == lowerUUIDStr, "normalizeUUID lowercases mixed")

            // Rejection of invalid UUID strings
            for invalid in ["", "not-a-uuid", "e621e1f8-c36c-495a-93fc", "e621e1f8-c36c-495a-93fc-0c247a3e6e5g", "e621e1f8c36c495a93fc0c247a3e6e5f"] {
                try reject { _ = try NativeInstanceProvisioner.deriveCoreInstanceID(from: invalid) }
                try reject { _ = try NativeInstanceProvisioner.normalizeUUID(invalid) }
            }

            // Receipt validation
            let receipt = NativeInstanceReceipt(nativeUUID: uuid, coreInstanceSHA256: expectedDigest)
            try require(receipt.nativeUUIDString == lowerUUIDStr, "receipt nativeUUIDString is lowercased")
            let encoded = try JSONEncoder().encode(receipt)
            let decoded = try JSONDecoder().decode(NativeInstanceReceipt.self, from: encoded)
            try require(decoded == receipt, "receipt decodes identically")

            // Corrupted SHA in receipt fails decoding
            let badJSON = try JSONSerialization.data(withJSONObject: [
                "nativeUUID": lowerUUIDStr,
                "coreInstanceSHA256": String(repeating: "0", count: 64)
            ])
            try reject { _ = try JSONDecoder().decode(NativeInstanceReceipt.self, from: badJSON) }

            // Unknown / extra keys fail decoding (strict schema)
            let extraKeysJSON = try JSONSerialization.data(withJSONObject: [
                "nativeUUID": lowerUUIDStr,
                "coreInstanceSHA256": expectedDigest,
                "unknown": true
            ])
            try reject { _ = try JSONDecoder().decode(NativeInstanceReceipt.self, from: extraKeysJSON) }

            // Legacy/alias snake_case keys fail decoding (strict schema)
            let aliasJSON = try JSONSerialization.data(withJSONObject: [
                "native_uuid": lowerUUIDStr,
                "core_instance_sha256": expectedDigest
            ])
            try reject { _ = try JSONDecoder().decode(NativeInstanceReceipt.self, from: aliasJSON) }

            print("PASS deterministic UUID mapping and supplied uppercase UUID normalization")
        }

        // Test 2: Same-instance reentry with no disk creation
        do {
            let root = tempBase.appendingPathComponent("clean-identity")
            let receipt1 = try prepareOrOpenNativeInstance(root: root)
            try require(receipt1.coreInstanceSHA256 == NativeInstanceProvisioner.deriveCoreInstanceID(from: receipt1.nativeUUID), "receipt1 sha256 matches")

            let vmDir = root.appendingPathComponent("vm")
            try require(FileManager.default.fileExists(atPath: vmDir.appendingPathComponent("instance.json").path), "instance.json created")
            try require(!FileManager.default.fileExists(atPath: vmDir.appendingPathComponent("guest.raw").path), "no disk allocated")
            try require(!FileManager.default.fileExists(atPath: vmDir.appendingPathComponent("seed").path), "no seed allocated")
            try require(!FileManager.default.fileExists(atPath: vmDir.appendingPathComponent("machine-id").path), "no machine-id allocated")
            try require(!FileManager.default.fileExists(atPath: vmDir.appendingPathComponent("efi-vars").path), "no efi-vars allocated")

            // Reentry
            let receipt2 = try prepareOrOpenNativeInstance(root: root)
            try require(receipt1 == receipt2, "reentry returns identical receipt")
            try require(receipt1.nativeUUID == receipt2.nativeUUID, "reentry returns identical UUID")
            try require(receipt1.coreInstanceSHA256 == receipt2.coreInstanceSHA256, "reentry returns identical SHA256")

            try require(!FileManager.default.fileExists(atPath: vmDir.appendingPathComponent("guest.raw").path), "still no disk allocated after reentry")
            try require(!FileManager.default.fileExists(atPath: vmDir.appendingPathComponent("seed").path), "still no seed allocated after reentry")

            print("PASS same-instance reentry with no disk creation")
        }

        // Test 3: Valid ready installation with both diagnostic logs unchanged
        do {
            let fixtureRoot = tempBase.appendingPathComponent("ready-with-diagnostics")
            let instanceID: UUID
            do {
                let fixture = try MacBootstrapFixture(root: fixtureRoot)
                _ = try fixture.complete()
                instanceID = fixture.preparer.instanceID
            } // fixture deallocated here, releasing its lock

            let stateRoot = fixtureRoot.appendingPathComponent("state")
            let vmDir = stateRoot.appendingPathComponent("vm")

            // Write both bounded diagnostic log files (mode 0600)
            let entryDiag = vmDir.appendingPathComponent("entry-diagnostics.log")
            let vsockDiag = vmDir.appendingPathComponent("vsock-diagnostics.log")
            let entryBytes = Data("entry diagnostics sample line 1\nline 2\n".utf8)
            let vsockBytes = Data("vsock diagnostics connection established port 8080\n".utf8)
            try writeSecureFile(data: entryBytes, to: entryDiag)
            try writeSecureFile(data: vsockBytes, to: vsockDiag)

            let receipt = try prepareOrOpenNativeInstance(root: stateRoot)
            try require(receipt.nativeUUID == instanceID, "reopens same UUID with diagnostic logs")
            try require(try Data(contentsOf: entryDiag) == entryBytes, "entry-diagnostics.log unchanged")
            try require(try Data(contentsOf: vsockDiag) == vsockBytes, "vsock-diagnostics.log unchanged")

            print("PASS valid ready with both diagnostic logs unchanged")
        }

        // Test 4: Malformed / schema / foreign unknown inventory refusal with before/after snapshots
        do {
            // 4a: Foreign unknown file in vm directory (secure 0700 dir, 0600 file)
            let root4a = tempBase.appendingPathComponent("foreign-vm")
            try createSecureDirectory(at: root4a)
            let vmDir4a = root4a.appendingPathComponent("vm")
            try createSecureDirectory(at: vmDir4a)
            let foreignFile4a = vmDir4a.appendingPathComponent("unknown-inventory.bin")
            try writeSecureFile(data: Data("foreign-bytes".utf8), to: foreignFile4a)

            let before4a = try takeSnapshot(at: root4a)
            try reject { _ = try prepareOrOpenNativeInstance(root: root4a) }
            let after4a = try takeSnapshot(at: root4a)
            try require(before4a == after4a, "foreign vm inventory refused without deletion/repair")
            try require(!FileManager.default.fileExists(atPath: vmDir4a.appendingPathComponent("instance.json").path), "no instance.json written on foreign inventory")

            // 4b: Foreign unknown file in state root (secure 0700 dir, 0600 file)
            let root4b = tempBase.appendingPathComponent("foreign-root")
            try createSecureDirectory(at: root4b)
            let foreignFile4b = root4b.appendingPathComponent("stray-file.txt")
            try writeSecureFile(data: Data("stray".utf8), to: foreignFile4b)

            let before4b = try takeSnapshot(at: root4b)
            try reject { _ = try prepareOrOpenNativeInstance(root: root4b) }
            let after4b = try takeSnapshot(at: root4b)
            try require(before4b == after4b, "foreign root inventory refused without deletion/repair")

            // 4c: Malformed instance.json schema refusal (version 2)
            let root4c = tempBase.appendingPathComponent("malformed-instance")
            try createSecureDirectory(at: root4c)
            let vmDir4c = root4c.appendingPathComponent("vm")
            try createSecureDirectory(at: vmDir4c)
            let instFile4c = vmDir4c.appendingPathComponent("instance.json")
            try writeSecureFile(data: Data("{\"version\": 2, \"id\": \"00000000-0000-0000-0000-000000000001\"}".utf8), to: instFile4c)

            let before4c = try takeSnapshot(at: root4c)
            try reject { _ = try prepareOrOpenNativeInstance(root: root4c) }
            let after4c = try takeSnapshot(at: root4c)
            try require(before4c == after4c, "malformed version 2 instance.json refused without repair")

            // 4d: Corrupted (not JSON) instance.json
            try writeSecureFile(data: Data("corrupted-not-json".utf8), to: instFile4c)
            let before4d = try takeSnapshot(at: root4c)
            try reject { _ = try prepareOrOpenNativeInstance(root: root4c) }
            let after4d = try takeSnapshot(at: root4c)
            try require(before4d == after4d, "corrupted instance.json refused without overwrite")

            // 4e: Extra keys in instance.json
            let extraKeyData = Data("{\"version\": 1, \"id\": \"00000000-0000-0000-0000-000000000001\", \"extra\": true}".utf8)
            try writeSecureFile(data: extraKeyData, to: instFile4c)
            let before4e = try takeSnapshot(at: root4c)
            try reject { _ = try prepareOrOpenNativeInstance(root: root4c) }
            let after4e = try takeSnapshot(at: root4c)
            try require(before4e == after4e, "extra keys in instance.json refused without overwrite")

            // 4f: Duplicate keys in instance.json
            let dupKeyData = Data("{\"version\": 1, \"version\": 1, \"id\": \"00000000-0000-0000-0000-000000000001\"}".utf8)
            try writeSecureFile(data: dupKeyData, to: instFile4c)
            let before4f = try takeSnapshot(at: root4c)
            try reject { _ = try prepareOrOpenNativeInstance(root: root4c) }
            let after4f = try takeSnapshot(at: root4c)
            try require(before4f == after4f, "duplicate keys in instance.json refused without overwrite")

            // 4g: Torn preparation file in vm directory
            let root4g = tempBase.appendingPathComponent("torn-vm")
            try createSecureDirectory(at: root4g)
            let vmDir4g = root4g.appendingPathComponent("vm")
            try createSecureDirectory(at: vmDir4g)
            let tornFile = vmDir4g.appendingPathComponent(".prepare-junk.raw")
            try writeSecureFile(data: Data("torn".utf8), to: tornFile)

            let before4g = try takeSnapshot(at: root4g)
            try reject { _ = try prepareOrOpenNativeInstance(root: root4g) }
            let after4g = try takeSnapshot(at: root4g)
            try require(before4g == after4g, "torn file refused without repair/deletion")

            // 4h: Non-empty vm without instance.json (e.g. orphan guest.raw)
            let root4h = tempBase.appendingPathComponent("orphan-guest")
            try createSecureDirectory(at: root4h)
            let vmDir4h = root4h.appendingPathComponent("vm")
            try createSecureDirectory(at: vmDir4h)
            let orphanGuest = vmDir4h.appendingPathComponent("guest.raw")
            try writeSecureFile(data: Data("orphan-raw".utf8), to: orphanGuest)

            let before4h = try takeSnapshot(at: root4h)
            try reject { _ = try prepareOrOpenNativeInstance(root: root4h) }
            let after4h = try takeSnapshot(at: root4h)
            try require(before4h == after4h, "orphan guest disk without instance.json refused without overwriting")

            // 4i: Directory in place of a known file (e.g. directory named guest.raw)
            let root4i = tempBase.appendingPathComponent("dir-in-place-of-file")
            try createSecureDirectory(at: root4i)
            let vmDir4i = root4i.appendingPathComponent("vm")
            try createSecureDirectory(at: vmDir4i)
            let validInst = vmDir4i.appendingPathComponent("instance.json")
            try writeSecureFile(data: Data("{\"version\": 1, \"id\": \"00000000-0000-0000-0000-000000000001\"}".utf8), to: validInst)
            let fakeGuestDir = vmDir4i.appendingPathComponent("guest.raw")
            try createSecureDirectory(at: fakeGuestDir)

            let before4i = try takeSnapshot(at: root4i)
            try reject { _ = try prepareOrOpenNativeInstance(root: root4i) }
            let after4i = try takeSnapshot(at: root4i)
            try require(before4i == after4i, "directory in place of file refused without mutation")

            // 4j: Hardlink on known file (nlink > 1)
            let root4j = tempBase.appendingPathComponent("hardlink-known-file")
            try createSecureDirectory(at: root4j)
            let vmDir4j = root4j.appendingPathComponent("vm")
            try createSecureDirectory(at: vmDir4j)
            let instFile4j = vmDir4j.appendingPathComponent("instance.json")
            try writeSecureFile(data: Data("{\"version\": 1, \"id\": \"00000000-0000-0000-0000-000000000001\"}".utf8), to: instFile4j)
            let hardlinkTarget = root4j.appendingPathComponent("hardlink-copy")
            try FileManager.default.linkItem(at: instFile4j, to: hardlinkTarget)

            let before4j = try takeSnapshot(at: root4j)
            try reject { _ = try prepareOrOpenNativeInstance(root: root4j) }
            let after4j = try takeSnapshot(at: root4j)
            try require(before4j == after4j, "hardlinked instance.json refused without mutation")

            // 4k: Wrong mode on known file (0644 instead of 0600)
            let root4k = tempBase.appendingPathComponent("wrong-mode-file")
            try createSecureDirectory(at: root4k)
            let vmDir4k = root4k.appendingPathComponent("vm")
            try createSecureDirectory(at: vmDir4k)
            let instFile4k = vmDir4k.appendingPathComponent("instance.json")
            try writeSecureFile(data: Data("{\"version\": 1, \"id\": \"00000000-0000-0000-0000-000000000001\"}".utf8), to: instFile4k, mode: 0o644)

            let before4k = try takeSnapshot(at: root4k)
            try reject { _ = try prepareOrOpenNativeInstance(root: root4k) }
            let after4k = try takeSnapshot(at: root4k)
            try require(before4k == after4k, "wrong-mode instance.json refused without mutation")

            print("PASS malformed/schema/foreign unknown inventory refusal with before/after snapshots")
        }

        // Test 5: Deterministic precheck-to-locked replacement
        do {
            let root5 = tempBase.appendingPathComponent("replacement-race")
            try createSecureDirectory(at: root5)
            let state = try PrivateState(root: root5)

            // Simulate inode replacement between state opening and preflight lock
            let otherRoot = tempBase.appendingPathComponent("replacement-other")
            try createSecureDirectory(at: otherRoot)
            try FileManager.default.removeItem(at: root5)
            try FileManager.default.moveItem(at: otherRoot, to: root5)

            // Calling open on the old PrivateState whose pinned FD inode no longer matches root5 path
            try reject {
                _ = try DiskPreparer.open(
                    state: state,
                    rootPreflight: NativeInstanceProvisioner.rootPreflight,
                    vmPreflight: NativeInstanceProvisioner.vmPreflight
                )
            }

            print("PASS deterministic precheck-to-locked replacement refused")
        }

        // Test 6: Lock conflict
        do {
            let root = tempBase.appendingPathComponent("lock-conflict")
            let state = try PrivateState(root: root)
            do {
                let lockHandle = try InstanceLock(directory: state.directory)
                try reject { _ = try prepareOrOpenNativeInstance(state: state) }
                _ = lockHandle
            } // lockHandle is deallocated here and releases flock

            // Now calling after lock is released:
            let receipt = try prepareOrOpenNativeInstance(root: root)
            try require(receipt.coreInstanceSHA256 == NativeInstanceProvisioner.deriveCoreInstanceID(from: receipt.nativeUUID), "lock released allows identity")

            print("PASS lock conflict refused with HostError.busy; released lock succeeds")
        }

        print("ALL NATIVE INSTANCE PROVISIONER TESTS PASSED")
    }
}

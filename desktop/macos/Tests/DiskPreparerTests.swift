import Foundation
import CryptoKit
import Darwin

@main struct DiskPreparerTests {
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func require(_ value: @autoclosure () throws -> Bool, _ message: String) throws {
        if try !value() { throw NSError(domain: message, code: 1) }
    }
    static func rejects(_ body: () throws -> Void) throws {
        var failed = false; do { try body() } catch { failed = true }; try require(failed, "expected rejection")
    }
    static func main() throws {
        if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "lock-probe" {
            do { _ = try DiskPreparer(state: PrivateState(root: URL(fileURLWithPath: CommandLine.arguments[2]))); exit(2) }
            catch HostError.busy { exit(0) }
            catch { exit(3) }
        }
        if CommandLine.arguments.count == 6 && CommandLine.arguments[1] == "interrupt-probe" {
            let disk = try DiskPreparer(state: PrivateState(root: URL(fileURLWithPath: CommandLine.arguments[2])))
            let manifest = try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[4])))
            disk.checkpoint = { if $0 == CommandLine.arguments[5] { kill(getpid(), SIGKILL) } }
            _ = try disk.prepare(gzip: URL(fileURLWithPath: CommandLine.arguments[3]), manifest: manifest, virtualBytes: 1024 * 1024)
            exit(4)
        }
        let base = URL(fileURLWithPath: "/private/tmp/acornfox-disk-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: base) }
        let raw = Data((0..<32768).map { UInt8($0 % 251) })
        let rawURL = base.appendingPathComponent("base.raw"); try raw.write(to: rawURL)
        let gzip = base.appendingPathComponent("base.raw.gz")
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/gzip"); p.arguments = ["-c", rawURL.path]
        FileManager.default.createFile(atPath: gzip.path, contents: nil)
        let output = try FileHandle(forWritingTo: gzip); p.standardOutput = output; try p.run(); p.waitUntilExit(); try output.close()
        try require(p.terminationStatus == 0, "gzip fixture")
        let compressed = try Data(contentsOf: gzip)
        let manifest = Manifest(baseRawSHA256: hash(raw), baseRawBytes: UInt64(raw.count), candidateBindingSHA256: String(repeating: "a", count: 64), files: [Resource(path: "base.raw.gz", sha256: hash(compressed), size: UInt64(compressed.count))])
        func preparer(_ name: String) throws -> DiskPreparer { try DiskPreparer(state: PrivateState(root: base.appendingPathComponent(name))) }
        func run(_ name: String, _ body: () throws -> Void) throws { try body(); print("PASS \(name)") }
        try run("stream hash and sparse 40 GiB; reentry preserves user bytes") {
            let disk = try preparer("happy")
            let file = try disk.prepare(gzip: gzip, manifest: manifest)
            let s = try disk.vm.info("guest.raw")!
            try require(s.st_size == 40 * 1024 * 1024 * 1024, "40 GiB")
            try require(s.st_blocks * 512 < 1024 * 1024, "sparse allocation")
            let handle = try FileHandle(forUpdating: file); defer { try? handle.close() }
            try require(try handle.read(upToCount: raw.count) == raw, "raw payload")
            try handle.seek(toOffset: 0); try handle.write(contentsOf: Data("USER".utf8)); try handle.synchronize()
            _ = try disk.prepare(gzip: URL(fileURLWithPath: "/absent"), manifest: manifest)
            try handle.seek(toOffset: 0); try require(try handle.read(upToCount: 4) == Data("USER".utf8), "user changes")
        }
        try run("bad raw hash and length never publish") {
            for (name, digest, size) in [("hash", String(repeating: "0", count: 64), UInt64(raw.count)), ("size", hash(raw), UInt64(raw.count - 1)), ("short", hash(raw), UInt64(raw.count + 1))] {
                let disk = try preparer(name)
                let wrong = Manifest(baseRawSHA256: digest, baseRawBytes: size, candidateBindingSHA256: manifest.candidateBindingSHA256, files: manifest.files)
                try rejects { _ = try disk.prepare(gzip: gzip, manifest: wrong) }
                try require(try disk.vm.info("guest.raw") == nil, "no final")
                _ = try disk.prepare(gzip: gzip, manifest: manifest, virtualBytes: 1024 * 1024)
            }
        }
        try run("bad compressed hash never publishes") {
            let disk = try preparer("compressed")
            let wrong = Manifest(baseRawSHA256: hash(raw), baseRawBytes: UInt64(raw.count), candidateBindingSHA256: manifest.candidateBindingSHA256, files: [Resource(path: "base.raw.gz", sha256: String(repeating: "0", count: 64), size: UInt64(compressed.count))])
            try rejects { _ = try disk.prepare(gzip: gzip, manifest: wrong) }; try require(try disk.vm.info("guest.raw") == nil, "no final")
        }
        try run("unknown disk never overwritten") {
            let disk = try preparer("unknown"); let file = try disk.vm.create("guest.raw"); try PrivateDirectory.write(Data("KEEP".utf8), to: file); close(file)
            try rejects { _ = try disk.prepare(gzip: gzip, manifest: manifest) }
            try require(try Data(contentsOf: disk.vm.url.appendingPathComponent("guest.raw")) == Data("KEEP".utf8), "unknown retained")
        }
        try run("same process and cross process lifetime lock") {
            let disk = try preparer("locked")
            try rejects { _ = try DiskPreparer(state: disk.state) }
            let child = Process(); child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0]); child.arguments = ["lock-probe", disk.state.root.path]
            try child.run(); child.waitUntilExit(); try require(child.terminationStatus == 0, "child lock busy")
        }
        try run("journal owner and publication interruption recovery; foreign temp retained") {
            for stage in ["journal", "owner", "published"] {
                let disk = try preparer(stage)
                let foreign = try disk.vm.create(".prepare-FOREIGN.raw"); try PrivateDirectory.write(Data("FOREIGN".utf8), to: foreign); close(foreign)
                disk.checkpoint = { if $0 == stage { throw HostError.busy } }
                try rejects { _ = try disk.prepare(gzip: gzip, manifest: manifest, virtualBytes: 1024 * 1024) }
                disk.checkpoint = nil
                _ = try disk.prepare(gzip: gzip, manifest: manifest, virtualBytes: 1024 * 1024)
                try require(try disk.vm.info("prepare.json") == nil, "journal retired")
                try require(try Data(contentsOf: disk.vm.url.appendingPathComponent(".prepare-FOREIGN.raw")) == Data("FOREIGN".utf8), "foreign retained")
            }
        }
        try run("SIGKILL process interruption releases lock and recovers all phases") {
            let manifestURL = base.appendingPathComponent("manifest.json")
            try JSONEncoder().encode(manifest).write(to: manifestURL)
            for stage in ["journal", "owner", "published"] {
                let root = base.appendingPathComponent("killed-" + stage)
                let child = Process(); child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
                child.arguments = ["interrupt-probe", root.path, gzip.path, manifestURL.path, stage]
                try child.run(); child.waitUntilExit()
                try require(child.terminationReason == .uncaughtSignal && child.terminationStatus == SIGKILL, "child was killed")
                let disk = try DiskPreparer(state: PrivateState(root: root))
                _ = try disk.prepare(gzip: gzip, manifest: manifest, virtualBytes: 1024 * 1024)
                try require(try disk.vm.info("prepare.json") == nil, "recovered process journal")
            }
        }
        try run("new handle retains persistent owner and user modifications") {
            let disk = try preparer("happy")
            _ = try disk.prepare(gzip: URL(fileURLWithPath: "/absent"), manifest: manifest)
            let handle = FileHandle(fileDescriptor: try disk.vm.openFile("guest.raw"), closeOnDealloc: true)
            try require(try handle.read(upToCount: 4) == Data("USER".utf8), "persistent user bytes")
        }
        try run("disk replacement before check and around rename is rejected and retained") {
            for stage in ["before-publish-check", "before-rename", "published"] {
                let disk = try preparer("replacement-" + stage)
                disk.checkpoint = { point in
                    if point == stage {
                        let journal = try disk.vm.read("prepare.json", as: DiskPreparer.Preparation.self)!
                        let name = stage == "published" ? "guest.raw" : journal.temporary
                        let source = disk.vm.url.appendingPathComponent(name)
                        try FileManager.default.moveItem(at: source, to: source.appendingPathExtension("saved"))
                        let fd = try disk.vm.create(name); try PrivateDirectory.write(Data("FOREIGN".utf8), to: fd); close(fd)
                    }
                }
                try rejects { _ = try disk.prepare(gzip: gzip, manifest: manifest, virtualBytes: 1024 * 1024) }
                let journal = try disk.vm.read("prepare.json", as: DiskPreparer.Preparation.self)!
                let name = stage == "before-publish-check" ? journal.temporary : "guest.raw"
                try require(try Data(contentsOf: disk.vm.url.appendingPathComponent(name)) == Data("FOREIGN".utf8), "foreign retained")
            }
        }
        try run("symlink parent and target rejected") {
            let link = base.appendingPathComponent("linked"); try FileManager.default.createSymbolicLink(at: link, withDestinationURL: base)
            try rejects { _ = try PrivateState(root: link.appendingPathComponent("child")) }
            let disk = try preparer("symlink")
            try FileManager.default.createSymbolicLink(at: disk.vm.url.appendingPathComponent("guest.raw"), withDestinationURL: rawURL)
            try rejects { _ = try disk.prepare(gzip: gzip, manifest: manifest) }; try require(try Data(contentsOf: rawURL) == raw, "target retained")
        }
        try run("hardlink mode and corrupt owner rejected") {
            let disk = try preparer("corrupt")
            _ = try disk.prepare(gzip: gzip, manifest: manifest, virtualBytes: 1024 * 1024)
            let file = disk.vm.url.appendingPathComponent("guest.raw")
            let other = base.appendingPathComponent("hardlink"); try FileManager.default.linkItem(at: file, to: other)
            try rejects { _ = try disk.prepare(gzip: gzip, manifest: manifest) }; try FileManager.default.removeItem(at: other)
            chmod(file.path, 0o644); try rejects { _ = try disk.prepare(gzip: gzip, manifest: manifest) }; chmod(file.path, 0o600)
            let owner = disk.vm.url.appendingPathComponent("disk-owner.json"); let h = try FileHandle(forWritingTo: owner); try h.truncate(atOffset: 0); try h.write(contentsOf: Data("broken".utf8)); try h.close()
            try rejects { _ = try disk.prepare(gzip: gzip, manifest: manifest) }; try require(try Data(contentsOf: owner) == Data("broken".utf8), "corrupt owner retained")
        }
        print("ALL DISK TESTS PASSED")
    }
}

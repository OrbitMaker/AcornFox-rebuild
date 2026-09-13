import Foundation
import Darwin
import Virtualization

@main struct EFIPreparerTests {
    static func create(_ url: URL) throws { _ = try VZEFIVariableStore(creatingVariableStoreAt: url, options: []) }
    static func require(_ value: @autoclosure () throws -> Bool, _ label: String) throws { if try !value() { throw NSError(domain: label, code: 1) } }
    static func rejects(_ work: () throws -> Void) throws {
        var failed = false; do { try work() } catch { failed = true }; try require(failed, "expected rejection")
    }
    static func main() throws {
        if CommandLine.arguments.count == 4 && CommandLine.arguments[1] == "interrupt" {
            let disk = try DiskPreparer(state: PrivateState(root: URL(fileURLWithPath: CommandLine.arguments[2])))
            disk.checkpoint = { if $0 == CommandLine.arguments[3] { kill(getpid(), SIGKILL) } }
            _ = try disk.prepareEFI(create: create); exit(4)
        }
        let base = URL(fileURLWithPath: "/private/tmp/acornfox-efi-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: base) }
        func disk(_ name: String) throws -> DiskPreparer { try DiskPreparer(state: PrivateState(root: base.appendingPathComponent(name))) }
        for stage in ["efi-intent", "efi-created", "efi-ready", "efi-published"] {
            let root = base.appendingPathComponent(stage)
            let child = Process(); child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0]); child.arguments = ["interrupt", root.path, stage]
            try child.run(); child.waitUntilExit()
            try require(child.terminationReason == .uncaughtSignal && child.terminationStatus == SIGKILL, "child SIGKILL")
            let reopened = try DiskPreparer(state: PrivateState(root: root))
            let final = try reopened.prepareEFI(create: create)
            try require(try reopened.vm.info("efi-vars")!.st_size > 0, "nonempty real EFI")
            try require(try reopened.vm.info("efi-prepare.json") == nil, "retired journal")
            let inode = try reopened.vm.info("efi-vars")!.st_ino
            _ = try reopened.prepareEFI { _ in throw HostError.invalid("must not recreate") }
            try require(try reopened.vm.info("efi-vars")!.st_ino == inode, "preserved EFI inode")
            _ = VZEFIVariableStore(url: final)
            print("PASS real VZ EFI SIGKILL recovery \(stage)")
        }
        do {
            let d = try disk("unknown"); let fd = try d.vm.create("efi-vars"); try PrivateDirectory.write(Data("FOREIGN".utf8), to: fd); close(fd)
            try rejects { _ = try d.prepareEFI(create: create) }
            try require(try Data(contentsOf: d.vm.url.appendingPathComponent("efi-vars")) == Data("FOREIGN".utf8), "unknown final retained")
            print("PASS unknown EFI final retained")
        }
        for stage in ["efi-before-publish-check", "efi-before-rename", "efi-published"] {
            let d = try disk("replace-" + stage)
            let foreign = Data("FOREIGN".utf8)
            d.checkpoint = { point in
                if point == stage {
                    let intent = try d.vm.read("efi-prepare.json", as: EFIPreparer.Intent.self)!
                    let path = stage == "efi-published" ? d.vm.url.appendingPathComponent("efi-vars") : d.vm.url.appendingPathComponent(intent.namespace).appendingPathComponent(intent.child)
                    let saved = path.appendingPathExtension("saved")
                    try FileManager.default.moveItem(at: path, to: saved)
                    let fd = open(path.path, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW, 0o600)
                    try require(fd >= 0, "foreign exclusive create"); try PrivateDirectory.write(foreign, to: fd); close(fd)
                }
            }
            try rejects { _ = try d.prepareEFI(create: create) }
            let intent = try d.vm.read("efi-prepare.json", as: EFIPreparer.Intent.self)!
            let foreignPath = stage == "efi-before-publish-check" ? d.vm.url.appendingPathComponent(intent.namespace).appendingPathComponent(intent.child) : d.vm.url.appendingPathComponent("efi-vars")
            try require(try Data(contentsOf: foreignPath) == foreign, "foreign replacement retained")
            print("PASS EFI replacement detected \(stage)")
        }
        do {
            let d = try disk("foreign-namespace")
            let extra = d.vm.url.appendingPathComponent(".efi-unknown")
            try FileManager.default.createDirectory(at: extra, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let payload = extra.appendingPathComponent("foreign"); try Data("KEEP".utf8).write(to: payload)
            _ = try d.prepareEFI(create: create)
            try require(try Data(contentsOf: payload) == Data("KEEP".utf8), "unknown namespace retained")
            print("PASS unknown EFI namespace retained")
        }
        print("ALL EFI TESTS PASSED")
    }
}

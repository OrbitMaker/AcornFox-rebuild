import Foundation
import CryptoKit
import Darwin

final class Resources {
    let root: URL; let manifest: Manifest
    init(root: URL? = nil) throws {
        guard let root = root ?? Bundle.main.resourceURL else { throw HostError.missing("资源目录") }
        self.root = root
        let file = root.appendingPathComponent("resource-manifest.json")
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw HostError.missing("资源清单") }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var s = stat(); guard fstat(fd, &s) == 0, s.st_mode & S_IFMT == S_IFREG, s.st_nlink == 1,
              s.st_size > 0, s.st_size <= 65536, let data = try handle.readToEnd() else { throw HostError.invalid("资源清单") }
        manifest = try JSONDecoder().decode(Manifest.self, from: data)
    }
    func verify() throws {
        try Self.validateManifest(manifest)
        for resource in manifest.files {
            var parent = root
            for part in resource.path.split(separator: "/").dropLast() {
                parent.appendPathComponent(String(part))
                var s = stat(); guard lstat(parent.path, &s) == 0, s.st_mode & S_IFMT == S_IFDIR else { throw HostError.invalid(resource.path) }
            }
            let file = root.appendingPathComponent(resource.path)
            let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw HostError.missing(resource.path) }
            let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            var info = stat(); guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1,
                  info.st_size > 0, UInt64(info.st_size) == resource.size else { throw HostError.invalid(resource.path) }
            var hash = SHA256()
            while let data = try handle.read(upToCount: 1 << 20), !data.isEmpty { hash.update(data: data) }
            guard hash.finalize().map({ String(format: "%02x", $0) }).joined() == resource.sha256 else { throw HostError.invalid(resource.path) }
        }
    }
    static func validateManifest(_ manifest: Manifest) throws {
        func hash(_ value: String) -> Bool { value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
        let fixed: Set<String> = ["base.raw.gz", "acornfox-guest-bridge", "candidate/candidate-binding.json", "candidate/candidate-binding.sha256", "candidate/bundle-manifest.sha256", "candidate/build-record.json", "candidate/release-manifest.json"]
        let paths = manifest.files.map(\.path)
        let archives = paths.filter { $0.range(of: "^candidate/[A-Za-z0-9][A-Za-z0-9._-]*\\.tar\\.gz$", options: .regularExpression) != nil }
        guard manifest.files.count == 8, Set(paths).count == 8, archives.count == 1,
              Set(paths) == fixed.union(archives), manifest.baseRawBytes > 0, manifest.baseRawBytes <= 40 * 1024 * 1024 * 1024,
              hash(manifest.baseRawSHA256), hash(manifest.candidateBindingSHA256), hash(manifest.bootstrapHelperSHA256 ?? ""),
              manifest.files.allSatisfy({ hash($0.sha256) && $0.size > 0 }),
              manifest.files.first(where: { $0.path == "candidate/candidate-binding.json" })?.sha256 == manifest.candidateBindingSHA256 else { throw HostError.invalid("资源清单必须包含8个已校验文件") }
    }
}

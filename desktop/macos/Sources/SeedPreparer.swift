import Foundation
import CryptoKit
import Darwin

struct PreparedSeed {
    let isoURL: URL
    let privateKeyURL: URL
    let publicKey: String
    let instanceID: UUID
    var instanceProtocol: Int = 1
    var receiptSHA256: String? = nil
}

final class SeedPreparer {
    struct Receipt: Codable {
        let version: Int; let instance: UUID; let bridgeSHA256: String; let baseSHA256: String
        let files: [Resource]; let configurationSHA256: String
        let instanceProtocol: Int?
        let bootstrapManifestSHA256: String?
    }
    let vm: PrivateDirectory
    let instance: UUID
    init(vm: PrivateDirectory, instance: UUID) { self.vm = vm; self.instance = instance }
    func prepare(resources: URL, manifest: Manifest) throws -> PreparedSeed {
        let config = try Self.controlConfig(instance: instance, manifest: manifest)
        let template = Data(Self.userData(publicKey: "seed-public-key", bridge: Data(), config: config, instance: instance).utf8)
        let configHash = SHA256.hash(data: config + template).map { String(format: "%02x", $0) }.joined()
        let matches = manifest.files.filter { $0.path == "acornfox-guest-bridge" }
        guard matches.count == 1, let bridge = matches.first, bridge.size >= 20, bridge.size <= 32 * 1024 * 1024 else { throw HostError.invalid("本机通信资源") }
        let bridgeURL = resources.appendingPathComponent(bridge.path)
        let bridgeData = try Self.readResource(bridgeURL, expected: bridge)
        guard bridgeData.prefix(4) == Data([0x7f, 0x45, 0x4c, 0x46]), bridgeData[4] == 2, bridgeData[5] == 1,
              bridgeData[18] == 0xb7, bridgeData[19] == 0 else { throw HostError.invalid("本机通信资源架构") }
        let finalURL = vm.url.appendingPathComponent("seed")
        var existing = stat()
        if fstatat(vm.fd, "seed", &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            let final = try PrivateDirectory(url: finalURL, create: false)
            return try validate(final, bridge: bridge, manifest: manifest, configHash: configHash)
        }
        guard errno == ENOENT else { throw HostError.unsafeState }
        // Until atomic directory publication succeeds this namespace is never used
        // to boot a guest. An interrupted, unpublished namespace is preserved.
        let name = ".seed-\(UUID().uuidString)"
        guard mkdirat(vm.fd, name, 0o700) == 0 else { throw HostError.unsafeState }; try vm.sync()
        let temp = try PrivateDirectory(url: vm.url.appendingPathComponent(name), create: false)
        let key = temp.url.appendingPathComponent("ssh-key")
        _ = try Self.run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "acornfox-host", "-f", key.path])
        try Self.normalizeCreated(temp, name: "ssh-key")
        try Self.normalizeCreated(temp, name: "ssh-key.pub")
        let publicKey = try Self.publicKey(temp)
        let compressedBridge = try Self.run("/usr/bin/gzip", ["-n", "-c"], input: bridgeData)
        let userData = Self.userData(publicKey: publicKey, bridge: compressedBridge, config: config, instance: instance)
        let metaData = "instance-id: acornfox-\(instance.uuidString.lowercased())\nlocal-hostname: acornfox\n"
        let cidata = try PrivateDirectory(url: temp.url.appendingPathComponent("cidata"))
        try cidata.writeNew("user-data", data: Data(userData.utf8))
        try cidata.writeNew("meta-data", data: Data(metaData.utf8))
        _ = try Self.run("/usr/bin/hdiutil", ["makehybrid", "-iso", "-joliet", "-default-volume-name", "cidata", "-o", temp.url.appendingPathComponent("seed.iso").path, cidata.url.path])
        try Self.normalizeCreated(temp, name: "seed.iso")
        let files = try ["ssh-key", "ssh-key.pub", "seed.iso"].map { try Self.resource(temp, name: $0) }
            + [try Self.resource(cidata, name: "user-data", path: "cidata/user-data"), try Self.resource(cidata, name: "meta-data", path: "cidata/meta-data")]
        try temp.record("seed-owner.json", Receipt(version: 2, instance: instance, bridgeSHA256: bridge.sha256, baseSHA256: manifest.baseRawSHA256, files: files, configurationSHA256: configHash, instanceProtocol: 1, bootstrapManifestSHA256: try InstalledReceiptStore.manifestFingerprint(manifest)))
        try temp.sync()
        var before = stat(); guard fstat(temp.fd, &before) == 0 else { throw HostError.unsafeState }
        guard renameatx_np(vm.fd, name, vm.fd, "seed", UInt32(RENAME_EXCL)) == 0 else { throw HostError.unsafeState }; try vm.sync()
        let final = try PrivateDirectory(url: finalURL, create: false)
        var after = stat(); guard fstat(final.fd, &after) == 0, before.st_dev == after.st_dev, before.st_ino == after.st_ino else { throw HostError.unsafeState }
        return try validate(final, bridge: bridge, manifest: manifest, configHash: configHash)
    }
    private func validate(_ directory: PrivateDirectory, bridge: Resource, manifest: Manifest, configHash: String) throws -> PreparedSeed {
        guard let saved = try directory.read("seed-owner.json", as: Receipt.self), saved.version == 2, saved.instanceProtocol == 1,
              saved.instance == instance, saved.configurationSHA256 == configHash, saved.bridgeSHA256 == bridge.sha256, saved.baseSHA256 == manifest.baseRawSHA256,
              Set(saved.files.map(\.path)) == Set(["ssh-key", "ssh-key.pub", "seed.iso", "cidata/user-data", "cidata/meta-data"]), saved.files.count == 5 else { throw HostError.invalid("已有本机启动配置与安装资源不一致") }
        return try validateSaved(directory, saved: saved, expectedReceiptSHA256: nil, instanceProtocol: 1, bootstrapManifestSHA256: try InstalledReceiptStore.manifestFingerprint(manifest))
    }
    func openExisting(expectedReceiptSHA256: String? = nil, instanceProtocol: Int = 1, bootstrapManifestSHA256: String? = nil) throws -> PreparedSeed {
        let directory = try PrivateDirectory(url: vm.url.appendingPathComponent("seed"), create: false)
        guard let saved = try directory.read("seed-owner.json", as: Receipt.self) else { throw HostError.unsafeState }
        return try validateSaved(directory, saved: saved, expectedReceiptSHA256: expectedReceiptSHA256, instanceProtocol: instanceProtocol, bootstrapManifestSHA256: bootstrapManifestSHA256)
    }
    private func validateSaved(_ directory: PrivateDirectory, saved: Receipt, expectedReceiptSHA256: String?, instanceProtocol: Int, bootstrapManifestSHA256: String?) throws -> PreparedSeed {
        guard saved.version == 2, saved.instance == instance, saved.instanceProtocol == 1, instanceProtocol == 1,
              InstallationRecord.isSHA(saved.bootstrapManifestSHA256 ?? ""),
              InstallationRecord.isSHA(saved.configurationSHA256), InstallationRecord.isSHA(saved.bridgeSHA256), InstallationRecord.isSHA(saved.baseSHA256),
              saved.files.count == 5, Set(saved.files.map(\.path)) == Set(["ssh-key", "ssh-key.pub", "seed.iso", "cidata/user-data", "cidata/meta-data"]) else { throw HostError.unsafeState }
        if let bootstrapManifestSHA256 { guard saved.bootstrapManifestSHA256 == bootstrapManifestSHA256 else { throw HostError.unsafeState } }
        let owner = try Self.resource(directory, name: "seed-owner.json")
        if let expectedReceiptSHA256 { guard expectedReceiptSHA256 == owner.sha256 else { throw HostError.unsafeState } }
        let cidata = try PrivateDirectory(url: directory.url.appendingPathComponent("cidata"), create: false)
        for file in saved.files {
            let actual = try Self.resource(file.path.hasPrefix("cidata/") ? cidata : directory, name: String(file.path.split(separator: "/").last!), path: file.path)
            guard actual.sha256 == file.sha256, actual.size == file.size else { throw HostError.invalid("已有本机启动配置") }
        }
        let publicKey = try Self.publicKey(directory)
        return PreparedSeed(isoURL: directory.url.appendingPathComponent("seed.iso"), privateKeyURL: directory.url.appendingPathComponent("ssh-key"), publicKey: publicKey, instanceID: instance, instanceProtocol: 1, receiptSHA256: owner.sha256)
    }
    private static func publicKey(_ directory: PrivateDirectory) throws -> String {
        _ = try directory.info("ssh-key"); let publicFD = try directory.openFile("ssh-key.pub")
        let handle = FileHandle(fileDescriptor: publicFD, closeOnDealloc: true)
        guard let bytes = try handle.read(upToCount: 4097), bytes.count <= 4096, let text = String(data: bytes, encoding: .utf8) else { throw HostError.invalid("本机连接密钥") }
        let fields = text.split(whereSeparator: \.isWhitespace)
        guard fields.count == 3, fields[0] == "ssh-ed25519", fields[2] == "acornfox-host",
              let wire = Data(base64Encoded: String(fields[1])), wire.count == 51,
              wire.prefix(19) == Data([0,0,0,11] + Array("ssh-ed25519".utf8) + [0,0,0,32]) else { throw HostError.invalid("本机连接公钥") }
        let expected = "\(fields[0]) \(fields[1])"
        let derived = try run("/usr/bin/ssh-keygen", ["-y", "-P", "", "-f", directory.url.appendingPathComponent("ssh-key").path])
        guard let derivedText = String(data: derived, encoding: .utf8), derivedText.split(whereSeparator: \.isWhitespace).prefix(2).joined(separator: " ") == expected else { throw HostError.invalid("本机连接密钥不匹配") }
        return expected
    }
    private static func normalizeCreated(_ directory: PrivateDirectory, name: String) throws {
        guard let before = try directory.info(name, requiredMode: nil), before.st_size > 0 else { throw HostError.unsafeState }
        let fd = openat(directory.fd, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw HostError.unsafeState }; defer { close(fd) }
        var s = stat(); guard fstat(fd, &s) == 0, s.st_dev == before.st_dev, s.st_ino == before.st_ino,
              fchmod(fd, 0o600) == 0, fsync(fd) == 0 else { throw HostError.unsafeState }; try directory.sync()
    }
    private static func resource(_ directory: PrivateDirectory, name: String, path: String? = nil) throws -> Resource {
        let file = try directory.openFile(name); let handle = FileHandle(fileDescriptor: file, closeOnDealloc: true)
        var hash = SHA256(); var count: UInt64 = 0
        while let data = try handle.read(upToCount: 1 << 20), !data.isEmpty { hash.update(data: data); count += UInt64(data.count) }
        return Resource(path: path ?? name, sha256: hash.finalize().map { String(format: "%02x", $0) }.joined(), size: count)
    }
    private static func readResource(_ url: URL, expected: Resource) throws -> Data {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw HostError.missing("本机通信资源") }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var s = stat(); guard fstat(fd, &s) == 0, s.st_mode & S_IFMT == S_IFREG, s.st_nlink == 1, s.st_size >= 0, UInt64(s.st_size) == expected.size else { throw HostError.invalid("本机通信资源") }
        guard let data = try handle.read(upToCount: Int(expected.size) + 1), UInt64(data.count) == expected.size,
              SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == expected.sha256 else { throw HostError.invalid("本机通信资源") }
        return data
    }
    static func run(_ executable: String, _ arguments: [String], input: Data? = nil) throws -> Data {
        let process = Process(); process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        let output = Pipe(); process.standardOutput = output; process.standardError = FileHandle.nullDevice; process.standardInput = FileHandle.nullDevice
        var pipe: Pipe?
        if let input {
            let source = Pipe(); pipe = source; process.standardInput = source
            try process.run()
            DispatchQueue.global(qos: .utility).async { try? source.fileHandleForWriting.write(contentsOf: input); try? source.fileHandleForWriting.close() }
        } else { try process.run() }
        defer { try? output.fileHandleForReading.close(); try? pipe?.fileHandleForReading.close() }
        let data = try output.fileHandleForReading.readToEnd() ?? Data(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw HostError.invalid("生成本机启动配置") }; return data
    }
    static func controlConfig(instance: UUID, manifest: Manifest) throws -> Data {
        let candidate = manifest.files.filter { $0.path.hasPrefix("candidate/") }
        guard candidate.count == 6, let helper = manifest.bootstrapHelperSHA256,
              helper.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              let archive = candidate.first(where: { $0.path.hasSuffix(".tar.gz") }) else { throw HostError.invalid("安装候选配置") }
        let object: [String: Any] = ["instance": instance.uuidString.lowercased(), "instanceProtocol": 1, "bindingSHA256": manifest.candidateBindingSHA256,
            "helperSHA256": helper, "archiveName": URL(fileURLWithPath: archive.path).lastPathComponent,
            "files": candidate.map { ["path": $0.path, "sha256": $0.sha256, "size": $0.size] as [String: Any] }]
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
    static func userData(publicKey: String, bridge: Data, config: Data, instance: UUID) -> String {
        """
        #cloud-config
        manage_etc_hosts: localhost
        users:
          - name: af-host
            gecos: AcornFox local controller
            shell: /bin/bash
            lock_passwd: true
            sudo: false
            ssh_authorized_keys:
              - \(publicKey)
        ssh_pwauth: false
        disable_root: true
        growpart:
          mode: auto
          devices: ['/']
          ignore_growroot_disabled: false
        resize_rootfs: true
        write_files:
          - path: /etc/acornfox-desktop.json
            owner: root:root
            permissions: '0600'
            encoding: b64
            content: \(config.base64EncodedString())
          - path: /var/lib/acornfox-desktop/owner-marker
            owner: root:root
            permissions: '0600'
            content: '{"product":"acornfox","instance":"\(instance.uuidString.lowercased())"}'
          - path: /usr/local/sbin/acornfox-desktop-control
            owner: root:root
            permissions: '0755'
            encoding: b64
            content: \(Data(GuestControlScript.source.utf8).base64EncodedString())
          - path: /etc/sudoers.d/acornfox-host
            owner: root:root
            permissions: '0440'
            content: 'af-host ALL=(root) NOPASSWD: /usr/local/sbin/acornfox-desktop-control'
          - path: /usr/local/sbin/acornfox-guest-bridge
            owner: root:root
            permissions: '0755'
            encoding: gz+b64
            content: \(bridge.base64EncodedString())
          - path: /etc/systemd/system/com.acornfox.guest-bridge.service
            owner: root:root
            permissions: '0644'
            content: |
              [Unit]
              Description=AcornFox local host connection
              After=network.target ssh.service
              [Service]
              ExecStart=/usr/local/sbin/acornfox-guest-bridge
              Restart=always
              RestartSec=2
              NoNewPrivileges=true
              ProtectSystem=strict
              ProtectHome=true
              PrivateTmp=true
              [Install]
              WantedBy=multi-user.target
        runcmd:
          - [chmod, '0700', /var/lib/acornfox-desktop]
          - [systemctl, enable, --now, ssh]
          - [systemctl, daemon-reload]
          - [systemctl, enable, --now, com.acornfox.guest-bridge.service]

        """
    }
}

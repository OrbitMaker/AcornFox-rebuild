import Foundation
import CryptoKit
import Darwin

struct NativeInstanceReceipt: Codable, Equatable {
    let nativeUUID: UUID
    let coreInstanceSHA256: String

    var nativeUUIDString: String {
        nativeUUID.uuidString.lowercased()
    }

    init(nativeUUID: UUID, coreInstanceSHA256: String) {
        self.nativeUUID = nativeUUID
        self.coreInstanceSHA256 = coreInstanceSHA256
    }

    init(nativeUUID: UUID) {
        self.nativeUUID = nativeUUID
        self.coreInstanceSHA256 = NativeInstanceProvisioner.deriveCoreInstanceID(from: nativeUUID)
    }

    private struct AnyCodingKey: CodingKey {
        var stringValue: String
        var intValue: Int?
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }

    enum CodingKeys: String, CodingKey {
        case nativeUUID
        case coreInstanceSHA256
    }

    init(from decoder: Decoder) throws {
        let allContainer = try decoder.container(keyedBy: AnyCodingKey.self)
        guard allContainer.allKeys.count == 2,
              Set(allContainer.allKeys.map(\.stringValue)) == Set(["nativeUUID", "coreInstanceSHA256"]) else {
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "strict receipt schema requires exact nativeUUID and coreInstanceSHA256 keys"))
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let uuidVal = try container.decode(UUID.self, forKey: .nativeUUID)
        let shaVal = try container.decode(String.self, forKey: .coreInstanceSHA256)
        let expected = NativeInstanceProvisioner.deriveCoreInstanceID(from: uuidVal)
        guard shaVal == expected,
              shaVal.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "invalid coreInstanceSHA256"))
        }
        self.nativeUUID = uuidVal
        self.coreInstanceSHA256 = shaVal
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(nativeUUID, forKey: .nativeUUID)
        try container.encode(coreInstanceSHA256, forKey: .coreInstanceSHA256)
    }
}

final class NativeInstanceProvisioner {
    let state: PrivateState

    init(state: PrivateState) {
        self.state = state
    }

    convenience init(root: URL? = nil) throws {
        self.init(state: try PrivateState(root: root))
    }

    static func deriveCoreInstanceID(from nativeUUID: UUID) -> String {
        let lower = nativeUUID.uuidString.lowercased()
        let hash = SHA256.hash(data: Data(("mac-managed:" + lower).utf8))
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    static func deriveCoreInstanceID(from uuidString: String) throws -> String {
        let normalized = try normalizeUUID(uuidString)
        guard let uuid = UUID(uuidString: normalized) else {
            throw HostError.invalid("native UUID")
        }
        return deriveCoreInstanceID(from: uuid)
    }

    static func normalizeUUID(_ uuidString: String) throws -> String {
        let pattern = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        guard uuidString.range(of: pattern, options: .regularExpression) != nil,
              UUID(uuidString: uuidString) != nil else {
            throw HostError.invalid("native UUID")
        }
        return uuidString.lowercased()
    }

    static func listDirectoryFD(_ fd: Int32) throws -> [String] {
        let dupFD = fcntl(fd, F_DUPFD_CLOEXEC, 0)
        guard dupFD >= 0 else { throw HostError.unsafeState }
        guard let dir = fdopendir(dupFD) else {
            close(dupFD)
            throw HostError.unsafeState
        }
        defer { closedir(dir) }
        var entries: [String] = []
        while let entry = readdir(dir) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) { ptr -> String in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { cStr in
                    String(cString: cStr)
                }
            }
            if name != "." && name != ".." {
                entries.append(name)
            }
        }
        return entries
    }

    static func validateStrictInstanceJSON(data: Data) throws -> DiskPreparer.Instance {
        guard data.count > 0, data.count <= 65536, let text = String(data: data, encoding: .utf8) else {
            throw HostError.unsafeState
        }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              obj.count == 2,
              let version = obj["version"] as? Int, version == 1,
              let idStr = obj["id"] as? String else {
            throw HostError.unsafeState
        }
        let uuidPattern = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        guard idStr.range(of: uuidPattern, options: .regularExpression) != nil,
              let uuid = UUID(uuidString: idStr) else {
            throw HostError.unsafeState
        }

        let keyRegex = try NSRegularExpression(pattern: #""([^"\\]*)"\s*:"#)
        let matches = keyRegex.matches(in: text, range: NSRange(text.startIndex..., in: text))
        guard matches.count == 2 else { throw HostError.unsafeState }
        var seenKeys: Set<String> = []
        for match in matches {
            guard let keyRange = Range(match.range(at: 1), in: text) else { throw HostError.unsafeState }
            let key = String(text[keyRange])
            guard seenKeys.insert(key).inserted else { throw HostError.unsafeState }
        }
        guard seenKeys == Set(["version", "id"]) else { throw HostError.unsafeState }
        return DiskPreparer.Instance(version: 1, id: uuid)
    }

    static func preliminaryScreening(state: PrivateState) throws {
        let rootPath = state.root.path
        if FileManager.default.fileExists(atPath: rootPath) {
            let rootEntries: [String]
            do { rootEntries = try FileManager.default.contentsOfDirectory(atPath: rootPath) }
            catch { throw HostError.unsafeState }
            guard Set(rootEntries).isSubset(of: ["instance.lock", "vm"]) else {
                throw HostError.unsafeState
            }
            for name in rootEntries {
                var s = stat()
                guard lstat(rootPath + "/" + name, &s) == 0, s.st_uid == getuid() else {
                    throw HostError.unsafeState
                }
                if name == "instance.lock" {
                    guard s.st_mode & S_IFMT == S_IFREG, s.st_mode & 0o7777 == 0o600, s.st_nlink == 1 else {
                        throw HostError.unsafeState
                    }
                } else if name == "vm" {
                    guard s.st_mode & S_IFMT == S_IFDIR, s.st_mode & 0o7777 == 0o700 else {
                        throw HostError.unsafeState
                    }
                }
            }
        }

        let vmPath = state.root.appendingPathComponent("vm", isDirectory: true).path
        if FileManager.default.fileExists(atPath: vmPath) {
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: vmPath, isDirectory: &isDir), isDir.boolValue else {
                throw HostError.unsafeState
            }
            let entries: [String]
            do { entries = try FileManager.default.contentsOfDirectory(atPath: vmPath) }
            catch { throw HostError.unsafeState }

            if !entries.contains("instance.json") {
                guard entries.isEmpty else { throw HostError.unsafeState }
            } else {
                let instURL = URL(fileURLWithPath: vmPath).appendingPathComponent("instance.json")
                var instStat = stat()
                guard lstat(instURL.path, &instStat) == 0,
                      instStat.st_uid == getuid(),
                      instStat.st_mode & S_IFMT == S_IFREG,
                      instStat.st_mode & 0o7777 == 0o600,
                      instStat.st_nlink == 1,
                      instStat.st_size > 0, instStat.st_size <= 65536,
                      let data = try? Data(contentsOf: instURL) else { throw HostError.unsafeState }
                _ = try validateStrictInstanceJSON(data: data)

                let allowedVMRegularFiles: Set<String> = [
                    "instance.json",
                    "host-installation.json",
                    "guest.raw",
                    "disk-owner.json",
                    "prepare.json",
                    "machine-id",
                    "efi-vars",
                    "efi-owner.json",
                    "efi-prepare.json",
                    "ssh-known-hosts",
                    "serial-console.log",
                    "entry-diagnostics.log",
                    "vsock-diagnostics.log"
                ]

                guard entries.allSatisfy({ allowedVMRegularFiles.contains($0) || $0 == "seed" }) else {
                    throw HostError.unsafeState
                }

                for name in entries {
                    var s = stat()
                    guard lstat(vmPath + "/" + name, &s) == 0, s.st_uid == getuid() else {
                        throw HostError.unsafeState
                    }
                    if allowedVMRegularFiles.contains(name) {
                        guard s.st_mode & S_IFMT == S_IFREG, s.st_mode & 0o7777 == 0o600, s.st_nlink == 1 else {
                            throw HostError.unsafeState
                        }
                    } else if name == "seed" {
                        guard s.st_mode & S_IFMT == S_IFDIR, s.st_mode & 0o7777 == 0o700 else {
                            throw HostError.unsafeState
                        }
                        let seedPath = vmPath + "/seed"
                        let seedEntries = (try? FileManager.default.contentsOfDirectory(atPath: seedPath)) ?? []
                        let allowedSeedFiles: Set<String> = ["ssh-key", "ssh-key.pub", "seed.iso", "seed-owner.json"]
                        guard seedEntries.allSatisfy({ allowedSeedFiles.contains($0) || $0 == "cidata" }) else {
                            throw HostError.unsafeState
                        }
                        for sname in seedEntries {
                            var ss = stat()
                            guard lstat(seedPath + "/" + sname, &ss) == 0, ss.st_uid == getuid() else {
                                throw HostError.unsafeState
                            }
                            if allowedSeedFiles.contains(sname) {
                                guard ss.st_mode & S_IFMT == S_IFREG, ss.st_mode & 0o7777 == 0o600, ss.st_nlink == 1 else {
                                    throw HostError.unsafeState
                                }
                            } else if sname == "cidata" {
                                guard ss.st_mode & S_IFMT == S_IFDIR, ss.st_mode & 0o7777 == 0o700 else {
                                    throw HostError.unsafeState
                                }
                                let cidataPath = seedPath + "/cidata"
                                let cidataEntries = (try? FileManager.default.contentsOfDirectory(atPath: cidataPath)) ?? []
                                let allowedCidataFiles: Set<String> = ["user-data", "meta-data"]
                                guard Set(cidataEntries).isSubset(of: allowedCidataFiles) else {
                                    throw HostError.unsafeState
                                }
                                for cname in cidataEntries {
                                    var cs = stat()
                                    guard lstat(cidataPath + "/" + cname, &cs) == 0,
                                          cs.st_uid == getuid(),
                                          cs.st_mode & S_IFMT == S_IFREG,
                                          cs.st_mode & 0o7777 == 0o600,
                                          cs.st_nlink == 1 else {
                                        throw HostError.unsafeState
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    static func rootPreflight(directory: PrivateDirectory) throws {
        let entries = try listDirectoryFD(directory.fd)
        let allowedRootNames: Set<String> = ["instance.lock", "vm"]
        guard Set(entries).isSubset(of: allowedRootNames) else {
            throw HostError.unsafeState
        }
        for name in entries {
            var s = stat()
            guard fstatat(directory.fd, name, &s, AT_SYMLINK_NOFOLLOW) == 0, s.st_uid == getuid() else {
                throw HostError.unsafeState
            }
            if name == "instance.lock" {
                guard s.st_mode & S_IFMT == S_IFREG, s.st_mode & 0o7777 == 0o600, s.st_nlink == 1 else {
                    throw HostError.unsafeState
                }
            } else if name == "vm" {
                guard s.st_mode & S_IFMT == S_IFDIR, s.st_mode & 0o7777 == 0o700 else {
                    throw HostError.unsafeState
                }
            }
        }
    }

    static func vmPreflight(vm: PrivateDirectory, vmExisted: Bool) throws {
        let entries = try listDirectoryFD(vm.fd)
        if !entries.contains("instance.json") {
            guard entries.isEmpty else { throw HostError.unsafeState }
            return
        }

        // Validate instance.json strictly under the held lock
        let instFD = openat(vm.fd, "instance.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard instFD >= 0 else { throw HostError.unsafeState }
        defer { close(instFD) }
        var instStat = stat()
        guard fstat(instFD, &instStat) == 0,
              instStat.st_uid == getuid(),
              instStat.st_mode & S_IFMT == S_IFREG,
              instStat.st_mode & 0o7777 == 0o600,
              instStat.st_nlink == 1,
              instStat.st_size > 0, instStat.st_size <= 65536 else {
            throw HostError.unsafeState
        }
        let handle = FileHandle(fileDescriptor: instFD, closeOnDealloc: false)
        guard let instData = try handle.read(upToCount: 65536) else { throw HostError.unsafeState }
        _ = try validateStrictInstanceJSON(data: instData)

        let allowedVMRegularFiles: Set<String> = [
            "instance.json",
            "host-installation.json",
            "guest.raw",
            "disk-owner.json",
            "prepare.json",
            "machine-id",
            "efi-vars",
            "efi-owner.json",
            "efi-prepare.json",
            "ssh-known-hosts",
            "serial-console.log",
            "entry-diagnostics.log",
            "vsock-diagnostics.log"
        ]

        guard entries.allSatisfy({ allowedVMRegularFiles.contains($0) || $0 == "seed" }) else {
            throw HostError.unsafeState
        }

        for name in entries {
            var s = stat()
            guard fstatat(vm.fd, name, &s, AT_SYMLINK_NOFOLLOW) == 0, s.st_uid == getuid() else {
                throw HostError.unsafeState
            }

            if allowedVMRegularFiles.contains(name) {
                guard s.st_mode & S_IFMT == S_IFREG, s.st_mode & 0o7777 == 0o600, s.st_nlink == 1 else {
                    throw HostError.unsafeState
                }
            } else if name == "seed" {
                guard s.st_mode & S_IFMT == S_IFDIR, s.st_mode & 0o7777 == 0o700 else {
                    throw HostError.unsafeState
                }
                let seedFD = openat(vm.fd, "seed", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard seedFD >= 0 else { throw HostError.unsafeState }
                defer { close(seedFD) }

                let seedEntries = try listDirectoryFD(seedFD)
                let allowedSeedFiles: Set<String> = ["ssh-key", "ssh-key.pub", "seed.iso", "seed-owner.json"]
                guard seedEntries.allSatisfy({ allowedSeedFiles.contains($0) || $0 == "cidata" }) else {
                    throw HostError.unsafeState
                }

                for sname in seedEntries {
                    var ss = stat()
                    guard fstatat(seedFD, sname, &ss, AT_SYMLINK_NOFOLLOW) == 0, ss.st_uid == getuid() else {
                        throw HostError.unsafeState
                    }
                    if allowedSeedFiles.contains(sname) {
                        guard ss.st_mode & S_IFMT == S_IFREG, ss.st_mode & 0o7777 == 0o600, ss.st_nlink == 1 else {
                            throw HostError.unsafeState
                        }
                    } else if sname == "cidata" {
                        guard ss.st_mode & S_IFMT == S_IFDIR, ss.st_mode & 0o7777 == 0o700 else {
                            throw HostError.unsafeState
                        }
                        let cidataFD = openat(seedFD, "cidata", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                        guard cidataFD >= 0 else { throw HostError.unsafeState }
                        defer { close(cidataFD) }

                        let cidataEntries = try listDirectoryFD(cidataFD)
                        let allowedCidataFiles: Set<String> = ["user-data", "meta-data"]
                        guard Set(cidataEntries).isSubset(of: allowedCidataFiles) else {
                            throw HostError.unsafeState
                        }
                        for cname in cidataEntries {
                            var cs = stat()
                            guard fstatat(cidataFD, cname, &cs, AT_SYMLINK_NOFOLLOW) == 0,
                                  cs.st_uid == getuid(),
                                  cs.st_mode & S_IFMT == S_IFREG,
                                  cs.st_mode & 0o7777 == 0o600,
                                  cs.st_nlink == 1 else {
                                throw HostError.unsafeState
                            }
                        }
                    }
                }
            }
        }
    }

    func openDiskPreparer() throws -> DiskPreparer {
        try Self.preliminaryScreening(state: state)
        return try DiskPreparer.open(
            state: state,
            rootPreflight: Self.rootPreflight,
            vmPreflight: Self.vmPreflight
        )
    }

    func prepareOrOpen() throws -> NativeInstanceReceipt {
        let preparer = try openDiskPreparer()
        let nativeUUID = preparer.instanceID
        let coreInstanceSHA256 = Self.deriveCoreInstanceID(from: nativeUUID)
        return NativeInstanceReceipt(nativeUUID: nativeUUID, coreInstanceSHA256: coreInstanceSHA256)
    }
}

func prepareOrOpenNativeInstance(state: PrivateState? = nil) throws -> NativeInstanceReceipt {
    let s = try state ?? PrivateState()
    return try NativeInstanceProvisioner(state: s).prepareOrOpen()
}

func prepareOrOpenNativeInstance(root: URL) throws -> NativeInstanceReceipt {
    return try NativeInstanceProvisioner(root: root).prepareOrOpen()
}

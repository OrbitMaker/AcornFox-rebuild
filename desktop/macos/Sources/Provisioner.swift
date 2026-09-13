import Foundation
import Darwin

final class SetupProbe: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private var body = Data()
    private var accepted = false
    private var result: String?
    private let done = DispatchSemaphore(value: 0)
    static func parse(_ data: Data) -> String? {
        guard data.count < 4096, let text = String(data: data, encoding: .utf8),
              text.range(of: #"^\s*\{\s*"state"\s*:\s*"(initialized|uninitialized)"\s*\}\s*$"#, options: .regularExpression) != nil,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: String] else { return nil }
        return object["state"]
    }
    static func probe(port: UInt16 = 8080, timeout: TimeInterval = 45, cancelled: () -> Bool = { false }) throws -> String {
        let until = Date().addingTimeInterval(timeout)
        repeat {
            if cancelled() { throw HostError.invalid("操作已取消") }
            let request = SetupProbe()
            if let state = request.once(port: port) { return state }
            Thread.sleep(forTimeInterval: 0.25)
        } while Date() < until
        throw HostError.invalid("本机应用尚未通过安装检查")
    }
    private func once(port: UInt16) -> String? {
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]; config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 3; config.timeoutIntervalForResource = 3
        let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: URL(string: "http://127.0.0.1:\(port)/api/v1/acornfox/setup")!)
        request.setValue("no-cache, no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("no-cache", forHTTPHeaderField: "Pragma")
        session.dataTask(with: request).resume()
        guard done.wait(timeout: .now() + 4) == .success else { return nil }; return result
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        accepted = (response as? HTTPURLResponse)?.statusCode == 200
        completionHandler(accepted ? .allow : .cancel)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        if body.count + data.count >= 4096 { accepted = false; dataTask.cancel() } else { body.append(data) }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if error == nil && accepted { result = Self.parse(body) }; done.signal()
    }
}

final class Provisioner {
    let running: RunningInstance
    let resources: Resources?
    private let state: PrivateDirectory
    private let lock = NSLock()
    private var cancelled = false
    private var processes: [UUID: Process] = [:]
    init(running: RunningInstance, resources: Resources? = nil, state: PrivateDirectory) throws {
        self.running = running; self.resources = resources; self.state = state
        if try state.info("ssh-known-hosts") == nil {
            guard resources != nil else { throw HostError.unsafeState }
            try state.writeNew("ssh-known-hosts", data: Data())
        }
    }
    func cancel() {
        lock.lock(); cancelled = true; let pending = Array(processes.values); lock.unlock()
        for process in pending where process.isRunning { process.terminate() }
    }
    private func isCancelled() -> Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
    func prepare(onAuthenticated: () -> Void = {}, progress: (String) -> Void) throws -> String {
        if isCancelled() { throw HostError.invalid("操作已取消") }
        guard let resources else { throw HostError.unsafeState }
        try resources.verify()
        let installation = InstalledReceiptStore(directory: state, instance: running.seed.instanceID)
        _ = try installation.requireBootstrap(manifest: resources.manifest)
        try authenticate(onAuthenticated: onAuthenticated, progress: progress)
        let initial = try installed()
        if !initial {
            progress("正在复制已验证的安装文件…")
            for file in resources.manifest.files where file.path.hasPrefix("candidate/") {
                _ = try execute(["upload", URL(fileURLWithPath: file.path).lastPathComponent], input: resources.root.appendingPathComponent(file.path), timeout: 300)
            }
            progress("正在安装本机服务，首次安装需要一些时间…")
            _ = try execute(["install"], timeout: 1900)
            guard try installed() else { throw HostError.invalid("本机安装结果未通过检查") }
        }
        let evidence = try currentEvidence(instance: running.seed.instanceID, binding: resources.manifest.candidateBindingSHA256, instanceProtocol: 1)
        progress("正在检查应用入口…")
        let ready = try SetupProbe.probe(port: running.endpoints.httpPort, cancelled: isCancelled)
        try installation.completeBootstrap(manifest: resources.manifest, evidence: evidence, readyState: ready)
        return ready
    }
    private func authenticate(onAuthenticated: () -> Void, progress: (String) -> Void) throws {
        progress("正在连接本机服务…")
        let until = Date().addingTimeInterval(180)
        var ready = false
        repeat {
            if isCancelled() { throw HostError.invalid("操作已取消") }
            if let data = try? execute(["identity"], timeout: 10), let identity = try? JSONSerialization.jsonObject(with: data) as? [String: String],
               identity["product"] == "acornfox", identity["instance"] == running.seed.instanceID.uuidString.lowercased() { ready = true; break }
            Thread.sleep(forTimeInterval: 0.5)
        } while Date() < until
        guard ready else { throw HostError.invalid("本机连接未就绪") }
        onAuthenticated()
    }
    private func currentEvidence(instance: UUID, binding: String, instanceProtocol: Int) throws -> CurrentBackendEvidence {
        let data = try execute(["verify-current"], timeout: 120)
        let evidence = try JSONDecoder().decode(CurrentBackendEvidence.self, from: data)
        try evidence.validate(instance: instance, binding: binding, instanceProtocol: instanceProtocol)
        return evidence
    }
    func openInstalled(context: InstalledInstanceContext, onAuthenticated: () -> Void = {}, progress: (String) -> Void) throws -> String {
        defer { context.closeAuthority() }
        let store = InstalledReceiptStore(directory: state, instance: running.seed.instanceID)
        _ = try store.validate(context)
        try authenticate(onAuthenticated: onAuthenticated, progress: progress)
        return try Self.verifyInstalled(context: context, store: store, execute: { try self.execute($0, timeout: 120) }, probe: {
            try SetupProbe.probe(port: self.running.endpoints.httpPort, cancelled: self.isCancelled)
        })
    }
    // The same read-only sequence is used in production and transport tests.
    // No branch here can call upload, install or a recovery operation.
    static func verifyInstalled(context: InstalledInstanceContext, store: InstalledReceiptStore,
                                execute: ([String]) throws -> Data, probe: () throws -> String) throws -> String {
        _ = try store.validate(context)
        let evidence = try JSONDecoder().decode(CurrentBackendEvidence.self, from: execute(["verify-current"]))
        try evidence.validate(instance: context.instance, binding: context.expectedBackendBinding, instanceProtocol: context.instanceProtocol)
        let ready = try probe()
        guard ready == "initialized" || ready == "uninitialized" else { throw HostError.unsafeState }
        _ = try store.validate(context) // Reject a lease closed/changed during the fresh probe.
        return ready
    }
    // Capture immutable inputs, not this install operation's cancellation state.
    // A fresh short-lived SSH scope is created only when shutdown is requested.
    func makeShutdownRequest() -> GuestShutdownRequest {
        let run = running, inputs = resources, directory = state
        return { completed in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let control = try Provisioner(running: run, resources: inputs, state: directory)
                    try Self.requestGuestShutdown(instanceID: run.seed.instanceID) { arguments in
                        try control.execute(arguments, timeout: 10)
                    }
                    completed(.success(()))
                } catch { completed(.failure(error)) }
            }
        }
    }
    static func requestGuestShutdown(instanceID: UUID, execute: ([String]) throws -> Data) throws {
        let identityData = try execute(["identity"])
        guard let identity = try JSONSerialization.jsonObject(with: identityData) as? [String: String],
              identity == ["product": "acornfox", "instance": instanceID.uuidString.lowercased()] else { throw HostError.unsafeState }
        let response = try execute(["shutdown"])
        guard let result = try JSONSerialization.jsonObject(with: response) as? [String: Any], result.count == 2,
              result["shutdown_requested"] as? Bool == true, result["instance"] as? String == instanceID.uuidString.lowercased() else { throw HostError.invalid("关机请求未被接受") }
    }
    private func installed() throws -> Bool {
        let result = try execute(["verify"], timeout: 120)
        guard let json = try JSONSerialization.jsonObject(with: result) as? [String: Any], let installed = json["installed"] as? Bool else { throw HostError.invalid("已有安装凭据") }
        return installed
    }
    // Called only by the explicit Copy action; never enters status/logs/disk/URL.
    func setupCode() throws -> String {
        guard try SetupProbe.probe(port: running.endpoints.httpPort, timeout: 5, cancelled: isCancelled) == "uninitialized" else { throw HostError.invalid("应用已完成初始设置") }
        let data = try execute(["setup-code"], timeout: 10)
        guard let text = String(data: data, encoding: .utf8), text.range(of: "^[A-Za-z0-9_-]{16,256}$", options: .regularExpression) != nil else { throw HostError.invalid("设置码暂不可用") }; return text
    }
    static func escapeOpenSSHConfigPath(_ path: String) throws -> String {
        guard !path.isEmpty else { throw HostError.invalid("known-hosts 路径为空") }
        guard !path.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f }) else {
            throw HostError.invalid("安全检查未通过：路径包含不支持的控制字符")
        }
        var escaped = ""
        for ch in path {
            switch ch {
            case "\\": escaped.append("\\\\")
            case "\"": escaped.append("\\\"")
            case "%":  escaped.append("%%")
            default:   escaped.append(ch)
            }
        }
        return "\"\(escaped)\""
    }
    static func knownHostsConfigValue(in directory: PrivateDirectory) throws -> String {
        let path = directory.url.appendingPathComponent("ssh-known-hosts").path
        return try escapeOpenSSHConfigPath(path)
    }
    static func sshArguments(running: RunningInstance, state: PrivateDirectory, command: [String]) throws -> [String] {
        let knownHostsOption = try knownHostsConfigValue(in: state)
        return [
            "-F", "/dev/null",
            "-T",
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UpdateHostKeys=no",
            "-o", "UserKnownHostsFile=\(knownHostsOption)",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "HostKeyAlias=acornfox-\(running.seed.instanceID.uuidString.lowercased())",
            "-o", "CheckHostIP=no",
            "-o", "ConnectTimeout=5",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=3",
            "-p", String(running.endpoints.sshPort),
            "-i", running.seed.privateKeyURL.path,
            "af-host@127.0.0.1",
            "sudo", "-n", "/usr/local/sbin/acornfox-desktop-control"
        ] + command
    }
    func sshArguments(for command: [String]) throws -> [String] {
        return try Self.sshArguments(running: running, state: state, command: command)
    }
    private func execute(_ arguments: [String], input: URL? = nil, timeout: TimeInterval) throws -> Data {
        guard !isCancelled(), arguments.allSatisfy({ $0.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil }) else { throw HostError.invalid("操作已取消") }
        _ = try state.info("ssh-known-hosts")
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        process.arguments = try sshArguments(for: arguments)
        let output = Pipe(); process.standardOutput = output; process.standardError = FileHandle.nullDevice; process.standardInput = FileHandle.nullDevice
        var source: FileHandle?
        if let input {
            let fd = open(input.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw HostError.invalid("安装资源") }; source = FileHandle(fileDescriptor: fd, closeOnDealloc: true); process.standardInput = source
        }
        let id = UUID()
        lock.lock()
        if cancelled { lock.unlock(); throw HostError.invalid("操作已取消") }
        do { try process.run(); processes[id] = process; lock.unlock() } catch { lock.unlock(); throw error }
        defer { lock.lock(); processes.removeValue(forKey: id); lock.unlock(); try? source?.close(); try? output.fileHandleForReading.close() }
        let deadline = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: deadline)
        defer { deadline.cancel() }
        var body = Data()
        while let data = try output.fileHandleForReading.read(upToCount: 4096), !data.isEmpty {
            guard body.count + data.count <= 65536 else { process.terminate(); process.waitUntilExit(); throw HostError.invalid("本机响应过长") }; body.append(data)
        }
        process.waitUntilExit()
        guard process.terminationStatus == 0, !isCancelled() else { throw HostError.invalid("本机安装或连接检查未通过，已有数据已保留") }
        return body
    }
}

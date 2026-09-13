import Foundation
import CryptoKit
import Virtualization
import Darwin

@available(macOS 13.0, *)
final class VMConfigurationFactory {
    // Versioned derivation is stable across launches. Changing it would require
    // an explicit guest network migration; never silently choose a random MAC.
    static func makeNetwork(instanceID: UUID) throws -> VZVirtioNetworkDeviceConfiguration {
        let input = Data(("acornfox-virtio-network-v1:" + instanceID.uuidString.lowercased()).utf8)
        var bytes = Array(SHA256.hash(data: input).prefix(6))
        bytes[0] = (bytes[0] & 0xfc) | 0x02 // Local administration, unicast.
        let value = bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
        guard let address = VZMACAddress(string: value) else { throw HostError.unsafeState }
        let network = VZVirtioNetworkDeviceConfiguration()
        network.macAddress = address; network.attachment = VZNATNetworkDeviceAttachment()
        return network
    }
    func make(preparer: DiskPreparer, seed: PreparedSeed) throws -> VZVirtualMachineConfiguration {
        let vm = preparer.vm.url
        let directory = try PrivateDirectory(url: vm)
        let disk = vm.appendingPathComponent("guest.raw")
        guard try directory.info("guest.raw") != nil else { throw HostError.missing("已准备的本机磁盘") }
        guard seed.instanceID == preparer.instanceID, seed.instanceProtocol == 1 else { throw HostError.unsafeState }
        let installation = InstalledReceiptStore(directory: directory, instance: preparer.instanceID)
        guard let installationRecord = try installation.load() else { throw HostError.unsafeState }
        let existing = installationRecord.phase == "ready"
        if existing {
            let expectedSeed = try installation.validate(installation.context())
            guard seed.isoURL == expectedSeed.isoURL, seed.privateKeyURL == expectedSeed.privateKeyURL else { throw HostError.unsafeState }
        }
        let config = VZVirtualMachineConfiguration(); config.cpuCount = 2; config.memorySize = 4 * 1024 * 1024 * 1024
        let platform = VZGenericPlatformConfiguration()
        if try directory.info("machine-id") != nil {
            let handle = FileHandle(fileDescriptor: try directory.openFile("machine-id"), closeOnDealloc: true)
            guard let old = try handle.read(upToCount: 65537), old.count <= 65536,
                  let restored = VZGenericMachineIdentifier(dataRepresentation: old) else { throw HostError.invalid("machine-id") }
            platform.machineIdentifier = restored
        } else {
            guard !existing else { throw HostError.unsafeState }
            let created = VZGenericMachineIdentifier()
            try directory.writeNew("machine-id", data: created.dataRepresentation)
            platform.machineIdentifier = created
        }
        config.platform = platform
        let loader = VZEFIBootLoader()
        let efi: URL
        if existing { efi = vm.appendingPathComponent("efi-vars") }
        else {
            efi = try preparer.prepareEFI { target in
                _ = try VZEFIVariableStore(creatingVariableStoreAt: target, options: [])
            }
        }
        loader.variableStore = VZEFIVariableStore(url: efi)
        config.bootLoader = loader
        config.storageDevices = [
            VZVirtioBlockDeviceConfiguration(attachment: try VZDiskImageStorageDeviceAttachment(url: disk, readOnly: false)),
            VZVirtioBlockDeviceConfiguration(attachment: try VZDiskImageStorageDeviceAttachment(url: seed.isoURL, readOnly: true))
        ]
        // Pin an append-only private diagnostic file; no pathname is handed to VZ.
        if try directory.info("serial-console.log") == nil { try directory.writeNew("serial-console.log", data: Data()) }
        let consoleHandle = FileHandle(fileDescriptor: try directory.openFile("serial-console.log", flags: O_WRONLY | O_APPEND), closeOnDealloc: true)
        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        console.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: consoleHandle)
        config.serialPorts = [console]
        config.networkDevices = [try Self.makeNetwork(instanceID: preparer.instanceID)]
        config.socketDevices = [VZVirtioSocketDeviceConfiguration()]; config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        try config.validate(); return config
    }
}

typealias GuestShutdownRequest = (@escaping (Result<Void, Error>) -> Void) -> Void

struct RunningInstance {
    let sessionID = UUID()
    let endpoints: LocalEndpoints
    let seed: PreparedSeed
}

enum VMStatus {
    case starting, running(RunningInstance), stopping, stopped, failed(String, running: Bool)
}

// The production shutdown gate has no force-stop operation. All methods and
// scheduled callbacks run on the VZ queue; tests inject a clock and guest event.
final class GracefulStopGate {
    enum Phase { case idle, waitingForStart, waitingForGuest, completed }
    private(set) var phase: Phase = .idle
    var requested: Bool { phase == .waitingForStart || phase == .waitingForGuest }
    private var generation = UUID()
    private let scheduleTimeout: (@escaping () -> Void) -> Void
    private let waiting: () -> Void
    private let failed: (String) -> Void
    private let confirmed: () -> Void
    init(scheduleTimeout: @escaping (@escaping () -> Void) -> Void, waiting: @escaping () -> Void, failed: @escaping (String) -> Void, confirmed: @escaping () -> Void) {
        self.scheduleTimeout = scheduleTimeout; self.waiting = waiting; self.failed = failed; self.confirmed = confirmed
    }
    func reset() { generation = UUID(); phase = .idle }
    func request(starting: Bool, alreadyStopped: Bool, canRequestStop: Bool, send: () throws -> Void) {
        requestAsync(starting: starting, alreadyStopped: alreadyStopped, canRequestStop: canRequestStop) { completed in
            do { try send(); completed(.success(())) } catch { completed(.failure(error)) }
        }
    }
    func requestAsync(starting: Bool, alreadyStopped: Bool, canRequestStop: Bool, send: GuestShutdownRequest) {
        if phase == .waitingForGuest { return }
        if starting {
            if phase != .waitingForStart { phase = .waitingForStart; waiting(); armTimeout() }
            return
        }
        if alreadyStopped { guestDidStop(); return }
        guard canRequestStop else { reject("本机服务暂时不能安全停止，仍在运行。请稍后重试。"); return }
        phase = .waitingForGuest; waiting(); armTimeout()
        let current = generation
        send { [weak self] result in
            guard let self, self.generation == current, self.phase == .waitingForGuest else { return }
            if case .failure = result { self.reject("关机请求未被接受，本机服务仍在运行。请稍后重试。") }
            // An acknowledged request is NOT a stopped VM. Only the guest event
            // confirms shutdown and lets the controller release its resources.
        }
    }
    private func armTimeout() {
        generation = UUID(); let current = generation
        scheduleTimeout { [weak self] in
            guard let self, self.generation == current, self.requested else { return }
            self.reject("本机服务尚未完成关机，已继续保留运行状态。请稍后再试，勿直接结束进程。")
        }
    }
    func guestDidStop() {
        guard phase != .completed else { return }
        generation = UUID(); phase = .completed; confirmed()
    }
    private func reject(_ message: String) { generation = UUID(); phase = .idle; failed(message) }
}

@available(macOS 13.0, *)
final class VMController: NSObject, VZVirtualMachineDelegate {
    private let queue = DispatchQueue(label: "com.acornfox.vm")
    private var machine: VZVirtualMachine?
    private var preparer: DiskPreparer?
    private var forwarding: LoopbackForwarder?
    private var currentRun: RunningInstance?
    private var authenticatedShutdown: GuestShutdownRequest?
    private var socketConnections: [Int32: VZVirtioSocketConnection] = [:]
    private var finishing = false
    private var starting = false
    private var connectorAttemptCounter = 0
    private var stopping: Bool { shutdown.phase == .waitingForGuest }
    private var stopRequested: Bool { shutdown.requested }
    private struct StopObserver { let completed: () -> Void; let failed: (String) -> Void }
    private var onStopped: [StopObserver] = []

    struct ConnectorGateDecision: Equatable {
        let authorized: Bool
        let rejectionReason: String?
    }

    static func evaluateConnectorGate(
        port: UInt32,
        machineState: VZVirtualMachine.State?,
        hasSocketDevice: Bool,
        finishing: Bool
    ) -> ConnectorGateDecision {
        guard GuestRoute.allCases.contains(where: { $0.guestPort == port }) else {
            return ConnectorGateDecision(authorized: false, rejectionReason: "unsupported-port")
        }
        guard let machineState else {
            return ConnectorGateDecision(authorized: false, rejectionReason: "missing-machine")
        }
        guard machineState == .running else {
            return ConnectorGateDecision(authorized: false, rejectionReason: "machine-not-running actualState=\(machineState.description)")
        }
        guard !finishing else {
            return ConnectorGateDecision(authorized: false, rejectionReason: "controller-finishing")
        }
        guard hasSocketDevice else {
            return ConnectorGateDecision(authorized: false, rejectionReason: "missing-socket-device")
        }
        return ConnectorGateDecision(authorized: true, rejectionReason: nil)
    }

    private func recordVsockDiagnostic(attempt: Int, port: UInt32, details: String) {
        guard let directory = preparer?.vm else { return }
        do {
            let name = "vsock-diagnostics.log"
            if try directory.info(name) == nil { try directory.writeNew(name, data: Data()) }
            guard let info = try directory.info(name), info.st_size < 1024 * 1024 else { return }
            let fd = try directory.openFile(name, flags: O_WRONLY | O_APPEND); defer { close(fd) }
            let line = "\(Int(Date().timeIntervalSince1970)) attempt=\(attempt) guestPort=\(port) \(details)\n"
            try PrivateDirectory.write(Data(line.utf8), to: fd)
        } catch { /* Diagnostics never overwrite an unsafe existing file. */ }
    }
    private lazy var shutdown = GracefulStopGate(scheduleTimeout: { [weak self] callback in
        self?.queue.asyncAfter(deadline: .now() + 90, execute: DispatchWorkItem(block: callback))
    }, waiting: { [weak self] in self?.report(.stopping) }, failed: { [weak self] message in
        self?.stopFailed(message)
    }, confirmed: { [weak self] in self?.finishStopped() })
    private let status: (VMStatus) -> Void
    init(status: @escaping (VMStatus) -> Void) { self.status = status }
    private func report(_ value: VMStatus) { DispatchQueue.main.async { self.status(value) } }
    func start(preparer: DiskPreparer, seed: PreparedSeed) {
        queue.async {
            guard self.machine == nil, !self.starting, !self.stopping else { self.report(.failed(HostError.busy.localizedDescription, running: self.machine != nil)); return }
            self.starting = true; self.shutdown.reset(); self.currentRun = nil; self.authenticatedShutdown = nil; self.preparer = preparer; self.report(.starting)
            do {
                let config = try VMConfigurationFactory().make(preparer: preparer, seed: seed)
                let vm = VZVirtualMachine(configuration: config, queue: self.queue)
                vm.delegate = self; self.machine = vm
                let forwarding = LoopbackForwarder(connector: { [weak self] port, completion in
                    guard let self else { completion(.failure(HostError.invalid("本机服务已停止"))); return }
                    self.queue.async {
                        self.connectorAttemptCounter += 1
                        let attempt = self.connectorAttemptCounter
                        let stateString = self.machine.map { $0.state.description } ?? "none"
                        let stopPhase = self.shutdown.phase.description
                        self.recordVsockDiagnostic(attempt: attempt, port: port, details: "event=connector-entry machineState=\(stateString) finishing=\(self.finishing) stopPhase=\(stopPhase)")

                        guard let machine = self.machine else {
                            self.recordVsockDiagnostic(attempt: attempt, port: port, details: "event=connector-rejected reason=missing-machine machineState=none finishing=\(self.finishing) stopPhase=\(stopPhase)")
                            completion(.failure(HostError.invalid("本机服务仍在启动")))
                            return
                        }
                        let socketDevice = machine.socketDevices.first as? VZVirtioSocketDevice
                        let gate = Self.evaluateConnectorGate(
                            port: port,
                            machineState: machine.state,
                            hasSocketDevice: socketDevice != nil,
                            finishing: self.finishing
                        )
                        guard gate.authorized, let socket = socketDevice else {
                            let reason = gate.rejectionReason ?? "unknown"
                            self.recordVsockDiagnostic(attempt: attempt, port: port, details: "event=connector-rejected reason=\(reason) machineState=\(stateString) finishing=\(self.finishing) stopPhase=\(stopPhase)")
                            completion(.failure(HostError.invalid("本机服务仍在启动")))
                            return
                        }
                        self.recordVsockDiagnostic(attempt: attempt, port: port, details: "event=connect-dispatched")
                        socket.connect(toPort: port) { [weak self] result in
                            guard let self else { completion(.failure(HostError.invalid("本机服务已停止"))); return }
                            self.queue.async {
                                switch result {
                                case .failure(let error):
                                    let nsError = error as NSError
                                    self.recordVsockDiagnostic(attempt: attempt, port: port, details: "event=connect-completed-failure domain=\(nsError.domain) code=\(nsError.code)")
                                    completion(.failure(error))
                                case .success(let connection):
                                    self.recordVsockDiagnostic(attempt: attempt, port: port, details: "event=connect-completed-success")
                                    guard self.machine === machine, machine.state == .running, !self.finishing else {
                                        let postState = self.machine.map { $0.state.description } ?? "none"
                                        self.recordVsockDiagnostic(attempt: attempt, port: port, details: "event=connect-postcheck-rejected sameMachine=\(self.machine === machine) machineState=\(postState) finishing=\(self.finishing)")
                                        connection.close(); completion(.failure(HostError.invalid("本机服务已停止"))); return
                                    }
                                    let fd = fcntl(connection.fileDescriptor, F_DUPFD_CLOEXEC, 0)
                                    // Retain VZ's owner until the forwarding pump closes the
                                    // duplicate. Never overwrite an unreleased/reused fd slot.
                                    guard fd >= 0, self.socketConnections[fd] == nil else {
                                        self.recordVsockDiagnostic(attempt: attempt, port: port, details: "event=connect-fd-failed dupFD=\(fd >= 0) slotAvailable=\(fd >= 0 ? self.socketConnections[fd] == nil : false)")
                                        if fd >= 0 { close(fd) }; connection.close(); completion(.failure(HostError.unsafeState)); return
                                    }
                                    self.socketConnections[fd] = connection
                                    self.recordVsockDiagnostic(attempt: attempt, port: port, details: "event=connected; VZ owner retained")
                                    completion(.success(fd))
                                }
                            }
                        }
                    }
                }, releaseGuest: { [weak self] fd in
                    self?.queue.async { self?.socketConnections.removeValue(forKey: fd)?.close() }
                }, failure: { [weak self] error in
                    self?.queue.async { self?.report(.failed(error.localizedDescription, running: true)); self?.requestStop() }
                })
                self.forwarding = forwarding
                forwarding.start { result in
                    self.queue.async {
                        switch result {
                        case .failure(let error): self.starting = false; self.report(.failed(error.localizedDescription, running: false)); self.finishStopped(reportStatus: false)
                        case .success(let endpoints):
                            vm.start { result in
                                self.starting = false
                                switch result {
                                case .failure(let error): self.report(.failed(error.localizedDescription, running: false)); self.finishStopped(reportStatus: false)
                                case .success:
                                    if self.stopRequested { self.requestStop() }
                                    else {
                                        let run = RunningInstance(endpoints: endpoints, seed: seed)
                                        self.currentRun = run; self.report(.running(run))
                                    }
                                }
                            }
                        }
                    }
                }
            } catch { self.starting = false; self.report(.failed(error.localizedDescription, running: false)); self.finishStopped(reportStatus: false) }
        }
    }
    private func recordSocketResult(port: UInt32, error: Error?) {
        let outcome: String
        if let error { let value = error as NSError; outcome = "error domain=\(value.domain) code=\(value.code)" }
        else { outcome = "connected; VZ owner retained" }
        recordVsockDiagnostic(attempt: 0, port: port, details: outcome)
    }
    func useAuthenticatedShutdown(for run: RunningInstance, request: @escaping GuestShutdownRequest) {
        queue.async {
            guard self.currentRun?.sessionID == run.sessionID, self.machine?.state == .running, !self.finishing else { return }
            let upgradePendingRequest = self.shutdown.requested && self.authenticatedShutdown == nil
            self.authenticatedShutdown = request
            if upgradePendingRequest { self.shutdown.reset(); self.requestStop() }
        }
    }
    func stop(failure: @escaping (String) -> Void = { _ in }, completion: @escaping () -> Void = {}) {
        queue.async { self.onStopped.append(StopObserver(completed: completion, failed: failure)); self.requestStop() }
    }
    private func requestStop() {
        let vm = machine
        let authenticated = authenticatedShutdown
        shutdown.requestAsync(starting: starting, alreadyStopped: vm == nil || vm?.state == .stopped,
                              canRequestStop: authenticated != nil || vm?.canRequestStop == true) { completed in
            if let authenticated {
                authenticated { result in self.queue.async { completed(result) } }
            } else {
                do { try vm?.requestStop(); completed(.success(())) }
                catch { completed(.failure(error)) }
            }
        }
    }
    private func stopFailed(_ message: String) {
        // No VM, lock, socket owner or forwarding cleanup on rejection/timeout.
        report(.failed(message, running: true))
        let callbacks = onStopped; onStopped.removeAll()
        DispatchQueue.main.async { callbacks.forEach { $0.failed(message) } }
    }
    private func finishStopped(reportStatus: Bool = true) {
        guard !finishing else { return }; finishing = true
        let finish = {
            self.socketConnections.values.forEach { $0.close() }; self.socketConnections.removeAll()
            self.forwarding = nil; self.authenticatedShutdown = nil; self.currentRun = nil; self.machine = nil; self.preparer = nil
            self.starting = false; self.finishing = false; self.shutdown.reset()
            let callbacks = self.onStopped; self.onStopped.removeAll()
            if reportStatus { self.report(.stopped) }
            DispatchQueue.main.async { callbacks.forEach { $0.completed() } }
        }
        if let forwarding { forwarding.stop { self.queue.async(execute: DispatchWorkItem(block: finish)) } }
        else { finish() }
    }
    func guestDidStop(_ virtualMachine: VZVirtualMachine) { queue.async { if self.machine === virtualMachine { self.shutdown.guestDidStop() } } }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        queue.async {
            guard self.machine === virtualMachine else { return }
            self.shutdown.reset()
            let callbacks = self.onStopped; self.onStopped.removeAll()
            DispatchQueue.main.async { callbacks.forEach { $0.failed("本机服务意外停止，关机状态未通过确认。") } }
            self.report(.failed(error.localizedDescription, running: false)); self.finishStopped(reportStatus: false)
        }
    }
}

@available(macOS 13.0, *)
extension VZVirtualMachine.State {
    var description: String {
        switch self {
        case .stopped: return "stopped"
        case .running: return "running"
        case .paused: return "paused"
        case .error: return "error"
        case .starting: return "starting"
        case .pausing: return "pausing"
        case .resuming: return "resuming"
        case .stopping: return "stopping"
        case .saving: return "saving"
        case .restoring: return "restoring"
        @unknown default: return "unknown(\(rawValue))"
        }
    }
}

extension GracefulStopGate.Phase {
    var description: String {
        switch self {
        case .idle: return "idle"
        case .waitingForStart: return "waitingForStart"
        case .waitingForGuest: return "waitingForGuest"
        case .completed: return "completed"
        }
    }
}

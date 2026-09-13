import Foundation
import Darwin

enum GuestRoute: CaseIterable {
    case http, ssh
    var guestPort: UInt32 { self == .http ? 18080 : 22022 }
    var hostPort: UInt16 { self == .http ? 8080 : 0 }
}
struct LocalEndpoints { let httpPort: UInt16; let sshPort: UInt16 }

// One serial-queue direction, bounded to one 64 KiB buffer. The owning pump
// closes descriptors only after both directions' dispatch sources are cancelled.
private final class StreamDirection {
    private let input: Int32, output: Int32
    private let reader: DispatchSourceRead
    private let writer: DispatchSourceWrite
    private let onEOF: () -> Void, onError: () -> Void
    private var readSuspended = true, writeSuspended = true, stopped = false
    private var pending = Data()
    private var offset = 0
    init(input: Int32, output: Int32, queue: DispatchQueue, onEOF: @escaping () -> Void, onError: @escaping () -> Void) {
        self.input = input; self.output = output; self.onEOF = onEOF; self.onError = onError
        reader = DispatchSource.makeReadSource(fileDescriptor: input, queue: queue)
        writer = DispatchSource.makeWriteSource(fileDescriptor: output, queue: queue)
    }
    func start() {
        reader.setEventHandler { [weak self] in self?.read() }
        writer.setEventHandler { [weak self] in self?.write() }
        readSuspended = false; reader.resume()
    }
    func stop(completion: @escaping () -> Void) {
        guard !stopped else { return }; stopped = true
        var cancelled = 0
        let finished = { cancelled += 1; if cancelled == 2 { completion() } }
        reader.setCancelHandler(handler: finished); writer.setCancelHandler(handler: finished)
        if readSuspended { readSuspended = false; reader.resume() }
        if writeSuspended { writeSuspended = false; writer.resume() }
        reader.cancel(); writer.cancel(); pending.removeAll()
    }
    private func read() {
        guard !stopped else { return }
        var bytes = [UInt8](repeating: 0, count: 65536)
        let count = Darwin.read(input, &bytes, bytes.count)
        if count < 0 {
            if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { return }; onError(); return
        }
        readSuspended = true; reader.suspend()
        if count == 0 { shutdown(output, SHUT_WR); onEOF(); return }
        pending = Data(bytes.prefix(count)); offset = 0; write()
    }
    private func write() {
        guard !stopped else { return }
        while offset < pending.count {
            let count = pending.withUnsafeBytes { Darwin.write(output, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0 && errno == EINTR { continue }
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                if writeSuspended { writeSuspended = false; writer.resume() }; return
            }
            guard count > 0 else { onError(); return }; offset += count
        }
        if !writeSuspended { writeSuspended = true; writer.suspend() }
        pending.removeAll(keepingCapacity: true); offset = 0
        if readSuspended { readSuspended = false; reader.resume() }
    }
}

private final class SocketBytePump {
    private let host: Int32, guest: Int32
    private let queue: DispatchQueue
    private let onClose: () -> Void
    private var directions: [StreamDirection] = []
    private var stopped = false, closed = false
    private var eofCount = 0
    init(host: Int32, guest: Int32, queue: DispatchQueue, onClose: @escaping () -> Void) {
        self.host = host; self.guest = guest; self.queue = queue; self.onClose = onClose
    }
    func start() {
        for fd in [host, guest] {
            var yes: Int32 = 1
            guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0,
                  fcntl(fd, F_SETFD, FD_CLOEXEC) == 0,
                  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size)) == 0 else { stop(); return }
        }
        directions = [(host, guest), (guest, host)].map { input, output in
            StreamDirection(input: input, output: output, queue: queue, onEOF: { [weak self] in
                guard let self else { return }; self.eofCount += 1; if self.eofCount == 2 { self.stop() }
            }, onError: { [weak self] in self?.stop() })
        }
        directions.forEach { $0.start() }
    }
    func stop() {
        guard !stopped else { return }; stopped = true
        shutdown(host, SHUT_RDWR); shutdown(guest, SHUT_RDWR)
        if directions.isEmpty { finish(); return }
        var remaining = directions.count
        for direction in directions {
            direction.stop { [self] in remaining -= 1; if remaining == 0 { finish() } }
        }
    }
    private func finish() {
        guard !closed else { return }; closed = true
        close(host); close(guest); directions.removeAll(); onClose()
    }
}

// NWParameters.allowLocalEndpointReuse combines SO_REUSEADDR and SO_REUSEPORT.
// A BSD listener permits the needed TIME_WAIT reuse without duplicate listeners:
// only SO_REUSEADDR is enabled, and the bound fd remains owned until cancellation.
private final class ExclusiveListener {
    let port: UInt16
    private let source: DispatchSourceRead
    init(port: UInt16, queue: DispatchQueue, accepted: @escaping (Int32) -> Void, failed: @escaping (Error) -> Void, closed: @escaping () -> Void) throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        let guardFD = socket(AF_INET, SOCK_STREAM, 0)
        guard guardFD >= 0 else { if fd >= 0 { close(fd) }; throw HostError.unsafeState }
        guard fd >= 0 else { close(guardFD); throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var owned = false
        defer { if !owned { close(fd); close(guardFD) } }
        var yes: Int32 = 1, no: Int32 = 0
        guard setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size)) == 0,
              setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &no, socklen_t(MemoryLayout<Int32>.size)) == 0,
              fcntl(fd, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        // A non-listening wildcard guard prevents SO_REUSEADDR from shadowing
        // an existing wildcard SO_REUSEPORT listener. It accepts no traffic.
        guard setsockopt(guardFD, SOL_SOCKET, SO_REUSEADDR, &yes, 4) == 0,
              setsockopt(guardFD, SOL_SOCKET, SO_REUSEPORT, &no, 4) == 0,
              fcntl(guardFD, F_SETFD, FD_CLOEXEC) == 0 else { throw HostError.unsafeState }
        var reservation = sockaddr_in()
        reservation.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); reservation.sin_family = sa_family_t(AF_INET)
        reservation.sin_addr.s_addr = INADDR_ANY; reservation.sin_port = port.bigEndian
        guard withUnsafePointer(to: &reservation, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(guardFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }) == 0 else {
            if errno == EADDRINUSE { throw HostError.invalid("本机应用端口已被其他程序占用，请关闭占用程序后重试") }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var reservationLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to: &reservation, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(guardFD, $0, &reservationLength) } }) == 0 else { throw HostError.unsafeState }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1"); address.sin_port = reservation.sin_port
        let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard bound == 0, listen(fd, 32) == 0 else {
            if errno == EADDRINUSE { throw HostError.invalid("本机应用端口已被其他程序占用，请关闭占用程序后重试") }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }) == 0 else { throw HostError.unsafeState }
        self.port = UInt16(bigEndian: address.sin_port)
        source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler {
            for _ in 0..<64 {
                let client = accept(fd, nil, nil)
                if client < 0 {
                    if errno == EINTR { continue }
                    if errno != EAGAIN && errno != EWOULDBLOCK { failed(POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)) }
                    return
                }
                accepted(client)
            }
        }
        source.setCancelHandler { close(fd); close(guardFD); closed() }
        owned = true; source.resume()
    }
    func stop() { source.cancel() }
    deinit { source.cancel() }
}

final class LoopbackForwarder {
    typealias Connector = (UInt32, @escaping (Result<Int32, Error>) -> Void) -> Void
    private let queue = DispatchQueue(label: "com.acornfox.loopback")
    private let connector: Connector
    private let httpPort: UInt16
    private var listeners: [GuestRoute: ExclusiveListener] = [:]
    private var pending: [UUID: Int32] = [:]
    private var pumps: [UUID: SocketBytePump] = [:]
    private var stopped = true, stopping = false
    private var stopCallbacks: [() -> Void] = []
    private let failure: (Error) -> Void
    private let releaseGuest: (Int32) -> Void
    init(httpPort: UInt16 = 8080, connector: @escaping Connector, releaseGuest: @escaping (Int32) -> Void = { _ in }, failure: @escaping (Error) -> Void) {
        self.httpPort = httpPort; self.connector = connector; self.releaseGuest = releaseGuest; self.failure = failure
    }
    func start(completion: @escaping (Result<LocalEndpoints, Error>) -> Void) {
        queue.async {
            guard self.stopped, !self.stopping else { completion(.failure(HostError.busy)); return }
            self.stopped = false
            do {
                for route in GuestRoute.allCases {
                    self.listeners[route] = try ExclusiveListener(port: route == .http ? self.httpPort : route.hostPort, queue: self.queue,
                        accepted: { [weak self] fd in guard let self else { close(fd); return }; self.accept(fd, route: route) },
                        failed: { [weak self] error in self?.fail(error) },
                        closed: { [weak self] in self?.listeners.removeValue(forKey: route); self?.finishStop() })
                }
                completion(.success(LocalEndpoints(httpPort: self.listeners[.http]!.port, sshPort: self.listeners[.ssh]!.port)))
            } catch { self.stopOnQueue { completion(.failure(error)) } }
        }
    }
    // Completion means listener fds and every active/pending connection are closed,
    // not merely that asynchronous cancellation has been requested.
    func stop(completion: @escaping () -> Void = {}) { queue.async { self.stopOnQueue(completion: completion) } }
    private func accept(_ host: Int32, route: GuestRoute) {
        guard !stopped, pending.count + pumps.count < 32 else { close(host); return }
        guard fcntl(host, F_SETFD, FD_CLOEXEC) == 0 else { close(host); return }
        let id = UUID(); pending[id] = host
        let releaseGuest = self.releaseGuest
        connector(route.guestPort) { [weak self] result in
            guard let self else { if case .success(let guest) = result { close(guest); releaseGuest(guest) }; return }
            self.queue.async {
                guard let host = self.pending.removeValue(forKey: id) else { if case .success(let guest) = result { close(guest); releaseGuest(guest) }; return }
                switch result {
                case .failure: close(host)
                case .success(let guest):
                    let pump = SocketBytePump(host: host, guest: guest, queue: self.queue) { [weak self] in releaseGuest(guest); self?.pumps.removeValue(forKey: id); self?.finishStop() }
                    self.pumps[id] = pump; pump.start()
                }
            }
        }
        queue.asyncAfter(deadline: .now() + 10) { [weak self] in if let host = self?.pending.removeValue(forKey: id) { close(host) } }
    }
    private func fail(_ error: Error) { guard !stopped else { return }; stopOnQueue { self.failure(error) } }
    private func stopOnQueue(completion: @escaping () -> Void) {
        stopCallbacks.append(completion)
        if stopping { return }
        stopped = true; stopping = true
        Array(listeners.values).forEach { $0.stop() }
        pending.values.forEach { close($0) }; pending.removeAll()
        Array(pumps.values).forEach { $0.stop() }
        finishStop()
    }
    private func finishStop() {
        guard stopping, listeners.isEmpty, pumps.isEmpty, pending.isEmpty else { return }
        stopping = false
        let callbacks = stopCallbacks; stopCallbacks.removeAll(); callbacks.forEach { $0() }
    }
}

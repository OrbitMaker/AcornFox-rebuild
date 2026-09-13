import Foundation
import Network
import Darwin

@main struct LoopbackForwarderTests {
    static func require(_ value: @autoclosure () -> Bool, _ label: String) throws { if !value() { throw NSError(domain: label, code: 1) } }
    static func wait(_ semaphore: DispatchSemaphore) throws { try require(semaphore.wait(timeout: .now() + 20) == .success, "timeout") }
    static func main() throws {
        try require(GuestRoute.http.guestPort == 18080 && GuestRoute.http.hostPort == 8080, "HTTP fixed mapping")
        try require(GuestRoute.ssh.guestPort == 22022 && GuestRoute.ssh.hostPort == 0, "SSH fixed mapping")
        let stateLock = NSLock(); var mapped = [UInt32]()
        let connector: LoopbackForwarder.Connector = { port, completion in
            stateLock.lock(); mapped.append(port); stateLock.unlock()
            var descriptors = [Int32](repeating: -1, count: 2)
            guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else { completion(.failure(HostError.unsafeState)); return }
            let host = descriptors[0], guest = descriptors[1]
            completion(.success(host))
            DispatchQueue.global().async {
                defer { close(guest) }
                var yes: Int32 = 1; setsockopt(guest, SOL_SOCKET, SO_NOSIGPIPE, &yes, 4)
                var bytes = [UInt8](repeating: 0, count: 8192)
                while true {
                    let count = read(guest, &bytes, bytes.count)
                    if count <= 0 { shutdown(guest, SHUT_WR); return }
                    var offset = 0
                    while offset < count {
                        let wrote = bytes.withUnsafeBytes { write(guest, $0.baseAddress!.advanced(by: offset), count - offset) }
                        if wrote <= 0 { return }; offset += wrote
                    }
                }
            }
        }
        let forwarder = LoopbackForwarder(httpPort: 0, connector: connector, failure: { _ in })
        let started = DispatchSemaphore(value: 0); var startResult: Result<LocalEndpoints, Error>?
        forwarder.start { startResult = $0; started.signal() }; try wait(started)
        let endpoints = try startResult!.get()
        try require(endpoints.httpPort != 0 && endpoints.sshPort != 0 && endpoints.httpPort != endpoints.sshPort, "two bound loopback ports")
        func roundtrip(_ port: UInt16) throws {
            let fd = socket(AF_INET, SOCK_STREAM, 0); try require(fd >= 0, "TCP socket"); defer { close(fd) }
            var timeout = timeval(tv_sec: 10, tv_usec: 0); setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)); setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            var address = sockaddr_in(); address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET); address.sin_port = port.bigEndian; address.sin_addr.s_addr = inet_addr("127.0.0.1")
            let connected = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            try require(connected == 0, "TCP connect")
            let expected = Data("POST /setup HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n".utf8) + Data((0..<2_000_000).map { UInt8($0 % 251) })
            let sent = DispatchSemaphore(value: 0); var writeOK = true
            DispatchQueue.global().async {
                var offset = 0
                while offset < expected.count {
                    let count = expected.withUnsafeBytes { write(fd, $0.baseAddress!.advanced(by: offset), expected.count - offset) }
                    if count <= 0 { writeOK = false; break }; offset += count
                }
                shutdown(fd, SHUT_WR); sent.signal()
            }
            var actual = Data(); var buffer = [UInt8](repeating: 0, count: 32768)
            while true { let count = read(fd, &buffer, buffer.count); if count == 0 { break }; try require(count > 0, "TCP read"); actual.append(contentsOf: buffer.prefix(count)) }
            try wait(sent); try require(writeOK && actual == expected, "byte exact 2 MB full duplex + half close")
        }
        try roundtrip(endpoints.httpPort); try roundtrip(endpoints.sshPort)
        stateLock.lock(); let ports = mapped; stateLock.unlock()
        try require(ports == [18080, 22022], "only fixed guest ports connected")
        print("PASS fixed maps; HTTP Host unchanged; 2 MB simultaneous duplex and half-close on both loopback ports")
        let competitor = LoopbackForwarder(httpPort: endpoints.httpPort, connector: { _, done in done(.failure(HostError.unsafeState)) }, failure: { _ in })
        let competing = DispatchSemaphore(value: 0); var rejected = false
        competitor.start { if case .failure = $0 { rejected = true }; competing.signal() }; try wait(competing)
        try require(rejected, "occupied port fails")
        try roundtrip(endpoints.httpPort)
        print("PASS occupied port rejected without disturbing existing listener")
        let stopped = DispatchSemaphore(value: 0); forwarder.stop { stopped.signal() }; try wait(stopped)
        competitor.stop()
        func start(_ forwarder: LoopbackForwarder) throws -> LocalEndpoints {
            let semaphore = DispatchSemaphore(value: 0); var result: Result<LocalEndpoints, Error>?
            forwarder.start { result = $0; semaphore.signal() }; try wait(semaphore); return try result!.get()
        }
        func stop(_ forwarder: LoopbackForwarder) throws {
            let semaphore = DispatchSemaphore(value: 0); forwarder.stop { semaphore.signal() }; try wait(semaphore)
        }
        func connectClient(_ port: UInt16) throws -> Int32 {
            let fd = socket(AF_INET, SOCK_STREAM, 0); try require(fd >= 0, "client socket")
            var address = sockaddr_in(); address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET); address.sin_port = port.bigEndian; address.sin_addr.s_addr = inet_addr("127.0.0.1")
            let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            if result != 0 { close(fd); throw HostError.unsafeState }; return fd
        }
        // Force the SERVER to close an established connection first. This leaves
        // server-side TIME_WAIT after the peer acknowledges FIN and closes.
        var current = LoopbackForwarder(httpPort: endpoints.httpPort, connector: connector, failure: { _ in })
        _ = try start(current)
        for _ in 0..<5 {
            let activeClient = try connectClient(endpoints.httpPort)
            var sentByte: UInt8 = 42; try require(write(activeClient, &sentByte, 1) == 1, "active write")
            var received: UInt8 = 0; try require(read(activeClient, &received, 1) == 1 && received == sentByte, "established active connection")
            try stop(current)
            try require(read(activeClient, &received, 1) == 0, "server closes active stream before stop callback")
            close(activeClient)
            current = LoopbackForwarder(httpPort: endpoints.httpPort, connector: connector, failure: { _ in })
            let reopened = try start(current)
            try require(reopened.httpPort == endpoints.httpPort, "immediate same-port restart")
            try roundtrip(reopened.httpPort)
        }
        try stop(current)
        print("PASS five established-server-close immediate same-port restart cycles")
        let legacy = socket(AF_INET, SOCK_STREAM, 0)
        var legacyAddress = sockaddr_in(); legacyAddress.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); legacyAddress.sin_family = sa_family_t(AF_INET); legacyAddress.sin_addr.s_addr = inet_addr("127.0.0.1")
        try require(withUnsafePointer(to: &legacyAddress) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(legacy, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } } == 0 && listen(legacy, 2) == 0, "legacy non-reuse listener")
        var legacySize = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &legacyAddress) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(legacy, $0, &legacySize) } }
        let legacyPort = UInt16(bigEndian: legacyAddress.sin_port)
        let legacyClient = try connectClient(legacyPort); let legacyAccepted = accept(legacy, nil, nil)
        shutdown(legacyAccepted, SHUT_RDWR); close(legacyAccepted)
        var endByte: UInt8 = 0; try require(read(legacyClient, &endByte, 1) == 0, "legacy active close")
        close(legacyClient); close(legacy)
        let afterLegacy = LoopbackForwarder(httpPort: legacyPort, connector: connector, failure: { _ in })
        _ = try start(afterLegacy); try roundtrip(legacyPort); try stop(afterLegacy)
        print("PASS immediate reuse after closed legacy listener with SO_REUSEADDR disabled")
        // A foreign wildcard listener that explicitly allows port sharing still
        // must not be shadowed: this implementation never enables SO_REUSEPORT.
        let foreign = socket(AF_INET, SOCK_STREAM, 0); try require(foreign >= 0, "foreign socket")
        defer { close(foreign) }
        var yes: Int32 = 1
        setsockopt(foreign, SOL_SOCKET, SO_REUSEADDR, &yes, 4); setsockopt(foreign, SOL_SOCKET, SO_REUSEPORT, &yes, 4)
        var address = sockaddr_in(); address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET); address.sin_addr.s_addr = INADDR_ANY
        try require(withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(foreign, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } } == 0, "foreign wildcard bind")
        try require(listen(foreign, 4) == 0, "foreign wildcard listen")
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(foreign, $0, &size) } }
        let foreignPort = UInt16(bigEndian: address.sin_port)
        let denied = LoopbackForwarder(httpPort: foreignPort, connector: connector, failure: { _ in })
        var conflict = false; do { _ = try start(denied) } catch { conflict = true }
        try require(conflict, "foreign wildcard reuseport listener rejected")
        let client = try connectClient(foreignPort); let accepted = accept(foreign, nil, nil)
        try require(accepted >= 0, "foreign listener still receives")
        var byte: UInt8 = 99; try require(write(client, &byte, 1) == 1, "foreign write")
        var received: UInt8 = 0; try require(read(accepted, &received, 1) == 1 && received == byte, "foreign transport untouched")
        close(client); close(accepted); try stop(denied)
        print("PASS foreign wildcard SO_REUSEPORT listener cannot be shadowed and remains functional")
        print("ALL LOOPBACK TESTS PASSED")
    }
}

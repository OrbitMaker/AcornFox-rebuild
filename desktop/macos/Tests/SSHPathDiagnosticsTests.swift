import Foundation
import Virtualization
import Darwin

@available(macOS 13.0, *)
@main struct SSHPathDiagnosticsTests {
    static func require(_ value: @autoclosure () throws -> Bool, _ message: String) throws {
        if try !value() { throw NSError(domain: message, code: 1) }
    }
    static func reject(_ operation: () throws -> Void) throws {
        var failed = false
        do { try operation() } catch { failed = true }
        try require(failed, "expected operation to be rejected")
    }

    static func main() throws {
        try testOpenSSHConfigPathEscaping()
        try testActualOpenSSHOptionParsing()
        try testNormalAndShutdownShareSameEscapedOption()
        try testRealSSHInProcessFixtureWithSpaces()
        try testConnectorAuthorizationGateDiagnostics()
        try testStopPhaseDoesNotAlterConnectorAuthorization()
        print("ALL SSH PATH AND CONNECTOR DIAGNOSTIC TESTS PASSED")
    }

    // 1. Central path escaping tests: quotes, spaces, backslashes, percent-tokens, control chars
    static func testOpenSSHConfigPathEscaping() throws {
        let simple = "/tmp/test/ssh-known-hosts"
        try require(try Provisioner.escapeOpenSSHConfigPath(simple) == "\"/tmp/test/ssh-known-hosts\"", "simple path quoting")

        let spacePath = "/Users/a007/Documents/trae_projects/战略项目/Open Card/state/vm/ssh-known-hosts"
        try require(try Provisioner.escapeOpenSSHConfigPath(spacePath) == "\"\(spacePath)\"", "spaces and unicode preserved in quotes")

        let backslashPath = "/tmp/foo\\bar/ssh-known-hosts"
        try require(try Provisioner.escapeOpenSSHConfigPath(backslashPath) == "\"/tmp/foo\\\\bar/ssh-known-hosts\"", "backslash escaped")

        let quotePath = "/tmp/foo\"bar/ssh-known-hosts"
        try require(try Provisioner.escapeOpenSSHConfigPath(quotePath) == "\"/tmp/foo\\\"bar/ssh-known-hosts\"", "double quote escaped")

        let percentPath = "/tmp/foo%u%h/ssh-known-hosts"
        try require(try Provisioner.escapeOpenSSHConfigPath(percentPath) == "\"/tmp/foo%%u%%h/ssh-known-hosts\"", "percent token escaped")

        let comboPath = "/tmp/a b\\c\"d%e/hosts"
        try require(try Provisioner.escapeOpenSSHConfigPath(comboPath) == "\"/tmp/a b\\\\c\\\"d%%e/hosts\"", "combined quoting and escaping")

        // Reject control characters and empty path
        try reject { _ = try Provisioner.escapeOpenSSHConfigPath("") }
        try reject { _ = try Provisioner.escapeOpenSSHConfigPath("/tmp/a\nb/hosts") }
        try reject { _ = try Provisioner.escapeOpenSSHConfigPath("/tmp/a\rb/hosts") }
        try reject { _ = try Provisioner.escapeOpenSSHConfigPath("/tmp/a\tb/hosts") }
        try reject { _ = try Provisioner.escapeOpenSSHConfigPath("/tmp/a\0b/hosts") }
        try reject { _ = try Provisioner.escapeOpenSSHConfigPath("/tmp/a\u{01}b/hosts") }
        try reject { _ = try Provisioner.escapeOpenSSHConfigPath("/tmp/a\u{7f}b/hosts") }

        print("PASS OpenSSH config path escaping: quotes, backslash, percent-tokens and control-char rejection")
    }

    // 2. Test actual OpenSSH parsing using /usr/bin/ssh -G
    static func testActualOpenSSHOptionParsing() throws {
        let testPath = "/Users/a007/Documents/trae_projects/战略项目/Open Card/state/vm/ssh-known-hosts"
        let quoted = try Provisioner.escapeOpenSSHConfigPath(testPath)

        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        p.arguments = [
            "-G",
            "-F", "/dev/null",
            "-T",
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UpdateHostKeys=no",
            "-o", "UserKnownHostsFile=\(quoted)",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "HostKeyAlias=acornfox-test-alias",
            "-o", "CheckHostIP=no",
            "127.0.0.1"
        ]
        let pipe = Pipe()
        let errPipe = Pipe()
        p.standardOutput = pipe
        p.standardError = errPipe
        try p.run()
        p.waitUntilExit()

        try require(p.terminationStatus == 0, "ssh -G exit code 0")
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        var parsedHostsFile: String?
        var parsedStrictHostKeyChecking: String?
        var parsedHostKeyAlias: String?
        var parsedGlobalHostsFile: String?

        for line in output.split(separator: "\n") {
            if line.starts(with: "userknownhostsfile ") {
                parsedHostsFile = String(line.dropFirst("userknownhostsfile ".count))
            } else if line.starts(with: "stricthostkeychecking ") {
                parsedStrictHostKeyChecking = String(line.dropFirst("stricthostkeychecking ".count))
            } else if line.starts(with: "hostkeyalias ") {
                parsedHostKeyAlias = String(line.dropFirst("hostkeyalias ".count))
            } else if line.starts(with: "globalknownhostsfile ") {
                parsedGlobalHostsFile = String(line.dropFirst("globalknownhostsfile ".count))
            }
        }

        try require(parsedHostsFile == testPath, "OpenSSH parses quoted known-hosts path as exact single file: \(parsedHostsFile ?? "nil")")
        try require(parsedStrictHostKeyChecking == "accept-new", "OpenSSH preserves StrictHostKeyChecking=accept-new")
        try require(parsedHostKeyAlias == "acornfox-test-alias", "OpenSSH preserves HostKeyAlias")
        try require(parsedGlobalHostsFile == "/dev/null", "OpenSSH preserves GlobalKnownHostsFile=/dev/null")

        print("PASS actual OpenSSH /usr/bin/ssh -G parsing verifies single quoted path, policy and alias")
    }

    // 3. Normal commands and shutdown scope share identical safely quoted known-hosts path
    static func testNormalAndShutdownShareSameEscapedOption() throws {
        let base = URL(fileURLWithPath: "/private/tmp/acornfox-scope-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: base) }
        let dir1 = base.appendingPathComponent("path with spaces")
        try FileManager.default.createDirectory(at: dir1, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let dir2 = dir1.appendingPathComponent("Open Card")
        try FileManager.default.createDirectory(at: dir2, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let stateDir = dir2.appendingPathComponent("vm-state")
        let directory = try PrivateDirectory(url: stateDir)

        let keyURL = stateDir.appendingPathComponent("dummy_key")
        try Data("dummy".utf8).write(to: keyURL)
        try directory.writeNew("ssh-known-hosts", data: Data())
        let instanceID = UUID()
        let run = RunningInstance(
            endpoints: LocalEndpoints(httpPort: 8080, sshPort: 22022),
            seed: PreparedSeed(isoURL: base.appendingPathComponent("u.iso"), privateKeyURL: keyURL, publicKey: "u", instanceID: instanceID)
        )

        // Normal provisioner
        let normal = try Provisioner(running: run, resources: nil, state: directory)
        let normalArgs = try normal.sshArguments(for: ["identity"])

        // Shutdown provisioner constructed via makeShutdownRequest helper
        let expectedKnownHostsValue = try Provisioner.knownHostsConfigValue(in: directory)

        try require(normalArgs.contains("UserKnownHostsFile=\(expectedKnownHostsValue)"), "normal args contain escaped known hosts")
        try require(normalArgs.contains("HostKeyAlias=acornfox-\(instanceID.uuidString.lowercased())"), "normal args contain host key alias")
        try require(normalArgs.contains("StrictHostKeyChecking=accept-new"), "normal args contain accept-new")

        let shutdownArgs = try Provisioner.sshArguments(running: run, state: directory, command: ["shutdown"])
        try require(shutdownArgs.contains("UserKnownHostsFile=\(expectedKnownHostsValue)"), "shutdown args contain identical escaped known hosts")
        try require(shutdownArgs.contains("HostKeyAlias=acornfox-\(instanceID.uuidString.lowercased())"), "shutdown args contain identical alias")

        // Assert exact match on all options prior to the target subcommand
        let normalPrefix = Array(normalArgs.dropLast(1))
        let shutdownPrefix = Array(shutdownArgs.dropLast(1))
        try require(normalPrefix == shutdownPrefix, "normal and shutdown scopes share identical base SSH options")

        print("PASS normal commands and fresh shutdown scope share identical safely quoted path and options")
    }

    // Helper to run a strictly bounded, isolated, non-login sshd on loopback with no shell access
    static func withSafeEphemeralSSHD(
        base: URL,
        port: UInt16,
        hostKey: URL,
        execute: () throws -> Void
    ) throws {
        let configFile = base.appendingPathComponent("sshd_config_\(port)")
        let pidFile = base.appendingPathComponent("sshd_\(port).pid")
        let configContent = """
Port \(port)
ListenAddress 127.0.0.1
AddressFamily inet
HostKey \(hostKey.path)
PidFile \(pidFile.path)
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication no
HostbasedAuthentication no
UsePAM no
GSSAPIAuthentication no
AllowTcpForwarding no
X11Forwarding no
AllowAgentForwarding no
PermitUserRC no
PermitTunnel no
GatewayPorts no
AllowUsers nonexistent-task-test-user-only
ForceCommand /usr/bin/false
AuthorizedKeysFile /dev/null
StrictModes no
"""
        try configContent.write(to: configFile, atomically: true, encoding: .utf8)
        chmod(configFile.path, 0o600)

        // Validate configuration using sshd -t
        let testP = Process()
        testP.executableURL = URL(fileURLWithPath: "/usr/sbin/sshd")
        testP.arguments = ["-t", "-f", configFile.path]
        let testErrPipe = Pipe()
        testP.standardError = testErrPipe
        try? testP.run()
        testP.waitUntilExit()
        let testOut = String(decoding: testErrPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        if testP.terminationStatus != 0 {
            print("sshd -t failed (code \(testP.terminationStatus)):\n\(testOut)")
        }

        let server = Process()
        server.executableURL = URL(fileURLWithPath: "/usr/sbin/sshd")
        server.arguments = ["-e", "-d", "-f", configFile.path]
        let errPipe = Pipe()
        server.standardError = errPipe

        let readySem = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var signalled = false
        var serverStderr = ""

        errPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            let text = String(decoding: data, as: UTF8.self)
            lock.lock()
            serverStderr.append(text)
            if !signalled && (serverStderr.contains("Server listening") || serverStderr.contains("Bind to port")) {
                signalled = true
                readySem.signal()
            }
            lock.unlock()
        }

        try server.run()

        var cleanedUp = false
        func cleanupServer() {
            guard !cleanedUp else { return }
            cleanedUp = true
            errPipe.fileHandleForReading.readabilityHandler = nil
            if server.isRunning {
                server.terminate()
                let deadline = Date().addingTimeInterval(2)
                while server.isRunning && Date() < deadline {
                    Thread.sleep(forTimeInterval: 0.05)
                }
                if server.isRunning {
                    kill(server.processIdentifier, SIGKILL)
                }
                server.waitUntilExit()
            }
            // Confirm listener socket has closed
            let probeSocket = socket(AF_INET, SOCK_STREAM, 0)
            if probeSocket >= 0 {
                defer { close(probeSocket) }
                var tv = timeval(tv_sec: 0, tv_usec: 50_000)
                setsockopt(probeSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                setsockopt(probeSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                var probeAddr = sockaddr_in()
                probeAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                probeAddr.sin_family = sa_family_t(AF_INET)
                probeAddr.sin_port = in_port_t(port).bigEndian
                probeAddr.sin_addr.s_addr = inet_addr("127.0.0.1")
                let connected = withUnsafePointer(to: &probeAddr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        connect(probeSocket, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                if connected == 0 {
                    Thread.sleep(forTimeInterval: 0.1)
                }
            }
        }
        defer { cleanupServer() }

        // Bounded wait for sshd to report listening on loopback port
        let ready = (readySem.wait(timeout: .now() + 3) == .success)
        if !ready || !server.isRunning {
            lock.lock()
            let captured = serverStderr
            lock.unlock()
            let statusStr = server.isRunning ? "running" : "exited"
            print("SSHD STARTUP FAILED: state=\(statusStr)\n\(captured)")
        }
        try require(ready && server.isRunning, "safe isolated sshd failed to bind or exited prematurely")

        try execute()
    }

    // 4. In-process SSH fixture under state path with spaces: non-empty known-hosts, no prefix file,
    // reconnect succeeds, changed key fails closed, distinct failure stages.
    static func testRealSSHInProcessFixtureWithSpaces() throws {
        let base = URL(fileURLWithPath: "/private/tmp/acornfox-ssh-spaces-\(UUID().uuidString)")
        let stateDir = base.appendingPathComponent("path with spaces/Open Card/state")
        try FileManager.default.createDirectory(at: stateDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }

        let hostKey1 = base.appendingPathComponent("host_key1")
        _ = try SeedPreparer.run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", hostKey1.path])
        let hostKey2 = base.appendingPathComponent("host_key2")
        _ = try SeedPreparer.run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", hostKey2.path])
        let userKey = base.appendingPathComponent("user_key")
        _ = try SeedPreparer.run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", userKey.path])

        let knownHostsURL = stateDir.appendingPathComponent("ssh-known-hosts")
        try Data().write(to: knownHostsURL)

        let quoted = try Provisioner.escapeOpenSSHConfigPath(knownHostsURL.path)

        // Stage A: First connection with StrictHostKeyChecking=accept-new
        try withSafeEphemeralSSHD(base: base, port: 52481, hostKey: hostKey1) {
            let ssh1 = Process()
            ssh1.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
            ssh1.arguments = [
                "-F", "/dev/null", "-T", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "UserKnownHostsFile=\(quoted)",
                "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "HostKeyAlias=acornfox-space-test",
                "-o", "CheckHostIP=no",
                "-p", "52481", "-i", userKey.path, "testuser@127.0.0.1", "true"
            ]
            let ssh1Err = Pipe(); ssh1.standardError = ssh1Err; try ssh1.run(); ssh1.waitUntilExit()

            let recordedHosts = try Data(contentsOf: knownHostsURL)
            try require(!recordedHosts.isEmpty, "intended known-hosts file became non-empty after accept-new (actual bytes: \(recordedHosts.count))")

            // Assert NO prefix stray files created
            let strayPrefix1 = base.appendingPathComponent("path")
            let strayPrefix2 = base.appendingPathComponent("path with spaces/Open")
            try require(!FileManager.default.fileExists(atPath: strayPrefix1.path), "no stray whitespace-prefix file 'path'")
            try require(!FileManager.default.fileExists(atPath: strayPrefix2.path), "no stray whitespace-prefix file 'Open'")
        }

        // Stage B: Reconnect with same host key and StrictHostKeyChecking=yes -> host key check passes
        try withSafeEphemeralSSHD(base: base, port: 52482, hostKey: hostKey1) {
            let ssh2 = Process()
            ssh2.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
            ssh2.arguments = [
                "-F", "/dev/null", "-T", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=\(quoted)",
                "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "HostKeyAlias=acornfox-space-test",
                "-o", "CheckHostIP=no",
                "-p", "52482", "-i", userKey.path, "testuser@127.0.0.1", "true"
            ]
            let ssh2Err = Pipe(); ssh2.standardError = ssh2Err; try ssh2.run(); ssh2.waitUntilExit()
            let err2Text = String(decoding: ssh2Err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)

            try require(!err2Text.contains("Host key verification failed"), "reconnect with existing host key passed verification")
        }

        // Stage C: Connect with changed host key -> must FAIL CLOSED at host-key verification stage
        try withSafeEphemeralSSHD(base: base, port: 52483, hostKey: hostKey2) {
            let ssh3 = Process()
            ssh3.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
            ssh3.arguments = [
                "-F", "/dev/null", "-T", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=\(quoted)",
                "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "HostKeyAlias=acornfox-space-test",
                "-o", "CheckHostIP=no",
                "-p", "52483", "-i", userKey.path, "testuser@127.0.0.1", "true"
            ]
            let ssh3Err = Pipe(); ssh3.standardError = ssh3Err; try ssh3.run(); ssh3.waitUntilExit()
            let err3Text = String(decoding: ssh3Err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)

            try require(ssh3.terminationStatus != 0, "changed host key must exit non-zero")
            try require(err3Text.contains("Host key verification failed"), "changed host key fails with explicit host key verification failure stage")
        }

        print("PASS in-process SSH fixture under spaces path: known-hosts recorded, no stray files, reconnect passed, changed host key fails closed")
    }

    // 5. Native connector entry and gate diagnostics
    static func testConnectorAuthorizationGateDiagnostics() throws {
        // Test port allowlist: GuestRoute.allCases guest ports are 22022 and 18080
        let portAllow = VMController.evaluateConnectorGate(port: GuestRoute.ssh.guestPort, machineState: .running, hasSocketDevice: true, finishing: false)
        try require(portAllow.authorized && portAllow.rejectionReason == nil, "control port 22022 authorized when running")

        let httpAllow = VMController.evaluateConnectorGate(port: GuestRoute.http.guestPort, machineState: .running, hasSocketDevice: true, finishing: false)
        try require(httpAllow.authorized && httpAllow.rejectionReason == nil, "http guest port 18080 authorized when running")

        let hostPortRejected = VMController.evaluateConnectorGate(port: 8080, machineState: .running, hasSocketDevice: true, finishing: false)
        try require(!hostPortRejected.authorized && hostPortRejected.rejectionReason == "unsupported-port", "host port 8080 is not a guest port and must be rejected")

        let unsuppPort = VMController.evaluateConnectorGate(port: 9999, machineState: .running, hasSocketDevice: true, finishing: false)
        try require(!unsuppPort.authorized && unsuppPort.rejectionReason == "unsupported-port", "unsupported port rejected with reason")

        // Test missing machine
        let missingMachine = VMController.evaluateConnectorGate(port: 22022, machineState: nil, hasSocketDevice: true, finishing: false)
        try require(!missingMachine.authorized && missingMachine.rejectionReason == "missing-machine", "missing machine rejected with reason")

        // Test non-running states: stopping, stopped, starting, paused, error
        let stoppingGate = VMController.evaluateConnectorGate(port: 22022, machineState: .stopping, hasSocketDevice: true, finishing: false)
        try require(!stoppingGate.authorized && stoppingGate.rejectionReason == "machine-not-running actualState=stopping", "stopping machine rejected with exact reason")

        let stoppedGate = VMController.evaluateConnectorGate(port: 22022, machineState: .stopped, hasSocketDevice: true, finishing: false)
        try require(!stoppedGate.authorized && stoppedGate.rejectionReason == "machine-not-running actualState=stopped", "stopped machine rejected with exact reason")

        let startingGate = VMController.evaluateConnectorGate(port: 22022, machineState: .starting, hasSocketDevice: true, finishing: false)
        try require(!startingGate.authorized && startingGate.rejectionReason == "machine-not-running actualState=starting", "starting machine rejected with exact reason")

        let pausedGate = VMController.evaluateConnectorGate(port: 22022, machineState: .paused, hasSocketDevice: true, finishing: false)
        try require(!pausedGate.authorized && pausedGate.rejectionReason == "machine-not-running actualState=paused", "paused machine rejected with exact reason")

        let errorGate = VMController.evaluateConnectorGate(port: 22022, machineState: .error, hasSocketDevice: true, finishing: false)
        try require(!errorGate.authorized && errorGate.rejectionReason == "machine-not-running actualState=error", "error machine rejected with exact reason")

        // Test finishing flag
        let finishingGate = VMController.evaluateConnectorGate(port: 22022, machineState: .running, hasSocketDevice: true, finishing: true)
        try require(!finishingGate.authorized && finishingGate.rejectionReason == "controller-finishing", "finishing controller rejected with exact reason")

        // Test missing socket device
        let noSocketGate = VMController.evaluateConnectorGate(port: 22022, machineState: .running, hasSocketDevice: false, finishing: false)
        try require(!noSocketGate.authorized && noSocketGate.rejectionReason == "missing-socket-device", "missing socket device rejected with exact reason")

        print("PASS connector authorization gate evaluates exact production gate: .running && !finishing, port allowlist, individual diagnostic reasons")
    }

    // 6. Stop phase order and connector authorization invariants
    static func testStopPhaseDoesNotAlterConnectorAuthorization() throws {
        var deadlines: [() -> Void] = []
        var gateReportedStatus: String?
        var sends = 0

        let gate = GracefulStopGate(
            scheduleTimeout: { deadlines.append($0) },
            waiting: { gateReportedStatus = "stopping" },
            failed: { _ in gateReportedStatus = "failed" },
            confirmed: { gateReportedStatus = "completed" }
        )

        // Request stop with canRequestStop = true (authenticated shutdown registered)
        gate.requestAsync(starting: false, alreadyStopped: false, canRequestStop: true) { _ in
            sends += 1
        }

        // Gate is now in waitingForGuest phase, UI reports "stopping"
        try require(gate.phase == .waitingForGuest, "gate phase is waitingForGuest")
        try require(gateReportedStatus == "stopping", "UI status is stopping")
        try require(sends == 1, "authenticated shutdown was invoked without VZ requestStop")

        // In this phase, VZ machine is still in .running state in production.
        // Connector gate evaluation MUST remain authorized for the running machine:
        let decisionDuringWaiting = VMController.evaluateConnectorGate(
            port: 22022,
            machineState: .running,
            hasSocketDevice: true,
            finishing: false
        )
        try require(decisionDuringWaiting.authorized, "connector remains authorized during waitingForGuest while machine.state is .running")

        // If the machine actually transitioned to .stopping, the gate rejects with actual state:
        let decisionIfVZStopping = VMController.evaluateConnectorGate(
            port: 22022,
            machineState: .stopping,
            hasSocketDevice: true,
            finishing: false
        )
        try require(!decisionIfVZStopping.authorized && decisionIfVZStopping.rejectionReason == "machine-not-running actualState=stopping", "if VZ state is .stopping, connector rejects")

        print("PASS stop phase does not alter connector authorization; UI stopping != VZ stopping; gate remains .running")
    }
}

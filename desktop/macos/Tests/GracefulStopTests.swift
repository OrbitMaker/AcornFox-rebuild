import Foundation
import Darwin

@main struct GracefulStopTests {
    static func require(_ value: @autoclosure () throws -> Bool, _ label: String) throws { if try !value() { throw NSError(domain: label, code: 1) } }
    static func busy(_ directory: PrivateDirectory) throws {
        var rejected = false
        do { _ = try InstanceLock(directory: directory) } catch HostError.busy { rejected = true }
        try require(rejected, "instance lock must remain held")
    }
    static func main() throws {
        let root = URL(fileURLWithPath: "/private/tmp/acornfox-shutdown-tests-\(UUID().uuidString)")
        let directory = try PrivateDirectory(url: root)
        defer { try? FileManager.default.removeItem(at: root) }
        var held: InstanceLock? = try InstanceLock(directory: directory)
        var deadlines: [() -> Void] = [], failures: [String] = []
        var sends = 0, cleanups = 0, forwardingAlive = true
        let gate = GracefulStopGate(scheduleTimeout: { deadlines.append($0) }, waiting: {}, failed: { failures.append($0) }, confirmed: {
            cleanups += 1; forwardingAlive = false; held = nil
        })
        gate.request(starting: false, alreadyStopped: false, canRequestStop: true) { sends += 1 }
        try require(gate.phase == .waitingForGuest && sends == 1 && cleanups == 0 && forwardingAlive, "request is not shutdown completion")
        try busy(directory)
        gate.request(starting: false, alreadyStopped: false, canRequestStop: true) { sends += 1 }
        try require(sends == 1, "duplicate in-flight stop must not resend")
        deadlines[0]()
        try require(failures.count == 1 && cleanups == 0 && forwardingAlive, "timeout retains VM resources and forwarder")
        try busy(directory)
        gate.request(starting: false, alreadyStopped: false, canRequestStop: true) { sends += 1 }
        try require(sends == 2 && deadlines.count == 2, "retry is another graceful request")
        deadlines[0]()
        try require(failures.count == 1 && gate.phase == .waitingForGuest, "stale timeout cannot cancel retry")
        gate.guestDidStop()
        try require(cleanups == 1 && !forwardingAlive && held == nil, "only guest event releases resources")
        _ = try InstanceLock(directory: directory)
        deadlines[1](); gate.guestDidStop()
        try require(cleanups == 1 && failures.count == 1, "late timeout or duplicate guest event has no effect")
        print("PASS accepted request waits for guest event; timeout/retry retain real instance lock and forwarding")

        held = try InstanceLock(directory: directory); forwardingAlive = true
        gate.reset(); let priorSends = sends, priorCleanup = cleanups
        gate.request(starting: true, alreadyStopped: false, canRequestStop: false) { sends += 1 }
        try require(gate.phase == .waitingForStart && sends == priorSends && cleanups == priorCleanup, "startup stop deferred")
        try busy(directory)
        let startupDeadline = deadlines.last!
        startupDeadline()
        try require(cleanups == priorCleanup && sends == priorSends && forwardingAlive && gate.phase == .idle, "startup timeout retains everything without guest power operation")
        try busy(directory)
        gate.request(starting: true, alreadyStopped: false, canRequestStop: false) { sends += 1 }
        gate.request(starting: false, alreadyStopped: false, canRequestStop: true) { sends += 1 }
        startupDeadline()
        try require(sends == priorSends + 1 && gate.phase == .waitingForGuest && forwardingAlive, "startup completion requests guest power button")
        gate.guestDidStop()
        try require(cleanups == priorCleanup + 1, "startup stop completes after guest event")
        print("PASS startup timeout retains resources; successful startup then requests guest shutdown")

        held = try InstanceLock(directory: directory); forwardingAlive = true; gate.reset()
        let previousCleanup = cleanups, previousSends = sends
        gate.request(starting: false, alreadyStopped: false, canRequestStop: false) { sends += 1 }
        try require(sends == previousSends && cleanups == previousCleanup && forwardingAlive, "unsupported stop preserves resources")
        try busy(directory)
        gate.request(starting: false, alreadyStopped: false, canRequestStop: true) { throw HostError.busy }
        try require(cleanups == previousCleanup && forwardingAlive && gate.phase == .idle, "request error preserves resources")
        try busy(directory)
        print("PASS unsupported and rejected guest shutdown cannot power off or release lock")

        gate.request(starting: false, alreadyStopped: true, canRequestStop: false) { sends += 1 }
        try require(cleanups == previousCleanup + 1 && sends == previousSends, "absent/stopped VM cleanup needs no power operation")
        print("PASS already-stopped VM cleanup")
        held = try InstanceLock(directory: directory); forwardingAlive = true; gate.reset()
        var replies: [(Result<Void, Error>) -> Void] = []
        let countBeforeAsync = cleanups
        gate.requestAsync(starting: false, alreadyStopped: false, canRequestStop: true) { replies.append($0) }
        let oldDeadline = deadlines.last!
        replies[0](.success(()))
        try require(cleanups == countBeforeAsync && gate.phase == .waitingForGuest && forwardingAlive, "SSH success only acknowledges request")
        try busy(directory)
        oldDeadline()
        try require(cleanups == countBeforeAsync && gate.phase == .idle, "acknowledged shutdown still times out without guest event")
        gate.requestAsync(starting: false, alreadyStopped: false, canRequestStop: true) { replies.append($0) }
        let beforeLateReply = failures.count
        replies[0](.failure(HostError.busy)); oldDeadline()
        try require(failures.count == beforeLateReply && gate.phase == .waitingForGuest, "old SSH reply and timer cannot reject a new request")
        replies[1](.failure(HostError.busy))
        try require(cleanups == countBeforeAsync && forwardingAlive && gate.phase == .idle, "SSH rejection preserves VM and forwarding")
        try busy(directory)
        gate.requestAsync(starting: false, alreadyStopped: false, canRequestStop: true) { replies.append($0) }
        replies[2](.success(())); gate.guestDidStop()
        try require(cleanups == countBeforeAsync + 1 && held == nil, "guest event completes authenticated shutdown")
        print("PASS async authenticated request ACK/rejection/timeout/stale callbacks; guest event remains required")

        let instanceID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        var commands: [[String]] = []
        try Provisioner.requestGuestShutdown(instanceID: instanceID) { arguments in
            commands.append(arguments)
            let value: [String: Any] = arguments == ["identity"]
                ? ["product": "acornfox", "instance": instanceID.uuidString.lowercased()]
                : ["shutdown_requested": true, "instance": instanceID.uuidString.lowercased()]
            return try JSONSerialization.data(withJSONObject: value)
        }
        try require(commands == [["identity"], ["shutdown"]], "only fixed authenticated shutdown command")
        commands.removeAll()
        var rejected = false
        do {
            try Provisioner.requestGuestShutdown(instanceID: instanceID) { arguments in
                commands.append(arguments)
                return Data(#"{"product":"acornfox","instance":"foreign"}"#.utf8)
            }
        } catch { rejected = true }
        try require(rejected && commands == [["identity"]], "foreign identity prevents shutdown dispatch")
        rejected = false
        do {
            try Provisioner.requestGuestShutdown(instanceID: instanceID) { arguments in
                if arguments == ["identity"] { return try JSONSerialization.data(withJSONObject: ["product": "acornfox", "instance": instanceID.uuidString.lowercased()]) }
                return Data(#"{"stopped":true}"#.utf8)
            }
        } catch { rejected = true }
        try require(rejected, "SSH zero status with invalid body cannot acknowledge shutdown")
        print("PASS real host shutdown API validates identity and fixed request receipt")
        print("ALL GRACEFUL STOP TESTS PASSED")
    }
}

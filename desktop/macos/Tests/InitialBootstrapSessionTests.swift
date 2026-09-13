import Foundation
import CryptoKit
import Darwin

final class RecordingProvisionerOperations: BootstrapProvisionerOperations {
    enum Operation: Equatable {
        case prepare
        case openInstalled(binding: String)
    }

    var recordedOperations: [Operation] = []
    var wasCancelled = false
    var returnValue: String

    init(returnValue: String = "initialized") {
        self.returnValue = returnValue
    }

    func prepare(onAuthenticated: @escaping () -> Void, progress: @escaping (String) -> Void) throws -> String {
        recordedOperations.append(.prepare)
        onAuthenticated()
        progress("preparing progress")
        return returnValue
    }

    func openInstalled(context: InstalledInstanceContext, onAuthenticated: @escaping () -> Void, progress: @escaping (String) -> Void) throws -> String {
        recordedOperations.append(.openInstalled(binding: context.expectedBackendBinding))
        onAuthenticated()
        progress("openInstalled progress")
        return returnValue
    }

    func cancel() {
        wasCancelled = true
    }
}

final class BlockingProvisionerOperations: BootstrapProvisionerOperations {
    let entered = DispatchSemaphore(value: 0)
    let releaseGate = DispatchSemaphore(value: 0)
    var wasCancelled = false

    func prepare(onAuthenticated: @escaping () -> Void, progress: @escaping (String) -> Void) throws -> String {
        entered.signal()
        _ = releaseGate.wait(timeout: .now() + 5)
        return "blocked-done"
    }

    func openInstalled(context: InstalledInstanceContext, onAuthenticated: @escaping () -> Void, progress: @escaping (String) -> Void) throws -> String {
        entered.signal()
        _ = releaseGate.wait(timeout: .now() + 5)
        return "blocked-done"
    }

    func cancel() {
        wasCancelled = true
    }
}

@main struct InitialBootstrapSessionTests {
    static func require(_ value: @autoclosure () throws -> Bool, _ label: String) throws {
        if try !value() { throw NSError(domain: label, code: 1) }
    }

    static func reject(_ operation: () throws -> Void) throws {
        var failed = false
        do { try operation() } catch { failed = true }
        try require(failed, "expected refusal")
    }

    struct PreparingFixtureInfo {
        let instanceID: UUID
        let binding: String
        let manifest: Manifest
        let resourcesRoot: URL
    }

    static func createPreparingFixture(at root: URL) throws -> PreparingFixtureInfo {
        let fixture = try MacBootstrapFixture(root: root)
        return PreparingFixtureInfo(
            instanceID: fixture.preparer.instanceID,
            binding: fixture.resources.manifest.candidateBindingSHA256,
            manifest: fixture.resources.manifest,
            resourcesRoot: fixture.resources.root
        )
    }

    struct ReadyFixtureInfo {
        let instanceID: UUID
        let binding: String
        let helperSHA: String
        let seedISO: Data
        let seedKey: Data
        let receiptData: Data
        let resourcesRoot: URL
    }

    static func createReadyFixture(at root: URL) throws -> ReadyFixtureInfo {
        let fixture = try MacBootstrapFixture(root: root)
        let seed = try fixture.complete()
        let receiptPath = fixture.preparer.vm.url.appendingPathComponent(InstalledReceiptStore.filename)
        let receiptData = try Data(contentsOf: receiptPath)
        let seedISO = try Data(contentsOf: seed.isoURL)
        let seedKey = try Data(contentsOf: seed.privateKeyURL)
        return ReadyFixtureInfo(
            instanceID: fixture.preparer.instanceID,
            binding: fixture.resources.manifest.candidateBindingSHA256,
            helperSHA: fixture.resources.manifest.bootstrapHelperSHA256!,
            seedISO: seedISO,
            seedKey: seedKey,
            receiptData: receiptData,
            resourcesRoot: fixture.resources.root
        )
    }

    static func main() throws {
        let tempBase = URL(fileURLWithPath: "/private/tmp/acornfox-initial-bootstrap-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempBase, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempBase) }

        // Test 1: Preparing vs ready branch selection using existing MacBootstrapFixture
        do {
            // 1a: Preparing phase
            let prepRoot = tempBase.appendingPathComponent("fixture-branch-prep")
            let prepInfo = try createPreparingFixture(at: prepRoot)
            let prepStateRoot = prepRoot.appendingPathComponent("state")

            let inputsPreparing = try InitialBootstrapInputs(
                expectedInstanceID: prepInfo.instanceID,
                expectedBootstrapBinding: prepInfo.binding
            )
            let sessionPreparing = try InitialBootstrapSession(
                root: prepStateRoot,
                inputs: inputsPreparing,
                resources: try Resources(root: prepInfo.resourcesRoot),
                virtualBytes: 1024 * 1024
            )
            let planPreparing = try sessionPreparing.prepareLocal()
            try require(planPreparing.branch == .preparing, "branch is preparing")
            try require(planPreparing.context == nil, "context is nil in preparing branch")
            try require(planPreparing.instanceID == prepInfo.instanceID, "instanceID matches")
            try require(planPreparing.expectedBinding == prepInfo.binding, "expectedBinding matches")

            let opsPreparing = RecordingProvisionerOperations(returnValue: "preparing-done")
            var authenticatedPreparing = false
            var progressMessagesPreparing: [String] = []
            let resultPreparing = try sessionPreparing.run(
                operations: opsPreparing,
                onAuthenticated: { authenticatedPreparing = true },
                progress: { progressMessagesPreparing.append($0) }
            )
            try require(resultPreparing == "preparing-done", "run returned operations result")
            try require(opsPreparing.recordedOperations == [.prepare], "preparing branch delegates to prepare")
            try require(authenticatedPreparing, "onAuthenticated invoked")
            try require(!progressMessagesPreparing.isEmpty, "progress invoked")
            sessionPreparing.close()

            // 1b: Ready phase
            let readyRoot = tempBase.appendingPathComponent("fixture-branch-ready")
            let readyInfo = try createReadyFixture(at: readyRoot)
            let readyStateRoot = readyRoot.appendingPathComponent("state")

            let inputsReady = try InitialBootstrapInputs(
                expectedInstanceID: readyInfo.instanceID,
                expectedBootstrapBinding: readyInfo.binding
            )
            let sessionReady = try InitialBootstrapSession(
                root: readyStateRoot,
                inputs: inputsReady,
                resources: nil
            )
            let planReady = try sessionReady.prepareLocal()
            try require(planReady.branch == .ready, "branch is ready")
            try require(planReady.context != nil, "context is non-nil in ready branch")
            try require(planReady.context?.expectedBackendBinding == readyInfo.binding, "expectedBackendBinding matches")
            try require(planReady.instanceID == readyInfo.instanceID, "ready instanceID matches")

            let opsReady = RecordingProvisionerOperations(returnValue: "initialized")
            var authenticatedReady = false
            let resultReady = try sessionReady.run(
                operations: opsReady,
                onAuthenticated: { authenticatedReady = true }
            )
            try require(resultReady == "initialized", "run returned ready result")
            try require(opsReady.recordedOperations == [.openInstalled(binding: readyInfo.binding)], "ready branch delegates to openInstalled")
            try require(authenticatedReady, "onAuthenticated invoked for ready")
            sessionReady.close()

            print("PASS preparing vs ready branch selection using existing test fixtures")
        }

        // Test 2: No fresh install on ready; existing files preserved, no upload/install commands
        do {
            let fixtureRoot = tempBase.appendingPathComponent("fixture-no-fresh-install")
            let readyInfo = try createReadyFixture(at: fixtureRoot)
            let stateRoot = fixtureRoot.appendingPathComponent("state")
            let vmDir = stateRoot.appendingPathComponent("vm")

            let receiptPath = vmDir.appendingPathComponent(InstalledReceiptStore.filename)
            let diskPath = vmDir.appendingPathComponent("guest.raw")
            let seedISOPath = vmDir.appendingPathComponent("seed/seed.iso")
            let seedKeyPath = vmDir.appendingPathComponent("seed/ssh-key")

            // Modify user bytes on guest disk to ensure they are preserved
            let diskHandle = try FileHandle(forUpdating: diskPath)
            try diskHandle.write(contentsOf: Data("MUTATED-USER-DATA".utf8))
            try diskHandle.synchronize()
            try diskHandle.close()
            let mutatedDisk = try Data(contentsOf: diskPath)

            // Completely remove resources to verify ready branch has zero reliance on App resources
            try FileManager.default.removeItem(at: readyInfo.resourcesRoot)

            let inputs = try InitialBootstrapInputs(
                expectedInstanceID: readyInfo.instanceID,
                expectedBootstrapBinding: readyInfo.binding
            )
            let session = try InitialBootstrapSession(
                root: stateRoot,
                inputs: inputs,
                resources: nil
            )

            let ops = RecordingProvisionerOperations(returnValue: "uninitialized")
            let result = try session.run(operations: ops)
            try require(result == "uninitialized", "ready state returned")
            try require(ops.recordedOperations == [.openInstalled(binding: readyInfo.binding)], "ready branch calls only openInstalled")

            // Verify files on disk remained untouched
            try require(try Data(contentsOf: receiptPath) == readyInfo.receiptData, "receipt untouched")
            try require(try Data(contentsOf: seedISOPath) == readyInfo.seedISO, "seed untouched")
            try require(try Data(contentsOf: seedKeyPath) == readyInfo.seedKey, "ssh key untouched")
            try require(try Data(contentsOf: diskPath) == mutatedDisk, "mutated disk user data preserved")
            session.close()

            print("PASS no fresh install on ready: files preserved, openInstalled selected without resources")
        }

        // Test 3: Immutable binding mismatch refusal (both ready and preparing)
        do {
            let fixtureRoot = tempBase.appendingPathComponent("fixture-binding-mismatch")
            let readyInfo = try createReadyFixture(at: fixtureRoot)
            let stateRoot = fixtureRoot.appendingPathComponent("state")

            let legitimateBinding = readyInfo.binding
            let mismatchedBinding = String(repeating: "f", count: 64)

            // Ready phase with mismatched binding inputs
            let badInputsReady = try InitialBootstrapInputs(
                expectedInstanceID: readyInfo.instanceID,
                expectedBootstrapBinding: mismatchedBinding
            )
            let badSessionReady = try InitialBootstrapSession(
                root: stateRoot,
                inputs: badInputsReady,
                resources: nil
            )
            try reject { _ = try badSessionReady.prepareLocal() }
            badSessionReady.close()

            // Ready phase with wrong instance ID
            let wrongIDInputs = try InitialBootstrapInputs(
                expectedInstanceID: UUID(),
                expectedBootstrapBinding: legitimateBinding
            )
            let wrongIDSession = try InitialBootstrapSession(
                root: stateRoot,
                inputs: wrongIDInputs,
                resources: nil
            )
            try reject { _ = try wrongIDSession.prepareLocal() }
            wrongIDSession.close()

            // Preparing phase with mismatched binding inputs
            let preparingRoot = tempBase.appendingPathComponent("fixture-preparing-mismatch")
            let prepInfo = try createPreparingFixture(at: preparingRoot)
            let prepStateRoot = preparingRoot.appendingPathComponent("state")

            let badInputsPreparing = try InitialBootstrapInputs(
                expectedInstanceID: prepInfo.instanceID,
                expectedBootstrapBinding: mismatchedBinding
            )
            let badSessionPreparing = try InitialBootstrapSession(
                root: prepStateRoot,
                inputs: badInputsPreparing,
                resources: try Resources(root: prepInfo.resourcesRoot),
                virtualBytes: 1024 * 1024
            )
            try reject { _ = try badSessionPreparing.prepareLocal() }
            badSessionPreparing.close()

            print("PASS immutable binding mismatch and instance mismatch refused")
        }

        // Test 4: Reentry with existing disk and seed, and single local preparation
        do {
            let reentryRoot = tempBase.appendingPathComponent("fixture-reentry")
            let prepInfo = try createPreparingFixture(at: reentryRoot)
            let stateRoot = reentryRoot.appendingPathComponent("state")

            let inputs = try InitialBootstrapInputs(
                expectedInstanceID: prepInfo.instanceID,
                expectedBootstrapBinding: prepInfo.binding
            )
            let session = try InitialBootstrapSession(
                root: stateRoot,
                inputs: inputs,
                resources: try Resources(root: prepInfo.resourcesRoot),
                virtualBytes: 1024 * 1024
            )

            let plan1 = try session.prepareLocal()
            try require(plan1.branch == .preparing, "first prepareLocal selects preparing")

            // Reentry on the same session
            let plan2 = try session.prepareLocal()
            try require(plan2.branch == .preparing, "reentry prepareLocal selects preparing")
            try require(plan2.instanceID == plan1.instanceID, "reentry instanceID matches")
            try require(plan2.seed.isoURL == plan1.seed.isoURL, "reentry reopens same seed")

            // Run execution prepares local state exactly once and reaches operation seam
            let ops = RecordingProvisionerOperations(returnValue: "done")
            let result = try session.run(operations: ops)
            try require(result == "done", "run returned done")
            try require(ops.recordedOperations == [.prepare], "reached prepare seam exactly once")

            session.close()

            print("PASS same-instance reentry reopens existing disk and seed without re-allocation")
        }

        // Test 5: Blocking operation test: close during operation maintains lock until return
        do {
            let sessionRoot = tempBase.appendingPathComponent("fixture-blocking-close")
            let readyInfo = try createReadyFixture(at: sessionRoot)
            let stateRoot = sessionRoot.appendingPathComponent("state")

            let inputs = try InitialBootstrapInputs(
                expectedInstanceID: readyInfo.instanceID,
                expectedBootstrapBinding: readyInfo.binding
            )
            let session1 = try InitialBootstrapSession(
                root: stateRoot,
                inputs: inputs,
                resources: nil
            )

            let blockingOps = BlockingProvisionerOperations()
            let queue = DispatchQueue(label: "test.blocking.queue")
            let runFinished = DispatchSemaphore(value: 0)

            queue.async {
                _ = try? session1.run(operations: blockingOps)
                runFinished.signal()
            }

            // Wait until the operation is entered
            _ = blockingOps.entered.wait(timeout: .now() + 5)

            // Close session1 while operation is active
            session1.close()
            try require(blockingOps.wasCancelled, "close forwarded cancel to active operations")

            // While operation is still running, session2 on the same root MUST fail with HostError.busy
            let session2 = try InitialBootstrapSession(
                root: stateRoot,
                inputs: inputs,
                resources: nil
            )
            try reject { _ = try session2.acquirePreparer() }

            // Release the blocking gate so session1's operation completes and exits
            blockingOps.releaseGate.signal()
            _ = runFinished.wait(timeout: .now() + 5)

            // Now that session1's run has returned, deferred close released diskPreparer.
            // session2 can acquire lock immediately without deallocating session1!
            let preparer2 = try session2.acquirePreparer()
            try require(preparer2.instanceID == readyInfo.instanceID, "session2 acquired preparer after session1 run completed")
            session2.close()

            print("PASS close during active operation cancels and releases lock after return")
        }

        // Test 6: Cancellation, close, and lock release in idle state
        do {
            let sessionRoot = tempBase.appendingPathComponent("fixture-cancellation")
            let receipt = try prepareOrOpenNativeInstance(root: sessionRoot)

            let inputs = try InitialBootstrapInputs(
                expectedInstanceID: receipt.nativeUUID,
                expectedBootstrapBinding: String(repeating: "a", count: 64)
            )
            let session = try InitialBootstrapSession(
                root: sessionRoot,
                inputs: inputs,
                resources: nil
            )

            _ = try session.acquirePreparer()
            session.cancel()
            try reject { _ = try session.prepareLocal() }

            session.close()

            // After close, lock must be released so a new InstanceLock can be acquired
            let state = try PrivateState(root: sessionRoot)
            let freshLock = try InstanceLock(directory: state.directory)
            _ = freshLock

            print("PASS cancellation refuses execution and close releases owned resources")
        }

        // Test 7: Lock conflict between sessions on same root
        do {
            let conflictRoot = tempBase.appendingPathComponent("session-lock-conflict")
            let receipt = try prepareOrOpenNativeInstance(root: conflictRoot)
            let inputs = try InitialBootstrapInputs(
                expectedInstanceID: receipt.nativeUUID,
                expectedBootstrapBinding: String(repeating: "a", count: 64)
            )
            let session1 = try InitialBootstrapSession(root: conflictRoot, inputs: inputs, resources: nil)
            _ = try session1.acquirePreparer() // session1 holds lock

            let session2 = try InitialBootstrapSession(root: conflictRoot, inputs: inputs, resources: nil)
            try reject { _ = try session2.acquirePreparer() } // Must fail with HostError.busy!

            session1.close() // session1 releases lock
            _ = try session2.acquirePreparer() // session2 now succeeds!
            session2.close()

            print("PASS lock conflict between sessions refused with HostError.busy; close allows next session")
        }

        print("ALL INITIAL BOOTSTRAP SESSION TESTS PASSED")
    }
}

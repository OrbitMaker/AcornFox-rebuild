import Foundation
import CryptoKit
import Darwin

struct InitialBootstrapInputs: Equatable {
    let expectedInstanceID: UUID
    let expectedBootstrapBinding: String

    init(expectedInstanceID: UUID, expectedBootstrapBinding: String) throws {
        let pattern = "^[0-9a-f]{64}$"
        guard expectedBootstrapBinding.range(of: pattern, options: .regularExpression) != nil else {
            throw HostError.invalid("bootstrap binding")
        }
        self.expectedInstanceID = expectedInstanceID
        self.expectedBootstrapBinding = expectedBootstrapBinding
    }
}

enum InitialBootstrapBranch: String, Codable, Equatable {
    case preparing
    case ready
}

struct InitialBootstrapPlan {
    let branch: InitialBootstrapBranch
    let instanceID: UUID
    let expectedBinding: String
    let seed: PreparedSeed
    let context: InstalledInstanceContext?

    init(branch: InitialBootstrapBranch, instanceID: UUID, expectedBinding: String, seed: PreparedSeed, context: InstalledInstanceContext?) {
        self.branch = branch
        self.instanceID = instanceID
        self.expectedBinding = expectedBinding
        self.seed = seed
        self.context = context
    }
}

protocol BootstrapProvisionerOperations: AnyObject {
    func prepare(onAuthenticated: @escaping () -> Void, progress: @escaping (String) -> Void) throws -> String
    func openInstalled(context: InstalledInstanceContext, onAuthenticated: @escaping () -> Void, progress: @escaping (String) -> Void) throws -> String
    func cancel()
}

final class ProductionProvisionerOperations: BootstrapProvisionerOperations {
    private let provisioner: Provisioner

    init(running: RunningInstance, resources: Resources?, state: PrivateDirectory) throws {
        self.provisioner = try Provisioner(running: running, resources: resources, state: state)
    }

    func prepare(onAuthenticated: @escaping () -> Void, progress: @escaping (String) -> Void) throws -> String {
        try provisioner.prepare(onAuthenticated: onAuthenticated, progress: progress)
    }

    func openInstalled(context: InstalledInstanceContext, onAuthenticated: @escaping () -> Void, progress: @escaping (String) -> Void) throws -> String {
        try provisioner.openInstalled(context: context, onAuthenticated: onAuthenticated, progress: progress)
    }

    func cancel() {
        provisioner.cancel()
    }
}

final class InitialBootstrapSession {
    let state: PrivateState
    let inputs: InitialBootstrapInputs
    let resources: Resources?
    let virtualBytes: UInt64?

    private(set) var diskPreparer: DiskPreparer?
    private var ownsPreparer: Bool = true
    private var activeOperations: BootstrapProvisionerOperations?
    private var isRunning: Bool = false
    private(set) var isCancelled: Bool = false
    private var closeRequested: Bool = false
    private let lock = NSLock()

    init(
        state: PrivateState,
        inputs: InitialBootstrapInputs,
        resources: Resources? = nil,
        virtualBytes: UInt64? = nil
    ) {
        self.state = state
        self.inputs = inputs
        self.resources = resources
        self.virtualBytes = virtualBytes
    }

    convenience init(
        root: URL,
        inputs: InitialBootstrapInputs,
        resources: Resources? = nil,
        virtualBytes: UInt64? = nil
    ) throws {
        self.init(state: try PrivateState(root: root), inputs: inputs, resources: resources, virtualBytes: virtualBytes)
    }

    init(
        preparer: DiskPreparer,
        inputs: InitialBootstrapInputs,
        resources: Resources? = nil,
        virtualBytes: UInt64? = nil
    ) {
        self.state = preparer.state
        self.inputs = inputs
        self.resources = resources
        self.virtualBytes = virtualBytes
        self.diskPreparer = preparer
        self.ownsPreparer = false
    }

    func acquirePreparer() throws -> DiskPreparer {
        lock.lock()
        defer { lock.unlock() }
        if let existing = diskPreparer {
            return existing
        }
        let preparer = try NativeInstanceProvisioner(state: state).openDiskPreparer()
        self.diskPreparer = preparer
        self.ownsPreparer = true
        return preparer
    }

    func prepareLocal() throws -> InitialBootstrapPlan {
        lock.lock()
        guard !isCancelled else {
            lock.unlock()
            throw HostError.invalid("操作已取消")
        }
        lock.unlock()

        let preparer = try acquirePreparer()
        guard preparer.instanceID == inputs.expectedInstanceID else {
            throw HostError.unsafeState
        }

        let store = InstalledReceiptStore(directory: preparer.vm, instance: preparer.instanceID)
        let record = try store.load()

        if record?.phase == "ready" {
            guard let readyRecord = record else { throw HostError.unsafeState }
            // On ready receipt use nil update authority and exact bootstrap binding.
            guard readyRecord.bootstrapBinding == inputs.expectedBootstrapBinding else {
                throw HostError.unsafeState
            }
            let context = try store.context(authority: nil)
            guard context.expectedBackendBinding == inputs.expectedBootstrapBinding else {
                throw HostError.unsafeState
            }
            _ = try preparer.openExistingDisk()
            let seed = try store.validate(context)
            return InitialBootstrapPlan(
                branch: .ready,
                instanceID: preparer.instanceID,
                expectedBinding: inputs.expectedBootstrapBinding,
                seed: seed,
                context: context
            )
        } else {
            guard let resources = self.resources else {
                throw HostError.missing("安装资源")
            }
            try resources.verify()
            guard resources.manifest.candidateBindingSHA256 == inputs.expectedBootstrapBinding else {
                throw HostError.unsafeState
            }
            try store.authorizeBootstrap(manifest: resources.manifest)
            let vBytes = virtualBytes ?? (40 * 1024 * 1024 * 1024)
            _ = try preparer.prepare(gzip: resources.root.appendingPathComponent("base.raw.gz"), manifest: resources.manifest, virtualBytes: vBytes)
            let seed: PreparedSeed
            var existingSeed = stat()
            if fstatat(preparer.vm.fd, "seed", &existingSeed, AT_SYMLINK_NOFOLLOW) == 0 {
                seed = try SeedPreparer(vm: preparer.vm, instance: preparer.instanceID).openExisting(
                    instanceProtocol: 1,
                    bootstrapManifestSHA256: InstalledReceiptStore.manifestFingerprint(resources.manifest)
                )
            } else {
                guard errno == ENOENT else { throw HostError.unsafeState }
                seed = try preparer.prepareSeed(resources: resources.root, manifest: resources.manifest)
            }
            return InitialBootstrapPlan(
                branch: .preparing,
                instanceID: preparer.instanceID,
                expectedBinding: inputs.expectedBootstrapBinding,
                seed: seed,
                context: nil
            )
        }
    }

    private func runImpl(
        plan: InitialBootstrapPlan,
        operations: BootstrapProvisionerOperations,
        onAuthenticated: @escaping () -> Void,
        progress: @escaping (String) -> Void
    ) throws -> String {
        lock.lock()
        guard !isCancelled else {
            lock.unlock()
            throw HostError.invalid("操作已取消")
        }
        activeOperations = operations
        isRunning = true
        lock.unlock()

        defer {
            lock.lock()
            isRunning = false
            activeOperations = nil
            if closeRequested && ownsPreparer {
                diskPreparer = nil
            }
            lock.unlock()
        }

        switch plan.branch {
        case .ready:
            guard let context = plan.context else { throw HostError.unsafeState }
            return try operations.openInstalled(context: context, onAuthenticated: onAuthenticated, progress: progress)
        case .preparing:
            return try operations.prepare(onAuthenticated: onAuthenticated, progress: progress)
        }
    }

    func run(
        operations: BootstrapProvisionerOperations,
        onAuthenticated: @escaping () -> Void = {},
        progress: @escaping (String) -> Void = { _ in }
    ) throws -> String {
        let plan = try prepareLocal()
        return try runImpl(plan: plan, operations: operations, onAuthenticated: onAuthenticated, progress: progress)
    }

    func run(
        running: RunningInstance,
        onAuthenticated: @escaping () -> Void = {},
        progress: @escaping (String) -> Void = { _ in }
    ) throws -> String {
        let plan = try prepareLocal()
        let preparer = try acquirePreparer()
        let ops = try ProductionProvisionerOperations(
            running: running,
            resources: plan.branch == .ready ? nil : resources,
            state: preparer.vm
        )
        return try runImpl(plan: plan, operations: ops, onAuthenticated: onAuthenticated, progress: progress)
    }

    func cancel() {
        lock.lock()
        isCancelled = true
        let ops = activeOperations
        lock.unlock()
        ops?.cancel()
    }

    func close() {
        lock.lock()
        defer { lock.unlock() }
        closeRequested = true
        isCancelled = true
        activeOperations?.cancel()
        guard !isRunning else { return }
        if ownsPreparer {
            diskPreparer = nil
        }
        activeOperations = nil
    }

    deinit {
        close()
    }
}

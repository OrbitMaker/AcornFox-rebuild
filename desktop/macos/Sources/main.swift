import AppKit
import CryptoKit
import Foundation
import Network
import Virtualization

@main final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    static func main() {
        let application = NSApplication.shared
        let delegate = AppDelegate()
        application.setActivationPolicy(.regular)
        application.delegate = delegate
        withExtendedLifetime(delegate) { application.run() }
    }
    private let status = NSTextField(labelWithString: "正在准备，请稍候…")
    private let openButton = NSButton(title: "打开应用", target: nil, action: nil)
    private let copyButton = NSButton(title: "复制设置码", target: nil, action: nil)
    private var busy = false
    private var active = false
    private var terminating = false
    private var generation = UUID()
    private var diskPreparer: DiskPreparer?
    private var resources: Resources?
    private var installedContext: InstalledInstanceContext?
    private var provisioner: Provisioner?
    private var running: RunningInstance?
    private var window: NSWindow?
    private lazy var controller = VMController { [weak self] update in
        guard let self, !self.terminating else { return }
        self.openButton.isEnabled = false; self.copyButton.isEnabled = false
        switch update {
        case .starting: self.active = true; self.status.stringValue = "正在准备，请稍候…"
        case .running(let running):
            self.active = true; self.running = running
            do {
                guard let preparer = self.diskPreparer else { throw HostError.unsafeState }
                self.provisioner = try Provisioner(running: running, resources: self.resources, state: preparer.vm)
                self.prepareInstalled()
            } catch { self.busy = false; self.show(error) }
        case .stopping: self.status.stringValue = "正在停止，请稍候…"
        case .stopped:
            self.generation = UUID(); self.provisioner?.cancel()
            self.active = false; self.busy = false; self.diskPreparer = nil; self.installedContext = nil; self.resources = nil; self.running = nil; self.provisioner = nil
            self.status.stringValue = "已停止。"
        case .failed(let message, let retained):
            self.recordDiagnostic(message)
            self.active = retained; self.busy = false
            if !retained { self.generation = UUID(); self.provisioner?.cancel(); self.provisioner = nil; self.diskPreparer = nil; self.installedContext = nil; self.resources = nil; self.running = nil }
            self.status.stringValue = HostError.userMessage(forInternalMessage: message)
        }
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        let retry = NSButton(title: "重试", target: self, action: #selector(prepare))
        let stop = NSButton(title: "停止", target: self, action: #selector(stopService))
        openButton.target = self; openButton.action = #selector(openApp); openButton.isEnabled = false
        copyButton.target = self; copyButton.action = #selector(copyCode); copyButton.isEnabled = false
        let buttons = NSStackView(views: [retry, openButton, copyButton, stop]); buttons.spacing = 8
        let stack = NSStackView(views: [status, buttons]); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 16; stack.frame = NSRect(x: 24, y: 24, width: 500, height: 112)
        let view = NSView(frame: NSRect(x: 0, y: 0, width: 548, height: 160)); view.addSubview(stack)
        let window = NSWindow(contentRect: view.frame, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "AcornFox"; window.contentView = view; window.delegate = self; window.center(); window.makeKeyAndOrderFront(nil); self.window = window
        prepare()
    }
    @objc private func prepare() {
        guard !busy, !terminating else { return }
        if active {
            do {
                guard let running, let diskPreparer else { throw HostError.busy }
                // Stop/exit cancels the previous operation. Retry gets a fresh
                // operation scope while retaining the same VM, identity and data.
                provisioner = try Provisioner(running: running, resources: resources, state: diskPreparer.vm)
                prepareInstalled()
            } catch { show(error) }
            return
        }
        busy = true; status.stringValue = "正在准备，请稍候…"; openButton.isEnabled = false; copyButton.isEnabled = false
        let existing = diskPreparer; let current = generation
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let preparer = try existing ?? DiskPreparer(state: PrivateState())
                let installation = InstalledReceiptStore(directory: preparer.vm, instance: preparer.instanceID)
                let resources: Resources?
                let context: InstalledInstanceContext?
                let seed: PreparedSeed
                if try installation.load()?.phase == "ready" {
                    context = try installation.context() // No update authority is installed in this package.
                    _ = try preparer.openExistingDisk()
                    seed = try installation.validate(context!)
                    resources = nil
                } else {
                    let inputs = try Resources(); try inputs.verify()
                    try installation.authorizeBootstrap(manifest: inputs.manifest)
                    _ = try preparer.prepare(gzip: inputs.root.appendingPathComponent("base.raw.gz"), manifest: inputs.manifest)
                    var existingSeed = stat()
                    if fstatat(preparer.vm.fd, "seed", &existingSeed, AT_SYMLINK_NOFOLLOW) == 0 {
                        seed = try SeedPreparer(vm: preparer.vm, instance: preparer.instanceID).openExisting(
                            instanceProtocol: 1, bootstrapManifestSHA256: InstalledReceiptStore.manifestFingerprint(inputs.manifest))
                    } else {
                        guard errno == ENOENT else { throw HostError.unsafeState }
                        seed = try preparer.prepareSeed(resources: inputs.root, manifest: inputs.manifest)
                    }
                    resources = inputs; context = nil
                }
                DispatchQueue.main.async {
                    guard !self.terminating, current == self.generation else { return }
                    self.resources = resources; self.installedContext = context; self.diskPreparer = preparer
                    self.controller.start(preparer: preparer, seed: seed)
                }
            } catch { DispatchQueue.main.async { guard current == self.generation else { return }; self.busy = false; self.show(error) } }
        }
    }
    private func prepareInstalled() {
        guard let provisioner, let running, let preparer = diskPreparer else { return }
        busy = true; openButton.isEnabled = false; copyButton.isEnabled = false
        let current = generation, suppliedContext = installedContext
        let installation = InstalledReceiptStore(directory: preparer.vm, instance: preparer.instanceID)
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let context: InstalledInstanceContext?
                if let suppliedContext { context = suppliedContext }
                else if try installation.load()?.phase == "ready" { context = try installation.context() }
                else { context = nil }
                let authenticated = { self.controller.useAuthenticatedShutdown(for: running, request: provisioner.makeShutdownRequest()) }
                let progress = { (message: String) in DispatchQueue.main.async { if current == self.generation { self.status.stringValue = Self.progressMessage(message) } } }
                let state: String
                if let context { state = try provisioner.openInstalled(context: context, onAuthenticated: authenticated, progress: progress) }
                else { state = try provisioner.prepare(onAuthenticated: authenticated, progress: progress) }
                let completedContext = try context ?? installation.context()
                DispatchQueue.main.async { guard !self.terminating, current == self.generation else { return }
                    self.installedContext = completedContext; self.resources = nil; self.setReady(state)
                }
            } catch { DispatchQueue.main.async { guard current == self.generation else { return }; self.busy = false; self.show(error) } }
        }
    }
    private func setReady(_ state: String) {
        busy = false; openButton.isEnabled = true; copyButton.isEnabled = state == "uninitialized"
        status.stringValue = state == "uninitialized" ? "已准备好。请复制设置码，再打开应用。" : "已准备好，可以打开应用。"
    }
    @objc private func openApp() {
        guard openButton.isEnabled, !busy, let running else { return }
        busy = true; openButton.isEnabled = false; copyButton.isEnabled = false; status.stringValue = "正在打开，请稍候…"
        let current = generation
        DispatchQueue.global().async {
            do {
                let state = try SetupProbe.probe(port: running.endpoints.httpPort, timeout: 5)
                DispatchQueue.main.async {
                    guard !self.terminating, current == self.generation else { return }; self.setReady(state)
                    NSWorkspace.shared.open(URL(string: "http://127.0.0.1:8080")!)
                }
            } catch { DispatchQueue.main.async { guard current == self.generation else { return }; self.busy = false; self.show(error) } }
        }
    }
    @objc private func copyCode() {
        guard copyButton.isEnabled, !busy, let provisioner else { return }
        busy = true; openButton.isEnabled = false; copyButton.isEnabled = false
        let current = generation
        DispatchQueue.global().async {
            do {
                let code = try provisioner.setupCode()
                DispatchQueue.main.async {
                    guard !self.terminating, current == self.generation else { return }
                    NSPasteboard.general.clearContents(); NSPasteboard.general.setString(code, forType: .string)
                    self.setReady("uninitialized"); self.status.stringValue = "设置码已复制。打开应用后即可粘贴。"
                }
            } catch { DispatchQueue.main.async { guard current == self.generation else { return }; self.busy = false; self.show(error) } }
        }
    }
    @objc private func stopService() {
        busy = true; status.stringValue = "正在停止，请稍候…"
        generation = UUID(); provisioner?.cancel(); openButton.isEnabled = false; copyButton.isEnabled = false
        controller.stop(failure: { [weak self] message in
            guard let self else { return }; self.active = true; self.busy = false; self.recordDiagnostic(message); self.status.stringValue = HostError.notStoppedMessage
        })
    }
    private static func progressMessage(_ message: String) -> String {
        switch message {
        case "正在复制已验证的安装文件…": return "正在准备所需内容，请稍候…"
        case "正在安装本机服务，首次安装需要一些时间…": return "首次准备需要一些时间，请稍候…"
        case "正在检查应用入口…": return "正在完成最后一步，请稍候…"
        default: return "正在准备，请稍候…"
        }
    }
    private func show(_ error: Error) {
        recordDiagnostic(String(reflecting: error))
        status.stringValue = HostError.userMessage(for: error)
    }
    private func recordDiagnostic(_ message: String) {
        // Never create/claim an unsafe location just to record a diagnostic.
        guard let directory = diskPreparer?.vm else { return }
        do {
            let name = "entry-diagnostics.log"
            if try directory.info(name) == nil { try directory.writeNew(name, data: Data()) }
            guard let info = try directory.info(name), info.st_size < 1024 * 1024 else { return }
            let fd = try directory.openFile(name, flags: O_WRONLY | O_APPEND); defer { close(fd) }
            let entry = String(message.prefix(4096)).replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " ")
            try PrivateDirectory.write(Data("\(Int(Date().timeIntervalSince1970)) \(entry)\n".utf8), to: fd)
        } catch { /* An unavailable private log never sends raw details to the UI. */ }
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool { NSApplication.shared.terminate(nil); return false }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        terminating = true; generation = UUID(); provisioner?.cancel()
        if !active && !busy { return .terminateNow }
        busy = true; status.stringValue = "正在停止，请稍候…"
        controller.stop(failure: { [weak self] message in
            guard let self else { return }
            self.terminating = false; self.active = true; self.busy = false
            self.recordDiagnostic(message); self.status.stringValue = HostError.notStoppedMessage
            sender.reply(toApplicationShouldTerminate: false)
        }, completion: { sender.reply(toApplicationShouldTerminate: true) })
        return .terminateLater
    }
}

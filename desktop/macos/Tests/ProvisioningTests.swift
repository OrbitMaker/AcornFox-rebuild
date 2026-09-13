import Foundation
import CryptoKit
import Darwin

@main struct ProvisioningTests {
    static func require(_ value: @autoclosure () -> Bool, _ message: String) throws { if !value() { throw NSError(domain: message, code: 1) } }
    static func reject(_ operation: () throws -> Void) throws { var failed = false; do { try operation() } catch { failed = true }; try require(failed, "expected rejection") }
    static func main() throws {
        let hash = String(repeating: "a", count: 64)
        let paths = ["base.raw.gz", "acornfox-guest-bridge", "candidate/candidate.tar.gz", "candidate/candidate-binding.json", "candidate/candidate-binding.sha256", "candidate/bundle-manifest.sha256", "candidate/build-record.json", "candidate/release-manifest.json"]
        let files = paths.map { Resource(path: $0, sha256: hash, size: 1) }
        let manifest = Manifest(baseRawSHA256: hash, baseRawBytes: 1, candidateBindingSHA256: hash, files: files, bootstrapHelperSHA256: hash)
        try Resources.validateManifest(manifest)
        for invalid in [Array(files.dropLast()), files + [files[0]], Array(files.dropLast()) + [files[0]]] {
            try reject { try Resources.validateManifest(Manifest(baseRawSHA256: hash, baseRawBytes: 1, candidateBindingSHA256: hash, files: invalid, bootstrapHelperSHA256: hash)) }
        }
        try require(SetupProbe.parse(Data(#"{"state":"initialized"}"#.utf8)) == "initialized", "initialized")
        try require(SetupProbe.parse(Data(#"{"state":"uninitialized"}"#.utf8)) == "uninitialized", "uninitialized")
        for text in [#"{"state":"ready"}"#, #"{"state":"initialized","extra":true}"#, #"{"state":"initialized","state":"uninitialized"}"#, #"{"state":"initialized"} {}"#, "<html>ready</html>"] {
            try require(SetupProbe.parse(Data(text.utf8)) == nil, "reject ambiguous setup")
        }
        print("PASS strict 8-file manifest and setup payload boundary")
        let base = URL(fileURLWithPath: "/private/tmp/acornfox-provision-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]); defer { try? FileManager.default.removeItem(at: base) }
        let script = base.appendingPathComponent("control.py"); try Data(GuestControlScript.source.utf8).write(to: script)
        let test = #"""
import importlib.util, pathlib, tempfile
spec=importlib.util.spec_from_file_location('control',__import__('sys').argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as temp:
    root=pathlib.Path(temp); m.ROOT=root; m.HELPER=root/'helper'; m.HELPER.write_bytes(b'helper'); m.RUNTIME=root/'runtime'
    sha='a'*64; cfg={'helperSHA256':sha,'bindingSHA256':sha,'instance':'00000000-0000-0000-0000-000000000001','instanceProtocol':1,'files':[]}
    calls=[]
    m.regular=lambda *args: None
    m.digest=lambda *args: sha
    m.jsonfile=lambda *args: {'schema_version':1,'state':'RUNTIME_CONFIGURED','binding_sha256':sha,'release_id':'r1','source_commit':'c1','intent_sha256':sha}
    def command(args):
        calls.append(args[1:])
        if args[1:]==['contract-check','--product','acornfox','--layout-schema','1']: return {'schema_version':1,'ok':True,'code':'ok','binding_sha256':sha,'executable_sha256':sha,'substrate_receipt_sha256':sha,'identity':{'product':'acornfox','role':'upgrade','layout_version':1,'release_id':'r1','source_commit':'c1'}}
        if args[1:]==['verify-prepared']: return {'ok':True,'command':'verify-prepared','receipt':{'schema_version':1,'state':'REPO_PREPARED','binding_sha256':sha,'release_id':'r1','source_commit':'c1','final_evidence_sha256':sha}}
        raise AssertionError('unexpected mutating command')
    m.command=command
    assert m.verify(cfg)['installed'] is True
    assert calls==[['contract-check','--product','acornfox','--layout-schema','1'],['verify-prepared']]
    assert m.install(cfg)['installed'] is True
    assert all(x in [['contract-check','--product','acornfox','--layout-schema','1'],['verify-prepared']] for x in calls)
    try: m.verify(dict(cfg,bindingSHA256='b'*64))
    except RuntimeError: pass
    else: raise AssertionError('mismatched installed binding accepted')
    m.HELPER.unlink(); (root/'install-started').write_text('partial')
    try: m.verify(cfg)
    except RuntimeError: pass
    else: raise AssertionError('foreign partial install accepted for reinstall')
print('PASS guest controller existing-install is read-only; mismatch/foreign partial fail closed')
"""#
        let output = try SeedPreparer.run("/usr/bin/python3", ["-c", test, script.path])
        print(String(decoding: output, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
        let fixture = #"""
import http.server, urllib.parse
class Handler(http.server.BaseHTTPRequestHandler):
    count=0
    def log_message(self,*args): pass
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.query:
            body = b'{"code":"setup_failed","message":"invalid request"}'
            self.send_response(400)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path != '/api/v1/acornfox/setup':
            body = b'{"code":"setup_failed","message":"invalid request"}'
            self.send_response(404)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        cc = [x.strip() for x in self.headers.get('Cache-Control', '').split(',')]
        if 'no-cache' not in cc or 'no-store' not in cc or self.headers.get('Pragma', '').strip() != 'no-cache':
            body = b'{"code":"setup_failed","message":"invalid request"}'
            self.send_response(400)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        type(self).count += 1
        number = type(self).count
        if number == 1:
            body = b'{"state":"uninitialized"}'; self.send_response(200)
        elif number == 2:
            body = b''; self.send_response(302); self.send_header('Location', 'http://127.0.0.1:1/other')
        else:
            body = b'{"state":"initialized","extra":true}'; self.send_response(200)
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
print(server.server_port, flush=True)
server.serve_forever()
"""#
        let server = Process(); server.executableURL = URL(fileURLWithPath: "/usr/bin/python3"); server.arguments = ["-c", fixture]
        let stdout = Pipe(); server.standardOutput = stdout; server.standardError = FileHandle.nullDevice; try server.run()
        defer { server.terminate(); server.waitUntilExit(); try? stdout.fileHandleForReading.close() }
        var portBuffer = [UInt8](repeating: 0, count: 32)
        let portCount = read(stdout.fileHandleForReading.fileDescriptor, &portBuffer, portBuffer.count)
        let portData = Data(portBuffer.prefix(max(0, portCount)))
        let port = UInt16(String(decoding: portData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))!
        let apiState = try SetupProbe.probe(port: port, timeout: 0)
        try require(apiState == "uninitialized", "actual HTTP readiness")
        try reject { _ = try SetupProbe.probe(port: port, timeout: 0) }
        try reject { _ = try SetupProbe.probe(port: port, timeout: 0) }
        print("PASS actual HTTP setup probe; redirects and extra payload rejected")
        let retryFixture = try MacBootstrapFixture(root: base.appendingPathComponent("retry-fixture"))
        let retryState = retryFixture.preparer.vm
        let retryResources = retryFixture.resources
        let keyURL = base.appendingPathComponent("retry-ssh-key")
        _ = try SeedPreparer.run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", keyURL.path])
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        try require(listener >= 0, "retry SSH fixture listener")
        defer { close(listener) }
        _ = fcntl(listener, F_SETFL, O_NONBLOCK)
        var address = sockaddr_in(); address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET); address.sin_addr.s_addr = inet_addr("127.0.0.1")
        try require(withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } } == 0 && listen(listener, 2) == 0, "retry SSH fixture bind")
        var addressSize = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &addressSize) } }
        let run = RunningInstance(endpoints: LocalEndpoints(httpPort: 8080, sshPort: UInt16(bigEndian: address.sin_port)), seed: PreparedSeed(isoURL: base.appendingPathComponent("unused.iso"), privateKeyURL: keyURL, publicKey: "unused", instanceID: retryFixture.preparer.instanceID))
        let cancelled = try Provisioner(running: run, resources: retryResources, state: retryState)
        cancelled.cancel()
        try reject { _ = try cancelled.prepare(progress: { _ in }) }
        let unexpected = accept(listener, nil, nil)
        if unexpected >= 0 { close(unexpected) }
        try require(unexpected < 0 && (errno == EAGAIN || errno == EWOULDBLOCK), "cancelled operation cannot reconnect")
        let fresh = try Provisioner(running: run, resources: retryResources, state: retryState)
        let retryDone = DispatchSemaphore(value: 0)
        DispatchQueue.global().async { defer { retryDone.signal() }; _ = try? fresh.prepare(progress: { _ in }) }
        var client: Int32 = -1
        let until = Date().addingTimeInterval(5)
        while client < 0 && Date() < until { client = accept(listener, nil, nil); if client < 0 { Thread.sleep(forTimeInterval: 0.01) } }
        fresh.cancel()
        if client >= 0 { close(client) }
        try require(client >= 0, "fresh retry scope reaches actual system SSH connection")
        try require(retryDone.wait(timeout: .now() + 5) == .success, "new operation can be cancelled independently")
        try require(fresh.running.sessionID == cancelled.running.sessionID && fresh.running.seed.instanceID == cancelled.running.seed.instanceID, "retry retains VM run and persistent identity")
        print("PASS cancelled pre-identity operation fails; fresh same-VM retry reconnects over real system SSH")
        print("ALL PROVISIONING TESTS PASSED")
    }
}

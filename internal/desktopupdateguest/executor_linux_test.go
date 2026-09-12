//go:build linux

package desktopupdateguest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/desktopupdate"
)

type fakeBackend struct {
	root  string
	delay bool
}
type fakeWorld struct {
	Binding           string
	Calls, Recoveries int
}

func (f fakeBackend) read() fakeWorld {
	raw, e := os.ReadFile(filepath.Join(f.root, "world"))
	if e != nil {
		panic(e)
	}
	var w fakeWorld
	if json.Unmarshal(raw, &w) != nil {
		panic("world")
	}
	return w
}
func (f fakeBackend) write(w fakeWorld) {
	if e := os.WriteFile(filepath.Join(f.root, "world"), encoded(w), 0600); e != nil {
		panic(e)
	}
}
func (f fakeBackend) Observe(context.Context) (desktopupdate.BackendObservation, error) {
	w := f.read()
	return desktopupdate.BackendObservation{Binding: w.Binding, Architecture: runtime.GOARCH, MigrationVersion: "0040", Ready: true, Finalized: true, LocalLoopback: true}, nil
}
func (f fakeBackend) Upgrade(_ context.Context, _ string, _ string, i desktopupdate.HostUpgradeIntent) error {
	w := f.read()
	w.Calls++
	f.write(w)
	if f.delay {
		time.Sleep(250 * time.Millisecond)
	}
	w.Binding = i.ToBinding
	f.write(w)
	return nil
}
func (f fakeBackend) Recover(context.Context) error {
	w := f.read()
	w.Recoveries++
	f.write(w)
	return nil
}

type fixture struct {
	x       *Executor
	request SubmitRequest
	payload []byte
	private ed25519.PrivateKey
}

func fixturePaths(root string) systemPaths {
	return systemPaths{root, filepath.Join(root, "config", "policy"), filepath.Join(root, "config", "instance"), filepath.Join(root, "state"), filepath.Join(root, "worker"), filepath.Join(root, "marker")}
}
func openFixture(root string) (*Executor, error) {
	x, e := open(fixturePaths(root))
	if e != nil {
		return nil, e
	}
	x.backend = fakeBackend{root: root, delay: true}
	x.spawn = x.detach
	return x, nil
}
func newFixture(t *testing.T) fixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires actual root Linux filesystem ownership")
	}
	root := t.TempDir()
	for _, dir := range []string{"config", "state"} {
		if e := os.Mkdir(filepath.Join(root, dir), 0700); e != nil {
			t.Fatal(e)
		}
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	policy := Policy{1, public, "linux", runtime.GOARCH, "beta", []string{"updates.example.test"}, 1 << 20}
	native := strings.Repeat("a", 64)
	marker := encoded(struct {
		Product  string `json:"product"`
		Instance string `json:"instance"`
	}{"acornfox", native})
	instance := Instance{1, "linux-local", native, digest([]byte("linux-local:" + native)), digest(marker), "0.1.0-beta.13"}
	paths := fixturePaths(root)
	for p, raw := range map[string][]byte{paths.policy: encoded(policy), paths.instance: encoded(instance), filepath.Join(root, "config", "linux-owner-marker"): marker} {
		if e := os.WriteFile(p, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	world := fakeBackend{root: root}
	world.write(fakeWorld{Binding: strings.Repeat("1", 64)})
	x, e := openFixture(root)
	if e != nil {
		t.Fatal(e)
	}
	x.spawn = func(string) error { return nil }
	payload, to := signedTestPayload(t, world.read().Binding)
	req := SubmitRequest{Intent: desktopupdate.HostUpgradeIntent{InstanceID: instance.InstanceID, AttemptID: strings.Repeat("2", 64), FromBinding: world.read().Binding, ToBinding: to, ArtifactSHA256: digest(payload)}, PayloadSize: int64(len(payload))}
	req.Envelope = signFixture(t, private, payload, to, 1, time.Now().Add(time.Hour))
	return fixture{x, req, payload, private}
}
func archive(t *testing.T, names []string, contents map[string][]byte, modes map[string]int64) []byte {
	t.Helper()
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	w := tar.NewWriter(g)
	for _, name := range names {
		raw := contents[name]
		if e := w.WriteHeader(&tar.Header{Name: name, Mode: modes[name], Size: int64(len(raw)), Typeflag: tar.TypeReg}); e != nil {
			t.Fatal(e)
		}
		if _, e := w.Write(raw); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	if e := g.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func signedTestPayload(t *testing.T, from string, versions ...string) ([]byte, string) {
	t.Helper()
	version := "0.1.0-beta.14"
	if len(versions) > 0 {
		version = versions[0]
	}
	helper := []byte("signed fixture helper bytes")
	helperSHA := digest(helper)
	inner := archive(t, []string{"release/bin/acornfox-upgrade"}, map[string][]byte{"release/bin/acornfox-upgrade": helper}, map[string]int64{"release/bin/acornfox-upgrade": 0755})
	manifest := encoded(map[string]any{"schema_version": 1, "product": "acornfox", "version": version, "release_id": "release-" + version, "source_commit": strings.Repeat("a", 40), "architecture": runtime.GOARCH, "migration_version": "0040", "files": []map[string]any{{"path": "bin/acornfox-upgrade", "sha256": helperSHA, "mode": 0755}}})
	bundle := []byte("fixture bundle manifest\n")
	binding := encoded(map[string]any{"schema_version": 1, "product": "acornfox", "version": version, "release_id": "release-" + version, "source_commit": strings.Repeat("a", 40), "architecture": runtime.GOARCH, "migration_version": "0040", "archive_sha256": digest(inner), "manifest_sha256": digest(manifest), "bundle_manifest_sha256": digest(bundle), "n_minus_one": map[string]string{"binding_sha256": from}})
	to := digest(binding)
	contents := map[string][]byte{"launcher/AcornFox": []byte("launcher"), "controller/acornfox-host-update": []byte("controller"), "backend/candidate/candidate-binding.json": binding, "backend/candidate/candidate-binding.sha256": []byte(to + "\n"), "backend/candidate/release-manifest.json": manifest, "backend/candidate/bundle-manifest.sha256": bundle, "backend/candidate/build-record.json": []byte(`{"schema_version":1}`), "backend/candidate/acornfox-" + version + "-production.tar.gz": inner}
	m := desktopupdate.HostBundleManifest{SchemaVersion: 1, Product: "acornfox", Kind: "host-update-v1", OS: "linux", Architecture: runtime.GOARCH, Version: version, ControllerProtocol: 1, InstanceProtocol: 1, Launcher: "launcher/AcornFox", Controller: "controller/acornfox-host-update", Backend: desktopupdate.HostBackendPlan{Mode: "candidate", FromBinding: from, ToBinding: to, Architecture: runtime.GOARCH, HelperSHA256: helperSHA, APIProtocol: 1}}
	names := []string{}
	modes := map[string]int64{"bundle.json": 0644}
	for name, raw := range contents {
		mode := int64(0644)
		if strings.HasPrefix(name, "launcher/") || strings.HasPrefix(name, "controller/") {
			mode = 0755
		}
		m.Files = append(m.Files, desktopupdate.HostBundleFile{Path: name, SHA256: digest(raw), Size: int64(len(raw)), Mode: mode})
		modes[name] = mode
		names = append(names, name)
	}
	sort.Strings(names)
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	contents["bundle.json"] = encoded(m)
	return archive(t, append([]string{"bundle.json"}, names...), contents, modes), to
}
func signFixture(t *testing.T, key ed25519.PrivateKey, payload []byte, to string, seq uint64, expires time.Time, versions ...string) []byte {
	t.Helper()
	version := "0.1.0-beta.14"
	if len(versions) > 0 {
		version = versions[0]
	}
	p := desktopupdate.IndexPayload{Channel: "beta", Sequence: seq, ExpiresAt: expires.UTC().Format(time.RFC3339), Version: version, Artifacts: []desktopupdate.Artifact{{OS: "linux", Arch: runtime.GOARCH, URL: "https://updates.example.test/update.tar.gz", SHA256: digest(payload), Size: int64(len(payload)), BackendBinding: to}}}
	raw := encoded(p)
	return encoded(desktopupdate.IndexEnvelope{SchemaVersion: 1, Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))})
}
func submitFixture(t *testing.T, f fixture) JobReceipt {
	t.Helper()
	j, e := f.x.Submit(context.Background(), f.request, bytes.NewReader(f.payload))
	if e != nil {
		t.Fatal(e)
	}
	return j
}

func TestMissingPolicyDoesNotProvision(t *testing.T) {
	f := newFixture(t)
	if e := os.Remove(f.x.paths.policy); e != nil {
		t.Fatal(e)
	}
	if _, e := open(f.x.paths); !errors.Is(e, ErrNotConfigured) {
		t.Fatalf("missing policy: %v", e)
	}
}
func TestRootPolicyAndOriginalMarkerGuards(t *testing.T) {
	for _, mutation := range []string{"policy-mode", "policy-symlink", "policy-owner", "marker-drift", "marker-kind", "instance-id"} {
		t.Run(mutation, func(t *testing.T) {
			f := newFixture(t)
			p := f.x.paths
			switch mutation {
			case "policy-mode":
				os.Chmod(p.policy, 0666)
			case "policy-symlink":
				os.Rename(p.policy, p.policy+"-real")
				os.Symlink(p.policy+"-real", p.policy)
			case "policy-owner":
				os.Chown(p.policy, 65534, 65534)
			case "marker-drift":
				os.WriteFile(filepath.Join(filepath.Dir(p.instance), "linux-owner-marker"), []byte("other"), 0600)
			case "marker-kind":
				f.x.instance.Kind = "wsl-managed"
				os.WriteFile(p.instance, encoded(f.x.instance), 0600)
			case "instance-id":
				f.x.instance.InstanceID = strings.Repeat("b", 64)
				os.WriteFile(p.instance, encoded(f.x.instance), 0600)
			}
			if _, e := open(p); e == nil {
				t.Fatal("unsafe policy/marker accepted")
			}
		})
	}
}
func TestRejectForgedEnvelopePayloadAndRequest(t *testing.T) {
	for _, mutation := range []string{"signature", "payload", "intent", "size", "expired", "trailing"} {
		t.Run(mutation, func(t *testing.T) {
			f := newFixture(t)
			switch mutation {
			case "signature":
				_, private, _ := ed25519.GenerateKey(rand.Reader)
				f.request.Envelope = signFixture(t, private, f.payload, f.request.Intent.ToBinding, 1, time.Now().Add(time.Hour))
			case "payload":
				f.payload = append([]byte(nil), f.payload...)
				f.payload[len(f.payload)/2] ^= 1
			case "intent":
				f.request.Intent.ToBinding = strings.Repeat("f", 64)
			case "size":
				f.request.PayloadSize++
			case "expired":
				f.request.Envelope = signFixture(t, f.private, f.payload, f.request.Intent.ToBinding, 1, time.Now().Add(-time.Hour))
			case "trailing":
				f.payload = append(f.payload, 0)
			}
			if _, e := f.x.Submit(context.Background(), f.request, bytes.NewReader(f.payload)); e == nil {
				t.Fatal("invalid input accepted")
			}
			if fakeBackend(f.x.backend.(fakeBackend)).read().Calls != 0 {
				t.Fatal("backend invoked for invalid input")
			}
		})
	}
}
func TestQueuedJobExtractsOnlyCandidateAndRunsOnce(t *testing.T) {
	f := newFixture(t)
	submitFixture(t, f)
	dir := f.x.jobDir(f.request.Intent.AttemptID)
	if _, e := os.Stat(filepath.Join(dir, "launcher")); !os.IsNotExist(e) {
		t.Fatal("host launcher extracted into root job")
	}
	entries, e := os.ReadDir(filepath.Join(dir, "candidate"))
	if e != nil || len(entries) != 6 {
		t.Fatalf("candidate entries %d, %v", len(entries), e)
	}
	if e := f.x.Run(context.Background(), f.request.Intent.AttemptID, false); e != nil {
		t.Fatal(e)
	}
	if e := f.x.Run(context.Background(), f.request.Intent.AttemptID, false); e != nil {
		t.Fatal(e)
	}
	j, e := f.x.Submit(context.Background(), f.request, bytes.NewReader(f.payload))
	if e != nil || j.State != "upgraded" {
		t.Fatalf("replay %s %v", j.State, e)
	}
	if f.x.backend.(fakeBackend).read().Calls != 1 {
		t.Fatal("upgrade replayed")
	}
}
func TestSameJobCannotChangeIdentity(t *testing.T) {
	f := newFixture(t)
	submitFixture(t, f)
	f.request.Intent.ArtifactSHA256 = strings.Repeat("f", 64)
	if _, e := f.x.Submit(context.Background(), f.request, bytes.NewReader(f.payload)); e == nil {
		t.Fatal("same job accepted different intent")
	}
}
func TestQueuedCandidateTamperNeverExecutes(t *testing.T) {
	f := newFixture(t)
	submitFixture(t, f)
	os.WriteFile(filepath.Join(f.x.jobDir(f.request.Intent.AttemptID), "successor"), []byte("evil"), 0755)
	if e := f.x.Run(context.Background(), f.request.Intent.AttemptID, false); e == nil {
		t.Fatal("tampered successor executed")
	}
	if f.x.backend.(fakeBackend).read().Calls != 0 {
		t.Fatal("backend invoked")
	}
}
func TestNewQueuedJobCannotStartAfterExpiry(t *testing.T) {
	f := newFixture(t)
	submitFixture(t, f)
	f.x.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if e := f.x.Run(context.Background(), f.request.Intent.AttemptID, false); !errors.Is(e, desktopupdate.ErrExpired) {
		t.Fatalf("queued expiry = %v", e)
	}
}
func TestRecoveryUsesAcceptedTimeAndNeverReplaysUpgrade(t *testing.T) {
	f := newFixture(t)
	submitFixture(t, f)
	lock, e := f.x.lock()
	if e != nil {
		t.Fatal(e)
	}
	s, e := f.x.load()
	if e != nil {
		t.Fatal(e)
	}
	s.Jobs[0].State = "running"
	s.Jobs[0].Process = processIdentity{PID: 999999, Boot: "old-boot", Start: "1"}
	if e := f.x.save(s); e != nil {
		t.Fatal(e)
	}
	lock.Close()
	w := f.x.backend.(fakeBackend).read()
	w.Binding = f.request.Intent.ToBinding
	f.x.backend.(fakeBackend).write(w)
	f.x.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if e := f.x.Run(context.Background(), f.request.Intent.AttemptID, true); e != nil {
		t.Fatal(e)
	}
	w = f.x.backend.(fakeBackend).read()
	if w.Calls != 0 || w.Recoveries != 1 {
		t.Fatalf("recovery effects: %+v", w)
	}
}
func TestUnknownOldRecoveryRemainsUnknown(t *testing.T) {
	f := newFixture(t)
	submitFixture(t, f)
	lock, _ := f.x.lock()
	s, _ := f.x.load()
	s.Jobs[0].State = "running"
	s.Jobs[0].Process = processIdentity{PID: 999999, Boot: "old-boot", Start: "1"}
	if e := f.x.save(s); e != nil {
		t.Fatal(e)
	}
	s.Jobs[0].State = "unknown"
	if e := f.x.save(s); e != nil {
		t.Fatal(e)
	}
	lock.Close()
	if e := f.x.Run(context.Background(), f.request.Intent.AttemptID, true); !errors.Is(e, ErrBusy) {
		t.Fatalf("ambiguous old state = %v", e)
	}
	j, _ := f.x.Status(f.request.Intent.AttemptID)
	if j.State != "unknown" || f.x.backend.(fakeBackend).read().Calls != 0 {
		t.Fatal("unknown recovery inferred upgrade/rollback")
	}
}
func TestCommandRejectsPathAndTrustFlags(t *testing.T) {
	f := newFixture(t)
	for _, args := range [][]string{{"submit", "--public-key", "anything"}, {"run", "../../x"}, {"upgrade", "/bin/sh"}} {
		var out bytes.Buffer
		if f.x.Command(context.Background(), args, strings.NewReader(""), &out) == 0 {
			t.Fatalf("accepted %v", args)
		}
	}
}

// The test binary doubles as a root-owned worker executable, so this covers
// the production fd-pinned exec/setsid code without relying on an image shell.
func init() {
	if len(os.Args) == 3 && os.Args[1] == "run" {
		exe, e := os.Executable()
		if e != nil {
			os.Exit(71)
		}
		x, e := openFixture(filepath.Dir(exe))
		if e != nil {
			os.Exit(72)
		}
		if e := x.Run(context.Background(), os.Args[2], false); e != nil {
			os.Exit(73)
		}
		os.Exit(0)
	}
}

func TestDetachedWorkerSurvivesSubmittingProcess(t *testing.T) {
	if os.Getenv("GUEST_UPDATE_SUBMIT") != "" {
		root := os.Getenv("GUEST_UPDATE_SUBMIT")
		x, e := openFixture(root)
		if e != nil {
			os.Exit(74)
		}
		raw, e := os.ReadFile(filepath.Join(root, "request"))
		if e != nil {
			os.Exit(75)
		}
		var r SubmitRequest
		if decode(raw, &r) != nil {
			os.Exit(76)
		}
		f, e := os.Open(filepath.Join(root, "input"))
		if e != nil {
			os.Exit(77)
		}
		if _, e = x.Submit(context.Background(), r, f); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(78)
		}
		os.Exit(0)
	}
	f := newFixture(t)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	root := f.x.paths.anchor
	binary, e := os.ReadFile(exe)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(f.x.paths.executable, binary, 0755); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(root, "request"), encoded(f.request), 0600)
	os.WriteFile(filepath.Join(root, "input"), f.payload, 0600)
	cmd := exec.Command(exe, "-test.run=^TestDetachedWorkerSurvivesSubmittingProcess$")
	cmd.Env = append(os.Environ(), "GUEST_UPDATE_SUBMIT="+root)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("submit process %v: %s", e, out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, e := f.x.Status(f.request.Intent.AttemptID)
		if e == nil && j.State == "upgraded" {
			if f.x.backend.(fakeBackend).read().Calls != 1 {
				t.Fatal("worker executed twice")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("detached worker did not finish after submitter exited")
}
func TestBoundedReceiptAndConcurrentLocks(t *testing.T) {
	f := newFixture(t)
	lock, e := f.x.lock()
	if e != nil {
		t.Fatal(e)
	}
	if _, e := f.x.lock(); !errors.Is(e, ErrBusy) {
		t.Fatal("concurrent writer lock admitted")
	}
	s, e := f.x.load()
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 32; i++ {
		id := digest([]byte{byte(i)})
		r := f.request.Intent
		r.AttemptID = id
		s.Jobs = append(s.Jobs, JobReceipt{Intent: r, State: "queued", EnvelopeSHA: digest(f.request.Envelope), AcceptedAt: time.Now(), Sequence: 1})
		s.Floor = 1
		s.FloorSHA = digest([]byte("floor"))
		if e := f.x.save(s); e != nil {
			t.Fatal(e)
		}
		s.Jobs[len(s.Jobs)-1].State = "rejected"
		if e := f.x.save(s); e != nil {
			t.Fatal(e)
		}
	}
	lock.Close()
	if _, e := f.x.Submit(context.Background(), f.request, bytes.NewReader(f.payload)); !errors.Is(e, ErrConflict) {
		t.Fatalf("unverifiable historical receipt must not be collected: %v", e)
	}
}

func TestCatalogFloorSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	f.request.Envelope = signFixture(t, f.private, f.payload, f.request.Intent.ToBinding, 2, time.Now().Add(time.Hour))
	submitFixture(t, f)
	if e := f.x.Run(context.Background(), f.request.Intent.AttemptID, false); e != nil {
		t.Fatal(e)
	}
	reopened, e := openFixture(f.x.paths.anchor)
	if e != nil {
		t.Fatal(e)
	}
	reopened.spawn = func(string) error { return nil }
	f.request.Intent.AttemptID = strings.Repeat("3", 64)
	f.request.Envelope = signFixture(t, f.private, f.payload, f.request.Intent.ToBinding, 1, time.Now().Add(time.Hour))
	if _, e := reopened.Submit(context.Background(), f.request, bytes.NewReader(f.payload)); !errors.Is(e, desktopupdate.ErrSequenceRollback) {
		t.Fatalf("lower persisted floor: %v", e)
	}
	f.request.Envelope = signFixture(t, f.private, f.payload, f.request.Intent.ToBinding, 2, time.Now().Add(2*time.Hour))
	if _, e := reopened.Submit(context.Background(), f.request, bytes.NewReader(f.payload)); !errors.Is(e, desktopupdate.ErrSequenceRollback) {
		t.Fatalf("same sequence altered payload: %v", e)
	}
}

func TestQuarantinedUploadsAreBounded(t *testing.T) {
	f := newFixture(t)
	// Model interrupted intakes after the store was initialized.
	lock, _ := f.x.lock()
	if _, e := f.x.load(); e != nil {
		t.Fatal(e)
	}
	lock.Close()
	for i := 0; i < 32; i++ {
		if e := os.Mkdir(f.x.jobDir(digest([]byte{byte(i)})), 0700); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := f.x.Submit(context.Background(), f.request, bytes.NewReader(f.payload)); !errors.Is(e, ErrCapacity) {
		t.Fatalf("orphan upload capacity: %v", e)
	}
}

func TestLiveWorkerCannotBeRecoveredConcurrently(t *testing.T) {
	f := newFixture(t)
	submitFixture(t, f)
	lock, _ := f.x.lock()
	s, e := f.x.load()
	if e != nil {
		t.Fatal(e)
	}
	s.Jobs[0].State = "running"
	s.Jobs[0].Process, e = currentProcess()
	if e != nil {
		t.Fatal(e)
	}
	if e := f.x.save(s); e != nil {
		t.Fatal(e)
	}
	lock.Close()
	if e := f.x.Run(context.Background(), f.request.Intent.AttemptID, true); !errors.Is(e, ErrBusy) {
		t.Fatalf("live worker recovered: %v", e)
	}
	if f.x.backend.(fakeBackend).read().Recoveries != 0 {
		t.Fatal("recovery raced running worker")
	}
}

func TestMarkerKindsMatchExistingNativeSchemas(t *testing.T) {
	for _, kind := range []string{"mac-managed", "wsl-managed"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			var marker []byte
			if kind == "mac-managed" {
				f.x.policy.HostOS = "darwin"
				f.x.instance.NativeID = "01234567-89ab-cdef-0123-456789abcdef"
				marker = []byte(`{"product": "acornfox", "instance": "01234567-89ab-cdef-0123-456789abcdef"}`)
			} else {
				f.x.policy.HostOS = "windows"
				f.x.instance.NativeID = "0123456789abcdef0123456789abcdef"
				marker = []byte(`{"product":"acornfox","host_uuid":"0123456789abcdef0123456789abcdef"}`)
			}
			f.x.instance.Kind = kind
			f.x.instance.InstanceID = digest([]byte(kind + ":" + f.x.instance.NativeID))
			f.x.instance.MarkerSHA256 = digest(marker)
			os.WriteFile(f.x.paths.policy, encoded(f.x.policy), 0600)
			os.WriteFile(f.x.paths.instance, encoded(f.x.instance), 0600)
			os.WriteFile(f.x.paths.marker, marker, 0600)
			if _, e := open(f.x.paths); e != nil {
				t.Fatal(e)
			}
			bad := append([]byte(nil), marker[:len(marker)-1]...)
			bad = append(bad, []byte(`,"product":"acornfox"}`)...)
			f.x.instance.MarkerSHA256 = digest(bad)
			os.WriteFile(f.x.paths.marker, bad, 0600)
			os.WriteFile(f.x.paths.instance, encoded(f.x.instance), 0600)
			if _, e := open(f.x.paths); e == nil {
				t.Fatal("duplicate native marker key accepted")
			}
		})
	}
}

func TestSnapshotCrashChild(t *testing.T) {
	root := os.Getenv("GUEST_UPDATE_CRASH_ROOT")
	if root == "" {
		return
	}
	x, e := openFixture(root)
	if e != nil {
		os.Exit(85)
	}
	point := os.Getenv("GUEST_UPDATE_CRASH_POINT")
	terminal := os.Getenv("GUEST_UPDATE_CRASH_STAGE") == "terminal"
	hits := 0
	x.fault = func(label string) {
		if label == point {
			hits++
			if (!terminal && hits == 1) || (terminal && hits == 2) {
				os.Exit(89)
			}
		}
	}
	if os.Getenv("GUEST_UPDATE_CRASH_STAGE") == "queued" {
		x.spawn = func(string) error { return nil }
		raw, e := os.ReadFile(filepath.Join(root, "request"))
		if e != nil {
			os.Exit(84)
		}
		var request SubmitRequest
		if decode(raw, &request) != nil {
			os.Exit(84)
		}
		input, e := os.Open(filepath.Join(root, "input"))
		if e != nil {
			os.Exit(84)
		}
		if _, e := x.Submit(context.Background(), request, input); e != nil {
			os.Exit(86)
		}
	} else if e := x.Run(context.Background(), crashJobID(), false); e != nil {
		os.Exit(86)
	}
	os.Exit(87)
}
func TestSnapshotCrashRecoveryNeverReplaysBackend(t *testing.T) {
	for _, stage := range []string{"queued", "running", "terminal"} {
		for _, point := range []string{"snapshot-partial", "snapshot-before-rename", "snapshot-after-rename"} {
			t.Run(stage+"/"+point, func(t *testing.T) {
				f := newFixture(t)
				if stage == "queued" {
					if _, e := f.x.Status(f.request.Intent.AttemptID); e != nil {
						t.Fatal(e)
					}
					os.WriteFile(filepath.Join(f.x.paths.anchor, "request"), encoded(f.request), 0600)
					os.WriteFile(filepath.Join(f.x.paths.anchor, "input"), f.payload, 0600)
				} else {
					submitFixture(t, f)
				}
				exe, e := os.Executable()
				if e != nil {
					t.Fatal(e)
				}
				cmd := exec.Command(exe, "-test.run=^TestSnapshotCrashChild$")
				cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
				cmd.Env = append(os.Environ(), "GUEST_UPDATE_CRASH_ROOT="+f.x.paths.anchor, "GUEST_UPDATE_CRASH_POINT="+point, "GUEST_UPDATE_CRASH_STAGE="+stage)
				err := cmd.Run()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 89 {
					t.Fatalf("crash injection: %v", err)
				}
				x, e := openFixture(f.x.paths.anchor)
				if e != nil {
					t.Fatal(e)
				}
				if _, e := x.Status(f.request.Intent.AttemptID); e != nil {
					t.Fatal(e)
				}
				x.spawn = func(string) error { return nil }
				if stage == "queued" {
					if _, e := x.Submit(context.Background(), f.request, bytes.NewReader(f.payload)); e != nil {
						t.Fatal(e)
					}
				}
				e = x.Run(context.Background(), f.request.Intent.AttemptID, false)
				world := x.backend.(fakeBackend).read()
				if stage == "running" && point != "snapshot-partial" {
					if !errors.Is(e, ErrBusy) || world.Calls != 0 || world.Recoveries != 1 {
						t.Fatalf("durable start must only recover: %+v %v", world, e)
					}
				} else {
					if e != nil || world.Calls != 1 {
						t.Fatalf("backend effects replayed/lost: %+v %v", world, e)
					}
				}
				if point == "snapshot-partial" {
					// A preserved torn-state quarantine must not disable later,
					// explicitly signed submissions after this job is finalized.
					payload, to := signedTestPayload(t, world.Binding)
					next := f.request
					next.Intent.AttemptID = strings.Repeat("4", 64)
					next.Intent.FromBinding = world.Binding
					next.Intent.ToBinding = to
					next.Intent.ArtifactSHA256 = digest(payload)
					next.PayloadSize = int64(len(payload))
					next.Envelope = signFixture(t, f.private, payload, to, 2, time.Now().Add(time.Hour))
					if _, e := x.Submit(context.Background(), next, bytes.NewReader(payload)); e != nil {
						t.Fatal(e)
					}
					if _, e := os.Lstat(filepath.Join(x.paths.state, "state-quarantine")); !errors.Is(e, os.ErrNotExist) {
						t.Fatalf("converged owned quarantine not collected: %v", e)
					}
				}
			})
		}
	}
}
func TestQuarantineNeverOverwritesUnknownBytes(t *testing.T) {
	f := newFixture(t)
	submitFixture(t, f)
	p := filepath.Join(f.x.paths.state, "state-quarantine")
	os.WriteFile(p, []byte("retain me"), 0600)
	next := filepath.Join(f.x.paths.state, "state-next.json")
	os.WriteFile(next, []byte(`{"revision":`), 0600)
	if _, e := f.x.Status(f.request.Intent.AttemptID); !errors.Is(e, ErrConflict) {
		t.Fatalf("second partial should stop: %v", e)
	}
	raw, _ := os.ReadFile(p)
	if string(raw) != "retain me" {
		t.Fatal("quarantine was overwritten")
	}
	if _, e := os.Stat(next); e != nil {
		t.Fatal("new unknown partial was removed")
	}
}

func TestObservationUsesSharedControllerAttemptStates(t *testing.T) {
	f := newFixture(t)
	submitFixture(t, f)
	lock, _ := f.x.lock()
	s, e := f.x.load()
	if e != nil {
		t.Fatal(e)
	}
	s.Jobs[0].State = "running"
	s.Jobs[0].Process, e = currentProcess()
	if e != nil {
		t.Fatal(e)
	}
	if e := f.x.save(s); e != nil {
		t.Fatal(e)
	}
	s.Jobs[0].State = "recovering"
	if e := f.x.save(s); e != nil {
		t.Fatal(e)
	}
	lock.Close()
	obs, e := f.x.Observe(context.Background(), f.request.Intent.AttemptID)
	if e != nil || obs.AttemptState != "running" {
		t.Fatalf("shared attempt state = %s, %v", obs.AttemptState, e)
	}
}

func crashJobID() string {
	if id := os.Getenv("GUEST_UPDATE_CRASH_ID"); id != "" {
		return id
	}
	return strings.Repeat("2", 64)
}

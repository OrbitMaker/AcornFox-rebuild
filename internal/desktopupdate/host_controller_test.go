package desktopupdate

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

type hostWorld struct {
	Offline                 bool
	Reject                  bool
	Instance, Binding, Slot string
	Attempts                map[string]bool
	Calls                   int
	Rollback, FailHost      bool
}
type hostFake struct {
	path  string
	crash string
}

func (f hostFake) read() hostWorld {
	raw, e := os.ReadFile(f.path)
	if e != nil {
		panic(e)
	}
	var w hostWorld
	if json.Unmarshal(raw, &w) != nil {
		panic("world")
	}
	return w
}
func (f hostFake) write(w hostWorld) {
	if e := os.WriteFile(f.path, hostBytes(w), 0600); e != nil {
		panic(e)
	}
}
func (f hostFake) Observe(_ context.Context, id string) (BackendObservation, error) {
	w := f.read()
	if w.Offline {
		return BackendObservation{}, errors.New("VM is stopped during host handoff")
	}
	phase := "absent"
	if w.Attempts[id] {
		phase = "upgraded"
		if w.Rollback {
			phase = "rolled-back"
		}
		if w.Reject {
			phase = "rejected"
		}
	}
	return BackendObservation{LocalLoopback: true, MigrationVersion: "0040", Architecture: "amd64", InstanceID: w.Instance, Binding: w.Binding, Ready: true, Finalized: true, AttemptState: phase}, nil
}
func (f hostFake) EnsureUpgrade(_ context.Context, i HostUpgradeIntent, b *VerifiedHostBundle) error {
	w := f.read()
	if !w.Attempts[i.AttemptID] {
		if i.InstanceID != w.Instance || i.FromBinding != w.Binding || i.ToBinding != b.manifest.Backend.ToBinding || i.ArtifactSHA256 != b.SHA256() {
			return ErrHostConflict
		}
		w.Calls++
		w.Attempts[i.AttemptID] = true
		if !w.Rollback && !w.Reject {
			w.Binding = i.ToBinding
		}
		f.write(w)
	}
	if f.crash == "backend-executed" {
		os.Exit(83)
	}
	return nil
}
func (f hostFake) CurrentSlot(context.Context) (string, error) { return f.read().Slot, nil }
func (f hostFake) Prepare(_ context.Context, b *VerifiedHostBundle, old string) error {
	if f.read().Slot != old {
		return ErrHostConflict
	}
	return b.ReadFile(b.manifest.Launcher, io.Discard)
}
func (f hostFake) Activate(_ context.Context, id, old, next string) error {
	w := f.read()
	if w.Slot == next {
		return nil
	}
	if w.Slot != old {
		return ErrHostConflict
	}
	w.Slot = next
	if w.FailHost {
		w.Offline = next != strings.Repeat("1", 64)
	}
	f.write(w)
	if f.crash == "host-activated" {
		os.Exit(83)
	}
	return nil
}
func (f hostFake) Probe(_ context.Context, slot, backend string) error {
	w := f.read()
	if w.Slot != slot || w.Binding != backend {
		return ErrHostConflict
	}
	if w.FailHost && slot != strings.Repeat("1", 64) {
		return errors.New("launcher failed")
	}
	return nil
}

type hostFixture struct {
	c        *HostController
	world    hostFake
	private  ed25519.PrivateKey
	payload  []byte
	manifest HostBundleManifest
	envelope []byte
}

func hostTestBundle(t *testing.T, version, from string) ([]byte, HostBundleManifest) {
	t.Helper()
	helper := hostSHA([]byte("helper"))
	manifest := hostBytes(map[string]any{"schema_version": 1, "product": "acornfox", "version": version, "release_id": "release-" + version, "source_commit": strings.Repeat("a", 40), "architecture": "amd64", "migration_version": "0040", "files": []map[string]any{{"path": "bin/acornfox-upgrade", "sha256": helper, "mode": 0755}}})
	archive := []byte("backend executor owns verification of this signed backend fixture")
	bundle := []byte("bundle manifest\n")
	binding := hostBytes(map[string]any{"schema_version": 1, "product": "acornfox", "version": version, "release_id": "release-" + version, "source_commit": strings.Repeat("a", 40), "architecture": "amd64", "migration_version": "0040", "archive_sha256": hostSHA(archive), "manifest_sha256": hostSHA(manifest), "bundle_manifest_sha256": hostSHA(bundle), "n_minus_one": map[string]string{"binding_sha256": from}})
	to := hostSHA(binding)
	contents := map[string][]byte{"launcher/AcornFox": []byte("host launcher"), "controller/acornfox-host-update": []byte("controller"), "backend/candidate/candidate-binding.json": binding, "backend/candidate/candidate-binding.sha256": []byte(to + "\n"), "backend/candidate/release-manifest.json": manifest, "backend/candidate/bundle-manifest.sha256": bundle, "backend/candidate/build-record.json": []byte(`{"schema_version":1}`), "backend/candidate/acornfox-" + version + "-production.tar.gz": archive}
	m := HostBundleManifest{SchemaVersion: 1, Product: "acornfox", Kind: "host-update-v1", OS: "linux", Architecture: "amd64", Version: version, ControllerProtocol: 1, InstanceProtocol: 1, Launcher: "launcher/AcornFox", Controller: "controller/acornfox-host-update", Backend: HostBackendPlan{Mode: "candidate", FromBinding: from, ToBinding: to, Architecture: "amd64", HelperSHA256: helper, APIProtocol: 1}}
	for p, b := range contents {
		mode := int64(0644)
		if strings.HasPrefix(p, "launcher/") || strings.HasPrefix(p, "controller/") {
			mode = 0755
		}
		m.Files = append(m.Files, HostBundleFile{p, hostSHA(b), int64(len(b)), mode})
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	return hostArchive(t, m, contents), m
}
func hostArchive(t *testing.T, m HostBundleManifest, contents map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	w := tar.NewWriter(g)
	raw := hostBytes(m)
	if e := w.WriteHeader(&tar.Header{Name: "bundle.json", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(raw))}); e != nil {
		t.Fatal(e)
	}
	w.Write(raw)
	for _, f := range m.Files {
		w.WriteHeader(&tar.Header{Name: f.Path, Typeflag: tar.TypeReg, Mode: f.Mode, Size: f.Size})
		w.Write(contents[f.Path])
	}
	w.Close()
	g.Close()
	return b.Bytes()
}
func newHostFixture(t *testing.T) hostFixture {
	t.Helper()
	root, e := filepath.EvalSymlinks(createTestParentDir(t))
	if e != nil {
		t.Fatal(e)
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	data, m := hostTestBundle(t, "1.1.0", strings.Repeat("a", 64))
	server, client := setupTestTLSServer(t, "downloads.example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(data) }))
	t.Cleanup(server.Close)
	policy := &HostPolicy{PublicKey: pub, IndexURL: "https://downloads.example.com/index.json", OS: "linux", Arch: "amd64", Channel: "stable", AllowedHosts: []string{"downloads.example.com"}}
	initial := HostInstallation{Version: "1.0.0", SlotSHA256: strings.Repeat("1", 64), BackendBinding: strings.Repeat("a", 64)}
	f := hostFake{path: filepath.Join(t.TempDir(), "world.json")}
	f.write(hostWorld{Instance: strings.Repeat("e", 64), Binding: initial.BackendBinding, Slot: initial.SlotSHA256, Attempts: map[string]bool{}})
	c, e := NewHostController(HostControllerOptions{Root: root, InstanceID: strings.Repeat("e", 64), Initial: initial, Policy: policy, Backend: f, Runtime: f, HTTPClient: client, Now: func() time.Time { return time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC) }})
	if e != nil {
		t.Fatal(e)
	}
	c.diskSpaceCheck = func(string) (uint64, error) { return 1 << 40, nil }
	env := createTestEnvelope(t, priv, IndexPayload{Channel: "stable", Sequence: 1, Version: "1.1.0", ExpiresAt: "2026-10-01T00:00:00Z", Artifacts: []Artifact{{OS: "linux", Arch: "amd64", URL: "https://downloads.example.com/bundle", SHA256: hostSHA(data), Size: int64(len(data)), BackendBinding: m.Backend.ToBinding}}})
	return hostFixture{c, f, priv, data, m, env}
}
func finishHost(t *testing.T, c *HostController) HostUpdateStatus {
	t.Helper()
	for n := 0; n < 5; n++ {
		status, e := c.Advance(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		if status.Snapshot.Pending == nil {
			return status
		}
	}
	t.Fatal("did not finish")
	return HostUpdateStatus{}
}
func TestHostControllerSuccessAndBackendFailures(t *testing.T) {
	for _, kind := range []string{"success", "backend", "host"} {
		t.Run(kind, func(t *testing.T) {
			f := newHostFixture(t)
			w := f.world.read()
			w.Rollback = kind == "backend"
			w.FailHost = kind == "host"
			f.world.write(w)
			if _, e := f.c.Select(context.Background(), f.envelope, false); e != nil {
				t.Fatal(e)
			}
			status := finishHost(t, f.c)
			w = f.world.read()
			if w.Calls != 1 {
				t.Fatal("backend execution count", w.Calls)
			}
			if kind == "success" {
				if status.State != "updated" || w.Slot != hostSHA(f.payload) || w.Binding != f.manifest.Backend.ToBinding {
					t.Fatal("success mismatch")
				}
			} else {
				if status.State != kind+"-rolled-back" || w.Slot != strings.Repeat("1", 64) {
					t.Fatal("rollback mismatch")
				}
				if kind == "host" && w.Binding != f.manifest.Backend.ToBinding {
					t.Fatal("host failure downgraded backend")
				}
				if _, e := f.c.Select(context.Background(), f.envelope, false); !errors.Is(e, ErrHostSuppressed) {
					t.Fatal("not suppressed", e)
				}
				w.Rollback = false
				w.FailHost = false
				f.world.write(w)
				if _, e := f.c.Select(context.Background(), f.envelope, true); e != nil {
					t.Fatal("explicit retry", e)
				}
				finishHost(t, f.c)
				if kind == "host" && f.world.read().Calls != 1 {
					t.Fatal("host retry repeated upgrade")
				}
			}
			entries, e := os.ReadDir(f.c.options.Root)
			if e != nil {
				t.Fatal(e)
			}
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "download-") {
					t.Fatal("stage not collected")
				}
			}
		})
	}
}
func TestHostPolicyAndCatalog(t *testing.T) {
	c, e := NewHostController(HostControllerOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if s, e := c.Status(context.Background()); e != nil || s.State != "not-configured" {
		t.Fatal(s, e)
	}
	f := newHostFixture(t)
	if _, e = f.c.Select(context.Background(), f.envelope, false); e != nil {
		t.Fatal(e)
	}
	// Current sequence has been observed, but installed sequence is still zero;
	// the very same signed candidate must still be downloadable and applicable.
	finishHost(t, f.c)
	var env IndexEnvelope
	json.Unmarshal(f.envelope, &env)
	raw, _ := base64DecodeForHost(env.Payload)
	var payload IndexPayload
	json.Unmarshal(raw, &payload)
	payload.Sequence = 2
	noUpdate := createTestEnvelope(t, f.private, payload)
	if _, e := f.c.Select(context.Background(), noUpdate, false); e != nil {
		t.Fatal(e)
	}
	if _, e := f.c.Select(context.Background(), f.envelope, false); !errors.Is(e, ErrSequenceRollback) {
		t.Fatal("floor rollback", e)
	}
	payload.Version = "1.2.0"
	different := createTestEnvelope(t, f.private, payload)
	if _, e := f.c.Select(context.Background(), different, false); !errors.Is(e, ErrSequenceRollback) {
		t.Fatal("same sequence changed payload", e)
	}
}
func base64DecodeForHost(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
func TestHostBundleRejectsClosedInventoryViolations(t *testing.T) {
	for _, kind := range []string{"base", "unknown", "traversal", "case", "binding", "digest"} {
		t.Run(kind, func(t *testing.T) {
			f := newHostFixture(t)
			data := append([]byte(nil), f.payload...)
			if kind == "digest" {
				data[len(data)/2] ^= 1
			} else {
				m := f.manifest
				contents := map[string][]byte{}
				g, _ := gzip.NewReader(bytes.NewReader(data))
				tr := tar.NewReader(g)
				for {
					h, e := tr.Next()
					if e == io.EOF {
						break
					}
					if e != nil {
						t.Fatal(e)
					}
					b, _ := io.ReadAll(tr)
					contents[h.Name] = b
				}
				g.Close()
				switch kind {
				case "base":
					m.Files[0].Path = "launcher/base.raw.gz"
				case "unknown":
					m.Kind = "other"
				case "traversal":
					m.Files[0].Path = "launcher/../../secret"
				case "case":
					m.Files[1].Path = strings.ToUpper(m.Files[0].Path)
				case "binding":
					m.Backend.ToBinding = strings.Repeat("f", 64)
				}
				data = hostArchive(t, m, contents)
				var env IndexEnvelope
				json.Unmarshal(f.envelope, &env)
				r, _ := base64DecodeForHost(env.Payload)
				var p IndexPayload
				json.Unmarshal(r, &p)
				p.Artifacts[0].SHA256 = hostSHA(data)
				p.Artifacts[0].Size = int64(len(data))
				f.envelope = createTestEnvelope(t, f.private, p)
			}
			root, _ := filepath.EvalSymlinks(createTestParentDir(t))
			p := filepath.Join(root, "payload.bin")
			os.WriteFile(p, data, 0600)
			if b, e := VerifyHostBundle(context.Background(), p, f.envelope, f.c.indexOptions(HostSnapshot{Installed: f.c.options.Initial}, f.c.options.Now())); e == nil {
				b.Close()
				t.Fatal("invalid bundle accepted")
			}
		})
	}
}

// These children run the real store lock/rename/fsync and intentionally exit
// without Go defers. Adapter state is also on disk, independent of the child.
type hostChildInput struct {
	Root, InstanceID string
	Initial          HostInstallation
	Policy           *HostPolicy
	World, Fault     string
}

func TestHostControllerChild(t *testing.T) {
	p := os.Getenv("ACORNFOX_HOST_CONTROLLER_CHILD")
	if p == "" {
		t.Skip("child only")
	}
	raw, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	var input hostChildInput
	if json.Unmarshal(raw, &input) != nil {
		t.Fatal("input")
	}
	f := hostFake{input.World, input.Fault}
	o := HostControllerOptions{Root: input.Root, InstanceID: input.InstanceID, Initial: input.Initial, Policy: input.Policy, Backend: f, Runtime: f, Now: func() time.Time { return time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC) }}
	c, e := NewHostController(o)
	if e != nil {
		t.Fatal(e)
	}
	if input.Fault == "hold-lock" {
		s, _, e := c.open(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		defer s.close()
		fmt.Println("locked")
		io.Copy(io.Discard, os.Stdin)
		return
	}
	c.fault = func(name string) error {
		if name == input.Fault {
			os.Exit(83)
		}
		return nil
	}
	if _, e := c.Advance(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func runHostChild(t *testing.T, f hostFixture, fault string, want int) {
	t.Helper()
	o := f.c.options
	o.Backend = nil
	o.Runtime = nil
	o.HTTPClient = nil
	o.Now = nil
	raw, e := json.Marshal(hostChildInput{o.Root, o.InstanceID, o.Initial, o.Policy, f.world.path, fault})
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(t.TempDir(), "child.json")
	os.WriteFile(p, raw, 0600)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHostControllerChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "ACORNFOX_HOST_CONTROLLER_CHILD="+p)
	out, e := cmd.CombinedOutput()
	code := 0
	if e != nil {
		var ex *exec.ExitError
		if !errors.As(e, &ex) {
			t.Fatal(e)
		}
		code = ex.ExitCode()
	}
	if code != want {
		t.Fatalf("child exit=%d want=%d: %s", code, want, out)
	}
}
func TestHostControllerProcessRecovery(t *testing.T) {
	for _, fault := range []string{"state-prefix", "state-staged", "state-payload", "state-published", "backend-before-ensure", "backend-executed", "host-activated", "stage-collected"} {
		t.Run(fault, func(t *testing.T) {
			f := newHostFixture(t)
			if _, e := f.c.Select(context.Background(), f.envelope, false); e != nil {
				t.Fatal(e)
			}
			s, state, e := f.c.open(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if e = f.c.download(context.Background(), s, &state); e != nil {
				t.Fatal(e)
			}
			s.close()
			if fault == "host-activated" || fault == "stage-collected" {
				runHostChild(t, f, "", 0)
			}
			runHostChild(t, f, fault, 83)
			runHostChild(t, f, "", 0)
			runHostChild(t, f, "", 0)
			status, e := f.c.Status(context.Background())
			if e != nil || status.Snapshot.Pending != nil || status.State != "updated" || f.world.read().Calls != 1 {
				t.Fatalf("not settled: %s calls=%d err=%v", status.State, f.world.read().Calls, e)
			}
		})
	}
}

func TestHostStoreOwnershipAndForeignFiles(t *testing.T) {
	for _, kind := range []string{"mode", "hardlink", "symlink", "foreign", "temporary"} {
		t.Run(kind, func(t *testing.T) {
			f := newHostFixture(t)
			if _, e := f.c.Status(context.Background()); e != nil {
				t.Fatal(e)
			}
			statePath := filepath.Join(f.c.options.Root, "state.json")
			before, _ := os.ReadFile(statePath)
			switch kind {
			case "mode":
				os.Chmod(statePath, 0666)
			case "hardlink":
				os.Link(statePath, filepath.Join(t.TempDir(), "linked"))
			case "symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				os.Symlink(f.c.options.Root, alias)
				f.c.options.Root = alias
			case "foreign":
				os.WriteFile(filepath.Join(f.c.options.Root, "user-data"), []byte("keep"), 0600)
			case "temporary":
				os.WriteFile(filepath.Join(f.c.options.Root, "state.new"), []byte("foreign"), 0600)
			}
			if _, e := f.c.Status(context.Background()); e == nil {
				t.Fatal("unsafe state accepted")
			}
			after, _ := os.ReadFile(statePath)
			if !bytes.Equal(before, after) {
				t.Fatal("changed foreign state")
			}
			if f.world.read().Calls != 0 {
				t.Fatal("reached backend")
			}
		})
	}
}
func TestHostStoreCrossProcessLock(t *testing.T) {
	f := newHostFixture(t)
	if _, e := f.c.Status(context.Background()); e != nil {
		t.Fatal(e)
	}
	o := f.c.options
	raw, _ := json.Marshal(hostChildInput{o.Root, o.InstanceID, o.Initial, o.Policy, f.world.path, "hold-lock"})
	p := filepath.Join(t.TempDir(), "input.json")
	os.WriteFile(p, raw, 0600)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHostControllerChild$")
	cmd.Env = append(os.Environ(), "ACORNFOX_HOST_CONTROLLER_CHILD="+p)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { in.Close(); cmd.Wait() }()
	line, e := bufio.NewReader(out).ReadString('\n')
	if e != nil || line != "locked\n" {
		t.Fatal(line, e)
	}
	if _, e := f.c.Status(context.Background()); !errors.Is(e, ErrHostBusy) {
		t.Fatal("second process acquired lock", e)
	}
}
func TestHostDownloadRecoveryAndTamper(t *testing.T) {
	for _, kind := range []string{"partial", "published-link", "unknown", "mode", "tamper"} {
		t.Run(kind, func(t *testing.T) {
			f := newHostFixture(t)
			if _, e := f.c.Select(context.Background(), f.envelope, false); e != nil {
				t.Fatal(e)
			}
			s, state, e := f.c.open(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			key, e := s.stageDirectory(state.Pending.ID)
			if e != nil {
				t.Fatal(e)
			}
			state.Pending.StageIdentity = key
			if e = s.save(&state); e != nil {
				t.Fatal(e)
			}
			dir := s.stagePath(state.Pending.ID)
			s.close()
			switch kind {
			case "partial":
				os.WriteFile(filepath.Join(dir, StageTempFileName), []byte("partial"), 0600)
			case "published-link":
				os.WriteFile(filepath.Join(dir, StageTempFileName), f.payload, 0600)
				os.Link(filepath.Join(dir, StageTempFileName), filepath.Join(dir, StagePayloadFileName))
			case "unknown":
				os.WriteFile(filepath.Join(dir, "foreign"), []byte("keep"), 0600)
			case "mode":
				os.WriteFile(filepath.Join(dir, StagePayloadFileName), f.payload, 0644)
			case "tamper":
				os.WriteFile(filepath.Join(dir, StagePayloadFileName), bytes.Repeat([]byte{'x'}, len(f.payload)), 0600)
			}
			if kind == "partial" || kind == "published-link" {
				finishHost(t, f.c)
				if f.world.read().Calls != 1 {
					t.Fatal("incorrect upgrade count")
				}
			} else {
				if _, e := f.c.Advance(context.Background()); e == nil {
					t.Fatal("tamper accepted")
				}
				if f.world.read().Calls != 0 {
					t.Fatal("tamper reached backend")
				}
				if kind == "unknown" {
					if b, e := os.ReadFile(filepath.Join(dir, "foreign")); e != nil || string(b) != "keep" {
						t.Fatal("foreign deleted")
					}
				}
			}
		})
	}
}

func (f hostFake) DiscardPrepared(_ context.Context, sha string) error {
	if f.read().Slot == sha {
		return ErrHostConflict
	}
	return nil
}
func TestHostExpiredOfferCanBeDismissedWithoutLoweringFloor(t *testing.T) {
	f := newHostFixture(t)
	if _, e := f.c.Select(context.Background(), f.envelope, false); e != nil {
		t.Fatal(e)
	}
	f.c.options.Now = func() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) }
	if _, e := f.c.Advance(context.Background()); e == nil {
		t.Fatal("expired accepted")
	}
	status, e := f.c.Dismiss(context.Background())
	if e != nil || status.Snapshot.Pending != nil || status.Snapshot.Catalog.Sequence != 1 || f.world.read().Calls != 0 {
		t.Fatal(status, e)
	}
}

func (f hostFake) CollectInactive(_ context.Context, keep []string) error {
	if len(keep) < 1 || len(keep) > 2 || f.read().Slot != keep[0] {
		return ErrHostConflict
	}
	return nil
}

func TestHostBackendRejectionNeverHandoffs(t *testing.T) {
	f := newHostFixture(t)
	w := f.world.read()
	w.Reject = true
	f.world.write(w)
	if _, e := f.c.Select(context.Background(), f.envelope, false); e != nil {
		t.Fatal(e)
	}
	status := finishHost(t, f.c)
	if status.State != "backend-rejected" || f.world.read().Slot != f.c.options.Initial.SlotSHA256 || f.world.read().Calls != 1 {
		t.Fatal("rejected backend switched launcher")
	}
	if _, e := f.c.Select(context.Background(), f.envelope, false); !errors.Is(e, ErrHostSuppressed) {
		t.Fatal(e)
	}
}
func TestHostFourUpdatesKeepBoundedState(t *testing.T) {
	f := newHostFixture(t)
	for n := 1; n <= 4; n++ {
		version := fmt.Sprintf("1.%d.0", n)
		data, m := hostTestBundle(t, version, f.world.read().Binding)
		server, client := setupTestTLSServer(t, "downloads.example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(data) }))
		f.c.options.HTTPClient = client
		env := createTestEnvelope(t, f.private, IndexPayload{Channel: "stable", Sequence: uint64(n), Version: version, ExpiresAt: "2026-10-01T00:00:00Z", Artifacts: []Artifact{{OS: "linux", Arch: "amd64", URL: "https://downloads.example.com/bundle", SHA256: hostSHA(data), Size: int64(len(data)), BackendBinding: m.Backend.ToBinding}}})
		if _, e := f.c.Select(context.Background(), env, false); e != nil {
			server.Close()
			t.Fatal(e)
		}
		status := finishHost(t, f.c)
		server.Close()
		if status.State != "updated" || status.Snapshot.PreviousSlot == "" || status.Snapshot.Installed.AppliedSequence != uint64(n) {
			t.Fatal("invalid committed state")
		}
		entries, _ := os.ReadDir(f.c.options.Root)
		if len(entries) != 2 {
			t.Fatal("state/stage growth", len(entries))
		}
	}
	if f.world.read().Calls != 4 {
		t.Fatal("upgrade count")
	}
}

func TestHostInterruptedHandoffRestartsOldHostBeforeProbingOfflineBackend(t *testing.T) {
	f := newHostFixture(t)
	if _, e := f.c.Select(context.Background(), f.envelope, false); e != nil {
		t.Fatal(e)
	}
	s, state, e := f.c.open(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = f.c.download(context.Background(), s, &state); e != nil {
		t.Fatal(e)
	}
	s.close()
	runHostChild(t, f, "", 0)
	w := f.world.read()
	w.FailHost = true
	f.world.write(w)
	runHostChild(t, f, "host-activated", 83)
	if !f.world.read().Offline {
		t.Fatal("did not simulate VM handoff")
	}
	runHostChild(t, f, "", 0)
	runHostChild(t, f, "", 0)
	status, e := f.c.Status(context.Background())
	w = f.world.read()
	if e != nil || status.State != "host-rolled-back" || w.Calls != 1 || w.Offline || w.Slot != strings.Repeat("1", 64) || w.Binding != f.manifest.Backend.ToBinding {
		t.Fatal(status, e)
	}
}

func TestHostStatusDoesNotExposePrivateEnvelope(t *testing.T) {
	f := newHostFixture(t)
	status, e := f.c.Select(context.Background(), f.envelope, false)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(status)
	if e != nil || bytes.Contains(raw, []byte("downloads.example.com")) || bytes.Contains(raw, []byte("Envelope")) || bytes.Contains(raw, []byte("payload")) {
		t.Fatal("status leaked private data")
	}
	if strings.Contains(fmt.Sprintf("%+v", *status.Snapshot), "downloads.example.com") {
		t.Fatal("formatter leaked URL")
	}
}

func TestHostBundleRejectsSecondGzipMemberIncludingZeroPadding(t *testing.T) {
	for _, second := range [][]byte{nil, {0, 0, 0}, {'x'}} {
		f := newHostFixture(t)
		var extra bytes.Buffer
		g := gzip.NewWriter(&extra)
		g.Write(second)
		g.Close()
		data := append(append([]byte(nil), f.payload...), extra.Bytes()...)
		var env IndexEnvelope
		json.Unmarshal(f.envelope, &env)
		raw, _ := base64DecodeForHost(env.Payload)
		var p IndexPayload
		json.Unmarshal(raw, &p)
		p.Artifacts[0].SHA256 = hostSHA(data)
		p.Artifacts[0].Size = int64(len(data))
		signed := createTestEnvelope(t, f.private, p)
		root, _ := filepath.EvalSymlinks(createTestParentDir(t))
		file := filepath.Join(root, "payload.bin")
		os.WriteFile(file, data, 0600)
		if b, e := VerifyHostBundle(context.Background(), file, signed, f.c.indexOptions(HostSnapshot{Installed: f.c.options.Initial}, f.c.options.Now())); e == nil {
			b.Close()
			t.Fatal("concatenated gzip accepted")
		}
	}
}

func TestHostFullFailureLedgerStillPersistsCatalogFloor(t *testing.T) {
	f := newHostFixture(t)
	store, state, e := f.c.open(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	state.Failures = append(state.Failures, HostFailure{"backend", f.manifest.Backend.ToBinding, state.Installed.BackendBinding, "rolled-back"})
	for i := 1; i < 64; i++ {
		state.Failures = append(state.Failures, HostFailure{"backend", hostSHA([]byte(fmt.Sprint(i))), state.Installed.BackendBinding, "rolled-back"})
	}
	if e := store.save(&state); e != nil {
		t.Fatal(e)
	}
	store.close()
	data, m := hostTestBundle(t, "1.2.0", state.Installed.BackendBinding)
	offer := IndexPayload{Channel: "stable", Version: "1.2.0", Sequence: 100, ExpiresAt: "2026-10-01T00:00:00Z", Artifacts: []Artifact{{OS: "linux", Arch: "amd64", URL: "https://downloads.example.com/bundle", SHA256: hostSHA(data), Size: int64(len(data)), BackendBinding: m.Backend.ToBinding}}}
	if _, e := f.c.Select(context.Background(), createTestEnvelope(t, f.private, offer), false); !errors.Is(e, ErrHostSuppressed) {
		t.Fatal(e)
	}
	status, e := f.c.Status(context.Background())
	if e != nil || status.Snapshot.Catalog.Sequence != 100 {
		t.Fatal("suppression lost catalog floor", e)
	}
	if _, e := f.c.Select(context.Background(), f.envelope, true); !errors.Is(e, ErrSequenceRollback) {
		t.Fatal("old known failure bypassed floor", e)
	}
	var envelope IndexEnvelope
	json.Unmarshal(f.envelope, &envelope)
	raw, _ := base64DecodeForHost(envelope.Payload)
	var retry IndexPayload
	json.Unmarshal(raw, &retry)
	retry.Sequence = 101
	if _, e := f.c.Select(context.Background(), createTestEnvelope(t, f.private, retry), true); e != nil {
		t.Fatal(e)
	}
	finishHost(t, f.c)
	offer.Sequence = 99
	if _, e := f.c.Select(context.Background(), createTestEnvelope(t, f.private, offer), false); !errors.Is(e, ErrSequenceRollback) {
		t.Fatal("failure pruning lowered floor", e)
	}
}

func TestHostControllerTerminalCleanupClosesPayload(t *testing.T) {
	for _, kind := range []string{"success", "backend-rolled-back", "backend-rejected", "host-rolled-back"} {
		t.Run(kind, func(t *testing.T) {
			f := newHostFixture(t)
			world := f.world.read()
			world.Rollback = kind == "backend-rolled-back"
			world.Reject = kind == "backend-rejected"
			world.FailHost = kind == "host-rolled-back"
			f.world.write(world)
			selected, e := f.c.Select(context.Background(), f.envelope, false)
			if e != nil {
				t.Fatal(e)
			}
			stage := filepath.Join(f.c.options.Root, "download-"+selected.Snapshot.Pending.ID)
			var last HostUpdateStatus
			for n := 0; n < 5; n++ {
				last, e = f.c.Advance(context.Background())
				if e != nil {
					t.Fatal("terminal cleanup failed", e)
				}
				if last.Snapshot.Pending == nil {
					break
				}
			}
			want := kind
			if kind == "success" {
				want = "updated"
			}
			if last.State != want || last.Snapshot.Pending != nil || len(last.Snapshot.Cleanup) != 0 || last.Snapshot.CollectSlots {
				t.Fatal("cleanup did not settle", last.State)
			}
			if _, e := os.Lstat(stage); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("terminal stage retained", e)
			}
			// A second explicit reconciliation is unnecessary for handle reclamation.
			if _, e = f.c.Advance(context.Background()); e != nil {
				t.Fatal(e)
			}
		})
	}
}

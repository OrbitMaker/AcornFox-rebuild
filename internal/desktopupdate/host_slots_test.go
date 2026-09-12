package desktopupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

var slotHelperOnce sync.Once
var slotHelperBytes []byte
var slotHelperError error

func slotHelper(t *testing.T) []byte {
	t.Helper()
	slotHelperOnce.Do(func() {
		supplied := os.Getenv("ACORNFOX_SLOT_TEST_HELPER")
		expected := os.Getenv("ACORNFOX_SLOT_TEST_HELPER_SHA256")
		if supplied != "" || expected != "" {
			if !filepath.IsAbs(supplied) || validateSHA256(expected) != nil {
				slotHelperError = errors.New("test helper requires absolute path and SHA256")
				return
			}
			slotHelperBytes, slotHelperError = slotReadTestHelper(supplied, expected)
			return
		}
		dir, e := os.MkdirTemp("", "acornfox-slot-helper-")
		if e != nil {
			slotHelperError = e
			return
		}
		defer os.RemoveAll(dir)
		binary := filepath.Join(dir, "helper")
		if runtime.GOOS == "windows" {
			binary += ".exe"
		}
		source := filepath.Join("testdata", "slot_helper", "main.go")
		out, e := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", binary, source).CombinedOutput()
		if e != nil {
			slotHelperError = fmt.Errorf("build helper (or provide ACORNFOX_SLOT_TEST_HELPER and pinned SHA256): %w %s", e, out)
			return
		}
		raw, e := os.ReadFile(binary)
		if e != nil {
			slotHelperError = e
			return
		}
		slotHelperBytes, slotHelperError = slotReadTestHelper(binary, hostSHA(raw))
	})
	if slotHelperError != nil {
		t.Fatal(slotHelperError)
	}
	return slotHelperBytes
}

type slotFixture struct {
	Root     string
	Spec     HostBootstrapSpec
	Payload  string
	Envelope []byte
	Options  CheckUpdateOptions
	ID       string
	Input    string
}

func newSlotFixture(t *testing.T) slotFixture {
	t.Helper()
	base, e := filepath.EvalSymlinks(createTestParentDir(t))
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(base, "slots")
	boot := filepath.Join(base, "bootstrap")
	for _, p := range []string{root, boot} {
		if e = os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
		if e = secureNewStageDirectory(context.Background(), p); e != nil {
			t.Fatal(e)
		}
	}
	data := slotHelper(t)
	spec := HostBootstrapSpec{Root: boot, OS: runtime.GOOS, Architecture: runtime.GOARCH, Version: "1.0.0", Launcher: "launcher", Controller: "controller", ControllerProtocol: 1, InstanceProtocol: 1, BackendAPIProtocol: 1}
	if runtime.GOOS == "windows" {
		spec.Launcher += ".exe"
		spec.Controller += ".exe"
	}
	for _, name := range []string{spec.Controller, spec.Launcher} {
		if e = os.WriteFile(filepath.Join(boot, name), data, 0755); e != nil {
			t.Fatal(e)
		}
		spec.Files = append(spec.Files, HostBundleFile{name, hostSHA(data), int64(len(data)), 0755})
	}
	os.WriteFile(filepath.Join(boot, "user-owned-sentinel"), []byte("retain"), 0600)
	f := slotFixture{Root: root, Spec: spec, ID: strings.Repeat("e", 64), Input: filepath.Join(base, "child.json")}
	f = slotFixtureBundle(t, f, "1.1.0", data)
	return f
}
func slotFixtureBundle(t *testing.T, f slotFixture, version string, executable []byte) slotFixture {
	t.Helper()
	controller := "controller/acornfox-host-update"
	launcher := "launcher/acornfox"
	if runtime.GOOS == "windows" {
		controller += ".exe"
		launcher += ".exe"
	}
	contents := map[string][]byte{controller: executable, launcher: executable, "launcher/assets/readme.txt": []byte(version)}
	binding := strings.Repeat("a", 64)
	m := HostBundleManifest{SchemaVersion: 1, Product: "acornfox", Kind: "host-update-v1", OS: runtime.GOOS, Architecture: runtime.GOARCH, Version: version, ControllerProtocol: 1, InstanceProtocol: 1, Launcher: launcher, Controller: controller, Backend: HostBackendPlan{Mode: "unchanged", FromBinding: binding, ToBinding: binding, Architecture: runtime.GOARCH, APIProtocol: 1}}
	for name, data := range contents {
		mode := int64(0644)
		if name == launcher || name == controller {
			mode = 0755
		}
		m.Files = append(m.Files, HostBundleFile{name, hostSHA(data), int64(len(data)), mode})
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	payload := hostArchive(t, m, contents)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	f.Payload = filepath.Join(filepath.Dir(f.Root), "payload-"+version)
	if e = os.WriteFile(f.Payload, payload, 0600); e != nil {
		t.Fatal(e)
	}
	f.Envelope = createTestEnvelope(t, key, IndexPayload{Channel: "stable", Sequence: 1, Version: version, ExpiresAt: "2026-10-01T00:00:00Z", Artifacts: []Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "https://downloads.example.com/bundle", SHA256: hostSHA(payload), Size: int64(len(payload)), BackendBinding: binding}}})
	f.Options = CheckUpdateOptions{PublicKey: pub, TargetOS: runtime.GOOS, TargetArch: runtime.GOARCH, AllowedChannel: "stable", CurrentVersion: "1.0.0", CurrentTime: time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC), AllowedHosts: []string{"downloads.example.com"}}
	return f
}
func (f slotFixture) open(t *testing.T) (*HostSlots, *VerifiedHostBundle) {
	t.Helper()
	b, e := PinHostBootstrap(context.Background(), f.Spec)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close() })
	hooks := HostSlotHooks{Stop: func(context.Context, string, string, HostSlotView) error { return nil }, Start: func(_ context.Context, instance string, v HostSlotView) error {
		if instance != f.ID {
			return ErrHostConflict
		}
		out, e := exec.Command(v.LauncherPath(), "fixture-start").CombinedOutput()
		if e != nil || string(out) != "fixture-started" {
			return fmt.Errorf("start: %v %q", e, out)
		}
		return nil
	}, Probe: func(context.Context, string, HostSlotView, string) error { return nil }}
	m, e := NewHostSlots(HostSlotOptions{Root: f.Root, InstanceID: f.ID, Bootstrap: b, Hooks: hooks})
	if e != nil {
		t.Fatal(e)
	}
	bundle, e := VerifyHostBundle(context.Background(), f.Payload, f.Envelope, f.Options)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { bundle.Close() })
	return m, bundle
}
func slotMust(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func slotLedgerRead(t *testing.T, m *HostSlots) slotLedger {
	t.Helper()
	s, l, e := m.open(context.Background())
	slotMust(t, e)
	s.close()
	return l
}
func TestHostSlotsLifecycleAndExactGC(t *testing.T) {
	f := newSlotFixture(t)
	m, a := f.open(t)
	ctx := context.Background()
	boot := m.options.Bootstrap.ID()
	current, e := m.CurrentSlot(ctx)
	slotMust(t, e)
	if current != boot {
		t.Fatal("wrong bootstrap")
	}
	slotMust(t, m.Prepare(ctx, a, boot))
	if len(slotLedgerRead(t, m).Records) != 1 {
		t.Fatal("unpublished")
	}
	slotMust(t, m.Activate(ctx, strings.Repeat("1", 64), boot, a.SHA256()))
	slotMust(t, m.Probe(ctx, a.SHA256(), strings.Repeat("a", 64)))
	old := a.SHA256()
	for i := 2; i <= 4; i++ {
		f = slotFixtureBundle(t, f, fmt.Sprintf("1.%d.0", i), slotHelper(t))
		next, b := f.open(t)
		slotMust(t, next.Prepare(ctx, b, old))
		slotMust(t, next.Activate(ctx, strings.Repeat(fmt.Sprint(i), 64), old, b.SHA256()))
		slotMust(t, next.Probe(ctx, b.SHA256(), strings.Repeat("a", 64)))
		slotMust(t, next.CollectInactive(ctx, []string{old, b.SHA256()}))
		l := slotLedgerRead(t, next)
		if len(l.Records) != 2 {
			t.Fatal("unbounded records", len(l.Records))
		}
		old = b.SHA256()
		m = next
	}
	if data, e := os.ReadFile(filepath.Join(f.Spec.Root, "user-owned-sentinel")); e != nil || string(data) != "retain" {
		t.Fatal("bootstrap changed")
	}
	if e = m.DiscardPrepared(ctx, old); !errors.Is(e, ErrHostConflict) {
		t.Fatal("deleted active", e)
	}
}
func TestHostSlotsFailClosed(t *testing.T) {
	for _, kind := range []string{"unknown-root", "unknown-slot", "hash", "mode", "link", "cpu", "bootstrap-drift", "directory-swap", "unregistered-temp"} {
		t.Run(kind, func(t *testing.T) {
			f := newSlotFixture(t)
			if kind == "cpu" {
				f = slotFixtureBundle(t, f, "1.2.0", []byte("not an executable"))
			}
			m, b := f.open(t)
			ctx := context.Background()
			boot := m.options.Bootstrap.ID()
			if kind == "cpu" {
				if e := m.Prepare(ctx, b, boot); !errors.Is(e, ErrHostConflict) {
					t.Fatal("CPU accepted", e)
				}
				return
			}
			slotMust(t, m.Prepare(ctx, b, boot))
			l := slotLedgerRead(t, m)
			r := l.Records[0]
			dir := filepath.Join(f.Root, r.Directory)
			file := filepath.Join(dir, filepath.FromSlash(r.Launcher))
			switch kind {
			case "unknown-root":
				os.WriteFile(filepath.Join(f.Root, "foreign"), []byte("retain"), 0600)
			case "unknown-slot":
				os.WriteFile(filepath.Join(dir, "foreign"), []byte("retain"), 0600)
			case "hash":
				os.WriteFile(file, []byte("changed"), 0755)
			case "mode":
				if runtime.GOOS == "windows" {
					slotGrantWideTestACL(t, file)
				} else {
					slotMust(t, os.Chmod(file, 0777))
				}
			case "link":
				os.Link(file, filepath.Join(filepath.Dir(f.Root), "foreign-hardlink"))
			case "bootstrap-drift":
				slotMust(t, os.WriteFile(filepath.Join(f.Spec.Root, f.Spec.Launcher), []byte("bootstrap drift"), 0755))
			case "directory-swap":
				os.Rename(dir, dir+"-old")
				os.Mkdir(dir, 0700)
			case "unregistered-temp":
				os.WriteFile(filepath.Join(f.Root, "state.new"), []byte("foreign"), 0600)
			}
			if e := m.Activate(ctx, strings.Repeat("1", 64), boot, b.SHA256()); e == nil {
				t.Fatal("unsafe candidate accepted")
			}
			if kind == "unknown-root" {
				if _, e := os.Stat(filepath.Join(f.Root, "foreign")); e != nil {
					t.Fatal("removed unknown")
				}
			}
		})
	}
}

type slotChild struct {
	DurableStop              bool
	FaultAfter               int
	Fixture                  slotFixture
	Action, Fault, Old, Next string
	Keep                     []string
}

func TestHostSlotsChild(t *testing.T) {
	input := os.Getenv("ACORNFOX_SLOT_CHILD")
	if input == "" {
		t.Skip("child only")
	}
	raw, e := os.ReadFile(input)
	slotMust(t, e)
	var child slotChild
	slotMust(t, json.Unmarshal(raw, &child))
	m, b := child.Fixture.open(t)
	if child.DurableStop {
		m.options.Hooks.Stop = func(_ context.Context, instance, attempt string, old HostSlotView) error {
			target := filepath.Join(filepath.Dir(child.Fixture.Root), "native-stop-proof.json")
			proof := slotStopProof{Instance: instance, Attempt: attempt, Old: old.ID()}
			if raw, e := os.ReadFile(target); e == nil {
				if json.Unmarshal(raw, &proof) != nil || proof.Instance != instance || proof.Attempt != attempt || proof.Old != old.ID() || !proof.Stopped {
					return ErrHostConflict
				}
			} else if !os.IsNotExist(e) {
				return e
			}
			proof.Calls++
			if !proof.Stopped {
				proof.Stopped = true
				proof.Effects++
			}
			f, e := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if e != nil {
				return e
			}
			_, e = f.Write(hostBytes(proof))
			if e == nil {
				e = f.Sync()
			}
			ce := f.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
			return hostSyncDirectory(filepath.Dir(target))
		}
	}
	ctx := context.Background()
	if child.Action == "lock" {
		s, _, e := m.open(ctx)
		slotMust(t, e)
		defer s.close()
		fmt.Println("locked")
		io.Copy(io.Discard, os.Stdin)
		return
	}
	count := 0
	m.fault = func(name string) error {
		if name == child.Fault {
			count++
			if child.FaultAfter > 0 && count < child.FaultAfter {
				return nil
			}
			os.Exit(73)
		}
		return nil
	}
	switch child.Action {
	case "prepare":
		e = m.Prepare(ctx, b, child.Old)
	case "activate":
		e = m.Activate(ctx, strings.Repeat("1", 64), child.Old, child.Next)
	case "gc":
		e = m.CollectInactive(ctx, child.Keep)
	default:
		t.Fatal("action")
	}
	slotMust(t, e)
}
func runSlotChild(t *testing.T, c slotChild, want int) {
	t.Helper()
	slotMust(t, os.WriteFile(c.Fixture.Input, hostBytes(c), 0600))
	cmd := exec.Command(os.Args[0], "-test.run=^TestHostSlotsChild$")
	cmd.Env = append(os.Environ(), "ACORNFOX_SLOT_CHILD="+c.Fixture.Input)
	out, e := cmd.CombinedOutput()
	code := 0
	if e != nil {
		if exit, ok := e.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatal(e)
		}
	}
	if code != want {
		t.Fatalf("child %s/%s exit %d want %d: %s", c.Action, c.Fault, code, want, out)
	}
}
func TestHostSlotsProcessRecovery(t *testing.T) {
	for _, point := range []string{"slot-directory", "slot-file-prefix", "slot-file-written", "slot-before-publish", "slot-published"} {
		t.Run(point, func(t *testing.T) {
			f := newSlotFixture(t)
			m, b := f.open(t)
			boot := m.options.Bootstrap.ID()
			slotMust(t, func() error { _, e := m.CurrentSlot(context.Background()); return e }())
			runSlotChild(t, slotChild{Fixture: f, Action: "prepare", Fault: point, Old: boot}, 73)
			runSlotChild(t, slotChild{Fixture: f, Action: "prepare", Old: boot}, 0)
			l := slotLedgerRead(t, m)
			if len(l.Records) != 1 || l.Preparing != nil || l.Records[0].ID != b.SHA256() || l.Active != boot {
				t.Fatal("bad recovered prepare")
			}
		})
	}
	for _, point := range []string{"slot-stopped", "state-prefix", "state-payload", "state-published", "slot-activated"} {
		t.Run(point, func(t *testing.T) {
			f := newSlotFixture(t)
			m, b := f.open(t)
			boot := m.options.Bootstrap.ID()
			slotMust(t, m.Prepare(context.Background(), b, boot))
			runSlotChild(t, slotChild{Fixture: f, Action: "activate", Fault: point, Old: boot, Next: b.SHA256()}, 73)
			runSlotChild(t, slotChild{Fixture: f, Action: "activate", Old: boot, Next: b.SHA256()}, 0)
			current, e := m.CurrentSlot(context.Background())
			slotMust(t, e)
			if current != b.SHA256() {
				t.Fatal("bad pointer")
			}
			slotMust(t, m.Probe(context.Background(), current, strings.Repeat("a", 64)))
		})
	}
}
func TestHostSlotsDiscardInterruptedAndGCRecovery(t *testing.T) {
	f := newSlotFixture(t)
	m, b := f.open(t)
	boot := m.options.Bootstrap.ID()
	ctx := context.Background()
	_, e := m.CurrentSlot(ctx)
	slotMust(t, e)
	runSlotChild(t, slotChild{Fixture: f, Action: "prepare", Fault: "slot-file-prefix", Old: boot}, 73)
	slotMust(t, m.DiscardPrepared(ctx, b.SHA256()))
	if l := slotLedgerRead(t, m); len(l.Records) != 0 || l.Preparing != nil {
		t.Fatal("discard did not settle")
	}
	slotMust(t, m.Prepare(ctx, b, boot))
	runSlotChild(t, slotChild{Fixture: f, Action: "gc", Fault: "slot-gc-entry", Keep: []string{boot}}, 73)
	runSlotChild(t, slotChild{Fixture: f, Action: "gc", Keep: []string{boot}}, 0)
	if l := slotLedgerRead(t, m); len(l.Records) != 0 || len(l.Deleting) != 0 {
		t.Fatal("gc did not settle")
	}
}
func TestHostSlotsCrossProcessLock(t *testing.T) {
	f := newSlotFixture(t)
	m, _ := f.open(t)
	slotMust(t, os.WriteFile(f.Input, hostBytes(slotChild{Fixture: f, Action: "lock"}), 0600))
	cmd := exec.Command(os.Args[0], "-test.run=^TestHostSlotsChild$")
	cmd.Env = append(os.Environ(), "ACORNFOX_SLOT_CHILD="+f.Input)
	in, e := cmd.StdinPipe()
	slotMust(t, e)
	out, e := cmd.StdoutPipe()
	slotMust(t, e)
	slotMust(t, cmd.Start())
	defer func() { in.Close(); cmd.Wait() }()
	buf := make([]byte, 7)
	_, e = io.ReadFull(out, buf)
	slotMust(t, e)
	if !bytes.Equal(buf, []byte("locked\n")) {
		t.Fatal("lock child")
	}
	if _, e = m.CurrentSlot(context.Background()); !errors.Is(e, ErrHostBusy) {
		t.Fatal("lock not held", e)
	}
}

func TestHostSlotsHookOrderingAndRollback(t *testing.T) {
	f := newSlotFixture(t)
	m, b := f.open(t)
	ctx := context.Background()
	boot := m.options.Bootstrap.ID()
	var calls []string
	m.options.Hooks = HostSlotHooks{Stop: func(context.Context, string, string, HostSlotView) error {
		calls = append(calls, "stop")
		return errors.New("stop failed")
	}, Start: func(context.Context, string, HostSlotView) error {
		calls = append(calls, "start")
		return errors.New("start failed")
	}, Probe: func(context.Context, string, HostSlotView, string) error { calls = append(calls, "probe"); return nil }}
	slotMust(t, m.Prepare(ctx, b, boot))
	if len(calls) != 0 {
		t.Fatal("Prepare executed a hook")
	}
	attempt := strings.Repeat("1", 64)
	if e := m.Activate(ctx, attempt, boot, b.SHA256()); e == nil {
		t.Fatal("ignored stop failure")
	}
	id, e := m.CurrentSlot(ctx)
	slotMust(t, e)
	if id != boot {
		t.Fatal("advanced despite stop failure")
	}
	m.options.Hooks.Stop = func(context.Context, string, string, HostSlotView) error { calls = append(calls, "stop"); return nil }
	slotMust(t, m.Activate(ctx, attempt, boot, b.SHA256()))
	if e = m.Probe(ctx, b.SHA256(), strings.Repeat("a", 64)); e == nil {
		t.Fatal("ignored failed trial")
	}
	if calls[len(calls)-1] != "start" {
		t.Fatal("probed failed start")
	}
	slotMust(t, m.Activate(ctx, attempt, b.SHA256(), boot))
	slotMust(t, m.DiscardPrepared(ctx, b.SHA256()))
	id, e = m.CurrentSlot(ctx)
	slotMust(t, e)
	if id != boot {
		t.Fatal("bootstrap rollback failed")
	}
}
func TestHostSlotsUnknownDuringGCIsPreserved(t *testing.T) {
	f := newSlotFixture(t)
	m, b := f.open(t)
	ctx := context.Background()
	boot := m.options.Bootstrap.ID()
	slotMust(t, m.Prepare(ctx, b, boot))
	l := slotLedgerRead(t, m)
	dir := filepath.Join(f.Root, l.Records[0].Directory)
	unknown := filepath.Join(dir, "foreign")
	slotMust(t, os.WriteFile(unknown, []byte("retain"), 0600))
	if e := m.CollectInactive(ctx, []string{boot}); !errors.Is(e, ErrHostConflict) {
		t.Fatal("collected unknown tree", e)
	}
	if _, e := os.Stat(unknown); e != nil {
		t.Fatal("removed foreign object")
	}
}
func TestHostSlotsInterruptedFileCannotChangeCandidate(t *testing.T) {
	f := newSlotFixture(t)
	m, b := f.open(t)
	ctx := context.Background()
	boot := m.options.Bootstrap.ID()
	_, e := m.CurrentSlot(ctx)
	slotMust(t, e)
	runSlotChild(t, slotChild{Fixture: f, Action: "prepare", Fault: "slot-file-prefix", Old: boot}, 73)
	next := slotFixtureBundle(t, f, "1.2.0", slotHelper(t))
	other, c := next.open(t)
	if e = other.Prepare(ctx, c, boot); !errors.Is(e, ErrHostConflict) {
		t.Fatal("substituted candidate", e)
	}
	l := slotLedgerRead(t, m)
	file := filepath.Join(f.Root, l.Preparing.Record.Directory, filepath.FromSlash(l.Preparing.Writing))
	fd, e := os.OpenFile(file, os.O_WRONLY, 0)
	slotMust(t, e)
	_, e = fd.WriteAt([]byte{0xff}, 0)
	slotMust(t, e)
	fd.Close()
	if e = m.Prepare(ctx, b, boot); !errors.Is(e, ErrHostConflict) {
		t.Fatal("accepted changed prefix", e)
	}
	slotMust(t, m.DiscardPrepared(ctx, b.SHA256()))
}

func TestHostSlotsPreparationJournalProcessRecovery(t *testing.T) {
	for _, c := range []struct {
		point string
		after int
	}{{"state-prefix", 1}, {"state-prefix", 2}, {"state-prefix", 3}, {"state-staged", 3}, {"state-payload", 3}, {"state-published", 3}} {
		t.Run(fmt.Sprintf("%s-%d", c.point, c.after), func(t *testing.T) {
			f := newSlotFixture(t)
			m, _ := f.open(t)
			boot := m.options.Bootstrap.ID()
			_, e := m.CurrentSlot(context.Background())
			slotMust(t, e)
			runSlotChild(t, slotChild{Fixture: f, Action: "prepare", Fault: c.point, FaultAfter: c.after, Old: boot}, 73)
			runSlotChild(t, slotChild{Fixture: f, Action: "prepare", Old: boot}, 0)
			if l := slotLedgerRead(t, m); len(l.Records) != 1 || l.Preparing != nil {
				t.Fatal("preparation not recovered")
			}
		})
	}
}
func TestHostSlotsGCDirectoryProcessRecovery(t *testing.T) {
	f := newSlotFixture(t)
	m, b := f.open(t)
	boot := m.options.Bootstrap.ID()
	slotMust(t, m.Prepare(context.Background(), b, boot))
	runSlotChild(t, slotChild{Fixture: f, Action: "gc", Fault: "slot-gc-directory", Keep: []string{boot}}, 73)
	runSlotChild(t, slotChild{Fixture: f, Action: "gc", Keep: []string{boot}}, 0)
	if l := slotLedgerRead(t, m); len(l.Records) != 0 || len(l.Deleting) != 0 {
		t.Fatal("GC directory not settled")
	}
}

type slotStopProof struct {
	Instance, Attempt, Old string
	Stopped                bool
	Calls, Effects         int
}

func TestHostSlotsStoppedHookIsIdempotentAcrossProcesses(t *testing.T) {
	f := newSlotFixture(t)
	m, b := f.open(t)
	ctx := context.Background()
	old := m.options.Bootstrap.ID()
	slotMust(t, m.Prepare(ctx, b, old))
	runSlotChild(t, slotChild{Fixture: f, Action: "activate", Fault: "slot-stopped", Old: old, Next: b.SHA256(), DurableStop: true}, 73)
	current, e := m.CurrentSlot(ctx)
	slotMust(t, e)
	if current != old {
		t.Fatal("pointer changed before commit")
	}
	runSlotChild(t, slotChild{Fixture: f, Action: "activate", Old: old, Next: b.SHA256(), DurableStop: true}, 0)
	raw, e := os.ReadFile(filepath.Join(filepath.Dir(f.Root), "native-stop-proof.json"))
	slotMust(t, e)
	var proof slotStopProof
	slotMust(t, json.Unmarshal(raw, &proof))
	if proof.Instance != f.ID || proof.Attempt != strings.Repeat("1", 64) || proof.Old != old || !proof.Stopped || proof.Calls != 2 || proof.Effects != 1 {
		t.Fatalf("stop was not exact/idempotent: %+v", proof)
	}
	current, e = m.CurrentSlot(ctx)
	slotMust(t, e)
	if current != b.SHA256() {
		t.Fatal("recovered pointer not committed")
	}
}

// External helper input is test-only. Its bytes must match an explicit digest
// and this test process's actual CPU/OS before any copy is allowed to execute.
func slotReadTestHelper(path, expected string) ([]byte, error) {
	before, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > 32<<20 || validateSHA256(expected) != nil {
		return nil, ErrHostConflict
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return nil, ErrHostConflict
	}
	raw, e := io.ReadAll(io.LimitReader(f, (32<<20)+1))
	if e != nil || len(raw) > 32<<20 || int64(len(raw)) != before.Size() || hostSHA(raw) != expected {
		return nil, ErrHostConflict
	}
	if e = slotCPU(f, runtime.GOOS, runtime.GOARCH); e != nil {
		return nil, e
	}
	after, e := f.Stat()
	if e != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, ErrHostConflict
	}
	return raw, nil
}
func slotGrantWideTestACL(t *testing.T, file string) {
	t.Helper()
	systemRoot := os.Getenv("SystemRoot")
	if !filepath.IsAbs(systemRoot) {
		t.Fatal("missing absolute Windows SystemRoot")
	}
	tool := filepath.Join(systemRoot, "System32", "icacls.exe")
	out, e := exec.Command(tool, file, "/grant", "*S-1-1-0:(W)").CombinedOutput()
	if e != nil {
		t.Fatalf("grant test-only wide write ACL: %v %s", e, out)
	}
	t.Cleanup(func() {
		out, e := exec.Command(tool, file, "/remove:g", "*S-1-1-0").CombinedOutput()
		if e != nil {
			t.Errorf("restore test-only ACL: %v %s", e, out)
		}
	})
}
func TestHostSlotsPrebuiltHelperIsHashAndCPUPinned(t *testing.T) {
	raw := slotHelper(t)
	path := filepath.Join(t.TempDir(), "helper")
	slotMust(t, os.WriteFile(path, raw, 0600))
	if _, e := slotReadTestHelper(path, hostSHA(raw)); e != nil {
		t.Fatal(e)
	}
	if _, e := slotReadTestHelper(path, strings.Repeat("0", 64)); !errors.Is(e, ErrHostConflict) {
		t.Fatal("accepted wrong helper SHA", e)
	}
	slotMust(t, os.WriteFile(path, []byte("not native executable"), 0600))
	if _, e := slotReadTestHelper(path, hostSHA([]byte("not native executable"))); !errors.Is(e, ErrHostConflict) {
		t.Fatal("accepted wrong helper CPU", e)
	}
}

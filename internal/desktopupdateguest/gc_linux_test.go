//go:build linux

package desktopupdateguest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func nextFixture(t *testing.T, f fixture, sequence int) fixture {
	t.Helper()
	world := f.x.backend.(fakeBackend).read()
	version := fmt.Sprintf("0.1.0-beta.%d", 13+sequence)
	payload, to := signedTestPayload(t, world.Binding, version)
	f.payload = payload
	f.request.Intent.AttemptID = digest([]byte(fmt.Sprintf("gc-job-%d", sequence)))
	f.request.Intent.FromBinding = world.Binding
	f.request.Intent.ToBinding = to
	f.request.Intent.ArtifactSHA256 = digest(payload)
	f.request.PayloadSize = int64(len(payload))
	f.request.Envelope = signFixture(t, f.private, payload, to, uint64(sequence), time.Now().Add(time.Hour), version)
	return f
}
func completeFixture(t *testing.T, f fixture, stopBeforeGC bool) {
	t.Helper()
	submitFixture(t, f)
	if stopBeforeGC {
		f.x.fault = func(label string) {
			if label == "job-terminal-committed" {
				panic("test stopped after durable terminal")
			}
		}
		func() {
			defer func() {
				if v := recover(); v != "test stopped after durable terminal" {
					t.Fatalf("unexpected interruption: %v", v)
				}
			}()
			if e := f.x.Run(context.Background(), f.request.Intent.AttemptID, false); e != nil {
				t.Fatal(e)
			}
			t.Fatal("terminal hook not reached")
		}()
		f.x.fault = nil
	} else if e := f.x.Run(context.Background(), f.request.Intent.AttemptID, false); e != nil {
		t.Fatal(e)
	}
}
func gcFixture(t *testing.T) (fixture, SubmitRequest) {
	t.Helper()
	f := newFixture(t)
	f.x.backend = fakeBackend{root: f.x.paths.anchor}
	first := f.request
	completeFixture(t, f, false)
	f = nextFixture(t, f, 2)
	completeFixture(t, f, false)
	f = nextFixture(t, f, 3)
	completeFixture(t, f, true)
	return f, first
}
func TestGCMoreThan32UpdatesAndRetiredIDCannotChange(t *testing.T) {
	f := newFixture(t)
	f.x.backend = fakeBackend{root: f.x.paths.anchor}
	first := f.request
	firstPayload := append([]byte(nil), f.payload...)
	for i := 1; i <= 40; i++ {
		if i > 1 {
			f = nextFixture(t, f, i)
		}
		completeFixture(t, f, false)
	}
	lock, e := f.x.lock()
	if e != nil {
		t.Fatal(e)
	}
	s, e := f.x.load()
	lock.Close()
	if e != nil || len(s.Jobs) != 2 || s.Floor != 40 {
		t.Fatalf("retention after 40: jobs=%d floor=%d %v", len(s.Jobs), s.Floor, e)
	}
	if _, e := os.Stat(f.x.jobDir(first.Intent.AttemptID)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("old complete payload not collected")
	}
	retired, e := f.x.readRetired(first.Intent.AttemptID)
	if e != nil || retired.IntentSHA != digest(encoded(first.Intent)) {
		t.Fatal("retired identity lost")
	}
	before := f.x.backend.(fakeBackend).read().Calls
	receipt, e := f.x.Submit(context.Background(), first, bytes.NewReader(firstPayload))
	if e != nil || receipt.State != "upgraded" {
		t.Fatalf("exact retired replay: %v", e)
	}
	changed := first
	changed.Intent.ArtifactSHA256 = f.request.Intent.ArtifactSHA256
	if _, e := f.x.Submit(context.Background(), changed, bytes.NewReader(f.payload)); !errors.Is(e, ErrConflict) {
		t.Fatalf("retired ID reused: %v", e)
	}
	if f.x.backend.(fakeBackend).read().Calls != before {
		t.Fatal("retired job executed again")
	}
	entries, e := os.ReadDir(f.x.paths.state)
	if e != nil {
		t.Fatal(e)
	}
	jobs := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "job-") {
			jobs++
		}
	}
	if jobs != 2 {
		t.Fatalf("intake directories=%d", jobs)
	}
}
func TestGCUnknownFilesAndReplacementArePreserved(t *testing.T) {
	for _, mutation := range []string{"extra", "symlink", "hardlink", "modified", "replaced-identical"} {
		t.Run(mutation, func(t *testing.T) {
			f, first := gcFixture(t)
			dir := f.x.jobDir(first.Intent.AttemptID)
			target := filepath.Join(dir, "candidate", "build-record.json")
			// For replacement, persist deletion authority first so identical bytes at a
			// different inode still cannot be mistaken for the originally owned object.
			if mutation == "replaced-identical" {
				lock, _ := f.x.lock()
				s, _ := f.x.load()
				g, e := f.x.prepareJobGC(context.Background(), s)
				if e != nil {
					t.Fatal(e)
				}
				s.GC = g
				if e := f.x.save(s); e != nil {
					t.Fatal(e)
				}
				lock.Close()
			}
			switch mutation {
			case "extra":
				target = filepath.Join(dir, "candidate", "user-notes")
				os.WriteFile(target, []byte("retain"), 0600)
			case "symlink":
				os.Remove(target)
				os.Symlink("/etc/passwd", target)
			case "hardlink":
				os.Link(target, filepath.Join(dir, "keep-link"))
			case "modified":
				os.WriteFile(target, []byte("foreign"), 0644)
			case "replaced-identical":
				raw, _ := os.ReadFile(target)
				os.Rename(target, target+"-old")
				os.WriteFile(target, raw, 0644)
				os.Remove(target + "-old")
			}
			if e := f.x.Collect(context.Background()); e == nil {
				t.Fatal("unknown/replaced object collected")
			}
			if _, e := os.Lstat(target); e != nil {
				t.Fatalf("unknown object deleted: %v", e)
			}
		})
	}
}
func TestGCSkipsActiveAndUnknown(t *testing.T) {
	f, _ := gcFixture(t)
	f = nextFixture(t, f, 4)
	submitFixture(t, f)
	for _, phase := range []string{"queued", "running", "unknown"} {
		if phase != "queued" {
			lock, _ := f.x.lock()
			s, _ := f.x.load()
			i := jobIndex(s, f.request.Intent.AttemptID)
			s.Jobs[i].State = phase
			if phase == "running" {
				s.Jobs[i].Process = processIdentity{PID: 999999, Boot: "old-boot", Start: "1"}
			}
			if e := f.x.save(s); e != nil {
				t.Fatal(e)
			}
			lock.Close()
		}
		if e := f.x.Collect(context.Background()); e != nil {
			t.Fatal(e)
		}
		if _, e := os.Stat(f.x.jobDir(f.request.Intent.AttemptID)); e != nil {
			t.Fatal(e)
		}
	}
}

func TestGCCrashChild(t *testing.T) {
	root := os.Getenv("GC_CRASH_ROOT")
	if root == "" {
		return
	}
	x, e := openFixture(root)
	if e != nil {
		os.Exit(81)
	}
	point := os.Getenv("GC_CRASH_POINT")
	hits := 0
	target := 1
	if os.Getenv("GC_CRASH_FINAL") == "1" {
		target = 2
	}
	x.fault = func(label string) {
		if label == point {
			hits++
			if hits == target {
				os.Exit(88)
			}
		}
	}
	if e := x.Collect(context.Background()); e != nil {
		os.Exit(82)
	}
	os.Exit(83)
}
func runGCCrash(t *testing.T, root, point string, final bool) {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "-test.run=^TestGCCrashChild$")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Env = append(os.Environ(), "GC_CRASH_ROOT="+root, "GC_CRASH_POINT="+point)
	if final {
		cmd.Env = append(cmd.Env, "GC_CRASH_FINAL=1")
	}
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 88 {
		t.Fatalf("GC crash %s final=%v: %v", point, final, err)
	}
}
func TestGCResumesEveryDeletionBoundaryAcrossProcesses(t *testing.T) {
	points := []string{"gc-file-removed:acornfox-0.1.0-beta.14-production.tar.gz", "gc-directory-removed:job-" + strings.Repeat("2", 64), "gc-tombstone-partial", "gc-tombstone-written", "gc-file-removed:build-record.json", "gc-file-removed:candidate-binding.json", "gc-file-removed:candidate-binding.sha256", "gc-file-removed:release-manifest.json", "gc-file-removed:bundle-manifest.sha256", "gc-file-removed:successor", "gc-file-removed:envelope.json", "gc-file-removed:payload", "gc-directory-removed:candidate"}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			f, first := gcFixture(t)
			// Kill once at the exact step, then kill a fresh recovery process at another
			// point; neither replay may re-execute the backend or lose the tombstone.
			runGCCrash(t, f.x.paths.anchor, point, false)
			second := "gc-file-removed:payload"
			if point == second || point == "gc-directory-removed:candidate" {
				second = "gc-directory-removed:job-" + first.Intent.AttemptID
			}
			runGCCrash(t, f.x.paths.anchor, second, false)
			x, e := openFixture(f.x.paths.anchor)
			if e != nil {
				t.Fatal(e)
			}
			if e := x.Collect(context.Background()); e != nil {
				t.Fatal(e)
			}
			if _, e := os.Stat(x.jobDir(first.Intent.AttemptID)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("old job survived completed GC")
			}
			if _, e := x.readRetired(first.Intent.AttemptID); e != nil {
				t.Fatal(e)
			}
			if x.backend.(fakeBackend).read().Calls != 3 {
				t.Fatal("GC repeated backend execution")
			}
		})
	}
}
func TestGCIntentAndCompletionSnapshotsRecover(t *testing.T) {
	for _, point := range []string{"snapshot-partial", "snapshot-before-rename", "snapshot-after-rename"} {
		for _, final := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/final-%v", point, final), func(t *testing.T) {
				f, first := gcFixture(t)
				runGCCrash(t, f.x.paths.anchor, point, final)
				x, e := openFixture(f.x.paths.anchor)
				if e != nil {
					t.Fatal(e)
				}
				if e := x.Collect(context.Background()); e != nil {
					t.Fatal(e)
				}
				if _, e := x.readRetired(first.Intent.AttemptID); e != nil {
					t.Fatal(e)
				}
				if x.backend.(fakeBackend).read().Calls != 3 {
					t.Fatal("GC replayed backend")
				}
			})
		}
	}
}

func TestQuarantineRecoverChild(t *testing.T) {
	root := os.Getenv("QUARANTINE_RECOVER_ROOT")
	if root == "" {
		return
	}
	x, e := openFixture(root)
	if e != nil {
		os.Exit(75)
	}
	if e := x.Run(context.Background(), os.Getenv("QUARANTINE_RECOVER_ID"), true); e != nil {
		os.Exit(76)
	}
	os.Exit(0)
}
func TestTwoIndependentTornSnapshotsDoNotExhaustQuarantine(t *testing.T) {
	f := newFixture(t)
	f.x.backend = fakeBackend{root: f.x.paths.anchor}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for sequence := 1; sequence <= 2; sequence++ {
		if sequence > 1 {
			f = nextFixture(t, f, sequence)
		}
		submitFixture(t, f)
		cmd := exec.Command(exe, "-test.run=^TestSnapshotCrashChild$")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Env = append(os.Environ(), "GUEST_UPDATE_CRASH_ROOT="+f.x.paths.anchor, "GUEST_UPDATE_CRASH_STAGE=terminal", "GUEST_UPDATE_CRASH_POINT=snapshot-partial", "GUEST_UPDATE_CRASH_ID="+f.request.Intent.AttemptID)
		var exit *exec.ExitError
		if e := cmd.Run(); !errors.As(e, &exit) || exit.ExitCode() != 89 {
			t.Fatalf("torn snapshot %d: %v", sequence, e)
		}
		if _, e := f.x.Status(f.request.Intent.AttemptID); e != nil {
			t.Fatal(e)
		}
		if _, e := os.Stat(filepath.Join(f.x.paths.state, "state-quarantine")); e != nil {
			t.Fatal("missing owned quarantine before recovery")
		}
		for retry := 0; retry < 2; retry++ {
			cmd = exec.Command(exe, "-test.run=^TestQuarantineRecoverChild$")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			cmd.Env = append(os.Environ(), "QUARANTINE_RECOVER_ROOT="+f.x.paths.anchor, "QUARANTINE_RECOVER_ID="+f.request.Intent.AttemptID)
			if e := cmd.Run(); e != nil {
				t.Fatalf("recovery %d/%d: %v", sequence, retry, e)
			}
		}
		for _, name := range []string{"state-quarantine", "quarantine-owner.json"} {
			if _, e := os.Lstat(filepath.Join(f.x.paths.state, name)); !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("owned %s not collected: %v", name, e)
			}
		}
	}
	if f.x.backend.(fakeBackend).read().Calls != 2 {
		t.Fatal("independent torn snapshots replayed upgrade")
	}
}
func TestQuarantineOwnershipAndDeletionResumeAcrossProcesses(t *testing.T) {
	for _, point := range []string{"quarantine-owner-partial", "quarantine-owner-written", "quarantine-renamed", "gc-file-removed:state-quarantine", "gc-file-removed:quarantine-owner.json"} {
		t.Run(point, func(t *testing.T) {
			f, _ := gcFixture(t)
			runGCCrash(t, f.x.paths.anchor, "snapshot-partial", false)
			runGCCrash(t, f.x.paths.anchor, point, false)
			runGCCrash(t, f.x.paths.anchor, "gc-file-removed:quarantine-owner.json", false)
			x, e := openFixture(f.x.paths.anchor)
			if e != nil {
				t.Fatal(e)
			}
			if e := x.Collect(context.Background()); e != nil {
				t.Fatal(e)
			}
			if _, e := os.Stat(filepath.Join(x.paths.state, "state-quarantine")); !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("quarantine not removed: %v", e)
			}
		})
	}
}
func TestQuarantineGCSnapshotInterruptionsResume(t *testing.T) {
	for _, point := range []string{"snapshot-partial", "snapshot-before-rename", "snapshot-after-rename"} {
		for _, final := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/final-%v", point, final), func(t *testing.T) {
				f, _ := gcFixture(t)
				runGCCrash(t, f.x.paths.anchor, "snapshot-partial", false)
				if _, e := f.x.Status(f.request.Intent.AttemptID); e != nil {
					t.Fatal(e)
				}
				runGCCrash(t, f.x.paths.anchor, point, final)
				x, e := openFixture(f.x.paths.anchor)
				if e != nil {
					t.Fatal(e)
				}
				if e := x.Collect(context.Background()); e != nil {
					t.Fatal(e)
				}
				if _, e := os.Stat(filepath.Join(x.paths.state, "state-quarantine")); !errors.Is(e, os.ErrNotExist) {
					t.Fatalf("quarantine survived: %v", e)
				}
			})
		}
	}
}
func TestGCNeverAdoptsUnownedQuarantineOrOrphan(t *testing.T) {
	for _, kind := range []string{"legacy-quarantine", "tampered-owner", "orphan"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := gcFixture(t)
			p := filepath.Join(f.x.paths.state, "state-quarantine")
			switch kind {
			case "legacy-quarantine":
				os.WriteFile(p, []byte("unknown old data"), 0600)
			case "tampered-owner":
				runGCCrash(t, f.x.paths.anchor, "snapshot-partial", false)
				if _, e := f.x.Status(f.request.Intent.AttemptID); e != nil {
					t.Fatal(e)
				}
				p = filepath.Join(f.x.paths.state, "quarantine-owner.json")
				raw, _ := os.ReadFile(p)
				var owner quarantineOwner
				if decode(raw, &owner) != nil {
					t.Fatal("owner")
				}
				owner.Source.SHA256 = strings.Repeat("f", 64)
				os.WriteFile(p, encoded(owner), 0600)
			case "orphan":
				p = f.x.jobDir(strings.Repeat("e", 64))
				os.Mkdir(p, 0700)
				os.WriteFile(filepath.Join(p, "user-data"), []byte("retain"), 0600)
			}
			e := f.x.Collect(context.Background())
			if kind != "orphan" && e == nil {
				t.Fatal("unknown quarantine acquired deletion authority")
			}
			if _, e := os.Lstat(p); e != nil {
				t.Fatal("unknown data deleted")
			}
		})
	}
}

func TestAmbiguousShortTempNeverAcquiresQuarantineOwnership(t *testing.T) {
	f, _ := gcFixture(t)
	p := filepath.Join(f.x.paths.state, "state-next.json")
	if e := os.WriteFile(p, []byte(`{"revision":`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := f.x.Status(f.request.Intent.AttemptID); !errors.Is(e, ErrConflict) {
		t.Fatalf("ambiguous source accepted: %v", e)
	}
	if _, e := os.Stat(p); e != nil {
		t.Fatal("ambiguous temp deleted")
	}
	if _, e := os.Stat(filepath.Join(f.x.paths.state, "quarantine-owner.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("unproven owner manufactured")
	}
}

func TestStatusCannotResumeGCForChangedInstance(t *testing.T) {
	f, first := gcFixture(t)
	lock, _ := f.x.lock()
	s, e := f.x.load()
	if e != nil {
		t.Fatal(e)
	}
	g, e := f.x.prepareJobGC(context.Background(), s)
	if e != nil {
		t.Fatal(e)
	}
	s.GC = g
	if e := f.x.save(s); e != nil {
		t.Fatal(e)
	}
	lock.Close()
	if e := os.WriteFile(filepath.Join(filepath.Dir(f.x.paths.instance), "linux-owner-marker"), []byte("other instance"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := f.x.Status(first.Intent.AttemptID); !errors.Is(e, ErrConflict) {
		t.Fatalf("foreign instance GC resumed: %v", e)
	}
	if _, e := os.Stat(filepath.Join(f.x.jobDir(first.Intent.AttemptID), "payload")); e != nil {
		t.Fatal("foreign instance caused deletion")
	}
}

func TestDetachedWorkerWaitsForStatusLockAndCanCancel(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			f := newFixture(t)
			f.x.backend = fakeBackend{root: f.x.paths.anchor}
			submitFixture(t, f)
			lock, e := f.x.lock()
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- f.x.Run(ctx, f.request.Intent.AttemptID, false) }()
			select {
			case e := <-done:
				lock.Close()
				t.Fatalf("worker exited for transient status lock: %v", e)
			case <-time.After(25 * time.Millisecond):
			}
			if cancelled {
				cancel()
			} else {
				lock.Close()
			}
			select {
			case e := <-done:
				if cancelled && !errors.Is(e, context.Canceled) || !cancelled && e != nil {
					t.Fatalf("worker wait: %v", e)
				}
			case <-time.After(2 * time.Second):
				lock.Close()
				t.Fatal("worker did not finish")
			}
			if cancelled {
				lock.Close()
				if f.x.backend.(fakeBackend).read().Calls != 0 {
					t.Fatal("cancelled queued worker executed")
				}
			} else if f.x.backend.(fakeBackend).read().Calls != 1 {
				t.Fatal("worker replayed or lost upgrade")
			}
		})
	}
}

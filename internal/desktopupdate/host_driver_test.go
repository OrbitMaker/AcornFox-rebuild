package desktopupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type driverTreeEntry struct {
	info os.FileInfo
	sha  string
}

func driverTree(t *testing.T, root string) map[string]driverTreeEntry {
	t.Helper()
	tree := map[string]driverTreeEntry{}
	if _, e := os.Lstat(root); os.IsNotExist(e) {
		return tree
	}
	e := filepath.WalkDir(root, func(p string, _ os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		info, e := os.Lstat(p)
		if e != nil {
			return e
		}
		sum := ""
		if info.Mode().IsRegular() {
			raw, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			sum = hostSHA(raw)
		}
		tree[p] = driverTreeEntry{info, sum}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return tree
}
func driverTreeUnchanged(t *testing.T, root string, before map[string]driverTreeEntry) {
	t.Helper()
	after := driverTree(t, root)
	if len(before) != len(after) {
		t.Fatal("read changed tree size", len(before), len(after))
	}
	for p, a := range before {
		b, ok := after[p]
		if !ok || !os.SameFile(a.info, b.info) || a.info.Mode() != b.info.Mode() || !a.info.ModTime().Equal(b.info.ModTime()) || a.info.Size() != b.info.Size() || a.sha != b.sha {
			t.Fatal("read changed bytes/inode/mode/mtime", p)
		}
	}
}
func driverInitialized(t *testing.T) hostFixture {
	t.Helper()
	f := newHostFixture(t)
	if _, e := f.c.Status(context.Background()); e != nil {
		t.Fatal(e)
	}
	return f
}
func driverEdit(t *testing.T, c *HostController, change func(*HostSnapshot)) {
	t.Helper()
	s, state, e := c.open(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	change(&state)
	if e = s.save(&state); e != nil {
		t.Fatal(e)
	}
}
func TestHostDriverReadStartupBasisIsReadOnlyLease(t *testing.T) {
	f := driverInitialized(t)
	f.c.options.Backend = nil
	f.c.options.Runtime = nil
	before := driverTree(t, f.c.options.Root)
	basis, e := f.c.ReadStartupBasis(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if !basis.Valid() || basis.InstanceID() != f.c.options.InstanceID || basis.SlotSHA256() != f.c.options.Initial.SlotSHA256 || basis.BackendBinding() != f.c.options.Initial.BackendBinding || basis.Version() != f.c.options.Initial.Version || basis.ControllerProtocol() != 1 || basis.InstanceProtocol() != 1 || basis.BackendAPIProtocol() != 1 {
		t.Fatal("incorrect startup basis")
	}
	if second, e := f.c.ReadStartupBasis(context.Background()); !errors.Is(e, ErrHostBusy) || second != nil {
		if second != nil {
			second.Close()
		}
		t.Fatal("did not hold existing controller lock", e)
	}
	if _, e = json.Marshal(basis); e == nil {
		t.Fatal("opaque authority serialized")
	}
	var forged HostStartupBasis
	if e = json.Unmarshal([]byte(`{}`), &forged); e == nil || forged.Valid() {
		t.Fatal("JSON fabricated authority")
	}
	if e = basis.Close(); e != nil {
		t.Fatal(e)
	}
	basis.Close()
	if basis.Valid() || basis.InstanceID() != "" || basis.SlotSHA256() != "" || basis.BackendBinding() != "" || basis.Version() != "" || basis.ControllerProtocol() != 0 || basis.InstanceProtocol() != 0 || basis.BackendAPIProtocol() != 0 {
		t.Fatal("closed basis stayed usable")
	}
	next, e := f.c.ReadStartupBasis(context.Background())
	if e != nil {
		t.Fatal("Close did not release lock", e)
	}
	next.Close()
	driverTreeUnchanged(t, f.c.options.Root, before)
}
func TestHostDriverReadRejectsWithoutRepair(t *testing.T) {
	for _, kind := range []string{"no-state", "no-root", "missing-state", "missing-lock", "policy-empty", "policy-lost", "policy-lost-partial", "pending", "collect", "cleanup", "state-new", "state-payload", "unknown", "invalid-state", "wrong-policy", "wrong-instance", "lock-symlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newHostFixture(t)
			ctx := context.Background()
			want := ErrHostConflict
			if kind != "no-state" && kind != "no-root" && kind != "policy-empty" {
				if _, e := f.c.Status(ctx); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "no-state":
				want = ErrHostUninitialized
			case "no-root":
				if e := os.Remove(f.c.options.Root); e != nil {
					t.Fatal(e)
				}
				want = ErrHostUninitialized
			case "missing-state":
				if e := os.Remove(filepath.Join(f.c.options.Root, "state.json")); e != nil {
					t.Fatal(e)
				}
				want = ErrHostUninitialized
			case "missing-lock":
				if e := os.Remove(filepath.Join(f.c.options.Root, "lock")); e != nil {
					t.Fatal(e)
				}
			case "policy-empty":
				f.c.options.Policy = nil
				want = ErrHostNotConfigured
			case "policy-lost":
				f.c.options.Policy = nil
				want = ErrHostPolicyMissing
			case "policy-lost-partial":
				os.Remove(filepath.Join(f.c.options.Root, "state.json"))
				os.WriteFile(filepath.Join(f.c.options.Root, "state.new"), []byte("partial evidence"), 0600)
				f.c.options.Policy = nil
				want = ErrHostPolicyMissing
			case "pending":
				if _, e := f.c.Select(ctx, f.envelope, false); e != nil {
					t.Fatal(e)
				}
				want = ErrHostPending
			case "collect":
				driverEdit(t, f.c, func(s *HostSnapshot) { s.CollectSlots = true })
				want = ErrHostPending
			case "cleanup":
				driverEdit(t, f.c, func(s *HostSnapshot) {
					s.Cleanup = []HostStageCleanup{{ID: strings.Repeat("a", 64), Identity: "known", SHA256: strings.Repeat("b", 64), Size: 1}}
				})
				want = ErrHostPending
			case "state-new", "state-payload":
				name := strings.ReplaceAll(kind, "-", ".")
				os.WriteFile(filepath.Join(f.c.options.Root, name), []byte("interrupted bytes must remain"), 0600)
				want = ErrHostPending
			case "unknown":
				os.WriteFile(filepath.Join(f.c.options.Root, "foreign"), []byte("retain"), 0600)
			case "invalid-state":
				os.WriteFile(filepath.Join(f.c.options.Root, "state.json"), []byte(`{"unknown":true}`), 0600)
			case "wrong-policy":
				p := *f.c.options.Policy
				p.Channel = "beta"
				f.c.options.Policy = &p
			case "wrong-instance":
				f.c.options.InstanceID = strings.Repeat("7", 64)
			case "lock-symlink":
				lock := filepath.Join(f.c.options.Root, "lock")
				os.Rename(lock, filepath.Join(filepath.Dir(lock), "outside-lock"))
				os.Symlink("outside-lock", lock)
			}
			before := driverTree(t, f.c.options.Root)
			basis, e := f.c.ReadStartupBasis(ctx)
			if basis != nil {
				basis.Close()
				t.Fatal("returned unauthorized basis")
			}
			if !errors.Is(e, want) {
				t.Fatal("wrong error", e, "want", want)
			}
			driverTreeUnchanged(t, f.c.options.Root, before)
		})
	}
}
func TestHostDriverLeaseInvalidationAndCancellation(t *testing.T) {
	for _, kind := range []string{"cancel", "state-change", "temporary", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			f := driverInitialized(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			basis, e := f.c.ReadStartupBasis(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer basis.Close()
			switch kind {
			case "cancel":
				cancel()
			case "state-change":
				os.WriteFile(filepath.Join(f.c.options.Root, "state.json"), []byte("changed"), 0600)
			case "temporary":
				os.WriteFile(filepath.Join(f.c.options.Root, "state.new"), []byte("partial"), 0600)
			case "unknown":
				os.WriteFile(filepath.Join(f.c.options.Root, "foreign"), []byte("unknown"), 0600)
			}
			if basis.Valid() || basis.InstanceID() != "" || basis.BackendAPIProtocol() != 0 {
				t.Fatal("stale lease remains authority")
			}
			if kind == "cancel" {
				deadline := time.Now().Add(time.Second)
				for {
					fresh, e := f.c.ReadStartupBasis(context.Background())
					if e == nil {
						fresh.Close()
						break
					}
					if !errors.Is(e, ErrHostBusy) || time.Now().After(deadline) {
						t.Fatal("cancel did not release lease", e)
					}
					time.Sleep(time.Millisecond)
				}
			}
		})
	}
}

type driverResumeFake struct {
	hostFake
	ensures, resumes  int
	pending           *HostUpgradeIntent
	envelope, payload []byte
	finish            bool
	check             func(HostUpgradeIntent, *VerifiedHostBundle) error
}

func (f *driverResumeFake) EnsureUpgrade(_ context.Context, i HostUpgradeIntent, _ *VerifiedHostBundle) error {
	f.ensures++
	f.pending = &i
	return ErrHostPending
}
func (f *driverResumeFake) Observe(ctx context.Context, id string) (BackendObservation, error) {
	obs, e := f.hostFake.Observe(ctx, id)
	if e == nil && f.pending != nil && id == f.pending.AttemptID && !f.finish {
		obs.AttemptState = "unknown"
	}
	return obs, e
}
func (f *driverResumeFake) Resume(_ context.Context, i HostUpgradeIntent, b *VerifiedHostBundle) error {
	f.resumes++
	if f.pending == nil || i != *f.pending || !bytes.Equal(b.SignedEnvelope(), f.envelope) {
		return ErrHostConflict
	}
	var payload bytes.Buffer
	if e := b.CopyPayload(&payload); e != nil || !bytes.Equal(payload.Bytes(), f.payload) {
		return ErrHostConflict
	}
	if f.check != nil {
		if e := f.check(i, b); e != nil {
			return e
		}
	}
	if f.finish {
		w := f.read()
		w.Attempts[i.AttemptID] = true
		w.Binding = i.ToBinding
		f.write(w)
	}
	return nil
}
func driverPending(t *testing.T) (hostFixture, *driverResumeFake) {
	t.Helper()
	f := newHostFixture(t)
	backend := &driverResumeFake{hostFake: f.world, envelope: f.envelope, payload: f.payload}
	f.c.options.Backend = backend
	if _, e := f.c.Select(context.Background(), f.envelope, false); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 4 && backend.pending == nil; i++ {
		if _, e := f.c.Advance(context.Background()); e != nil && !errors.Is(e, ErrHostPending) {
			t.Fatal(e)
		}
	}
	if backend.pending == nil {
		t.Fatal("did not reach backend applying")
	}
	return f, backend
}
func TestHostDriverResumeUsesOnlyLockedPendingAuthority(t *testing.T) {
	f, backend := driverPending(t)
	before := driverTree(t, f.c.options.Root)
	backend.check = func(i HostUpgradeIntent, b *VerifiedHostBundle) error {
		if lease, e := f.c.ReadStartupBasis(context.Background()); !errors.Is(e, ErrHostBusy) || lease != nil {
			if lease != nil {
				lease.Close()
			}
			t.Fatal("Resume did not retain controller lock", e)
		}
		return nil
	}
	status, e := f.c.ResumeBackend(context.Background())
	if !errors.Is(e, ErrHostPending) || status.State != "backend_applying" || backend.resumes != 1 || backend.ensures != 1 {
		t.Fatal("resume settled or resubmitted", status.State, e, backend.resumes, backend.ensures)
	}
	driverTreeUnchanged(t, f.c.options.Root, before)
	if lease, e := f.c.ReadStartupBasis(context.Background()); !errors.Is(e, ErrHostPending) || lease != nil {
		if lease != nil {
			lease.Close()
		}
		t.Fatal("pending authorized a startup", e)
	}
	backend.finish = true
	if _, e = f.c.ResumeBackend(context.Background()); !errors.Is(e, ErrHostPending) {
		t.Fatal(e)
	}
	result := finishHost(t, f.c)
	if result.State != "updated" || backend.ensures != 1 {
		t.Fatal("fresh Advance did not finish")
	}
	lease, e := f.c.ReadStartupBasis(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	if lease.SlotSHA256() != hostSHA(f.payload) || lease.BackendBinding() != f.manifest.Backend.ToBinding {
		t.Fatal("wrong settled authority")
	}
}
func TestHostDriverResumeRejectsCorruptOrMissingAuthority(t *testing.T) {
	for _, kind := range []string{"missing-state", "missing-lock", "wrong-phase", "unsupported", "envelope", "stage-identity", "payload", "missing-stage", "temp", "foreign-instance"} {
		t.Run(kind, func(t *testing.T) {
			f, backend := driverPending(t)
			status, e := f.c.Status(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			stage := filepath.Join(f.c.options.Root, "download-"+status.Snapshot.Pending.ID)
			want := ErrHostConflict
			switch kind {
			case "missing-state":
				os.Remove(filepath.Join(f.c.options.Root, "state.json"))
				want = ErrHostConflict // Orphan stage is evidence, never initialization.
			case "missing-lock":
				os.Remove(filepath.Join(f.c.options.Root, "lock"))
			case "wrong-phase":
				driverEdit(t, f.c, func(s *HostSnapshot) { s.Pending.Phase = "host_trial" })
				want = ErrHostPending
			case "unsupported":
				f.c.options.Backend = f.world
				want = ErrHostResumeUnsupported
			case "envelope":
				driverEdit(t, f.c, func(s *HostSnapshot) { s.Pending.Envelope[len(s.Pending.Envelope)-2] ^= 1 })
			case "stage-identity":
				driverEdit(t, f.c, func(s *HostSnapshot) { s.Pending.StageIdentity = "wrong" })
			case "payload":
				os.WriteFile(filepath.Join(stage, StagePayloadFileName), []byte("tampered"), 0600)
			case "missing-stage":
				os.RemoveAll(stage)
			case "temp":
				os.WriteFile(filepath.Join(f.c.options.Root, "state.new"), []byte("retain interrupted state"), 0600)
				want = ErrHostPending
			case "foreign-instance":
				f.c.options.InstanceID = strings.Repeat("8", 64)
			}
			before := driverTree(t, f.c.options.Root)
			_, e = f.c.ResumeBackend(context.Background())
			if !errors.Is(e, want) {
				t.Fatal("wrong refusal", e, "want", want)
			}
			if backend.resumes != 0 || backend.ensures != 1 {
				t.Fatal("invalid pending invoked backend")
			}
			driverTreeUnchanged(t, f.c.options.Root, before)
		})
	}
}
func TestHostDriverMissingStateNeverBootstrapsResume(t *testing.T) {
	f := newHostFixture(t)
	before := driverTree(t, f.c.options.Root)
	if _, e := f.c.ResumeBackend(context.Background()); !errors.Is(e, ErrHostUninitialized) {
		t.Fatal(e)
	}
	driverTreeUnchanged(t, f.c.options.Root, before)
}
func TestHostDriverBasisHasNoExportedAuthorityFields(t *testing.T) {
	typ := reflect.TypeOf(HostStartupBasis{})
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).IsExported() {
			t.Fatal("caller-writable authority", typ.Field(i).Name)
		}
	}
	var b *HostStartupBasis
	if b.Valid() || b.InstanceID() != "" || b.ControllerProtocol() != 0 {
		t.Fatal("nil basis")
	}
	if e := b.Close(); e != nil {
		t.Fatal(e)
	}
}

var _ io.Closer = (*HostStartupBasis)(nil)

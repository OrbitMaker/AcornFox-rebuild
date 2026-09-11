package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/acornfoxsetup"
)

func localRolloverFixture(t *testing.T, versions ...string) (*acornFoxUpgrade, acornFoxProductionPreparedFixture, acornFoxFixture, *acornFoxUpgradeServiceFake) {
	t.Helper()
	runtime, p, id := runtimeConfigFixture(t, versions...)
	if _, err := runtime.run(context.Background(), id, acornfoxsetup.ExactLocalLoopbackOrigin, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(p.host, "var/tmp"), 0755); err != nil {
		t.Fatal(err)
	}
	u := newAcornFoxUpgrade(p.layout)
	u.ownership = p.owners.edge()
	service := &acornFoxUpgradeServiceFake{old: p.binding, forbidEdge: true}
	u.services = service
	version := "1.2.3-test.1"
	if len(versions) > 0 {
		version = versions[0]
	}
	return u, p, newAcornFoxFixture(t, version, nil), service
}
func localRolloverRequest(t *testing.T, u *acornFoxUpgrade, old, next acornFoxFixture) AcornFoxUpgradeRequestV1 {
	t.Helper()
	dir, self, sha := writeAcornFoxBridgeCandidate(t, t.TempDir(), next)
	if sha != sha256Hex([]byte("content: bin/acornfox-upgrade\n")) {
		if err := os.WriteFile(self, []byte("authenticated successor recovery helper "+next.binding.Version+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	u.self = acornFoxSelfVerifier{path: self, uid: os.Getuid(), gid: os.Getgid()}
	return AcornFoxUpgradeRequestV1{dir, next.bindingSHA, old.bindingSHA, sha}
}
func TestAcornFoxLocalRolloverThirdRelease(t *testing.T) {
	u, _, old, _ := localRolloverFixture(t)
	for _, version := range []string{"1.2.4-test.1", "1.2.5-test.1"} {
		next := newAcornFoxFixture(t, version, &old)
		if _, err := u.upgrade(context.Background(), localRolloverRequest(t, u, old, next)); err != nil {
			t.Fatalf("version %s: %v", version, err)
		}
		old = next
	}
}

func localRolloverJournal(t *testing.T, u *acornFoxUpgrade) acornFoxUpgradeJournal {
	t.Helper()
	s, err := u.openStore()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	j, err := u.load(s)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func assertLocalRolloverPair(t *testing.T, u *acornFoxUpgrade, p acornFoxProductionPreparedFixture, current string) {
	t.Helper()
	j := localRolloverJournal(t, u)
	if j.LocalRollover != nil || acornFoxLocalCurrent(j).Repo.BindingSHA256 != current {
		t.Fatalf("unsettled or wrong current: %s", j.Phase)
	}
	s, err := u.openStore()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := u.verifyImage(s, j, j.Phase == "UPGRADED"); err != nil {
		t.Fatalf("pair verification: %v", err)
	}
	for _, relative := range []string{"opt/acornfox/releases", "opt/acornfox/activations", "var/lib/acornfox/install/releases"} {
		entries, err := os.ReadDir(filepath.Join(p.host, relative))
		if err != nil || len(entries) != 2 {
			t.Fatalf("%s count=%d err=%v", relative, len(entries), err)
		}
	}
	bindings, err := os.ReadDir(filepath.Join(p.state, "bindings"))
	if err != nil || len(bindings) != 3 {
		t.Fatalf("bindings count=%d err=%v", len(bindings), err)
	}
	entries, err := os.ReadDir(p.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".acornfox-local-") {
			t.Fatal("transient local control remains", entry.Name())
		}
	}
	stages, err := os.ReadDir(filepath.Join(p.host, "var/tmp/acornfox-upgrade"))
	if err != nil || len(stages) > 2 {
		t.Fatalf("stage growth %d err=%v", len(stages), err)
	}
}
func TestAcornFoxLocalRolloverFourSuccesses(t *testing.T) {
	t.Parallel()
	u, p, old, service := localRolloverFixture(t)
	for _, version := range []string{"1.2.4-test.1", "1.2.5-test.1", "1.2.6-test.1", "1.2.7-test.1"} {
		next := newAcornFoxFixture(t, version, &old)
		if _, err := u.upgrade(context.Background(), localRolloverRequest(t, u, old, next)); err != nil {
			t.Fatalf("%s: %v", version, err)
		}
		assertLocalRolloverPair(t, u, p, next.bindingSHA)
		old = next
	}
	if len(service.edgeViolations) != 0 {
		t.Fatal(service.edgeViolations)
	}
}
func TestAcornFoxLocalRolloverRetry(t *testing.T) {
	for _, sourceRollback := range []bool{false, true} {
		for _, same := range []bool{false, true} {
			t.Run(fmt.Sprintf("sourceRollback=%t/same=%t", sourceRollback, same), func(t *testing.T) {
				t.Parallel()
				u, p, a, service := localRolloverFixture(t)
				b := newAcornFoxFixture(t, "1.2.4-test.1", &a)
				service.failNext = sourceRollback
				_, err := u.upgrade(context.Background(), localRolloverRequest(t, u, a, b))
				if sourceRollback {
					if !errors.Is(err, ErrAcornFoxUpgradeRolledBack) {
						t.Fatal(err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				previous := localRolloverJournal(t, u)
				if sourceRollback {
					alias := previous
					alias.Phase = "PREPARED"
					alias.LocalRollover = acornFoxNewLocalRollover(previous)
					if alias.validate(u.layout) == nil {
						t.Fatal("rollover can collect its current candidate")
					}
				}
				old := b
				if sourceRollback {
					old = a
				}
				service.old = old.bindingSHA
				service.failNext = true
				c := newAcornFoxFixture(t, "1.2.5-test.1", &old)
				request := localRolloverRequest(t, u, old, c)
				receipt, err := u.upgrade(context.Background(), request)
				if !errors.Is(err, ErrAcornFoxUpgradeRolledBack) || receipt.State != "ROLLED_BACK" {
					t.Fatalf("failed candidate: %v state=%s", err, receipt.State)
				}
				if !bytes.Equal(acornFoxUpgradeJSON(previous), acornFoxUpgradeJSON(localRolloverJournal(t, u))) {
					t.Fatal("original journal not restored")
				}
				assertLocalRolloverPair(t, u, p, old.bindingSHA)
				service.failNext = false
				if !same {
					c = newAcornFoxFixture(t, "1.2.6-test.1", &old)
					request = localRolloverRequest(t, u, old, c)
				}
				if _, err := u.upgrade(context.Background(), request); err != nil {
					t.Fatal("retry", err)
				}
				assertLocalRolloverPair(t, u, p, c.bindingSHA)
			})
		}
	}
}
func TestAcornFoxLocalRolloverFaultRecovery(t *testing.T) {
	for _, test := range []struct {
		name           string
		nth            int
		fail           bool
		sourceRollback bool
	}{
		{"local-journal-prefix", 1, false, false}, {"local-journal-staged", 1, false, false}, {"local-journal-committed", 1, false, false},
		{"prepared", 1, false, false}, {"local-retiring-before", 1, false, false}, {"local-retiring-after", 1, false, false},
		{"substrate-retired", 1, false, false}, {"healthy", 1, false, false},
		{"local-collection-started", 1, false, false}, {"local-collection-unlinked", 1, false, false}, {"local-collection-unlinked", 100, false, false},
		{"local-collection-started", 1, true, false}, {"local-collection-unlinked", 100, true, false},
		{"local-reset-before-restore", 1, true, false}, {"local-reset-restored", 1, true, false}, {"local-reset-before-journal", 1, true, false}, {"local-reset-complete", 1, true, false},
		{"local-reset-restored", 1, true, true},
	} {
		t.Run(fmt.Sprintf("%s-%d-fail%t-sourceRollback%t", test.name, test.nth, test.fail, test.sourceRollback), func(t *testing.T) {
			t.Parallel()
			u, p, a, service := localRolloverFixture(t)
			b := newAcornFoxFixture(t, "1.2.4-test.1", &a)
			service.failNext = test.sourceRollback
			_, err := u.upgrade(context.Background(), localRolloverRequest(t, u, a, b))
			if err != nil && !test.sourceRollback {
				t.Fatal(err)
			}
			previous := localRolloverJournal(t, u)
			old := b
			if test.sourceRollback {
				old = a
			}
			service.old = old.bindingSHA
			service.failNext = test.fail
			c := newAcornFoxFixture(t, "1.2.5-test.1", &old)
			request := localRolloverRequest(t, u, old, c)
			fired := false
			count := 0
			u.step = func(name string) error {
				if name == test.name {
					count++
					if count == test.nth {
						fired = true
						return errors.New("power loss")
					}
				}
				return nil
			}
			if _, err := u.upgrade(context.Background(), request); err == nil || !fired {
				t.Fatalf("fault not reached err=%v count=%d", err, count)
			}
			// A fresh engine observes only durable disk state. Boot invokes the fixed
			// helper currently on disk, never the caller's external candidate directory.
			fresh := newAcornFoxUpgrade(p.layout)
			fresh.ownership = p.owners.edge()
			fresh.services = &acornFoxUpgradeServiceFake{old: old.bindingSHA, forbidEdge: true}
			fresh.self = acornFoxSelfVerifier{path: filepath.Join(p.host, AcornFoxUpgradeHelperPath), uid: os.Getuid(), gid: os.Getgid()}
			durable := localRolloverJournal(t, fresh)
			expected := durable.Old.identity()
			if durable.Phase == "UPGRADED" {
				expected = durable.Next.identity()
			}
			receipt, handled, err := fresh.recover(context.Background(), expected)
			if err != nil || !handled {
				t.Fatalf("recover %s: %v handled=%t", durable.Phase, err, handled)
			}
			settled := localRolloverJournal(t, fresh)
			want := old.bindingSHA
			if settled.Phase == "UPGRADED" && settled.Next.Repo.BindingSHA256 == c.bindingSHA {
				want = c.bindingSHA
			} else if !bytes.Equal(acornFoxUpgradeJSON(settled), acornFoxUpgradeJSON(previous)) {
				t.Fatal("neither committed nor original journal")
			}
			assertLocalRolloverPair(t, fresh, p, want)
			if receipt.BindingSHA256 != want {
				t.Fatal("wrong receipt")
			}
			if _, handled, err := fresh.recover(context.Background(), acornFoxLocalCurrent(settled).identity()); err != nil || !handled {
				t.Fatalf("second recover %v", err)
			}
		})
	}
}

func TestAcornFoxLocalRolloverReaderGate(t *testing.T) {
	for _, reader := range []string{"0.1.0-beta.12", "0.1.0-beta.13"} {
		t.Run(reader, func(t *testing.T) {
			t.Parallel()
			u, p, a, service := localRolloverFixture(t, "0.1.0-beta.11")
			b := newAcornFoxFixture(t, reader, &a)
			if _, err := u.upgrade(context.Background(), localRolloverRequest(t, u, a, b)); err != nil {
				t.Fatal("first ordinary upgrade", err)
			}
			before := localRolloverJournal(t, u)
			calls := len(service.calls)
			c := newAcornFoxFixture(t, "0.1.0-beta.14", &b)
			request := localRolloverRequest(t, u, b, c)
			writes := 0
			u.step = func(name string) error {
				writes++
				if reader == "0.1.0-beta.13" && name == "prepared" {
					assertAcornFoxOldReaderRejectsLocalRollover(t, u)
				}
				return nil
			}
			_, err := u.upgrade(context.Background(), request)
			if reader == "0.1.0-beta.12" {
				if !errors.Is(err, ErrAcornFoxUpgradeRetentionFull) || writes != 0 || len(service.calls) != calls {
					t.Fatalf("old helper effects err=%v writes=%d", err, writes)
				}
				if !bytes.Equal(acornFoxUpgradeJSON(before), acornFoxUpgradeJSON(localRolloverJournal(t, u))) {
					t.Fatal("gate mutated journal")
				}
				if _, err := os.Lstat(u.stagePath(c.bindingSHA)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("gate staged candidate")
				}
			} else if err != nil {
				t.Fatal("reader continuation", err)
			} else {
				assertLocalRolloverPair(t, u, p, c.bindingSHA)
			}
		})
	}
}

func TestAcornFoxLocalRolloverGarbageDrift(t *testing.T) {
	t.Parallel()
	u, p, a, _ := localRolloverFixture(t)
	b := newAcornFoxFixture(t, "1.2.4-test.1", &a)
	if _, err := u.upgrade(context.Background(), localRolloverRequest(t, u, a, b)); err != nil {
		t.Fatal(err)
	}
	sentinels := map[string][]byte{}
	for _, dir := range []string{"uploads", "workspaces", "oci", "secrets", "pi"} {
		path := filepath.Join(p.host, "var/lib/acornfox", dir, "rollover-user-data")
		raw := []byte("private user data: " + dir)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		sentinels[path] = raw
	}
	c := newAcornFoxFixture(t, "1.2.5-test.1", &b)
	u.step = func(name string) error {
		if name == "local-collection-started" {
			return errors.New("power loss")
		}
		return nil
	}
	if _, err := u.upgrade(context.Background(), localRolloverRequest(t, u, b, c)); err == nil {
		t.Fatal("fault missed")
	}
	u.step = func(string) error { return nil }
	j := localRolloverJournal(t, u)
	if j.LocalRollover == nil || j.LocalRollover.State != "PRUNING" {
		t.Fatal("not pruning")
	}
	release := filepath.Join(p.host, "opt/acornfox/releases", a.binding.ReleaseID)
	file := filepath.Join(release, "manifest.json")
	original, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"unknown", "symlink", "hardlink", "owner", "mode", "content", "stage-unknown"} {
		t.Run(kind, func(t *testing.T) {
			cleanup := func() {}
			switch kind {
			case "unknown":
				path := filepath.Join(release, "foreign")
				if err := os.WriteFile(path, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
				cleanup = func() { os.Remove(path) }
			case "symlink":
				os.Remove(file)
				if err := os.Symlink(p.sentinel, file); err != nil {
					t.Fatal(err)
				}
				cleanup = func() {
					os.Remove(file)
					os.WriteFile(file, original, 0644)
					info, _ := os.Lstat(file)
					p.owners.set(info, acornFoxInstallPrincipal{})
				}
			case "hardlink":
				path := filepath.Join(p.parent, "hardlink")
				if err := os.Link(file, path); err != nil {
					t.Fatal(err)
				}
				cleanup = func() { os.Remove(path) }
			case "owner":
				info, _ := os.Lstat(file)
				p.owners.set(info, acornFoxInstallPrincipal{111, 222})
				cleanup = func() { p.owners.set(info, acornFoxInstallPrincipal{}) }
			case "mode":
				os.Chmod(file, 0600)
				cleanup = func() { os.Chmod(file, 0644) }
			case "content":
				os.WriteFile(file, []byte("foreign"), 0644)
				cleanup = func() { os.WriteFile(file, original, 0644) }
			case "stage-unknown":
				path := filepath.Join(u.stagePath(a.bindingSHA), "foreign")
				os.MkdirAll(filepath.Dir(path), 0700)
				os.WriteFile(path, []byte("foreign"), 0600)
				cleanup = func() { os.Remove(path); os.Remove(filepath.Dir(path)) }
			}
			defer cleanup()
			s, err := u.openStore()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			lock, err := s.Acquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Release()
			writes := 0
			u.step = func(string) error { writes++; return nil }
			attempt := j
			if err := u.finishLocalRollover(s, &attempt); err == nil || writes != 0 {
				t.Fatalf("drift accepted/deleted err=%v writes=%d", err, writes)
			}
			if _, err := os.Lstat(filepath.Join(release, "bin")); err != nil {
				t.Fatal("deleted prior to complete validation")
			}
		})
	}
	u.step = func(string) error { return nil }
	s, err := u.openStore()
	if err != nil {
		t.Fatal(err)
	}
	lock, err := s.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := u.finishLocalRollover(s, &j); err != nil {
		t.Fatal(err)
	}
	lock.Release()
	s.Close()
	assertLocalRolloverPair(t, u, p, c.bindingSHA)
	for path, want := range sentinels {
		raw, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(raw, want) {
			t.Fatal("user data changed", path)
		}
	}
	p.assertExternalSentinel(t)
}

func TestAcornFoxLocalRolloverRecoveryProcess(t *testing.T) {
	for _, test := range []struct {
		name string
		nth  int
		fail bool
	}{
		{"local-journal-prefix", 1, false}, {"local-collection-unlinked", 100, false}, {"local-reset-restored", 1, true},
		{"local-intent-staged", 1, false}, {"local-intent-committed", 1, false}, {"local-intent-cleared", 1, false}, {"local-intent-cleared", 1, true},
		{"local-phase-staged", 5, false}, {"local-phase-staged", 6, true},
		{"local-settle-staged", 1, false}, {"local-settle-committed", 1, false},
		{"local-settle-staged", 1, true}, {"local-settle-committed", 1, true},
	} {
		t.Run(fmt.Sprintf("%s-fail%t", test.name, test.fail), func(t *testing.T) {
			t.Parallel()
			u, p, a, service := localRolloverFixture(t)
			b := localRolloverDistinctHelperCandidate(t, "1.2.4-test.1", &a)
			if _, err := u.upgrade(context.Background(), localRolloverRequest(t, u, a, b)); err != nil {
				t.Fatal(err)
			}
			c := localRolloverDistinctHelperCandidate(t, "1.2.5-test.1", &b)
			service.old = b.bindingSHA
			service.failNext = test.fail
			n := 0
			fired := false
			u.step = func(name string) error {
				if name == test.name {
					n++
					if n == test.nth {
						fired = true
						return errors.New("power loss")
					}
				}
				return nil
			}
			if _, err := u.upgrade(context.Background(), localRolloverRequest(t, u, b, c)); err == nil || !fired {
				t.Fatalf("fault %v fired=%t", err, fired)
			}
			durable := localRolloverJournal(t, u)
			identity := b.binding
			want := "ROLLED_BACK"
			current := b.bindingSHA
			if test.name == "local-settle-committed" {
				want = durable.Phase
				identity = func() AcornFoxCandidateBindingV1 {
					var binding AcornFoxCandidateBindingV1
					json.Unmarshal(acornFoxLocalCurrent(durable).Binding, &binding)
					return binding
				}()
				current = acornFoxLocalCurrent(durable).Repo.BindingSHA256
			}
			if durable.LocalRollover != nil && durable.Phase == "UPGRADED" {
				identity = c.binding
				want = "UPGRADED"
				current = c.bindingSHA
			}
			id := AcornFoxBuildIdentityV1{SchemaVersion: 1, Product: identity.Product, LayoutVersion: 1, Role: "upgrade", Version: identity.Version, ReleaseID: identity.ReleaseID, SourceCommit: identity.SourceCommit}
			self := filepath.Join(p.host, AcornFoxUpgradeHelperPath)
			runRetired0039RecoveryProcess(t, p, self, id, false, want)
			assertLocalRolloverPair(t, u, p, current)
			settled := localRolloverJournal(t, u)
			runRetired0039RecoveryProcess(t, p, self, acornFoxLocalCurrent(settled).identity(), false, settled.Phase)
		})
	}
}

// Frozen pre-beta.13 decoder schema. It must reject a complete valid envelope
// before any validation fallback, file creation, lock, or service operation.
type acornFoxPreRolloverJournal struct {
	SchemaVersion int                           `json:"schema_version"`
	Phase         string                        `json:"phase"`
	LayoutSHA256  string                        `json:"layout_sha256"`
	PIEnabled     bool                          `json:"pi_enabled,omitempty"`
	CrossSchema   *acornFoxCrossSchemaUpgradeV1 `json:"cross_schema,omitempty"`
	Retired0039   *acornFoxRetired0039          `json:"retired_0039,omitempty"`
	PostCross     *acornFoxPostCrossUpgrade     `json:"post_cross,omitempty"`
	Old           acornFoxUpgradeImage          `json:"old"`
	Next          acornFoxUpgradeImage          `json:"next"`
}

func assertAcornFoxOldReaderRejectsLocalRollover(t *testing.T, u *acornFoxUpgrade) {
	t.Helper()
	j := localRolloverJournal(t, u)
	if j.validate(u.layout) != nil || j.LocalRollover == nil {
		t.Fatal("reader fixture is not fully valid")
	}
	for _, state := range []string{"RETAINING", "PRUNING", "RESETTING"} {
		clone := j
		r := *j.LocalRollover
		clone.LocalRollover = &r
		r.State = state
		if state == "PRUNING" {
			clone.Phase = "UPGRADED"
		}
		if state == "RESETTING" {
			clone.Phase = "ROLLED_BACK"
		}
		if clone.validate(u.layout) != nil {
			t.Fatal("invalid reader state fixture", state)
		}
		var old acornFoxPreRolloverJournal
		if err := strictCanonicalJSON(acornFoxUpgradeJSON(clone), &old, "old journal"); err == nil || !strings.Contains(err.Error(), `unknown field "local_rollover"`) {
			t.Fatalf("old reader did not refuse new field: %v", err)
		}
	}
	plain := j
	plain.LocalRollover = nil
	var old acornFoxPreRolloverJournal
	if err := strictCanonicalJSON(acornFoxUpgradeJSON(plain), &old, "old journal"); err != nil {
		t.Fatal("old reader rejects ordinary pair", err)
	}
}

func localRolloverDistinctHelperCandidate(t *testing.T, version string, old *acornFoxFixture) acornFoxFixture {
	t.Helper()
	fixture := newAcornFoxFixture(t, version, old)
	changeAcornFoxRecoveryHelperFixture(t, &fixture)
	return fixture
}

func TestAcornFoxLocalRolloverIntentNeverSubstitutesCandidate(t *testing.T) {
	u, p, a, _ := localRolloverFixture(t)
	b := localRolloverDistinctHelperCandidate(t, "1.2.4-test.1", &a)
	if _, err := u.upgrade(context.Background(), localRolloverRequest(t, u, a, b)); err != nil {
		t.Fatal(err)
	}
	previous := localRolloverJournal(t, u)
	d := localRolloverDistinctHelperCandidate(t, "1.2.6-test.1", &b)
	dRequest := localRolloverRequest(t, u, b, d)
	set, err := loadAcornFoxCandidateSet(AcornFoxCandidateSetRequestV1{dRequest.Directory, dRequest.BindingSHA256, dRequest.SelfSHA256}, b.bindingRaw, u.self)
	if err != nil {
		t.Fatal(err)
	}
	s, err := u.openStore()
	if err != nil {
		t.Fatal(err)
	}
	lock, err := s.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stage, err := u.stage(context.Background(), s, set)
	if err != nil {
		t.Fatal(err)
	}
	stage.Close()
	set.Close()
	lock.Release()
	s.Close()
	dReceiptPath := filepath.Join(u.stagePath(d.bindingSHA), acornFoxSubstrateReceipt)
	dReceipt, err := os.ReadFile(dReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	c := localRolloverDistinctHelperCandidate(t, "1.2.5-test.1", &b)
	cRequest := localRolloverRequest(t, u, b, c)
	u.step = func(name string) error {
		if name == "local-journal-prefix" {
			return errors.New("power loss")
		}
		return nil
	}
	if _, err := u.upgrade(context.Background(), cRequest); err == nil {
		t.Fatal("prefix fault missed")
	}
	previousSHA := sha256Hex(acornFoxUpgradeJSON(previous))
	intentPath, _ := acornFoxLocalIntentPaths(previousSHA)
	originalIntent, err := os.ReadFile(filepath.Join(p.state, intentPath))
	if err != nil {
		t.Fatal(err)
	}
	var intent acornFoxLocalRolloverIntent
	if json.Unmarshal(originalIntent, &intent) != nil || intent.NextBindingSHA256 != c.bindingSHA {
		t.Fatal("intent did not bind C before prefix")
	}
	prefixPath := filepath.Join(p.state, ".acornfox-local-rollover-"+previousSHA)
	originalPrefix, err := os.ReadFile(prefixPath)
	if err != nil {
		t.Fatal(err)
	}
	fresh := newAcornFoxUpgrade(p.layout)
	fresh.ownership = p.owners.edge()
	service := &acornFoxUpgradeServiceFake{old: b.bindingSHA, forbidEdge: true}
	fresh.services = service
	fresh.self = acornFoxSelfVerifier{path: filepath.Join(p.host, AcornFoxUpgradeHelperPath), uid: os.Getuid(), gid: os.Getgid()}
	reject := func(t *testing.T) {
		t.Helper()
		service.calls = nil
		if _, _, err := fresh.recover(context.Background(), previous.Next.identity()); err == nil {
			t.Fatal("substituted or ignored invalid C")
		}
		if len(service.calls) != 0 {
			t.Fatal("invalid pending input reached services")
		}
		if !bytes.Equal(acornFoxUpgradeJSON(previous), acornFoxUpgradeJSON(localRolloverJournal(t, fresh))) {
			t.Fatal("previous journal changed")
		}
		raw, err := os.ReadFile(prefixPath)
		if err != nil || !bytes.Equal(raw, originalPrefix) {
			t.Fatal("pending prefix changed")
		}
		raw, err = os.ReadFile(dReceiptPath)
		if err != nil || !bytes.Equal(raw, dReceipt) {
			t.Fatal("D stage changed")
		}
	}
	t.Run("C-missing-D-only", func(t *testing.T) {
		held := filepath.Join(p.parent, "held-C-stage")
		if err := os.Rename(u.stagePath(c.bindingSHA), held); err != nil {
			t.Fatal(err)
		}
		defer os.Rename(held, u.stagePath(c.bindingSHA))
		reject(t)
	})
	t.Run("C-corrupt-D-valid", func(t *testing.T) {
		path := filepath.Join(u.stagePath(c.bindingSHA), acornFoxSubstrateReceipt)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
			t.Fatal(err)
		}
		defer os.WriteFile(path, raw, 0600)
		reject(t)
	})
	t.Run("intent-candidate-changed-with-original-journal-hash", func(t *testing.T) {
		changed := intent
		changed.NextBindingSHA256 = d.bindingSHA
		if err := os.WriteFile(filepath.Join(p.state, intentPath), acornFoxUpgradeJSON(changed), 0600); err != nil {
			t.Fatal(err)
		}
		defer os.WriteFile(filepath.Join(p.state, intentPath), originalIntent, 0600)
		reject(t)
	})
	t.Run("intent-missing", func(t *testing.T) {
		path := filepath.Join(p.state, intentPath)
		held := filepath.Join(p.parent, "held-intent")
		if err := os.Rename(path, held); err != nil {
			t.Fatal(err)
		}
		defer os.Rename(held, path)
		store, err := fresh.openStore()
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		draft, err := fresh.reconstructLocalRolloverPrefix(store, previous, originalPrefix, intent)
		if err != nil {
			t.Fatal(err)
		}
		if err := fresh.verifyLocalRolloverIntent(store, draft); err == nil {
			t.Fatal("uncommitted draft accepted absent intent")
		}
		reject(t)
	})
	t.Run("valid-intent-unknown-pending-temp", func(t *testing.T) {
		_, temp := acornFoxLocalIntentPaths(previousSHA)
		path := filepath.Join(p.state, temp)
		if err := os.WriteFile(path, []byte("unknown"), 0600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path)
		reject(t)
	})
	t.Run("intent-consumed-before-recovery-lock", func(t *testing.T) {
		path := filepath.Join(p.state, intentPath)
		held := filepath.Join(p.parent, "concurrently-consumed-intent")
		moved := false
		fresh.step = func(name string) error {
			if name == "local-pending-verified" && !moved {
				if err := os.Rename(path, held); err != nil {
					t.Fatal(err)
				}
				moved = true
			}
			return nil
		}
		defer func() {
			fresh.step = func(string) error { return nil }
			if moved {
				os.Rename(held, path)
			}
		}()
		reject(t)
		if !moved {
			t.Fatal("recovery lock boundary was not reached")
		}
	})
	promotedC := false
	fresh.step = func(name string) error {
		if name == "local-journal-committed" {
			j := localRolloverJournal(t, fresh)
			if j.Next.Repo.BindingSHA256 != c.bindingSHA {
				t.Fatal("D promoted instead of C")
			}
			promotedC = true
		}
		return nil
	}
	if receipt, handled, err := fresh.recover(context.Background(), previous.Next.identity()); err != nil || !handled || receipt.BindingSHA256 != b.bindingSHA || !promotedC {
		t.Fatalf("C+D exact recovery err=%v handled=%t promotedC=%t", err, handled, promotedC)
	}
	assertLocalRolloverPair(t, fresh, p, b.bindingSHA)
	if raw, err := os.ReadFile(dReceiptPath); err != nil || !bytes.Equal(raw, dReceipt) {
		t.Fatal("unrelated D stage consumed")
	}
	t.Run("committed-PREPARED-journal-is-independent-authority", func(t *testing.T) {
		u.step = func(name string) error {
			if name == "prepared" {
				return errors.New("power loss")
			}
			return nil
		}
		if _, err := u.upgrade(context.Background(), cRequest); err == nil {
			t.Fatal("prepared fault missed")
		}
		committed := localRolloverJournal(t, fresh)
		if committed.Phase != "PREPARED" || committed.LocalRollover == nil || committed.Next.Repo.BindingSHA256 != c.bindingSHA {
			t.Fatal("no committed C authority")
		}
		if err := os.Remove(filepath.Join(p.state, intentPath)); err != nil {
			t.Fatal(err)
		}
		fresh.step = func(string) error { return nil }
		if receipt, handled, err := fresh.recover(context.Background(), previous.Next.identity()); err != nil || !handled || receipt.BindingSHA256 != b.bindingSHA {
			t.Fatalf("committed journal recovery err=%v handled=%t", err, handled)
		}
		assertLocalRolloverPair(t, fresh, p, b.bindingSHA)
		if raw, err := os.ReadFile(dReceiptPath); err != nil || !bytes.Equal(raw, dReceipt) {
			t.Fatal("D substituted or changed")
		}
	})

}

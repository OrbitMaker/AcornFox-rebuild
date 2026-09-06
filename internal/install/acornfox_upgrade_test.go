package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type acornFoxUpgradeServiceFake struct {
	calls             []string
	failNext, failOld bool
	old               string
}

func (f *acornFoxUpgradeServiceFake) Run(_ context.Context, verb, unit string) error {
	f.calls = append(f.calls, verb+" "+unit)
	return nil
}
func (f *acornFoxUpgradeServiceFake) Healthy(_ context.Context, i acornFoxUpgradeImage) error {
	f.calls = append(f.calls, "healthy "+i.Repo.BindingSHA256)
	if i.Repo.BindingSHA256 == f.old && f.failOld || i.Repo.BindingSHA256 != f.old && f.failNext {
		return errors.New("health failed")
	}
	return nil
}
func (f *acornFoxUpgradeServiceFake) EdgeHealthy(context.Context) error {
	f.calls = append(f.calls, "edge healthy")
	return nil
}
func upgradeFixture(t *testing.T) (*acornFoxUpgrade, acornFoxProductionPreparedFixture, AcornFoxUpgradeRequestV1, *acornFoxUpgradeServiceFake) {
	t.Helper()
	runtime, p, id := runtimeConfigFixture(t)
	if _, e := runtimeRun(runtime, id); e != nil {
		t.Fatal(e)
	}
	old := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	next := newAcornFoxFixture(t, "1.2.4-test.1", &old)
	candidate, self, sha := writeAcornFoxBridgeCandidate(t, p.parent, next)
	if e := os.MkdirAll(filepath.Join(p.host, "var/tmp"), 0755); e != nil {
		t.Fatal(e)
	}
	u := newAcornFoxUpgrade(p.layout)
	u.ownership = p.owners.edge()
	u.self = acornFoxSelfVerifier{path: self, uid: os.Getuid(), gid: os.Getgid()}
	service := &acornFoxUpgradeServiceFake{old: p.binding}
	u.services = service
	return u, p, AcornFoxUpgradeRequestV1{candidate, next.bindingSHA, p.binding, sha}, service
}
func TestAcornFoxUpgradeSuccessPreservesDataAndRebindsReceipts(t *testing.T) {
	u, p, request, services := upgradeFixture(t)
	_, oldRaw := runtimeIntentForTest(t, p)
	sentinel := filepath.Join(p.host, "var/lib/acornfox/uploads/business-sentinel")
	if e := os.WriteFile(sentinel, []byte("keep database and application data"), 0600); e != nil {
		t.Fatal(e)
	}
	receipt, e := u.upgrade(context.Background(), request)
	if e != nil {
		raw, _ := os.ReadFile(filepath.Join(p.state, acornFoxUpgradeJournalPath))
		var j acornFoxUpgradeJournal
		_ = strictCanonicalJSON(raw, &j, "test")
		t.Fatalf("upgrade phase=%s calls=%v error=%v", j.Phase, services.calls, e)
	}
	if receipt.Validate() != nil || receipt.State != "UPGRADED" || receipt.BindingSHA256 != request.BindingSHA256 {
		t.Fatal("wrong receipt")
	}
	newIntent, newRaw := runtimeIntentForTest(t, p)
	var oldIntent acornFoxRuntimeIntent
	if strictCanonicalJSON(oldRaw, &oldIntent, "old") != nil {
		t.Fatal("old intent")
	}
	if newIntent.Inputs.Version != "1.2.4-test.1" || newIntent.BindingSHA256 != request.BindingSHA256 || bytes.Equal(newRaw, oldRaw) {
		t.Fatal("runtime binding was not updated")
	}
	for _, old := range oldIntent.Files {
		for _, next := range newIntent.Files {
			if old.Path == next.Path && !strings.HasSuffix(old.Path, "agent.env") && !bytes.Equal(old.Data, next.Data) {
				t.Fatal("private material changed")
			}
		}
	}
	if raw, e := os.ReadFile(sentinel); e != nil || string(raw) != "keep database and application data" {
		t.Fatal("business data changed")
	}
	if _, e := os.Stat(filepath.Join(p.host, "opt/acornfox/releases/release-1.2.3-test.1/manifest.json")); e != nil {
		t.Fatal("old release removed")
	}
	if _, e := os.Lstat(filepath.Join(p.host, acornFoxUpgradeMarkerPath)); !os.IsNotExist(e) {
		t.Fatal("marker remained")
	}
	for _, call := range services.calls {
		if strings.HasPrefix(call, "stop ") && (strings.Contains(call, "docker") || strings.Contains(call, "postgres") || strings.Contains(call, "runtime-network")) {
			t.Fatal("protected substrate service stopped")
		}
	}
	s, e := u.openStore()
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	lock, e := s.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Release()
	j, e := u.load(s)
	if e != nil {
		t.Fatal(e)
	}
	if handled, e := acornFoxUpgradeRetainedScope(s.hostRoot, s, j.Next.Activation); !handled || e != nil {
		t.Fatalf("retained scope failed: %v", e)
	}
	p.assertExternalSentinel(t)
}
func TestAcornFoxUpgradeVersionPrecedence(t *testing.T) {
	for _, test := range []struct {
		next, old string
		want      bool
	}{{"1.2.4", "1.2.3", true}, {"1.2.3", "1.2.3", false}, {"1.2.2", "1.2.3", false}, {"1.2.3", "1.2.3-rc.2", true}, {"1.2.3-rc.10", "1.2.3-rc.2", true}, {"1.2.3-rc.2", "1.2.3-rc.10", false}, {"1.2.3-beta", "1.2.3-10", true}, {"1.2.3+new", "1.2.3+old", false}, {"1.2.3-01", "1.2.3-0", false}, {"1.2.3-..", "1.2.2", false}, {" 2.0.0", "1.0.0", false}, {"999999999999999999999.0.0", "100000000000000000000.0.0", true}} {
		if got := acornFoxUpgradeVersionAfter(test.next, test.old); got != test.want {
			t.Fatalf("%s > %s = %t", test.next, test.old, got)
		}
	}
}

func TestAcornFoxUpgradeRejectsForeignInputsBeforeAnyWrites(t *testing.T) {
	for _, kind := range []string{"wrong predecessor", "wrong self", "same version", "downgrade", "migration changed", "foreign scope"} {
		t.Run(kind, func(t *testing.T) {
			u, p, request, service := upgradeFixture(t)
			switch kind {
			case "wrong predecessor":
				request.CurrentBindingSHA256 = strings.Repeat("f", 64)
			case "wrong self":
				request.SelfSHA256 = strings.Repeat("f", 64)
			case "same version", "downgrade", "migration changed":
				old := newAcornFoxFixture(t, "1.2.3-test.1", nil)
				version := "1.2.3-test.1"
				if kind == "downgrade" {
					version = "1.2.2"
				}
				if kind == "migration changed" {
					version = "1.2.4-test.1"
				}
				f := newAcornFoxFixture(t, version, &old)
				if kind == "migration changed" {
					var m Manifest
					if strictCanonicalJSON(f.manifestRaw, &m, "fixture") != nil {
						t.Fatal("manifest")
					}
					contents := map[string][]byte{}
					for idx, file := range m.Files {
						body := []byte("content: " + file.Path + "\n")
						if file.Path == "web/dist/assets/app-12345678.js" {
							body = []byte("asset\n")
						}
						if strings.HasPrefix(file.Path, "migrations/") {
							body = []byte("changed SQL\n")
							m.Files[idx].SHA256 = sha256Hex(body)
						}
						contents[file.Path] = body
					}
					f.manifestRaw = acornFoxUpgradeJSON(m)
					f.archive = acornFoxArchive(t, f.manifestRaw, m.Files, contents, nil)
					f.binding.ManifestSHA256 = sha256Hex(f.manifestRaw)
					f.binding.ArchiveSHA256 = sha256Hex(f.archive)
					f.bundleRaw = []byte(f.binding.ArchiveSHA256 + "  acornfox-" + version + "-production.tar.gz\n" + f.binding.ManifestSHA256 + "  release/manifest.json\n")
					f.binding.BundleManifestSHA256 = sha256Hex(f.bundleRaw)
					f.bindingRaw = acornFoxUpgradeJSON(f.binding)
					f.bindingSHA = sha256Hex(f.bindingRaw)
				}
				parent := t.TempDir()
				dir, self, sha := writeAcornFoxBridgeCandidate(t, parent, f)
				u.self.path = self
				request.Directory, request.BindingSHA256, request.SelfSHA256 = dir, f.bindingSHA, sha
			case "foreign scope":
				if e := os.WriteFile(filepath.Join(p.host, "opt/acornfox/foreign"), []byte("retain"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			before, e := os.ReadFile(filepath.Join(p.state, acornFoxRepoInstallJournal))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = u.upgrade(context.Background(), request); e == nil {
				t.Fatal("invalid input accepted")
			}
			after, e := os.ReadFile(filepath.Join(p.state, acornFoxRepoInstallJournal))
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("repository journal changed")
			}
			if len(service.calls) != 0 {
				t.Fatal("service side effects on rejected input")
			}
			for _, path := range []string{filepath.Join(p.state, "upgrade"), filepath.Join(p.host, acornFoxUpgradeMarkerPath), u.stagePath(request.BindingSHA256)} {
				if _, e = os.Lstat(path); !os.IsNotExist(e) {
					t.Fatal("rejected input created upgrade output")
				}
			}
			p.assertExternalSentinel(t)
		})
	}
}
func TestAcornFoxUpgradeDurablePhasesRecoverWithNextHelper(t *testing.T) {
	for _, point := range []string{"prepared", "blocked", "services-stopped", "file-published", "published", "substrate-retired", "switched", "healthy", "marker-cleared", "upgraded"} {
		t.Run(point, func(t *testing.T) {
			u, p, request, _ := upgradeFixture(t)
			_, oldRaw := runtimeIntentForTest(t, p)
			fired := false
			u.step = func(name string) error {
				if name == point && !fired {
					fired = true
					return errors.New("power loss")
				}
				return nil
			}
			if _, e := u.upgrade(context.Background(), request); e == nil || !fired {
				t.Fatalf("fault not reached: %s %v", point, e)
			}
			u.step = func(string) error { return nil }
			expected := AcornFoxBuildIdentityV1{1, AcornFoxV1Product, 1, "upgrade", "1.2.4-test.1", "release-1.2.4-test.1", strings.Repeat("a", 40)}
			r, handled, e := u.recover(context.Background(), expected)
			if e != nil || !handled || r.Validate() != nil {
				t.Fatalf("recovery %s: handled=%t err=%v", point, handled, e)
			}
			want := "ROLLED_BACK"
			if point == "upgraded" {
				want = "UPGRADED"
			}
			if r.State != want {
				t.Fatalf("wanted %s, got %s", want, r.State)
			}
			if want == "ROLLED_BACK" {
				raw, e := os.ReadFile(filepath.Join(p.state, acornFoxRuntimeIntentName))
				if e != nil || !bytes.Equal(raw, oldRaw) {
					t.Fatal("rollback regenerated runtime keys")
				}
			}
			if _, e := os.Lstat(filepath.Join(p.host, acornFoxUpgradeMarkerPath)); !os.IsNotExist(e) {
				t.Fatal("successful recovery left marker")
			}
			again, handled, e := u.recover(context.Background(), expected)
			if e != nil || !handled || again != r {
				t.Fatal("terminal recovery not idempotent", e)
			}
			p.assertExternalSentinel(t)
		})
	}
}
func TestAcornFoxUpgradeHealthFailureRollsBackAndDoubleFailureStaysBlocked(t *testing.T) {
	for _, both := range []bool{false, true} {
		t.Run(map[bool]string{false: "new fails", true: "both fail"}[both], func(t *testing.T) {
			u, p, request, services := upgradeFixture(t)
			services.failNext, services.failOld = true, both
			_, oldRaw := runtimeIntentForTest(t, p)
			r, e := u.upgrade(context.Background(), request)
			if e == nil {
				t.Fatal("new health failure accepted")
			}
			if both {
				if !errors.Is(e, ErrAcornFoxUpgradeUnknown) {
					t.Fatal(e)
				}
				if _, e := os.Stat(filepath.Join(p.host, acornFoxUpgradeMarkerPath)); e != nil {
					t.Fatal("failed rollback lost marker")
				}
				if services.calls[len(services.calls)-1] != "stop acornfox-edge.service" {
					t.Fatal("edge not stopped after rollback failure")
				}
			} else {
				if r.State != "ROLLED_BACK" || r.BindingSHA256 != request.CurrentBindingSHA256 {
					t.Fatal("old result was not returned")
				}
				if _, e := os.Lstat(filepath.Join(p.host, acornFoxUpgradeMarkerPath)); !os.IsNotExist(e) {
					t.Fatal("recovered marker remained")
				}
			}
			raw, e := os.ReadFile(filepath.Join(p.state, acornFoxRuntimeIntentName))
			if e != nil || !bytes.Equal(raw, oldRaw) {
				t.Fatal("rollback did not restore exact old intent")
			}
			p.assertExternalSentinel(t)
		})
	}
}
func TestAcornFoxUpgradeBootPrepareDoesNotStartServicesBeforeSafeTarget(t *testing.T) {
	u, p, request, services := upgradeFixture(t)
	u.step = func(name string) error {
		if name == "switched" {
			return errors.New("crash")
		}
		return nil
	}
	if _, e := u.upgrade(context.Background(), request); e == nil {
		t.Fatal("fault not reached")
	}
	u.step = func(string) error { return nil }
	services.calls = nil
	next := AcornFoxBuildIdentityV1{1, AcornFoxV1Product, 1, "upgrade", "1.2.4-test.1", "release-1.2.4-test.1", strings.Repeat("a", 40)}
	r, handled, e := u.recoverMode(context.Background(), next, true)
	if e != nil || !handled || r.State != "RECOVERY_PREPARED" || r.BindingSHA256 != request.CurrentBindingSHA256 || r.Validate() != nil {
		t.Fatal("prepare failed", e)
	}
	for _, call := range services.calls {
		if strings.HasPrefix(call, "start ") || strings.HasPrefix(call, "healthy ") {
			t.Fatal("prepare waited for safe-target services")
		}
	}
	if _, e := os.Stat(filepath.Join(p.host, acornFoxUpgradeMarkerPath)); e != nil {
		t.Fatal("prepare removed ingress marker")
	}
	// Finalize executes the restored old helper and accepts its old identity.
	old := next
	old.Version = "1.2.3-test.1"
	old.ReleaseID = "release-" + old.Version
	u.self.path = filepath.Join(p.host, AcornFoxUpgradeHelperPath)
	r, handled, e = u.recover(context.Background(), old)
	if e != nil || !handled || r.State != "ROLLED_BACK" {
		t.Fatal("finalize failed", e)
	}
}

func TestAcornFoxUpgradePartialFilesAndPrivateDirectoryReplay(t *testing.T) {
	for _, point := range []string{"directory-created", "private-substrate-directory-created", "host-file-prefix", "host-file-synced", "host-file-renamed"} {
		t.Run(point, func(t *testing.T) {
			u, _, request, _ := upgradeFixture(t)
			fired := false
			u.step = func(name string) error {
				if name == point && !fired {
					fired = true
					return errors.New("power loss")
				}
				return nil
			}
			if _, e := u.upgrade(context.Background(), request); e == nil || !fired {
				t.Fatalf("fault not reached %s: %v", point, e)
			}
			u.step = func(string) error { return nil }
			expected := AcornFoxBuildIdentityV1{1, AcornFoxV1Product, 1, "upgrade", "1.2.4-test.1", "release-1.2.4-test.1", strings.Repeat("a", 40)}
			r, handled, e := u.recover(context.Background(), expected)
			if e != nil || !handled || r.State != "ROLLED_BACK" {
				t.Fatal("partial durable state failed recovery", e)
			}
		})
	}
}
func TestAcornFoxUpgradeRecoveryDoesNotRecreateMissingBusinessDirectory(t *testing.T) {
	u, p, request, _ := upgradeFixture(t)
	u.step = func(name string) error {
		if name == "prepared" {
			return errors.New("crash")
		}
		return nil
	}
	if _, e := u.upgrade(context.Background(), request); e == nil {
		t.Fatal("fault not reached")
	}
	u.step = func(string) error { return nil }
	directory := filepath.Join(p.host, "var/lib/acornfox/uploads")
	if e := os.Remove(directory); e != nil {
		t.Fatal(e)
	}
	expected := AcornFoxBuildIdentityV1{1, AcornFoxV1Product, 1, "upgrade", "1.2.4-test.1", "release-1.2.4-test.1", strings.Repeat("a", 40)}
	r, handled, e := u.recover(context.Background(), expected)
	if !handled || e == nil || r.SchemaVersion != 0 {
		t.Fatal("missing service data was accepted")
	}
	if _, e := os.Lstat(directory); !os.IsNotExist(e) {
		t.Fatal("missing data root was recreated")
	}
	if _, e := os.Stat(filepath.Join(p.host, acornFoxUpgradeMarkerPath)); e != nil {
		t.Fatal("failed recovery lost marker")
	}
}
func TestAcornFoxUpgradeSameCandidateCanRetryAfterRollback(t *testing.T) {
	u, p, request, services := upgradeFixture(t)
	services.failNext = true
	r, e := u.upgrade(context.Background(), request)
	if !errors.Is(e, ErrAcornFoxUpgradeRolledBack) || r.State != "ROLLED_BACK" {
		t.Fatal("typed rollback not returned", e)
	}
	services.failNext = false
	r, e = u.upgrade(context.Background(), request)
	if e != nil || r.State != "UPGRADED" || r.BindingSHA256 != request.BindingSHA256 {
		t.Fatal("same candidate retry failed", e)
	}
	before, e := os.ReadFile(filepath.Join(p.state, acornFoxUpgradeJournalPath))
	if e != nil {
		t.Fatal(e)
	}
	old := newAcornFoxFixture(t, "1.2.3-test.1", nil)
	one := newAcornFoxFixture(t, "1.2.4-test.1", &old)
	two := newAcornFoxFixture(t, "1.2.5-test.1", &one)
	directory, self, sha := writeAcornFoxBridgeCandidate(t, t.TempDir(), two)
	u.self.path = self
	r, e = u.upgrade(context.Background(), AcornFoxUpgradeRequestV1{directory, two.bindingSHA, one.bindingSHA, sha})
	if !errors.Is(e, ErrAcornFoxUpgradeRetentionFull) || r.SchemaVersion != 0 {
		t.Fatal("third release did not report retention limit", e)
	}
	after, e := os.ReadFile(filepath.Join(p.state, acornFoxUpgradeJournalPath))
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("retention rejection altered journal")
	}
}
func TestAcornFoxUpgradeTerminalVerificationFailureHasNoSuccessReceipt(t *testing.T) {
	u, p, request, _ := upgradeFixture(t)
	if _, e := u.upgrade(context.Background(), request); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(p.host, "opt/acornfox/active")
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("foreign", path); e != nil {
		t.Fatal(e)
	}
	expected := AcornFoxBuildIdentityV1{1, AcornFoxV1Product, 1, "upgrade", "1.2.4-test.1", "release-1.2.4-test.1", strings.Repeat("a", 40)}
	r, handled, e := u.recover(context.Background(), expected)
	if !handled || e == nil || r.SchemaVersion != 0 || errors.Is(e, ErrAcornFoxUpgradeRolledBack) {
		t.Fatal("failed terminal verify returned successful receipt")
	}
	r, e = u.upgrade(context.Background(), request)
	if e == nil || r.SchemaVersion != 0 {
		t.Fatal("failed terminal upgrade replay returned receipt")
	}
}

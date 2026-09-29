package state

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(Config{Path: filepath.Join(dir, "acornfox.db")})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenPermissionsAndMigrations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "acornfox.db")
	s, err := Open(Config{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	di, err := statMode(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Perm() != 0o700 {
		t.Errorf("dir mode = %o, want 700", di.Perm())
	}
	fi, err := statMode(path)
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	if fi.Perm() != 0o600 {
		t.Errorf("db mode = %o, want 600", fi.Perm())
	}

	// Both migrations recorded.
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM _schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if n != 3 {
		t.Errorf("migrations recorded = %d, want 3", n)
	}
	// Admin auth table present.
	var tbl string
	if err := s.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='admin_credentials'`).Scan(&tbl); err != nil {
		t.Fatalf("admin_credentials table missing: %v", err)
	}
}

func TestLockExclusion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acornfox.db")
	s1, err := Open(Config{Path: path})
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	defer s1.Close()

	if _, err := Open(Config{Path: path}); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open err = %v, want ErrLocked", err)
	}

	// Releasing the first lets a new one open.
	if err := s1.Close(); err != nil {
		t.Fatalf("close first: %v", err)
	}
	s2, err := Open(Config{Path: path})
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	s2.Close()
}

func TestEnsureAppDefaultsAndPortAllocation(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	a, created, err := s.EnsureApp(ctx, "web")
	if err != nil || !created {
		t.Fatalf("EnsureApp web: %v created=%v", err, created)
	}
	if a.Desired != DesiredRunning || a.HealthPath != DefaultHealthPath ||
		a.MemoryMB != DefaultMemoryMB || a.CPUMilli != DefaultCPUMilli {
		t.Errorf("defaults wrong: %+v", a)
	}
	if a.PublicPort != 18810 {
		t.Errorf("first public port = %d, want 18810", a.PublicPort)
	}

	// Idempotent.
	a2, created2, err := s.EnsureApp(ctx, "web")
	if err != nil || created2 {
		t.Fatalf("EnsureApp web again: %v created=%v", err, created2)
	}
	if a2.PublicPort != a.PublicPort {
		t.Errorf("public port changed on re-ensure")
	}

	// Second app gets the next free port.
	b, _, err := s.EnsureApp(ctx, "api")
	if err != nil {
		t.Fatalf("EnsureApp api: %v", err)
	}
	if b.PublicPort != 18811 {
		t.Errorf("second public port = %d, want 18811", b.PublicPort)
	}

	// Invalid name.
	if _, _, err := s.EnsureApp(ctx, "Bad_Name"); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid name err = %v, want ErrInvalid", err)
	}
}

func TestPortExhaustion(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Path: filepath.Join(dir, "acornfox.db"), PublicPortMin: 20000, PublicPortMax: 20001})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	if _, _, err := s.EnsureApp(ctx, "aa"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.EnsureApp(ctx, "bb"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.EnsureApp(ctx, "cc"); !errors.Is(err, ErrConflict) {
		t.Fatalf("exhaustion err = %v, want ErrConflict", err)
	}
}

func TestUpdateAppImmutableFields(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	orig, _, _ := s.EnsureApp(ctx, "web")

	updated, err := s.UpdateApp(ctx, "web", func(a *App) error {
		a.Name = "evil"
		a.PublicPort = 99999
		a.CreatedAt = time.Unix(0, 0)
		a.Desired = DesiredStopped
		a.Port = 3000
		return nil
	})
	if err != nil {
		t.Fatalf("UpdateApp: %v", err)
	}
	if updated.Name != "web" || updated.PublicPort != orig.PublicPort || !updated.CreatedAt.Equal(orig.CreatedAt) {
		t.Errorf("immutable field changed: %+v", updated)
	}
	if updated.Desired != DesiredStopped || updated.Port != 3000 {
		t.Errorf("mutable field not applied: %+v", updated)
	}

	// fn error propagates.
	sentinel := errors.New("boom")
	if _, err := s.UpdateApp(ctx, "web", func(a *App) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Errorf("fn error not propagated: %v", err)
	}

	// Missing app.
	if _, err := s.UpdateApp(ctx, "nope", func(a *App) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing app err = %v, want ErrNotFound", err)
	}
}

func TestCreateDeploymentBasicAndSeq(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	s.EnsureApp(ctx, "web")

	d1, created, err := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/u/1", SourceDigest: "aaa"})
	if err != nil || !created {
		t.Fatalf("create d1: %v created=%v", err, created)
	}
	if d1.Seq != 1 || d1.Status != StatusQueued || len(d1.ID) != 12 {
		t.Errorf("d1 wrong: %+v", d1)
	}

	d2, created, err := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/u/2", SourceDigest: "bbb"})
	if err != nil || !created {
		t.Fatalf("create d2: %v created=%v", err, created)
	}
	if d2.Seq != 2 {
		t.Errorf("d2 seq = %d, want 2", d2.Seq)
	}
}

func TestCreateDeploymentIdempotency(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	s.EnsureApp(ctx, "web")

	// Same request key -> same deployment.
	d1, created, err := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/u/1", SourceDigest: "aaa", RequestKey: "k1"})
	if err != nil || !created {
		t.Fatalf("create: %v", err)
	}
	dup, created, err := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/u/1b", SourceDigest: "zzz", RequestKey: "k1"})
	if err != nil {
		t.Fatalf("dup by key: %v", err)
	}
	if created || dup.ID != d1.ID {
		t.Errorf("request-key idempotency failed: created=%v id=%s want %s", created, dup.ID, d1.ID)
	}

	// Same digest as the newest pending -> same deployment even without key.
	dupDigest, created, err := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/u/other", SourceDigest: "aaa"})
	if err != nil {
		t.Fatalf("dup by digest: %v", err)
	}
	if created || dupDigest.ID != d1.ID {
		t.Errorf("digest idempotency failed: created=%v id=%s", created, dupDigest.ID)
	}

	// Different digest -> new deployment.
	d2, created, err := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/u/3", SourceDigest: "ccc"})
	if err != nil || !created {
		t.Fatalf("new digest: %v created=%v", err, created)
	}
	if d2.ID == d1.ID {
		t.Errorf("expected new deployment for new digest")
	}
}

func TestConcurrentCreateDeployment(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	s.EnsureApp(ctx, "web")

	const n = 20
	var wg sync.WaitGroup
	ids := make([]string, n)
	createdFlags := make([]bool, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// All share one request key: exactly one must be created.
			d, created, err := s.CreateDeployment(ctx, NewDeployment{
				App: "web", SourceKind: SourceUpload, SourceRef: "/u", SourceDigest: "same", RequestKey: "shared",
			})
			ids[i] = d.ID
			createdFlags[i] = created
			errs[i] = err
		}(i)
	}
	wg.Wait()

	createdCount := 0
	var theID string
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d err: %v", i, errs[i])
		}
		if createdFlags[i] {
			createdCount++
		}
		if theID == "" {
			theID = ids[i]
		} else if ids[i] != theID {
			t.Errorf("goroutine %d got different id %s vs %s", i, ids[i], theID)
		}
	}
	if createdCount != 1 {
		t.Errorf("createdCount = %d, want exactly 1", createdCount)
	}
	deps, _ := s.ListDeployments(ctx, "web", 0)
	if len(deps) != 1 {
		t.Errorf("deployments in db = %d, want 1", len(deps))
	}
}

func TestUpdateDeploymentTerminalGuardAndFinishedAt(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	s.EnsureApp(ctx, "web")
	d, _, _ := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/u/1", SourceDigest: "a"})

	// Move to building, set attempts.
	up, err := s.UpdateDeployment(ctx, d.ID, func(dep *Deployment) error {
		dep.Status = StatusBuilding
		dep.Attempts = 1
		dep.ImageID = "img1"
		return nil
	})
	if err != nil {
		t.Fatalf("update building: %v", err)
	}
	if up.FinishedAt != nil {
		t.Errorf("non-terminal should not set FinishedAt")
	}

	// Move to failed (terminal) with a diagnosis and a warning.
	up, err = s.UpdateDeployment(ctx, d.ID, func(dep *Deployment) error {
		dep.Status = StatusFailed
		dep.Diagnosis = &Diagnosis{Stage: "build", Code: "build_failed", Message: "构建失败"}
		dep.Warnings = []Diagnosis{{Stage: "data", Code: "unpersisted_database", Message: "检测到未持久化数据库"}}
		return nil
	})
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}
	if up.FinishedAt == nil {
		t.Errorf("terminal status must set FinishedAt")
	}
	if up.Diagnosis == nil || up.Diagnosis.Code != "build_failed" {
		t.Errorf("diagnosis not persisted: %+v", up.Diagnosis)
	}
	if len(up.Warnings) != 1 || up.Warnings[0].Code != "unpersisted_database" {
		t.Errorf("warnings not persisted: %+v", up.Warnings)
	}

	// Leaving terminal is rejected.
	if _, err := s.UpdateDeployment(ctx, d.ID, func(dep *Deployment) error {
		dep.Status = StatusLive
		return nil
	}); !errors.Is(err, ErrConflict) {
		t.Errorf("terminal guard err = %v, want ErrConflict", err)
	}
}

func TestSetCurrentDeployment(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	s.EnsureApp(ctx, "web")

	d1, _, _ := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/u/1", SourceDigest: "a"})
	if err := s.SetCurrentDeployment(ctx, "web", d1.ID); err != nil {
		t.Fatalf("set current d1: %v", err)
	}
	app, _ := s.GetApp(ctx, "web")
	if app.CurrentDeployment != d1.ID {
		t.Errorf("current = %s, want %s", app.CurrentDeployment, d1.ID)
	}
	got, _ := s.GetDeployment(ctx, d1.ID)
	if got.Status != StatusLive {
		t.Errorf("d1 status = %s, want live", got.Status)
	}

	d2, _, _ := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/u/2", SourceDigest: "b"})
	if err := s.SetCurrentDeployment(ctx, "web", d2.ID); err != nil {
		t.Fatalf("set current d2: %v", err)
	}
	old, _ := s.GetDeployment(ctx, d1.ID)
	if old.Status != StatusRetired {
		t.Errorf("previous live status = %s, want retired", old.Status)
	}
	if old.FinishedAt == nil {
		t.Errorf("retired deployment must have FinishedAt")
	}
	nowLive, _ := s.GetDeployment(ctx, d2.ID)
	if nowLive.Status != StatusLive {
		t.Errorf("d2 status = %s, want live", nowLive.Status)
	}
}

func TestKeptImageDeployments(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	s.EnsureApp(ctx, "web")

	// Build a chain: 5 successful versions promoted one after another.
	var ids []string
	for i := 0; i < 5; i++ {
		d, _, _ := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/u", SourceDigest: string(rune('a' + i))})
		s.UpdateDeployment(ctx, d.ID, func(dep *Deployment) error {
			dep.Status = StatusStarting
			dep.ImageID = "img-" + d.ID
			return nil
		})
		s.SetCurrentDeployment(ctx, "web", d.ID)
		ids = append(ids, d.ID)
	}

	kept, err := s.KeptImageDeployments(ctx, "web")
	if err != nil {
		t.Fatalf("KeptImageDeployments: %v", err)
	}
	// live (last) + KeepVersions(3) retired = 4.
	if len(kept) != 1+KeepVersions {
		t.Fatalf("kept = %d, want %d", len(kept), 1+KeepVersions)
	}
	keptSet := map[string]bool{}
	for _, d := range kept {
		keptSet[d.ID] = true
	}
	// The oldest retired deployment must be eligible for GC (not kept):
	// retired = {d0,d1,d2,d3}, keep newest 3 (d3,d2,d1) + live d4.
	if keptSet[ids[0]] {
		t.Errorf("oldest deployment should not be kept: %v", keptSet)
	}
	if !keptSet[ids[1]] || !keptSet[ids[2]] || !keptSet[ids[3]] {
		t.Errorf("three newest retired must be kept: %v", keptSet)
	}
	// The live one must be kept.
	if !keptSet[ids[4]] {
		t.Errorf("live deployment must be kept")
	}
}

func TestEnvCRUD(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	s.EnsureApp(ctx, "web")

	if err := s.SetEnv(ctx, EnvVar{App: "web", Key: "PORT", Value: "3000"}); err != nil {
		t.Fatalf("set env: %v", err)
	}
	if err := s.SetEnv(ctx, EnvVar{App: "web", Key: "SECRET_TOKEN", Value: "shh", Secret: true}); err != nil {
		t.Fatalf("set secret env: %v", err)
	}
	// Overwrite.
	if err := s.SetEnv(ctx, EnvVar{App: "web", Key: "PORT", Value: "8080"}); err != nil {
		t.Fatalf("overwrite env: %v", err)
	}
	env, _ := s.ListEnv(ctx, "web")
	if len(env) != 2 {
		t.Fatalf("env count = %d, want 2", len(env))
	}
	byKey := map[string]EnvVar{}
	for _, e := range env {
		byKey[e.Key] = e
	}
	if byKey["PORT"].Value != "8080" {
		t.Errorf("PORT = %q, want 8080", byKey["PORT"].Value)
	}
	if !byKey["SECRET_TOKEN"].Secret || byKey["SECRET_TOKEN"].Value != "shh" {
		t.Errorf("secret env wrong: %+v", byKey["SECRET_TOKEN"])
	}

	// Invalid key.
	if err := s.SetEnv(ctx, EnvVar{App: "web", Key: "1BAD", Value: "x"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid key err = %v, want ErrInvalid", err)
	}

	if err := s.DeleteEnv(ctx, "web", "PORT"); err != nil {
		t.Fatalf("delete env: %v", err)
	}
	env, _ = s.ListEnv(ctx, "web")
	if len(env) != 1 {
		t.Errorf("after delete env count = %d, want 1", len(env))
	}
}

func TestVolumesNamingAndIdempotency(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	s.EnsureApp(ctx, "web")

	v1, created, err := s.AddVolume(ctx, "web", "/data", true)
	if err != nil || !created {
		t.Fatalf("add v1: %v created=%v", err, created)
	}
	if v1.VolumeName != "af-web-1" {
		t.Errorf("v1 name = %s, want af-web-1", v1.VolumeName)
	}
	if !v1.Auto {
		t.Errorf("v1 should be auto")
	}

	// Idempotent per (app, path).
	v1b, created, err := s.AddVolume(ctx, "web", "/data", false)
	if err != nil {
		t.Fatalf("add v1 again: %v", err)
	}
	if created || v1b.VolumeName != "af-web-1" {
		t.Errorf("idempotent add reused? created=%v name=%s", created, v1b.VolumeName)
	}

	v2, _, _ := s.AddVolume(ctx, "web", "/uploads", false)
	if v2.VolumeName != "af-web-2" {
		t.Errorf("v2 name = %s, want af-web-2", v2.VolumeName)
	}

	// Non-absolute path rejected.
	if _, _, err := s.AddVolume(ctx, "web", "data", false); !errors.Is(err, ErrInvalid) {
		t.Errorf("relative path err = %v, want ErrInvalid", err)
	}

	vols, _ := s.ListVolumes(ctx, "web")
	if len(vols) != 2 {
		t.Errorf("volume count = %d, want 2", len(vols))
	}
}

func TestVolumeCounterNeverReused(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	s.EnsureApp(ctx, "web")

	s.AddVolume(ctx, "web", "/a", false) // af-web-1
	s.AddVolume(ctx, "web", "/b", false) // af-web-2
	// There is no delete API, but the counter is stored on the app; verify it
	// increments monotonically even if a row were removed directly.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM app_volumes WHERE path='/b'`); err != nil {
		t.Fatalf("manual delete: %v", err)
	}
	v3, _, err := s.AddVolume(ctx, "web", "/c", false)
	if err != nil {
		t.Fatalf("add /c: %v", err)
	}
	if v3.VolumeName != "af-web-3" {
		t.Errorf("v3 name = %s, want af-web-3 (counter must not reuse)", v3.VolumeName)
	}
}

func TestEvents(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	s.EnsureApp(ctx, "web")
	d, _, _ := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/u", SourceDigest: "a"})

	for i := 0; i < 3; i++ {
		if err := s.AddEvent(ctx, Event{App: "web", DeploymentID: d.ID, Stage: "build", Message: "step"}); err != nil {
			t.Fatalf("add event: %v", err)
		}
	}
	if err := s.AddEvent(ctx, Event{App: "web", Stage: "gc", Message: "no deployment"}); err != nil {
		t.Fatalf("add event: %v", err)
	}

	all, _ := s.ListEvents(ctx, "web", "", 0, 0)
	if len(all) != 4 {
		t.Fatalf("events = %d, want 4", len(all))
	}
	// IDs strictly increasing.
	for i := 1; i < len(all); i++ {
		if all[i].ID <= all[i-1].ID {
			t.Errorf("event ids not increasing: %d then %d", all[i-1].ID, all[i].ID)
		}
	}
	// Filter by deployment.
	byDep, _ := s.ListEvents(ctx, "web", d.ID, 0, 0)
	if len(byDep) != 3 {
		t.Errorf("deployment events = %d, want 3", len(byDep))
	}
	// after cursor.
	after, _ := s.ListEvents(ctx, "web", "", all[1].ID, 0)
	if len(after) != 2 {
		t.Errorf("after cursor events = %d, want 2", len(after))
	}
}

func TestReopenPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acornfox.db")
	ctx := context.Background()

	s, err := Open(Config{Path: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s.EnsureApp(ctx, "web")
	d, _, _ := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/u", SourceDigest: "a"})
	s.UpdateDeployment(ctx, d.ID, func(dep *Deployment) error {
		dep.Status = StatusStarting
		dep.ImageID = "img"
		return nil
	})
	s.SetCurrentDeployment(ctx, "web", d.ID)
	s.SetEnv(ctx, EnvVar{App: "web", Key: "K", Value: "V", Secret: true})
	s.AddVolume(ctx, "web", "/data", true)
	s.Close()

	// Reopen and verify everything survived.
	s2, err := Open(Config{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	app, err := s2.GetApp(ctx, "web")
	if err != nil {
		t.Fatalf("get app: %v", err)
	}
	if app.CurrentDeployment != d.ID {
		t.Errorf("current deployment lost: %s", app.CurrentDeployment)
	}
	got, _ := s2.GetDeployment(ctx, d.ID)
	if got.Status != StatusLive || got.ImageID != "img" {
		t.Errorf("deployment not persisted: %+v", got)
	}
	env, _ := s2.ListEnv(ctx, "web")
	if len(env) != 1 || !env[0].Secret || env[0].Value != "V" {
		t.Errorf("env not persisted: %+v", env)
	}
	vols, _ := s2.ListVolumes(ctx, "web")
	if len(vols) != 1 || vols[0].VolumeName != "af-web-1" {
		t.Errorf("volumes not persisted: %+v", vols)
	}
}

func TestBadSchemaChecksum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acornfox.db")
	s, err := Open(Config{Path: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Corrupt a recorded checksum, then reopen.
	if _, err := s.db.Exec(`UPDATE _schema_migrations SET checksum=? WHERE version='0001_apps'`,
		"0000000000000000000000000000000000000000000000000000000000000000"); err != nil {
		t.Fatalf("corrupt checksum: %v", err)
	}
	s.Close()

	if _, err := Open(Config{Path: path}); !errors.Is(err, ErrBadSchema) {
		t.Fatalf("reopen with bad checksum err = %v, want ErrBadSchema", err)
	}
}

func TestPendingDeploymentsOrder(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	s.EnsureApp(ctx, "web")

	d1, _, _ := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/1", SourceDigest: "a"})
	d2, _, _ := s.CreateDeployment(ctx, NewDeployment{App: "web", SourceKind: SourceUpload, SourceRef: "/2", SourceDigest: "b"})
	// Terminate d1 so it drops out of pending.
	s.UpdateDeployment(ctx, d1.ID, func(dep *Deployment) error {
		dep.Status = StatusSuperseded
		return nil
	})
	pending, _ := s.PendingDeployments(ctx, "web")
	if len(pending) != 1 || pending[0].ID != d2.ID {
		t.Errorf("pending wrong: %+v", pending)
	}
}

// TestCreateGitDeployment verifies migration 0003 widened the source_kind CHECK
// so a 'git' deployment is accepted and round-trips through the store.
func TestCreateGitDeployment(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, _, err := s.EnsureApp(ctx, "notes"); err != nil {
		t.Fatalf("EnsureApp: %v", err)
	}
	d, created, err := s.CreateDeployment(ctx, NewDeployment{
		App:          "notes",
		SourceKind:   SourceGit,
		SourceRef:    "https://example.com/repo.git#main",
		SourceDigest: "abc123",
	})
	if err != nil {
		t.Fatalf("CreateDeployment(git): %v", err)
	}
	if !created {
		t.Fatalf("expected a new deployment")
	}
	if d.SourceKind != SourceGit {
		t.Fatalf("source_kind = %q, want git", d.SourceKind)
	}
	got, err := s.GetDeployment(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetDeployment: %v", err)
	}
	if got.SourceKind != SourceGit || got.SourceRef != "https://example.com/repo.git#main" {
		t.Fatalf("git deployment did not round-trip: %+v", got)
	}
}

// TestCreateDeploymentRejectsUnknownSourceKind guards the widened CHECK still
// rejects unknown kinds at the validation layer.
func TestCreateDeploymentRejectsUnknownSourceKind(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, _, err := s.EnsureApp(ctx, "notes"); err != nil {
		t.Fatalf("EnsureApp: %v", err)
	}
	_, _, err := s.CreateDeployment(ctx, NewDeployment{
		App:        "notes",
		SourceKind: "bogus",
		SourceRef:  "x",
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

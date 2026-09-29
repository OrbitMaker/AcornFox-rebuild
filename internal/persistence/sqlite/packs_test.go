package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	contracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/packprotocol"
)

func fixtureSelection(t *testing.T, s *Store, id string, sequence uint64, artifact string) packprotocol.VerifiedPackSelection {
	t.Helper()
	binding, err := s.InstallationBinding(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(packprotocol.Manifest{Schema: "acornfox-pack-manifest-v1", PackID: id, Version: "1.0.0", OS: "linux", Arch: "amd64", MinCoreVersion: "1.0.0", ProtocolVersion: "1.0", Capabilities: []string{"echo.run"}, Dependencies: []packprotocol.Dependency{}, Permissions: []string{}, Entries: []packprotocol.Entry{{Role: "adapter", Path: "bin/adapter"}}, Files: []packprotocol.File{{Path: "bin/adapter", SHA256: strings.Repeat("a", 64), Size: 42, Mode: 0755}}})
	payload, _ := json.Marshal(packprotocol.CatalogPayload{Publisher: "fixture-publisher", PackID: id, Version: "1.0.0", OS: "linux", Arch: "amd64", Sequence: sequence, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), ManifestSHA256: sha256Hex(string(manifest)), ArtifactSHA256: artifact, ArtifactSize: 100, ArtifactURL: "https://fixture-packs.invalid/archive.tgz"})
	signature := ed25519.Sign(private, append([]byte(packprotocol.CatalogSignatureDomain), payload...))
	envelope, _ := json.Marshal(packprotocol.CatalogEnvelope{Schema: "acornfox-pack-catalog-envelope-v1", Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(signature)})
	selected, err := packprotocol.VerifySelection(envelope, manifest, packprotocol.VerificationPolicy{Publisher: "fixture-publisher", PublicKey: public, AllowedHosts: []string{"fixture-packs.invalid"}, CoreVersion: "1.0.0", ProtocolVersion: "1.0", OS: "linux", Arch: "amd64", InstallationBinding: binding, Now: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return selected
}
func packRequest(id, key string, selection packprotocol.VerifiedPackSelection) contracts.PlanPackInstallRecord {
	return contracts.PlanPackInstallRecord{Intent: contracts.PackInstallIntent{PackID: id, Version: "1.0.0", OS: "linux", Arch: "amd64", IdempotencyKey: key}, Selection: selection, Audit: contracts.AuditContext{ActorType: "system", ActorID: "pack-manager", Reason: "trusted planned installation intent"}}
}
func TestPackInstallAtomicIntentReplayFloorAndReopen(t *testing.T) {
	ctx := context.Background()
	dir := secureTestDir(t, "tc2a-pack")
	cfg := Config{DataDirectory: dir, PackCoreVersion: "1.0.0", PackProtocolVersion: "1.0"}
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	binding, _ := s.InstallationBinding(ctx)
	selection := fixtureSelection(t, s, "fixture-echo", 3, strings.Repeat("b", 64))
	request := packRequest("fixture-echo", "install-key", selection)
	result, err := s.PlanPackInstall(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE pack_install_intents SET version='forged' WHERE operation_id=?`, `UPDATE pack_install_intents SET selected_identity='{}' WHERE operation_id=?`, `DELETE FROM pack_install_intents WHERE operation_id=?`} {
		if _, err := s.db.Exec(q, result.OperationID); err == nil {
			t.Fatal("frozen pack intent mutable")
		}
	}
	var apps, envs int
	s.db.QueryRow(`SELECT count(*) FROM applications`).Scan(&apps)
	s.db.QueryRow(`SELECT count(*) FROM environments`).Scan(&envs)
	if apps != 0 || envs != 0 || result.State != "planned" {
		t.Fatal("package intent fabricated application/installed facts")
	}
	// No fresh selection/policy is needed for a completed idempotent response.
	replay, err := s.PlanPackInstall(ctx, packRequest("fixture-echo", "install-key", packprotocol.VerifiedPackSelection{}))
	if err != nil || replay != result {
		t.Fatalf("completed replay %+v %v", replay, err)
	}
	conflict := request
	conflict.Intent.Version = "2.0.0"
	if _, err := s.PlanPackInstall(ctx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different request not conflicted %v", err)
	}
	next := packRequest("fixture-echo", "busy", fixtureSelection(t, s, "fixture-echo", 4, strings.Repeat("c", 64)))
	if _, err := s.PlanPackInstall(ctx, next); !errors.Is(err, ErrPackBusy) {
		t.Fatalf("pending package did not serialize %v", err)
	}
	if _, err := s.db.Exec(`UPDATE operations SET state='cancelled' WHERE id=?`, result.OperationID); err != nil {
		t.Fatal(err)
	} // fixture-only future terminal history
	low := packRequest("fixture-echo", "low", fixtureSelection(t, s, "fixture-echo", 2, strings.Repeat("b", 64)))
	if _, err := s.PlanPackInstall(ctx, low); err == nil {
		t.Fatal("catalog floor rollback accepted")
	}
	equivocal := packRequest("fixture-echo", "equivocal", fixtureSelection(t, s, "fixture-echo", 3, strings.Repeat("d", 64)))
	if _, err := s.PlanPackInstall(ctx, equivocal); err == nil {
		t.Fatal("catalog same-sequence equivocation accepted")
	}
	// Competing different keys create one authoritative nonterminal operation.
	raceSelection := fixtureSelection(t, s, "fixture-race", 1, strings.Repeat("b", 64))
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted, busy := 0, 0
	for _, key := range []string{"race-a", "race-b"} {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			_, err := s.PlanPackInstall(ctx, packRequest("fixture-race", key, raceSelection))
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				accepted++
			} else if errors.Is(err, ErrPackBusy) {
				busy++
			} else {
				t.Error(err)
			}
		}(key)
	}
	wg.Wait()
	if accepted != 1 || busy != 1 {
		t.Fatalf("race accepted/busy %d/%d", accepted, busy)
	}
	counts := map[string]int{}
	for _, table := range []string{"pack_records", "operations", "pack_install_intents", "task_leases", "outbox_events", "audit_evidence", "idempotency_records"} {
		var n int
		if s.db.QueryRow(`SELECT count(*) FROM `+table).Scan(&n) != nil {
			t.Fatal("count failed")
		}
		counts[table] = n
	}
	failedRequest := packRequest("fixture-rollback", "rollback", fixtureSelection(t, s, "fixture-rollback", 1, strings.Repeat("b", 64)))
	if _, err := s.db.Exec(`CREATE TRIGGER reject_pack_audit BEFORE INSERT ON audit_evidence BEGIN SELECT RAISE(ABORT,'fixture audit rejected'); END;`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PlanPackInstall(ctx, failedRequest); err == nil {
		t.Fatal("audit fault accepted")
	}
	for table, want := range counts {
		var n int
		s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n)
		if n != want {
			t.Fatalf("partial %s %d want%d", table, n, want)
		}
	}
	s.db.Exec(`DROP TRIGGER reject_pack_audit`)
	if _, err := s.PlanPackInstall(ctx, failedRequest); err != nil {
		t.Fatal(err)
	}
	app := taskFixture(t, s, "application-still-real", time.Now().UTC())
	events, err := s.ListEvents(ctx, contracts.EventFilter{})
	if err != nil || len(events) != 1 || events[0].ID != app.Event.ID || events[0].Sequence <= result.Event.Sequence {
		t.Fatalf("app event stream parsed pack payload %+v %v", events, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after, _ := reopened.InstallationBinding(ctx)
	if after != binding {
		t.Fatal("public binding regenerated")
	}
	if _, err := reopened.PlanPackInstall(ctx, packRequest("fixture-echo", "install-key", packprotocol.VerifiedPackSelection{})); err != nil {
		t.Fatal("missing compatibility config blocked completed replay")
	}
	if _, err := reopened.db.Exec(`DELETE FROM core_installation`); err != nil {
		t.Fatal(err)
	}
	reopened.Close()
	if bad, err := Open(cfg); err == nil {
		bad.Close()
		t.Fatal("missing binding silently regenerated")
	}
}

type failedFKIterator struct{}

func (failedFKIterator) Next() bool   { return false }
func (failedFKIterator) Err() error   { return errors.New("fixture iteration failed") }
func (failedFKIterator) Close() error { return nil }
func TestPackMigrationFrozen0004HistoryFailureRetryAndFK(t *testing.T) {
	if violation, err := foreignKeyCheckResult(failedFKIterator{}); violation || err == nil {
		t.Fatal("FK iterator error certified success")
	}
	ctx := context.Background()
	dir := secureTestDir(t, "tc2a-upgrade")
	path := filepath.Join(dir, "acornfox.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if _, err := db.Exec(ownedSchemaDefinitions[0].sql + authMigrationSQL() + applicationMigrationSQL() + taskMigrationSQL() + auditMigrationSQL()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	frozen := map[string]string{version0001_admin_auth: accepted0001Checksum, version0002_application_repository: accepted0002Checksum, version0003_task_fencing: "78dd09154900c633d56f3ade93220680c20106d8f61ca40e7b27934c3511f877", version0004_audit_evidence: "a1566d9095b59aa5755994b64a2d0c779d423aa5124b4611510f6f80f36431e8"}
	for v, c := range frozen {
		if _, err := db.Exec(`INSERT INTO _schema_migrations VALUES(?,?,?)`, v, c, FormatTime(now)); err != nil {
			t.Fatal(err)
		}
	}
	legacy := &Store{db: db}
	original := taskFixture(t, legacy, "frozen-real-application", now)
	var beforeResponse string
	if db.QueryRow(`SELECT response FROM idempotency_records WHERE idempotency_key='frozen-real-application'`).Scan(&beforeResponse) != nil {
		t.Fatal("response seed missing")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyPackMigration(ctx, tx, func() error { return errors.New("midway fixture failure") }); err == nil {
		t.Fatal("midway failure missing")
	}
	tx.Rollback()
	conn.ExecContext(ctx, `PRAGMA foreign_keys=ON`)
	var fk int
	conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk)
	conn.Close()
	if fk != 1 {
		t.Fatal("failure did not restore FK")
	}
	var partial int
	db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name IN ('new_operations','pack_records','core_installation')`).Scan(&partial)
	if partial != 0 {
		t.Fatal("migration failure left partial schema")
	}
	db.Close()
	if os.Chmod(path, 0600) != nil {
		t.Fatal("fixture chmod")
	}
	upgraded, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	var response string
	upgraded.db.QueryRow(`SELECT response FROM idempotency_records WHERE idempotency_key='frozen-real-application'`).Scan(&response)
	if response != beforeResponse {
		t.Fatal("historical response bytes changed")
	}
	upgraded.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk)
	if fk != 1 {
		t.Fatal("successful migration left FK off")
	}
	task, err := upgraded.db.Query(`PRAGMA foreign_key_list(task_leases)`)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for task.Next() {
		var id, seq int
		var table, from, to, onUpdate, onDelete, match string
		if task.Scan(&id, &seq, &table, &from, &to, &onUpdate, &onDelete, &match) != nil {
			t.Fatal("fk scan")
		}
		if table == "operations" && from == "operation_id" {
			found = true
		}
	}
	task.Close()
	if !found {
		t.Fatal("task FK retargeted to temporary parent")
	}
	for v, c := range frozen {
		var actual string
		upgraded.db.QueryRow(`SELECT checksum FROM _schema_migrations WHERE version=?`, v).Scan(&actual)
		if actual != c {
			t.Fatal("frozen checksum changed")
		}
	}
	for _, q := range []string{`UPDATE operations SET target_kind='pack' WHERE id=?`, `UPDATE operations SET pack_id='missing' WHERE id=?`, `UPDATE operations SET application_id=NULL WHERE id=?`} {
		if _, err := upgraded.db.Exec(q, original.OperationID.String()); err == nil {
			t.Fatal("invalid app/pack target accepted")
		}
	}
	var taskCount, eventCount, auditCount int
	upgraded.db.QueryRow(`SELECT count(*) FROM task_leases WHERE operation_id=?`, original.OperationID.String()).Scan(&taskCount)
	upgraded.db.QueryRow(`SELECT count(*) FROM outbox_events WHERE id=?`, original.Event.ID).Scan(&eventCount)
	upgraded.db.QueryRow(`SELECT count(*) FROM audit_evidence`).Scan(&auditCount)
	if taskCount != 1 || eventCount != 1 || auditCount != 1 {
		t.Fatal("historical fact references lost")
	}
}

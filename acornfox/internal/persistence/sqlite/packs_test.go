package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	contracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/packprotocol"
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

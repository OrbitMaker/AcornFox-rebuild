package sqlite

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	contracts "github.com/acornfox/acornfox/internal/application/contracts"
)

// Literal vector independently calculated with Python hashlib, not this writer.
const auditVectorHash = "sha256:09e34f90893e422c9828b5a7b310007a960d090bfcadf1f896413fb6a8c1c474"
const auditVectorCanonical = `{"hash_scheme":"acornfox-audit-v1","id":"audit_vector","sequence":1,"actor_type":"system","actor_id":"application-controller","action":"application.created","reason":"verified internal command password=[REDACTED]","input_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","result":"accepted","evidence_refs":[],"previous_hash":null,"created_at":"2026-09-26T00:00:00.000000000Z"}`

func TestSQLiteAuditVectorChainLegacyImmutabilityAndReopen(t *testing.T) {
	ctx := context.Background()
	s, dir := newTestSQLiteStore(t)
	at := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	vector, err := appendAuditTx(ctx, tx, auditInput{ID: "audit_vector", Actor: contracts.AuditContext{ActorType: "system", ActorID: "application-controller", Reason: "verified internal command password=vectorsecret"}, Action: "application.created", InputDigest: "sha256:" + strings.Repeat("a", 64), Result: "accepted", CreatedAt: at})
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	bytes, err := auditCanonicalBytes(vector)
	if err != nil || string(bytes) != auditVectorCanonical || vector.RecordHash != auditVectorHash || vector.PreviousHash != nil || vector.EvidenceRefs == nil {
		tx.Rollback()
		t.Fatalf("independent vector mismatch %s %+v %v", bytes, vector, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	created := taskFixture(t, s, "audited-create", at.Add(time.Second))
	rows, err := s.ListAuditEvidence(ctx, contracts.AuditFilter{})
	if err != nil || len(rows) != 2 || rows[1].Action != "application.created" || rows[1].Result != "accepted" || rows[1].ActorID != "application-controller" || *rows[1].PreviousHash != vector.RecordHash {
		t.Fatalf("chain %+v %v", rows, err)
	}
	var safeRefs []string
	if err := json.Unmarshal(rows[1].EvidenceRefs, &safeRefs); err != nil {
		t.Fatal(err)
	}
	if len(safeRefs) != 4 || safeRefs[0] != created.Application.ID.String() || safeRefs[1] != created.OperationID.String() || safeRefs[3] != created.Event.ID {
		t.Fatalf("safe refs %+v", rows[1])
	}
	if _, err := s.db.Exec(`UPDATE audit_evidence SET reason='changed' WHERE id=?`, vector.ID); err == nil {
		t.Fatal("audit mutable")
	}
	if _, err := s.db.Exec(`DELETE FROM audit_evidence WHERE id=?`, vector.ID); err == nil {
		t.Fatal("audit deletable")
	}
	if _, err := s.db.Exec(`INSERT INTO audit_evidence(id,sequence,actor_type,actor_id,action,reason,input_digest,result,evidence_refs,previous_hash,record_hash,hash_scheme,created_at) VALUES('audit_badhead',3,'system','fixture','x','','','recorded','[]',NULL,'wrong','legacy-pg-unclassified','2020-01-01T00:00:00Z')`); err == nil {
		t.Fatal("chain head mismatch accepted")
	}
	// Lease heartbeat and outbox publication do not manufacture business audit facts.
	task := mustClaim(t, s, claimRequest(at.Add(time.Minute), 3))
	if err := s.RenewTask(ctx, mutation(task, at.Add(time.Minute+time.Second))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkOutboxPublished(ctx, created.Event.ID, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	after, err := s.ListAuditEvidence(ctx, contracts.AuditFilter{})
	if err != nil || len(after) != 2 {
		t.Fatal("heartbeat/publication inflated audit")
	}
	s.Close()
	reopened, err := Open(Config{DataDirectory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	taskFixture(t, reopened, "audited-after-reopen", at.Add(2*time.Minute))
	continued, err := reopened.ListAuditEvidence(ctx, contracts.AuditFilter{AfterSequence: 2, Limit: 1})
	if err != nil || len(continued) != 1 || continued[0].Sequence != 3 || *continued[0].PreviousHash != rows[1].RecordHash {
		t.Fatalf("reopen continuation %+v %v", continued, err)
	}

	t.Run("legacy-source-manifest-and-linkage-only", func(t *testing.T) {
		legacy, _ := newTestSQLiteStore(t)
		oldHash1 := "sha256:" + strings.Repeat("1", 64)
		oldHash2 := "sha256:" + strings.Repeat("2", 64)
		manifest := []contracts.AuditEvidence{
			{ID: "audit_legacy1", Sequence: 40, ActorType: "system", ActorID: "release-controller", Action: "historical.delivery", Reason: "preserved reason", InputDigest: "historical-payload-digest", Result: "recorded", EvidenceRefs: json.RawMessage(`[]`), RecordHash: oldHash1, HashScheme: "legacy-pg-m1", CreatedAt: "2025-08-09T10:11:12.123456+02:00"},
			{ID: "audit_legacy2", Sequence: 44, ActorType: "admin", ActorID: "admin_original", Action: "historical.unknown", Reason: "preserved serving producer", InputDigest: "old-input-digest", Result: "recorded", EvidenceRefs: json.RawMessage(`[ {"id":"evidence_old", "kind":"probe", "digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "locator":"evidence://old-serving"} ]`), PreviousHash: &oldHash1, RecordHash: oldHash2, HashScheme: "legacy-pg-serving", CreatedAt: "2025-08-09T10:11:13.123456789+02:00"},
		}
		// Fixed source-manifest fixture; old hashes are provenance, not recomputed here.
		for _, e := range manifest {
			if _, err := legacy.db.Exec(`INSERT INTO audit_evidence(id,sequence,actor_type,actor_id,action,reason,input_digest,result,evidence_refs,previous_hash,record_hash,hash_scheme,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, e.ID, e.Sequence, e.ActorType, e.ActorID, e.Action, e.Reason, e.InputDigest, e.Result, string(e.EvidenceRefs), e.PreviousHash, e.RecordHash, e.HashScheme, e.CreatedAt); err != nil {
				t.Fatal(err)
			}
		}
		copied, err := legacy.ListAuditEvidence(ctx, contracts.AuditFilter{})
		if err != nil || !reflect.DeepEqual(copied, manifest) {
			t.Fatalf("legacy fields normalized %+v %v", copied, err)
		}
		taskFixture(t, legacy, "new-after-legacy", at)
		next, err := legacy.ListAuditEvidence(ctx, contracts.AuditFilter{AfterSequence: 44})
		if err != nil || len(next) != 1 || next[0].Sequence != 45 || *next[0].PreviousHash != oldHash2 || next[0].HashScheme != auditV1 {
			t.Fatalf("legacy continuation %+v %v", next, err)
		}
		unchanged, err := legacy.ListAuditEvidence(ctx, contracts.AuditFilter{Limit: 2})
		if err != nil || !reflect.DeepEqual(unchanged, manifest) {
			t.Fatalf("legacy history changed %+v %v", unchanged, err)
		}
	})
}

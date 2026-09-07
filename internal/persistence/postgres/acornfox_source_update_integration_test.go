//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
)

func TestAcornFoxSourceUpdateSessionFenceAndDeadWriterRecovery(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_SOURCE_METADATA_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_SOURCE_METADATA_TEST_DATABASE_URL is required")
	}
	expected := validateAcornFoxSourceMetadataDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	resetAcornFoxSourceMetadataSchema(t, ctx, db, expected)
	applyControlPlaneMigrations(t, ctx, db)
	now := time.Unix(1700600000, 0).UTC()
	for _, q := range []string{`INSERT INTO applications(id,name,created_at,updated_at) VALUES('app_update','update',$1,$1)`, `INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,git_commit,content_digest,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES('src_update','app_update','git','git_https','https://github.com/acme/update.git','main','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','/private/update','prepared',true,$1)`, `INSERT INTO acornfox_source_metadata(source_revision_id,repository_url,accepted_at) VALUES('src_update','https://github.com/acme/update.git',$1)`} {
		if _, err := db.ExecContext(ctx, q, now); err != nil {
			t.Fatal(err)
		}
	}
	storeOne, storeTwo := NewStore(db), NewStore(db)
	first := application.AcornFoxSourceUpdateRequest{ApplicationID: "app_update", BaseSourceRevisionID: "src_update", Ref: "main", IdempotencyKey: "one"}
	d1 := sourceUpdateTestDigest(first)
	_, lease, err := storeOne.AcquireAcornFoxSourceUpdate(ctx, first, d1, now)
	if err != nil || lease == nil {
		t.Fatalf("first lease=%v err=%v", lease, err)
	}
	second := first
	second.IdempotencyKey = "two"
	if _, _, err := storeTwo.AcquireAcornFoxSourceUpdate(ctx, second, sourceUpdateTestDigest(second), now); !errors.Is(err, application.ErrAcornFoxSourceUpdateInProgress) {
		t.Fatalf("second live writer err=%v", err)
	}
	if err := storeTwo.RecoverAcornFoxSourceUpdates(ctx, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := db.QueryRowContext(ctx, `SELECT state FROM acornfox_source_updates WHERE application_id='app_update' AND idempotency_key='one'`).Scan(&state); err != nil || state != "preparing" {
		t.Fatalf("live lease was recovered state=%q err=%v", state, err)
	}
	if err := lease.(*acornFoxSourceUpdateLease).conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := storeTwo.RecoverAcornFoxSourceUpdates(ctx, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := storeTwo.AcquireAcornFoxSourceUpdate(ctx, first, d1, now); !errors.Is(err, application.ErrAcornFoxSourceUpdateUnknown) {
		t.Fatalf("old key after recovery err=%v", err)
	}
	_, fresh, err := storeTwo.AcquireAcornFoxSourceUpdate(ctx, second, sourceUpdateTestDigest(second), now.Add(3*time.Second))
	if err != nil || fresh == nil {
		t.Fatalf("new key after recovery lease=%v err=%v", fresh, err)
	}
	revision := domain.SourceRevision{
		ID: "src_updated_public", ApplicationID: "app_update", Kind: domain.SourceGitHTTPS,
		Locator: "https://github.com/acme/update.git", Ref: "main", Commit: strings.Repeat("c", 40),
		ContentDigest: "sha256:" + strings.Repeat("d", 64), WorkspaceRef: "/private/update/new",
		Immutable: true, CreatedAt: now.Add(4 * time.Second),
	}
	if _, err := storeTwo.CompleteAcornFoxSourceUpdate(ctx, fresh, second, sourceUpdateTestDigest(second), revision, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	storeTwo.ReleaseAcornFoxSourceUpdate(ctx, fresh)
	page, err := storeTwo.ListAcornFoxSourceRevisions(ctx, "app_update", nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	visible := false
	for _, source := range page.Items {
		visible = visible || source.ID == revision.ID
	}
	if !visible {
		t.Fatal("completed public source update is missing from normal source discovery")
	}
	loaded, err := storeTwo.GetAcornFoxSourceRevision(ctx, "app_update", revision.ID)
	if err != nil || loaded.Commit != revision.Commit {
		t.Fatalf("updated source cannot be read for deployment: %v", err)
	}
	if _, err := storeTwo.GetAcornFoxSourceRevision(ctx, "app_foreign", revision.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign application source read: %v", err)
	}
}
func sourceUpdateTestDigest(r application.AcornFoxSourceUpdateRequest) string {
	sum := sha256.Sum256([]byte(r.ApplicationID.String() + "\x00" + r.BaseSourceRevisionID.String() + "\x00" + r.Ref))
	return "sha256:" + hex.EncodeToString(sum[:])
}

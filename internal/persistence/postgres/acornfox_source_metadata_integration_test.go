//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
)

func TestAcornFoxSourceMetadataUsesExplicitProvenanceAndExactReleaseBuildSource(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_SOURCE_METADATA_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_SOURCE_METADATA_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	expected := validateAcornFoxSourceMetadataDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	resetAcornFoxSourceMetadataSchema(t, ctx, db, expected)
	applyControlPlaneMigrations(t, ctx, db)
	applyAcornFoxSourceMetadataMigration(t, ctx, db)

	now := time.Unix(1_700_300_000, 0).UTC()
	seedAcornFoxSourceMetadataFacts(t, ctx, db, now)
	store := NewStore(db)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAcornFoxPublicSourceProvenanceTx(ctx, tx, contracts.AcornFoxPublicSourceProvenance{SourceRevisionID: "src_source_meta_public", RepositoryURL: "https://github.com/acme/public.git"}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := store.RecordAcornFoxPublicSourceProvenanceTx(ctx, tx, contracts.AcornFoxPublicSourceProvenance{SourceRevisionID: "src_source_meta_latest", RepositoryURL: "https://github.com/acme/latest.git"}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// The source and its public claim are meant to be created in one caller
	// transaction. A rollback must leave neither an exposed claim nor a source
	// that could later be mistaken for a completed public ingest.
	atomicTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := atomicTx.ExecContext(ctx, `INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,git_commit,content_digest,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES('src_source_meta_rolled_back','app_source_meta','git','git_https','https://github.com/acme/rolled-back.git','main',$1,$2,'/private/rolled-back','prepared',true,$3)`, strings.Repeat("f", 40), "sha256:"+strings.Repeat("b", 64), now); err != nil {
		atomicTx.Rollback()
		t.Fatal(err)
	}
	if err := store.RecordAcornFoxPublicSourceProvenanceTx(ctx, atomicTx, contracts.AcornFoxPublicSourceProvenance{SourceRevisionID: "src_source_meta_rolled_back", RepositoryURL: "https://github.com/acme/rolled-back.git"}); err != nil {
		atomicTx.Rollback()
		t.Fatal(err)
	}
	if err := atomicTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAcornFoxSourceMetadata(ctx, "app_source_meta", "src_source_meta_rolled_back"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rolled-back source metadata err=%v", err)
	}

	old, err := store.GetAcornFoxSourceMetadata(ctx, "app_source_meta", "src_source_meta_old")
	if err != nil || old.Availability != contracts.AcornFoxUnavailable || old.RepositoryURL != "" {
		t.Fatalf("historical private locator projection=%+v err=%v", old, err)
	}
	oldJSON, err := json.Marshal(old)
	if err != nil || strings.Contains(string(oldJSON), "private.example") || strings.Contains(string(oldJSON), "token") {
		t.Fatalf("historical metadata leaked locator=%s err=%v", oldJSON, err)
	}
	public, err := store.GetAcornFoxSourceMetadata(ctx, "app_source_meta", "src_source_meta_public")
	if err != nil || public.Availability != contracts.AcornFoxAvailable || public.RepositoryURL != "https://github.com/acme/public.git" {
		t.Fatalf("explicit public metadata=%+v err=%v", public, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE acornfox_source_metadata SET repository_url='https://github.com/acme/changed.git' WHERE source_revision_id='src_source_meta_public'`); err == nil {
		t.Fatal("source metadata UPDATE was accepted")
	}

	exact, err := store.GetAcornFoxDeploymentSource(ctx, "app_source_meta", "dep_source_meta_good")
	if err != nil || exact.Availability != contracts.AcornFoxAvailable || exact.SourceRevisionID != "src_source_meta_public" || exact.RepositoryURL != "https://github.com/acme/public.git" || exact.Commit != strings.Repeat("a", 40) || exact.Ref != "main" {
		t.Fatalf("exact deployment source=%+v err=%v", exact, err)
	}

	// An unfinished second artifact is incomplete history, even when the
	// first artifact is a valid successful build of this source.
	for _, statement := range []string{
		`INSERT INTO builds(id,plan_id,state,created_at,updated_at) VALUES('build_source_meta_pending','plan_source_meta_good','running',now(),now())`,
		`INSERT INTO artifacts(id,build_id,image_repository,image_digest,oci_storage_ref,size_bytes,created_at) VALUES('artifact_source_meta_pending','build_source_meta_pending','registry.example/source-meta','sha256:` + strings.Repeat("3", 64) + `','oci://source-meta/pending',1,now())`,
		`INSERT INTO release_artifacts(release_id,service_name,artifact_id) VALUES('rel_source_meta_good','pending','artifact_source_meta_pending')`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	incomplete, err := store.GetAcornFoxDeploymentSource(ctx, "app_source_meta", "dep_source_meta_good")
	if err != nil || incomplete.Availability != contracts.AcornFoxUnavailable {
		t.Fatalf("incomplete release history=%+v err=%v", incomplete, err)
	}
	ambiguous, err := store.GetAcornFoxDeploymentSource(ctx, "app_source_meta", "dep_source_meta_ambiguous")
	if err != nil || ambiguous.Availability != contracts.AcornFoxUnavailable || !ambiguous.SourceRevisionID.Empty() {
		t.Fatalf("ambiguous deployment source=%+v err=%v", ambiguous, err)
	}
	if _, err := store.GetAcornFoxDeploymentSource(ctx, "app_source_meta_other", "dep_source_meta_good"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign deployment err=%v", err)
	}
	if _, err := store.GetAcornFoxSourceMetadata(ctx, "app_source_meta_other", "src_source_meta_public"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign source err=%v", err)
	}

	if _, err := db.ExecContext(ctx, `CREATE OR REPLACE FUNCTION acornfox_source_metadata_test_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'metadata write rejected'; END $$; CREATE TRIGGER acornfox_source_metadata_test_reject BEFORE INSERT ON acornfox_source_metadata FOR EACH ROW EXECUTE FUNCTION acornfox_source_metadata_test_reject()`); err != nil {
		t.Fatal(err)
	}
	controller := application.NewController(store)
	controller.SetSourcePreparer(&postgresGitSourcePreparer{})
	_, err = controller.CreateApplicationWithSource(ctx, "must roll back", &application.CreateApplicationSource{Kind: application.CreateApplicationSourceGit, RepositoryURL: "https://github.com/acme/transaction-failure.git", Ref: "main", PublicGit: true}, "source-metadata-transaction-failure")
	if err == nil || !strings.Contains(err.Error(), "metadata write rejected") {
		t.Fatalf("metadata failure err=%v", err)
	}
	for name, query := range map[string]string{
		"application":       `SELECT count(*) FROM applications WHERE name='must roll back'`,
		"source_revision":   `SELECT count(*) FROM source_revisions WHERE locator='https://github.com/acme/transaction-failure.git'`,
		"source_provenance": `SELECT count(*) FROM acornfox_source_metadata WHERE repository_url='https://github.com/acme/transaction-failure.git'`,
	} {
		var count int
		if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed provenance transaction left %s count=%d err=%v", name, count, err)
		}
	}
}

func validateAcornFoxSourceMetadataDSN(t *testing.T, dsn string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1" && parsed.Hostname() != "localhost") {
		t.Fatal("task-scoped AcornFox source metadata database URL is invalid")
	}
	database := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if database == "" || strings.Contains(database, "/") || !strings.HasPrefix(database, "open_card_afbsourcemeta_") {
		t.Fatal("task-scoped AcornFox source metadata database name is invalid")
	}
	return database
}

func resetAcornFoxSourceMetadataSchema(t *testing.T, ctx context.Context, db *sql.DB, expected string) {
	t.Helper()
	var current string
	if err := db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&current); err != nil || current != expected {
		t.Fatal("connected database does not match validated source metadata database")
	}
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
}

func applyAcornFoxSourceMetadataMigration(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "migrations", "control-plane", "0035_acornfox_source_metadata.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(raw)); err != nil {
		t.Fatal(err)
	}
}

func seedAcornFoxSourceMetadataFacts(t *testing.T, ctx context.Context, db *sql.DB, now time.Time) {
	t.Helper()
	digest := "sha256:" + strings.Repeat("b", 64)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name,created_at,updated_at) VALUES('app_source_meta','source metadata',$1,$1),('app_source_meta_other','other',$1,$1)`, []any{now}},
		{`INSERT INTO environments(id,application_id,name,created_at) VALUES('env_source_meta','app_source_meta','default',$1)`, []any{now}},
		{`INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,git_commit,content_digest,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES
			('src_source_meta_old','app_source_meta','git','git_https','https://private.example/repo.git?token=old','main',$1,$2,'/private/old','prepared',true,$3),
			('src_source_meta_public','app_source_meta','git','git_https','https://github.com/acme/public.git','main',$4,$2,'/private/public','prepared',true,$3),
			('src_source_meta_latest','app_source_meta','git','git_https','https://github.com/acme/latest.git','latest',$5,$2,'/private/latest','prepared',true,$3)`, []any{strings.Repeat("c", 40), digest, now, strings.Repeat("a", 40), strings.Repeat("d", 40)}},
		{`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration,created_at) VALUES
			('def_source_meta_good','app_source_meta','src_source_meta_public',1,'{}'::jsonb,$1),
			('def_source_meta_ambiguous','app_source_meta','src_source_meta_public',2,'{}'::jsonb,$1)`, []any{now}},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests,created_at) VALUES
			('rel_source_meta_good','app_source_meta','def_source_meta_good',1,jsonb_build_object('web',$1::text),$2),
			('rel_source_meta_ambiguous','app_source_meta','def_source_meta_ambiguous',2,jsonb_build_object('web',$1::text,'worker',$3::text),$2)`, []any{"sha256:" + strings.Repeat("e", 64), now, "sha256:" + strings.Repeat("f", 64)}},
		{`INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) VALUES
			('dep_source_meta_good','env_source_meta','rel_source_meta_good','runtime_ready',$1,$1),
			('dep_source_meta_ambiguous','env_source_meta','rel_source_meta_ambiguous','runtime_ready',$1,$1)`, []any{now}},
		{`INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,dockerfile_path,target_repository,output_contract,secret_refs,idempotency_key,created_at) VALUES
			('plan_source_meta_good','src_source_meta_public',$1,'web','dockerfile','.','Dockerfile','registry.example/source-meta','{"format":"oci","retention":"persistent","storage_key":"source-meta/good"}'::jsonb,'[]'::jsonb,'source-meta-good',$2),
			('plan_source_meta_latest','src_source_meta_latest',$1,'worker','dockerfile','.','Dockerfile','registry.example/source-meta','{"format":"oci","retention":"persistent","storage_key":"source-meta/latest"}'::jsonb,'[]'::jsonb,'source-meta-latest',$2)`, []any{digest, now}},
		{`INSERT INTO builds(id,plan_id,state,created_at,updated_at) VALUES
			('build_source_meta_good','plan_source_meta_good','running',$1,$1),
			('build_source_meta_latest','plan_source_meta_latest','running',$1,$1)`, []any{now}},
		{`INSERT INTO artifacts(id,build_id,image_repository,image_digest,oci_storage_ref,size_bytes,created_at) VALUES
			('artifact_source_meta_good','build_source_meta_good','registry.example/source-meta','sha256:` + strings.Repeat("1", 64) + `','oci://source-meta/good',1,$1),
			('artifact_source_meta_latest','build_source_meta_latest','registry.example/source-meta','sha256:` + strings.Repeat("2", 64) + `','oci://source-meta/latest',1,$1)`, []any{now}},
		{`UPDATE builds SET state='succeeded', artifact_id=CASE id WHEN 'build_source_meta_good' THEN 'artifact_source_meta_good' WHEN 'build_source_meta_latest' THEN 'artifact_source_meta_latest' END WHERE id IN ('build_source_meta_good','build_source_meta_latest')`, nil},
		{`INSERT INTO release_artifacts(release_id,service_name,artifact_id) VALUES
			('rel_source_meta_good','web','artifact_source_meta_good'),
			('rel_source_meta_ambiguous','web','artifact_source_meta_good'),
			('rel_source_meta_ambiguous','worker','artifact_source_meta_latest')`, nil},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

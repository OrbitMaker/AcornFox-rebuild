//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-card/open-card/internal/domain"
)

func TestAcornFoxBuildPlanBindingRoundTripsOnTaskScopedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_BUILD_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_BUILD_TEST_DATABASE_URL is required for task-scoped PostgreSQL")
	}
	expectedDatabase := validateAcornFoxBuildPlanTestDSN(t, dsn)
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
	resetAcornFoxBuildPlanTestSchema(t, ctx, db, expectedDatabase)
	applyControlPlaneMigrations(t, ctx, db)
	assertAcornFoxBuildPlanMigrationsIdempotent(t, ctx, db)

	now := time.Unix(1_700_000_000, 0).UTC()
	source := domain.ID("src_afb_build")
	sourceDigest := "sha256:" + strings.Repeat("a", 64)
	if _, err := db.ExecContext(ctx, `INSERT INTO applications(id,name,created_at,updated_at) VALUES ('app_afb_build','AcornFox build binding',$1,$1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO source_revisions(id,application_id,provider,source_kind,locator,source_ref,content_digest,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES ($1,'app_afb_build','upload','upload','upload://afb-build','main',$2,'/var/lib/open-card/afb-build','prepared',true,$3)`, source.String(), sourceDigest, now); err != nil {
		t.Fatal(err)
	}

	store := NewStore(db)
	legacy := acornFoxBuildPlan("plan_afb_legacy", source, sourceDigest, "legacy", "build-afb-legacy", now)
	persistedLegacy, err := store.CreateBuildPlan(ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if persistedLegacy.AcornFoxDefinitionDigest != "" || persistedLegacy.AcornFoxDockerfileDigest != "" || persistedLegacy.AcornFoxNetworkMode != "" || persistedLegacy.AcornFoxWorkerPolicyDigest != "" {
		t.Fatalf("legacy plan unexpectedly bound: %+v", persistedLegacy)
	}
	loadedLegacy, err := store.GetBuildPlan(ctx, legacy.ID)
	if err != nil || loadedLegacy.AcornFoxDefinitionDigest != "" || loadedLegacy.AcornFoxDockerfileDigest != "" || loadedLegacy.AcornFoxNetworkMode != "" || loadedLegacy.AcornFoxWorkerPolicyDigest != "" {
		t.Fatalf("legacy roundtrip=%+v err=%v", loadedLegacy, err)
	}
	if mode, digest := loadedLegacy.EffectiveAcornFoxNetworkPolicy(); mode != "none" || digest != "" {
		t.Fatalf("legacy effective network identity = %q/%q", mode, digest)
	}

	bound := acornFoxBuildPlan("plan_afb_bound", source, sourceDigest, "bound", "build-afb-bound", now)
	bound.AcornFoxDefinitionDigest = "sha256:" + strings.Repeat("b", 64)
	bound.AcornFoxDockerfileDigest = "sha256:" + strings.Repeat("c", 64)
	bound.AcornFoxNetworkMode = "controlled_egress_v1"
	bound.AcornFoxWorkerPolicyDigest = "sha256:" + strings.Repeat("d", 64)
	persistedBound, err := store.CreateBuildPlan(ctx, bound)
	if err != nil {
		t.Fatal(err)
	}
	loadedBound, err := store.GetBuildPlan(ctx, bound.ID)
	if err != nil || loadedBound.ID != bound.ID || loadedBound.SourceRevisionID != bound.SourceRevisionID || loadedBound.SourceDigest != bound.SourceDigest || loadedBound.AcornFoxDefinitionDigest != bound.AcornFoxDefinitionDigest || loadedBound.AcornFoxDockerfileDigest != bound.AcornFoxDockerfileDigest || loadedBound.AcornFoxNetworkMode != bound.AcornFoxNetworkMode || loadedBound.AcornFoxWorkerPolicyDigest != bound.AcornFoxWorkerPolicyDigest {
		t.Fatalf("bound roundtrip persisted=%+v loaded=%+v err=%v", persistedBound, loadedBound, err)
	}
	replayed, err := store.CreateBuildPlan(ctx, bound)
	if err != nil || replayed.ID != loadedBound.ID || replayed.AcornFoxDefinitionDigest != loadedBound.AcornFoxDefinitionDigest || replayed.AcornFoxDockerfileDigest != loadedBound.AcornFoxDockerfileDigest || replayed.AcornFoxNetworkMode != loadedBound.AcornFoxNetworkMode || replayed.AcornFoxWorkerPolicyDigest != loadedBound.AcornFoxWorkerPolicyDigest {
		t.Fatalf("bound replay=%+v err=%v", replayed, err)
	}
	changedNetwork := bound
	changedNetwork.AcornFoxNetworkMode = "none"
	changedNetwork.AcornFoxWorkerPolicyDigest = ""
	if _, err := store.CreateBuildPlan(ctx, changedNetwork); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed durable network policy replay err=%v, want idempotency conflict", err)
	}

	var legacyDefinition, legacyDockerfile, legacyMode, legacyPolicy, boundDefinition, boundDockerfile, boundMode, boundPolicy sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT acornfox_definition_digest,acornfox_dockerfile_digest,acornfox_network_mode,acornfox_worker_policy_digest FROM build_plans WHERE id=$1`, legacy.ID.String()).Scan(&legacyDefinition, &legacyDockerfile, &legacyMode, &legacyPolicy); err != nil || legacyDefinition.Valid || legacyDockerfile.Valid || legacyMode.Valid || legacyPolicy.Valid {
		t.Fatalf("legacy persisted binding definition=%+v dockerfile=%+v mode=%+v policy=%+v err=%v", legacyDefinition, legacyDockerfile, legacyMode, legacyPolicy, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT acornfox_definition_digest,acornfox_dockerfile_digest,acornfox_network_mode,acornfox_worker_policy_digest FROM build_plans WHERE id=$1`, bound.ID.String()).Scan(&boundDefinition, &boundDockerfile, &boundMode, &boundPolicy); err != nil || !boundDefinition.Valid || !boundDockerfile.Valid || !boundMode.Valid || !boundPolicy.Valid || boundDefinition.String != bound.AcornFoxDefinitionDigest || boundDockerfile.String != bound.AcornFoxDockerfileDigest || boundMode.String != bound.AcornFoxNetworkMode || boundPolicy.String != bound.AcornFoxWorkerPolicyDigest {
		t.Fatalf("bound persisted binding definition=%+v dockerfile=%+v mode=%+v policy=%+v err=%v", boundDefinition, boundDockerfile, boundMode, boundPolicy, err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,dockerfile_path,acornfox_definition_digest,target_repository,output_contract,secret_refs,idempotency_key,created_at)
		VALUES ('plan_afb_unpaired',$1,$2,'unpaired','dockerfile','.','Dockerfile',$3,'registry.example/open-card/unpaired','{"format":"oci","retention":"persistent","storage_key":"app_afb_build/unpaired"}'::jsonb,'[]'::jsonb,'build-afb-unpaired',$4)`, source.String(), sourceDigest, bound.AcornFoxDefinitionDigest, now); err == nil {
		t.Fatal("database accepted an unpaired AcornFox build-plan digest")
	}
	for _, variant := range []struct {
		name                string
		kind, context, path any
		staticRuntime       any
		output              string
	}{
		{name: "static", kind: "static", context: ".", path: nil, staticRuntime: "sha256:" + strings.Repeat("d", 64), output: `{"format":"oci","retention":"persistent","storage_key":"app_afb_build/static"}`},
		{name: "non_root_context", kind: "dockerfile", context: "service", path: "Dockerfile", staticRuntime: nil, output: `{"format":"oci","retention":"persistent","storage_key":"app_afb_build/context"}`},
		{name: "non_root_path", kind: "dockerfile", context: ".", path: "service/Dockerfile", staticRuntime: nil, output: `{"format":"oci","retention":"persistent","storage_key":"app_afb_build/path"}`},
		{name: "static_runtime", kind: "dockerfile", context: ".", path: "Dockerfile", staticRuntime: "sha256:" + strings.Repeat("d", 64), output: `{"format":"oci","retention":"persistent","storage_key":"app_afb_build/runtime"}`},
		{name: "non_persistent_output", kind: "dockerfile", context: ".", path: "Dockerfile", staticRuntime: nil, output: `{"format":"tar","retention":"ephemeral","storage_key":"app_afb_build/output"}`},
	} {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,dockerfile_path,static_runtime_digest,acornfox_definition_digest,acornfox_dockerfile_digest,target_repository,output_contract,secret_refs,idempotency_key,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'registry.example/open-card/rejected',$11::jsonb,'[]'::jsonb,$12,$13)`, "plan_afb_"+variant.name, source.String(), sourceDigest, variant.name, variant.kind, variant.context, variant.path, variant.staticRuntime, bound.AcornFoxDefinitionDigest, bound.AcornFoxDockerfileDigest, variant.output, "build-afb-"+variant.name, now); err == nil {
			t.Fatalf("database accepted bound AcornFox %s build plan", variant.name)
		}
	}
	for _, variant := range []struct {
		name, mode, workerPolicy, definition, dockerfile string
	}{
		{name: "network_unpaired", mode: "controlled_egress_v1", workerPolicy: bound.AcornFoxWorkerPolicyDigest},
		{name: "network_uppercase", mode: "controlled_egress_v1", workerPolicy: "sha256:" + strings.Repeat("D", 64), definition: bound.AcornFoxDefinitionDigest, dockerfile: bound.AcornFoxDockerfileDigest},
		{name: "offline_with_policy", mode: "none", workerPolicy: bound.AcornFoxWorkerPolicyDigest, definition: bound.AcornFoxDefinitionDigest, dockerfile: bound.AcornFoxDockerfileDigest},
	} {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,dockerfile_path,acornfox_definition_digest,acornfox_dockerfile_digest,acornfox_network_mode,acornfox_worker_policy_digest,target_repository,output_contract,secret_refs,idempotency_key,created_at)
			VALUES ($1,$2,$3,$4,'dockerfile','.','Dockerfile',NULLIF($5,''),NULLIF($6,''),$7,$8,'registry.example/open-card/rejected','{"format":"oci","retention":"persistent","storage_key":"app_afb_build/network"}'::jsonb,'[]'::jsonb,$9,$10)`, "plan_afb_"+variant.name, source.String(), sourceDigest, variant.name, variant.definition, variant.dockerfile, variant.mode, variant.workerPolicy, "build-afb-"+variant.name, now); err == nil {
			t.Fatalf("database accepted invalid AcornFox network policy %s", variant.name)
		}
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,dockerfile_path,acornfox_definition_digest,acornfox_dockerfile_digest,acornfox_network_mode,acornfox_worker_policy_digest,target_repository,output_contract,secret_refs,idempotency_key,created_at)
		VALUES ('plan_afb_network_null_policy',$1,$2,'network_null_policy','dockerfile','.','Dockerfile',$3,$4,'controlled_egress_v1',NULL,'registry.example/open-card/rejected','{"format":"oci","retention":"persistent","storage_key":"app_afb_build/network-null"}'::jsonb,'[]'::jsonb,'build-afb-network-null-policy',$5)`, source.String(), sourceDigest, bound.AcornFoxDefinitionDigest, bound.AcornFoxDockerfileDigest, now); err == nil {
		t.Fatal("database accepted controlled egress with a NULL worker policy digest")
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,dockerfile_path,acornfox_definition_digest,acornfox_dockerfile_digest,acornfox_network_mode,acornfox_worker_policy_digest,target_repository,output_contract,secret_refs,idempotency_key,created_at)
		VALUES ('plan_afb_null_network_mode',$1,$2,'null_network_mode','dockerfile','.','Dockerfile',$3,$4,NULL,$5,'registry.example/open-card/rejected','{"format":"oci","retention":"persistent","storage_key":"app_afb_build/null-mode"}'::jsonb,'[]'::jsonb,'build-afb-null-network-mode',$6)`, source.String(), sourceDigest, bound.AcornFoxDefinitionDigest, bound.AcornFoxDockerfileDigest, bound.AcornFoxWorkerPolicyDigest, now); err == nil {
		t.Fatal("database accepted a NULL network mode with a worker policy digest")
	}
}

func assertAcornFoxBuildPlanMigrationsIdempotent(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	for _, migration := range []string{"0025_acornfox_build_plan_binding.sql", "0026_acornfox_build_network_policy.sql"} {
		payload, err := os.ReadFile(filepath.Join("..", "..", "..", "migrations", "control-plane", migration))
		if err != nil {
			t.Fatal(err)
		}
		for run := 1; run <= 2; run++ {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.ExecContext(ctx, string(payload)); err != nil {
				_ = tx.Rollback()
				t.Fatalf("rerun %s migration %d: %v", migration[:4], run, err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatalf("commit rerun %s migration %d: %v", migration[:4], run, err)
			}
		}
	}
}

func acornFoxBuildPlan(id, sourceID domain.ID, sourceDigest, service, key string, now time.Time) domain.BuildPlan {
	return domain.BuildPlan{
		ID:               id,
		SourceRevisionID: sourceID,
		SourceDigest:     sourceDigest,
		ServiceName:      service,
		Kind:             domain.BuildDockerfile,
		ContextPath:      ".",
		DockerfilePath:   "Dockerfile",
		TargetRepository: "registry.example/open-card/" + service,
		Output:           domain.BuildOutputContract{Format: domain.BuildOutputOCI, Retention: domain.BuildRetentionPersist, StorageKey: "app_afb_build/" + service},
		IdempotencyKey:   key,
		CreatedAt:        now,
	}
}

func validateAcornFoxBuildPlanTestDSN(t *testing.T, dsn string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("task-scoped AcornFox build database URL is invalid")
	}
	if host := parsed.Hostname(); host != "127.0.0.1" && host != "::1" && host != "localhost" {
		t.Fatal("task-scoped AcornFox build database must be loopback-only")
	}
	database := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if database == "" || strings.Contains(database, "/") || !strings.HasPrefix(database, "open_card_afbbuild_") {
		t.Fatal("task-scoped AcornFox build database name must use open_card_afbbuild_ prefix")
	}
	return database
}

func resetAcornFoxBuildPlanTestSchema(t *testing.T, ctx context.Context, db *sql.DB, expectedDatabase string) {
	t.Helper()
	var currentDatabase string
	if err := db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&currentDatabase); err != nil || currentDatabase != expectedDatabase {
		t.Fatal("connected database does not match validated dedicated AcornFox build test database")
	}
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset validated dedicated AcornFox build test schema: %v", err)
	}
}

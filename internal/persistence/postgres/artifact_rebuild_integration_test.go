//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

func TestIndependentBuildsMayShareAnImageWithoutSharingEvidence(t *testing.T) {
	dsn := os.Getenv("OPEN_CARD_AFB_BUILD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL fixture required")
	}
	expected := validateAcornFoxBuildPlanTestDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	resetAcornFoxBuildPlanTestSchema(t, ctx, db, expected)
	applyControlPlaneMigrations(t, ctx, db)
	now := time.Now().UTC()
	insertAcornFoxDeliveryCommitFixture(t, ctx, db, now, "repeatimage")
	store := NewStore(db)
	image := domain.ImageDigest{Repository: "registry.example/open-card/web", Digest: "sha256:" + strings.Repeat("b", 64)}
	for index, suffix := range []string{"one", "two"} {
		plan := acornFoxBuildPlan(domain.ID("plan_rebuild_"+suffix), "src_afb_api06_repeatimage", "sha256:"+strings.Repeat("a", 64), "web", "rebuild-"+suffix, now)
		if _, err := store.CreateBuildPlan(ctx, plan); err != nil {
			t.Fatal(err)
		}
		build := domain.Build{ID: domain.ID("build_rebuild_" + suffix), PlanID: plan.ID, Status: domain.BuildPending, CreatedAt: now, UpdatedAt: now}
		if _, err := store.CreateBuild(ctx, build); err != nil {
			t.Fatal(err)
		}
		if _, err := store.StartBuild(ctx, build.ID, now); err != nil {
			t.Fatal(err)
		}
		artifact := domain.Artifact{ID: domain.ID("artifact_rebuild_" + suffix), BuildID: build.ID, Image: image, OCIStorageRef: "oci://shared-image", SizeBytes: 100, Evidence: []domain.EvidenceRef{{ID: domain.ID("ev_rebuild_" + suffix), Kind: "build.log", Digest: "sha256:" + strings.Repeat("c", 64), Locator: "log://" + suffix}}, CreatedAt: now}
		release, err := domain.NewRelease("app_afb_api06_repeatimage", "legacy", index+2, "sha256:"+strings.Repeat("d", 64), map[string]domain.ImageDigest{"web": image}, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.CompleteBuild(ctx, artifact, &ReleaseCreation{Release: *release, DefinitionID: "def_afb_api06_repeatimage"}, now); err != nil {
			t.Fatalf("%s: %v", suffix, err)
		}
		var linked string
		if err := db.QueryRowContext(ctx, `SELECT artifact_id FROM release_artifacts WHERE release_id=$1 AND service_name='web'`, release.ID.String()).Scan(&linked); err != nil || linked != artifact.ID.String() {
			t.Fatalf("release linked another build: artifact=%s error=%v", linked, err)
		}
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(DISTINCT a.build_id) FROM artifacts a JOIN builds b ON b.id=a.build_id WHERE b.state='succeeded' AND a.image_repository=$1 AND a.image_digest=$2`, image.Repository, image.Digest).Scan(&count); err != nil || count != 2 {
		t.Fatalf("independent evidence count=%d error=%v", count, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE artifacts SET size_bytes=101 WHERE id='artifact_rebuild_one'`); err == nil {
		t.Fatal("artifact immutability was lost")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO artifacts(id,build_id,image_repository,image_digest,oci_storage_ref,size_bytes) VALUES('duplicate_build','build_rebuild_one',$1,$2,'oci://other',100)`, image.Repository, image.Digest); err == nil {
		t.Fatal("one build accepted multiple artifacts")
	}
}

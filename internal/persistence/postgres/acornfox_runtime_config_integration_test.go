//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAcornFoxConfiguredRuntimeFactMatchesRelease(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_ENTRY07_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("task PostgreSQL required")
	}
	expected := validateAcornFoxEntryDiscoveryDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	resetAcornFoxEntryDiscoverySchema(t, ctx, db, expected)
	applyControlPlaneMigrations(t, ctx, db)
	now := time.Unix(1700200000, 0).UTC()
	fixture := insertAcornFoxProbeFixture(t, ctx, db, now)
	configuration := contracts.AcornFoxRuntimeConfiguration{Command: []string{"serve"}}
	resources := contracts.AcornFoxRuntimeRequestedResources{CPUMillis: 100, MemoryBytes: 128 << 20, PIDs: 64, DiskReservationBytes: 64 << 20}
	digest, err := contracts.CanonicalAcornFoxRuntimeConfigDigest(configuration, resources, 8080)
	if err != nil {
		t.Fatal(err)
	}
	image := domain.ImageDigest{Repository: "registry.test/configured", Digest: "sha256:" + strings.Repeat("c", 64)}
	release, err := domain.NewRelease(domain.ID(fixture.applicationID), "legacy", 2, digest, map[string]domain.ImageDigest{"web": image}, now)
	if err != nil {
		t.Fatal(err)
	}
	release.ID = "release_configured"
	fact, err := contracts.ProjectAcornFoxConfiguredRuntimeReleaseFact(*release, domain.ID(fixture.environmentID), resources, 8080, now, configuration)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO build_plans(id,source_revision_id,source_digest,service_name,build_kind,context_path,dockerfile_path,target_repository,output_contract,idempotency_key,created_at) VALUES('plan_configured','source_afb_probe',$1,'web','dockerfile','.','Dockerfile',$2,'{}'::jsonb,'configured-plan',$3)`, []any{"sha256:" + strings.Repeat("d", 64), image.Repository, now}},
		{`INSERT INTO builds(id,plan_id,state,created_at,updated_at) VALUES('build_configured','plan_configured','running',$1,$1)`, []any{now}},
		{`INSERT INTO artifacts(id,build_id,image_repository,image_digest,oci_storage_ref,size_bytes,created_at) VALUES('artifact_configured','build_configured',$1,$2,'oci://configured',1,$3)`, []any{image.Repository, image.Digest, now}},
		{`UPDATE builds SET state='succeeded',artifact_id='artifact_configured' WHERE id='build_configured'`, nil},
		{`INSERT INTO releases(id,application_id,definition_id,version,service_digests,service_group_id,config_digest,release_status,created_at) VALUES('release_configured',$1,'definition_afb_probe',2,jsonb_build_object('web',$2::text),'legacy',$3,'ready',$4)`, []any{fixture.applicationID, image.Digest, digest, now}},
		{`INSERT INTO release_artifacts(release_id,service_name,artifact_id) VALUES('release_configured','web','artifact_configured')`, nil},
	} {
		if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	store := NewStore(db)
	for index, kind := range []string{"valid", "wrong configuration", "wrong image"} {
		t.Run(kind, func(t *testing.T) {
			candidate := fact
			if kind == "wrong configuration" {
				c := configuration
				c.Command = []string{"changed"}
				candidate.Configuration = &c
				candidate.ConfigDigest, _ = contracts.CanonicalAcornFoxRuntimeConfigDigest(c, resources, 8080)
			}
			if kind == "wrong image" {
				candidate.Image.Repository = "registry.test/foreign"
			}
			deploymentID, err := contracts.AcornFoxRuntimeDeploymentID(candidate)
			if err != nil {
				t.Fatal(err)
			}
			key := "configured-fact-" + string(rune('a'+index))
			operationID := "operation_" + key
			taskID := "task_" + key
			parameters, _ := json.Marshal(map[string]any{"acornfox_payload_type": "deploy", "request": contracts.AcornFoxRuntimeDeployRequest{Fact: candidate, IdempotencyKey: key}})
			payload, _ := json.Marshal(map[string]any{"kind": v1.TaskDeploy, "parameters": json.RawMessage(parameters)})
			for _, statement := range []struct {
				query string
				args  []any
			}{
				{`INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) VALUES($1,$2,'release_configured','runtime_ready',$3,$3)`, []any{deploymentID, fixture.environmentID, now}},
				{`INSERT INTO operations(id,application_id,environment_id,deployment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES($1,$2,$3,$4,'deploy',$5,'succeeded',$6,$7,$7)`, []any{operationID, fixture.applicationID, fixture.environmentID, deploymentID, key, "deployment/" + deploymentID.String(), now}},
				{`INSERT INTO task_leases(task_id,operation_id,attempt,max_attempts,state,payload,created_at,updated_at) VALUES($1,$2,1,3,'completed',$3::jsonb,$4,$4)`, []any{taskID, operationID, payload, now}},
			} {
				if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
					t.Fatal(err)
				}
			}
			readCtx, stop := context.WithTimeout(ctx, 3*time.Second)
			defer stop()
			recovered, err := store.GetAcornFoxRuntimeRequest(readCtx, domain.ID(fixture.applicationID), deploymentID)
			if kind == "valid" {
				if err != nil || recovered.Fact.ConfigDigest != digest || recovered.Fact.Configuration.Command[0] != "serve" {
					t.Fatal("valid configured fact not recovered", err)
				}
			} else if err == nil {
				t.Fatal("fact not bound to persisted release was accepted")
			}
			if _, err := store.GetAcornFoxRuntimeRequest(ctx, "another_application", deploymentID); err == nil {
				t.Fatal("cross-application read accepted")
			}
		})
	}
}

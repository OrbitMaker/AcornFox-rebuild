//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	v1 "github.com/open-card/open-card/api/agent/v1"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/domain"
)

func TestAcornFoxFixCandidateLedgerReplayOwnerAndSourceMatch(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_AFB_CANDIDATE_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_AFB_CANDIDATE_TEST_DATABASE_URL is required")
	}
	validateAcornFoxCandidateDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	applyControlPlaneMigrations(t, ctx, db)
	now := time.Unix(1_700_000_000, 0).UTC()
	seedAcornFoxFixCandidateFacts(t, ctx, db, now)
	store := NewStore(db)
	leader, err := store.AcquireAcornFoxFixCandidateLeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := store.AcquireAcornFoxFixCandidateLeader(ctx); !errors.Is(err, ErrAcornFoxFixCandidateLeaderHeld) || second != nil {
		t.Fatalf("second leader=%v err=%v", second, err)
	}
	if err := leader.Release(ctx); err != nil {
		t.Fatal(err)
	}
	reacquired, err := store.AcquireAcornFoxFixCandidateLeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := reacquired.conn.Close(); err != nil {
		t.Fatal(err)
	}
	monitorContext, monitorCancel := context.WithTimeout(ctx, time.Second)
	defer monitorCancel()
	if err := reacquired.Monitor(monitorContext, 50*time.Millisecond); err == nil {
		t.Fatal("lost leader connection was not detected")
	}
	replacement, err := store.AcquireAcornFoxFixCandidateLeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := replacement.Release(ctx); err != nil {
		t.Fatal(err)
	}
	executionLeader, err := store.AcquireAcornFoxFixCandidateLeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	candidateStore, err := NewAcornFoxFixCandidateFencedStore(store, executionLeader)
	if err != nil {
		t.Fatal(err)
	}
	request := application.AcornFoxFixCandidateCreateRequest{ApplicationID: "app_candidate", BaseSourceRevisionID: "src_candidate_base", IdempotencyKey: "candidate-key", OwnerAdminID: "admin_candidate"}
	requestDigest := "sha256:" + strings.Repeat("a", 64)
	if replay, err := candidateStore.BeginAcornFoxFixCandidate(ctx, request, requestDigest, now); err != nil || replay != nil {
		t.Fatalf("begin replay=%+v err=%v", replay, err)
	}
	acceptedID := application.AcornFoxFixCandidateIDFromRequestDigest(requestDigest)
	accepted, err := store.GetAcornFoxFixCandidate(ctx, request.ApplicationID, acceptedID)
	if err != nil || accepted.Status != application.AcornFoxFixCandidatePreparing || accepted.ID != acceptedID || accepted.OwnerAdminID != request.OwnerAdminID {
		t.Fatalf("accepted=%+v err=%v", accepted, err)
	}
	preparingReplay, err := candidateStore.BeginAcornFoxFixCandidate(ctx, request, requestDigest, now.Add(time.Second))
	if err != nil || preparingReplay == nil || preparingReplay.ID != acceptedID || preparingReplay.Status != application.AcornFoxFixCandidatePreparing || !preparingReplay.CreatedAt.Equal(now) {
		t.Fatalf("preparing replay=%+v err=%v", preparingReplay, err)
	}
	if _, err := candidateStore.BeginAcornFoxFixCandidate(ctx, request, "sha256:"+strings.Repeat("e", 64), now.Add(time.Second)); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("body conflict err=%v", err)
	}
	candidate := persistedAcornFoxFixCandidate(now)
	candidate.ID = acceptedID
	if err := candidateStore.CompleteAcornFoxFixCandidate(ctx, candidate, requestDigest); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.GetAcornFoxFixCandidate(ctx, candidate.ApplicationID, candidate.ID)
	if err != nil || loaded.Status != application.AcornFoxFixCandidateValidated || loaded.OwnerAdminID != request.OwnerAdminID || loaded.CanonicalDiff != candidate.CanonicalDiff {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	replayed, err := candidateStore.BeginAcornFoxFixCandidate(ctx, request, requestDigest, now.Add(time.Minute))
	if err != nil || replayed == nil || replayed.ID != candidate.ID || !replayed.CreatedAt.Equal(candidate.CreatedAt) {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	otherOwner := request
	otherOwner.OwnerAdminID = "admin_candidate_other"
	if _, err := candidateStore.BeginAcornFoxFixCandidate(ctx, otherOwner, requestDigest, now); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("owner mismatch err=%v", err)
	}
	listed, err := store.ListAcornFoxFixCandidates(ctx, candidate.ApplicationID, candidate.OwnerAdminID)
	if err != nil || len(listed) != 1 || listed[0].ID != candidate.ID || listed[0].Status != application.AcornFoxFixCandidateValidated {
		t.Fatalf("listed=%+v err=%v", listed, err)
	}
	foreign, err := store.ListAcornFoxFixCandidates(ctx, candidate.ApplicationID, "admin_candidate_other")
	if err != nil || len(foreign) != 0 {
		t.Fatalf("foreign=%+v err=%v", foreign, err)
	}
	failedRequest := request
	failedRequest.IdempotencyKey = "candidate-failed"
	failedDigest := "sha256:" + strings.Repeat("f", 64)
	if replay, err := candidateStore.BeginAcornFoxFixCandidate(ctx, failedRequest, failedDigest, now.Add(2*time.Second)); err != nil || replay != nil {
		t.Fatalf("failed begin replay=%+v err=%v", replay, err)
	}
	if err := candidateStore.FailAcornFoxFixCandidate(ctx, failedRequest.ApplicationID, failedRequest.IdempotencyKey, failedDigest, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	failedID := application.AcornFoxFixCandidateIDFromRequestDigest(failedDigest)
	failed, err := store.GetAcornFoxFixCandidate(ctx, failedRequest.ApplicationID, failedID)
	if err != nil || failed.Status != application.AcornFoxFixCandidateFailed || failed.ID != failedID {
		t.Fatalf("failed=%+v err=%v", failed, err)
	}
	recoveryRequest := request
	recoveryRequest.IdempotencyKey = "candidate-recovery"
	recoveryDigest := "sha256:" + strings.Repeat("0", 64)
	if replay, err := candidateStore.BeginAcornFoxFixCandidate(ctx, recoveryRequest, recoveryDigest, now.Add(4*time.Second)); err != nil || replay != nil {
		t.Fatalf("recovery begin replay=%+v err=%v", replay, err)
	}
	if err := candidateStore.RecoverAcornFoxFixCandidates(ctx, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.GetAcornFoxFixCandidate(ctx, recoveryRequest.ApplicationID, application.AcornFoxFixCandidateIDFromRequestDigest(recoveryDigest))
	if err != nil || recovered.Status != application.AcornFoxFixCandidateFailed {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	zombie := persistedAcornFoxFixCandidate(now.Add(4 * time.Second))
	zombie.ID = recovered.ID
	zombie.RequestKey = recoveryRequest.IdempotencyKey
	if err := candidateStore.CompleteAcornFoxFixCandidate(ctx, zombie, recoveryDigest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("zombie completion err=%v", err)
	}
	recovered, err = store.GetAcornFoxFixCandidate(ctx, recoveryRequest.ApplicationID, recovered.ID)
	if err != nil || recovered.Status != application.AcornFoxFixCandidateFailed {
		t.Fatalf("zombie changed recovered=%+v err=%v", recovered, err)
	}

	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO source_revisions(id,application_id,provider,git_commit,content_digest,workspace_manifest,source_kind,locator,source_ref,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES('src_candidate_imported','app_candidate','git',$1,$2,'{}'::jsonb,'git_https',$3,'refs/heads/fix','/immutable/imported','prepared',true,$4)`, []any{strings.Repeat("d", 40), candidate.ResultTreeDigest, candidate.BaseRepositoryURL, now}},
		{`INSERT INTO source_workspace_events(source_revision_id,sequence,workspace_ref,state,created_at) VALUES('src_candidate_imported',1,'/immutable/imported','prepared',$1)`, []any{now}},
		{`INSERT INTO acornfox_source_metadata(source_revision_id,repository_url) VALUES('src_candidate_imported',$1)`, []any{candidate.BaseRepositoryURL}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	matched, err := candidateStore.MatchAcornFoxFixCandidateSource(ctx, candidate.ApplicationID, candidate.ID, "src_candidate_imported", strings.Repeat("d", 40), now.Add(time.Minute))
	if err != nil || matched.Status != application.AcornFoxFixCandidateSourceMatched || matched.MatchedSourceRevisionID != "src_candidate_imported" {
		t.Fatalf("matched=%+v err=%v", matched, err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO operations(id,application_id,environment_id,operation_type,idempotency_key,state,target_ref,created_at,updated_at) VALUES('op_candidate_default_observe','app_candidate','env_candidate','observe','default-observe','pending','deployment/default/logs',$1,$1)`, now); err != nil {
		t.Fatal(err)
	}
	taskID, err := store.EnqueueAcornFoxFixCandidateRuntimeTask(ctx, AcornFoxFixCandidateRuntimeTaskRequest{CandidateID: candidate.ID, ApplicationID: candidate.ApplicationID, Image: candidate.ValidatedImage, ContainerPort: candidate.ContainerPort, IdempotencyKey: "candidate-runtime", Actor: "admin_candidate", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	task, err := store.GetControllerTask(ctx, taskID)
	if err != nil || !task.DeploymentID.Empty() || task.Operation.Type != domain.OperationDeploy || task.Operation.EnvironmentID == "env_candidate" || task.Task.State != TaskReady || !strings.Contains(string(task.Task.Payload), "acornfox_candidate_validation_v1") {
		t.Fatalf("candidate task=%+v err=%v", task, err)
	}
	var candidateEnvironmentApplication, candidateEnvironmentName, defaultOperationState string
	if err := db.QueryRowContext(ctx, `SELECT application_id,name FROM environments WHERE id=$1`, task.Operation.EnvironmentID.String()).Scan(&candidateEnvironmentApplication, &candidateEnvironmentName); err != nil || candidateEnvironmentApplication != candidate.ApplicationID.String() || candidateEnvironmentName != acornFoxCandidateEnvironmentName {
		t.Fatalf("candidate environment app=%q name=%q err=%v", candidateEnvironmentApplication, candidateEnvironmentName, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT state FROM operations WHERE id='op_candidate_default_observe'`).Scan(&defaultOperationState); err != nil || defaultOperationState != "pending" {
		t.Fatalf("default observe state=%q err=%v", defaultOperationState, err)
	}
	var deployments int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM deployments`).Scan(&deployments); err != nil || deployments != 0 {
		t.Fatalf("candidate runtime created normal deployments=%d err=%v", deployments, err)
	}
	var durable acornFoxCandidateTaskPayload
	if err := json.Unmarshal(task.Task.Payload, &durable); err != nil {
		t.Fatal(err)
	}
	var wrapper acornFoxCandidateAgentWrapper
	if err := json.Unmarshal(durable.Parameters, &wrapper); err != nil {
		t.Fatal(err)
	}
	runtimeID, err := candidateAgentRuntimeID(wrapper.Request)
	if err != nil {
		t.Fatal(err)
	}
	containerID := strings.Repeat("9", 64)
	absenceDigest := sha256.Sum256([]byte("candidate-container-absent\x00" + containerID))
	probeRef, absenceRef := "candidate-probe:sha256:"+strings.Repeat("7", 64), "candidate-absence:sha256:"+hex.EncodeToString(absenceDigest[:])
	details, _ := json.Marshal(map[string]any{"candidate_id": candidate.ID, "runtime_id": runtimeID, "image": candidate.ValidatedImage, "resources": wrapper.Request.Resources, "probe": map[string]any{"runtime_id": runtimeID, "container_id": containerID, "target_class": "loopback", "outcome": "responded", "evidence_ref": probeRef, "observed_at": now}, "absence": map[string]any{"runtime_id": runtimeID, "absent": true, "evidence_ref": absenceRef, "observed_at": now}})
	wire, _ := json.Marshal(v1.Observation{TaskID: taskID.String(), Sequence: 1, TargetRef: "candidate/" + candidate.ID.String() + "/runtime", Status: "stopped", Healthy: false, At: now, EvidenceRefs: []string{probeRef, absenceRef}, Details: details})
	if _, err := db.ExecContext(ctx, `INSERT INTO task_agent_events(task_id,sequence,event_type,payload,event_digest,created_at) VALUES($1,1,'observation',$2::jsonb,$3,$4)`, taskID.String(), wire, "sha256:"+strings.Repeat("a", 64), now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE operations SET state='succeeded',updated_at=$2 WHERE id=$1`, task.Operation.ID.String(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE task_leases SET state='completed',result_digest=$2,result='{}'::jsonb,completed_at=$3,last_agent_sequence=1,updated_at=$3 WHERE task_id=$1`, taskID.String(), "sha256:"+strings.Repeat("b", 64), now); err != nil {
		t.Fatal(err)
	}
	runtimeEvidence, complete, err := store.GetAcornFoxFixCandidateRuntimeEvidence(ctx, taskID, candidate.ValidatedImage)
	if err != nil || !complete || !runtimeEvidence.CleanupConfirmed || runtimeEvidence.TaskID != taskID {
		t.Fatalf("runtime evidence=%+v complete=%v err=%v", runtimeEvidence, complete, err)
	}
	badTaskID, err := store.EnqueueAcornFoxFixCandidateRuntimeTask(ctx, AcornFoxFixCandidateRuntimeTaskRequest{CandidateID: candidate.ID, ApplicationID: candidate.ApplicationID, Image: candidate.ValidatedImage, ContainerPort: candidate.ContainerPort, IdempotencyKey: "candidate-runtime-bad-receipt", Actor: "admin_candidate", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	badTask, err := store.GetControllerTask(ctx, badTaskID)
	if err != nil {
		t.Fatal(err)
	}
	var badDurable acornFoxCandidateTaskPayload
	if err := json.Unmarshal(badTask.Task.Payload, &badDurable); err != nil {
		t.Fatal(err)
	}
	var badWrapper acornFoxCandidateAgentWrapper
	if err := json.Unmarshal(badDurable.Parameters, &badWrapper); err != nil {
		t.Fatal(err)
	}
	badRuntimeID, err := candidateAgentRuntimeID(badWrapper.Request)
	if err != nil {
		t.Fatal(err)
	}
	badAbsenceRef := "candidate-absence:sha256:" + strings.Repeat("8", 64)
	badDetails, _ := json.Marshal(map[string]any{"candidate_id": candidate.ID, "runtime_id": badRuntimeID, "image": candidate.ValidatedImage, "resources": badWrapper.Request.Resources, "probe": map[string]any{"runtime_id": badRuntimeID, "container_id": containerID, "target_class": "loopback", "outcome": "responded", "evidence_ref": probeRef, "observed_at": now}, "absence": map[string]any{"runtime_id": badRuntimeID, "absent": true, "evidence_ref": badAbsenceRef, "observed_at": now}})
	badWire, _ := json.Marshal(v1.Observation{TaskID: badTaskID.String(), Sequence: 1, TargetRef: "candidate/" + candidate.ID.String() + "/runtime", Status: "stopped", Healthy: false, At: now, EvidenceRefs: []string{probeRef, badAbsenceRef}, Details: badDetails})
	if _, err := db.ExecContext(ctx, `INSERT INTO task_agent_events(task_id,sequence,event_type,payload,event_digest,created_at) VALUES($1,1,'observation',$2::jsonb,$3,$4)`, badTaskID.String(), badWire, "sha256:"+strings.Repeat("c", 64), now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE operations SET state='succeeded',updated_at=$2 WHERE id=$1`, badTask.Operation.ID.String(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE task_leases SET state='completed',result_digest=$2,result='{}'::jsonb,completed_at=$3,last_agent_sequence=1,updated_at=$3 WHERE task_id=$1`, badTaskID.String(), "sha256:"+strings.Repeat("d", 64), now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GetAcornFoxFixCandidateRuntimeEvidence(ctx, badTaskID, candidate.ValidatedImage); err == nil {
		t.Fatal("container-unbound absence evidence was accepted")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO applications(id,name,created_at,updated_at) VALUES('app_candidate_collision','collision',$1,$1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO environments(id,application_id,name,created_at) VALUES('env_foreign_reserved','app_candidate_collision',$2,$1)`, now, acornFoxCandidateEnvironmentName); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnqueueAcornFoxFixCandidateRuntimeTask(ctx, AcornFoxFixCandidateRuntimeTaskRequest{CandidateID: "candidate_ffffffffffffffffffffffffffffffff", ApplicationID: "app_candidate_collision", Image: candidate.ValidatedImage, ContainerPort: candidate.ContainerPort, IdempotencyKey: "candidate-runtime-collision", Actor: "admin_candidate", Now: now}); !domain.IsCode(err, domain.ErrValidation) {
		t.Fatalf("reserved environment collision err=%v", err)
	}
	if err := executionLeader.Release(ctx); err != nil {
		t.Fatal(err)
	}
	doomedLeader, err := store.AcquireAcornFoxFixCandidateLeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	doomedStore, err := NewAcornFoxFixCandidateFencedStore(store, doomedLeader)
	if err != nil {
		t.Fatal(err)
	}
	doomedRequest := request
	doomedRequest.IdempotencyKey = "candidate-lost-leader"
	doomedDigest := "sha256:" + strings.Repeat("6", 64)
	if replay, err := doomedStore.BeginAcornFoxFixCandidate(ctx, doomedRequest, doomedDigest, now.Add(10*time.Second)); err != nil || replay != nil {
		t.Fatalf("doomed begin replay=%+v err=%v", replay, err)
	}
	if err := doomedLeader.conn.Close(); err != nil {
		t.Fatal(err)
	}
	doomed := persistedAcornFoxFixCandidate(now.Add(10 * time.Second))
	doomed.ID = application.AcornFoxFixCandidateIDFromRequestDigest(doomedDigest)
	doomed.RequestKey = doomedRequest.IdempotencyKey
	if err := doomedStore.CompleteAcornFoxFixCandidate(ctx, doomed, doomedDigest); err == nil {
		t.Fatal("candidate completed after losing the fenced leader connection")
	}
	recoveryLeader, err := store.AcquireAcornFoxFixCandidateLeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	recoveryStore, err := NewAcornFoxFixCandidateFencedStore(store, recoveryLeader)
	if err != nil {
		t.Fatal(err)
	}
	if err := recoveryStore.RecoverAcornFoxFixCandidates(ctx, now.Add(11*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := recoveryLeader.Release(ctx); err != nil {
		t.Fatal(err)
	}
	doomedFact, err := store.GetAcornFoxFixCandidate(ctx, doomedRequest.ApplicationID, doomed.ID)
	if err != nil || doomedFact.Status != application.AcornFoxFixCandidateFailed {
		t.Fatalf("doomed fact=%+v err=%v", doomedFact, err)
	}
}

func validateAcornFoxCandidateDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" && parsed.Hostname() != "::1") || !strings.HasPrefix(strings.TrimPrefix(parsed.EscapedPath(), "/"), "open_card_afbcandidate_") {
		t.Fatal("candidate test database URL is invalid")
	}
}

func seedAcornFoxFixCandidateFacts(t *testing.T, ctx context.Context, db *sql.DB, now time.Time) {
	t.Helper()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO applications(id,name,created_at,updated_at) VALUES('app_candidate','candidate',$1,$1)`, []any{now}},
		{`INSERT INTO environments(id,application_id,name,created_at) VALUES('env_candidate','app_candidate','default',$1)`, []any{now}},
		{`INSERT INTO source_revisions(id,application_id,provider,git_commit,content_digest,workspace_manifest,source_kind,locator,source_ref,workspace_ref,workspace_lifecycle,immutable,created_at) VALUES('src_candidate_base','app_candidate','git',$1,$2,'{}'::jsonb,'git_https',$3,'main','/immutable/base','prepared',true,$4)`, []any{strings.Repeat("c", 40), "sha256:" + strings.Repeat("1", 64), "https://github.com/OrbitMaker/acornfox.git", now}},
		{`INSERT INTO source_workspace_events(source_revision_id,sequence,workspace_ref,state,created_at) VALUES('src_candidate_base',1,'/immutable/base','prepared',$1)`, []any{now}},
		{`INSERT INTO acornfox_source_metadata(source_revision_id,repository_url) VALUES('src_candidate_base',$1)`, []any{"https://github.com/OrbitMaker/acornfox.git"}},
		{`INSERT INTO admin_credentials(id,password_hash_scheme,password_hash,credential_version,disabled_at,created_at,updated_at) VALUES('admin_candidate','argon2id-v1',$1,1,NULL,$2,$2),('admin_candidate_other','argon2id-v1',$1,1,$2,$2,$2)`, []any{"$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$ZGlnaWVzdA", now}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func persistedAcornFoxFixCandidate(now time.Time) application.AcornFoxFixCandidate {
	image, _ := domain.ParseImageDigest("local/candidate", "sha256:"+strings.Repeat("4", 64))
	return application.AcornFoxFixCandidate{
		ID: "candidate_0123456789abcdef0123456789abcdef", ApplicationID: "app_candidate", BaseSourceRevisionID: "src_candidate_base",
		BaseRepositoryURL: "https://github.com/OrbitMaker/acornfox.git", BaseCommit: strings.Repeat("c", 40), BaseTreeDigest: "sha256:" + strings.Repeat("1", 64), PatchDigest: "sha256:" + strings.Repeat("2", 64), ResultTreeDigest: "sha256:" + strings.Repeat("3", 64), ContainerPort: 8080, ChangedPaths: []string{"Dockerfile"}, CanonicalDiff: "diff\n",
		ValidatedImage: image, BuildLogRef: "candidate-log", BuildEvidenceDigest: "sha256:" + strings.Repeat("5", 64),
		Runtime:      application.AcornFoxFixCandidateRuntimeEvidence{TaskID: "task_candidate", Image: image, RuntimeState: "stopped", ProbeOutcome: "responded", CleanupConfirmed: true, EvidenceDigest: "sha256:" + strings.Repeat("6", 64)},
		OwnerAdminID: "admin_candidate", RequestKey: "candidate-key", Status: application.AcornFoxFixCandidateValidated, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

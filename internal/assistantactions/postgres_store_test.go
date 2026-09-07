package assistantactions

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
	"github.com/open-card/open-card/internal/assistant"
)

func TestActionsMigrationContainsConfirmationAndActiveSlotGuards(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "control-plane", "0038_acornfox_assistant_actions.sql"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(raw))
	for _, required := range []string{"assistant_session_id", "assistant_run_id", "proposal_key", "request_digest", "execution_key", "target_release_id", "target_release_version", "one_active_action_per_app", "state in ('executing','accepted','unknown')"} {
		if !strings.Contains(text, required) {
			t.Errorf("migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"shell_command", "source_patch", "confirmed_by_model", "tool_arguments"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("migration contains %q", forbidden)
		}
	}
}

func TestPostgresActionsConcurrentApprovalReplayIsolationAndDrift(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("OPEN_CARD_ASSISTANT_ACTIONS_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("OPEN_CARD_ASSISTANT_ACTIONS_TEST_DATABASE_URL is required")
	}
	validateActionsDSN(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.ExecContext(ctx, `DROP SCHEMA public CASCADE;CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"0001_foundation.sql", "0022_admin_auth.sql", "0037_acornfox_assistant.sql", "0038_acornfox_assistant_actions.sql", "0038_acornfox_assistant_actions.sql"} {
		applyActionsMigration(t, ctx, db, name)
	}
	now := time.Date(2026, 9, 7, 15, 0, 0, 0, time.UTC)
	statements := []string{
		`INSERT INTO admin_credentials(id,password_hash_scheme,password_hash,credential_version,created_at,updated_at) VALUES('admin_1','pbkdf2-sha256-v1','$pbkdf2-sha256$i=600000,l=32$c2FsdA$ZGlnaWVzdA',1,$1,$1)`,
		`INSERT INTO applications(id,name,created_at,updated_at) VALUES('app_1','Safe App',$1,$1)`,
		`INSERT INTO environments(id,application_id,name,created_at) VALUES('env_1','app_1','prod',$1)`,
		`INSERT INTO source_revisions(id,application_id,provider,content_digest,created_at) VALUES('src_1','app_1','upload','sha256:source',$1)`,
		`INSERT INTO delivery_definitions(id,application_id,source_revision_id,version,configuration,created_at) VALUES('definition_1','app_1','src_1',1,'{}',$1)`,
		`INSERT INTO releases(id,application_id,definition_id,version,service_digests,created_at) VALUES('release_1','app_1','definition_1',1,'{}',$1),('release_2','app_1','definition_1',2,'{}',$1)`,
		`INSERT INTO deployments(id,environment_id,release_id,state,created_at,updated_at) VALUES('dep_1','env_1','release_1','serving',$1,$1)`,
		`INSERT INTO acornfox_assistant_sessions(id,owner_admin_id,scope_kind,app_id,created_at,updated_at) VALUES('session_1','admin_1','app','app_1',$1,$1),('session_2','admin_1','app','app_1',$1,$1)`,
		`INSERT INTO acornfox_assistant_runs(id,session_id,idempotency_key,request_digest,message,status,created_at,updated_at) VALUES('run_1','session_1','r1',repeat('a',64),'propose','completed',$1,$1),('run_2','session_2','r2',repeat('b',64),'propose','completed',$1,$1),('run_3','session_2','r3',repeat('c',64),'propose','completed',$1,$1),('run_4','session_2','r4',repeat('d',64),'propose','completed',$1,$1),('run_5','session_2','r5',repeat('e',64),'propose','completed',$1,$1)`,
		`INSERT INTO operations(id,environment_id,deployment_id,operation_type,idempotency_key,state,created_at,updated_at) VALUES('operation_1','env_1','dep_1','restart','action-op','succeeded',$1,$1),('operation_unknown','env_1','dep_1','restart','action-unknown','pending',$1,$1)`,
	}
	for _, statement := range statements {
		if _, err = db.ExecContext(ctx, statement, now); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	store := NewPostgresStore(db)
	resolver := store
	executor := &fakeExecutor{results: []ExecutionResult{{OperationID: "operation_1", Accepted: true}}}
	clock := now
	service, err := NewService(Config{Store: store, Resolver: resolver, Executor: executor, Clock: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	actor := assistant.Actor{AdminID: "admin_1"}
	p, err := service.PrepareProposal(ctx, actor, "session_1", "run_1", PrepareInput{Action: ActionRestart, ApplicationID: "app_1", DeploymentID: "dep_1"}, "call-1")
	if err != nil || p.Target.ReleaseID != "release_1" || p.Target.ReleaseVersion != 1 {
		t.Fatalf("proposal=%+v err=%v", p, err)
	}
	again, err := service.PrepareProposal(ctx, actor, "session_1", "run_1", PrepareInput{Action: ActionRestart, ApplicationID: "app_1", DeploymentID: "dep_1"}, "new-call")
	if err != nil || again.ID != p.ID {
		t.Fatalf("replay=%+v err=%v", again, err)
	}
	if items, err := service.List(ctx, assistant.Actor{AdminID: "admin_2"}, "session_1"); err != nil || len(items) != 0 {
		t.Fatalf("owner isolation=%+v err=%v", items, err)
	}
	results := make(chan Proposal, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { value, e := service.Decide(ctx, actor, p.SessionID, p.ID, true); results <- value; errs <- e }()
	}
	for i := 0; i < 2; i++ {
		if e := <-errs; e != nil {
			t.Fatal(e)
		}
		if value := <-results; value.State != StateAccepted || value.OperationID != "operation_1" {
			t.Fatalf("decision=%+v", value)
		}
	}
	executor.mu.Lock()
	calls := len(executor.calls)
	executor.mu.Unlock()
	if calls != 1 {
		t.Fatalf("executor calls=%d", calls)
	}
	// Verified/failed W06 verdict is the only release path for the active slot.
	observed := now.Add(time.Minute)
	service.verifier = fakeVerifier{verification: Verification{State: VerificationVerified, Verdict: "operation completed; application health not asserted", ObservedAt: &observed}}
	items, err := service.List(ctx, actor, "session_1")
	if err != nil || items[0].State != StateVerified {
		t.Fatalf("verification=%+v err=%v", items, err)
	}
	// Exact deployment release drift invalidates a pending proposal before any execution.
	p2, err := service.PrepareProposal(ctx, actor, "session_2", "run_2", PrepareInput{Action: ActionRedeploy, ApplicationID: "app_1", DeploymentID: "dep_1"}, "call-2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE deployments SET release_id='release_2',version=version+1,updated_at=$1 WHERE id='dep_1'`, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Decide(ctx, actor, p2.SessionID, p2.ID, true); !errors.Is(err, ErrTargetChanged) {
		t.Fatalf("drift=%v", err)
	}
	executor.mu.Lock()
	calls = len(executor.calls)
	executor.mu.Unlock()
	if calls != 1 {
		t.Fatalf("drift executor calls=%d", calls)
	}
	// Expiry persists as terminal and never occupies the app slot.
	expiring, err := service.PrepareProposal(ctx, actor, "session_2", "run_3", PrepareInput{Action: ActionRestart, ApplicationID: "app_1", DeploymentID: "dep_1"}, "call-expire")
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(ProposalTTL)
	if _, err = service.Decide(ctx, actor, expiring.SessionID, expiring.ID, true); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry=%v", err)
	}
	clock = now.Add(3 * time.Minute)
	// Lost command acknowledgement remains active/unknown; retry uses the same
	// proposal-derived key and the idempotent executor result.
	unknownExecutor := &fakeExecutor{results: []ExecutionResult{{OperationID: "operation_unknown"}, {OperationID: "operation_unknown", Accepted: true}}, errors: []error{errors.New("commit acknowledgement lost"), nil}}
	unknownService, err := NewService(Config{Store: store, Resolver: resolver, Executor: unknownExecutor, Clock: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	unknownProposal, err := unknownService.PrepareProposal(ctx, actor, "session_2", "run_4", PrepareInput{Action: ActionRestart, ApplicationID: "app_1", DeploymentID: "dep_1"}, "call-unknown")
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := unknownService.Decide(ctx, actor, unknownProposal.SessionID, unknownProposal.ID, true)
	if err != nil || unknown.State != StateUnknown {
		t.Fatalf("unknown=%+v err=%v", unknown, err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE deployments SET release_id='release_1',version=version+1,updated_at=$1 WHERE id='dep_1'`, clock.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	retried, err := unknownService.Decide(ctx, actor, unknownProposal.SessionID, unknownProposal.ID, true)
	if err != nil || retried.State != StateAccepted {
		t.Fatalf("unknown retry=%+v err=%v", retried, err)
	}
	unknownExecutor.mu.Lock()
	if len(unknownExecutor.calls) != 2 || unknownExecutor.calls[0].IdempotencyKey != unknownExecutor.calls[1].IdempotencyKey {
		t.Fatalf("unknown keys=%+v", unknownExecutor.calls)
	}
	if unknownExecutor.calls[1].Target.ReleaseID != "release_2" {
		t.Fatalf("unknown retry target=%+v", unknownExecutor.calls[1].Target)
	}
	unknownExecutor.mu.Unlock()
	blocked, err := unknownService.PrepareProposal(ctx, actor, "session_2", "run_5", PrepareInput{Action: ActionRedeploy, ApplicationID: "app_1", DeploymentID: "dep_1"}, "call-blocked")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = unknownService.Decide(ctx, actor, blocked.SessionID, blocked.ID, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("active app isolation=%v", err)
	}
}

func validateActionsDSN(t *testing.T, dsn string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" && parsed.Hostname() != "::1") || !strings.HasPrefix(strings.TrimPrefix(parsed.EscapedPath(), "/"), "open_card_assistant_actions_") {
		t.Fatal("assistant actions test DSN invalid")
	}
}
func applyActionsMigration(t *testing.T, ctx context.Context, db *sql.DB, name string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "control-plane", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(raw)); err != nil {
		t.Fatalf("apply %s: %v", name, err)
	}
}

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	aicontext "github.com/open-card/open-card/internal/ai/context"
	ailedger "github.com/open-card/open-card/internal/ai/ledger"
	"github.com/open-card/open-card/internal/ai/orchestrator"
	airunner "github.com/open-card/open-card/internal/ai/runner"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

var m6TaskTypes = map[string]struct{}{"definition_ambiguity": {}, "build_failure_diagnosis": {}, "log_anomaly_analysis": {}, "usage_analysis": {}}
var m6DataScopes = map[string]struct{}{"definition_summary": {}, "source_excerpt": {}, "build_log_summary": {}, "operations_summary": {}, "usage_aggregate": {}}

type m6AIBackend struct {
	db            *sql.DB
	ledger        ailedger.Repository
	base          orchestrator.Orchestrator
	providers     map[ailedger.Profile]contracts.AIProvider
	workspaceRoot string
	now           func() time.Time
}

func validateM6Schema(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("M6 PostgreSQL dependency is missing")
	}
	required := []string{"m6_ai_invocations", "m6_ai_context_packages", "m6_ai_action_plans", "m6_ai_tool_actions", "m6_ai_verifications", "m6_ai_rollbacks", "m6_ai_outcomes", "m6_ai_candidate_refs", "m6_ai_interventions", "m6_ai_settings_events", "m6_rule_candidates", "m6_rule_candidate_observations", "m6_rule_candidate_events", "m6_rule_evaluations", "m6_rule_versions", "m6_rule_registry_events"}
	for _, table := range required {
		var relation sql.NullString
		if err := db.QueryRowContext(ctx, "SELECT to_regclass($1)", "public."+table).Scan(&relation); err != nil {
			return err
		}
		if !relation.Valid {
			return fmt.Errorf("M6 schema 0021 is incomplete: %s", table)
		}
	}
	return nil
}

type sqlRows struct{}

func (b *m6AIBackend) nowUTC() time.Time {
	if b.now != nil {
		return b.now().UTC()
	}
	return time.Now().UTC()
}

func (b *m6AIBackend) GetSettings(ctx context.Context) (M6AISettings, error) {
	settings, err := b.ledger.CurrentSettings(ctx)
	if errors.Is(err, ailedger.ErrNotFound) {
		return M6AISettings{Version: "ai-v0", Enabled: false, Status: "disabled", Profile: "disabled", DataScopes: []string{}, MaxTokens: 128, MaxDurationMS: 5000, CooldownSeconds: 60, CacheEnabled: true, ExternalCalls: false}, nil
	}
	if err != nil {
		return M6AISettings{}, err
	}
	return b.projectSettings(settings), nil
}

func (b *m6AIBackend) UpdateSettings(ctx context.Context, input M6AISettingsUpdate) (M6AISettings, error) {
	current, err := b.GetSettings(ctx)
	if err != nil {
		return M6AISettings{}, err
	}
	if input.ExpectedVersion != current.Version {
		return M6AISettings{}, domain.NewError(domain.ErrConflict, "AI settings changed; refresh before retrying")
	}
	profile, err := m6LedgerProfile(input.Profile)
	if err != nil {
		return M6AISettings{}, err
	}
	if input.MaxTokens <= 0 || input.MaxDurationMS <= 0 || input.CooldownSeconds < 0 || len(input.DataScopes) == 0 {
		return M6AISettings{}, domain.NewError(domain.ErrValidation, "AI settings budgets and data scopes are required")
	}
	for _, scope := range input.DataScopes {
		if _, ok := m6DataScopes[scope]; !ok {
			return M6AISettings{}, domain.NewError(domain.ErrValidation, "AI data scope is unsupported")
		}
	}
	if !input.Enabled {
		profile = ailedger.ProfileDisabled
		input.Provider, input.Model = "", ""
	}
	version := int64(1)
	if current.Version != "ai-v0" {
		value, parseErr := strconv.ParseInt(strings.TrimPrefix(current.Version, "ai-v"), 10, 64)
		if parseErr != nil {
			return M6AISettings{}, parseErr
		}
		version = value + 1
	}
	record := ailedger.AISettings{Version: version, Enabled: input.Enabled, Profile: profile, Provider: strings.TrimSpace(input.Provider), Model: strings.TrimSpace(input.Model), DataScopes: append([]string(nil), input.DataScopes...), MaxTokens: int64(input.MaxTokens), MaxDurationMS: input.MaxDurationMS, CooldownMS: input.CooldownSeconds * 1000, CacheEnabled: input.CacheEnabled, Actor: input.Actor, ExternalCalls: false, CreatedAt: b.nowUTC()}
	digest := m6Digest(record)
	stored, _, err := b.ledger.AppendSettings(ctx, ailedger.SettingsRequest{IdempotencyKey: input.IdempotencyKey, RequestDigest: digest, Settings: record})
	if err != nil {
		if errors.Is(err, ailedger.ErrConflict) {
			return M6AISettings{}, domain.NewError(domain.ErrConflict, "AI settings idempotency conflict")
		}
		return M6AISettings{}, err
	}
	return b.projectSettings(stored), nil
}

func (b *m6AIBackend) projectSettings(value ailedger.AISettings) M6AISettings {
	status := "disabled"
	if value.Enabled {
		status = "unavailable"
		if value.Provider == "deterministic-fixture" && b.providers[value.Profile] != nil {
			status = "available"
		}
	}
	return M6AISettings{Version: fmt.Sprintf("ai-v%d", value.Version), Enabled: value.Enabled, Status: status, Profile: m6APIProfile(value.Profile), Provider: value.Provider, Model: value.Model, DataScopes: append([]string(nil), value.DataScopes...), MaxTokens: int(value.MaxTokens), MaxDurationMS: value.MaxDurationMS, CooldownSeconds: value.CooldownMS / 1000, CacheEnabled: value.CacheEnabled, ExternalCalls: false}
}

func (b *m6AIBackend) ListInterventions(ctx context.Context, appID domain.ID, operator bool) (M6AIInterventionView, error) {
	items, err := b.ledger.Query(ctx, ailedger.QueryFilter{ApplicationID: appID.String(), Limit: 100})
	if err != nil {
		return M6AIInterventionView{}, err
	}
	metrics, err := b.ledger.Metrics(ctx, ailedger.QueryFilter{ApplicationID: appID.String()})
	if err != nil {
		return M6AIInterventionView{}, err
	}
	settings, _ := b.GetSettings(ctx)
	mode := "ordinary"
	if operator {
		mode = "operator"
	}
	view := M6AIInterventionView{Version: m6ViewVersion(items), Mode: mode, AIStatus: settings.Status, Items: []M6AIInterventionFact{}, SuccessCount: int(metrics.Succeeded), FailureCount: int(metrics.Failed), RollbackCount: int(metrics.RolledBack), CandidateCount: int(metrics.DistinctCandidates), TotalTokens: uint64(metrics.Tokens), TotalDurationMS: metrics.DurationMS}
	for _, item := range items {
		view.Items = append(view.Items, m6InterventionFact(item, operator))
	}
	return view, nil
}

func (b *m6AIBackend) RequestIntervention(ctx context.Context, appID domain.ID, input M6AIRequest) (M6AIInterventionFact, error) {
	if _, ok := m6TaskTypes[strings.TrimSpace(input.TaskType)]; !ok {
		return M6AIInterventionFact{}, domain.NewError(domain.ErrValidation, "controlled AI task type is unsupported")
	}
	view, err := b.ListInterventions(ctx, appID, true)
	if err != nil {
		return M6AIInterventionFact{}, err
	}
	if input.ExpectedVersion != view.Version {
		return M6AIInterventionFact{}, domain.NewError(domain.ErrConflict, "AI intervention facts changed; refresh before retrying")
	}
	settingsRecord, err := b.ledger.CurrentSettings(ctx)
	if errors.Is(err, ailedger.ErrNotFound) || !settingsRecord.Enabled {
		return M6AIInterventionFact{ID: "manual-" + input.IdempotencyKey, ApplicationID: appID.String(), TaskType: input.TaskType, Status: "manual_fallback", Reason: foundation.RedactText(input.Reason), Summary: "AI is disabled", Suggestion: "Continue with deterministic rules, the minimum missing question, or a manual draft", RequiresUserAction: true, CreatedAt: b.nowUTC().Format(time.RFC3339Nano)}, nil
	}
	if err != nil {
		return M6AIInterventionFact{}, err
	}
	provider := b.providers[settingsRecord.Profile]
	if settingsRecord.Provider != "deterministic-fixture" {
		provider = nil
	}
	if provider == nil {
		return M6AIInterventionFact{ID: "manual-" + input.IdempotencyKey, ApplicationID: appID.String(), TaskType: input.TaskType, Status: "manual_fallback", Reason: foundation.RedactText(input.Reason), Summary: "Configured AI provider is unavailable", Suggestion: "Continue with deterministic rules or manual review", RequiresUserAction: true, CreatedAt: b.nowUTC().Format(time.RFC3339Nano)}, nil
	}
	contextInput, versions, err := b.contextInput(ctx, appID, input.TaskType, settingsRecord)
	if err != nil {
		return M6AIInterventionFact{}, err
	}
	orch := b.base
	orch.Enabled = true
	orch.Provider = provider
	orch.PolicyVersion = "m6-policy-v1"
	problem := foundation.ProblemFingerprint(foundation.ProblemInput{TaskType: input.TaskType, ApplicationID: appID.String(), ErrorCode: "rule_miss", ErrorMessage: foundation.RedactText(input.Reason)})
	result, processErr := orch.Process(ctx, orchestrator.Request{ApplicationID: appID, TaskType: input.TaskType, Reason: orchestrator.TriggerRuleMiss, ProblemFingerprint: problem, ObjectVersions: versions, Profile: m6APIProfile(settingsRecord.Profile), IdempotencyKey: input.IdempotencyKey, Actor: input.Actor, Confirmed: input.Confirmed, MaxTokens: int(settingsRecord.MaxTokens), MaxDuration: time.Duration(settingsRecord.MaxDurationMS) * time.Millisecond, ContextInput: contextInput})
	fact := m6ResultFact(appID, input, result, b.nowUTC())
	if processErr != nil && !result.Degraded {
		return fact, processErr
	}
	return fact, nil
}

func (b *m6AIBackend) contextInput(ctx context.Context, appID domain.ID, taskType string, settings ailedger.AISettings) (m6ExecutionInput, map[string]string, error) {
	var name string
	if err := b.db.QueryRowContext(ctx, "SELECT name FROM applications WHERE id=$1", appID.String()).Scan(&name); err != nil {
		return m6ExecutionInput{}, nil, err
	}
	versions := map[string]string{"application": m6Digest(map[string]any{"id": appID.String(), "name": name}), "policy": "m6-policy-v1"}
	input := aicontext.Input{ApplicationID: appID, TaskType: taskType, Profile: m6APIProfile(settings.Profile), AuthorizedScopes: []string{aicontext.ScopeObjectVersions, aicontext.ScopeSecretMetadata}, RelevantObjectIDs: []string{"application", "policy"}, TemplateVersion: "context-v1"}
	if m6HasScope(settings.DataScopes, "source_excerpt") {
		path := filepath.Join(b.workspaceRoot, "Dockerfile")
		if file, err := os.Open(path); err == nil {
			data, readErr := io.ReadAll(io.LimitReader(file, (64<<10)+1))
			_ = file.Close()
			if readErr != nil {
				return m6ExecutionInput{}, nil, readErr
			}
			if len(data) > 64<<10 {
				data = data[:64<<10]
			}
			input.AuthorizedScopes = append(input.AuthorizedScopes, aicontext.ScopeSourceFiles)
			input.RelevantFiles = []string{"Dockerfile"}
			input.SourceFiles = []aicontext.SourceFile{{ApplicationID: appID, Scope: aicontext.ScopeSourceFiles, Path: "Dockerfile", Content: string(data), Untrusted: true}}
		}
	}
	if m6HasScope(settings.DataScopes, "build_log_summary") || m6HasScope(settings.DataScopes, "operations_summary") {
		var unhealthy int
		_ = b.db.QueryRowContext(ctx, "SELECT count(*) FROM m4_service_observations WHERE application_id=$1 AND NOT healthy", appID.String()).Scan(&unhealthy)
		input.AuthorizedScopes = append(input.AuthorizedScopes, aicontext.ScopeBuildLogs)
		input.RelevantLogSources = []string{"control-plane-summary"}
		now := b.nowUTC()
		input.Logs = []aicontext.LogWindow{{ApplicationID: appID, Scope: aicontext.ScopeBuildLogs, Source: "control-plane-summary", Start: now.Add(-time.Hour), End: now, Content: fmt.Sprintf("unhealthy_observation_count=%d", unhealthy), Untrusted: true}}
	}
	input.Objects = []aicontext.ObjectVersion{{ApplicationID: appID, Scope: aicontext.ScopeObjectVersions, Kind: "application", ID: appID.String(), Version: versions["application"]}, {ApplicationID: appID, Scope: aicontext.ScopeObjectVersions, Kind: "policy", ID: "m6-policy", Version: "m6-policy-v1"}}
	rows, err := b.db.QueryContext(ctx, "SELECT name,revoked_at IS NULL FROM secret_references WHERE application_id=$1 ORDER BY name LIMIT 32", appID.String())
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var secretName string
			var valid bool
			if scanErr := rows.Scan(&secretName, &valid); scanErr != nil {
				return m6ExecutionInput{}, nil, scanErr
			}
			input.Secrets = append(input.Secrets, aicontext.SecretFact{ApplicationID: appID, Scope: aicontext.ScopeSecretMetadata, Name: secretName, Exists: true, Verified: valid})
		}
		if rows.Err() != nil {
			return m6ExecutionInput{}, nil, rows.Err()
		}
	}
	return m6ExecutionInput{Context: input, Workspace: airunner.Workspace{Root: b.workspaceRoot, DraftRoot: "drafts", Production: false}}, versions, nil
}

func m6ResultFact(appID domain.ID, input M6AIRequest, result orchestrator.Result, now time.Time) M6AIInterventionFact {
	fact := M6AIInterventionFact{ApplicationID: appID.String(), TaskType: input.TaskType, Status: result.Status, Reason: foundation.RedactText(input.Reason), Summary: result.Status, Suggestion: result.ManualQuestion, RequiresUserAction: result.Degraded, ControllerHandoff: result.ControllerHandoff, CreatedAt: now.Format(time.RFC3339Nano)}
	if result.Ledger != nil {
		fact.ID = result.Ledger.ID.String()
		fact.Tokens = result.Ledger.Tokens
		fact.DurationMS = result.Ledger.DurationMS
		fact.RolledBack = result.Ledger.RolledBack
		fact.Evidence = append([]domain.EvidenceRef(nil), result.Ledger.Verification...)
	} else {
		fact.ID = "ai-" + input.IdempotencyKey
	}
	if result.Invocation != nil {
		fact.Provider = result.Invocation.Provider
		fact.Model = result.Invocation.Model
		fact.Profile = result.Invocation.Profile
		fact.ContextManifestDigest = result.Invocation.ContextDigest
	}
	if result.Plan != nil {
		plan := *result.Plan
		fact.Plan = &plan
	}
	if result.Candidate != nil {
		fact.RuleCandidateID = result.Candidate.ID.String()
	}
	if fact.Suggestion == "" {
		if result.Status == "succeeded" {
			fact.Suggestion = "Review the independently verified result or candidate diff"
		} else {
			fact.Suggestion = "Continue with deterministic rules or manual review"
		}
	}
	return fact
}

func m6InterventionFact(value ailedger.Intervention, operator bool) M6AIInterventionFact {
	status := value.Invocation.Outcome
	if decision, ok := value.Invocation.Payload["decision"].(string); ok && decision != "" {
		status = decision
	}
	fact := M6AIInterventionFact{ID: value.ID, ApplicationID: value.Invocation.ApplicationID, TaskType: value.Invocation.TaskType, Status: status, Reason: "deterministic rule fallback", Summary: "controlled AI " + status, Suggestion: "Review the independently verified evidence", RequiresUserAction: status != "succeeded", Provider: value.Invocation.Provider, Model: value.Invocation.Model, Profile: m6APIProfile(ailedger.Profile(value.Invocation.Profile)), Tokens: uint64(value.Invocation.Tokens), DurationMS: value.Invocation.DurationMS, CreatedAt: value.Invocation.CreatedAt.Format(time.RFC3339Nano)}
	if value.Outcome != nil {
		fact.RolledBack = value.Outcome.RolledBack
	}
	if value.CandidateRef != nil {
		fact.RuleCandidateID = value.CandidateRef.CandidateID
	}
	if !operator {
		fact.Provider = ""
		fact.Model = ""
		fact.Profile = ""
		return fact
	}
	if value.Context != nil {
		if digest, ok := value.Context.Payload["manifest_digest"].(string); ok {
			fact.ContextManifestDigest = digest
		}
	}
	if value.Plan != nil {
		actions := []domain.AIAction{}
		for _, item := range value.Actions {
			actions = append(actions, domain.AIAction{ToolID: item.ToolID, ToolVersion: item.ToolVersion, Parameters: item.Parameters, Risk: item.RiskClass, ExpectedResult: "redacted ledger action", ValidationID: item.ValidationID})
		}
		fact.Plan = &domain.AIActionPlan{ID: domain.ID(value.Plan.ID), SchemaVersion: value.Plan.SchemaVersion, PolicyVersion: value.Invocation.PolicyVersion, TaskType: value.Plan.TaskType, TargetRefs: value.Plan.TargetRefs, Sources: []string{"ledger:context"}, Assumptions: value.Plan.Assumptions, EvidenceRefs: []domain.EvidenceRef{{ID: "ev_ledger", Kind: "ledger", Digest: "sha256:ledger"}}, Actions: actions, Budget: domain.AIPlanBudget{MaxTokens: int(value.Invocation.Tokens), MaxDurationMS: value.Invocation.DurationMS, MaxActions: maxM6Int(len(actions), 1)}, RollbackID: value.Plan.RollbackID, Confidence: value.Plan.Confidence, RequiresUserConfirmation: value.Plan.RequiresUserConfirmation}
	}
	for _, verification := range value.Verifications {
		for _, ref := range verification.EvidenceRefs {
			fact.Evidence = append(fact.Evidence, domain.EvidenceRef{ID: domain.ID(ref.ID), Kind: ref.Kind, Digest: ref.Digest, Locator: ref.Locator})
		}
	}
	return fact
}

func m6ViewVersion(items []ailedger.Intervention) string {
	if len(items) == 0 {
		return "ai-v1:empty"
	}
	return "ai-v1:" + m6Digest(map[string]any{"id": items[0].ID, "at": items[0].Invocation.CreatedAt})[:24]
}
func m6Digest(value any) string { return "sha256:" + foundation.VersionKey(fmt.Sprint(value)) }
func m6HasScope(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func maxM6Int(left, right int) int {
	if left > right {
		return left
	}
	return right
}
func m6APIProfile(value ailedger.Profile) string {
	if value == ailedger.ProfileMainland {
		return "china"
	}
	return string(value)
}
func m6LedgerProfile(value string) (ailedger.Profile, error) {
	switch strings.TrimSpace(value) {
	case "china":
		return ailedger.ProfileMainland, nil
	case "global":
		return ailedger.ProfileGlobal, nil
	case "local":
		return ailedger.ProfileLocal, nil
	case "disabled":
		return ailedger.ProfileDisabled, nil
	default:
		return "", domain.NewError(domain.ErrValidation, "AI profile is unsupported")
	}
}

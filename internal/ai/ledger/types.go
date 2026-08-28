// Package ledger contains the durable evidence boundary for controlled AI.
//
// The package intentionally owns no provider, runner, controller, or domain
// state.  It records the facts produced by those components.  Every write is
// an append and every request has an idempotency key, so a process restart can
// replay a committed result without inventing a second intervention.
package ledger

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalid            = errors.New("invalid AI ledger record")
	ErrNotFound           = errors.New("AI ledger record not found")
	ErrConflict           = errors.New("AI ledger idempotency conflict")
	ErrInProgress         = errors.New("AI ledger request is already in progress")
	ErrImmutable          = errors.New("AI ledger records are immutable")
	ErrSensitivePlaintext = errors.New("sensitive plaintext is not allowed in AI ledger")
	ErrCorrupt            = errors.New("AI ledger record is corrupt")
)

const (
	OutcomePending    = "pending"
	OutcomeRunning    = "running"
	OutcomeSucceeded  = "succeeded"
	OutcomeFailed     = "failed"
	OutcomeRolledBack = "rolled_back"
	OutcomeUnknown    = "unknown"
)

// Reference is a content-addressed or otherwise redacted reference to a
// source fact.  It deliberately has no value/body field.
type Reference struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Digest  string `json:"digest,omitempty"`
	Locator string `json:"locator,omitempty"`
}

// ResourceUsage records measured execution resources.  Configured limits
// belong in ResourceBounds and are never inferred from these measurements.
type ResourceUsage struct {
	CPUSeconds      float64 `json:"cpu_seconds,omitempty"`
	MemoryBytes     int64   `json:"memory_bytes,omitempty"`
	DiskBytes       int64   `json:"disk_bytes,omitempty"`
	NetworkRxBytes  int64   `json:"network_rx_bytes,omitempty"`
	NetworkTxBytes  int64   `json:"network_tx_bytes,omitempty"`
	PeakMemoryBytes int64   `json:"peak_memory_bytes,omitempty"`
	ExitCode        int     `json:"exit_code,omitempty"`
}

type ResourceBounds struct {
	CPUSeconds  float64 `json:"cpu_seconds,omitempty"`
	MemoryBytes int64   `json:"memory_bytes,omitempty"`
	DiskBytes   int64   `json:"disk_bytes,omitempty"`
	TimeoutMS   int64   `json:"timeout_ms,omitempty"`
	Network     string  `json:"network,omitempty"`
}

// Invocation is the provider call identity and its cost/outcome summary.
// Payload is restricted to redacted structured metadata; raw prompts and
// provider responses must not be stored here.
type Invocation struct {
	ID                 string         `json:"id"`
	IdempotencyKey     string         `json:"idempotency_key"`
	RequestDigest      string         `json:"request_digest"`
	TaskType           string         `json:"task_type"`
	ApplicationID      string         `json:"application_id,omitempty"`
	ProblemFingerprint string         `json:"problem_fingerprint"`
	VersionKey         string         `json:"version_key"`
	CacheKey           string         `json:"cache_key,omitempty"`
	Provider           string         `json:"provider"`
	Model              string         `json:"model"`
	PolicyVersion      string         `json:"policy_version"`
	Profile            string         `json:"profile,omitempty"`
	PromptVersion      string         `json:"prompt_version,omitempty"`
	ContextDigest      string         `json:"context_digest,omitempty"`
	Cached             bool           `json:"cached,omitempty"`
	ContextID          string         `json:"context_id,omitempty"`
	Status             string         `json:"status"`
	Outcome            string         `json:"outcome,omitempty"`
	Tokens             int64          `json:"tokens"`
	DurationMS         int64          `json:"duration_ms"`
	Resource           ResourceUsage  `json:"resource"`
	CandidateID        string         `json:"candidate_id,omitempty"`
	Payload            map[string]any `json:"payload,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
}

type ContextPackage struct {
	ID              string            `json:"id"`
	InvocationID    string            `json:"invocation_id,omitempty"`
	IdempotencyKey  string            `json:"idempotency_key"`
	RequestDigest   string            `json:"request_digest"`
	ApplicationID   string            `json:"application_id,omitempty"`
	TaskType        string            `json:"task_type,omitempty"`
	Scope           []string          `json:"scope"`
	SourceRefs      []Reference       `json:"source_refs,omitempty"`
	Authorized      bool              `json:"authorized"`
	Redacted        bool              `json:"redacted"`
	TemplateVersion string            `json:"template_version"`
	Profile         string            `json:"profile,omitempty"`
	ObjectVersions  map[string]string `json:"object_versions,omitempty"`
	ManifestDigest  string            `json:"manifest_digest,omitempty"`
	Bytes           int64             `json:"bytes,omitempty"`
	UntrustedData   bool              `json:"untrusted_data"`
	Retention       string            `json:"retention,omitempty"`
	Payload         map[string]any    `json:"payload,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
}

type ActionPlan struct {
	ID                       string            `json:"id"`
	InvocationID             string            `json:"invocation_id,omitempty"`
	IdempotencyKey           string            `json:"idempotency_key"`
	RequestDigest            string            `json:"request_digest"`
	TaskType                 string            `json:"task_type"`
	PolicyVersion            string            `json:"policy_version,omitempty"`
	Sources                  []string          `json:"sources,omitempty"`
	TargetRefs               map[string]string `json:"target_refs"`
	Assumptions              []string          `json:"assumptions,omitempty"`
	EvidenceRefs             []Reference       `json:"evidence_refs"`
	Actions                  []string          `json:"action_ids,omitempty"`
	RollbackID               string            `json:"rollback_id,omitempty"`
	Confidence               float64           `json:"confidence"`
	RequiresUserConfirmation bool              `json:"requires_user_confirmation"`
	Budget                   PlanBudget        `json:"budget"`
	SchemaVersion            string            `json:"schema_version"`
	CreatedAt                time.Time         `json:"created_at"`
}

type PlanBudget struct {
	MaxTokens     int   `json:"max_tokens"`
	MaxDurationMS int64 `json:"max_duration_ms"`
	MaxActions    int   `json:"max_actions"`
}

type ToolAction struct {
	ID             string         `json:"id"`
	InvocationID   string         `json:"invocation_id,omitempty"`
	PlanID         string         `json:"plan_id,omitempty"`
	IdempotencyKey string         `json:"idempotency_key"`
	RequestDigest  string         `json:"request_digest"`
	Sequence       int            `json:"sequence"`
	ToolID         string         `json:"tool_id"`
	ToolVersion    string         `json:"tool_version"`
	Parameters     map[string]any `json:"parameters,omitempty"`
	ExpectedResult string         `json:"expected_result,omitempty"`
	WorkspaceRef   string         `json:"workspace_ref,omitempty"`
	RiskClass      string         `json:"risk_class"`
	ValidationID   string         `json:"validation_id"`
	Bounds         ResourceBounds `json:"bounds"`
	Network        string         `json:"network,omitempty"`
	TimeoutMS      int64          `json:"timeout_ms"`
	Status         string         `json:"status"`
	OutputDigest   string         `json:"output_digest,omitempty"`
	DiffDigest     string         `json:"diff_digest,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

type Verification struct {
	ID             string      `json:"id"`
	InvocationID   string      `json:"invocation_id,omitempty"`
	PlanID         string      `json:"plan_id,omitempty"`
	ActionID       string      `json:"action_id,omitempty"`
	IdempotencyKey string      `json:"idempotency_key"`
	RequestDigest  string      `json:"request_digest"`
	ValidatorID    string      `json:"validator_id"`
	Passed         bool        `json:"passed"`
	EvidenceRefs   []Reference `json:"evidence_refs"`
	Summary        string      `json:"summary,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
}

type Rollback struct {
	ID             string      `json:"id"`
	InvocationID   string      `json:"invocation_id,omitempty"`
	PlanID         string      `json:"plan_id,omitempty"`
	IdempotencyKey string      `json:"idempotency_key"`
	RequestDigest  string      `json:"request_digest"`
	RollbackID     string      `json:"rollback_id"`
	Status         string      `json:"status"`
	Reason         string      `json:"reason"`
	EvidenceRefs   []Reference `json:"evidence_refs,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
}

type Outcome struct {
	ID             string        `json:"id"`
	InvocationID   string        `json:"invocation_id"`
	IdempotencyKey string        `json:"idempotency_key"`
	RequestDigest  string        `json:"request_digest"`
	Status         string        `json:"status"`
	ExitCode       int           `json:"exit_code"`
	Summary        string        `json:"summary,omitempty"`
	UserConfirmed  bool          `json:"user_confirmed"`
	RolledBack     bool          `json:"rolled_back"`
	FailureCode    string        `json:"failure_code,omitempty"`
	Resource       ResourceUsage `json:"resource"`
	Tokens         int64         `json:"tokens"`
	DurationMS     int64         `json:"duration_ms"`
	CandidateID    string        `json:"candidate_id,omitempty"`
	CreatedAt      time.Time     `json:"created_at"`
}

type CandidateRef struct {
	ID             string    `json:"id"`
	InvocationID   string    `json:"invocation_id"`
	IdempotencyKey string    `json:"idempotency_key"`
	RequestDigest  string    `json:"request_digest"`
	CandidateID    string    `json:"candidate_id"`
	Fingerprint    string    `json:"fingerprint"`
	Aggregation    string    `json:"aggregation"`
	Status         string    `json:"status,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type Intervention struct {
	ID            string          `json:"id"`
	Invocation    Invocation      `json:"invocation"`
	Context       *ContextPackage `json:"context,omitempty"`
	Plan          *ActionPlan     `json:"plan,omitempty"`
	Actions       []ToolAction    `json:"actions,omitempty"`
	Verifications []Verification  `json:"verifications,omitempty"`
	Rollback      *Rollback       `json:"rollback,omitempty"`
	Outcome       *Outcome        `json:"outcome,omitempty"`
	CandidateRef  *CandidateRef   `json:"candidate_ref,omitempty"`
}

type AppendInvocationRequest struct {
	IdempotencyKey string
	RequestDigest  string
	Record         Invocation
}
type AppendContextRequest struct {
	IdempotencyKey string
	RequestDigest  string
	Record         ContextPackage
}
type AppendPlanRequest struct {
	IdempotencyKey string
	RequestDigest  string
	Record         ActionPlan
}
type AppendToolActionRequest struct {
	IdempotencyKey string
	RequestDigest  string
	Record         ToolAction
}
type AppendVerificationRequest struct {
	IdempotencyKey string
	RequestDigest  string
	Record         Verification
}
type AppendRollbackRequest struct {
	IdempotencyKey string
	RequestDigest  string
	Record         Rollback
}
type AppendOutcomeRequest struct {
	IdempotencyKey string
	RequestDigest  string
	Record         Outcome
}
type AppendCandidateRefRequest struct {
	IdempotencyKey string
	RequestDigest  string
	Record         CandidateRef
}

type AppendInterventionRequest struct {
	IdempotencyKey string
	RequestDigest  string
	Record         Intervention
}

type QueryFilter struct {
	ApplicationID string
	TaskType      string
	Outcome       string
	CandidateID   string
	From          time.Time
	To            time.Time
	Limit         int
}

type Metrics struct {
	Interventions      int64 `json:"interventions"`
	Succeeded          int64 `json:"succeeded"`
	Failed             int64 `json:"failed"`
	RolledBack         int64 `json:"rolled_back"`
	VerificationFailed int64 `json:"verification_failed"`
	Tokens             int64 `json:"tokens"`
	DurationMS         int64 `json:"duration_ms"`
	CandidateRefs      int64 `json:"candidate_refs"`
	DistinctCandidates int64 `json:"distinct_candidates"`
}

// Repository is implemented by LocalStore and PostgresStore.  The explicit
// append methods are useful to controllers that checkpoint between phases;
// AppendIntervention is the atomic convenience path for a complete run.
type Repository interface {
	AppendInvocation(context.Context, AppendInvocationRequest) (Invocation, bool, error)
	AppendContext(context.Context, AppendContextRequest) (ContextPackage, bool, error)
	AppendPlan(context.Context, AppendPlanRequest) (ActionPlan, bool, error)
	AppendToolAction(context.Context, AppendToolActionRequest) (ToolAction, bool, error)
	AppendVerification(context.Context, AppendVerificationRequest) (Verification, bool, error)
	AppendRollback(context.Context, AppendRollbackRequest) (Rollback, bool, error)
	AppendOutcome(context.Context, AppendOutcomeRequest) (Outcome, bool, error)
	AppendCandidateRef(context.Context, AppendCandidateRefRequest) (CandidateRef, bool, error)
	AppendIntervention(context.Context, AppendInterventionRequest) (Intervention, bool, error)
	GetIntervention(context.Context, string) (Intervention, error)
	Query(context.Context, QueryFilter) ([]Intervention, error)
	Metrics(context.Context, QueryFilter) (Metrics, error)
	AppendSettings(context.Context, SettingsRequest) (AISettings, bool, error)
	CurrentSettings(context.Context) (AISettings, error)
}

// AIInterventionLedger is the semantic name used by the architecture
// documents; Repository is retained as the concise Go composition name.
type AIInterventionLedger = Repository
type LocalLedger = LocalStore

// LocalStore is a restart-safe in-process implementation.  Snapshot returns
// an immutable JSON snapshot; NewLocalFromSnapshot reconstructs the same
// append-only facts after a process restart.
type LocalStore struct {
	mu            sync.RWMutex
	invocations   map[string]Invocation
	contexts      map[string]ContextPackage
	plans         map[string]ActionPlan
	actions       map[string]ToolAction
	verifications map[string]Verification
	rollbacks     map[string]Rollback
	outcomes      map[string]Outcome
	candidates    map[string]CandidateRef
	interventions map[string]Intervention
	settings      []AISettings
	keys          map[string]idempotencyEntry
}

type idempotencyEntry struct {
	Digest string `json:"digest"`
	Kind   string `json:"kind"`
	ID     string `json:"id"`
}

type snapshot struct {
	Invocations   []Invocation                `json:"invocations"`
	Contexts      []ContextPackage            `json:"contexts"`
	Plans         []ActionPlan                `json:"plans"`
	Actions       []ToolAction                `json:"actions"`
	Verifications []Verification              `json:"verifications"`
	Rollbacks     []Rollback                  `json:"rollbacks"`
	Outcomes      []Outcome                   `json:"outcomes"`
	Candidates    []CandidateRef              `json:"candidate_refs"`
	Interventions []Intervention              `json:"interventions"`
	Settings      []AISettings                `json:"settings"`
	Keys          map[string]idempotencyEntry `json:"keys"`
}

func NewLocal() *LocalStore {
	return &LocalStore{
		invocations: make(map[string]Invocation), contexts: make(map[string]ContextPackage), plans: make(map[string]ActionPlan),
		actions: make(map[string]ToolAction), verifications: make(map[string]Verification), rollbacks: make(map[string]Rollback),
		outcomes: make(map[string]Outcome), candidates: make(map[string]CandidateRef), interventions: make(map[string]Intervention),
		keys: make(map[string]idempotencyEntry),
	}
}

func NewMemory() *LocalStore { return NewLocal() }

func (s *LocalStore) Snapshot() ([]byte, error) {
	if s == nil {
		return nil, ErrInvalid
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	value := snapshot{Keys: make(map[string]idempotencyEntry, len(s.keys))}
	for _, item := range s.invocations {
		value.Invocations = append(value.Invocations, cloneInvocation(item))
	}
	for _, item := range s.contexts {
		value.Contexts = append(value.Contexts, cloneContext(item))
	}
	for _, item := range s.plans {
		value.Plans = append(value.Plans, clonePlan(item))
	}
	for _, item := range s.actions {
		value.Actions = append(value.Actions, cloneAction(item))
	}
	for _, item := range s.verifications {
		value.Verifications = append(value.Verifications, cloneVerification(item))
	}
	for _, item := range s.rollbacks {
		value.Rollbacks = append(value.Rollbacks, cloneRollback(item))
	}
	for _, item := range s.outcomes {
		value.Outcomes = append(value.Outcomes, cloneOutcome(item))
	}
	for _, item := range s.candidates {
		value.Candidates = append(value.Candidates, item)
	}
	for _, item := range s.interventions {
		value.Interventions = append(value.Interventions, cloneIntervention(item))
	}
	value.Settings = append(value.Settings, s.settings...)
	for key, item := range s.keys {
		value.Keys[key] = item
	}
	return json.Marshal(value)
}

func NewLocalFromSnapshot(data []byte) (*LocalStore, error) {
	var value snapshot
	if len(data) == 0 || json.Unmarshal(data, &value) != nil {
		return nil, fmt.Errorf("%w: invalid local ledger snapshot", ErrCorrupt)
	}
	s := NewLocal()
	for _, item := range value.Invocations {
		s.invocations[item.ID] = cloneInvocation(item)
	}
	for _, item := range value.Contexts {
		s.contexts[item.ID] = cloneContext(item)
	}
	for _, item := range value.Plans {
		s.plans[item.ID] = clonePlan(item)
	}
	for _, item := range value.Actions {
		s.actions[item.ID] = cloneAction(item)
	}
	for _, item := range value.Verifications {
		s.verifications[item.ID] = cloneVerification(item)
	}
	for _, item := range value.Rollbacks {
		s.rollbacks[item.ID] = cloneRollback(item)
	}
	for _, item := range value.Outcomes {
		s.outcomes[item.ID] = cloneOutcome(item)
	}
	for _, item := range value.Candidates {
		s.candidates[item.ID] = item
	}
	for _, item := range value.Interventions {
		s.interventions[item.ID] = cloneIntervention(item)
	}
	s.settings = append(s.settings, value.Settings...)
	for key, item := range value.Keys {
		s.keys[key] = item
	}
	return s, nil
}

// Digest returns the stable request digest used when a caller does not have a
// precomputed digest.  JSON object keys are sorted by encoding/json.
func Digest(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func normalizeRequest(key, digest string, value any, id string) (string, string, error) {
	key, digest = strings.TrimSpace(key), strings.TrimSpace(digest)
	if key == "" {
		key = strings.TrimSpace(id)
	}
	if key == "" {
		return "", "", fmt.Errorf("%w: idempotency key is required", ErrInvalid)
	}
	if digest == "" {
		digest = Digest(value)
	}
	if digest == "" {
		return "", "", fmt.Errorf("%w: request digest is required", ErrInvalid)
	}
	return key, digest, nil
}

func ensureID(prefix, id, key, digest string) string {
	if id = strings.TrimSpace(id); id != "" {
		return id
	}
	sum := sha256.Sum256([]byte(prefix + "\x00" + key + "\x00" + digest))
	return prefix + "_" + hex.EncodeToString(sum[:])[:24]
}

func validOutcome(value string) bool {
	switch strings.TrimSpace(value) {
	case "", OutcomePending, OutcomeRunning, OutcomeSucceeded, OutcomeFailed, OutcomeRolledBack, OutcomeUnknown:
		return true
	}
	return false
}

func validNonNegative(resource ResourceUsage) bool {
	return !math.IsNaN(resource.CPUSeconds) && !math.IsInf(resource.CPUSeconds, 0) && resource.CPUSeconds >= 0 && resource.MemoryBytes >= 0 && resource.DiskBytes >= 0 && resource.NetworkRxBytes >= 0 && resource.NetworkTxBytes >= 0 && resource.PeakMemoryBytes >= 0
}

func validateReference(ref Reference) error {
	if strings.TrimSpace(ref.ID) == "" || strings.TrimSpace(ref.Kind) == "" {
		return fmt.Errorf("%w: evidence reference identity is required", ErrInvalid)
	}
	if err := ValidateNoPlaintext(ref); err != nil {
		return err
	}
	return nil
}

func validateInvocation(record Invocation) error {
	if strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.TaskType) == "" || strings.TrimSpace(record.Provider) == "" || strings.TrimSpace(record.Model) == "" || strings.TrimSpace(record.PolicyVersion) == "" || strings.TrimSpace(record.ProblemFingerprint) == "" || strings.TrimSpace(record.VersionKey) == "" || !validOutcome(record.Status) || !validOutcome(record.Outcome) || record.Tokens < 0 || record.DurationMS < 0 || !validNonNegative(record.Resource) || record.CreatedAt.IsZero() {
		return fmt.Errorf("%w: invocation fields are incomplete", ErrInvalid)
	}
	return ValidateNoPlaintext(record)
}

func validateContext(record ContextPackage) error {
	if strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.TemplateVersion) == "" || !record.Authorized || !record.Redacted || record.CreatedAt.IsZero() || len(record.Scope) == 0 {
		return fmt.Errorf("%w: context must be authorized, scoped, and redacted", ErrInvalid)
	}
	for _, ref := range record.SourceRefs {
		if err := validateReference(ref); err != nil {
			return err
		}
	}
	return ValidateNoPlaintext(record)
}

func validatePlan(record ActionPlan) error {
	if strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.TaskType) == "" || len(record.TargetRefs) == 0 || len(record.Actions) == 0 || strings.TrimSpace(record.SchemaVersion) == "" || math.IsNaN(record.Confidence) || math.IsInf(record.Confidence, 0) || record.Confidence < 0 || record.Confidence > 1 || record.CreatedAt.IsZero() {
		return fmt.Errorf("%w: action plan schema is incomplete", ErrInvalid)
	}
	for key, value := range record.TargetRefs {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: action plan target reference is empty", ErrInvalid)
		}
	}
	for _, ref := range record.EvidenceRefs {
		if err := validateReference(ref); err != nil {
			return err
		}
	}
	return ValidateNoPlaintext(record)
}

func validateAction(record ToolAction) error {
	if strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.ToolID) == "" || strings.TrimSpace(record.ToolVersion) == "" || strings.TrimSpace(record.RiskClass) == "" || strings.TrimSpace(record.ValidationID) == "" || strings.TrimSpace(record.Status) == "" || record.Sequence < 0 || record.TimeoutMS < 0 || !validNonNegative(ResourceUsage{CPUSeconds: record.Bounds.CPUSeconds, MemoryBytes: record.Bounds.MemoryBytes, DiskBytes: record.Bounds.DiskBytes}) || record.CreatedAt.IsZero() {
		return fmt.Errorf("%w: tool action is incomplete", ErrInvalid)
	}
	return ValidateNoPlaintext(record)
}

func validateVerification(record Verification) error {
	if strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.ValidatorID) == "" || record.CreatedAt.IsZero() {
		return fmt.Errorf("%w: verification is incomplete", ErrInvalid)
	}
	for _, ref := range record.EvidenceRefs {
		if err := validateReference(ref); err != nil {
			return err
		}
	}
	return ValidateNoPlaintext(record)
}

func validateRollback(record Rollback) error {
	if strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.RollbackID) == "" || strings.TrimSpace(record.Status) == "" || strings.TrimSpace(record.Reason) == "" || record.CreatedAt.IsZero() {
		return fmt.Errorf("%w: rollback is incomplete", ErrInvalid)
	}
	for _, ref := range record.EvidenceRefs {
		if err := validateReference(ref); err != nil {
			return err
		}
	}
	return ValidateNoPlaintext(record)
}

func validateOutcome(record Outcome) error {
	if strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.InvocationID) == "" || !validOutcome(record.Status) || record.Status == "" || record.Tokens < 0 || record.DurationMS < 0 || !validNonNegative(record.Resource) || record.CreatedAt.IsZero() {
		return fmt.Errorf("%w: outcome is incomplete", ErrInvalid)
	}
	for _, value := range []string{record.Summary, record.FailureCode} {
		if strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("%w: outcome text is invalid", ErrInvalid)
		}
	}
	return ValidateNoPlaintext(record)
}

func validateCandidateRef(record CandidateRef) error {
	if strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.InvocationID) == "" || strings.TrimSpace(record.CandidateID) == "" || strings.TrimSpace(record.Fingerprint) == "" || strings.TrimSpace(record.Aggregation) == "" || record.CreatedAt.IsZero() {
		return fmt.Errorf("%w: candidate reference is incomplete", ErrInvalid)
	}
	return ValidateNoPlaintext(record)
}

func validateIntervention(record Intervention) error {
	if err := validateInvocation(record.Invocation); err != nil {
		return err
	}
	if record.Context != nil {
		if err := validateContext(*record.Context); err != nil {
			return err
		}
	}
	if record.Plan != nil {
		if err := validatePlan(*record.Plan); err != nil {
			return err
		}
	}
	for _, item := range record.Actions {
		if err := validateAction(item); err != nil {
			return err
		}
	}
	for _, item := range record.Verifications {
		if err := validateVerification(item); err != nil {
			return err
		}
	}
	if record.Rollback != nil {
		if err := validateRollback(*record.Rollback); err != nil {
			return err
		}
	}
	if record.Outcome != nil {
		if err := validateOutcome(*record.Outcome); err != nil {
			return err
		}
	}
	if record.CandidateRef != nil {
		if err := validateCandidateRef(*record.CandidateRef); err != nil {
			return err
		}
	}
	return ValidateNoPlaintext(record)
}

func cloneInvocation(value Invocation) Invocation {
	value.Payload = cloneMap(value.Payload)
	return value
}
func cloneContext(value ContextPackage) ContextPackage {
	value.Scope = append([]string(nil), value.Scope...)
	value.SourceRefs = append([]Reference(nil), value.SourceRefs...)
	value.ObjectVersions = cloneStringMap(value.ObjectVersions)
	value.Payload = cloneMap(value.Payload)
	return value
}
func clonePlan(value ActionPlan) ActionPlan {
	value.TargetRefs = cloneStringMap(value.TargetRefs)
	value.Sources = append([]string(nil), value.Sources...)
	value.Assumptions = append([]string(nil), value.Assumptions...)
	value.EvidenceRefs = append([]Reference(nil), value.EvidenceRefs...)
	value.Actions = append([]string(nil), value.Actions...)
	return value
}
func cloneAction(value ToolAction) ToolAction {
	value.Parameters = cloneMap(value.Parameters)
	return value
}
func cloneVerification(value Verification) Verification {
	value.EvidenceRefs = append([]Reference(nil), value.EvidenceRefs...)
	return value
}
func cloneRollback(value Rollback) Rollback {
	value.EvidenceRefs = append([]Reference(nil), value.EvidenceRefs...)
	return value
}
func cloneOutcome(value Outcome) Outcome { return value }
func cloneIntervention(value Intervention) Intervention {
	value.Invocation = cloneInvocation(value.Invocation)
	if value.Context != nil {
		copy := cloneContext(*value.Context)
		value.Context = &copy
	}
	if value.Plan != nil {
		copy := clonePlan(*value.Plan)
		value.Plan = &copy
	}
	actions := value.Actions
	value.Actions = make([]ToolAction, len(actions))
	for i, item := range actions {
		value.Actions[i] = cloneAction(item)
	}
	verifications := value.Verifications
	value.Verifications = make([]Verification, len(verifications))
	for i, item := range verifications {
		value.Verifications[i] = cloneVerification(item)
	}
	if value.Rollback != nil {
		copy := cloneRollback(*value.Rollback)
		value.Rollback = &copy
	}
	if value.Outcome != nil {
		copy := cloneOutcome(*value.Outcome)
		value.Outcome = &copy
	}
	if value.CandidateRef != nil {
		copy := *value.CandidateRef
		value.CandidateRef = &copy
	}
	return value
}
func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = cloneValue(value)
	}
	return out
}
func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = cloneValue(item)
		}
		return out
	default:
		return typed
	}
}
func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 1000
	}
	if limit > 10000 {
		return 10000
	}
	return limit
}

func sortReferences(refs []Reference) []Reference {
	out := append([]Reference(nil), refs...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Keep database/sql in this file's public import graph for callers that use a
// nil *sql.DB check with the shared constructor helpers in postgres.go.
var _ = sql.ErrNoRows

// Ensure implementations stay in sync if one of the explicit methods drifts.
var _ Repository = (*LocalStore)(nil)

// Context cancellation is checked by both implementations before a write.
func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

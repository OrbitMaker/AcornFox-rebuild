// Package rules owns the reviewed, versioned deterministic-rule boundary.
// Candidate observations are useful evidence but never become active code by
// themselves.  A RuleVersion is immutable; enable/disable/rollback are
// append-only registry events resolved to a current view.
package rules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalid           = errors.New("invalid deterministic rule record")
	ErrNotFound          = errors.New("rule record not found")
	ErrConflict          = errors.New("rule idempotency conflict")
	ErrInvalidTransition = errors.New("invalid rule candidate transition")
	ErrPromotionGate     = errors.New("rule promotion gate is incomplete")
	ErrNoPrevious        = errors.New("no previous enabled rule version")
	ErrDisabled          = errors.New("rule version is disabled")
	ErrImmutable         = errors.New("rule versions are immutable")
	ErrCorrupt           = errors.New("rule record is corrupt")
)

const (
	MinSuccessCount     int64 = 2
	MinApplicationCount int64 = 1
)

type Status string

const (
	StatusDraft    Status = "draft"
	StatusTesting  Status = "testing"
	StatusReviewed Status = "reviewed"
	StatusShadow   Status = "shadow"
	StatusApproved Status = "approved"
	StatusPromoted Status = "promoted"
)

const (
	Draft    = StatusDraft
	Testing  = StatusTesting
	Reviewed = StatusReviewed
	Shadow   = StatusShadow
	Approved = StatusApproved
	Promoted = StatusPromoted
)

const (
	RuleCandidateDraft    = StatusDraft
	RuleCandidateTesting  = StatusTesting
	RuleCandidateReviewed = StatusReviewed
	RuleCandidateShadow   = StatusShadow
	RuleCandidateApproved = StatusApproved
	RuleCandidatePromoted = StatusPromoted
)

type EvidenceRef struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Digest  string `json:"digest,omitempty"`
	Locator string `json:"locator,omitempty"`
}

type RuleCandidate struct {
	ID               string        `json:"id"`
	Fingerprint      string        `json:"fingerprint"`
	Name             string        `json:"name,omitempty"`
	Status           Status        `json:"status"`
	SuccessCount     int64         `json:"success_count"`
	ApplicationCount int64         `json:"application_count"`
	RegressionPassed bool          `json:"regression_passed"`
	ShadowPassed     bool          `json:"shadow_passed"`
	ReviewDecision   string        `json:"review_decision,omitempty"`
	ReviewedBy       string        `json:"reviewed_by,omitempty"`
	ProposedVersion  string        `json:"proposed_version,omitempty"`
	TestEvidence     []EvidenceRef `json:"test_evidence,omitempty"`
	CreatedAt        time.Time     `json:"created_at"`
	UpdatedAt        time.Time     `json:"updated_at"`
}

type Candidate = RuleCandidate

type Observation struct {
	ID             string
	IdempotencyKey string
	RequestDigest  string
	Fingerprint    string
	Name           string
	InvocationID   string
	ApplicationID  string
	Success        bool
	Evidence       []EvidenceRef
	At             time.Time
}

type TransitionRequest struct {
	CandidateID      string
	To               Status
	IdempotencyKey   string
	RequestDigest    string
	Actor            string
	Reason           string
	ReviewDecision   string
	RegressionPassed bool
	ShadowPassed     bool
	ReviewedBy       string
	ProposedVersion  string
	TestEvidence     []EvidenceRef
	At               time.Time
}

type EvaluationEvidence struct {
	ID             string        `json:"id"`
	CandidateID    string        `json:"candidate_id"`
	TestName       string        `json:"test_name"`
	Passed         bool          `json:"passed"`
	Kind           string        `json:"kind,omitempty"`
	Evidence       []EvidenceRef `json:"evidence,omitempty"`
	IdempotencyKey string        `json:"idempotency_key"`
	RequestDigest  string        `json:"request_digest"`
	CreatedAt      time.Time     `json:"created_at"`
}

type RuleVersion struct {
	ID          string         `json:"id"`
	CandidateID string         `json:"candidate_id"`
	Fingerprint string         `json:"fingerprint"`
	Version     string         `json:"version"`
	CodeDigest  string         `json:"code_digest"`
	Definition  map[string]any `json:"definition,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

type Version = RuleVersion

type PromotionRequest struct {
	CandidateID    string
	Version        string
	CodeDigest     string
	Definition     map[string]any
	IdempotencyKey string
	RequestDigest  string
	Actor          string
	Reason         string
	At             time.Time
}

type RegistryRequest struct {
	RuleVersionID  string
	IdempotencyKey string
	RequestDigest  string
	Actor          string
	Reason         string
	At             time.Time
}

type RegistryEvent struct {
	ID             string    `json:"id"`
	RuleVersionID  string    `json:"rule_version_id"`
	CandidateID    string    `json:"candidate_id"`
	Fingerprint    string    `json:"fingerprint"`
	Kind           string    `json:"kind"`
	PreviousID     string    `json:"previous_id,omitempty"`
	IdempotencyKey string    `json:"idempotency_key"`
	RequestDigest  string    `json:"request_digest"`
	Actor          string    `json:"actor"`
	Reason         string    `json:"reason"`
	CreatedAt      time.Time `json:"created_at"`
}

type Metrics struct {
	Candidates       int64 `json:"candidates"`
	Draft            int64 `json:"draft"`
	Testing          int64 `json:"testing"`
	Reviewed         int64 `json:"reviewed"`
	Shadow           int64 `json:"shadow"`
	Approved         int64 `json:"approved"`
	Promoted         int64 `json:"promoted"`
	Versions         int64 `json:"versions"`
	EnabledVersions  int64 `json:"enabled_versions"`
	DisabledVersions int64 `json:"disabled_versions"`
	Rollbacks        int64 `json:"rollbacks"`
	Observations     int64 `json:"observations"`
	Successes        int64 `json:"successes"`
}

type Registry interface {
	Aggregate(context.Context, Observation) (RuleCandidate, bool, error)
	GetCandidate(context.Context, string) (RuleCandidate, error)
	Transition(context.Context, TransitionRequest) (RuleCandidate, error)
	RecordEvaluation(context.Context, EvaluationEvidence) (EvaluationEvidence, bool, error)
	Promote(context.Context, PromotionRequest) (RuleVersion, bool, error)
	Enable(context.Context, RegistryRequest) (RuleVersion, error)
	Disable(context.Context, RegistryRequest) (RuleVersion, error)
	Rollback(context.Context, RegistryRequest) (RuleVersion, error)
	Active(context.Context, string) (RuleVersion, error)
	Metrics(context.Context) (Metrics, error)
}

type RuleRegistry = Registry
type Local = LocalRegistry
type Postgres = PostgresRegistry

type LocalRegistry struct {
	mu           sync.RWMutex
	candidates   map[string]RuleCandidate
	observations map[string]Observation
	evaluations  map[string]EvaluationEvidence
	versions     map[string]RuleVersion
	events       []RegistryEvent
	keys         map[string]string
}

func NewLocal() *LocalRegistry {
	return &LocalRegistry{candidates: make(map[string]RuleCandidate), observations: make(map[string]Observation), evaluations: make(map[string]EvaluationEvidence), versions: make(map[string]RuleVersion), keys: make(map[string]string)}
}
func NewMemory() *LocalRegistry { return NewLocal() }

func NewCandidate(fingerprint string, now time.Time) (RuleCandidate, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return RuleCandidate{}, fmt.Errorf("%w: fingerprint is required", ErrInvalid)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	id := deterministicID("candidate", fingerprint, now.UTC().String())
	c := RuleCandidate{ID: id, Fingerprint: fingerprint, Status: StatusDraft, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	return c, c.Validate()
}

func (c RuleCandidate) Validate() error {
	if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.Fingerprint) == "" {
		return fmt.Errorf("%w: candidate identity is required", ErrInvalid)
	}
	switch c.Status {
	case StatusDraft, StatusTesting, StatusReviewed, StatusShadow, StatusApproved, StatusPromoted:
	default:
		return fmt.Errorf("%w: unsupported candidate status %q", ErrInvalid, c.Status)
	}
	if c.SuccessCount < 0 || c.ApplicationCount < 0 {
		return fmt.Errorf("%w: candidate counts are invalid", ErrInvalid)
	}
	if requiresReview(c.Status) && (strings.TrimSpace(c.ReviewedBy) == "" || strings.TrimSpace(c.ReviewDecision) == "") {
		return fmt.Errorf("%w: reviewed candidate requires reviewer and decision", ErrPromotionGate)
	}
	if (c.Status == StatusShadow || c.Status == StatusApproved || c.Status == StatusPromoted) && (!c.RegressionPassed || len(c.TestEvidence) == 0) {
		return fmt.Errorf("%w: regression evidence is required", ErrPromotionGate)
	}
	if (c.Status == StatusApproved || c.Status == StatusPromoted) && !c.ShadowPassed {
		return fmt.Errorf("%w: shadow evidence is required", ErrPromotionGate)
	}
	if (c.Status == StatusApproved || c.Status == StatusPromoted) && strings.TrimSpace(c.ProposedVersion) == "" {
		return fmt.Errorf("%w: version is required", ErrPromotionGate)
	}
	if c.Status == StatusPromoted && len(c.TestEvidence) == 0 {
		return fmt.Errorf("%w: promoted candidate requires test evidence", ErrPromotionGate)
	}
	for _, ref := range c.TestEvidence {
		if strings.TrimSpace(ref.ID) == "" || strings.TrimSpace(ref.Kind) == "" {
			return fmt.Errorf("%w: test evidence reference is incomplete", ErrInvalid)
		}
	}
	return validateSafe(c)
}

func requiresReview(status Status) bool {
	switch status {
	case StatusReviewed, StatusShadow, StatusApproved, StatusPromoted:
		return true
	default:
		return false
	}
}

func (c RuleCandidate) CanTransition(to Status) bool {
	switch c.Status {
	case StatusDraft:
		return to == StatusTesting
	case StatusTesting:
		return to == StatusReviewed
	case StatusReviewed:
		return to == StatusShadow
	case StatusShadow:
		return to == StatusApproved
	case StatusApproved:
		return to == StatusPromoted
	default:
		return false
	}
}

func (c *RuleCandidate) Transition(to Status) error {
	if c == nil {
		return ErrInvalid
	}
	if !c.CanTransition(to) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, c.Status, to)
	}
	c.Status = to
	return c.Validate()
}

func (c RuleCandidate) CanPromote() error {
	if c.SuccessCount < MinSuccessCount || c.ApplicationCount < MinApplicationCount {
		return fmt.Errorf("%w: minimum successful cases and application coverage are required", ErrPromotionGate)
	}
	if c.Status != StatusApproved {
		return fmt.Errorf("%w: candidate must be approved", ErrPromotionGate)
	}
	if !c.RegressionPassed || !c.ShadowPassed || strings.TrimSpace(c.ReviewedBy) == "" || strings.TrimSpace(c.ReviewDecision) == "" || strings.TrimSpace(c.ProposedVersion) == "" || len(c.TestEvidence) == 0 {
		return ErrPromotionGate
	}
	return nil
}

func validateSafe(value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var decoded any
	if json.Unmarshal(data, &decoded) != nil {
		return ErrInvalid
	}
	if containsSecret(decoded, "$") {
		return errors.New("sensitive plaintext is not allowed in rules")
	}
	return nil
}
func containsSecret(value any, path string) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			normalized := strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(key))
			if normalized == "token" || normalized == "password" || normalized == "secret" || normalized == "apikey" || normalized == "privatekey" || normalized == "authorization" || normalized == "cookie" {
				if text, ok := item.(string); !ok || (!strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), "ref:") && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), "sha256:") && strings.TrimSpace(text) != "[REDACTED]") {
					return true
				}
			}
			if containsSecret(item, path+"."+key) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if containsSecret(item, path+"[]") {
				return true
			}
		}
	case string:
		lower := strings.ToLower(typed)
		return strings.Contains(lower, "-----begin") || strings.Contains(lower, "bearer ")
	}
	return false
}

func deterministicID(prefix string, values ...string) string {
	h := sha256.New()
	for _, value := range values {
		_, _ = h.Write([]byte(value))
		_, _ = h.Write([]byte{0})
	}
	return prefix + "_" + hex.EncodeToString(h.Sum(nil))[:24]
}

func normalizeTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}
func requestDigest(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
func ensureRequest(key, digest string, value any, id string) (string, string, error) {
	key = firstNonEmpty(key, id)
	if key == "" {
		return "", "", fmt.Errorf("%w: idempotency key is required", ErrInvalid)
	}
	digest = firstNonEmpty(digest, requestDigest(value))
	return key, digest, nil
}
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

var _ Registry = (*LocalRegistry)(nil)
var _ = math.IsNaN

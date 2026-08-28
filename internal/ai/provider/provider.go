// Package provider contains the local, deterministic AI provider used by the
// M6 fake contract suite.  It deliberately has no model client, network
// transport, or production control-plane handle.  The package is a provider
// boundary: callers receive a structured plan or a classified degradation and
// must decide how to continue the normal controller flow.
package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

// Profile is the data-boundary profile selected by the instance administrator.
// The fake provider implements all profiles locally; the profile never implies
// that a real remote model or network endpoint is available.
type Profile string

const (
	ProfileChina    Profile = "china"
	ProfileGlobal   Profile = "global"
	ProfileLocal    Profile = "local"
	ProfileDisabled Profile = "disabled"
	ProfileCN       Profile = ProfileChina
	ProfileOff      Profile = ProfileDisabled

	// Short aliases keep call sites readable while preserving the serialized
	// profile values above.
	China    = ProfileChina
	Global   = ProfileGlobal
	Local    = ProfileLocal
	Disabled = ProfileDisabled
)

func (p Profile) String() string { return string(p) }

func (p Profile) Valid() bool {
	switch p {
	case ProfileChina, ProfileGlobal, ProfileLocal, ProfileDisabled:
		return true
	default:
		return false
	}
}

// ParseProfile accepts the product-facing names and a few stable display
// spellings. Unknown values are rejected instead of silently selecting a
// broader data boundary.
func ParseProfile(value string) (Profile, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "china", "cn", "mainland", "中国大陆", "中国":
		return ProfileChina, nil
	case "global", "worldwide", "全球":
		return ProfileGlobal, nil
	case "local", "on-premise", "on_premise", "本地":
		return ProfileLocal, nil
	case "disabled", "off", "none", "关闭":
		return ProfileDisabled, nil
	default:
		return "", fmt.Errorf("unsupported AI profile %q", value)
	}
}

// Capability names are intentionally provider-local. The contracts package
// exposes the coarse ai.structured capability; these names describe the
// profile matrix without changing that shared contract.
type Capability string

const (
	CapabilityStructuredOutput Capability = "structured_output"
	CapabilityToolPlanning     Capability = "tool_planning"
	CapabilityContextWindow    Capability = "context_window"
	CapabilityLocalData        Capability = "local_data_boundary"
)

// Capabilities is the declared, non-secret capability matrix for a profile.
// ExternalNetwork is always false for this implementation.
type Capabilities struct {
	StructuredOutput bool    `json:"structured_output"`
	ToolPlanning     bool    `json:"tool_planning"`
	ContextWindow    int     `json:"context_window"`
	Region           Profile `json:"region"`
	DataBoundary     string  `json:"data_boundary"`
	Available        bool    `json:"available"`
	ExternalNetwork  bool    `json:"external_network"`
	LocalOnly        bool    `json:"local_only"`
}

func (c Capabilities) Has(capability Capability) bool {
	switch capability {
	case CapabilityStructuredOutput:
		return c.StructuredOutput
	case CapabilityToolPlanning:
		return c.ToolPlanning
	case CapabilityContextWindow:
		return c.ContextWindow > 0
	case CapabilityLocalData:
		return c.LocalOnly
	default:
		return false
	}
}

func (c Capabilities) List() []Capability {
	result := make([]Capability, 0, 4)
	if c.StructuredOutput {
		result = append(result, CapabilityStructuredOutput)
	}
	if c.ToolPlanning {
		result = append(result, CapabilityToolPlanning)
	}
	if c.ContextWindow > 0 {
		result = append(result, CapabilityContextWindow)
	}
	if c.LocalOnly {
		result = append(result, CapabilityLocalData)
	}
	return result
}

// CapabilitiesFor is the stable profile matrix. All profiles use the same
// local fake implementation, but data-boundary declarations remain visible to
// policy code. Disabled has no callable capability.
func CapabilitiesFor(profile Profile) Capabilities {
	switch profile {
	case ProfileChina:
		return Capabilities{StructuredOutput: true, ToolPlanning: true, ContextWindow: 16 * 1024, Region: profile, DataBoundary: "mainland", Available: true}
	case ProfileGlobal:
		return Capabilities{StructuredOutput: true, ToolPlanning: true, ContextWindow: 16 * 1024, Region: profile, DataBoundary: "global", Available: true}
	case ProfileLocal:
		return Capabilities{StructuredOutput: true, ToolPlanning: true, ContextWindow: 8 * 1024, Region: profile, DataBoundary: "customer-local", Available: true, LocalOnly: true}
	case ProfileDisabled:
		return Capabilities{Region: profile, DataBoundary: "none", Available: false}
	default:
		return Capabilities{Region: profile, DataBoundary: "unknown", Available: false}
	}
}

// ProfileCapabilities is a naming alias used by settings/orchestration code.
func ProfileCapabilities(profile Profile) Capabilities { return CapabilitiesFor(profile) }

// CapabilityMatrix returns a fresh map so callers cannot mutate the profile
// policy table held by this package.
func CapabilityMatrix() map[Profile]Capabilities {
	return map[Profile]Capabilities{
		ProfileChina: CapabilitiesFor(ProfileChina), ProfileGlobal: CapabilitiesFor(ProfileGlobal),
		ProfileLocal: CapabilitiesFor(ProfileLocal), ProfileDisabled: CapabilitiesFor(ProfileDisabled),
	}
}

// FailureCode is intentionally independent of the shared provider error enum:
// budget and cooldown are orchestration policy outcomes, not infrastructure
// errors. CodeOf maps the shared timeout/unavailable errors into these values.
type FailureCode string

const (
	FailureUnavailable FailureCode = "unavailable"
	FailureTimeout     FailureCode = "timeout"
	FailureBudget      FailureCode = "budget_exhausted"
	FailureCooldown    FailureCode = "cooldown"
	FailureDisabled    FailureCode = "disabled"
	FailureCancelled   FailureCode = "cancelled"
	FailureInvalid     FailureCode = "invalid_request"
)

var (
	ErrBudgetExceeded = errors.New("AI token budget exhausted")
	ErrCooldownActive = errors.New("AI provider cooldown is active")
	ErrDisabled       = errors.New("AI provider is disabled")
)

// PolicyError represents local orchestration policy failures. Infrastructure
// failures still use contracts.ProviderError so callers can use the shared
// contract classification.
type PolicyError struct {
	Code     FailureCode
	Message  string
	Provider string
	Cause    error
}

func (e *PolicyError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message != "" {
		return e.Message
	}
	return string(e.Code)
}

func (e *PolicyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is supports errors.Is(err, ErrBudgetExceeded), etc., while keeping the
// serialized error message free of request content.
func (e *PolicyError) Is(target error) bool {
	if e == nil {
		return false
	}
	switch {
	case e.Code == FailureBudget && target == ErrBudgetExceeded:
		return true
	case e.Code == FailureCooldown && target == ErrCooldownActive:
		return true
	case e.Code == FailureDisabled && target == ErrDisabled:
		return true
	default:
		return false
	}
}

// Degradation identifies the safe next branch after a provider call cannot
// produce a fresh structured response.
type Degradation string

const (
	DegradationNone        Degradation = "none"
	DegradationCache       Degradation = "cache"
	DegradationUnavailable Degradation = "unavailable"
	DegradationTimeout     Degradation = "timeout"
	DegradationBudget      Degradation = "budget"
	DegradationCooldown    Degradation = "cooldown"
	DegradationDisabled    Degradation = "disabled"
	DegradationCancelled   Degradation = "cancelled"
	DegradationInvalid     Degradation = "invalid_request"
)

type OutcomeStatus string

const (
	OutcomeSucceeded OutcomeStatus = "succeeded"
	OutcomeCached    OutcomeStatus = "cached"
	OutcomeDegraded  OutcomeStatus = "degraded"
)

// Outcome is the orchestration-friendly form of a call. StructuredCall keeps
// the shared interface's error semantics; Invoke additionally records whether
// a cached result safely served a provider degradation.
type Outcome struct {
	Result          contracts.AIResult `json:"result"`
	Status          OutcomeStatus      `json:"status"`
	Degradation     Degradation        `json:"degradation"`
	ServedFromCache bool               `json:"served_from_cache"`
	Fallback        FallbackPlan       `json:"fallback"`
}

// FallbackPlan is deliberately descriptive and non-executable. It never
// grants a tool, network, secret, or production-controller capability.
type FallbackPlan struct {
	ContinueCoreFlow     bool   `json:"continue_core_flow"`
	UseDeterministicRule bool   `json:"use_deterministic_rule"`
	AskMinimalQuestion   bool   `json:"ask_minimal_question"`
	ManualDraft          bool   `json:"manual_draft"`
	Reason               string `json:"reason"`
}

// Config controls only local fake behavior. There is intentionally no URL,
// API key, HTTP client, or model SDK in this type.
type Config struct {
	Profile       Profile
	Model         string
	PolicyVersion string
	Available     bool
	Unavailable   bool
	MaxTokens     int
	MaxDuration   time.Duration
	Delay         time.Duration
	Cooldown      time.Duration
	CacheEnabled  bool
	CacheTTL      time.Duration
	Clock         func() time.Time
}

type ProviderConfig = Config

type cacheEntry struct {
	result  contracts.AIResult
	created time.Time
}

// Provider is concurrency-safe and deterministic. It stores only structured
// result metadata and bounded cache entries; request content is never retained.
type Provider struct {
	metadata     contracts.ProviderMetadata
	profile      Profile
	model        string
	policy       string
	caps         Capabilities
	available    bool
	maxTokens    int
	maxDuration  time.Duration
	delay        time.Duration
	cooldown     time.Duration
	cacheEnabled bool
	cacheTTL     time.Duration
	clock        func() time.Time

	mu         sync.Mutex
	cache      map[string]cacheEntry
	lastCall   map[string]time.Time
	operations map[string]string
}

// FakeProvider is kept as an explicit product-facing name; it is an alias so
// contract wiring can use either Provider or FakeProvider without adapters.
type FakeProvider = Provider
type AIProvider = Provider

var _ contracts.AIProvider = (*Provider)(nil)

// New creates a local fake provider. A zero Config.Profile defaults to local;
// a zero Available is treated as available unless Unavailable is explicit.
func New(config Config) (*Provider, error) {
	profile := config.Profile
	if profile == "" {
		profile = ProfileLocal
	}
	if !profile.Valid() {
		return nil, fmt.Errorf("invalid AI profile %q", profile)
	}
	caps := CapabilitiesFor(profile)
	model := strings.TrimSpace(config.Model)
	if model == "" {
		model = "fake-" + string(profile) + "-v1"
	}
	policy := strings.TrimSpace(config.PolicyVersion)
	if policy == "" {
		policy = "fake-policy-v1"
	}
	available := config.Available || !config.Unavailable
	if profile == ProfileDisabled {
		available = false
	}
	caps.Available = available
	if config.MaxTokens < 0 || config.MaxDuration < 0 || config.Delay < 0 || config.Cooldown < 0 || config.CacheTTL < 0 {
		return nil, errors.New("AI provider limits must not be negative")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	metadataCaps := contracts.CapabilitySet{}
	if profile != ProfileDisabled && caps.StructuredOutput {
		metadataCaps[contracts.CapabilityAI] = struct{}{}
	}
	name := "fake-ai-" + string(profile)
	return &Provider{
		metadata: contracts.ProviderMetadata{
			Name: name, Version: "m6", ContractVersion: contracts.ContractAPIVersion,
			Capabilities: metadataCaps, Region: string(profile),
			SensitiveInputs: []string{"AI context", "prompt", "structured response"},
		},
		profile: profile, model: model, policy: policy, caps: caps, available: available,
		maxTokens: config.MaxTokens, maxDuration: config.MaxDuration, delay: config.Delay,
		cooldown: config.Cooldown, cacheEnabled: config.CacheEnabled, cacheTTL: config.CacheTTL,
		clock: clock, cache: make(map[string]cacheEntry), lastCall: make(map[string]time.Time), operations: make(map[string]string),
	}, nil
}

// NewFake is the convenient constructor used by CT-AI-001 and the local M6
// evaluation suite. It never requires a network or external model.
func NewFake(profile Profile) *Provider {
	if !profile.Valid() {
		profile = ProfileLocal
	}
	provider, err := New(Config{Profile: profile, Available: true, CacheEnabled: true})
	if err != nil {
		panic(err)
	}
	return provider
}

func NewFakeProvider(profile Profile) *Provider { return NewFake(profile) }

func NewProvider(config Config) (*Provider, error) { return New(config) }

func MustNew(config Config) *Provider {
	provider, err := New(config)
	if err != nil {
		panic(err)
	}
	return provider
}

func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }
func (p *Provider) Profile() Profile                                    { return p.profile }
func (p *Provider) Model() string                                       { return p.model }
func (p *Provider) Capabilities() Capabilities {
	if p == nil {
		return Capabilities{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	caps := p.caps
	caps.Available = p.available
	return caps
}

// SetAvailable is a test/control-plane hook. It only changes local fake
// availability and never creates an external connection.
func (p *Provider) SetAvailable(available bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.available = available && p.profile != ProfileDisabled
	p.caps.Available = p.available
	p.mu.Unlock()
}

func (p *Provider) Available() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.available
}

func (p *Provider) SetCooldown(duration time.Duration) {
	if p == nil || duration < 0 {
		return
	}
	p.mu.Lock()
	p.cooldown = duration
	p.mu.Unlock()
}

func (p *Provider) SetDelay(duration time.Duration) {
	if p == nil || duration < 0 {
		return
	}
	p.mu.Lock()
	p.delay = duration
	p.mu.Unlock()
}

func (p *Provider) SetCacheEnabled(enabled bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.cacheEnabled = enabled
	p.mu.Unlock()
}

func (p *Provider) ClearCache() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.cache = make(map[string]cacheEntry)
	p.mu.Unlock()
}

// StructuredCall implements contracts.AIProvider. It returns only a valid,
// bounded structured result or a classified error; no model text is exposed.
func (p *Provider) StructuredCall(ctx context.Context, request contracts.AIRequest) (contracts.AIResult, error) {
	outcome, err := p.Invoke(ctx, request)
	if err != nil {
		return contracts.AIResult{}, err
	}
	return outcome.Result, nil
}

func (p *Provider) Call(ctx context.Context, request contracts.AIRequest) (Outcome, error) {
	return p.Invoke(ctx, request)
}

func (p *Provider) CacheKey(request contracts.AIRequest) string {
	if p == nil {
		return ""
	}
	return requestKey(request, p.profile, p.model, p.policy)
}

// Invoke exposes degradation and cache evidence to an orchestrator while
// retaining the shared provider error contract for fresh-call failures.
func (p *Provider) Invoke(ctx context.Context, request contracts.AIRequest) (Outcome, error) {
	if p == nil {
		return Outcome{Status: OutcomeDegraded, Degradation: DegradationUnavailable, Fallback: fallbackFor(DegradationUnavailable)}, unavailableError("provider is not initialized", nil)
	}
	if err := validateRequest(ctx, request); err != nil {
		degradation := degradationOf(err)
		return Outcome{Status: OutcomeDegraded, Degradation: degradation, Fallback: fallbackFor(degradation)}, err
	}
	if strings.TrimSpace(request.Context.Profile) != "" && request.Context.Profile != string(p.profile) {
		err := &PolicyError{Code: FailureInvalid, Message: "AI context profile does not match provider profile"}
		return Outcome{Status: OutcomeDegraded, Degradation: DegradationInvalid, Fallback: fallbackFor(DegradationInvalid)}, err
	}
	key := requestKey(request, p.profile, p.model, p.policy)
	now := p.clock().UTC()

	p.mu.Lock()
	cacheEnabled, cacheTTL := p.cacheEnabled, p.cacheTTL
	if previous, ok := p.operations[request.Operation.IdempotencyKey]; ok && previous != key {
		p.mu.Unlock()
		err := &contracts.ProviderError{Provider: p.metadata.Name, Code: contracts.ErrConflict, Message: "AI idempotency key was reused for a different request", Retry: contracts.RetryNever, Retryable: false, Capability: contracts.CapabilityAI, Operation: "structured_call"}
		return Outcome{Status: OutcomeDegraded, Degradation: DegradationInvalid, Fallback: fallbackFor(DegradationInvalid)}, err
	}
	if cacheEnabled {
		if entry, ok := p.cache[key]; ok && (cacheTTL <= 0 || now.Sub(entry.created) <= cacheTTL) {
			result := cloneResult(entry.result)
			result.Invocation.Cached = true
			p.operations[request.Operation.IdempotencyKey] = key
			p.mu.Unlock()
			return Outcome{Result: result, Status: OutcomeCached, Degradation: DegradationCache, ServedFromCache: true, Fallback: fallbackFor(DegradationCache)}, nil
		}
		if cacheTTL > 0 {
			delete(p.cache, key)
		}
	}
	cooldown := p.cooldown
	last := p.lastCall[key]
	available := p.available
	maxTokens, maxDuration, delay := p.maxTokens, p.maxDuration, p.delay
	p.mu.Unlock()

	if p.profile == ProfileDisabled {
		err := &contracts.ProviderError{Provider: p.metadata.Name, Code: contracts.ErrUnsupportedCapability, Message: "AI provider is disabled", Retry: contracts.RetryUserAction, Retryable: false, Capability: contracts.CapabilityAI, Operation: "structured_call", Cause: ErrDisabled}
		return Outcome{Status: OutcomeDegraded, Degradation: DegradationDisabled, Fallback: fallbackFor(DegradationDisabled)}, err
	}
	if cooldown > 0 && !last.IsZero() && now.Sub(last) < cooldown {
		err := &PolicyError{Code: FailureCooldown, Message: "AI provider cooldown is active", Provider: p.metadata.Name, Cause: ErrCooldownActive}
		return Outcome{Status: OutcomeDegraded, Degradation: DegradationCooldown, Fallback: fallbackFor(DegradationCooldown)}, err
	}
	if !available {
		err := unavailableError("AI provider is unavailable", nil)
		err.Provider = p.metadata.Name
		return Outcome{Status: OutcomeDegraded, Degradation: DegradationUnavailable, Fallback: fallbackFor(DegradationUnavailable)}, err
	}
	if maxTokens > 0 && request.Budget.MaxTokens > maxTokens {
		err := &PolicyError{Code: FailureBudget, Message: "AI token budget exceeds provider limit", Provider: p.metadata.Name, Cause: ErrBudgetExceeded}
		return Outcome{Status: OutcomeDegraded, Degradation: DegradationBudget, Fallback: fallbackFor(DegradationBudget)}, err
	}
	if request.Budget.MaxTokens <= 0 {
		err := &PolicyError{Code: FailureBudget, Message: "AI token budget is exhausted", Provider: p.metadata.Name, Cause: ErrBudgetExceeded}
		return Outcome{Status: OutcomeDegraded, Degradation: DegradationBudget, Fallback: fallbackFor(DegradationBudget)}, err
	}
	if maxDuration > 0 && request.Budget.MaxDuration > maxDuration {
		err := &PolicyError{Code: FailureBudget, Message: "AI duration budget exceeds provider limit", Provider: p.metadata.Name, Cause: ErrBudgetExceeded}
		return Outcome{Status: OutcomeDegraded, Degradation: DegradationBudget, Fallback: fallbackFor(DegradationBudget)}, err
	}
	if request.Budget.MaxDuration > 0 && delay > request.Budget.MaxDuration {
		err := timeoutError("AI request exceeded its duration budget", context.DeadlineExceeded)
		err.Provider = p.metadata.Name
		return Outcome{Status: OutcomeDegraded, Degradation: DegradationTimeout, Fallback: fallbackFor(DegradationTimeout)}, err
	}
	if err := contextDeadline(ctx, request.Operation.Deadline, now, delay); err != nil {
		if providerErr, ok := err.(*contracts.ProviderError); ok {
			providerErr.Provider = p.metadata.Name
		}
		degradation := degradationOf(err)
		return Outcome{Status: OutcomeDegraded, Degradation: degradation, Fallback: fallbackFor(degradation)}, err
	}

	result := p.makeResult(request, key)
	if err := result.Plan.Validate(); err != nil {
		err = contracts.InvalidProviderResponse(fmt.Sprintf("fake AI response failed action-plan validation: %v", err))
		return Outcome{Status: OutcomeDegraded, Degradation: DegradationInvalid, Fallback: fallbackFor(DegradationInvalid)}, err
	}
	p.mu.Lock()
	p.operations[request.Operation.IdempotencyKey] = key
	p.lastCall[key] = now
	if p.cacheEnabled {
		p.cache[key] = cacheEntry{result: cloneResult(result), created: now}
	}
	p.mu.Unlock()
	return Outcome{Result: result, Status: OutcomeSucceeded, Degradation: DegradationNone, Fallback: fallbackFor(DegradationNone)}, nil
}

func validateRequest(ctx context.Context, request contracts.AIRequest) error {
	if ctx == nil {
		return &PolicyError{Code: FailureInvalid, Message: "AI call context is nil"}
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return timeoutError("AI request context deadline exceeded", err)
		}
		return &PolicyError{Code: FailureCancelled, Message: "AI request context was cancelled", Cause: err}
	}
	if strings.TrimSpace(request.TaskType) == "" {
		return &PolicyError{Code: FailureInvalid, Message: "AI task type is required"}
	}
	if err := request.Operation.Validate(); err != nil {
		return &PolicyError{Code: FailureInvalid, Message: "AI operation is invalid", Cause: err}
	}
	if request.Context.ID.Empty() || !request.Context.Redacted || len(request.Context.Scope) == 0 {
		return &PolicyError{Code: FailureInvalid, Message: "AI context must be identified, scoped, and redacted"}
	}
	if err := request.Context.Validate(); err != nil {
		return &PolicyError{Code: FailureInvalid, Message: "AI context failed validation", Cause: err}
	}
	return nil
}

func contextDeadline(ctx context.Context, operationDeadline, now time.Time, delay time.Duration) error {
	if deadline, ok := ctx.Deadline(); ok {
		current := time.Now()
		if !deadline.After(current) || (delay > 0 && !deadline.After(current.Add(delay))) {
			return timeoutError("AI request exceeded its deadline", context.DeadlineExceeded)
		}
	}
	if operationDeadline.IsZero() {
		return nil
	}
	if !operationDeadline.After(now) || (delay > 0 && !operationDeadline.After(now.Add(delay))) {
		return timeoutError("AI request exceeded its deadline", context.DeadlineExceeded)
	}
	return nil
}

func unavailableError(message string, cause error) *contracts.ProviderError {
	return &contracts.ProviderError{Provider: "fake-ai", Code: contracts.ErrUnavailable, Message: message, Retry: contracts.RetryBackoff, Retryable: true, Capability: contracts.CapabilityAI, Operation: "structured_call", Cause: cause}
}

func timeoutError(message string, cause error) *contracts.ProviderError {
	return &contracts.ProviderError{Provider: "fake-ai", Code: contracts.ErrTimeout, Message: message, Retry: contracts.RetryBackoff, Retryable: true, Capability: contracts.CapabilityAI, Operation: "structured_call", Cause: cause}
}

func (p *Provider) makeResult(request contracts.AIRequest, key string) contracts.AIResult {
	fingerprint := digest(key, request.TaskType, string(request.Context.ID), request.Context.ManifestDigest, fmt.Sprint(request.Context.Bytes), request.Context.TemplateVersion, strings.Join(sortedStrings(request.Context.Scope), "\x00"))
	invocationID := domain.ID("aiinv_" + fingerprint[:32])
	planID := domain.ID("aiplan_" + fingerprint[32:64])
	evidenceDigest := "sha256:" + digest("evidence", fingerprint)
	refs := []domain.EvidenceRef{
		{ID: domain.ID("ev_" + digest("context", fingerprint)[:32]), Kind: "ai.context", Digest: evidenceDigest, Locator: "fake://ai/context/" + fingerprint[:16]},
		{ID: domain.ID("ev_" + digest("response", fingerprint)[:32]), Kind: "ai.response", Digest: evidenceDigest, Locator: "fake://ai/response/" + fingerprint[:16]},
	}
	tokens := request.Budget.MaxTokens
	if tokens > 32 {
		tokens = 32
	}
	durationMS := request.Budget.MaxDuration.Milliseconds()
	if durationMS <= 0 {
		durationMS = p.maxDuration.Milliseconds()
	}
	if durationMS <= 0 {
		durationMS = 1
	}
	contextDigest := strings.TrimSpace(request.Context.ManifestDigest)
	if contextDigest == "" {
		contextDigest = "sha256:" + digest("context", string(request.Context.ID))
	}
	readPath := "Dockerfile"
	switch request.TaskType {
	case "definition_ambiguity":
		readPath = "delivery.yaml"
	case "log_anomaly_analysis":
		readPath = "logs.txt"
	case "usage_analysis":
		readPath = "usage.json"
	}
	result := contracts.AIResult{
		Invocation: domain.AIInvocation{ID: invocationID, Provider: p.metadata.Name, Model: p.model, Profile: string(p.profile), PolicyVersion: p.policy, PromptVersion: request.Context.TemplateVersion, ProblemFingerprint: fingerprint, ContextID: request.Context.ID, ContextDigest: contextDigest, Tokens: uint64(tokens), DurationMS: p.delay.Milliseconds(), Cached: false, Status: "succeeded"},
		Plan: domain.AIActionPlan{
			ID: planID, SchemaVersion: "1.0", PolicyVersion: p.policy, TaskType: request.TaskType,
			TargetRefs:   map[string]string{"context": string(request.Context.ID), "controller": "required"},
			Sources:      []string{"ai.context", "ai.provider.fake"},
			EvidenceRefs: append([]domain.EvidenceRef(nil), refs...),
			Actions:      []domain.AIAction{{ToolID: "workspace.read", ToolVersion: "v1", Parameters: map[string]any{"path": readPath, "max_bytes": 65536}, Risk: domain.AIRiskReadOnly, ExpectedResult: "bounded read-only evidence", ValidationID: "workspace.read.v1"}},
			Assumptions:  []string{"fake provider response is a bounded suggestion, not a production fact"},
			Budget:       domain.AIPlanBudget{MaxTokens: tokens, MaxDurationMS: durationMS, MaxActions: 1},
			Confidence:   0.5, RequiresUserConfirmation: false,
		},
		Evidence: contracts.Evidence{Refs: append([]domain.EvidenceRef(nil), refs...), Summary: "deterministic local structured response", Digest: evidenceDigest, Redacted: true},
	}
	return result
}

func cloneResult(result contracts.AIResult) contracts.AIResult {
	result.Evidence.Refs = append([]domain.EvidenceRef(nil), result.Evidence.Refs...)
	result.Plan.EvidenceRefs = append([]domain.EvidenceRef(nil), result.Plan.EvidenceRefs...)
	result.Plan.Actions = append([]domain.AIAction(nil), result.Plan.Actions...)
	if result.Plan.TargetRefs != nil {
		refs := make(map[string]string, len(result.Plan.TargetRefs))
		for key, value := range result.Plan.TargetRefs {
			refs[key] = value
		}
		result.Plan.TargetRefs = refs
	}
	if result.Plan.Assumptions != nil {
		result.Plan.Assumptions = append([]string(nil), result.Plan.Assumptions...)
	}
	for i := range result.Plan.Actions {
		if result.Plan.Actions[i].Parameters != nil {
			params := make(map[string]any, len(result.Plan.Actions[i].Parameters))
			for key, value := range result.Plan.Actions[i].Parameters {
				params[key] = value
			}
			result.Plan.Actions[i].Parameters = params
		}
	}
	return result
}

func requestKey(request contracts.AIRequest, profile Profile, model, policy string) string {
	value := struct {
		Profile        Profile
		Model          string
		Policy         string
		Task           string
		ApplicationID  domain.ID
		ContextID      domain.ID
		ContextDigest  string
		ContextBytes   int64
		ObjectVersions map[string]string
		Template       string
		Scope          []string
	}{profile, model, policy, strings.TrimSpace(request.TaskType), request.Context.ApplicationID, request.Context.ID, request.Context.ManifestDigest, request.Context.Bytes, request.Context.ObjectVersions, request.Context.TemplateVersion, sortedStrings(request.Context.Scope)}
	encoded, _ := json.Marshal(value)
	return digest(string(encoded))
}

func digest(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	for i := range result {
		result[i] = strings.TrimSpace(result[i])
	}
	sort.Strings(result)
	return result
}

func degradationOf(err error) Degradation {
	if err == nil {
		return DegradationNone
	}
	var providerErr *contracts.ProviderError
	if errors.As(err, &providerErr) {
		switch providerErr.Code {
		case contracts.ErrUnavailable:
			return DegradationUnavailable
		case contracts.ErrTimeout:
			return DegradationTimeout
		case contracts.ErrCancelled:
			return DegradationCancelled
		case contracts.ErrUnsupportedCapability:
			return DegradationDisabled
		}
	}
	var policyErr *PolicyError
	if errors.As(err, &policyErr) {
		switch policyErr.Code {
		case FailureBudget:
			return DegradationBudget
		case FailureCooldown:
			return DegradationCooldown
		case FailureDisabled:
			return DegradationDisabled
		case FailureCancelled:
			return DegradationCancelled
		}
	}
	return DegradationInvalid
}

// DegradationOf classifies a provider error for orchestration and telemetry.
func DegradationOf(err error) Degradation { return degradationOf(err) }

// FailureOf exposes one stable classification for telemetry and fallback
// routing, including errors returned by the shared contracts package.
func FailureOf(err error) FailureCode {
	switch degradationOf(err) {
	case DegradationUnavailable:
		return FailureUnavailable
	case DegradationTimeout:
		return FailureTimeout
	case DegradationBudget:
		return FailureBudget
	case DegradationCooldown:
		return FailureCooldown
	case DegradationDisabled:
		return FailureDisabled
	case DegradationCancelled:
		return FailureCancelled
	default:
		return FailureInvalid
	}
}

// FallbackFor maps failure to a bounded, non-executing fallback plan.
func FallbackFor(value any) FallbackPlan {
	var degradation Degradation
	switch typed := value.(type) {
	case Degradation:
		degradation = typed
	case string:
		degradation = Degradation(typed)
	case error:
		degradation = degradationOf(typed)
	default:
		degradation = DegradationInvalid
	}
	return fallbackFor(degradation)
}

func fallbackFor(degradation Degradation) FallbackPlan {
	switch degradation {
	case DegradationNone:
		return FallbackPlan{ContinueCoreFlow: true, Reason: "structured response available"}
	case DegradationCache:
		return FallbackPlan{ContinueCoreFlow: true, Reason: "serve a previously validated cache entry"}
	case DegradationDisabled:
		return FallbackPlan{ContinueCoreFlow: true, UseDeterministicRule: true, AskMinimalQuestion: true, ManualDraft: true, Reason: "AI is disabled; use deterministic rules or a human draft"}
	default:
		return FallbackPlan{ContinueCoreFlow: true, UseDeterministicRule: true, AskMinimalQuestion: true, ManualDraft: true, Reason: "AI degradation must not expand permissions or block the controller flow"}
	}
}

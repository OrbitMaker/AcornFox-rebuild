// Package runner executes only actions that have already passed the strict AI
// tool catalog. It contains no shell, network, Docker, SSH, or Kubernetes
// client. The built-in executor is deliberately a deterministic workspace
// fixture so an AI suggestion cannot become a production side effect.
package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/ai/tools"
	"github.com/open-card/open-card/internal/domain"
)

var (
	ErrInvalidRequest       = errors.New("action runner request rejected")
	ErrConfirmationRequired = errors.New("explicit confirmation is required")
	ErrControllerHandoff    = errors.New("production action requires controller handoff")
	ErrWorkspaceBoundary    = errors.New("workspace boundary rejected")
	ErrSymlinkEscape        = errors.New("workspace symlink or link escape rejected")
	ErrSensitivePath        = errors.New("sensitive path is not available to AI tools")
	ErrNetworkDenied        = errors.New("network access is denied")
	ErrExecution            = errors.New("action execution failed")
	ErrVerification         = errors.New("independent verification failed")
	ErrRollback             = errors.New("rollback failed")
	ErrCleanup              = errors.New("sandbox cleanup failed")
	ErrTimeout              = errors.New("action timed out")
	ErrResourceLimit        = errors.New("action resource limit exceeded")
	ErrFixtureFailed        = errors.New("deterministic fixture reported failure")
	ErrIdempotencyConflict  = errors.New("idempotency key was reused for a different action")
	ErrCancelled            = errors.New("action cancelled")
)

type ResultStatus string

const (
	StatusSucceeded ResultStatus = "succeeded"
	StatusFailed    ResultStatus = "failed"
	StatusRejected  ResultStatus = "rejected"
	StatusHandoff   ResultStatus = "controller_handoff"
	StatusReplayed  ResultStatus = "replayed"
)

// Workspace is the only filesystem authority exposed to the runner. Paths in
// action parameters are always relative to Root (or DraftRoot for R2 draft
// edits); callers never pass a host path to a tool.
type Workspace struct {
	Root         string   `json:"root"`
	DraftRoot    string   `json:"draft_root,omitempty"`
	Production   bool     `json:"production,omitempty"`
	CorePrefixes []string `json:"core_prefixes,omitempty"`
}

func (w Workspace) normalized() Workspace {
	w.Root = strings.TrimSpace(w.Root)
	w.DraftRoot = strings.TrimSpace(w.DraftRoot)
	if len(w.CorePrefixes) == 0 {
		w.CorePrefixes = []string{".git", "api", "cmd", "deploy", "internal", "migrations", "scripts"}
	} else {
		copyOf := make([]string, 0, len(w.CorePrefixes))
		for _, prefix := range w.CorePrefixes {
			prefix = strings.Trim(strings.TrimSpace(prefix), "/")
			if prefix != "" {
				copyOf = append(copyOf, prefix)
			}
		}
		w.CorePrefixes = copyOf
	}
	return w
}

func (w Workspace) Validate() error {
	w = w.normalized()
	if err := validateWorkspaceRoot(w); err != nil {
		return err
	}
	if w.DraftRoot != "" {
		if filepath.IsAbs(w.DraftRoot) {
			rel, err := filepath.Rel(filepath.Clean(w.Root), filepath.Clean(w.DraftRoot))
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
				return fmt.Errorf("%w: draft root is outside workspace", ErrWorkspaceBoundary)
			}
			if _, err := securePathUnchecked(w, filepath.ToSlash(rel), true, true); err != nil {
				return fmt.Errorf("%w: draft root: %v", ErrWorkspaceBoundary, err)
			}
		} else if _, err := securePathUnchecked(w, w.DraftRoot, true, true); err != nil {
			return fmt.Errorf("%w: draft root: %v", ErrWorkspaceBoundary, err)
		}
	}
	return nil
}

func validateWorkspaceRoot(w Workspace) error {
	if w.Root == "" || !filepath.IsAbs(w.Root) || filepath.Clean(w.Root) != w.Root {
		return fmt.Errorf("%w: workspace root must be an absolute clean path", ErrWorkspaceBoundary)
	}
	if w.Root == string(filepath.Separator) {
		return fmt.Errorf("%w: filesystem root is not an authorized workspace", ErrWorkspaceBoundary)
	}
	info, err := os.Lstat(w.Root)
	if err != nil {
		return fmt.Errorf("%w: workspace root: %v", ErrWorkspaceBoundary, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: workspace root must be a real directory", ErrSymlinkEscape)
	}
	return nil
}

// ActionRequest is the stable runner input. Action is the already structured
// domain plan action; the runner never accepts a command string.
type ActionRequest struct {
	Action         domain.AIAction      `json:"action"`
	Workspace      Workspace            `json:"workspace"`
	WorkspaceRoot  string               `json:"workspace_root,omitempty"` // compatibility shorthand
	DraftRoot      string               `json:"draft_root,omitempty"`     // compatibility shorthand
	IdempotencyKey string               `json:"idempotency_key"`
	Confirmed      bool                 `json:"confirmed,omitempty"`
	TokenCount     int64                `json:"token_count,omitempty"`
	Tokens         int64                `json:"tokens,omitempty"` // compatibility alias
	Limits         tools.ResourceLimits `json:"limits,omitempty"`
	Network        tools.NetworkPolicy  `json:"network,omitempty"`
}

// RunRequest and Request are aliases kept as small, discoverable entry points
// for callers integrating the runner into different orchestration layers.
type RunRequest = ActionRequest
type Request = ActionRequest

type ControllerHandoff struct {
	ToolID              string `json:"tool_id"`
	ToolVersion         string `json:"tool_version"`
	Reason              string `json:"reason"`
	ControllerAction    string `json:"controller_action"`
	RequiresUserConfirm bool   `json:"requires_user_confirmation"`
}

type Evidence struct {
	Kind        string `json:"kind"`
	Summary     string `json:"summary"`
	Digest      string `json:"digest,omitempty"`
	Independent bool   `json:"independent"`
	Redacted    bool   `json:"redacted"`
	Files       int    `json:"files,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`
	Cleanup     bool   `json:"cleanup"`
	Rollback    bool   `json:"rollback"`
}

type RunResult struct {
	IdempotencyKey string             `json:"idempotency_key"`
	ToolID         string             `json:"tool_id"`
	ToolVersion    string             `json:"tool_version"`
	Risk           tools.RiskClass    `json:"risk"`
	Status         ResultStatus       `json:"status"`
	Output         any                `json:"output,omitempty"`
	OutputDigest   string             `json:"output_digest,omitempty"`
	Diff           string             `json:"diff,omitempty"`
	Evidence       Evidence           `json:"evidence"`
	Verification   Evidence           `json:"verification"`
	Cleanup        bool               `json:"cleanup"`
	RolledBack     bool               `json:"rolled_back"`
	Replay         bool               `json:"replay"`
	Handoff        *ControllerHandoff `json:"handoff,omitempty"`
	Error          string             `json:"error,omitempty"`
}

type ExecutionRequest struct {
	Action     domain.AIAction
	Descriptor tools.ToolDescriptor
	Workspace  Workspace
	Limits     tools.ResourceLimits
	Network    tools.NetworkPolicy
}

type RollbackState struct {
	Path     string
	Existed  bool
	Original []byte
	Mode     os.FileMode
	Changed  bool
}

type ExecutionOutput struct {
	Value     any
	Diff      string
	Digest    string
	Bytes     int64
	Files     int
	TempPaths []string
	Rollback  *RollbackState
}

type Executor interface {
	Execute(context.Context, ExecutionRequest) (ExecutionOutput, error)
}

type ExecutorFunc func(context.Context, ExecutionRequest) (ExecutionOutput, error)

func (f ExecutorFunc) Execute(ctx context.Context, request ExecutionRequest) (ExecutionOutput, error) {
	return f(ctx, request)
}

type VerificationRequest struct {
	Action     domain.AIAction
	Descriptor tools.ToolDescriptor
	Workspace  Workspace
	Limits     tools.ResourceLimits
	Output     ExecutionOutput
}

type Verifier interface {
	Verify(context.Context, VerificationRequest) (Evidence, error)
}

type VerifierFunc func(context.Context, VerificationRequest) (Evidence, error)

func (f VerifierFunc) Verify(ctx context.Context, request VerificationRequest) (Evidence, error) {
	return f(ctx, request)
}

type RollbackRequest struct {
	Action     domain.AIAction
	Descriptor tools.ToolDescriptor
	Workspace  Workspace
	State      *RollbackState
}

type Rollbacker interface {
	Rollback(context.Context, RollbackRequest) error
}

type RollbackFunc func(context.Context, RollbackRequest) error

func (f RollbackFunc) Rollback(ctx context.Context, request RollbackRequest) error {
	return f(ctx, request)
}

type Options struct {
	Catalog    *tools.ToolCatalog
	Executor   Executor
	Verifier   Verifier
	Rollback   Rollbacker
	Rollbacker Rollbacker // compatibility alias
	Limits     tools.ResourceLimits
	Network    tools.NetworkPolicy
}

type ActionRunner struct {
	catalog  *tools.ToolCatalog
	executor Executor
	verifier Verifier
	rollback Rollbacker
	limits   tools.ResourceLimits
	network  tools.NetworkPolicy

	mu      sync.Mutex
	entries map[string]*replayEntry
}

// AIActionRunner is the product-language spelling used by the architecture
// documents. It aliases the single bounded implementation.
type AIActionRunner = ActionRunner

type replayEntry struct {
	digest string
	done   chan struct{}
	result RunResult
	err    error
}

func NewActionRunner(catalog *tools.ToolCatalog, options Options) (*ActionRunner, error) {
	if catalog == nil {
		catalog = options.Catalog
	}
	if catalog == nil {
		catalog = tools.DefaultCatalog()
	}
	limits := options.Limits
	if limits == (tools.ResourceLimits{}) {
		limits = tools.DefaultResourceLimits()
	} else {
		if err := validatePartialLimits(limits); err != nil {
			return nil, err
		}
		limits = minPositive(tools.DefaultResourceLimits(), limits)
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	network := options.Network
	if strings.TrimSpace(string(network.Mode)) == "" {
		network = tools.NetworkPolicy{Mode: tools.NetworkDisabled}
	}
	if err := network.Validate(); err != nil {
		return nil, err
	}
	runner := &ActionRunner{catalog: catalog, limits: limits, network: network, entries: make(map[string]*replayEntry)}
	runner.executor = options.Executor
	if runner.executor == nil {
		runner.executor = builtinExecutor{}
	}
	runner.verifier = options.Verifier
	if runner.verifier == nil {
		runner.verifier = builtinVerifier{}
	}
	runner.rollback = options.Rollbacker
	if runner.rollback == nil {
		runner.rollback = options.Rollback
	}
	if runner.rollback == nil {
		runner.rollback = builtinRollbacker{}
	}
	return runner, nil
}

// New is the concise constructor used by application code. Invalid static
// options are programmer errors; use NewActionRunner when an error return is
// preferred.
func New(catalog *tools.ToolCatalog, options Options) *ActionRunner {
	runner, err := NewActionRunner(catalog, options)
	if err != nil {
		panic(err)
	}
	return runner
}

func Default() *ActionRunner { return New(nil, Options{}) }

func NewAIActionRunner(catalog *tools.ToolCatalog, options Options) (*ActionRunner, error) {
	return NewActionRunner(catalog, options)
}

func (r *ActionRunner) Catalog() *tools.ToolCatalog { return r.catalog }

func (r *ActionRunner) Run(ctx context.Context, request ActionRequest) (RunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	key := strings.TrimSpace(request.IdempotencyKey)
	if key == "" {
		return RunResult{Status: StatusRejected, Error: ErrInvalidRequest.Error()}, fmt.Errorf("%w: idempotency key is required", ErrInvalidRequest)
	}
	digest, err := requestDigest(request)
	if err != nil {
		return RunResult{IdempotencyKey: key, Status: StatusRejected, Error: ErrInvalidRequest.Error()}, fmt.Errorf("%w: request digest: %v", ErrInvalidRequest, err)
	}
	entry, wait, err := r.claim(key, digest)
	if err != nil {
		return RunResult{IdempotencyKey: key, Status: StatusRejected, Error: err.Error()}, err
	}
	if wait {
		select {
		case <-ctx.Done():
			return RunResult{IdempotencyKey: key, Status: StatusRejected, Error: ctx.Err().Error()}, ctx.Err()
		case <-entry.done:
			result := cloneResult(entry.result)
			result.Status = StatusReplayed
			result.Replay = true
			return result, entry.err
		}
	}
	result, runErr := r.runOnce(ctx, request)
	r.complete(key, entry, result, runErr)
	return result, runErr
}

// ExecuteAction and RunAction are stable aliases for integrations that use a
// verb-oriented runner surface.
func (r *ActionRunner) ExecuteAction(ctx context.Context, request ActionRequest) (RunResult, error) {
	return r.Run(ctx, request)
}

func (r *ActionRunner) RunAction(ctx context.Context, request ActionRequest) (RunResult, error) {
	return r.Run(ctx, request)
}

func (r *ActionRunner) claim(key, digest string) (*replayEntry, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if previous, ok := r.entries[key]; ok {
		if previous.digest != digest {
			return nil, false, fmt.Errorf("%w: %s", ErrIdempotencyConflict, key)
		}
		return previous, true, nil
	}
	entry := &replayEntry{digest: digest, done: make(chan struct{})}
	r.entries[key] = entry
	return entry, false, nil
}

func (r *ActionRunner) complete(key string, entry *replayEntry, result RunResult, err error) {
	r.mu.Lock()
	entry.result = cloneResult(result)
	entry.err = err
	close(entry.done)
	if result.Status == StatusRejected || result.Status == StatusHandoff {
		// Policy gates are intentionally retryable: an R2 request can be
		// confirmed after an awaiting-confirmation response, while a rejected
		// request may be corrected without burning its idempotency key.
		delete(r.entries, key)
	}
	r.mu.Unlock()
}

func (r *ActionRunner) runOnce(parent context.Context, request ActionRequest) (RunResult, error) {
	key := strings.TrimSpace(request.IdempotencyKey)
	result := RunResult{IdempotencyKey: key, Status: StatusRejected}
	descriptor, err := r.catalog.ValidateAction(request.Action)
	if err != nil {
		result.Error = safeError(err)
		return result, err
	}
	result.ToolID = descriptor.ID
	result.ToolVersion = descriptor.Version
	result.Risk = descriptor.Risk
	if descriptor.Risk == tools.RiskR3 || descriptor.ControllerHandoffOnly {
		result.Status = StatusHandoff
		result.Handoff = &ControllerHandoff{
			ToolID:              descriptor.ID,
			ToolVersion:         descriptor.Version,
			Reason:              "production mutations are owned by the release controller",
			ControllerAction:    descriptor.ID,
			RequiresUserConfirm: true,
		}
		result.Error = ErrControllerHandoff.Error()
		return result, fmt.Errorf("%w: %s", ErrControllerHandoff, descriptor.ID)
	}
	if descriptor.RequiresUserConfirmation && !request.Confirmed {
		result.Error = ErrConfirmationRequired.Error()
		return result, fmt.Errorf("%w: %s", ErrConfirmationRequired, descriptor.ID)
	}
	workspace := request.Workspace.normalized()
	if request.WorkspaceRoot != "" {
		workspace.Root = request.WorkspaceRoot
	}
	if request.DraftRoot != "" {
		workspace.DraftRoot = request.DraftRoot
	}
	if err := workspace.Validate(); err != nil {
		result.Error = safeError(err)
		return result, err
	}
	limits, err := effectiveLimits(descriptor.Limits, r.limits, request.Limits)
	if err != nil {
		result.Error = safeError(err)
		return result, err
	}
	network, err := effectiveNetwork(descriptor.Network, r.network, request.Network)
	if err != nil {
		result.Error = safeError(err)
		return result, err
	}
	tokens := request.TokenCount
	if request.Tokens > tokens {
		tokens = request.Tokens
	}
	if tokens < 0 || tokens > limits.MaxTokens {
		result.Error = ErrResourceLimit.Error()
		return result, fmt.Errorf("%w: token budget exceeded", ErrResourceLimit)
	}
	if workspace.Production {
		result.Error = ErrControllerHandoff.Error()
		return result, fmt.Errorf("%w: production workspace is not executable", ErrControllerHandoff)
	}
	deadline := limits.MaxDuration
	if parentDeadline, ok := parent.Deadline(); ok {
		remaining := time.Until(parentDeadline)
		if remaining <= 0 {
			result.Error = ErrTimeout.Error()
			return result, fmt.Errorf("%w: parent deadline elapsed", ErrTimeout)
		}
		if remaining < deadline {
			deadline = remaining
		}
	}
	ctx, cancel := context.WithTimeout(parent, deadline)
	defer cancel()
	input := ExecutionRequest{Action: cloneAction(request.Action), Descriptor: descriptor, Workspace: workspace, Limits: limits, Network: network}
	output, executeErr := r.executor.Execute(ctx, input)
	cleanupErr := cleanupTempPaths(workspace, output.TempPaths)
	result.Cleanup = cleanupErr == nil
	if cleanupErr != nil {
		if executeErr == nil {
			executeErr = fmt.Errorf("%w: %w", ErrCleanup, cleanupErr)
		} else {
			executeErr = fmt.Errorf("%w: %w; cleanup: %w", ErrExecution, executeErr, cleanupErr)
		}
	}
	if executeErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(executeErr, context.DeadlineExceeded) {
			executeErr = fmt.Errorf("%w: %w", ErrTimeout, executeErr)
		} else if errors.Is(ctx.Err(), context.Canceled) || errors.Is(executeErr, context.Canceled) {
			executeErr = fmt.Errorf("%w: %w", ErrCancelled, executeErr)
		} else if !errors.Is(executeErr, ErrCleanup) && !errors.Is(executeErr, ErrFixtureFailed) {
			executeErr = fmt.Errorf("%w: %w", ErrExecution, executeErr)
		}
		rolledBack, rollbackErr := r.rollbackIfNeeded(ctx, input, output)
		result.RolledBack = rolledBack
		if rollbackErr != nil {
			executeErr = fmt.Errorf("%w: %w; rollback: %w", ErrRollback, executeErr, rollbackErr)
		}
		result.Status = StatusFailed
		result.Error = safeError(executeErr)
		return result, executeErr
	}
	if err := validateOutput(output, limits); err != nil {
		rolledBack, rollbackErr := r.rollbackIfNeeded(ctx, input, output)
		result.RolledBack = rolledBack
		if rollbackErr != nil {
			err = fmt.Errorf("%w: %w; rollback: %w", ErrRollback, err, rollbackErr)
		}
		result.Status = StatusFailed
		result.Error = safeError(err)
		return result, err
	}
	verification, verifyErr := r.verifier.Verify(ctx, VerificationRequest{Action: input.Action, Descriptor: descriptor, Workspace: workspace, Limits: limits, Output: output})
	result.Verification = verification
	if verifyErr != nil || !verification.Independent {
		if verifyErr == nil {
			verifyErr = fmt.Errorf("%w: verifier did not provide independent evidence", ErrVerification)
		} else {
			verifyErr = fmt.Errorf("%w: %w", ErrVerification, verifyErr)
		}
		rolledBack, rollbackErr := r.rollbackIfNeeded(ctx, input, output)
		result.RolledBack = rolledBack
		if rollbackErr != nil {
			verifyErr = fmt.Errorf("%w: %w; rollback: %w", ErrRollback, verifyErr, rollbackErr)
		}
		result.Status = StatusFailed
		result.Error = safeError(verifyErr)
		return result, verifyErr
	}
	result.Status = StatusSucceeded
	result.Output = output.Value
	result.OutputDigest = output.Digest
	result.Diff = output.Diff
	result.Evidence = Evidence{Kind: "action", Summary: "bounded action completed", Digest: output.Digest, Independent: true, Redacted: true, Files: output.Files, Bytes: output.Bytes, Cleanup: result.Cleanup}
	return result, nil
}

func (r *ActionRunner) rollbackIfNeeded(ctx context.Context, input ExecutionRequest, output ExecutionOutput) (bool, error) {
	if output.Rollback == nil || !output.Rollback.Changed || input.Descriptor.RollbackID == "" {
		return false, nil
	}
	rollbackCtx := context.WithoutCancel(ctx)
	err := r.rollback.Rollback(rollbackCtx, RollbackRequest{Action: input.Action, Descriptor: input.Descriptor, Workspace: input.Workspace, State: output.Rollback})
	return err == nil, err
}

func validateOutput(output ExecutionOutput, limits tools.ResourceLimits) error {
	if output.Bytes < 0 || output.Files < 0 {
		return fmt.Errorf("%w: negative output accounting", ErrResourceLimit)
	}
	if output.Bytes > limits.MaxOutputBytes || output.Files > limits.MaxFiles || output.Bytes > limits.MaxTotalBytes || output.Bytes > limits.MaxDiskBytes || output.Bytes > limits.MaxMemoryBytes {
		return fmt.Errorf("%w: output exceeded declared bound", ErrResourceLimit)
	}
	encoded, err := json.Marshal(output.Value)
	if err != nil {
		return fmt.Errorf("%w: output is not serializable", ErrExecution)
	}
	if int64(len(encoded))+int64(len(output.Diff)) > limits.MaxOutputBytes {
		return fmt.Errorf("%w: serialized output exceeded declared bound", ErrResourceLimit)
	}
	return nil
}

func effectiveLimits(descriptor, runner, request tools.ResourceLimits) (tools.ResourceLimits, error) {
	if err := descriptor.Validate(); err != nil {
		return tools.ResourceLimits{}, err
	}
	if err := runner.Validate(); err != nil {
		return tools.ResourceLimits{}, err
	}
	if request != (tools.ResourceLimits{}) {
		if err := validatePartialLimits(request); err != nil {
			return tools.ResourceLimits{}, err
		}
		if exceedsNonZero(request, descriptor) {
			return tools.ResourceLimits{}, fmt.Errorf("%w: request exceeds catalog bounds", ErrResourceLimit)
		}
	}
	limits := minPositive(descriptor, runner)
	if request != (tools.ResourceLimits{}) {
		limits = minPositive(limits, request)
	}
	if err := limits.Validate(); err != nil {
		return tools.ResourceLimits{}, err
	}
	return limits, nil
}

func validatePartialLimits(value tools.ResourceLimits) error {
	if value.MaxDuration < 0 || value.MaxInputBytes < 0 || value.MaxOutputBytes < 0 || value.MaxFiles < 0 || value.MaxFileBytes < 0 || value.MaxTotalBytes < 0 || value.MaxTokens < 0 || value.MaxMemoryBytes < 0 || value.MaxDiskBytes < 0 {
		return fmt.Errorf("%w: request limits cannot be negative", ErrResourceLimit)
	}
	return nil
}

func exceedsNonZero(value, maximum tools.ResourceLimits) bool {
	return value.MaxDuration > 0 && value.MaxDuration > maximum.MaxDuration || value.MaxInputBytes > 0 && value.MaxInputBytes > maximum.MaxInputBytes || value.MaxOutputBytes > 0 && value.MaxOutputBytes > maximum.MaxOutputBytes || value.MaxFiles > 0 && value.MaxFiles > maximum.MaxFiles || value.MaxFileBytes > 0 && value.MaxFileBytes > maximum.MaxFileBytes || value.MaxTotalBytes > 0 && value.MaxTotalBytes > maximum.MaxTotalBytes || value.MaxTokens > 0 && value.MaxTokens > maximum.MaxTokens || value.MaxMemoryBytes > 0 && value.MaxMemoryBytes > maximum.MaxMemoryBytes || value.MaxDiskBytes > 0 && value.MaxDiskBytes > maximum.MaxDiskBytes
}

func minPositive(left, right tools.ResourceLimits) tools.ResourceLimits {
	return tools.ResourceLimits{
		MaxDuration:    minDuration(left.MaxDuration, right.MaxDuration),
		MaxInputBytes:  minInt64(left.MaxInputBytes, right.MaxInputBytes),
		MaxOutputBytes: minInt64(left.MaxOutputBytes, right.MaxOutputBytes),
		MaxFiles:       minInt(left.MaxFiles, right.MaxFiles),
		MaxFileBytes:   minInt64(left.MaxFileBytes, right.MaxFileBytes),
		MaxTotalBytes:  minInt64(left.MaxTotalBytes, right.MaxTotalBytes),
		MaxTokens:      minInt64(left.MaxTokens, right.MaxTokens),
		MaxMemoryBytes: minInt64(left.MaxMemoryBytes, right.MaxMemoryBytes),
		MaxDiskBytes:   minInt64(left.MaxDiskBytes, right.MaxDiskBytes),
	}
}

func minDuration(left, right time.Duration) time.Duration {
	if left == 0 {
		return right
	}
	if right == 0 || left < right {
		return left
	}
	return right
}

func minInt(left, right int) int {
	if left == 0 {
		return right
	}
	if right == 0 || left < right {
		return left
	}
	return right
}

func minInt64(left, right int64) int64 {
	if left == 0 {
		return right
	}
	if right == 0 || left < right {
		return left
	}
	return right
}

func effectiveNetwork(descriptor, runner, request tools.NetworkPolicy) (tools.NetworkPolicy, error) {
	if err := descriptor.Validate(); err != nil {
		return tools.NetworkPolicy{}, err
	}
	if err := runner.Validate(); err != nil {
		return tools.NetworkPolicy{}, err
	}
	descriptor = normalizeNetwork(descriptor)
	runner = normalizeNetwork(runner)
	request = normalizeNetwork(request)
	if descriptor.Mode != tools.NetworkDisabled || runner.Mode != tools.NetworkDisabled || request.Mode != tools.NetworkDisabled || request.AllowMetadata || len(request.AllowedCIDRs) != 0 {
		return tools.NetworkPolicy{}, fmt.Errorf("%w: built-in runner has no network capability", ErrNetworkDenied)
	}
	return tools.NetworkPolicy{Mode: tools.NetworkDisabled}, nil
}

func normalizeNetwork(policy tools.NetworkPolicy) tools.NetworkPolicy {
	if strings.TrimSpace(string(policy.Mode)) == "" {
		policy.Mode = tools.NetworkDisabled
	}
	return policy
}

func requestDigest(request ActionRequest) (string, error) {
	// Paths are included in the digest, but the digest is never logged with the
	// path. It only binds a replay key to the exact bounded request.
	canonical := struct {
		Action        domain.AIAction
		Workspace     Workspace
		WorkspaceRoot string
		DraftRoot     string
		Confirmed     bool
		TokenCount    int64
		Limits        tools.ResourceLimits
		Network       tools.NetworkPolicy
	}{request.Action, request.Workspace, request.WorkspaceRoot, request.DraftRoot, request.Confirmed, max(request.TokenCount, request.Tokens), request.Limits, request.Network}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func max(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func cloneAction(action domain.AIAction) domain.AIAction {
	clone := action
	if action.Parameters != nil {
		clone.Parameters = cloneMap(action.Parameters)
	}
	return clone
}

func cloneMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return map[string]any{}
	}
	var clone map[string]any
	if json.Unmarshal(encoded, &clone) != nil {
		return map[string]any{}
	}
	return clone
}

func cloneResult(result RunResult) RunResult {
	encoded, err := json.Marshal(result)
	if err != nil {
		return result
	}
	var clone RunResult
	if json.Unmarshal(encoded, &clone) != nil {
		return result
	}
	return clone
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	// Do not copy arbitrary executor/model text into an evidence result. The
	// error class is enough for policy and the detailed cause stays in the
	// caller's typed error chain.
	for _, classified := range []struct {
		err  error
		text string
	}{
		{ErrTimeout, ErrTimeout.Error()},
		{ErrCancelled, ErrCancelled.Error()},
		{ErrResourceLimit, ErrResourceLimit.Error()},
		{ErrVerification, ErrVerification.Error()},
		{ErrRollback, ErrRollback.Error()},
		{ErrCleanup, ErrCleanup.Error()},
		{ErrControllerHandoff, ErrControllerHandoff.Error()},
		{ErrConfirmationRequired, ErrConfirmationRequired.Error()},
		{tools.ErrParameters, tools.ErrParameters.Error()},
		{tools.ErrForbidden, tools.ErrForbidden.Error()},
		{tools.ErrNotFound, tools.ErrNotFound.Error()},
		{tools.ErrVersion, tools.ErrVersion.Error()},
	} {
		if errors.Is(err, classified.err) {
			return classified.text
		}
	}
	return ErrExecution.Error()
}

func cleanupTempPaths(workspace Workspace, paths []string) error {
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" || path == "." || filepath.IsAbs(path) {
			return fmt.Errorf("%w: cleanup path must be relative and non-empty", ErrCleanup)
		}
		resolved, err := securePath(workspace, path, false, true)
		if err != nil {
			return err
		}
		if filepath.Clean(resolved) == filepath.Clean(workspace.Root) {
			return fmt.Errorf("%w: refusing to remove workspace root", ErrCleanup)
		}
		if err := os.RemoveAll(resolved); err != nil {
			return err
		}
	}
	return nil
}

func fileLinkCount(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 1
	}
	return uint64(stat.Nlink)
}

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func outputDigest(value any, diff string) string {
	encoded, _ := json.Marshal(value)
	h := sha256.New()
	_, _ = h.Write(encoded)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(diff))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func sortedStrings(values []string) []string {
	copyOf := append([]string(nil), values...)
	sort.Strings(copyOf)
	return copyOf
}

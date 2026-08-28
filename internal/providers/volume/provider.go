// Package volume implements the Open Card VolumeProvider with Docker named
// volumes.  The provider owns only volumes in its task namespace; it never
// accepts host paths or acts on an unlabelled Docker volume.
package volume

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	providerName    = "docker-named-volume"
	providerVersion = "m2"
	defaultTimeout  = 2 * time.Minute
	volumeSegment   = "volume"
)

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// CommandRunner is the only Docker execution boundary.  Tests inject a
// recorder/fake and therefore never need a Docker daemon.
type CommandRunner interface {
	Run(context.Context, string, []string, io.Writer, io.Writer) error
}

// Runner is a readable compatibility alias for callers that name the
// dependency simply as a runner.
type Runner = CommandRunner

type execRunner struct{}

func (execRunner) Run(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// Config contains the provider-owned Docker boundary.  TaskPrefix is required
// and is used to derive every volume name and ownership label.  Command and
// Runner are injectable for tests and for an Agent process with a restricted
// Docker command boundary.
type Config struct {
	Command    string
	TaskPrefix string
	Runner     CommandRunner
	Timeout    time.Duration
}

func (c Config) normalized() (Config, error) {
	if c.Command == "" {
		c.Command = "docker"
	}
	if !safeName.MatchString(strings.TrimSpace(c.TaskPrefix)) {
		return Config{}, errors.New("volume task prefix must be a safe non-empty name")
	}
	c.TaskPrefix = strings.TrimSpace(c.TaskPrefix)
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
	if c.Timeout <= 0 {
		return Config{}, errors.New("volume timeout must be positive")
	}
	if c.Runner == nil {
		c.Runner = execRunner{}
	}
	return c, nil
}

// VolumeFacts is the redacted, checksum-friendly fact set returned by Docker
// inspect.  Mountpoint is included as an observation for a trusted local
// integration to checksum; it is never accepted as an input to this provider.
type VolumeFacts struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint"`
	Scope      string            `json:"scope,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
	Status     map[string]any    `json:"status,omitempty"`
	CreatedAt  string            `json:"created_at,omitempty"`
}

// Facts is kept as a short alias for integration code that calls an inspect
// result a fact set.
type Facts = VolumeFacts

type Provider struct {
	config   Config
	metadata contracts.ProviderMetadata

	mu         sync.Mutex
	operations map[string]*operationRecord
}

type operationRecord struct {
	action      string
	fingerprint string
	done        chan struct{}
	volume      contracts.VolumeSpec
	evidence    contracts.Evidence
	err         error
}

var _ contracts.VolumeProvider = (*Provider)(nil)

// New constructs a fail-closed provider.  It does not contact Docker until an
// operation is requested.
func New(config Config) (*Provider, error) {
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	return &Provider{
		config: config,
		metadata: contracts.ProviderMetadata{
			Name:            providerName,
			Version:         providerVersion,
			ContractVersion: contracts.ContractAPIVersion,
			Capabilities:    contracts.NewCapabilitySet(contracts.CapabilityVolumeManage),
			SensitiveInputs: []string{"confirmation token"},
		},
		operations: make(map[string]*operationRecord),
	}, nil
}

// NewProvider is an explicit composition-root alias.
func NewProvider(config Config) (*Provider, error) { return New(config) }

func (p *Provider) Metadata(context.Context) contracts.ProviderMetadata { return p.metadata }

// ResourceName returns the Docker name for a logical volume name.  Callers
// may pass an already-derived name when replaying persisted state; names from
// another namespace are rejected.
func (p *Provider) ResourceName(name string) (string, error) {
	return p.resourceName(name)
}

// Create creates or adopts one task-owned named volume.  Existing volumes are
// accepted only when inspect proves that they belong to this provider and
// namespace.  Creation is retained by default; this method never removes a
// volume as compensation.
func (p *Provider) Create(ctx context.Context, request contracts.VolumeRequest) (contracts.VolumeSpec, contracts.Evidence, error) {
	if err := p.check(ctx, request.Operation, "create"); err != nil {
		return contracts.VolumeSpec{}, contracts.Evidence{}, err
	}
	physical, err := p.resourceName(request.Volume.Name)
	if err != nil {
		return contracts.VolumeSpec{}, contracts.Evidence{}, p.failure(request.Operation, contracts.ErrInvalidArgument, "create", err.Error(), contracts.RetryNever, false, err)
	}
	if err := validateSpec(request.Volume); err != nil {
		return contracts.VolumeSpec{}, contracts.Evidence{}, p.failure(request.Operation, contracts.ErrValidation, "create", err.Error(), contracts.RetryNever, false, err)
	}
	resultSpec := request.Volume
	resultSpec.Name = physical
	fingerprint := operationFingerprint("create", resultSpec, false)
	record, wait, err := p.begin(request.Operation.IdempotencyKey, "create", fingerprint)
	if err != nil {
		return contracts.VolumeSpec{}, contracts.Evidence{}, p.failure(request.Operation, contracts.ErrConflict, "create", err.Error(), contracts.RetryNever, false, err)
	}
	if wait {
		if err := p.waitOperation(ctx, request.Operation, "create", record); err != nil {
			return contracts.VolumeSpec{}, contracts.Evidence{}, err
		}
		return record.volume, record.evidence, record.err
	}

	resultSpec, evidence, opErr := p.create(ctx, request.Operation, request.Volume, physical)
	p.finish(record, resultSpec, evidence, opErr)
	return resultSpec, evidence, opErr
}

func (p *Provider) create(ctx context.Context, operation contracts.OperationContext, requested contracts.VolumeSpec, physical string) (contracts.VolumeSpec, contracts.Evidence, error) {
	inspect, exists, err := p.inspectOwned(ctx, operation, "create", physical)
	if err != nil {
		return contracts.VolumeSpec{}, contracts.Evidence{}, err
	}
	if exists {
		if err := p.verifyExisting(inspect, requested, physical, operation, "create"); err != nil {
			return contracts.VolumeSpec{}, contracts.Evidence{}, err
		}
		result := requested
		result.Name = physical
		return result, p.evidence(operation, "volume.create", physical, inspect), nil
	}

	args := []string{
		"volume", "create",
		"--label", "open-card.managed=true",
		"--label", "open-card.task-prefix=" + p.config.TaskPrefix,
		"--label", "open-card.task=" + p.config.TaskPrefix,
		"--label", "open-card.volume-logical-name=" + requested.Name,
		"--label", "open-card.volume-mount-path=" + requested.MountPath,
		"--label", "open-card.volume-size-bytes=" + fmt.Sprint(requested.SizeBytes),
		"--label", "open-card.retention=retain",
		physical,
	}
	output, _, err := p.output(ctx, operation, "create", args)
	if err != nil {
		return contracts.VolumeSpec{}, contracts.Evidence{}, p.commandError(operation, "create", err)
	}
	if got := strings.TrimSpace(output); got != "" && got != physical {
		return contracts.VolumeSpec{}, contracts.Evidence{}, p.failure(operation, contracts.ErrConflict, "create", "Docker created a different volume name", contracts.RetryNever, false, nil)
	}

	// Re-inspect after create.  A successful CLI exit alone is not ownership or
	// lifecycle evidence.
	inspect, exists, err = p.inspectOwned(ctx, operation, "create", physical)
	if err != nil {
		return contracts.VolumeSpec{}, contracts.Evidence{}, err
	}
	if !exists {
		return contracts.VolumeSpec{}, contracts.Evidence{}, p.failure(operation, contracts.ErrValidation, "create", "Docker volume create returned success but the volume is absent", contracts.RetryNever, false, nil)
	}
	if err := p.verifyExisting(inspect, requested, physical, operation, "create"); err != nil {
		return contracts.VolumeSpec{}, contracts.Evidence{}, err
	}
	result := requested
	result.Name = physical
	return result, p.evidence(operation, "volume.create", physical, inspect), nil
}

// Attach validates that the named volume exists and is owned by this task.
// Docker named volumes are attached by the runtime container operation; the
// contract has no container identifier, so this provider records the fact
// without issuing an unsafe ad-hoc container mutation.
func (p *Provider) Attach(ctx context.Context, request contracts.VolumeRequest) error {
	return p.stateOperation(ctx, request, "attach")
}

// Detach validates the same ownership boundary.  Runtime container teardown
// performs the actual unmount; the volume remains retained.
func (p *Provider) Detach(ctx context.Context, request contracts.VolumeRequest) error {
	return p.stateOperation(ctx, request, "detach")
}

// Retain is an explicit, idempotent assertion of the default retention policy.
// It intentionally has no Docker mutation because Docker volume retention is
// represented by the volume's continued existence.
func (p *Provider) Retain(ctx context.Context, request contracts.VolumeRequest) error {
	return p.stateOperation(ctx, request, "retain")
}

func (p *Provider) stateOperation(ctx context.Context, request contracts.VolumeRequest, action string) error {
	if err := p.check(ctx, request.Operation, action); err != nil {
		return err
	}
	physical, err := p.resourceName(request.Volume.Name)
	if err != nil {
		return p.failure(request.Operation, contracts.ErrInvalidArgument, action, err.Error(), contracts.RetryNever, false, err)
	}
	if err := validateSpec(request.Volume); err != nil {
		return p.failure(request.Operation, contracts.ErrValidation, action, err.Error(), contracts.RetryNever, false, err)
	}
	fingerprint := operationFingerprint(action, contracts.VolumeSpec{Name: physical, MountPath: request.Volume.MountPath, SizeBytes: request.Volume.SizeBytes}, false)
	record, wait, err := p.begin(request.Operation.IdempotencyKey, action, fingerprint)
	if err != nil {
		return p.failure(request.Operation, contracts.ErrConflict, action, err.Error(), contracts.RetryNever, false, err)
	}
	if wait {
		if err := p.waitOperation(ctx, request.Operation, action, record); err != nil {
			return err
		}
		return record.err
	}

	_, exists, opErr := p.inspectOwned(ctx, request.Operation, action, physical)
	if opErr == nil && !exists {
		opErr = p.failure(request.Operation, contracts.ErrNotFound, action, "managed volume was not found", contracts.RetryUserAction, false, nil)
	}
	var evidence contracts.Evidence
	if opErr == nil {
		evidence = p.evidence(request.Operation, "volume."+action, physical, VolumeFacts{Name: physical})
	}
	p.finish(record, contracts.VolumeSpec{}, evidence, opErr)
	return opErr
}

// Destroy is the only destructive operation. It requires the exact physical
// volume-scoped confirmation token before inspecting or invoking Docker, so a
// confirmation for one claim cannot be replayed against another claim. The
// token is never persisted in an operation fingerprint or evidence.
func (p *Provider) Destroy(ctx context.Context, request contracts.VolumeRequest) error {
	if err := p.check(ctx, request.Operation, "destroy"); err != nil {
		return err
	}
	physical, err := p.resourceName(request.Volume.Name)
	if err != nil {
		return p.failure(request.Operation, contracts.ErrInvalidArgument, "destroy", err.Error(), contracts.RetryNever, false, err)
	}
	if request.ConfirmationToken != p.DestroyConfirmationToken(physical) {
		return p.failure(request.Operation, contracts.ErrUnauthorized, "destroy", "exact volume-scoped confirmation token is required", contracts.RetryUserAction, false, nil)
	}
	if err := validateSpec(request.Volume); err != nil {
		return p.failure(request.Operation, contracts.ErrValidation, "destroy", err.Error(), contracts.RetryNever, false, err)
	}
	fingerprint := operationFingerprint("destroy", contracts.VolumeSpec{Name: physical, MountPath: request.Volume.MountPath, SizeBytes: request.Volume.SizeBytes}, true)
	record, wait, err := p.begin(request.Operation.IdempotencyKey, "destroy", fingerprint)
	if err != nil {
		return p.failure(request.Operation, contracts.ErrConflict, "destroy", err.Error(), contracts.RetryNever, false, err)
	}
	if wait {
		if err := p.waitOperation(ctx, request.Operation, "destroy", record); err != nil {
			return err
		}
		return record.err
	}

	_, exists, opErr := p.inspectOwned(ctx, request.Operation, "destroy", physical)
	if opErr == nil && !exists {
		opErr = p.failure(request.Operation, contracts.ErrNotFound, "destroy", "managed volume was not found", contracts.RetryUserAction, false, nil)
	}
	if opErr == nil {
		if _, _, err := p.output(ctx, request.Operation, "destroy", []string{"volume", "rm", "--force", physical}); err != nil {
			opErr = p.commandError(request.Operation, "destroy", err)
		}
	}
	p.finish(record, contracts.VolumeSpec{}, contracts.Evidence{}, opErr)
	return opErr
}

// DestroyConfirmationToken returns the explicit non-secret phrase required
// for deleting one exact task-owned Docker volume.
func (p *Provider) DestroyConfirmationToken(name string) string {
	physical, err := p.resourceName(name)
	if err != nil {
		return ""
	}
	return "confirm-volume-destroy:" + physical
}

// Inspect returns the current owned Docker facts and redacted evidence.  It is
// intentionally read-only and is useful to integration tests that compute a
// checksum from the reported Mountpoint.
func (p *Provider) Inspect(ctx context.Context, request contracts.VolumeRequest) (VolumeFacts, contracts.Evidence, error) {
	if err := p.check(ctx, request.Operation, "inspect"); err != nil {
		return VolumeFacts{}, contracts.Evidence{}, err
	}
	physical, err := p.resourceName(request.Volume.Name)
	if err != nil {
		return VolumeFacts{}, contracts.Evidence{}, p.failure(request.Operation, contracts.ErrInvalidArgument, "inspect", err.Error(), contracts.RetryNever, false, err)
	}
	facts, exists, err := p.inspectOwned(ctx, request.Operation, "inspect", physical)
	if err != nil {
		return VolumeFacts{}, contracts.Evidence{}, err
	}
	if !exists {
		return VolumeFacts{}, contracts.Evidence{}, p.failure(request.Operation, contracts.ErrNotFound, "inspect", "managed volume was not found", contracts.RetryUserAction, false, nil)
	}
	return facts, p.evidence(request.Operation, "volume.inspect", physical, facts), nil
}

// InspectFacts is a convenience form for callers that do not need evidence.
func (p *Provider) InspectFacts(ctx context.Context, request contracts.VolumeRequest) (VolumeFacts, error) {
	facts, _, err := p.Inspect(ctx, request)
	return facts, err
}

// Facts is an alias for Inspect for integrations that use fact terminology.
func (p *Provider) Facts(ctx context.Context, request contracts.VolumeRequest) (VolumeFacts, contracts.Evidence, error) {
	return p.Inspect(ctx, request)
}

func (p *Provider) inspectOwned(ctx context.Context, operation contracts.OperationContext, action, physical string) (VolumeFacts, bool, error) {
	output, stderr, err := p.output(ctx, operation, action, []string{"volume", "inspect", "--format", "{{json .}}", physical})
	if err != nil {
		if isNotFound(strings.Join([]string{output, stderr, err.Error()}, "\n")) {
			return VolumeFacts{}, false, nil
		}
		return VolumeFacts{}, false, p.commandError(operation, action, err)
	}
	facts, err := parseFacts(output)
	if err != nil {
		return VolumeFacts{}, true, p.failure(operation, contracts.ErrValidation, action, "Docker returned invalid volume inspection data", contracts.RetryNever, false, err)
	}
	if err := verifyOwnership(facts, p.config.TaskPrefix, physical); err != nil {
		return VolumeFacts{}, true, p.failure(operation, contracts.ErrConflict, action, err.Error(), contracts.RetryNever, false, err)
	}
	return facts, true, nil
}

func (p *Provider) verifyExisting(facts VolumeFacts, requested contracts.VolumeSpec, physical string, operation contracts.OperationContext, action string) error {
	if err := verifyOwnership(facts, p.config.TaskPrefix, physical); err != nil {
		return p.failure(operation, contracts.ErrConflict, action, err.Error(), contracts.RetryNever, false, err)
	}
	labels := facts.Labels
	if value := labels["open-card.volume-logical-name"]; value != "" && value != requested.Name && requested.Name != physical {
		return p.failure(operation, contracts.ErrConflict, action, "managed volume has a different logical name", contracts.RetryNever, false, nil)
	}
	if value := labels["open-card.volume-mount-path"]; value != "" && value != requested.MountPath {
		return p.failure(operation, contracts.ErrConflict, action, "managed volume has a different mount path", contracts.RetryNever, false, nil)
	}
	if value := labels["open-card.volume-size-bytes"]; value != "" && value != fmt.Sprint(requested.SizeBytes) {
		return p.failure(operation, contracts.ErrConflict, action, "managed volume has a different requested size", contracts.RetryNever, false, nil)
	}
	if value := labels["open-card.retention"]; value != "" && value != "retain" {
		return p.failure(operation, contracts.ErrConflict, action, "managed volume does not have the retain-by-default policy", contracts.RetryNever, false, nil)
	}
	return nil
}

func verifyOwnership(facts VolumeFacts, taskPrefix, physical string) error {
	if strings.TrimSpace(facts.Name) != physical {
		return fmt.Errorf("Docker volume name does not match the task-scoped resource")
	}
	if facts.Labels["open-card.managed"] != "true" {
		return fmt.Errorf("Docker volume is not managed by Open Card")
	}
	prefix, hasPrefix := facts.Labels["open-card.task-prefix"]
	task, hasTask := facts.Labels["open-card.task"]
	if (hasPrefix && prefix != taskPrefix) || (hasTask && task != taskPrefix) || (!hasPrefix && !hasTask) {
		return fmt.Errorf("Docker volume does not belong to this task prefix")
	}
	if strings.TrimSpace(facts.Driver) == "" {
		return fmt.Errorf("Docker volume inspection omitted its driver")
	}
	return nil
}

func parseFacts(output string) (VolumeFacts, error) {
	value := strings.TrimSpace(output)
	if value == "" {
		return VolumeFacts{}, errors.New("empty Docker volume inspection")
	}
	// The format string above emits one JSON object.  Accepting one-element
	// arrays makes the read path tolerant of an integration runner that uses the
	// default `docker volume inspect` output while remaining fail-closed.
	var facts VolumeFacts
	if err := json.Unmarshal([]byte(value), &facts); err != nil {
		var list []VolumeFacts
		if listErr := json.Unmarshal([]byte(value), &list); listErr != nil || len(list) != 1 {
			return VolumeFacts{}, err
		}
		facts = list[0]
	}
	if facts.Labels == nil {
		facts.Labels = map[string]string{}
	}
	return facts, nil
}

func (p *Provider) resourceName(name string) (string, error) {
	if strings.TrimSpace(name) != name {
		return "", errors.New("volume name must not have leading or trailing whitespace")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("volume name is required")
	}
	if strings.ContainsAny(name, "/\\\x00\r\n") || strings.Contains(name, "..") {
		return "", errors.New("volume name must be a safe named-volume identifier")
	}
	if !safeName.MatchString(name) {
		return "", errors.New("volume name must be a safe named-volume identifier")
	}
	fullPrefix := p.config.TaskPrefix + "-" + volumeSegment + "-"
	if strings.HasPrefix(name, fullPrefix) {
		if len(name) > 255 {
			return "", errors.New("volume name is too long")
		}
		return name, nil
	}
	// A caller may not smuggle a different provider namespace as a logical
	// name.  The derived name remains under this provider's exact prefix.
	if strings.Contains(name, "-volume-") {
		return "", errors.New("volume name contains a foreign volume namespace")
	}
	resolved := fullPrefix + name
	if len(resolved) > 255 {
		return "", errors.New("volume name is too long")
	}
	return resolved, nil
}

func validateSpec(spec contracts.VolumeSpec) error {
	if spec.SizeBytes < 0 {
		return errors.New("volume size cannot be negative")
	}
	if spec.MountPath != "" && (strings.Contains(spec.MountPath, "\x00") || !strings.HasPrefix(spec.MountPath, "/")) {
		return errors.New("volume mount path must be absolute when supplied")
	}
	return nil
}

func (p *Provider) begin(key, action, fingerprint string) (*operationRecord, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if previous, ok := p.operations[key]; ok {
		if previous.action != action || previous.fingerprint != fingerprint {
			return nil, false, errors.New("idempotency key was reused for a different volume operation")
		}
		return previous, true, nil
	}
	record := &operationRecord{action: action, fingerprint: fingerprint, done: make(chan struct{})}
	p.operations[key] = record
	return record, false, nil
}

func (p *Provider) finish(record *operationRecord, volume contracts.VolumeSpec, evidence contracts.Evidence, err error) {
	p.mu.Lock()
	record.volume, record.evidence, record.err = volume, evidence, err
	close(record.done)
	p.mu.Unlock()
}

func (p *Provider) waitOperation(ctx context.Context, operation contracts.OperationContext, action string, record *operationRecord) error {
	select {
	case <-record.done:
		return nil
	case <-ctx.Done():
		return p.contextError(operation, action, ctx.Err())
	}
}

func operationFingerprint(action string, spec contracts.VolumeSpec, confirmed bool) string {
	value := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%t", action, spec.Name, spec.MountPath, spec.SizeBytes, confirmed)
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (p *Provider) output(ctx context.Context, operation contracts.OperationContext, action string, args []string) (string, string, error) {
	operationCtx, cancel := p.operationContext(ctx, operation)
	defer cancel()
	var stdout, stderr bytes.Buffer
	if err := p.config.Runner.Run(operationCtx, p.config.Command, args, &stdout, &stderr); err != nil {
		if errors.Is(operationCtx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return stdout.String(), stderr.String(), p.failure(operation, contracts.ErrTimeout, action, "provider operation timed out", contracts.RetryBackoff, true, context.DeadlineExceeded)
		}
		if errors.Is(operationCtx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return stdout.String(), stderr.String(), p.failure(operation, contracts.ErrCancelled, action, "provider operation was cancelled", contracts.RetryAfterReconnect, true, context.Canceled)
		}
		return stdout.String(), stderr.String(), err
	}
	return stdout.String(), stderr.String(), nil
}

func (p *Provider) commandError(operation contracts.OperationContext, action string, cause error) error {
	if providerErr, ok := cause.(*contracts.ProviderError); ok {
		return providerErr
	}
	return p.failure(operation, contracts.ErrUnavailable, action, "Docker command failed", contracts.RetryBackoff, true, nil)
}

func (p *Provider) check(ctx context.Context, operation contracts.OperationContext, action string) error {
	if err := p.metadata.Supports(contracts.CapabilityVolumeManage); err != nil {
		return err
	}
	if err := operation.Validate(); err != nil {
		return p.failure(operation, contracts.ErrInvalidArgument, action, "provider idempotency key is required", contracts.RetryNever, false, err)
	}
	if err := ctx.Err(); err != nil {
		return p.contextError(operation, action, err)
	}
	if !operation.Deadline.IsZero() && !time.Now().Before(operation.Deadline) {
		return p.contextError(operation, action, context.DeadlineExceeded)
	}
	return nil
}

func (p *Provider) operationContext(ctx context.Context, operation contracts.OperationContext) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(p.config.Timeout)
	if !operation.Deadline.IsZero() && operation.Deadline.Before(deadline) {
		deadline = operation.Deadline
	}
	return context.WithDeadline(ctx, deadline)
}

func (p *Provider) contextError(operation contracts.OperationContext, action string, cause error) error {
	if errors.Is(cause, context.DeadlineExceeded) {
		return p.failure(operation, contracts.ErrTimeout, action, "provider operation timed out", contracts.RetryBackoff, true, cause)
	}
	return p.failure(operation, contracts.ErrCancelled, action, "provider operation was cancelled", contracts.RetryAfterReconnect, true, cause)
}

func (p *Provider) failure(operation contracts.OperationContext, code contracts.ErrorCode, action, message string, retry contracts.RetryClass, retryable bool, cause error) error {
	return &contracts.ProviderError{
		Provider:   p.metadata.Name,
		Code:       code,
		Message:    message,
		Retry:      retry,
		Retryable:  retryable,
		Capability: contracts.CapabilityVolumeManage,
		Operation:  action,
		Cause:      cause,
		Details: map[string]string{
			"evidence_ref": string(evidenceID(p.metadata.Name, action, operation.IdempotencyKey)),
			"log_ref":      "docker-volume://" + p.metadata.Name + "/" + action + "/" + shortHash(operation.IdempotencyKey),
		},
	}
}

func (p *Provider) evidence(operation contracts.OperationContext, kind, physical string, facts VolumeFacts) contracts.Evidence {
	digest := factsDigest(facts)
	if digest == "" {
		digest = "sha256:" + shortHash(p.metadata.Name, kind, physical, operation.IdempotencyKey)
	}
	return contracts.Evidence{
		Refs:     []domain.EvidenceRef{{ID: evidenceID(p.metadata.Name, kind, operation.IdempotencyKey), Kind: kind, Digest: digest, Locator: "docker://volume/" + physical}},
		Summary:  "redacted managed Docker named-volume facts",
		Digest:   digest,
		Redacted: true,
	}
}

func factsDigest(facts VolumeFacts) string {
	if facts.Name == "" && facts.Driver == "" && facts.Mountpoint == "" && len(facts.Labels) == 0 {
		return ""
	}
	labels := make([]string, 0, len(facts.Labels))
	for key, value := range facts.Labels {
		labels = append(labels, key+"="+value)
	}
	sort.Strings(labels)
	value := strings.Join([]string{facts.Name, facts.Driver, facts.Mountpoint, facts.Scope, strings.Join(labels, "\x00")}, "\x00")
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func evidenceID(parts ...string) domain.ID { return domain.ID("ev_" + shortHash(parts...)[:32]) }

func shortHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func isNotFound(value string) bool {
	value = strings.ToLower(value)
	for _, phrase := range []string{"no such volume", "no such object", "volume not found", "does not exist", "not found"} {
		if strings.Contains(value, phrase) {
			return true
		}
	}
	return false
}

// Package sourcebuildexecution is a source-only provider adapter. Core durable
// facts, peer binding, RPC consumers and the production role are not implemented
// here; constructing this wrapper does not make a deployable Native component.
package sourcebuildexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/importers/dockerfile"
)

type CancelSourceBuildRequest struct {
	BuildID          domain.ID                  `json:"build_id"`
	PlanID           domain.ID                  `json:"plan_id"`
	SourceRevisionID domain.ID                  `json:"source_revision_id"`
	Operation        contracts.OperationContext `json:"operation"`
}

// Exactly one stage payload is present. Build.Source and Release.Revision must
// be the immutable source already persisted by Core, including its opaque
// workspace reference; callers do not choose new paths or invent Core facts.
type SourceBuildCommand struct {
	Stage   appcontracts.SourceBuildStage   `json:"stage"`
	Binding appcontracts.SourceBuildBinding `json:"binding"`
	Prepare *contracts.PrepareSourceRequest `json:"prepare,omitempty"`
	Build   *contracts.BuildRequest         `json:"build,omitempty"`
	Cancel  *CancelSourceBuildRequest       `json:"cancel,omitempty"`
	Release *contracts.ReleaseSourceRequest `json:"release,omitempty"`
}

// SourceBuildAuthority is an unimplemented Core seam, not a health/allow flag.
// A future consumer checks current task/owner/generations, admin/application,
// immutable source/workspace, approved plan/resources/network/capacity and the
// original build cancellation key, then binds ALL stage input to this digest.
// Caller cancellation/lease loss must cancel the execution context while a
// provider is running; this wrapper does not add a second durable controller.
type SourceBuildAuthority interface {
	AuthorizeSourceBuild(context.Context, SourceBuildCommand) (appcontracts.SourceBuildPermit, error)
}

func SourceBuildCommandDigest(command SourceBuildCommand) (string, error) {
	raw, err := json.Marshal(command)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type PreparedSourceBuildReceipt struct {
	Binding       appcontracts.SourceBuildBinding        `json:"binding"`
	CommandSHA256 string                                 `json:"command_sha256"`
	Result        contracts.PrepareSourceResult          `json:"result"`
	Definition    appcontracts.SourceBuildDefinitionFact `json:"definition"`
}

type SourceBuildOutputReceipt struct {
	Binding          appcontracts.SourceBuildBinding `json:"binding"`
	CommandSHA256    string                          `json:"command_sha256"`
	SourceRevisionID domain.ID                       `json:"source_revision_id"`
	SourceDigest     string                          `json:"source_digest"`
	Result           contracts.BuildResult           `json:"result"`
}

var ErrBinding = errors.New("source-build command or result identity is invalid")
var pinnedCommit = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

type Config struct {
	Source         contracts.SourceProvider
	BuilderFactory func(contracts.CapacityProvider) (contracts.BuildProvider, error)
	Authority      SourceBuildAuthority
	Capacity       contracts.CapacityProvider
}
type Runtime struct {
	source    contracts.SourceProvider
	builder   contracts.BuildProvider
	authority SourceBuildAuthority
	capacity  contracts.CapacityProvider
}

func NewRuntime(cfg Config) (*Runtime, error) {
	if cfg.Source == nil || cfg.BuilderFactory == nil || cfg.Authority == nil || cfg.Capacity == nil {
		return nil, errors.New("source/build providers and Core authority are required")
	}
	builder, err := cfg.BuilderFactory(cfg.Capacity)
	if err != nil {
		return nil, err
	}
	if builder == nil {
		return nil, errors.New("build provider factory returned nil")
	}
	return &Runtime{source: cfg.Source, builder: builder, authority: cfg.Authority, capacity: cfg.Capacity}, nil
}

// authorize gives the authority a separate typed copy, then restores the
// provider input from the same canonical bytes. Approval cannot mutate or
// substitute the command between its full-input digest and the effect.
func (r *Runtime) authorize(ctx context.Context, command SourceBuildCommand) (SourceBuildCommand, string, error) {
	if r == nil || ctx == nil {
		return SourceBuildCommand{}, "", ErrBinding
	}
	if err := ctx.Err(); err != nil {
		return SourceBuildCommand{}, "", err
	}
	if command.Binding.TaskID.Empty() || command.Binding.OperationID.Empty() || command.Binding.ApplicationID.Empty() || strings.TrimSpace(command.Binding.Owner) == "" || command.Binding.CoreGeneration == 0 || command.Binding.LeaseGeneration == 0 {
		return SourceBuildCommand{}, "", ErrBinding
	}
	raw, err := json.Marshal(command)
	if err != nil {
		return SourceBuildCommand{}, "", err
	}
	var observed SourceBuildCommand
	if err := json.Unmarshal(raw, &observed); err != nil {
		return observed, "", err
	}
	digest, err := SourceBuildCommandDigest(command)
	if err != nil {
		return observed, "", err
	}
	permit, err := r.authority.AuthorizeSourceBuild(ctx, observed)
	if err != nil {
		return SourceBuildCommand{}, "", err
	}
	if permit.CommandSHA256 != digest {
		return SourceBuildCommand{}, "", ErrBinding
	}
	if err := ctx.Err(); err != nil {
		return SourceBuildCommand{}, "", err
	}
	var approved SourceBuildCommand
	if err := json.Unmarshal(raw, &approved); err != nil {
		return approved, "", err
	}
	return approved, digest, nil
}

func (r *Runtime) Prepare(ctx context.Context, binding appcontracts.SourceBuildBinding, request contracts.PrepareSourceRequest) (PreparedSourceBuildReceipt, error) {
	if request.ApplicationID != binding.ApplicationID || request.Kind != domain.SourceGitHTTPS || !pinnedCommit.MatchString(request.Ref) || request.WorkspaceRef != "" || request.Operation.Validate() != nil {
		return PreparedSourceBuildReceipt{}, ErrBinding
	}
	command, digest, err := r.authorize(ctx, SourceBuildCommand{Stage: appcontracts.SourceBuildPrepare, Binding: binding, Prepare: &request})
	if err != nil {
		return PreparedSourceBuildReceipt{}, err
	}
	prepared, err := r.source.Prepare(ctx, *command.Prepare)
	if err != nil {
		return PreparedSourceBuildReceipt{}, err
	}
	source := prepared.Revision
	if source.Validate() != nil || source.ApplicationID != binding.ApplicationID || source.Kind != request.Kind || source.Locator != strings.TrimSpace(request.Locator) || source.Commit != request.Ref || source.Ref != request.Ref || (strings.TrimSpace(request.ContentDigest) != "" && !sameContentDigest(request.ContentDigest, source.ContentDigest)) || !contracts.IsSHA256Digest(source.ContentDigest) {
		return PreparedSourceBuildReceipt{}, &contracts.ProviderOutcomeUnknownError{Cause: ErrBinding}
	}
	if err := ctx.Err(); err != nil {
		return PreparedSourceBuildReceipt{}, &contracts.ProviderOutcomeUnknownError{Cause: err}
	}
	definition, err := dockerfile.Import(source)
	if err != nil {
		return PreparedSourceBuildReceipt{}, &contracts.ProviderOutcomeUnknownError{Cause: err}
	}
	if err := ctx.Err(); err != nil {
		return PreparedSourceBuildReceipt{}, &contracts.ProviderOutcomeUnknownError{Cause: err}
	}
	if definition.Validate() != nil || definition.SourceRevisionID != source.ID || definition.SourceContentDigest != source.ContentDigest {
		return PreparedSourceBuildReceipt{}, &contracts.ProviderOutcomeUnknownError{Cause: ErrBinding}
	}
	fact := appcontracts.SourceBuildDefinitionFact{Status: string(definition.Status), SourceRevisionID: source.ID, SourceDigest: source.ContentDigest, DefinitionDigest: definition.DefinitionDigest, DockerfileDigest: definition.DockerfileDigest}
	// No BuildPlan/BuildID is generated here: Core must persist this receipt and
	// issue a separately approved Build request referencing the actual revision.
	return PreparedSourceBuildReceipt{Binding: binding, CommandSHA256: digest, Result: prepared, Definition: fact}, nil
}

func (r *Runtime) Build(ctx context.Context, binding appcontracts.SourceBuildBinding, request contracts.BuildRequest) (SourceBuildOutputReceipt, error) {
	if request.Capacity != nil || request.BuildID.Empty() || request.Operation.Validate() != nil || request.Plan.Validate() != nil || !validSource(binding, request.Source) || request.Plan.SourceRevisionID != request.Source.ID || request.Plan.SourceDigest != request.Source.ContentDigest {
		return SourceBuildOutputReceipt{}, ErrBinding
	}
	command, digest, err := r.authorize(ctx, SourceBuildCommand{Stage: appcontracts.SourceBuildBuild, Binding: binding, Build: &request})
	if err != nil {
		return SourceBuildOutputReceipt{}, err
	}
	// Core approves the full intent with no caller-selected lease. Only this
	// role-owned provider creates a lease, and BuildKit uses the same instance.
	capacityRequest := contracts.CapacityRequest{Scope: contracts.CapacityBuild, Resources: command.Build.Resources, Operation: command.Build.Operation}
	capacityRequest.Operation.IdempotencyKey += ":capacity-preflight"
	if _, _, err := r.capacity.Preflight(ctx, capacityRequest); err != nil {
		return SourceBuildOutputReceipt{}, err
	}
	capacityRequest.Operation.IdempotencyKey = command.Build.Operation.IdempotencyKey + ":capacity-reserve"
	lease, err := r.capacity.Reserve(ctx, capacityRequest)
	if err != nil {
		return SourceBuildOutputReceipt{}, err
	}
	if lease.ID == "" || lease.Scope != contracts.CapacityBuild || lease.Resources != command.Build.Resources || lease.HostPort != 0 || !lease.ExpiresAt.After(time.Now()) {
		return SourceBuildOutputReceipt{}, &contracts.ProviderOutcomeUnknownError{Cause: ErrBinding}
	}
	providerRequest := *command.Build
	providerRequest.Capacity = &lease
	built, err := r.builder.Build(ctx, providerRequest)
	if err != nil {
		// A stopped buildctl client does not prove its remote BuildKit job ended.
		// Keep the reservation until reconciliation; never blind retry/release.
		return SourceBuildOutputReceipt{}, &contracts.ProviderOutcomeUnknownError{Cause: err}
	}
	if built.Build.ID != request.BuildID || built.Build.PlanID != request.Plan.ID || built.Build.Status != domain.BuildSucceeded || built.Artifact == nil || built.Artifact.Validate() != nil || built.Artifact.BuildID != request.BuildID || built.Build.ArtifactID != built.Artifact.ID || built.Artifact.Image.Repository != request.Plan.TargetRepository || strings.TrimSpace(built.LogRef) == "" {
		return SourceBuildOutputReceipt{}, &contracts.ProviderOutcomeUnknownError{Cause: ErrBinding}
	}
	if err := ctx.Err(); err != nil {
		return SourceBuildOutputReceipt{}, &contracts.ProviderOutcomeUnknownError{Cause: err}
	}
	releaseOperation := command.Build.Operation
	releaseOperation.IdempotencyKey += ":capacity-release"
	if err := r.capacity.Release(ctx, lease, releaseOperation); err != nil {
		return SourceBuildOutputReceipt{}, &contracts.ProviderOutcomeUnknownError{Cause: err}
	}
	return SourceBuildOutputReceipt{Binding: binding, CommandSHA256: digest, SourceRevisionID: request.Source.ID, SourceDigest: request.Source.ContentDigest, Result: built}, nil
}

func (r *Runtime) Cancel(ctx context.Context, binding appcontracts.SourceBuildBinding, request CancelSourceBuildRequest) error {
	if request.BuildID.Empty() || request.PlanID.Empty() || request.SourceRevisionID.Empty() || request.Operation.Validate() != nil {
		return ErrBinding
	}
	command, _, err := r.authorize(ctx, SourceBuildCommand{Stage: appcontracts.SourceBuildCancel, Binding: binding, Cancel: &request})
	if err != nil {
		return err
	}
	return r.builder.Cancel(ctx, command.Cancel.Operation)
}

func (r *Runtime) Release(ctx context.Context, binding appcontracts.SourceBuildBinding, request contracts.ReleaseSourceRequest) error {
	if !validSource(binding, request.Revision) || request.Operation.Validate() != nil {
		return ErrBinding
	}
	command, _, err := r.authorize(ctx, SourceBuildCommand{Stage: appcontracts.SourceBuildRelease, Binding: binding, Release: &request})
	if err != nil {
		return err
	}
	return r.source.Release(ctx, *command.Release)
}

func validSource(binding appcontracts.SourceBuildBinding, source domain.SourceRevision) bool {
	return source.Validate() == nil && source.ApplicationID == binding.ApplicationID && source.Kind == domain.SourceGitHTTPS && pinnedCommit.MatchString(source.Commit) && source.Ref == source.Commit && contracts.IsSHA256Digest(source.ContentDigest)
}

func sameContentDigest(expected, actual string) bool {
	normalize := func(v string) string { return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "sha256:") }
	return normalize(expected) == normalize(actual)
}

// ExecuteSourceBuild is the fixed typed client seam. Native IPC must authenticate
// the peer before forwarding these bytes; it cannot expose trusted Core Compose.
func (r *Runtime) ExecuteSourceBuild(ctx context.Context, raw []byte) (appcontracts.SourceBuildExecutionReceipt, error) {
	var command SourceBuildCommand
	var zero appcontracts.SourceBuildExecutionReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return zero, ErrBinding
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return zero, ErrBinding
	}
	result := appcontracts.SourceBuildExecutionReceipt{Binding: command.Binding, Stage: command.Stage}
	switch command.Stage {
	case appcontracts.SourceBuildPrepare:
		if command.Prepare == nil || command.Build != nil || command.Cancel != nil || command.Release != nil {
			return zero, ErrBinding
		}
		receipt, err := r.Prepare(ctx, command.Binding, *command.Prepare)
		if err != nil {
			return zero, err
		}
		result.CommandSHA256 = receipt.CommandSHA256
		result.Prepared = &appcontracts.CommitPreparedSourceInput{Binding: receipt.Binding, Revision: receipt.Result.Revision, CommandSHA256: receipt.CommandSHA256, Evidence: coreEvidence(receipt.Result.Evidence), Definition: receipt.Definition}
	case appcontracts.SourceBuildBuild:
		if command.Build == nil || command.Prepare != nil || command.Cancel != nil || command.Release != nil {
			return zero, ErrBinding
		}
		receipt, err := r.Build(ctx, command.Binding, *command.Build)
		if err != nil {
			return zero, err
		}
		result.CommandSHA256 = receipt.CommandSHA256
		result.Built = &appcontracts.CommitSourceBuildOutputInput{Binding: receipt.Binding, Build: receipt.Result.Build, Artifact: *receipt.Result.Artifact, CommandSHA256: receipt.CommandSHA256, LogRef: receipt.Result.LogRef, Evidence: coreEvidence(receipt.Result.Evidence)}
	default:
		return zero, ErrBinding // no durable Core cancel/release control intent.
	}
	return result, nil
}
func coreEvidence(e contracts.Evidence) appcontracts.SourceBuildEvidenceFact {
	return appcontracts.SourceBuildEvidenceFact{Digest: e.Digest, Summary: e.Summary, Refs: append([]domain.EvidenceRef(nil), e.Refs...), Redacted: e.Redacted}
}

var _ appcontracts.SourceBuildExecutionClient = (*Runtime)(nil)

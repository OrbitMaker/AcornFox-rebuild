package application

import (
	"context"
	"errors"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/sourcebuildexecution"
)

// CoreSourceBuildAuthority is a Core-side adapter, not a role-owned fact store.
// Only its AuthorizeSourceBuild method may be exposed to a future attested RPC.
// ComposeSourceBuildStage belongs to the trusted Core worker/composer and must
// never be registered as an RPC allowing the role to seal its own request.
type CoreSourceBuildAuthority struct {
	store appcontracts.SourceBuildFactsStore
}

func NewCoreSourceBuildAuthority(store appcontracts.SourceBuildFactsStore) (*CoreSourceBuildAuthority, error) {
	if store == nil {
		return nil, errors.New("durable Core source-build facts store required")
	}
	return &CoreSourceBuildAuthority{store: store}, nil
}

var _ sourcebuildexecution.SourceBuildAuthority = (*CoreSourceBuildAuthority)(nil)

func (a *CoreSourceBuildAuthority) ComposeSourceBuildStage(ctx context.Context, in appcontracts.BeginSourceBuildStageInput) (sourcebuildexecution.SourceBuildCommand, error) {
	if a == nil || ctx == nil {
		return sourcebuildexecution.SourceBuildCommand{}, sourcebuildexecution.ErrBinding
	}
	if err := ctx.Err(); err != nil {
		return sourcebuildexecution.SourceBuildCommand{}, err
	}
	fact, err := a.store.BeginSourceBuildStage(ctx, in)
	if err != nil {
		return sourcebuildexecution.SourceBuildCommand{}, err
	}
	command, err := sourceBuildCommandFromFacts(in.Binding, fact)
	if err != nil {
		return command, err
	}
	sha, err := sourcebuildexecution.SourceBuildCommandDigest(command)
	if err != nil {
		return command, err
	}
	if err := a.store.BindSourceBuildCommand(ctx, in.Binding, in.Stage, sha, in.Now); err != nil {
		return sourcebuildexecution.SourceBuildCommand{}, err
	}
	return command, nil
}
func (a *CoreSourceBuildAuthority) AuthorizeSourceBuild(ctx context.Context, command sourcebuildexecution.SourceBuildCommand) (appcontracts.SourceBuildPermit, error) {
	if a == nil || ctx == nil {
		return appcontracts.SourceBuildPermit{}, sourcebuildexecution.ErrBinding
	}
	if err := ctx.Err(); err != nil {
		return appcontracts.SourceBuildPermit{}, err
	}
	fact, err := a.store.ReadSourceBuildAuthority(ctx, command.Binding, command.Stage, time.Now().UTC())
	if err != nil {
		return appcontracts.SourceBuildPermit{}, err
	}
	expected, err := sourceBuildCommandFromFacts(command.Binding, fact)
	if err != nil {
		return appcontracts.SourceBuildPermit{}, err
	}
	expectedSHA, err := sourcebuildexecution.SourceBuildCommandDigest(expected)
	if err != nil {
		return appcontracts.SourceBuildPermit{}, err
	}
	actualSHA, err := sourcebuildexecution.SourceBuildCommandDigest(command)
	if err != nil {
		return appcontracts.SourceBuildPermit{}, err
	}
	if fact.CommandSHA256 == "" || expectedSHA != fact.CommandSHA256 || actualSHA != expectedSHA {
		return appcontracts.SourceBuildPermit{}, sourcebuildexecution.ErrBinding
	}
	return appcontracts.SourceBuildPermit{CommandSHA256: expectedSHA}, nil
}
func sourceBuildResources(f appcontracts.SourceBuildResourcesFact) contracts.ResourceLimits {
	return contracts.ResourceLimits{CPUMillis: f.CPUMillis, MemoryBytes: f.MemoryBytes, DiskBytes: f.DiskBytes, TimeoutSeconds: f.TimeoutSeconds, ConcurrencySlot: f.ConcurrencySlot, PIDs: f.PIDs}
}
func sourceBuildCommandFromFacts(binding appcontracts.SourceBuildBinding, f appcontracts.SourceBuildIntentFact) (sourcebuildexecution.SourceBuildCommand, error) {
	zero := sourcebuildexecution.SourceBuildCommand{}
	if f.TaskID != binding.TaskID || f.OperationID != binding.OperationID || f.ApplicationID != binding.ApplicationID || f.RecoveryRequired {
		return zero, domain.NewError(domain.ErrConflict, "source-build facts require reconciliation or do not match task")
	}
	if f.Deadline.IsZero() || f.ProviderOperationKey == "" || f.ProviderActor != "core-source-build" {
		return zero, sourcebuildexecution.ErrBinding
	}
	operation := contracts.OperationContext{IdempotencyKey: f.ProviderOperationKey, Deadline: f.Deadline, Actor: f.ProviderActor}
	command := sourcebuildexecution.SourceBuildCommand{Stage: f.Stage, Binding: binding}
	switch f.Stage {
	case appcontracts.SourceBuildPrepare:
		command.Prepare = &contracts.PrepareSourceRequest{ApplicationID: f.ApplicationID, Kind: domain.SourceGitHTTPS, Locator: f.Prepare.Repository, Ref: f.Prepare.Commit, ContentDigest: f.Prepare.ExpectedContentDigest, Operation: operation}
	case appcontracts.SourceBuildBuild:
		if f.Source == nil || f.Plan == nil {
			return zero, sourcebuildexecution.ErrBinding
		}
		command.Build = &contracts.BuildRequest{BuildID: f.BuildID, Source: *f.Source, Plan: *f.Plan, Resources: sourceBuildResources(f.Policy.Resources), Network: contracts.NetworkPolicy{Mode: contracts.NetworkMode(f.Policy.NetworkMode), WorkerPolicyDigest: f.Policy.WorkerPolicyDigest}, Operation: operation}

	default:
		// No durable cancel/release control command exists in this two-stage slice.
		// Never infer that approval from role-supplied IDs or an operation key.
		return zero, domain.NewError(domain.ErrConflict, "persisted source-build control intent not implemented")
	}
	return command, nil
}

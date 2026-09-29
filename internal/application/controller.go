// Package application coordinates Open Card use cases without depending on a
// concrete database or HTTP transport.
package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	persistence "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

var (
	ErrNotFound            = domain.ErrObjectNotFound
	ErrIdempotencyConflict = persistence.ErrIdempotencyConflict
)

type Event = persistence.Event
type CreateApplicationRecord = persistence.CreateApplicationRecord
type CreateApplicationResult = persistence.CreateApplicationResult
type CreateApplicationPreflight = persistence.CreateApplicationPreflight
type CreateApplicationSourceKind = persistence.CreateApplicationSourceKind
type CreateApplicationSource = persistence.CreateApplicationSource
type EventFilter = persistence.EventFilter
type Repository = persistence.Repository

const (
	CreateApplicationSourceUpload = persistence.CreateApplicationSourceUpload
	CreateApplicationSourceGit    = persistence.CreateApplicationSourceGit
)

type Controller struct {
	repository     Repository
	clock          func() time.Time
	sourcePreparer contracts.SourceProvider
	sourceCreateMu sync.Mutex
}

func NewController(repository Repository) *Controller {
	return &Controller{repository: repository, clock: time.Now}
}

func (c *Controller) SetSourcePreparer(provider contracts.SourceProvider) {
	c.sourcePreparer = provider
}

func (c *Controller) CreateApplication(ctx context.Context, name, idempotencyKey string) (CreateApplicationResult, error) {
	return c.CreateApplicationWithSource(ctx, name, nil, idempotencyKey)
}

func (c *Controller) CreateApplicationWithSource(ctx context.Context, name string, source *CreateApplicationSource, idempotencyKey string) (CreateApplicationResult, error) {
	now := c.clock().UTC()
	if source != nil {
		if err := source.Validate(); err != nil {
			return CreateApplicationResult{}, err
		}
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if idempotencyKey == "" {
		generated, generateErr := domain.NewID("request")
		if generateErr != nil {
			return CreateApplicationResult{}, domain.WrapError(domain.ErrUnavailable, "generate idempotency key", generateErr)
		}
		idempotencyKey = generated.String()
	}
	digestInput := strings.TrimSpace(name)
	if source != nil {
		digestInput += "\x00" + string(source.Kind) + "\x00" + source.UploadID.String() + "\x00" + strings.TrimSpace(source.RepositoryURL) + "\x00" + strings.TrimSpace(source.Ref)
	}
	digestBytes := sha256.Sum256([]byte(digestInput))
	preflight := CreateApplicationPreflight{IdempotencyKey: idempotencyKey, RequestDigest: "sha256:" + hex.EncodeToString(digestBytes[:]), Source: source, Now: now}
	if source != nil {
		// MVP has one controller process. Serializing source creation closes the
		// gap between durable preflight and filesystem publication without
		// widening the PostgreSQL transaction.
		c.sourceCreateMu.Lock()
		defer c.sourceCreateMu.Unlock()
	}
	if replay, found, err := c.repository.PreflightCreateApplication(ctx, preflight); err != nil {
		return CreateApplicationResult{}, err
	} else if found {
		return replay, nil
	}
	application, err := domain.NewApplication(name, now)
	if err != nil {
		return CreateApplicationResult{}, err
	}
	environmentID, err := domain.NewID("env")
	if err != nil {
		return CreateApplicationResult{}, domain.WrapError(domain.ErrUnavailable, "generate environment id", err)
	}
	operationID, err := domain.NewID("op")
	if err != nil {
		return CreateApplicationResult{}, domain.WrapError(domain.ErrUnavailable, "generate operation id", err)
	}
	taskID, err := domain.NewID("task")
	if err != nil {
		return CreateApplicationResult{}, domain.WrapError(domain.ErrUnavailable, "generate task id", err)
	}
	var preparedSource *domain.SourceRevision
	if source != nil {
		if c.sourcePreparer == nil {
			return CreateApplicationResult{}, domain.NewError(domain.ErrUnavailable, "source preparation is unavailable")
		}
		prepareRequest := contracts.PrepareSourceRequest{ApplicationID: application.ID, WorkspaceRef: "memory://" + application.ID.String(), Operation: contracts.OperationContext{IdempotencyKey: idempotencyKey + ":source:" + application.ID.String(), Actor: "control-plane"}}
		switch source.Kind {
		case CreateApplicationSourceUpload:
			prepareRequest.Kind, prepareRequest.Locator = domain.SourceUpload, "upload://"+source.UploadID.String()
		case CreateApplicationSourceGit:
			prepareRequest.Kind, prepareRequest.Locator, prepareRequest.Ref = domain.SourceGitHTTPS, source.RepositoryURL, source.Ref
		default:
			return CreateApplicationResult{}, domain.ValidationError("application source kind is unsupported")
		}
		prepared, prepareErr := c.sourcePreparer.Prepare(ctx, prepareRequest)
		if prepareErr != nil {
			return CreateApplicationResult{}, prepareErr
		}
		if err := prepared.Revision.Validate(); err != nil || prepared.Revision.ApplicationID != application.ID || !PreparedSourceMatches(*source, prepared.Revision) {
			return CreateApplicationResult{}, domain.NewError(domain.ErrUnavailable, "source preparation returned an invalid revision")
		}
		preparedSource = &prepared.Revision
	}
	record := CreateApplicationRecord{
		Audit:          persistence.AuditContext{ActorType: "system", ActorID: "application-controller", Reason: "application management record and durable creation intent requested"},
		Application:    application,
		EnvironmentID:  environmentID,
		OperationID:    operationID,
		TaskID:         taskID,
		IdempotencyKey: idempotencyKey,
		RequestDigest:  preflight.RequestDigest,
		Source:         source,
		PreparedSource: preparedSource,
		Event: Event{
			SchemaVersion: "1.1",
			OperationID:   operationID.String(),
			ApplicationID: application.ID.String(),
			OccurredAt:    now,
			Kind:          "operation.created",
			Status:        string(domain.PublishPreparing),
			Message:       "application accepted",
		},
	}
	if source != nil && source.Kind == CreateApplicationSourceGit && source.PublicGit {
		record.PublicSourceProvenance = &contracts.AcornFoxPublicSourceProvenance{SourceRevisionID: preparedSource.ID, RepositoryURL: preparedSource.Locator}
	}
	result, err := c.repository.CreateApplication(ctx, record)
	if err == nil || preparedSource == nil {
		return result, err
	}
	return c.compensateFailedSourceCreate(ctx, preflight, err)
}

// PreparedSourceMatches ensures the source provider's immutable result is the
// exact source the application request named, rather than merely a valid but
// different workspace.
func PreparedSourceMatches(source CreateApplicationSource, revision domain.SourceRevision) bool {
	switch source.Kind {
	case CreateApplicationSourceUpload:
		return revision.Kind == domain.SourceUpload && revision.Locator == "upload://"+source.UploadID.String()
	case CreateApplicationSourceGit:
		git, err := foundation.NormalizeGitSource(source.RepositoryURL, source.Ref)
		return err == nil && git.Scheme == foundation.GitHTTPS && revision.Kind == domain.SourceGitHTTPS && revision.Locator == git.Locator && revision.Ref == git.Ref && revision.Commit != ""
	default:
		return false
	}
}

// ValidatePublicSourceProvenance keeps explicit public-git evidence separate
// from generic Git source creation, whose visibility remains unknown.
func ValidatePublicSourceProvenance(source *CreateApplicationSource, prepared *domain.SourceRevision, provenance *contracts.AcornFoxPublicSourceProvenance) error {
	if provenance == nil {
		if source != nil && source.Kind == CreateApplicationSourceGit && source.PublicGit {
			return domain.ValidationError("explicit public git source requires provenance")
		}
		return nil
	}
	if source == nil || source.Kind != CreateApplicationSourceGit || !source.PublicGit || prepared == nil || provenance.SourceRevisionID != prepared.ID || provenance.RepositoryURL != prepared.Locator {
		return domain.ValidationError("public source provenance does not match prepared explicit public git source")
	}
	if err := provenance.Validate(); err != nil {
		return domain.ValidationError("public source provenance is invalid")
	}
	return nil
}

// compensateFailedSourceCreate first resolves the durable outcome. A failed
// application write retains a finalized content-addressed workspace: deleting
// it synchronously can race an outcome-unknown commit or a shared immutable
// digest. Provider Prepare already removes transient stage/object directories;
// a future reconciled GC owns finalized workspace reclamation.
func (c *Controller) compensateFailedSourceCreate(ctx context.Context, preflight CreateApplicationPreflight, createErr error) (CreateApplicationResult, error) {
	if replay, found, err := c.repository.PreflightCreateApplication(ctx, preflight); err == nil && found {
		return replay, nil
	}
	return CreateApplicationResult{}, createErr
}

func (c *Controller) ListApplications(ctx context.Context) ([]domain.Application, error) {
	return c.repository.ListApplications(ctx)
}

func (c *Controller) GetApplication(ctx context.Context, id domain.ID) (domain.Application, error) {
	return c.repository.GetApplication(ctx, id)
}

func (c *Controller) ListEvents(ctx context.Context, operationID string, afterSequence uint64) ([]Event, error) {
	return c.repository.ListEvents(ctx, EventFilter{
		OperationID:   strings.TrimSpace(operationID),
		AfterSequence: afterSequence,
		Since:         c.clock().UTC().Add(-24 * time.Hour),
		Limit:         1000,
	})
}

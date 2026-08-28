// Package application coordinates Open Card use cases without depending on a
// concrete database or HTTP transport.
package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

var (
	ErrNotFound            = errors.New("application object not found")
	ErrIdempotencyConflict = errors.New("idempotency key reused with different input")
)

type Event struct {
	SchemaVersion string    `json:"schema_version,omitempty"`
	ID            string    `json:"id"`
	OperationID   string    `json:"operation_id"`
	ApplicationID string    `json:"application_id"`
	Sequence      uint64    `json:"sequence"`
	OccurredAt    time.Time `json:"occurred_at"`
	Kind          string    `json:"kind"`
	Status        string    `json:"status"`
	Message       string    `json:"message,omitempty"`
	EvidenceIDs   []string  `json:"evidence_ids,omitempty"`
}

type CreateApplicationRecord struct {
	Application    domain.Application
	EnvironmentID  domain.ID
	OperationID    domain.ID
	TaskID         domain.ID
	IdempotencyKey string
	RequestDigest  string
	Source         *CreateApplicationSource
	PreparedSource *domain.SourceRevision
	Event          Event
}

type CreateApplicationResult struct {
	Application      domain.Application
	EnvironmentID    domain.ID
	OperationID      domain.ID
	SourceRevisionID domain.ID
	Event            Event
}

// CreateApplicationPreflight is a side-effect-free lookup performed before a
// source workspace can be materialized. It prevents replaying an upload from
// doing filesystem work after a durable application result already exists.
type CreateApplicationPreflight struct {
	IdempotencyKey string
	RequestDigest  string
	Source         *CreateApplicationSource
	Now            time.Time
}

type CreateApplicationSourceKind string

const (
	CreateApplicationSourceUpload CreateApplicationSourceKind = "upload"
	CreateApplicationSourceGit    CreateApplicationSourceKind = "git"
)

// CreateApplicationSource has no client filesystem locator. Uploads refer to
// one durable, private upload ID; git remains contract-only until a later
// source preparation path can perform a real remote fetch.
type CreateApplicationSource struct {
	Kind          CreateApplicationSourceKind
	UploadID      domain.ID
	RepositoryURL string
	Ref           string
}

func (s CreateApplicationSource) Validate() error {
	s.RepositoryURL, s.Ref = strings.TrimSpace(s.RepositoryURL), strings.TrimSpace(s.Ref)
	switch s.Kind {
	case CreateApplicationSourceUpload:
		if err := domain.RequireID(s.UploadID, "source upload id"); err != nil || s.RepositoryURL != "" || s.Ref != "" {
			return domain.ValidationError("upload application source must contain only upload_id")
		}
	case CreateApplicationSourceGit:
		if !s.UploadID.Empty() || s.RepositoryURL == "" || s.Ref == "" {
			return domain.ValidationError("git application source requires repository_url and ref")
		}
		git, err := foundation.NormalizeGitSource(s.RepositoryURL, s.Ref)
		if err != nil || git.Scheme != foundation.GitHTTPS {
			return domain.ValidationError("git application source requires a canonical HTTPS repository and ref")
		}
	default:
		return domain.ValidationError("application source kind is unsupported")
	}
	return nil
}

type EventFilter struct {
	OperationID   string
	AfterSequence uint64
	Since         time.Time
	Limit         int
}

type Repository interface {
	PreflightCreateApplication(context.Context, CreateApplicationPreflight) (CreateApplicationResult, bool, error)
	CreateApplication(context.Context, CreateApplicationRecord) (CreateApplicationResult, error)
	HasSourceWorkspaceReference(context.Context, string) (bool, error)
	ListApplications(context.Context) ([]domain.Application, error)
	GetApplication(context.Context, domain.ID) (domain.Application, error)
	ListEvents(context.Context, EventFilter) ([]Event, error)
}

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
	result, err := c.repository.CreateApplication(ctx, record)
	if err == nil || preparedSource == nil {
		return result, err
	}
	return c.compensateFailedSourceCreate(ctx, preflight, *preparedSource, err)
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

// compensateFailedSourceCreate first resolves the durable outcome. It releases
// only a workspace which has no committed source_revision reference, so a
// content-addressed workspace shared by another revision is never removed.
func (c *Controller) compensateFailedSourceCreate(ctx context.Context, preflight CreateApplicationPreflight, revision domain.SourceRevision, createErr error) (CreateApplicationResult, error) {
	if replay, found, err := c.repository.PreflightCreateApplication(ctx, preflight); err == nil && found {
		return replay, nil
	} else if err != nil {
		return CreateApplicationResult{}, createErr
	}
	referenced, err := c.repository.HasSourceWorkspaceReference(ctx, revision.WorkspaceRef)
	if err != nil || referenced {
		return CreateApplicationResult{}, createErr
	}
	cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cleanupErr := c.sourcePreparer.Release(cleanupContext, contracts.ReleaseSourceRequest{Revision: revision, Operation: contracts.OperationContext{IdempotencyKey: preflight.IdempotencyKey + ":source-cleanup:" + revision.ID.String(), Actor: "control-plane"}})
	if cleanupErr != nil {
		return CreateApplicationResult{}, errors.Join(createErr, domain.WrapError(domain.ErrUnavailable, "discard unclaimed source workspace", cleanupErr))
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

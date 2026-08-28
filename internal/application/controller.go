// Package application coordinates Open Card use cases without depending on a
// concrete database or HTTP transport.
package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
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
	Event          Event
}

type CreateApplicationResult struct {
	Application   domain.Application
	EnvironmentID domain.ID
	OperationID   domain.ID
	Event         Event
}

type EventFilter struct {
	OperationID   string
	AfterSequence uint64
	Since         time.Time
	Limit         int
}

type Repository interface {
	CreateApplication(context.Context, CreateApplicationRecord) (CreateApplicationResult, error)
	ListApplications(context.Context) ([]domain.Application, error)
	GetApplication(context.Context, domain.ID) (domain.Application, error)
	ListEvents(context.Context, EventFilter) ([]Event, error)
}

type Controller struct {
	repository Repository
	clock      func() time.Time
}

func NewController(repository Repository) *Controller {
	return &Controller{repository: repository, clock: time.Now}
}

func (c *Controller) CreateApplication(ctx context.Context, name, idempotencyKey string) (CreateApplicationResult, error) {
	now := c.clock().UTC()
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
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if idempotencyKey == "" {
		generated, generateErr := domain.NewID("request")
		if generateErr != nil {
			return CreateApplicationResult{}, domain.WrapError(domain.ErrUnavailable, "generate idempotency key", generateErr)
		}
		idempotencyKey = generated.String()
	}
	digestBytes := sha256.Sum256([]byte(strings.TrimSpace(name)))
	record := CreateApplicationRecord{
		Application:    application,
		EnvironmentID:  environmentID,
		OperationID:    operationID,
		TaskID:         taskID,
		IdempotencyKey: idempotencyKey,
		RequestDigest:  "sha256:" + hex.EncodeToString(digestBytes[:]),
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
	return c.repository.CreateApplication(ctx, record)
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

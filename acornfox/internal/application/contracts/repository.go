package contracts

import (
	"context"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/foundation"
	"strings"
	"time"
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
	// Audit must be supplied by a trusted command context, never copied from client actor fields.
	Audit                  AuditContext
	Application            domain.Application
	EnvironmentID          domain.ID
	OperationID            domain.ID
	TaskID                 domain.ID
	IdempotencyKey         string
	RequestDigest          string
	Source                 *CreateApplicationSource
	PreparedSource         *domain.SourceRevision
	PublicSourceProvenance *AcornFoxPublicSourceProvenance
	Event                  Event
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
// one durable, private upload ID; public HTTPS Git is prepared through the
// configured SourceProvider and then persisted as an immutable revision.
type CreateApplicationSource struct {
	Kind          CreateApplicationSourceKind
	UploadID      domain.ID
	RepositoryURL string
	Ref           string
	// PublicGit is set only by an explicit public_git transport command. Its
	// false zero value preserves the historical "visibility unknown" meaning
	// for all generic Git creation paths.
	PublicGit bool
}

func (s CreateApplicationSource) Validate() error {
	s.RepositoryURL, s.Ref = strings.TrimSpace(s.RepositoryURL), strings.TrimSpace(s.Ref)
	switch s.Kind {
	case CreateApplicationSourceUpload:
		if err := domain.RequireID(s.UploadID, "source upload id"); err != nil || s.RepositoryURL != "" || s.Ref != "" || s.PublicGit {
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
	ListApplications(context.Context) ([]domain.Application, error)
	GetApplication(context.Context, domain.ID) (domain.Application, error)
	ListEvents(context.Context, EventFilter) ([]Event, error)
}

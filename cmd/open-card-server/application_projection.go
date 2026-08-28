package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/controllers"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type applicationProjectionStore interface {
	ListApplicationProjections(context.Context) ([]postgres.ApplicationProjection, error)
	ApplicationProjection(context.Context, domain.ID) (postgres.ApplicationProjection, error)
}
type applicationAccessProvider interface {
	ApplicationAccess(context.Context, domain.ID) (controllers.G3ApplicationAccess, error)
}
type applicationSummary struct {
	ID            domain.ID                   `json:"id"`
	Name          string                      `json:"name"`
	CreatedAt     string                      `json:"created_at"`
	UpdatedAt     string                      `json:"updated_at"`
	Source        applicationProjectionSource `json:"source"`
	OperationID   *domain.ID                  `json:"operation_id"`
	RuntimeReady  bool                        `json:"runtime_ready"`
	Serving       bool                        `json:"serving"`
	RuntimeStatus string                      `json:"runtime_status"`
}
type applicationProjectionSource struct {
	Kind     string     `json:"kind"`
	UploadID *domain.ID `json:"source_upload_id,omitempty"`
	Locator  *string    `json:"locator,omitempty"`
	Ref      *string    `json:"ref,omitempty"`
}
type applicationDetail struct {
	applicationSummary
	SourceUploadID *domain.ID `json:"source_upload_id"`
	Access         any        `json:"access"`
}

type memoryApplicationProjectionStore struct{ repository *application.MemoryRepository }

func (s memoryApplicationProjectionStore) ListApplicationProjections(ctx context.Context) ([]postgres.ApplicationProjection, error) {
	items, err := s.repository.ListApplications(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]postgres.ApplicationProjection, 0, len(items))
	for _, item := range items {
		out = append(out, postgres.ApplicationProjection{ID: item.ID, Name: item.Name, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt, Source: postgres.ApplicationProjectionSource{Kind: "unknown"}, RuntimeStatus: "unknown"})
	}
	return out, nil
}
func (s memoryApplicationProjectionStore) ApplicationProjection(ctx context.Context, id domain.ID) (postgres.ApplicationProjection, error) {
	item, err := s.repository.GetApplication(ctx, id)
	if err != nil {
		return postgres.ApplicationProjection{}, err
	}
	return postgres.ApplicationProjection{ID: item.ID, Name: item.Name, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt, Source: postgres.ApplicationProjectionSource{Kind: "unknown"}, RuntimeStatus: "unknown"}, nil
}

func (s *Server) applicationSummary(ctx context.Context, item postgres.ApplicationProjection) (applicationSummary, error) {
	summary := applicationSummary{ID: item.ID, Name: item.Name, CreatedAt: item.CreatedAt.UTC().Format(time.RFC3339), UpdatedAt: item.UpdatedAt.UTC().Format(time.RFC3339), Source: applicationProjectionSource{Kind: item.Source.Kind, UploadID: item.Source.UploadID, Locator: item.Source.RepositoryURL, Ref: item.Source.Ref}, OperationID: item.OperationID, RuntimeReady: item.RuntimeReady, Serving: item.Serving, RuntimeStatus: item.RuntimeStatus}
	access, err := s.applicationAccess(ctx, item.ID)
	if err != nil {
		return applicationSummary{}, err
	}
	summary.RuntimeReady, summary.Serving = access.RuntimeReady, access.Serving
	if access.RuntimeReady && access.Serving {
		summary.RuntimeStatus = "running"
	} else if access.RuntimeReady {
		summary.RuntimeStatus = "partial"
	}
	return summary, nil
}
func (s *Server) applicationAccess(ctx context.Context, id domain.ID) (controllers.G3ApplicationAccess, error) {
	if s.applicationAccessProvider != nil {
		return s.applicationAccessProvider.ApplicationAccess(ctx, id)
	}
	if s.g3Access != nil && s.g3Access.Controller != nil {
		return s.g3Access.Controller.ApplicationAccess(ctx, id)
	}
	return controllers.G3ApplicationAccess{}, errors.New("G3 access projection is unavailable")
}
func (s *Server) handleApplicationProjectionList(w http.ResponseWriter, r *http.Request) {
	if s.applicationProjectionStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "application_projection_unavailable", "application projection is unavailable")
		return
	}
	items, err := s.applicationProjectionStore.ListApplicationProjections(r.Context())
	if err != nil {
		writeApplicationError(w, err)
		return
	}
	out := make([]applicationSummary, 0, len(items))
	for _, item := range items {
		summary, err := s.applicationSummary(r.Context(), item)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "application_projection_unavailable", "application projection is unavailable")
			return
		}
		out = append(out, summary)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}
func (s *Server) handleApplicationProjectionDetail(w http.ResponseWriter, r *http.Request, id domain.ID) {
	if s.applicationProjectionStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "application_projection_unavailable", "application projection is unavailable")
		return
	}
	item, err := s.applicationProjectionStore.ApplicationProjection(r.Context(), id)
	if err != nil {
		writeApplicationError(w, err)
		return
	}
	summary, err := s.applicationSummary(r.Context(), item)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "application_projection_unavailable", "application projection is unavailable")
		return
	}
	access, err := s.applicationAccess(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "application_projection_unavailable", "application projection is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, applicationDetail{applicationSummary: summary, SourceUploadID: item.Source.UploadID, Access: access})
}

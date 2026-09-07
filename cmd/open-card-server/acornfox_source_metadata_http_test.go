package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
)

type acornFoxSourceMetadataFixture struct {
	metadata   contracts.AcornFoxSourceMetadata
	deployment contracts.AcornFoxDeploymentSource
}

func (f acornFoxSourceMetadataFixture) GetAcornFoxSourceMetadata(_ context.Context, applicationID, sourceID domain.ID) (contracts.AcornFoxSourceMetadata, error) {
	if applicationID != "app_1" || sourceID != f.metadata.SourceRevisionID {
		return contracts.AcornFoxSourceMetadata{}, postgres.ErrNotFound
	}
	return f.metadata, nil
}

func (f acornFoxSourceMetadataFixture) GetAcornFoxDeploymentSource(_ context.Context, applicationID, deploymentID domain.ID) (contracts.AcornFoxDeploymentSource, error) {
	if applicationID != "app_1" || deploymentID != f.deployment.DeploymentID {
		return contracts.AcornFoxDeploymentSource{}, postgres.ErrNotFound
	}
	return f.deployment, nil
}

func TestAcornFoxSourceMetadataHTTPDoesNotInferPrivateHTTPSLocator(t *testing.T) {
	fixture := acornFoxSourceMetadataFixture{
		metadata:   contracts.AcornFoxSourceMetadata{SourceRevisionID: "src_private", Availability: contracts.AcornFoxUnavailable},
		deployment: contracts.AcornFoxDeploymentSource{DeploymentID: "dep_private", Availability: contracts.AcornFoxUnavailable},
	}
	handler := newAcornFoxSourceMetadataHTTPHandler(fixture)
	for name, request := range map[string]*http.Request{
		"source":     httptest.NewRequest(http.MethodGet, "/apps/app_1/sources/src_private/metadata", nil),
		"deployment": httptest.NewRequest(http.MethodGet, "/apps/app_1/deliveries/dep_private/source", nil),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			if name == "source" {
				handler.HandleSourceMetadata(response, request, "app_1", "src_private")
			} else {
				handler.HandleDeploymentSource(response, request, "app_1", "dep_private")
			}
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"availability":"unavailable"`) || strings.Contains(response.Body.String(), "repository_url") || strings.Contains(response.Body.String(), "source_revision_id") && name == "deployment" {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestAcornFoxSourceMetadataHTTPEnforcesRouteApplicationOwnership(t *testing.T) {
	fixture := acornFoxSourceMetadataFixture{
		metadata:   contracts.AcornFoxSourceMetadata{SourceRevisionID: "src_1", Availability: contracts.AcornFoxAvailable, RepositoryURL: "https://github.com/acme/example.git"},
		deployment: contracts.AcornFoxDeploymentSource{DeploymentID: "dep_1", Availability: contracts.AcornFoxAvailable, SourceRevisionID: "src_1", Commit: strings.Repeat("a", 40), Ref: "main", RepositoryURL: "https://github.com/acme/example.git"},
	}
	handler := newAcornFoxSourceMetadataHTTPHandler(fixture)
	for name, call := range map[string]func(http.ResponseWriter, *http.Request){
		"source": func(w http.ResponseWriter, r *http.Request) { handler.HandleSourceMetadata(w, r, "app_other", "src_1") },
		"deployment": func(w http.ResponseWriter, r *http.Request) {
			handler.HandleDeploymentSource(w, r, "app_other", "dep_1")
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			call(response, httptest.NewRequest(http.MethodGet, "/", nil))
			if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"not_found"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestAcornFoxSourceMetadataHTTPRejectsWrongMethod(t *testing.T) {
	handler := newAcornFoxSourceMetadataHTTPHandler(acornFoxSourceMetadataFixture{metadata: contracts.AcornFoxSourceMetadata{SourceRevisionID: "src_1", Availability: contracts.AcornFoxUnavailable}})
	response := httptest.NewRecorder()
	handler.HandleSourceMetadata(response, httptest.NewRequest(http.MethodPost, "/", nil), "app_1", "src_1")
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, OPTIONS" {
		t.Fatalf("status=%d allow=%q body=%s", response.Code, response.Header().Get("Allow"), response.Body.String())
	}
}

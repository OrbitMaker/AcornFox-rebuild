package main

import (
	"context"
	"github.com/open-card/open-card/internal/application"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type sourceUpdateCommand struct{}

func (sourceUpdateCommand) Update(context.Context, application.AcornFoxSourceUpdateRequest) (contracts.AcornFoxSourceUpdateResult, error) {
	return contracts.AcornFoxSourceUpdateResult{SourceRevisionID: "src_new", Status: contracts.AcornFoxSourceUpdateImported}, nil
}
func TestAcornFoxSourceUpdateHTTPReturnsImportedOnly(t *testing.T) {
	h := newAcornFoxSourceUpdateHTTPHandler(sourceUpdateCommand{})
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"base_source_revision_id":"src_old","ref":"main"}`))
	r.Header.Set("Idempotency-Key", "one")
	w := httptest.NewRecorder()
	h.Handle(w, r, domain.ID("app_1"))
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"status":"imported"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

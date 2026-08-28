package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
	"github.com/open-card/open-card/internal/providers/imagegc"
)

type lifecycleClaims struct {
	claims []postgres.M2ServiceGroupVolumeClaim
}

func (f lifecycleClaims) ListM2ReleaseVolumeClaims(_ context.Context, _ domain.ID) ([]postgres.M2ServiceGroupVolumeClaim, error) {
	return append([]postgres.M2ServiceGroupVolumeClaim(nil), f.claims...), nil
}

type lifecycleVolumes struct {
	facts         M2VolumeFacts
	destroyed     []M2VolumeDestroyCommand
	factsCommands []M2VolumeDestroyCommand
	destroyErr    error
}

func (f *lifecycleVolumes) Facts(_ context.Context, command M2VolumeDestroyCommand) (M2VolumeFacts, error) {
	f.factsCommands = append(f.factsCommands, command)
	return f.facts, nil
}
func (f *lifecycleVolumes) Destroy(_ context.Context, command M2VolumeDestroyCommand) error {
	f.destroyed = append(f.destroyed, command)
	return f.destroyErr
}

type lifecycleCollector struct {
	plans, collects int
	plan            imagegc.Plan
	result          imagegc.CollectResult
	err             error
}

func (f *lifecycleCollector) Plan(context.Context) (imagegc.Plan, error) {
	f.plans++
	return f.plan, f.err
}
func (f *lifecycleCollector) Collect(context.Context) (imagegc.CollectResult, error) {
	f.collects++
	return f.result, f.err
}

func lifecycleHandler(t *testing.T) (*M2LifecycleHandler, *lifecycleVolumes, *lifecycleCollector) {
	t.Helper()
	volumes := &lifecycleVolumes{facts: M2VolumeFacts{PhysicalName: "opencard-mvp-fa8f8eab-volume-data", Exists: true, Driver: "local", Retained: true}}
	collector := &lifecycleCollector{plan: imagegc.Plan{ImageCount: 1}}
	handler, err := NewM2LifecycleHandler(lifecycleClaims{claims: []postgres.M2ServiceGroupVolumeClaim{{ID: "claim_data", Name: "data", SizeBytes: 1024, Retain: true}}}, volumes, collector, "opencard-mvp-fa8f8eab")
	if err != nil {
		t.Fatal(err)
	}
	handler.Now = func() time.Time { return time.Date(2026, 8, 24, 1, 2, 3, 0, time.UTC) }
	return handler, volumes, collector
}

func TestM2LifecycleListsClaimsButNeverAcceptsVolumeNamesFromHTTP(t *testing.T) {
	handler, volumes, _ := lifecycleHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/releases/release_1/volumes?name=/etc/passwd&include_runtime=true", nil)
	recorder := httptest.NewRecorder()
	if !handler.Handle(recorder, request) || recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(volumes.factsCommands) != 1 || volumes.factsCommands[0].PhysicalName != "opencard-mvp-fa8f8eab-volume-data" {
		t.Fatalf("facts commands=%#v", volumes.factsCommands)
	}
	var body struct {
		Volumes []struct {
			PhysicalName string `json:"physical_name"`
			Exists       bool   `json:"exists"`
		} `json:"volumes"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Volumes) != 1 || body.Volumes[0].PhysicalName != "opencard-mvp-fa8f8eab-volume-data" || !body.Volumes[0].Exists {
		t.Fatalf("body=%s", recorder.Body.String())
	}
}

func TestM2LifecycleVolumeDestroyRequiresExactClaimScopedConfirmationAndIdempotency(t *testing.T) {
	handler, volumes, _ := lifecycleHandler(t)
	path := "/api/v1/releases/release_1/volumes/claim_data/destroy"
	for _, test := range []struct {
		name, key, token string
		status           int
	}{
		{"missing key", "", "confirm-volume-destroy:opencard-mvp-fa8f8eab-volume-data", http.StatusBadRequest},
		{"wrong token", "destroy-1", "confirm-volume-destroy:opencard-mvp-fa8f8eab-volume-other", http.StatusConflict},
		{"generic token", "destroy-1", "yes", http.StatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"confirmation_token":"`+test.token+`"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", test.key)
			recorder := httptest.NewRecorder()
			handler.Handle(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
	if len(volumes.destroyed) != 0 {
		t.Fatalf("invalid request reached volume command: %#v", volumes.destroyed)
	}
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"confirmation_token":"confirm-volume-destroy:opencard-mvp-fa8f8eab-volume-data"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "destroy-1")
	recorder := httptest.NewRecorder()
	handler.Handle(recorder, request)
	if recorder.Code != http.StatusAccepted || len(volumes.destroyed) != 1 {
		t.Fatalf("status=%d calls=%#v", recorder.Code, volumes.destroyed)
	}
	command := volumes.destroyed[0]
	if command.Claim.ID != "claim_data" || command.PhysicalName != "opencard-mvp-fa8f8eab-volume-data" || command.Deadline.Sub(time.Date(2026, 8, 24, 1, 2, 3, 0, time.UTC)) != 2*time.Minute {
		t.Fatalf("command=%#v", command)
	}
}

func TestM2LifecycleGCIsImageOnlyAndRequiresIdempotencyForMutation(t *testing.T) {
	handler, _, collector := lifecycleHandler(t)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/images/gc", strings.NewReader(`{"dry_run":true}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.Handle(recorder, request)
	if recorder.Code != http.StatusOK || collector.plans != 1 || collector.collects != 0 {
		t.Fatalf("dry status=%d plans=%d collects=%d", recorder.Code, collector.plans, collector.collects)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/images/gc", strings.NewReader(`{"dry_run":false}`))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	handler.Handle(recorder, request)
	if recorder.Code != http.StatusBadRequest || collector.collects != 0 {
		t.Fatalf("mutation without key status=%d collects=%d", recorder.Code, collector.collects)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/images/gc", strings.NewReader(`{"dry_run":false}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "gc-1")
	recorder = httptest.NewRecorder()
	handler.Handle(recorder, request)
	if recorder.Code != http.StatusOK || collector.collects != 1 {
		t.Fatalf("mutation status=%d collects=%d", recorder.Code, collector.collects)
	}
}

func TestM2LifecycleIsUnclaimedWhenNilAndRejectsUnsafePrefix(t *testing.T) {
	var nilHandler *M2LifecycleHandler
	if nilHandler.Handle(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/images/gc", nil)) {
		t.Fatal("nil handler claimed a route")
	}
	if _, err := NewM2LifecycleHandler(lifecycleClaims{}, nil, nil, "../unsafe"); err == nil {
		t.Fatal("unsafe task prefix accepted")
	}
}

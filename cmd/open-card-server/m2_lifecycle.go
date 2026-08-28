package main

// This file deliberately contains the M2 lifecycle HTTP boundary separately
// from m2.go.  The control-plane service does not receive a Docker socket: a
// caller must inject an Agent-backed volume command and an image-only GC
// collector.  Keeping these capabilities narrow makes an omitted composition
// fail closed instead of silently performing a host-local mutation.

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/persistence/postgres"
	"github.com/open-card/open-card/internal/providers/imagegc"
)

var m2LifecycleName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// M2VolumeClaimReader intentionally exposes only immutable release claims.
// A volume name submitted by an HTTP client is never trusted as a Docker
// resource identifier.
type M2VolumeClaimReader interface {
	ListM2ReleaseVolumeClaims(context.Context, domain.ID) ([]postgres.M2ServiceGroupVolumeClaim, error)
}

// M2VolumeFacts is the redacted, task-owned view returned by an Agent-backed
// volume command.  Mount paths and Docker inspect payloads are intentionally
// absent: they are host facts, not API inputs.
type M2VolumeFacts struct {
	PhysicalName string `json:"physical_name"`
	Exists       bool   `json:"exists"`
	Driver       string `json:"driver,omitempty"`
	Retained     bool   `json:"retained"`
}

// M2VolumeDestroyCommand carries an exact immutable claim and a confirmation
// token bound to its derived task-scoped physical resource.  The transport
// implementation must reject any attempt to reinterpret these fields.
type M2VolumeDestroyCommand struct {
	ReleaseID         domain.ID                          `json:"release_id"`
	Claim             postgres.M2ServiceGroupVolumeClaim `json:"claim"`
	PhysicalName      string                             `json:"physical_name"`
	ConfirmationToken string                             `json:"confirmation_token"`
	IdempotencyKey    string                             `json:"idempotency_key"`
	Actor             string                             `json:"actor"`
	Deadline          time.Time                          `json:"deadline"`
}

// M2VolumeCommand is normally implemented by a capability-gated Agent task
// bridge.  It is intentionally not contracts.VolumeProvider because the
// control plane must not gain direct Docker access.
type M2VolumeCommand interface {
	Facts(context.Context, M2VolumeDestroyCommand) (M2VolumeFacts, error)
	Destroy(context.Context, M2VolumeDestroyCommand) error
}

// M2ImageCollector is the image-only side effect boundary. imagegc.Provider
// implements it and cannot delete Docker volumes, containers or networks.
type M2ImageCollector interface {
	Plan(context.Context) (imagegc.Plan, error)
	Collect(context.Context) (imagegc.CollectResult, error)
}

// M2LifecycleHandler is a composition-friendly HTTP helper.  Main server
// routing may delegate request paths to Handle; until it is configured it
// owns no routes and returns false.
type M2LifecycleHandler struct {
	Claims     M2VolumeClaimReader
	Volumes    M2VolumeCommand
	Collector  M2ImageCollector
	TaskPrefix string
	Now        func() time.Time
}

func NewM2LifecycleHandler(claims M2VolumeClaimReader, volumes M2VolumeCommand, collector M2ImageCollector, taskPrefix string) (*M2LifecycleHandler, error) {
	if claims == nil {
		return nil, errors.New("M2 lifecycle claim reader is required")
	}
	if !m2LifecycleName.MatchString(strings.TrimSpace(taskPrefix)) {
		return nil, errors.New("M2 lifecycle task prefix must be a safe non-empty name")
	}
	return &M2LifecycleHandler{Claims: claims, Volumes: volumes, Collector: collector, TaskPrefix: strings.TrimSpace(taskPrefix), Now: func() time.Time { return time.Now().UTC() }}, nil
}

// Handle returns true only for an M2 lifecycle path.  This permits existing
// server routing to retain its default 404 and avoids accidentally claiming
// unrelated routes when M2 is partially composed.
func (h *M2LifecycleHandler) Handle(writer http.ResponseWriter, request *http.Request) bool {
	if h == nil {
		return false
	}
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) == 5 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "releases" && parts[4] == "volumes" {
		h.listVolumes(writer, request, domain.ID(parts[3]))
		return true
	}
	if len(parts) == 7 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "releases" && parts[4] == "volumes" && parts[6] == "destroy" {
		h.destroyVolume(writer, request, domain.ID(parts[3]), domain.ID(parts[5]))
		return true
	}
	if len(parts) == 4 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "images" && parts[3] == "gc" {
		h.collectImages(writer, request)
		return true
	}
	return false
}

func (h *M2LifecycleHandler) listVolumes(writer http.ResponseWriter, request *http.Request, releaseID domain.ID) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", "GET, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	claims, err := h.Claims.ListM2ReleaseVolumeClaims(request.Context(), releaseID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	items := make([]map[string]any, 0, len(claims))
	for _, claim := range claims {
		physical, valid := h.physicalName(claim)
		if !valid {
			writeJSONError(writer, http.StatusConflict, "invalid_volume_claim", "persisted volume claim violates the task resource contract")
			return
		}
		item := map[string]any{"id": claim.ID, "logical_name": claim.Name, "physical_name": physical, "size_bytes": claim.SizeBytes, "retain": claim.Retain}
		if h.Volumes != nil && request.URL.Query().Get("include_runtime") == "true" {
			facts, factsErr := h.Volumes.Facts(request.Context(), M2VolumeDestroyCommand{ReleaseID: releaseID, Claim: claim, PhysicalName: physical, Actor: "m2-api"})
			if factsErr != nil {
				writeJSONError(writer, http.StatusServiceUnavailable, "volume_facts_unavailable", "task volume facts are unavailable")
				return
			}
			if facts.PhysicalName != physical {
				writeJSONError(writer, http.StatusConflict, "volume_facts_mismatch", "volume facts do not match the immutable claim")
				return
			}
			item["exists"], item["driver"], item["retained"] = facts.Exists, facts.Driver, facts.Retained
		}
		items = append(items, item)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"release_id": releaseID, "volumes": items})
}

func (h *M2LifecycleHandler) destroyVolume(writer http.ResponseWriter, request *http.Request, releaseID, claimID domain.ID) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if h.Volumes == nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "volume_destroy_unavailable", "an Agent-backed volume command is required")
		return
	}
	var input struct {
		ConfirmationToken string `json:"confirmation_token"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_destroy", err.Error())
		return
	}
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if key == "" {
		writeJSONError(writer, http.StatusBadRequest, "invalid_destroy", "Idempotency-Key is required")
		return
	}
	claims, err := h.Claims.ListM2ReleaseVolumeClaims(request.Context(), releaseID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	claim, found := exactM2Claim(claims, claimID)
	if !found {
		writeJSONError(writer, http.StatusNotFound, "volume_claim_not_found", "volume claim does not belong to release")
		return
	}
	physical, valid := h.physicalName(claim)
	if !valid {
		writeJSONError(writer, http.StatusConflict, "invalid_volume_claim", "persisted volume claim violates the task resource contract")
		return
	}
	// Deleting retained data is never implicit. The token is exact rather than
	// a general "delete" acknowledgement, so it cannot authorize another claim.
	if strings.TrimSpace(input.ConfirmationToken) != "confirm-volume-destroy:"+physical {
		writeJSONError(writer, http.StatusConflict, "volume_confirmation_required", "exact volume-scoped confirmation token is required")
		return
	}
	now := time.Now().UTC()
	if h.Now != nil {
		now = h.Now().UTC()
	}
	command := M2VolumeDestroyCommand{ReleaseID: releaseID, Claim: claim, PhysicalName: physical, ConfirmationToken: input.ConfirmationToken, IdempotencyKey: key, Actor: "m2-api", Deadline: now.Add(2 * time.Minute)}
	if err := h.Volumes.Destroy(request.Context(), command); err != nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "volume_destroy_failed", "confirmed task volume destruction did not complete")
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{"release_id": releaseID, "claim_id": claimID, "physical_name": physical, "state": "destroy_requested"})
}

func (h *M2LifecycleHandler) collectImages(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST, OPTIONS")
		writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if h.Collector == nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "image_gc_unavailable", "an image-only GC collector is required")
		return
	}
	var input struct {
		DryRun bool `json:"dry_run"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSONError(writer, http.StatusBadRequest, "invalid_image_gc", err.Error())
		return
	}
	if !input.DryRun && strings.TrimSpace(request.Header.Get("Idempotency-Key")) == "" {
		writeJSONError(writer, http.StatusBadRequest, "invalid_image_gc", "Idempotency-Key is required for collection")
		return
	}
	if input.DryRun {
		plan, err := h.Collector.Plan(request.Context())
		if err != nil {
			writeJSONError(writer, http.StatusServiceUnavailable, "image_gc_plan_failed", "image GC inventory is unavailable or inconsistent")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"dry_run": true, "plan": plan})
		return
	}
	result, err := h.Collector.Collect(request.Context())
	if err != nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"code": "image_gc_partial_failure", "result": result})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"dry_run": false, "result": result})
}

func (h *M2LifecycleHandler) physicalName(claim postgres.M2ServiceGroupVolumeClaim) (string, bool) {
	if claim.ID.Empty() || claim.SizeBytes <= 0 || !m2LifecycleName.MatchString(strings.TrimSpace(claim.Name)) {
		return "", false
	}
	name := h.TaskPrefix + "-volume-" + claim.Name
	return name, m2LifecycleName.MatchString(name)
}

func exactM2Claim(claims []postgres.M2ServiceGroupVolumeClaim, id domain.ID) (postgres.M2ServiceGroupVolumeClaim, bool) {
	for _, claim := range claims {
		if claim.ID == id {
			return claim, true
		}
	}
	return postgres.M2ServiceGroupVolumeClaim{}, false
}

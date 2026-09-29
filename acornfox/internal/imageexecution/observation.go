package imageexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/domain"
	"github.com/acornfox/acornfox/internal/foundation"
	"github.com/acornfox/acornfox/internal/providers/standalone"
	"net/http"
	"time"
)

// Fixed process-wide bound; no polling controller or persisted sampling state.
var observationSlots = make(chan struct{}, 4)

func observationBinding(ctx context.Context, r *ContainerRuntime, q appcontracts.ImageObservationRequest) (appcontracts.ManagedImageObservationBinding, error) {
	var b appcontracts.ManagedImageObservationBinding
	if r == nil || r.authorityClient == nil {
		return b, errors.New("observation authority unavailable")
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return b, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/authority/managed-observation", bytes.NewReader(raw))
	if err != nil {
		return b, err
	}
	resp, data, err := r.authorityClient.Do(req)
	if err != nil {
		return b, err
	}
	if resp.StatusCode != http.StatusOK {
		return b, errors.New("managed observation authority rejected")
	}
	if err = decodeStrictJSON(bytes.NewReader(data), &b); err != nil {
		return b, err
	}
	if b.AdminID != q.AdminID || b.Runtime.DeploymentID != q.DeploymentID {
		return b, errors.New("managed observation authority mismatch")
	}
	return b, nil
}
func sameObservationBinding(a, b appcontracts.ManagedImageObservationBinding) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func boundedObservationLogs(raw contracts.AcornFoxBoundedLogs) ([]appcontracts.ImageObservationLog, bool) {
	out := []appcontracts.ImageObservationLog{}
	remaining := appcontracts.ImageObservationLogBytes
	limited := raw.SourceLimited
	for _, line := range raw.Records {
		data := foundation.RedactText(line.Data)
		if len(out) >= appcontracts.ImageObservationLogTail || len(data) > remaining {
			limited = true
			break
		}
		if data != "" {
			out = append(out, appcontracts.ImageObservationLog{Stream: line.Stream, Data: data})
			remaining -= len(data)
		}
	}
	return out, limited
}
func (r *ContainerRuntime) ReadManagedImageObservation(ctx context.Context, q appcontracts.ImageObservationRequest) (appcontracts.ImageObservationResult, error) {
	var out appcontracts.ImageObservationResult
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if !q.Valid(time.Now().UTC()) {
		return out, domain.ValidationError("invalid managed observation bounds")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	select {
	case observationSlots <- struct{}{}:
		defer func() { <-observationSlots }()
	case <-ctx.Done():
		return out, ctx.Err()
	default:
		return out, domain.NewError(domain.ErrConflict, "observation concurrency limit")
	}
	b, err := observationBinding(ctx, r, q)
	if err != nil {
		return out, err
	}
	runtime := b.Runtime
	op := contracts.OperationContext{IdempotencyKey: "image.observe:" + runtime.DeploymentID.String(), Deadline: time.Now().UTC().Add(10 * time.Second)}
	spec, err := mappedImageRuntimeSpec(DeployRequest{ApplicationID: runtime.ApplicationID, EnvironmentID: runtime.EnvironmentID, ReleaseID: runtime.ReleaseID, CanonicalInput: runtime.Plan.CanonicalInput}, domain.ImageDigest{Repository: runtime.Plan.ResolvedImage.Repository, Digest: runtime.ImageID})
	if err != nil {
		return out, err
	}
	before, err := r.standalone.ObserveExpectedDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: runtime.DeploymentID, Operation: op}, spec)
	if err != nil {
		return out, err
	}
	state, err := managedSnapshot(runtime, before)
	if err != nil {
		return out, err
	}
	if q.Logs {
		logs, readErr := r.standalone.ReadAcornFoxLogs(ctx, contracts.LogsRequest{DeploymentID: runtime.DeploymentID, ServiceName: "web", Tail: q.Tail, Since: q.Since, Operation: op})
		if readErr != nil {
			return out, readErr
		}
		if err = logs.Validate(); err != nil {
			return out, err
		}
		out.Records, out.SourceLimited = boundedObservationLogs(logs)
	}
	after, err := r.standalone.ObserveExpectedDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: runtime.DeploymentID, Operation: op}, spec)
	if err != nil {
		return appcontracts.ImageObservationResult{}, err
	}
	final, err := managedSnapshot(runtime, after)
	if err != nil {
		return appcontracts.ImageObservationResult{}, err
	}
	if final.ContainerID != state.ContainerID || final.ImageID != state.ImageID || final.Running != state.Running {
		return appcontracts.ImageObservationResult{}, errors.New("observation target changed during read")
	}
	current, err := observationBinding(ctx, r, q)
	if err != nil {
		return appcontracts.ImageObservationResult{}, err
	}
	if !sameObservationBinding(b, current) {
		return appcontracts.ImageObservationResult{}, errors.New("observation authority changed during read")
	}
	if err = ctx.Err(); err != nil {
		return appcontracts.ImageObservationResult{}, err
	}
	out.State = final
	return out, nil
}
func (cs *ContainerServer) handleManagedObservation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var q appcontracts.ImageObservationRequest
	if decodeStrictJSON(r.Body, &q) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	out, err := cs.runtime.ReadManagedImageObservation(r.Context(), q)
	if err != nil {
		http.Error(w, "managed observation unavailable", 409)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
func (as *CoreAuthorityServer) handleManagedObservationBinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var q appcontracts.ImageObservationRequest
	if decodeStrictJSON(r.Body, &q) != nil || !q.Valid(time.Now().UTC()) {
		http.Error(w, "invalid request", 400)
		return
	}
	store, ok := as.store.(appcontracts.ManagedImageObservationStore)
	if !ok {
		http.Error(w, "authority unavailable", 503)
		return
	}
	b, err := store.ReadManagedImageObservationBinding(r.Context(), q.AdminID, q.DeploymentID)
	if err != nil {
		http.Error(w, "authority rejected", 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b)
}

// Runtime identity is matched to Core's prior verified immutable deploy facts.
// This read-only operation does not claim a new OCI archive rehash.
func managedSnapshot(b appcontracts.ImageLifecycleBinding, s standalone.DeploymentObservationSnapshot) (appcontracts.ImageLifecycleResult, error) {
	o := s.Observation
	if appcontracts.ValidatePlanConsistency(b.Plan) != nil || b.Plan.PlanDigest != b.PlanDigest || b.Plan.ResolvedImage.Digest != b.ManifestDigest || s.ContainerName == "" {
		return appcontracts.ImageLifecycleResult{}, errors.New("invalid Core approved observation plan")
	}
	if s.Deployment.ID != b.DeploymentID || s.Deployment.ApplicationID != b.ApplicationID || s.Deployment.EnvironmentID != b.EnvironmentID || s.Deployment.ReleaseID != b.ReleaseID || s.Image.Repository != b.Plan.ResolvedImage.Repository || s.Image.Digest != b.ImageID || o.ContainerID != b.ContainerID || o.HostPort != b.HostPort || s.ContainerPort != b.ContainerPort || o.ObservedAt.IsZero() || o.ObservedAt.After(time.Now().UTC()) || o.ObservedAt.Before(time.Now().UTC().Add(-10*time.Second)) {
		return appcontracts.ImageLifecycleResult{}, errors.New("managed runtime differs from Core verified release")
	}
	return appcontracts.ImageLifecycleResult{Running: o.Status == "running", VerifiedIdentity: true, ContainerID: b.ContainerID, ImageID: b.ImageID, ManifestDigest: b.ManifestDigest, HostPort: b.HostPort, ContainerPort: b.ContainerPort, ObservedAt: o.ObservedAt}, nil
}
func decodeManagedObservationResult(data []byte) (appcontracts.ImageObservationResult, error) {
	var out appcontracts.ImageObservationResult
	if err := decodeStrictJSON(bytes.NewReader(data), &out); err != nil {
		return out, err
	}
	var wire struct {
		State         map[string]json.RawMessage `json:"state"`
		SourceLimited *bool                      `json:"source_limited"`
	}
	if json.Unmarshal(data, &wire) != nil || wire.SourceLimited == nil {
		return out, errors.New("missing observation fields")
	}
	for _, name := range []string{"running", "verified_identity", "endpoint_ready"} {
		var value *bool
		v, ok := wire.State[name]
		if !ok || json.Unmarshal(v, &value) != nil || value == nil {
			return appcontracts.ImageObservationResult{}, errors.New("missing observation state flag")
		}
	}
	if err := out.Validate(time.Now().UTC()); err != nil {
		return appcontracts.ImageObservationResult{}, err
	}
	return out, nil
}

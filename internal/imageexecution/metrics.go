package imageexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/dockermetrics"
	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/providers/standalone"
)

// ReadManagedImageMetrics shares the observation authority, target verification,
// deadline, and four read slots. Only the verified snapshot supplies a Docker ID.
func (r *ContainerRuntime) ReadManagedImageMetrics(ctx context.Context, q appcontracts.ImageMetricsRequest) (appcontracts.ImageMetricsResult, error) {
	var out appcontracts.ImageMetricsResult
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if !q.Valid() || r == nil {
		return out, domain.ValidationError("invalid managed metrics request")
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
	readRequest := appcontracts.ImageObservationRequest{AdminID: q.AdminID, DeploymentID: q.DeploymentID}
	b, err := observationBinding(ctx, r, readRequest)
	if err != nil {
		return out, err
	}
	runtime := b.Runtime
	spec, err := mappedImageRuntimeSpec(DeployRequest{ApplicationID: runtime.ApplicationID, EnvironmentID: runtime.EnvironmentID, ReleaseID: runtime.ReleaseID, CanonicalInput: runtime.Plan.CanonicalInput}, domain.ImageDigest{Repository: runtime.Plan.ResolvedImage.Repository, Digest: runtime.ImageID})
	if err != nil {
		return out, err
	}
	op := contracts.OperationContext{IdempotencyKey: "image.metrics:" + runtime.DeploymentID.String(), Deadline: time.Now().UTC().Add(10 * time.Second)}
	observe := func() (standalone.DeploymentObservationSnapshot, appcontracts.ImageLifecycleResult, error) {
		snapshot, readErr := r.standalone.ObserveExpectedDeploymentSnapshot(ctx, contracts.ObserveRequest{DeploymentID: runtime.DeploymentID, Operation: op}, spec)
		if readErr != nil {
			return snapshot, appcontracts.ImageLifecycleResult{}, readErr
		}
		state, readErr := managedSnapshot(runtime, snapshot)
		return snapshot, state, readErr
	}
	before, initial, err := observe()
	if err != nil {
		return out, err
	}
	var sample dockermetrics.DockerRuntimeMetrics
	var sampleErr error
	if initial.Running {
		if r.metricsReader == nil {
			sampleErr = errors.New("metrics reader unavailable")
		} else {
			sample, sampleErr = r.metricsReader.ReadContainerMetrics(ctx, initial.ContainerID)
		}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	after, final, err := observe()
	if err != nil {
		return out, err
	}
	if final.ContainerID != initial.ContainerID || final.ImageID != initial.ImageID || final.HostPort != initial.HostPort || final.ContainerPort != initial.ContainerPort {
		return out, errors.New("metrics target changed during read")
	}
	current, err := observationBinding(ctx, r, readRequest)
	if err != nil {
		return out, err
	}
	if !sameObservationBinding(b, current) {
		return out, errors.New("metrics authority changed during read")
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	out.State = final
	if !final.Running {
		out.UnavailableReason = "not_running"
	} else if !initial.Running || before.StartedAt == "" || before.StartedAt != after.StartedAt {
		out.UnavailableReason = "runtime_changed"
	} else if sampleErr != nil {
		out.UnavailableReason = "read_unavailable"
	} else if sample.ContainerID != initial.ContainerID {
		return appcontracts.ImageMetricsResult{}, errors.New("metrics reader returned another container")
	} else if sample.Status != "running" || sample.StartedAt != before.StartedAt {
		out.UnavailableReason = "runtime_changed"
	} else {
		started, parseErr := time.Parse(time.RFC3339Nano, sample.StartedAt)
		if parseErr != nil || started.IsZero() {
			out.UnavailableReason = "read_unavailable"
		} else {
			out = mapManagedMetrics(final, sample, started)
		}
	}
	if err := out.Validate(time.Now().UTC()); err != nil {
		return appcontracts.ImageMetricsResult{}, err
	}
	return out, nil
}

func metricUint(value uint64) *uint64 { return &value }

func mapManagedMetrics(state appcontracts.ImageLifecycleResult, sample dockermetrics.DockerRuntimeMetrics, started time.Time) appcontracts.ImageMetricsResult {
	out := appcontracts.ImageMetricsResult{State: state, Available: true, SampledAt: sample.ObservedAt, ProcessStartedAt: started}
	if sample.CPUUsageAvailable {
		out.CPUUsageMillis = metricUint(sample.CPUUsageMillis)
	}
	if sample.CPUUsageAvailable && sample.CPUUsageRateKnown && !sample.CPURateWindowStartedAt.Before(started) {
		rate := sample.CPUUsageRatePercent
		out.CPUPercent = &rate
	}
	if sample.MemoryUsageAvailable {
		out.MemoryUsageBytes = metricUint(sample.MemoryUsageBytes)
	}
	if sample.MemoryLimitAvailable {
		out.MemoryLimitBytes = metricUint(sample.MemoryLimitBytes)
	}
	if sample.NetworkAvailable {
		out.NetworkRxBytes, out.NetworkTxBytes = metricUint(sample.NetworkRxBytes), metricUint(sample.NetworkTxBytes)
	}
	if sample.PIDsAvailable {
		out.PIDsCurrent = metricUint(sample.PIDsCurrent)
	}
	if sample.CgroupVerified {
		out.Limits = &appcontracts.ImageMetricLimits{CPUMillis: sample.AppliedLimits.CPUMillis, MemoryBytes: sample.AppliedLimits.MemoryBytes, PIDs: sample.AppliedLimits.PIDs}
	}
	if out.CPUUsageMillis == nil && out.MemoryUsageBytes == nil && out.NetworkRxBytes == nil && out.PIDsCurrent == nil {
		return appcontracts.ImageMetricsResult{State: state, UnavailableReason: "read_unavailable"}
	}
	return out
}

func (cs *ContainerServer) handleManagedMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var q appcontracts.ImageMetricsRequest
	if decodeStrictJSON(r.Body, &q) != nil || !q.Valid() {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	out, err := cs.runtime.ReadManagedImageMetrics(r.Context(), q)
	if err != nil {
		http.Error(w, "managed metrics unavailable", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func decodeManagedMetricsResult(data []byte) (appcontracts.ImageMetricsResult, error) {
	var out appcontracts.ImageMetricsResult
	if len(data) > appcontracts.ImageMetricsJSONBytes {
		return out, errors.New("managed metrics response exceeds limit")
	}
	if err := decodeStrictJSON(bytes.NewReader(data), &out); err != nil {
		return out, err
	}
	var wire struct {
		Available *bool                      `json:"available"`
		State     map[string]json.RawMessage `json:"state"`
	}
	if json.Unmarshal(data, &wire) != nil || wire.Available == nil {
		return appcontracts.ImageMetricsResult{}, errors.New("missing metrics availability")
	}
	for _, name := range []string{"running", "verified_identity", "endpoint_ready"} {
		var value *bool
		if json.Unmarshal(wire.State[name], &value) != nil || value == nil {
			return appcontracts.ImageMetricsResult{}, errors.New("missing metrics state flag")
		}
	}
	if err := out.Validate(time.Now().UTC()); err != nil {
		return appcontracts.ImageMetricsResult{}, err
	}
	return out, nil
}

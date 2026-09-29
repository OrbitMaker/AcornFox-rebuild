package contracts

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/acornfox/acornfox/internal/domain"
)

const ImageMetricsJSONBytes = 4 << 10

// ImageMetricsRequest is a bounded, read-only request for one managed deployment.
type ImageMetricsRequest struct {
	AdminID      domain.ID `json:"admin_id"`
	DeploymentID domain.ID `json:"deployment_id"`
}

func (q ImageMetricsRequest) Valid() bool {
	return !q.AdminID.Empty() && !q.DeploymentID.Empty()
}

// ImageMetricLimits contains only observed kernel-enforced runtime limits.
type ImageMetricLimits struct {
	CPUMillis   int64 `json:"cpu_millis"`
	MemoryBytes int64 `json:"memory_bytes"`
	PIDs        int64 `json:"pids"`
}

// Nil numeric fields mean unavailable, never zero. Available is false for a
// verified but non-running deployment; it does not imply endpoint health.
type ImageMetricsResult struct {
	State             ImageLifecycleResult `json:"state"`
	Available         bool                 `json:"available"`
	UnavailableReason string               `json:"unavailable_reason,omitempty"`
	SampledAt         time.Time            `json:"sampled_at,omitempty"`
	ProcessStartedAt  time.Time            `json:"process_started_at,omitempty"`
	CPUPercent        *float64             `json:"cpu_percent,omitempty"`
	CPUUsageMillis    *uint64              `json:"cpu_usage_millis,omitempty"`
	MemoryUsageBytes  *uint64              `json:"memory_usage_bytes,omitempty"`
	MemoryLimitBytes  *uint64              `json:"memory_limit_bytes,omitempty"`
	NetworkRxBytes    *uint64              `json:"network_rx_bytes,omitempty"`
	NetworkTxBytes    *uint64              `json:"network_tx_bytes,omitempty"`
	PIDsCurrent       *uint64              `json:"pids_current,omitempty"`
	Limits            *ImageMetricLimits   `json:"limits,omitempty"`
}

func (r ImageMetricsResult) Validate(now time.Time) error {
	s := r.State
	if s.EndpointReady || !s.VerifiedIdentity || s.ContainerID == "" || s.ImageID == "" || s.ManifestDigest == "" || s.HostPort < 1 || s.HostPort > 65535 || s.ContainerPort < 1 || s.ContainerPort > 65535 || s.ObservedAt.IsZero() || s.ObservedAt.After(now.Add(time.Second)) || s.ObservedAt.Before(now.Add(-10*time.Second)) {
		return errors.New("invalid managed metrics identity")
	}
	if !r.Available {
		validReason := (r.UnavailableReason == "not_running" && !s.Running) || ((r.UnavailableReason == "read_unavailable" || r.UnavailableReason == "runtime_changed") && s.Running)
		if !validReason || !r.SampledAt.IsZero() || !r.ProcessStartedAt.IsZero() || r.CPUPercent != nil || r.CPUUsageMillis != nil || r.MemoryUsageBytes != nil || r.MemoryLimitBytes != nil || r.NetworkRxBytes != nil || r.NetworkTxBytes != nil || r.PIDsCurrent != nil || r.Limits != nil {
			return errors.New("unavailable metrics contain a sample")
		}
		return nil
	}
	if r.UnavailableReason != "" || !s.Running || r.SampledAt.IsZero() || r.SampledAt.After(now.Add(time.Second)) || r.SampledAt.Before(now.Add(-10*time.Second)) || r.ProcessStartedAt.IsZero() || r.ProcessStartedAt.After(r.SampledAt) || (r.CPUUsageMillis == nil && r.MemoryUsageBytes == nil && r.NetworkRxBytes == nil && r.PIDsCurrent == nil) {
		return errors.New("invalid managed metrics sample")
	}
	if r.CPUPercent != nil && (r.CPUUsageMillis == nil || math.IsNaN(*r.CPUPercent) || math.IsInf(*r.CPUPercent, 0) || *r.CPUPercent < 0) {
		return errors.New("invalid CPU rate")
	}
	if (r.NetworkRxBytes == nil) != (r.NetworkTxBytes == nil) {
		return errors.New("incomplete network sample")
	}
	if r.Limits != nil && (r.Limits.CPUMillis < 0 || r.Limits.MemoryBytes < 0 || r.Limits.PIDs < 0) {
		return errors.New("invalid observed limits")
	}
	return nil
}

type ImageMetricsClient interface {
	ReadManagedImageMetrics(context.Context, ImageMetricsRequest) (ImageMetricsResult, error)
}

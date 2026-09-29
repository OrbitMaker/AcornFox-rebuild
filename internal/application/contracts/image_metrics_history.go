package contracts

import (
	"context"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

const (
	ImageMetricsHistoryObjects   = 32
	ImageMetricsHistorySamples   = 360
	ImageMetricsHistoryDefault   = 60
	ImageMetricsHistoryRetention = 30 * time.Minute
	ImageMetricsHistoryJSONBytes = 256 << 10
)

// ImageMetricsHistoryPoint is one factual sample or an explicit unavailable
// observation. Nil numeric fields have never been read as zero.
type ImageMetricsHistoryPoint struct {
	SegmentID         uint64             `json:"segment_id"`
	ContainerID       string             `json:"container_id"`
	ProcessStartedAt  *time.Time         `json:"process_started_at,omitempty"`
	ObservedAt        time.Time          `json:"observed_at"`
	Available         bool               `json:"available"`
	UnavailableReason string             `json:"unavailable_reason,omitempty"`
	CPUPercent        *float64           `json:"cpu_percent,omitempty"`
	CPUUsageMillis    *uint64            `json:"cpu_usage_millis,omitempty"`
	MemoryUsageBytes  *uint64            `json:"memory_usage_bytes,omitempty"`
	MemoryLimitBytes  *uint64            `json:"memory_limit_bytes,omitempty"`
	NetworkRxBytes    *uint64            `json:"network_rx_bytes,omitempty"`
	NetworkTxBytes    *uint64            `json:"network_tx_bytes,omitempty"`
	PIDsCurrent       *uint64            `json:"pids_current,omitempty"`
	Limits            *ImageMetricLimits `json:"limits,omitempty"`
}

// Epoch changes on Core restart. SegmentID changes on container or process
// generation changes within that epoch; rates must not span two segments.
type ImageMetricsRecentResult struct {
	DeploymentID      domain.ID                  `json:"deployment_id"`
	ContainerID       string                     `json:"container_id"`
	HistoryEpoch      time.Time                  `json:"history_epoch"`
	HistoryStart      *time.Time                 `json:"history_start,omitempty"`
	SegmentStart      *time.Time                 `json:"segment_start,omitempty"`
	CurrentSegmentID  uint64                     `json:"current_segment_id"`
	Scheduled         bool                       `json:"scheduled"`
	StaleAfterSeconds int                        `json:"stale_after_seconds"`
	Stale             bool                       `json:"stale"`
	RecordingStatus   string                     `json:"recording_status"`
	Reason            string                     `json:"reason,omitempty"`
	SelectionLimited  bool                       `json:"selection_limited"`
	Samples           []ImageMetricsHistoryPoint `json:"samples"`
}

type ImageMetricsTargetSelection struct {
	Targets []ImageMetricsRequest
	Limited bool
}

// Target enumeration is a bounded Core-only read over the enabled admin's
// existing, verified deployments; it does not accept a caller-supplied CID.
type ImageMetricsTargetStore interface {
	ListActiveManagedImageMetricTargets(context.Context, int) (ImageMetricsTargetSelection, error)
}

type ImageMetricsHistoryReader interface {
	Record(domain.ID, ImageMetricsResult, time.Time) error
	Recent(domain.ID, string, int, time.Time) ImageMetricsRecentResult
}

type ImageMetricsBackgroundSampler interface {
	SetClient(ImageMetricsClient)
}

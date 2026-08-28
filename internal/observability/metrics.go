// Package observability contains the bounded metric and local-log storage
// primitives used by the control plane.  The package intentionally keeps its
// persistence contract on database/sql so the application chooses and owns
// the PostgreSQL driver registration.
package observability

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBucketWidth is the initial usage aggregation width from ADR-0006.
	DefaultBucketWidth = 5 * time.Minute
	// DefaultMetricRetention is the initial raw-observation retention target.
	DefaultMetricRetention = 7 * 24 * time.Hour
)

var (
	ErrInvalidSample          = errors.New("invalid metric sample")
	ErrSampleConflict         = errors.New("metric sample identity conflicts with existing sample")
	ErrInvalidMetricQuery     = errors.New("invalid metric query")
	ErrInvalidBucketWidth     = errors.New("invalid metric bucket width")
	ErrEmptyMetricAggregation = errors.New("cannot aggregate an empty metric sample set")
)

// ErrInvalidUsageSample keeps the error recognizable to callers migrating
// from the foundation usage helper.
var ErrInvalidUsageSample = ErrInvalidSample

// Sample is one immutable observation.  It is a value type: constructors and
// storage methods copy it, and no package method mutates a caller-owned value.
// ID is an optional producer identity.  When it is absent, the content digest
// is the deduplication identity.  CPU is a normalized utilization value and
// CPUSeconds is accepted for providers that emit a per-sample CPU integral;
// callers should populate one representation consistently.
type Sample struct {
	ID             string    `json:"id,omitempty"`
	ApplicationID  string    `json:"application_id"`
	ServiceName    string    `json:"service_name"`
	ReleaseID      string    `json:"release_id,omitempty"`
	At             time.Time `json:"at"`
	CPU            float64   `json:"cpu"`
	CPUSeconds     float64   `json:"cpu_seconds,omitempty"`
	MemoryBytes    float64   `json:"memory_bytes"`
	DiskBytes      float64   `json:"disk_bytes"`
	NetworkRxBytes uint64    `json:"network_rx_bytes"`
	NetworkTxBytes uint64    `json:"network_tx_bytes"`
	RestartCount   uint64    `json:"restart_count"`
	ExceptionCount uint64    `json:"exception_count"`
}

// MetricSample and TimeBucket are vocabulary aliases for provider contracts.
type MetricSample = Sample

// NewSample validates and copies an observation.  It does not fill ID: an
// anonymous producer remains safely deduplicable through ContentIdentity.
func NewSample(sample Sample) (Sample, error) {
	if err := sample.Validate(); err != nil {
		return Sample{}, err
	}
	return sample, nil
}

// Validate checks identity, timestamp, and finite non-negative measurements.
// ReleaseID is optional because a provider can observe a service before its
// first release has been persisted; query filters can still require it.
func (s Sample) Validate() error {
	if strings.TrimSpace(s.ApplicationID) == "" {
		return fmt.Errorf("%w: application id is required", ErrInvalidSample)
	}
	if strings.TrimSpace(s.ServiceName) == "" {
		return fmt.Errorf("%w: service name is required", ErrInvalidSample)
	}
	if s.At.IsZero() {
		return fmt.Errorf("%w: timestamp is required", ErrInvalidSample)
	}
	for _, metric := range []struct {
		name  string
		value float64
	}{
		{name: "cpu", value: s.CPU},
		{name: "cpu_seconds", value: s.CPUSeconds},
		{name: "memory_bytes", value: s.MemoryBytes},
		{name: "disk_bytes", value: s.DiskBytes},
	} {
		name, value := metric.name, metric.value
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return fmt.Errorf("%w: %s must be finite and non-negative", ErrInvalidSample, name)
		}
	}
	return nil
}

// ContentIdentity is a stable digest of all observation facts.  It is useful
// for anonymous producers and for detecting whether two payloads are equal.
func (s Sample) ContentIdentity() string {
	return digestString(s.canonical(false))
}

// Fingerprint is an alias for ContentIdentity.
func (s Sample) Fingerprint() string { return s.ContentIdentity() }

// Identity returns the deduplication identity. A producer ID is stable across
// retries (so a changed retry is a conflict), while anonymous observations
// use a full content digest. The SQL primary key also includes observed_at so
// range partitioning remains valid.
func (s Sample) Identity() string {
	if id := strings.TrimSpace(s.ID); id != "" {
		return digestString(strings.Join([]string{"id", id}, "\x00"))
	}
	return s.ContentIdentity()
}

// DedupKey is the explicit spelling used by ingestion code.
func (s Sample) DedupKey() string { return s.Identity() }

// SampleIdentity returns the stable deduplication identity for sample.
func SampleIdentity(sample Sample) string { return sample.Identity() }

// DedupIdentity is the function-shaped spelling used by ingestion adapters.
func DedupIdentity(sample Sample) string { return sample.Identity() }

// ValidateSample is the function-shaped validation spelling.
func ValidateSample(sample Sample) error { return sample.Validate() }

// SampleFingerprint returns the stable content fingerprint for sample.
func SampleFingerprint(sample Sample) string { return sample.ContentIdentity() }

func (s Sample) canonical(includeID bool) string {
	parts := []string{
		strings.TrimSpace(s.ApplicationID),
		strings.TrimSpace(s.ServiceName),
		strings.TrimSpace(s.ReleaseID),
		s.At.UTC().Format(time.RFC3339Nano),
		formatFloat(s.CPU),
		formatFloat(s.CPUSeconds),
		formatFloat(s.MemoryBytes),
		formatFloat(s.DiskBytes),
		strconv.FormatUint(s.NetworkRxBytes, 10),
		strconv.FormatUint(s.NetworkTxBytes, 10),
		strconv.FormatUint(s.RestartCount, 10),
		strconv.FormatUint(s.ExceptionCount, 10),
	}
	if includeID {
		parts = append([]string{strings.TrimSpace(s.ID)}, parts...)
	}
	return strings.Join(parts, "\x00")
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func formatFloat(value float64) string { return strconv.FormatFloat(value, 'g', -1, 64) }

// DeduplicateSamples validates and returns a fresh, stable-order copy.  Equal
// retries are dropped.  Reuse of a producer identity with different facts is
// rejected instead of silently choosing one reading.
func DeduplicateSamples(samples []Sample) ([]Sample, error) {
	if len(samples) == 0 {
		return []Sample{}, nil
	}
	result := make([]Sample, 0, len(samples))
	seen := make(map[string]Sample, len(samples))
	for _, sample := range samples {
		if err := sample.Validate(); err != nil {
			return nil, err
		}
		key := sample.Identity()
		if previous, ok := seen[key]; ok {
			if previous.ContentIdentity() != sample.ContentIdentity() {
				return nil, fmt.Errorf("%w: %s", ErrSampleConflict, key)
			}
			continue
		}
		copyOfSample := sample
		seen[key] = copyOfSample
		result = append(result, copyOfSample)
	}
	return result, nil
}

// DedupSamples is a short compatibility spelling.
func DedupSamples(samples []Sample) ([]Sample, error) { return DeduplicateSamples(samples) }

// Aggregate is a deterministic, query-ready five-minute (or caller-selected)
// usage result.  WindowStart/WindowEnd identify the bucket; the fields mirror
// the domain's UsageAggregate while retaining averages and peaks for UI and
// diagnostics.
type Aggregate struct {
	ApplicationID  string    `json:"application_id"`
	ServiceName    string    `json:"service_name"`
	ReleaseID      string    `json:"release_id,omitempty"`
	WindowStart    time.Time `json:"window_start"`
	WindowEnd      time.Time `json:"window_end"`
	BucketStart    time.Time `json:"bucket_start"`
	BucketEnd      time.Time `json:"bucket_end"`
	SampleCount    int       `json:"sample_count"`
	AverageCPU     float64   `json:"average_cpu"`
	PeakCPU        float64   `json:"peak_cpu"`
	TrendCPU       float64   `json:"trend_cpu"`
	CPUSeconds     float64   `json:"cpu_seconds"`
	AverageMemory  float64   `json:"average_memory_bytes"`
	PeakMemory     float64   `json:"peak_memory_bytes"`
	TrendMemory    float64   `json:"trend_memory_bytes"`
	MemoryByteSecs float64   `json:"memory_byte_seconds"`
	AverageDisk    float64   `json:"average_disk_bytes"`
	PeakDisk       float64   `json:"peak_disk_bytes"`
	TrendDisk      float64   `json:"trend_disk_bytes"`
	NetworkRx      uint64    `json:"network_rx_bytes"`
	NetworkTx      uint64    `json:"network_tx_bytes"`
	RestartCount   uint64    `json:"restart_count"`
	ExceptionCount uint64    `json:"exception_count"`

	// Verbose aliases mirror the domain/provider vocabulary. They are filled
	// together with the compact fields by aggregation and SQL reads.
	AverageMemoryBytes float64 `json:"-"`
	PeakMemoryBytes    float64 `json:"-"`
	TrendMemoryBytes   float64 `json:"-"`
	MemoryByteSeconds  float64 `json:"-"`
	AverageDiskBytes   float64 `json:"-"`
	PeakDiskBytes      float64 `json:"-"`
	TrendDiskBytes     float64 `json:"-"`
	NetworkRxBytes     uint64  `json:"-"`
	NetworkTxBytes     uint64  `json:"-"`
}

// UsageAggregate is an alias for callers using the domain vocabulary.
type UsageAggregate = Aggregate
type TimeBucket = Aggregate

// AggregateSamples computes one deterministic aggregate over homogeneous
// samples. Input order does not affect the result; the input slice is never
// sorted or modified.
func AggregateSamples(samples []Sample) (Aggregate, error) {
	unique, err := DeduplicateSamples(samples)
	if err != nil {
		return Aggregate{}, err
	}
	if len(unique) == 0 {
		return Aggregate{}, fmt.Errorf("%w: %w", ErrEmptyMetricAggregation, ErrInvalidSample)
	}
	ordered := append([]Sample(nil), unique...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].At.Equal(ordered[j].At) {
			return ordered[i].Identity() < ordered[j].Identity()
		}
		return ordered[i].At.Before(ordered[j].At)
	})
	for i := 1; i < len(ordered); i++ {
		if !ordered[i].At.After(ordered[i-1].At) {
			return Aggregate{}, fmt.Errorf("%w: duplicate timestamps in aggregate", ErrInvalidSample)
		}
	}

	first := ordered[0]
	last := ordered[len(ordered)-1]
	result := Aggregate{
		ApplicationID: first.ApplicationID,
		ServiceName:   first.ServiceName,
		ReleaseID:     first.ReleaseID,
		WindowStart:   first.At.UTC(),
		WindowEnd:     last.At.UTC(),
		SampleCount:   len(ordered),
		PeakCPU:       sampleCPU(first),
		PeakMemory:    first.MemoryBytes,
		PeakDisk:      first.DiskBytes,
	}
	for _, sample := range ordered {
		cpu := sampleCPU(sample)
		result.AverageCPU += cpu
		result.AverageMemory += sample.MemoryBytes
		result.AverageDisk += sample.DiskBytes
		if cpu > result.PeakCPU {
			result.PeakCPU = cpu
		}
		if sample.MemoryBytes > result.PeakMemory {
			result.PeakMemory = sample.MemoryBytes
		}
		if sample.DiskBytes > result.PeakDisk {
			result.PeakDisk = sample.DiskBytes
		}
		result.NetworkRx += sample.NetworkRxBytes
		result.NetworkTx += sample.NetworkTxBytes
		result.RestartCount += sample.RestartCount
		result.ExceptionCount += sample.ExceptionCount
	}
	count := float64(len(ordered))
	result.AverageCPU /= count
	result.AverageMemory /= count
	result.AverageDisk /= count
	windowSeconds := last.At.Sub(first.At).Seconds()
	if windowSeconds > 0 {
		result.TrendCPU = (sampleCPU(last) - sampleCPU(first)) / windowSeconds
		result.TrendMemory = (last.MemoryBytes - first.MemoryBytes) / windowSeconds
		result.TrendDisk = (last.DiskBytes - first.DiskBytes) / windowSeconds
	}
	if hasCPUSeconds(ordered) {
		for _, sample := range ordered {
			result.CPUSeconds += sample.CPUSeconds
		}
	} else {
		for i := 1; i < len(ordered); i++ {
			interval := ordered[i].At.Sub(ordered[i-1].At).Seconds()
			result.CPUSeconds += (sampleCPU(ordered[i-1]) + sampleCPU(ordered[i])) * interval / 2
			result.MemoryByteSecs += (ordered[i-1].MemoryBytes + ordered[i].MemoryBytes) * interval / 2
		}
	}
	if hasCPUSeconds(ordered) {
		for i := 1; i < len(ordered); i++ {
			interval := ordered[i].At.Sub(ordered[i-1].At).Seconds()
			result.MemoryByteSecs += (ordered[i-1].MemoryBytes + ordered[i].MemoryBytes) * interval / 2
		}
	}
	result.syncAliases()
	result.BucketStart = result.WindowStart
	result.BucketEnd = result.WindowEnd
	return result, nil
}

func (a *Aggregate) syncAliases() {
	if a == nil {
		return
	}
	a.AverageMemoryBytes = a.AverageMemory
	a.PeakMemoryBytes = a.PeakMemory
	a.TrendMemoryBytes = a.TrendMemory
	a.MemoryByteSeconds = a.MemoryByteSecs
	a.AverageDiskBytes = a.AverageDisk
	a.PeakDiskBytes = a.PeakDisk
	a.TrendDiskBytes = a.TrendDisk
	a.NetworkRxBytes = a.NetworkRx
	a.NetworkTxBytes = a.NetworkTx
}

func sampleCPU(sample Sample) float64 {
	if sample.CPU != 0 || sample.CPUSeconds == 0 {
		return sample.CPU
	}
	return sample.CPUSeconds
}

func hasCPUSeconds(samples []Sample) bool {
	for _, sample := range samples {
		if sample.CPUSeconds != 0 {
			return true
		}
	}
	return false
}

// AggregateBuckets de-duplicates, groups, and sorts observations into fixed
// time buckets. A late sample naturally lands in the bucket determined by its
// own timestamp.
func AggregateBuckets(samples []Sample, width time.Duration) ([]Aggregate, error) {
	if width <= 0 {
		return nil, ErrInvalidBucketWidth
	}
	unique, err := DeduplicateSamples(samples)
	if err != nil {
		return nil, err
	}
	type key struct {
		application string
		service     string
		release     string
		bucket      time.Time
	}
	groups := make(map[key][]Sample)
	for _, sample := range unique {
		bucket := sample.At.UTC().Truncate(width)
		groupKey := key{application: sample.ApplicationID, service: sample.ServiceName, release: sample.ReleaseID, bucket: bucket}
		groups[groupKey] = append(groups[groupKey], sample)
	}
	keys := make([]key, 0, len(groups))
	for groupKey := range groups {
		keys = append(keys, groupKey)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].application != keys[j].application {
			return keys[i].application < keys[j].application
		}
		if keys[i].service != keys[j].service {
			return keys[i].service < keys[j].service
		}
		if keys[i].release != keys[j].release {
			return keys[i].release < keys[j].release
		}
		return keys[i].bucket.Before(keys[j].bucket)
	})
	result := make([]Aggregate, 0, len(keys))
	for _, groupKey := range keys {
		aggregate, err := AggregateSamples(groups[groupKey])
		if err != nil {
			return nil, err
		}
		aggregate.BucketStart = groupKey.bucket.UTC()
		aggregate.BucketEnd = groupKey.bucket.Add(width).UTC()
		aggregate.WindowStart = aggregate.BucketStart
		aggregate.WindowEnd = aggregate.BucketEnd
		aggregate.syncAliases()
		result = append(result, aggregate)
	}
	return result, nil
}

// AggregateUsage is a compatibility alias for callers using the ADR term.
func AggregateUsage(samples []Sample, width time.Duration) ([]Aggregate, error) {
	return AggregateBuckets(samples, width)
}

// Query describes a half-open metric query window [From, To).  Filters are
// exact matches; an empty ServiceName or ReleaseID means all values.
type Query struct {
	ApplicationID string
	ServiceName   string
	ReleaseID     string
	From          time.Time
	To            time.Time
	Bucket        time.Duration
}

// MetricQuery is the explicit spelling used by SQL clients.
type MetricQuery = Query

func (q Query) Validate() error {
	if strings.TrimSpace(q.ApplicationID) == "" || q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) {
		return ErrInvalidMetricQuery
	}
	if q.Bucket < 0 {
		return ErrInvalidBucketWidth
	}
	return nil
}

// BucketWidth returns the requested width or the M0 default.
func (q Query) BucketWidth() time.Duration {
	if q.Bucket == 0 {
		return DefaultBucketWidth
	}
	return q.Bucket
}

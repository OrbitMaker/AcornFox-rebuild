// Package hostmetrics samples a small, read-only projection of host health.
// It intentionally has no network, command, or privilege boundary.
package hostmetrics

import (
	"time"
)

const (
	// MaxRecentObservations is the maximum capacity of the in-memory ring buffer (360 observations, matching 30 minutes at 5s sampling).
	MaxRecentObservations = 360

	// DefaultRecentLimit is the fallback count returned when a nonpositive limit is requested.
	DefaultRecentLimit = 60

	// RecentRetention is the maximum retention window for observations (30 minutes).
	RecentRetention = 30 * time.Minute
)

// observation stores a single host metrics sampling event as an inline record
// within the ring buffer. Mutating fields of a returned Response object cannot
// mutate sampler-owned history because Recent constructs fresh Response copies
// on each call.
//
// Memory and capacity boundaries:
//   - Fixed observation count: strictly capped at MaxRecentObservations (360 entries).
//   - Time-bounded expiry: observations older than RecentRetention (30 minutes) are expired.
//   - Bounded known labels: mountpoint is fixed to "/" and interface name is validated to at most 15 ASCII characters.
//   - No durable retention or general Go heap ceiling is guaranteed.
type observation struct {
	observedAt        time.Time
	availability      Availability
	staleAfterSeconds int

	hasCPU          bool
	logicalCores    int
	hasUsagePercent bool
	usagePercent    float64

	hasMemory       bool
	totalMemory     uint64
	availableMemory uint64
	usedMemory      uint64

	hasDisk    bool
	mountpoint string
	totalDisk  uint64
	freeDisk   uint64
	usedDisk   uint64

	hasNetwork       bool
	networkInterface string
	hasRXRate        bool
	rxRate           float64
	hasTXRate        bool
	txRate           float64
}

// toResponse constructs a newly allocated Response from the flat observation.
// Every pointer field is allocated afresh, providing complete deep-copy isolation.
func (obs observation) toResponse() Response {
	observedAt := obs.observedAt.UTC()
	resp := Response{
		SchemaVersion:     1,
		Availability:      obs.availability,
		ObservedAt:        &observedAt,
		StaleAfterSeconds: obs.staleAfterSeconds,
	}
	if obs.hasCPU {
		cpu := CPU{LogicalCores: obs.logicalCores}
		if obs.hasUsagePercent {
			val := obs.usagePercent
			cpu.UsagePercent = &val
		}
		resp.CPU = &cpu
	}
	if obs.hasMemory {
		resp.Memory = &Memory{
			TotalBytes:     obs.totalMemory,
			AvailableBytes: obs.availableMemory,
			UsedBytes:      obs.usedMemory,
		}
	}
	if obs.hasDisk {
		resp.Disk = &Disk{
			Mountpoint: obs.mountpoint,
			TotalBytes: obs.totalDisk,
			FreeBytes:  obs.freeDisk,
			UsedBytes:  obs.usedDisk,
		}
	}
	if obs.hasNetwork {
		net := Network{Interface: obs.networkInterface}
		if obs.hasRXRate {
			rx := obs.rxRate
			net.RXBytesPerSecond = &rx
		}
		if obs.hasTXRate {
			tx := obs.txRate
			net.TXBytesPerSecond = &tx
		}
		resp.Network = &net
	}
	return resp
}

// historyRing is a fixed-capacity in-memory circular buffer of exactly MaxRecentObservations (360) observations.
type historyRing struct {
	entries [MaxRecentObservations]observation
	head    int
	count   int
}

func newHistoryRing() *historyRing {
	return &historyRing{}
}

func (r *historyRing) push(obs observation) {
	if r == nil {
		return
	}
	r.entries[r.head] = obs
	r.head = (r.head + 1) % MaxRecentObservations
	if r.count < MaxRecentObservations {
		r.count++
	}
}

func (r *historyRing) recent(limit int, now time.Time) []Response {
	if r == nil || r.count == 0 {
		return []Response{}
	}
	effectiveLimit := limit
	if effectiveLimit <= 0 {
		effectiveLimit = DefaultRecentLimit
	}
	if effectiveLimit > MaxRecentObservations {
		effectiveLimit = MaxRecentObservations
	}

	cutoff := now.Add(-RecentRetention)
	start := (r.head - r.count + MaxRecentObservations) % MaxRecentObservations

	firstValid := r.count
	for i := 0; i < r.count; i++ {
		slot := (start + i) % MaxRecentObservations
		if !r.entries[slot].observedAt.Before(cutoff) {
			firstValid = i
			break
		}
	}

	unexpiredCount := r.count - firstValid
	if unexpiredCount <= 0 {
		return []Response{}
	}

	take := unexpiredCount
	if take > effectiveLimit {
		take = effectiveLimit
	}

	takeFrom := r.count - take
	result := make([]Response, 0, take)
	for i := takeFrom; i < r.count; i++ {
		slot := (start + i) % MaxRecentObservations
		result = append(result, r.entries[slot].toResponse())
	}
	return result
}

// Recent returns up to limit recent observations in oldest-to-newest order.
// If limit <= 0, DefaultRecentLimit (60) is used.
// If limit > MaxRecentObservations (360), it is clamped to MaxRecentObservations.
// Observations older than RecentRetention (30 minutes) are expired by time and omitted.
// The returned slice and its Response elements are independent copies; mutating them
// does not affect sampler-owned history.
func (s *Sampler) Recent(limit int) []Response {
	if s == nil {
		return nil
	}
	if s.os != "linux" {
		return []Response{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.history == nil {
		return []Response{}
	}
	nowFunc := s.now
	if nowFunc == nil {
		nowFunc = time.Now
	}
	return s.history.recent(limit, nowFunc().UTC())
}

func (s *Sampler) recordFailureLocked(sampleTime time.Time) {
	if s.history == nil {
		s.history = newHistoryRing()
	}
	s.history.push(observation{
		observedAt:        sampleTime.UTC(),
		availability:      Unavailable,
		staleAfterSeconds: seconds(s.staleAfter),
	})
}

func (s *Sampler) recordSuccessLocked(sample *recordedSample) {
	if sample == nil {
		return
	}
	if s.history == nil {
		s.history = newHistoryRing()
	}
	obs := observation{
		observedAt:        sample.raw.at.UTC(),
		availability:      WarmingUp,
		staleAfterSeconds: seconds(s.staleAfter),
		hasCPU:            true,
		logicalCores:      sample.raw.cores,
		hasMemory:         true,
		totalMemory:       sample.raw.memory.TotalBytes,
		availableMemory:   sample.raw.memory.AvailableBytes,
		usedMemory:        sample.raw.memory.UsedBytes,
		hasDisk:           true,
		mountpoint:        sample.raw.disk.Mountpoint,
		totalDisk:         sample.raw.disk.TotalBytes,
		freeDisk:          sample.raw.disk.FreeBytes,
		usedDisk:          sample.raw.disk.UsedBytes,
	}
	if sample.cpuUse != nil {
		obs.hasUsagePercent = true
		obs.usagePercent = *sample.cpuUse
		obs.availability = Available
	}
	if sample.raw.network != nil {
		obs.hasNetwork = true
		obs.networkInterface = sample.raw.network.interfaceName
		if sample.netRX != nil {
			obs.hasRXRate = true
			obs.rxRate = *sample.netRX
		}
		if sample.netTX != nil {
			obs.hasTXRate = true
			obs.txRate = *sample.netTX
		}
	}
	s.history.push(obs)
}

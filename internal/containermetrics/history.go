// Package containermetrics keeps a bounded, process-local history of verified
// Native container samples. It has no Docker access or durable state.
package containermetrics

import (
	"context"
	"errors"
	"sync"
	"time"

	appcontracts "github.com/open-card/open-card/internal/application/contracts"
	"github.com/open-card/open-card/internal/domain"
)

const (
	sampleInterval = 5 * time.Second
	readBudget     = 10 * time.Second
	maxIDBytes     = 128
	maxCIDBytes    = 64
)

const (
	hasCPUPercent uint16 = 1 << iota
	hasCPUUsage
	hasMemoryUsage
	hasMemoryLimit
	hasNetwork
	hasPIDs
	hasLimits
)

// All retained records and identities are inline fixed-width values. With 32
// series and 360 records per series, retained storage has a hard object/count
// ceiling independent of request volume. Recent allocates only response copies.
type record struct {
	atUnixNano      int64
	startedUnixNano int64
	segmentID       uint64
	cid             [maxCIDBytes]byte
	cidLen          uint8
	flags           uint16
	reason          uint8
	available       bool
	cpuPercent      float64
	cpuUsage        uint64
	memoryUsage     uint64
	memoryLimit     uint64
	networkRX       uint64
	networkTX       uint64
	pids            uint64
	cpuLimit        int64
	memoryLimitHost int64
	pidsLimit       int64
}

type series struct {
	id              [maxIDBytes]byte
	idLen           uint8
	cid             [maxCIDBytes]byte
	cidLen          uint8
	startedUnixNano int64
	running         bool
	segmentID       uint64
	segmentStart    int64
	head            uint16
	count           uint16
	entries         [appcontracts.ImageMetricsHistorySamples]record
}

type History struct {
	mu               sync.RWMutex
	epoch            time.Time
	nextSegment      uint64
	activeCount      int
	selectionLimited bool
	active           [appcontracts.ImageMetricsHistoryObjects][maxIDBytes]byte
	activeLens       [appcontracts.ImageMetricsHistoryObjects]uint8
	series           [appcontracts.ImageMetricsHistoryObjects]series
}

func NewHistory(now time.Time) *History {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return &History{epoch: now.UTC()}
}

func validID(id domain.ID) bool { return !id.Empty() && len(id.String()) <= maxIDBytes }

func sameID(raw [maxIDBytes]byte, length uint8, id domain.ID) bool {
	return int(length) == len(id.String()) && string(raw[:length]) == id.String()
}

// SetActiveTargets replaces the bounded sampling selection. A disabled admin
// or removed deployment disappears from history on the next successful read.
func (h *History) SetActiveTargets(selection appcontracts.ImageMetricsTargetSelection) error {
	targets := selection.Targets
	if h == nil || len(targets) > appcontracts.ImageMetricsHistoryObjects {
		return errors.New("invalid metrics target selection")
	}
	var selected [appcontracts.ImageMetricsHistoryObjects][maxIDBytes]byte
	var lengths [appcontracts.ImageMetricsHistoryObjects]uint8
	for i, target := range targets {
		if !target.Valid() || !validID(target.DeploymentID) {
			return errors.New("invalid metrics target identity")
		}
		copy(selected[i][:], target.DeploymentID.String())
		lengths[i] = uint8(len(target.DeploymentID.String()))
		for j := 0; j < i; j++ {
			if lengths[i] == lengths[j] && selected[i] == selected[j] {
				return errors.New("duplicate metrics target")
			}
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.active, h.activeLens, h.activeCount, h.selectionLimited = selected, lengths, len(targets), selection.Limited
	for i := range h.series {
		if h.series[i].idLen != 0 && !h.selectedLocked(domain.ID(string(h.series[i].id[:h.series[i].idLen]))) {
			h.series[i] = series{}
		}
	}
	return nil
}

func (h *History) selectedLocked(id domain.ID) bool {
	for i := 0; i < h.activeCount; i++ {
		if sameID(h.active[i], h.activeLens[i], id) {
			return true
		}
	}
	return false
}

func (h *History) selectedCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.activeCount
}

func (h *History) findLocked(id domain.ID) *series {
	for i := range h.series {
		if sameID(h.series[i].id, h.series[i].idLen, id) {
			return &h.series[i]
		}
	}
	return nil
}

func (h *History) freeLocked(id domain.ID) *series {
	if found := h.findLocked(id); found != nil {
		return found
	}
	for i := range h.series {
		if h.series[i].idLen == 0 {
			copy(h.series[i].id[:], id.String())
			h.series[i].idLen = uint8(len(id.String()))
			return &h.series[i]
		}
	}
	// A selected set has at most 32 deployments. A full set with no free slot
	// can only be an invalid race with a previous selection, not an eviction
	// request from a public read.
	return nil
}

func reasonCode(value string) uint8 {
	switch value {
	case "not_running":
		return 1
	case "read_unavailable":
		return 2
	case "runtime_changed":
		return 3
	default:
		return 0
	}
}

func reasonText(value uint8) string {
	switch value {
	case 1:
		return "not_running"
	case 2:
		return "read_unavailable"
	case 3:
		return "runtime_changed"
	default:
		return ""
	}
}

// Record accepts only a current selected target and a fully validated factual
// sample. Failed RPCs create a visible time gap instead of a fabricated zero.
func (h *History) Record(id domain.ID, value appcontracts.ImageMetricsResult, now time.Time) error {
	if h == nil || !validID(id) || len(value.State.ContainerID) > maxCIDBytes {
		return errors.New("invalid metrics history target")
	}
	if err := value.Validate(now.UTC()); err != nil {
		return err
	}
	at := value.SampledAt
	if !value.Available {
		at = value.State.ObservedAt
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.selectedLocked(id) {
		return nil
	}
	s := h.freeLocked(id)
	if s == nil {
		return errors.New("metrics history object capacity reached")
	}
	if s.count > 0 {
		last := s.entries[(int(s.head)+appcontracts.ImageMetricsHistorySamples-1)%appcontracts.ImageMetricsHistorySamples]
		if at.UnixNano() <= last.atUnixNano {
			return nil
		}
	}
	var cid [maxCIDBytes]byte
	copy(cid[:], value.State.ContainerID)
	started := int64(0)
	if value.Available {
		started = value.ProcessStartedAt.UnixNano()
	}
	rotate := s.segmentID == 0 || s.cid != cid || s.cidLen != uint8(len(value.State.ContainerID)) || s.running != value.State.Running || value.UnavailableReason == "runtime_changed" || (started != 0 && s.startedUnixNano != started)
	if rotate {
		h.nextSegment++
		s.segmentID = h.nextSegment
		s.segmentStart = at.UnixNano()
		s.startedUnixNano = started
	}
	s.cid, s.cidLen, s.running = cid, uint8(len(value.State.ContainerID)), value.State.Running
	r := record{atUnixNano: at.UnixNano(), startedUnixNano: started, segmentID: s.segmentID, cid: cid, cidLen: s.cidLen, available: value.Available, reason: reasonCode(value.UnavailableReason)}
	if value.CPUPercent != nil {
		r.flags |= hasCPUPercent
		r.cpuPercent = *value.CPUPercent
	}
	if value.CPUUsageMillis != nil {
		r.flags |= hasCPUUsage
		r.cpuUsage = *value.CPUUsageMillis
	}
	if value.MemoryUsageBytes != nil {
		r.flags |= hasMemoryUsage
		r.memoryUsage = *value.MemoryUsageBytes
	}
	if value.MemoryLimitBytes != nil {
		r.flags |= hasMemoryLimit
		r.memoryLimit = *value.MemoryLimitBytes
	}
	if value.NetworkRxBytes != nil && value.NetworkTxBytes != nil {
		r.flags |= hasNetwork
		r.networkRX, r.networkTX = *value.NetworkRxBytes, *value.NetworkTxBytes
	}
	if value.PIDsCurrent != nil {
		r.flags |= hasPIDs
		r.pids = *value.PIDsCurrent
	}
	if value.Limits != nil {
		r.flags |= hasLimits
		r.cpuLimit, r.memoryLimitHost, r.pidsLimit = value.Limits.CPUMillis, value.Limits.MemoryBytes, value.Limits.PIDs
	}
	s.entries[s.head] = r
	s.head = uint16((int(s.head) + 1) % appcontracts.ImageMetricsHistorySamples)
	if int(s.count) < appcontracts.ImageMetricsHistorySamples {
		s.count++
	}
	return nil
}

func point(r record) appcontracts.ImageMetricsHistoryPoint {
	out := appcontracts.ImageMetricsHistoryPoint{SegmentID: r.segmentID, ContainerID: string(r.cid[:r.cidLen]), ObservedAt: time.Unix(0, r.atUnixNano).UTC(), Available: r.available, UnavailableReason: reasonText(r.reason)}
	if r.startedUnixNano != 0 {
		started := time.Unix(0, r.startedUnixNano).UTC()
		out.ProcessStartedAt = &started
	}
	if r.flags&hasCPUPercent != 0 {
		v := r.cpuPercent
		out.CPUPercent = &v
	}
	if r.flags&hasCPUUsage != 0 {
		v := r.cpuUsage
		out.CPUUsageMillis = &v
	}
	if r.flags&hasMemoryUsage != 0 {
		v := r.memoryUsage
		out.MemoryUsageBytes = &v
	}
	if r.flags&hasMemoryLimit != 0 {
		v := r.memoryLimit
		out.MemoryLimitBytes = &v
	}
	if r.flags&hasNetwork != 0 {
		rx, tx := r.networkRX, r.networkTX
		out.NetworkRxBytes, out.NetworkTxBytes = &rx, &tx
	}
	if r.flags&hasPIDs != 0 {
		v := r.pids
		out.PIDsCurrent = &v
	}
	if r.flags&hasLimits != 0 {
		out.Limits = &appcontracts.ImageMetricLimits{CPUMillis: r.cpuLimit, MemoryBytes: r.memoryLimitHost, PIDs: r.pidsLimit}
	}
	return out
}

func staleAfter(count int) time.Duration {
	return staleAfterFor(count, readBudget, sampleInterval)
}

func staleAfterFor(count int, budget, interval time.Duration) time.Duration {
	if count < 1 {
		count = 1
	}
	if count > appcontracts.ImageMetricsHistoryObjects {
		count = appcontracts.ImageMetricsHistoryObjects
	}
	// At most two reads run concurrently. A read finishing just after a tick
	// waits one extra five-second tick before the next pair starts.
	threshold := time.Duration((count+1)/2)*(budget+interval) + budget
	minimum := 3 * budget
	if threshold < minimum {
		return minimum
	}
	return threshold
}

// Recent returns independent, ascending response copies, expiring points at
// thirty minutes. A Core restart has a new epoch and no retained points.
func (h *History) Recent(id domain.ID, currentCID string, limit int, now time.Time) appcontracts.ImageMetricsRecentResult {
	if limit < 1 || limit > appcontracts.ImageMetricsHistorySamples {
		limit = appcontracts.ImageMetricsHistoryDefault
	}
	result := appcontracts.ImageMetricsRecentResult{DeploymentID: id, ContainerID: currentCID, Stale: true, RecordingStatus: "warming_up", Reason: "first_sample_pending", Samples: []appcontracts.ImageMetricsHistoryPoint{}}
	if h == nil {
		return result
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	result.HistoryEpoch = h.epoch
	result.StaleAfterSeconds = int(staleAfter(h.activeCount) / time.Second)
	result.Scheduled = h.selectedLocked(id)
	result.SelectionLimited = h.selectionLimited
	if !result.Scheduled {
		result.RecordingStatus = "not_selected"
		result.Reason = "outside_sampling_selection"
		return result
	}
	s := h.findLocked(id)
	if s == nil || s.count == 0 {
		return result
	}
	cutoff := now.UTC().Add(-appcontracts.ImageMetricsHistoryRetention).UnixNano()
	start := (int(s.head) - int(s.count) + appcontracts.ImageMetricsHistorySamples) % appcontracts.ImageMetricsHistorySamples
	for i := 0; i < int(s.count); i++ {
		r := s.entries[(start+i)%appcontracts.ImageMetricsHistorySamples]
		if r.atUnixNano < cutoff {
			continue
		}
		result.Samples = append(result.Samples, point(r))
	}
	if len(result.Samples) == 0 {
		result.RecordingStatus = "stale"
		result.Reason = "sample_expired"
		return result
	}
	first := result.Samples[0].ObservedAt
	result.HistoryStart = &first
	if len(result.Samples) > limit {
		result.Samples = result.Samples[len(result.Samples)-limit:]
	}
	last := result.Samples[len(result.Samples)-1]
	result.CurrentSegmentID = last.SegmentID
	if s.segmentID == last.SegmentID {
		stamp := time.Unix(0, s.segmentStart).UTC()
		result.SegmentStart = &stamp
	}
	result.Stale = now.UTC().Sub(last.ObservedAt) > staleAfter(h.activeCount) || last.ContainerID != currentCID
	if last.ContainerID != currentCID {
		result.RecordingStatus = "stale"
		result.Reason = "runtime_changed"
	} else if !last.Available {
		result.Stale = true
		result.RecordingStatus = "stale"
		result.Reason = last.UnavailableReason
	} else if result.Stale {
		result.RecordingStatus = "stale"
		result.Reason = "sample_expired"
	} else {
		result.RecordingStatus = "recording"
		result.Reason = ""
	}
	return result
}

// Sampler chooses the enabled owner's bounded target set every five seconds.
// It never queues catch-up reads; two in-flight reads leave observation slots
// for interactive requests. Container RPC retains its own 10-second deadline.
type Sampler struct {
	Store       appcontracts.ImageMetricsTargetStore
	History     *History
	mu          sync.Mutex
	client      appcontracts.ImageMetricsClient
	cursor      int
	active      [2]domain.ID
	wg          sync.WaitGroup
	interval    time.Duration // test-only shorter phase; zero retains production 5s
	readTimeout time.Duration // test-only shorter phase; zero retains production 10s
}

func (s *Sampler) SetClient(client appcontracts.ImageMetricsClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.client = client
}

// Start returns a completion channel that closes only after cancellation has
// stopped scheduling and all in-flight reads have joined. Core must await it
// before closing the Store.
func (s *Sampler) Start(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	return done
}

func (s *Sampler) Run(ctx context.Context) {
	if s == nil || s.Store == nil || s.History == nil {
		return
	}
	defer s.wg.Wait()
	s.tick(ctx)
	interval := s.interval
	if interval <= 0 {
		interval = sampleInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

func (s *Sampler) tick(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	selection, err := s.Store.ListActiveManagedImageMetricTargets(ctx, appcontracts.ImageMetricsHistoryObjects)
	targets := selection.Targets
	if err != nil || len(targets) > appcontracts.ImageMetricsHistoryObjects {
		return
	}
	if err = s.History.SetActiveTargets(selection); err != nil || len(targets) == 0 {
		return
	}
	s.mu.Lock()
	client := s.client
	if client == nil {
		s.mu.Unlock()
		return
	}
	for tried, dispatched := 0, 0; tried < len(targets) && dispatched < 2; tried++ {
		slot := -1
		for i := range s.active {
			if s.active[i].Empty() {
				slot = i
				break
			}
		}
		if slot < 0 {
			break
		}
		index := s.cursor % len(targets)
		s.cursor = (s.cursor + 1) % len(targets)
		q := targets[index]
		if q.DeploymentID == s.active[0] || q.DeploymentID == s.active[1] {
			continue
		}
		s.active[slot] = q.DeploymentID
		s.wg.Add(1)
		dispatched++
		go func(slot int, q appcontracts.ImageMetricsRequest) {
			defer s.wg.Done()
			defer func() { s.mu.Lock(); s.active[slot] = ""; s.mu.Unlock() }()
			budget := s.readTimeout
			if budget <= 0 {
				budget = readBudget
			}
			readCtx, cancel := context.WithTimeout(ctx, budget)
			defer cancel()
			value, readErr := client.ReadManagedImageMetrics(readCtx, q)
			if readErr == nil && readCtx.Err() == nil {
				_ = s.History.Record(q.DeploymentID, value, time.Now().UTC())
			}
		}(slot, q)
	}
	s.mu.Unlock()
}

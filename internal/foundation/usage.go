package foundation

import (
	"errors"
	"math"
	"sort"
	"time"
)

var ErrInvalidUsageSample = errors.New("invalid usage sample")

// UsageSample is an observation at one instant. CPU is a normalized fraction
// (1.0 means one full CPU), memory and disk are bytes, and network fields are
// byte deltas since the preceding sample. Configuration limits intentionally
// do not appear here; they are a separate fact owned by delivery settings.
type UsageSample struct {
	At             time.Time
	CPU            float64
	MemoryBytes    float64
	DiskBytes      float64
	NetworkRxBytes uint64
	NetworkTxBytes uint64
	RestartCount   uint64
	ExceptionCount uint64
}

// UsageAggregate contains independently derived actual observations. Average
// and peak are arithmetic values over samples; trends are endpoint slopes per
// second. CPUSeconds and MemoryByteSeconds are time-integrated estimates over
// the observed window using the trapezoid rule.
type UsageAggregate struct {
	WindowStart time.Time
	WindowEnd   time.Time
	SampleCount int

	AverageCPU float64
	PeakCPU    float64
	TrendCPU   float64
	CPUSeconds float64

	AverageMemoryBytes float64
	PeakMemoryBytes    float64
	TrendMemoryBytes   float64
	MemoryByteSeconds  float64

	AverageDiskBytes float64
	PeakDiskBytes    float64
	TrendDiskBytes   float64

	NetworkRxBytes uint64
	NetworkTxBytes uint64
	RestartCount   uint64
	ExceptionCount uint64
}

// AggregateUsage sorts a copy of the samples by timestamp, validates values,
// and calculates a deterministic aggregate. Input order therefore cannot
// change evidence or cache keys.
func AggregateUsage(samples []UsageSample) (UsageAggregate, error) {
	if len(samples) == 0 {
		return UsageAggregate{}, ErrInvalidUsageSample
	}
	ordered := append([]UsageSample(nil), samples...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].At.Before(ordered[j].At) })
	for i, sample := range ordered {
		if sample.At.IsZero() || !finiteNonNegative(sample.CPU) || !finiteNonNegative(sample.MemoryBytes) || !finiteNonNegative(sample.DiskBytes) {
			return UsageAggregate{}, ErrInvalidUsageSample
		}
		if i > 0 && !sample.At.After(ordered[i-1].At) {
			return UsageAggregate{}, ErrInvalidUsageSample
		}
	}

	result := UsageAggregate{
		WindowStart:     ordered[0].At.UTC(),
		WindowEnd:       ordered[len(ordered)-1].At.UTC(),
		SampleCount:     len(ordered),
		PeakCPU:         ordered[0].CPU,
		PeakMemoryBytes: ordered[0].MemoryBytes,
		PeakDiskBytes:   ordered[0].DiskBytes,
	}
	for _, sample := range ordered {
		result.AverageCPU += sample.CPU
		result.AverageMemoryBytes += sample.MemoryBytes
		result.AverageDiskBytes += sample.DiskBytes
		if sample.CPU > result.PeakCPU {
			result.PeakCPU = sample.CPU
		}
		if sample.MemoryBytes > result.PeakMemoryBytes {
			result.PeakMemoryBytes = sample.MemoryBytes
		}
		if sample.DiskBytes > result.PeakDiskBytes {
			result.PeakDiskBytes = sample.DiskBytes
		}
		result.NetworkRxBytes += sample.NetworkRxBytes
		result.NetworkTxBytes += sample.NetworkTxBytes
		result.RestartCount += sample.RestartCount
		result.ExceptionCount += sample.ExceptionCount
	}
	count := float64(len(ordered))
	result.AverageCPU /= count
	result.AverageMemoryBytes /= count
	result.AverageDiskBytes /= count

	duration := result.WindowEnd.Sub(result.WindowStart).Seconds()
	if duration > 0 {
		result.TrendCPU = (ordered[len(ordered)-1].CPU - ordered[0].CPU) / duration
		result.TrendMemoryBytes = (ordered[len(ordered)-1].MemoryBytes - ordered[0].MemoryBytes) / duration
		result.TrendDiskBytes = (ordered[len(ordered)-1].DiskBytes - ordered[0].DiskBytes) / duration
		for i := 1; i < len(ordered); i++ {
			interval := ordered[i].At.Sub(ordered[i-1].At).Seconds()
			result.CPUSeconds += (ordered[i-1].CPU + ordered[i].CPU) * interval / 2
			result.MemoryByteSeconds += (ordered[i-1].MemoryBytes + ordered[i].MemoryBytes) * interval / 2
		}
	}
	return result, nil
}

// AggregateSamples is an alias matching the test-spec vocabulary.
func AggregateSamples(samples []UsageSample) (UsageAggregate, error) {
	return AggregateUsage(samples)
}

// Trend returns the endpoint slope per second for a pair of values. It is
// exported for parameterized unit vectors and returns zero for a zero window.
func Trend(first, last float64, firstAt, lastAt time.Time) float64 {
	duration := lastAt.Sub(firstAt).Seconds()
	if duration <= 0 {
		return 0
	}
	return (last - first) / duration
}

func finiteNonNegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

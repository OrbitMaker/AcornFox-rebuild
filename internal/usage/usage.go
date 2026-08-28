// Package usage contains M5's local, non-commercial usage-fact model.
// It deliberately has no price, plan, invoice, payment, region, or AI fields.
package usage

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const DefaultBucketWidth = 5 * time.Minute

var (
	ErrInvalidFact = errors.New("invalid usage fact")
	ErrConflict    = errors.New("usage fact identity conflict")
	ErrWatermark   = errors.New("usage storage watermark blocks ingestion")
)

// Fact is an immutable local actual measurement. Units are deliberately in
// field names: CPU is millicores, memory/disk are bytes, and network counters
// are bytes. Limits are configuration facts and never overwrite actuals.
type Fact struct {
	SourceID                                                                                            string
	ApplicationID, EnvironmentID, DeploymentID, ReleaseID, ServiceName                                  string
	ObservedAt                                                                                          time.Time
	CPUMillicores, MemoryBytes, DiskBytes, NetworkRxBytes, NetworkTxBytes, RestartCount, ExceptionCount int64
	CPUSeconds, MemoryByteSeconds, RuntimeSeconds                                                       float64
	LimitCPUMillicores, LimitMemoryBytes, LimitDiskBytes, LimitPIDs                                     int64
}

func (f Fact) Validate() error {
	if strings.TrimSpace(f.SourceID) == "" || strings.TrimSpace(f.ApplicationID) == "" || strings.TrimSpace(f.ServiceName) == "" || f.ObservedAt.IsZero() {
		return ErrInvalidFact
	}
	for _, v := range []int64{f.CPUMillicores, f.MemoryBytes, f.DiskBytes, f.NetworkRxBytes, f.NetworkTxBytes, f.RestartCount, f.ExceptionCount, f.LimitCPUMillicores, f.LimitMemoryBytes, f.LimitDiskBytes, f.LimitPIDs} {
		if v < 0 {
			return ErrInvalidFact
		}
	}
	if math.IsNaN(f.CPUSeconds) || math.IsInf(f.CPUSeconds, 0) || f.CPUSeconds < 0 || math.IsNaN(f.MemoryByteSeconds) || math.IsInf(f.MemoryByteSeconds, 0) || f.MemoryByteSeconds < 0 || math.IsNaN(f.RuntimeSeconds) || math.IsInf(f.RuntimeSeconds, 0) || f.RuntimeSeconds < 0 {
		return ErrInvalidFact
	}
	return nil
}

// AggregateFacts deterministically handles late/out-of-order facts. Counter
// resets never create negative usage; an observed decrease is treated as a
// reset and contributes zero until the next observation.
func AggregateFacts(facts []Fact, width time.Duration) ([]Aggregate, error) {
	if width <= 0 {
		return nil, ErrInvalidFact
	}
	seen := map[string]Fact{}
	for _, f := range facts {
		if err := f.Validate(); err != nil {
			return nil, err
		}
		if old, ok := seen[f.SourceID]; ok {
			if old != f {
				return nil, fmt.Errorf("%w: %s", ErrConflict, f.SourceID)
			}
			continue
		}
		seen[f.SourceID] = f
	}
	type key struct {
		app, env, dep, rel, svc string
		bucket                  time.Time
	}
	groups := map[key][]Fact{}
	for _, f := range seen {
		k := key{f.ApplicationID, f.EnvironmentID, f.DeploymentID, f.ReleaseID, f.ServiceName, f.ObservedAt.UTC().Truncate(width)}
		groups[k] = append(groups[k], f)
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
	out := make([]Aggregate, 0, len(keys))
	for _, k := range keys {
		fs := groups[k]
		sort.Slice(fs, func(i, j int) bool { return fs[i].ObservedAt.Before(fs[j].ObservedAt) })
		a := Aggregate{ApplicationID: k.app, EnvironmentID: k.env, DeploymentID: k.dep, ReleaseID: k.rel, ServiceName: k.svc, WindowStart: k.bucket, WindowEnd: k.bucket.Add(width), SampleCount: len(fs)}
		for i, f := range fs {
			a.AverageCPUMillicores += float64(f.CPUMillicores)
			a.AverageMemoryBytes += float64(f.MemoryBytes)
			a.AverageDiskBytes += float64(f.DiskBytes)
			a.CPUSeconds += f.CPUSeconds
			a.MemoryByteSeconds += f.MemoryByteSeconds
			a.PeakCPUMillicores = max(a.PeakCPUMillicores, f.CPUMillicores)
			a.PeakMemoryBytes = max(a.PeakMemoryBytes, f.MemoryBytes)
			a.PeakDiskBytes = max(a.PeakDiskBytes, f.DiskBytes)
			a.LimitCPUMillicores = max(a.LimitCPUMillicores, f.LimitCPUMillicores)
			a.LimitMemoryBytes = max(a.LimitMemoryBytes, f.LimitMemoryBytes)
			a.LimitDiskBytes = max(a.LimitDiskBytes, f.LimitDiskBytes)
			a.LimitPIDs = max(a.LimitPIDs, f.LimitPIDs)
			if f.RuntimeSeconds > a.RuntimeSeconds {
				a.RuntimeSeconds = f.RuntimeSeconds
			}
			a.RestartCount += f.RestartCount
			a.ExceptionCount += f.ExceptionCount
			if i+1 < len(fs) {
				seconds := fs[i+1].ObservedAt.Sub(f.ObservedAt).Seconds()
				a.DiskByteSeconds += float64(f.DiskBytes) * seconds
				if f.CPUSeconds == 0 && fs[i+1].CPUSeconds == 0 {
					a.CPUSeconds += float64(f.CPUMillicores) * seconds / 1000
				}
				if f.MemoryByteSeconds == 0 && fs[i+1].MemoryByteSeconds == 0 {
					a.MemoryByteSeconds += float64(f.MemoryBytes) * seconds
				}
				if d := fs[i+1].NetworkRxBytes - f.NetworkRxBytes; d > 0 {
					a.NetworkRxBytes += d
				}
				if d := fs[i+1].NetworkTxBytes - f.NetworkTxBytes; d > 0 {
					a.NetworkTxBytes += d
				}
			}
		}
		count := float64(len(fs))
		a.AverageCPUMillicores /= count
		a.AverageMemoryBytes /= count
		a.AverageDiskBytes /= count
		duration := fs[len(fs)-1].ObservedAt.Sub(fs[0].ObservedAt).Seconds()
		if duration > 0 {
			a.TrendCPUMillicoresPerSecond = float64(fs[len(fs)-1].CPUMillicores-fs[0].CPUMillicores) / duration
			a.TrendMemoryBytesPerSecond = float64(fs[len(fs)-1].MemoryBytes-fs[0].MemoryBytes) / duration
			a.TrendDiskBytesPerSecond = float64(fs[len(fs)-1].DiskBytes-fs[0].DiskBytes) / duration
		}
		out = append(out, a)
	}
	return out, nil
}
func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

type Aggregate struct {
	ApplicationID, EnvironmentID, DeploymentID, ReleaseID, ServiceName                                              string
	WindowStart, WindowEnd                                                                                          time.Time
	SampleCount                                                                                                     int
	CPUSeconds, MemoryByteSeconds, DiskByteSeconds, RuntimeSeconds                                                  float64
	AverageCPUMillicores, AverageMemoryBytes, AverageDiskBytes                                                      float64
	TrendCPUMillicoresPerSecond, TrendMemoryBytesPerSecond, TrendDiskBytesPerSecond                                 float64
	NetworkRxBytes, NetworkTxBytes, RestartCount, ExceptionCount, PeakCPUMillicores, PeakMemoryBytes, PeakDiskBytes int64
	LimitCPUMillicores, LimitMemoryBytes, LimitDiskBytes, LimitPIDs                                                 int64
}

func (a Aggregate) Validate() error {
	if a.SampleCount <= 0 || !a.WindowStart.Before(a.WindowEnd) || math.IsNaN(a.CPUSeconds) || math.IsInf(a.CPUSeconds, 0) || math.IsNaN(a.MemoryByteSeconds) || math.IsInf(a.MemoryByteSeconds, 0) || math.IsNaN(a.AverageCPUMillicores) || math.IsInf(a.AverageCPUMillicores, 0) || math.IsNaN(a.AverageMemoryBytes) || math.IsInf(a.AverageMemoryBytes, 0) || math.IsNaN(a.AverageDiskBytes) || math.IsInf(a.AverageDiskBytes, 0) || math.IsNaN(a.TrendCPUMillicoresPerSecond) || math.IsInf(a.TrendCPUMillicoresPerSecond, 0) || math.IsNaN(a.TrendMemoryBytesPerSecond) || math.IsInf(a.TrendMemoryBytesPerSecond, 0) || math.IsNaN(a.TrendDiskBytesPerSecond) || math.IsInf(a.TrendDiskBytesPerSecond, 0) || a.CPUSeconds < 0 || a.MemoryByteSeconds < 0 || a.AverageCPUMillicores < 0 || a.AverageMemoryBytes < 0 || a.AverageDiskBytes < 0 {
		return ErrInvalidFact
	}
	return nil
}

type StorageState struct{ TotalBytes, UsedBytes, HardWatermarkBytes int64 }

func (s StorageState) AllowsWrite() error {
	if s.TotalBytes <= 0 || s.UsedBytes < 0 || s.UsedBytes > s.TotalBytes || s.HardWatermarkBytes < 0 {
		return ErrWatermark
	}
	if s.HardWatermarkBytes > 0 && s.TotalBytes-s.UsedBytes <= s.HardWatermarkBytes {
		return ErrWatermark
	}
	return nil
}

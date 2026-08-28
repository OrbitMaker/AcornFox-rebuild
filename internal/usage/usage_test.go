package usage

import (
	"errors"
	"testing"
	"time"
)

func TestAggregateFactsLateAndCounterReset(t *testing.T) {
	b := time.Unix(0, 0).UTC()
	fs := []Fact{{SourceID: "b", ApplicationID: "app", ServiceName: "web", ObservedAt: b.Add(time.Minute), CPUMillicores: 1000, MemoryBytes: 10, NetworkRxBytes: 20}, {SourceID: "a", ApplicationID: "app", ServiceName: "web", ObservedAt: b, CPUMillicores: 1000, MemoryBytes: 10, NetworkRxBytes: 10}, {SourceID: "c", ApplicationID: "app", ServiceName: "web", ObservedAt: b.Add(2 * time.Minute), CPUMillicores: 1000, MemoryBytes: 10, NetworkRxBytes: 5}}
	got, err := AggregateFacts(fs, 5*time.Minute)
	if err != nil || len(got) != 1 || got[0].CPUSeconds != 120 || got[0].MemoryByteSeconds != 1200 || got[0].AverageCPUMillicores != 1000 || got[0].AverageMemoryBytes != 10 || got[0].AverageDiskBytes != 0 || got[0].NetworkRxBytes != 10 {
		t.Fatalf("aggregate=%+v err=%v", got, err)
	}
	changed := fs[0]
	changed.MemoryBytes++
	if _, err := AggregateFacts(append(fs, changed), 5*time.Minute); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict=%v", err)
	}
}
func TestStorageStateFailsClosed(t *testing.T) {
	if err := (StorageState{}).AllowsWrite(); !errors.Is(err, ErrWatermark) {
		t.Fatal(err)
	}
	if err := (StorageState{TotalBytes: 100, UsedBytes: 90, HardWatermarkBytes: 10}).AllowsWrite(); !errors.Is(err, ErrWatermark) {
		t.Fatal(err)
	}
}

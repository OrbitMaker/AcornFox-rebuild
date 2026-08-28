package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/open-card/open-card/internal/contracts"
)

type m4DockerMetricsFixture struct {
	metrics DockerRuntimeMetrics
	err     error
	called  string
}

func (f *m4DockerMetricsFixture) ReadContainerMetrics(_ context.Context, container string) (DockerRuntimeMetrics, error) {
	f.called = container
	return f.metrics, f.err
}

func TestM4GroupRuntimeMetricsAdapterMapsOnlyIndependentSafeFacts(t *testing.T) {
	limits := contracts.ResourceLimits{CPUMillis: 250, MemoryBytes: 256 << 20, PIDs: 64}
	reader := &m4DockerMetricsFixture{metrics: DockerRuntimeMetrics{ContainerID: strings.Repeat("a", 64), Status: "running", Healthy: true, RestartCount: 3, CPUUsageRateKnown: true, CPUUsageRatePercent: 12.5, MemoryUsageBytes: 128 << 20, WritableLayerBytes: 4096, NetworkRxBytes: 44, NetworkTxBytes: 55, PIDsCurrent: 7, CgroupVerified: true, AppliedLimits: limits, ExitReason: "", ObservedAt: time.Unix(1_700_000_000, 0).UTC()}}
	adapter := m4GroupRuntimeMetricsAdapter{reader: reader}
	metrics, err := adapter.ReadGroupRuntimeMetrics(context.Background(), "opencard-mvp-fa8f8eab-dep-api")
	if err != nil || reader.called != "opencard-mvp-fa8f8eab-dep-api" {
		t.Fatalf("metrics adapter did not preserve owned-container read: metrics=%#v err=%v called=%q", metrics, err, reader.called)
	}
	if metrics.ContainerID != strings.Repeat("a", 64) || metrics.CPUMillicores != 125 || metrics.MemoryBytes != 128<<20 || metrics.DiskBytes != 4096 || metrics.NetworkRxBytes != 44 || metrics.NetworkTxBytes != 55 || metrics.RestartCount != 3 || metrics.PIDsCurrent != 7 || !metrics.CgroupVerified || metrics.Limits != limits || !metrics.ObservedAt.Equal(reader.metrics.ObservedAt) {
		t.Fatalf("metrics adapter mapping=%#v", metrics)
	}
}

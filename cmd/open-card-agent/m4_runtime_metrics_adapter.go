package main

import (
	"context"
	"math"

	"github.com/open-card/open-card/internal/providers/standalonegroup"
)

// m4GroupRuntimeMetricsAdapter is the only bridge from the Agent's read-only
// Docker socket client into the ServiceGroup provider. The provider has
// already derived `container` from immutable task-owned state before calling
// this method, so no browser/Agent task input can select an arbitrary Docker
// object.
type m4GroupRuntimeMetricsAdapter struct{ reader DockerRuntimeMetricsReader }

func (a m4GroupRuntimeMetricsAdapter) ReadGroupRuntimeMetrics(ctx context.Context, container string) (standalonegroup.RuntimeMetrics, error) {
	metrics, err := a.reader.ReadContainerMetrics(ctx, container)
	if err != nil {
		return standalonegroup.RuntimeMetrics{}, err
	}
	millicores := int64(0)
	if metrics.CPUUsageRateKnown {
		// Docker reports percent across online CPUs; 100 percent equals one
		// CPU, so each percentage point is ten millicores. Bound conversion
		// before casting rather than propagating a malformed daemon value.
		value := math.Round(metrics.CPUUsageRatePercent * 10)
		if value >= 0 && value <= math.MaxInt64 {
			millicores = int64(value)
		}
	}
	changedPaths := int64(0)
	if metrics.ChangedPathCount != nil {
		changedPaths = int64(*metrics.ChangedPathCount)
	}
	return standalonegroup.RuntimeMetrics{ContainerID: metrics.ContainerID, Status: metrics.Status, Healthy: metrics.Healthy, RestartCount: metrics.RestartCount, CPUMillicores: millicores, MemoryBytes: nonNegativeM4Metric(metrics.MemoryUsageBytes), DiskBytes: metrics.WritableLayerBytes, NetworkRxBytes: nonNegativeM4Metric(metrics.NetworkRxBytes), NetworkTxBytes: nonNegativeM4Metric(metrics.NetworkTxBytes), PIDsCurrent: nonNegativeM4Metric(metrics.PIDsCurrent), ChangedPaths: changedPaths, CgroupVerified: metrics.CgroupVerified, Limits: metrics.AppliedLimits, ExitReason: metrics.ExitReason, ObservedAt: metrics.ObservedAt}, nil
}

func nonNegativeM4Metric(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}

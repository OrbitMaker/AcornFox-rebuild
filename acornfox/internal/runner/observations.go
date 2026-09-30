package runner

import (
	"context"
	"fmt"
	"strings"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// managedContainer pins subsequent operations to the inspected ID, rather than
// a name which another Docker client could replace between inspect and use.
func (d *Docker) managedContainer(ctx context.Context, app, name string) (container.InspectResponse, error) {
	if !ValidApp(app) || !strings.HasPrefix(name, VolumePrefix(app)) ||
		!validContainerSuffix(strings.TrimPrefix(name, VolumePrefix(app))) {
		return container.InspectResponse{}, refusedContainer(name, app)
	}
	res, err := d.cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return container.InspectResponse{}, ErrNotFound
		}
		return container.InspectResponse{}, err
	}
	if err := checkContainerOwner(res.Container, app, name); err != nil {
		return container.InspectResponse{}, err
	}
	return res.Container, nil
}

func checkContainerOwner(c container.InspectResponse, app, name string) error {
	if c.ID == "" || strings.TrimPrefix(c.Name, "/") != name || c.Config == nil ||
		c.Config.Labels[LabelManaged] != "1" || c.Config.Labels[LabelApp] != app {
		return refusedContainer(name, app)
	}
	return nil
}

func refusedContainer(name, app string) error {
	return &RemoteError{Status: 403, ErrorResponse: ErrorResponse{
		Code: "refused", Message: fmt.Sprintf("container %q is not managed for app %q", name, app),
	}}
}

// containerStatsView uses deltas only when counters have advanced. Reset or
// missing counters are reported unavailable, not a made-up zero CPU sample.
func containerStatsView(v container.StatsResponse) StatsResponse {
	resp := StatsResponse{}
	cur, prev := v.CPUStats, v.PreCPUStats
	if cur.CPUUsage.TotalUsage >= prev.CPUUsage.TotalUsage && cur.SystemUsage > prev.SystemUsage && prev.SystemUsage > 0 {
		cpus := cur.OnlineCPUs
		if cpus == 0 {
			cpus = uint32(len(cur.CPUUsage.PercpuUsage))
		}
		if cpus > 0 {
			resp.CPUAvailable = true
			resp.CPUPercent = float64(cur.CPUUsage.TotalUsage-prev.CPUUsage.TotalUsage) / float64(cur.SystemUsage-prev.SystemUsage) * float64(cpus) * 100
		}
	}
	usage := v.MemoryStats.Usage
	// Match Docker's working-set presentation without underflow on cgroup v1/v2.
	cache := v.MemoryStats.Stats["inactive_file"]
	if old, ok := v.MemoryStats.Stats["total_inactive_file"]; ok {
		cache = old
	}
	if cache < usage {
		usage -= cache
	}
	resp.MemoryUsageMB = float64(usage) / (1024 * 1024)
	resp.MemoryLimitMB = float64(v.MemoryStats.Limit) / (1024 * 1024)
	for _, n := range v.Networks {
		resp.NetworkRxMB += float64(n.RxBytes) / (1024 * 1024)
		resp.NetworkTxMB += float64(n.TxBytes) / (1024 * 1024)
	}
	resp.PIDs = v.PidsStats.Current
	return resp
}

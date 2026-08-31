package healthcheck

import (
	"context"
	"errors"
	"io"
	"math/bits"
	"net/http"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/install"
)

const (
	localProbeTimeout = time.Second
	maxProbeBodyBytes = 4 << 10

	controlAPIHealthURL = "http://127.0.0.1:8080/healthz"
	controlAPIReadyURL  = "http://127.0.0.1:8080/readyz"
	edgeHealthURL       = "http://127.0.0.1:18482/healthz"
	openCardDataRoot    = "/var/lib/open-card"
)

var errLocalProbeFailed = errors.New("local host probe failed")

// ServiceSnapshotSource is the narrow, task-testable systemd boundary. A
// production collector may pass an install.UpgradeServiceAdapter, whose
// exported Capture method returns the fixed five-unit snapshot.
type ServiceSnapshotSource interface {
	Capture(context.Context) (install.ServiceSnapshotV1, error)
}

// FilesystemUsage is the minimum statfs evidence needed by the disk and inode
// checks. Values describe capacities and free counts, never paths or command
// output, so test seams cannot feed sensitive text into a HostFact.
type FilesystemUsage struct {
	Blocks     uint64
	FreeBlocks uint64
	Files      uint64
	FreeFiles  uint64
}

// StatFS is an injected filesystem-stat boundary. Probes always request the
// fixed Open Card data root; callers cannot choose a production probe path.
type StatFS func(context.Context, string) (FilesystemUsage, error)

// NewTaskLocalProbes returns the five local, credential-free Gate7 probes in
// canonical order. The service source and statfs function are intentionally
// injected so this package neither owns systemd nor depends on cloud access.
func NewTaskLocalProbes(source ServiceSnapshotSource, client *http.Client, statfs StatFS) ([]HostProbe, error) {
	if source == nil || client == nil || statfs == nil {
		return nil, errLocalProbeFailed
	}
	fiveUnits, err := NewFiveUnitsProbe(source)
	if err != nil {
		return nil, errLocalProbeFailed
	}
	disk, err := NewDiskProbe(statfs)
	if err != nil {
		return nil, errLocalProbeFailed
	}
	inode, err := NewInodeProbe(statfs)
	if err != nil {
		return nil, errLocalProbeFailed
	}
	return []HostProbe{fiveUnits, NewControlAPIProbe(client), NewEdgeProbe(client), disk, inode}, nil
}

// NewFiveUnitsProbe evaluates the exact install snapshot. The production
// boot contract requires every unit, including public Edge, to be active and
// enabled; an inactive Edge is therefore unhealthy rather than a bypass.
func NewFiveUnitsProbe(source ServiceSnapshotSource) (HostProbe, error) {
	if source == nil {
		return HostProbe{}, errLocalProbeFailed
	}
	return HostProbe{Kind: CheckFiveUnits, Check: func(ctx context.Context) (HostFact, error) {
		if ctx == nil || ctx.Err() != nil {
			return HostFact{Subject: "local_systemd_units", Severity: SeverityEmergency}, errLocalProbeFailed
		}
		snapshot, err := source.Capture(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return HostFact{Subject: "local_systemd_units", Severity: SeverityEmergency}, errLocalProbeFailed
			}
			return HostFact{Subject: "local_systemd_units", Severity: SeverityEmergency}, nil
		}
		if snapshot.Edge.Active && snapshot.Edge.Enabled &&
			snapshot.Agent.Active && snapshot.Agent.Enabled &&
			snapshot.Server.Active && snapshot.Server.Enabled &&
			snapshot.Caddy.Active && snapshot.Caddy.Enabled &&
			snapshot.BuildKit.Active && snapshot.BuildKit.Enabled {
			return HostFact{Subject: "local_systemd_units", Severity: SeverityOK}, nil
		}
		return HostFact{Subject: "local_systemd_units", Severity: SeverityEmergency}, nil
	}}, nil
}

// NewControlAPIProbe probes exactly the private health and readiness endpoints
// in that order. It never accepts a caller-supplied target URL.
func NewControlAPIProbe(client *http.Client) HostProbe {
	return HostProbe{Kind: CheckControlAPI, Check: func(ctx context.Context) (HostFact, error) {
		return probeHTTP(ctx, client, "loopback_control_api", controlAPIHealthURL, controlAPIReadyURL)
	}}
}

// NewEdgeProbe probes only the fixed loopback Edge health endpoint.
func NewEdgeProbe(client *http.Client) HostProbe {
	return HostProbe{Kind: CheckEdge, Check: func(ctx context.Context) (HostFact, error) {
		return probeHTTP(ctx, client, "loopback_edge", edgeHealthURL)
	}}
}

// NewDiskProbe checks capacity at the fixed Open Card data root.
func NewDiskProbe(statfs StatFS) (HostProbe, error) {
	if statfs == nil {
		return HostProbe{}, errLocalProbeFailed
	}
	return HostProbe{Kind: CheckDisk, Check: func(ctx context.Context) (HostFact, error) {
		usage, err := filesystemUsage(ctx, statfs)
		if err != nil {
			if ctx == nil || ctx.Err() != nil {
				return HostFact{Subject: "open_card_data_disk", Severity: SeverityEmergency}, errLocalProbeFailed
			}
			return HostFact{Subject: "open_card_data_disk", Severity: SeverityEmergency}, nil
		}
		percent, ok := usedPercent(usage.Blocks, usage.FreeBlocks)
		if !ok {
			return HostFact{Subject: "open_card_data_disk", Severity: SeverityEmergency}, nil
		}
		return HostFact{Subject: "open_card_data_disk", Severity: DiskSeverity(percent)}, nil
	}}, nil
}

// NewInodeProbe checks inode capacity at the fixed Open Card data root.
func NewInodeProbe(statfs StatFS) (HostProbe, error) {
	if statfs == nil {
		return HostProbe{}, errLocalProbeFailed
	}
	return HostProbe{Kind: CheckInode, Check: func(ctx context.Context) (HostFact, error) {
		usage, err := filesystemUsage(ctx, statfs)
		if err != nil {
			if ctx == nil || ctx.Err() != nil {
				return HostFact{Subject: "open_card_data_inode", Severity: SeverityEmergency}, errLocalProbeFailed
			}
			return HostFact{Subject: "open_card_data_inode", Severity: SeverityEmergency}, nil
		}
		percent, ok := usedPercent(usage.Files, usage.FreeFiles)
		if !ok {
			return HostFact{Subject: "open_card_data_inode", Severity: SeverityEmergency}, nil
		}
		return HostFact{Subject: "open_card_data_inode", Severity: InodeSeverity(percent)}, nil
	}}, nil
}

func probeHTTP(ctx context.Context, client *http.Client, subject string, targets ...string) (HostFact, error) {
	if ctx == nil || ctx.Err() != nil {
		return HostFact{Subject: subject, Severity: SeverityEmergency}, errLocalProbeFailed
	}
	client = boundedHTTPClient(client)
	for _, target := range targets {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return HostFact{Subject: subject, Severity: SeverityEmergency}, errLocalProbeFailed
		}
		response, err := client.Do(request)
		if response != nil && response.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxProbeBodyBytes))
			_ = response.Body.Close()
		}
		if ctx.Err() != nil {
			return HostFact{Subject: subject, Severity: SeverityEmergency}, errLocalProbeFailed
		}
		if err != nil || response == nil || response.StatusCode != http.StatusOK {
			return HostFact{Subject: subject, Severity: SeverityEmergency}, nil
		}
	}
	return HostFact{Subject: subject, Severity: SeverityOK}, nil
}

func boundedHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	if clone.Timeout <= 0 || clone.Timeout > localProbeTimeout {
		clone.Timeout = localProbeTimeout
	}
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return errLocalProbeFailed }
	return &clone
}

func filesystemUsage(ctx context.Context, statfs StatFS) (FilesystemUsage, error) {
	if ctx == nil || ctx.Err() != nil || statfs == nil {
		return FilesystemUsage{}, errLocalProbeFailed
	}
	usage, err := statfs(ctx, openCardDataRoot)
	if err != nil || ctx.Err() != nil {
		return FilesystemUsage{}, errLocalProbeFailed
	}
	return usage, nil
}

func productionStatFS(ctx context.Context, root string) (FilesystemUsage, error) {
	if ctx == nil || ctx.Err() != nil || root != openCardDataRoot {
		return FilesystemUsage{}, errLocalProbeFailed
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(openCardDataRoot, &stat); err != nil {
		return FilesystemUsage{}, errLocalProbeFailed
	}
	return filesystemUsageFromStat(stat), nil
}

func filesystemUsageFromStat(stat syscall.Statfs_t) FilesystemUsage {
	return FilesystemUsage{Blocks: stat.Blocks, FreeBlocks: stat.Bavail, Files: stat.Files, FreeFiles: stat.Ffree}
}

// usedPercent avoids both multiplication overflow and division by zero.
func usedPercent(total, free uint64) (int, bool) {
	if total == 0 || free > total {
		return 0, false
	}
	used := total - free
	hi, lo := bits.Mul64(used, 100)
	percent, _ := bits.Div64(hi, lo, total)
	if percent > 100 {
		return 0, false
	}
	return int(percent), true
}

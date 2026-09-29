package dockermetrics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/contracts"
)

const (
	dockerRuntimeInspectLimit = 2 << 20
	dockerRuntimeStatsLimit   = 4 << 20
	dockerRuntimeChangesLimit = 1 << 20
)

var dockerContainerIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// DockerRuntimeMetrics is the allowlisted runtime fact set collected for one
// task-owned container. It deliberately contains no Docker inspect, command,
// environment, label, mount, network-name, or file-path payload.
//
// CPUUsageMillis is cumulative container CPU time. CPUUsageDeltaMillis and
// CPUUsageRatePercent are derived from Docker's current and previous stats
// samples. CPUUsageRatePercent uses Docker's standard formula:
// cpu_delta / system_delta * online_cpus * 100. SampleIntervalMillis is the
// daemon-provided read minus preread interval; a zero interval means the rate
// is unknown and CPUUsageRateKnown is false.
type DockerRuntimeMetrics struct {
	ContainerID            string                   `json:"container_id"`
	Status                 string                   `json:"status"`
	HealthStatus           string                   `json:"health_status,omitempty"`
	Healthy                bool                     `json:"healthy"`
	ExitCode               int                      `json:"exit_code,omitempty"`
	ExitReason             string                   `json:"exit_reason,omitempty"`
	RestartCount           uint64                   `json:"restart_count"`
	StartedAt              string                   `json:"started_at,omitempty"`
	CPUUsageMillis         uint64                   `json:"cpu_usage_millis"`
	CPUUsageAvailable      bool                     `json:"cpu_usage_available"`
	CPUUsageDeltaMillis    uint64                   `json:"cpu_usage_delta_millis,omitempty"`
	CPUUsageRatePercent    float64                  `json:"cpu_usage_rate_percent,omitempty"`
	CPUUsageRateKnown      bool                     `json:"cpu_usage_rate_known"`
	CPURateWindowStartedAt time.Time                `json:"cpu_rate_window_started_at,omitempty"`
	SampleIntervalMillis   int64                    `json:"sample_interval_millis,omitempty"`
	MemoryUsageBytes       uint64                   `json:"memory_usage_bytes"`
	MemoryUsageAvailable   bool                     `json:"memory_usage_available"`
	MemoryLimitBytes       uint64                   `json:"memory_limit_bytes"`
	MemoryLimitAvailable   bool                     `json:"memory_limit_available"`
	PIDsCurrent            uint64                   `json:"pids_current"`
	PIDsAvailable          bool                     `json:"pids_available"`
	CgroupVerified         bool                     `json:"cgroup_verified"`
	AppliedLimits          contracts.ResourceLimits `json:"applied_limits"`
	WritableLayerBytes     int64                    `json:"writable_layer_bytes,omitempty"`
	WritableLayerSizeKnown bool                     `json:"writable_layer_size_known"`
	NetworkRxBytes         uint64                   `json:"network_rx_bytes"`
	NetworkTxBytes         uint64                   `json:"network_tx_bytes"`
	NetworkAvailable       bool                     `json:"network_available"`
	ChangedPathCount       *int                     `json:"changed_path_count,omitempty"`
	ObservedAt             time.Time                `json:"observed_at"`
}

// DockerRuntimeMetricsReader is the narrow read-only boundary used by an
// Agent runtime adapter. The caller must obtain containerID from the
// task-owned runtime provider; it must never be copied from user input.
type DockerRuntimeMetricsReader interface {
	ReadContainerMetrics(context.Context, string) (DockerRuntimeMetrics, error)
}

// UnixDockerRuntimeMetricsReader uses only the Docker Engine GET endpoints
// needed for an independent runtime observation. The socket path is process
// configuration and is never included in a result or error returned to the
// control plane.
type UnixDockerRuntimeMetricsReader struct {
	options    ReadOptions
	client     *http.Client
	procRoot   string
	cgroupRoot string
}

// ReadOptions keeps legacy collection by default. Native can omit the optional
// writable-layer and change-list reads without representing absence as zero.
type ReadOptions struct {
	OmitChanges           bool
	OmitWritableLayerSize bool
	AllowPartialUsage     bool
}

// NewUnixDockerRuntimeMetricsReader constructs a reader for a configured Unix
// socket. It does not contact Docker and cannot perform a mutating request.
func NewUnixDockerRuntimeMetricsReader(socketPath string, options ...ReadOptions) (*UnixDockerRuntimeMetricsReader, error) {
	if len(options) > 1 {
		return nil, errors.New("at most one docker metrics read options value is allowed")
	}
	selected := ReadOptions{}
	if len(options) == 1 {
		selected = options[0]
	}
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" || !strings.HasPrefix(socketPath, "/") {
		return nil, errors.New("docker socket path must be absolute")
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true,
	}
	return &UnixDockerRuntimeMetricsReader{options: selected, client: &http.Client{
		Transport:     transport,
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, procRoot: "/proc", cgroupRoot: "/sys/fs/cgroup"}, nil
}

// ValidateDockerContainerIdentifier accepts only a single Docker name or
// identifier path segment. Ownership is established by the runtime provider;
// this second check prevents path traversal, query injection, control bytes,
// and accidental requests for a Docker API endpoint outside the task object.
func ValidateDockerContainerIdentifier(containerID string) error {
	if !dockerContainerIdentifierPattern.MatchString(containerID) || strings.Contains(containerID, "..") {
		return errors.New("docker container identifier is not safe")
	}
	return nil
}

// ReadContainerMetrics reads inspect and one non-streaming stats sample. The
// legacy default also reads changes and writable-layer size. Paths are always
// discarded; omitted facts stay absent rather than becoming observed zeros.
func (r *UnixDockerRuntimeMetricsReader) ReadContainerMetrics(ctx context.Context, containerID string) (DockerRuntimeMetrics, error) {
	if r == nil || r.client == nil {
		return DockerRuntimeMetrics{}, errors.New("docker runtime metrics reader is not initialized")
	}
	if err := ValidateDockerContainerIdentifier(containerID); err != nil {
		return DockerRuntimeMetrics{}, err
	}

	inspectSuffix := "/json?size=1"
	if r.options.OmitWritableLayerSize {
		inspectSuffix = "/json"
	}
	var inspect dockerRuntimeInspectResponse
	if err := r.getJSON(ctx, "inspect", dockerRuntimeContainerPath(containerID, inspectSuffix), dockerRuntimeInspectLimit, '{', &inspect); err != nil {
		return DockerRuntimeMetrics{}, err
	}
	if inspect.State == nil {
		return DockerRuntimeMetrics{}, errors.New("docker inspect response missing runtime state")
	}

	var stats dockerRuntimeStatsResponse
	if err := r.getJSON(ctx, "stats", dockerRuntimeContainerPath(containerID, "/stats?stream=false"), dockerRuntimeStatsLimit, '{', &stats); err != nil {
		return DockerRuntimeMetrics{}, err
	}
	if !r.options.AllowPartialUsage && (stats.CPUStats == nil || stats.MemoryStats == nil) {
		return DockerRuntimeMetrics{}, errors.New("docker stats response missing allowlisted usage facts")
	}

	var changedCount *int
	if !r.options.OmitChanges {
		var changes []dockerRuntimeChange
		if err := r.getJSON(ctx, "changes", dockerRuntimeContainerPath(containerID, "/changes"), dockerRuntimeChangesLimit, '[', &changes); err != nil {
			return DockerRuntimeMetrics{}, err
		}
		count := len(changes)
		changedCount = &count
	}

	metrics := DockerRuntimeMetrics{
		ContainerID:          inspect.ID,
		Status:               normalizeDockerStatus(inspect.State.Status),
		HealthStatus:         normalizeDockerHealth(inspect.State.Health),
		ExitCode:             inspect.State.ExitCode,
		RestartCount:         inspect.RestartCount,
		StartedAt:            inspect.State.StartedAt,
		MemoryUsageAvailable: stats.MemoryStats != nil && stats.MemoryStats.Usage != nil,
		MemoryLimitAvailable: stats.MemoryStats != nil && stats.MemoryStats.Limit != nil,
		ChangedPathCount:     changedCount,
		ObservedAt:           time.Now().UTC(),
	}
	if err := ValidateDockerContainerIdentifier(metrics.ContainerID); err != nil {
		return DockerRuntimeMetrics{}, errors.New("docker inspect returned an invalid container identity")
	}
	metrics.AppliedLimits = inspect.appliedLimits()
	if stats.MemoryStats != nil && stats.MemoryStats.Usage != nil {
		metrics.MemoryUsageBytes = *stats.MemoryStats.Usage
	}
	if stats.MemoryStats != nil && stats.MemoryStats.Limit != nil {
		metrics.MemoryLimitBytes = *stats.MemoryStats.Limit
	}
	if stats.PIDsStats != nil && stats.PIDsStats.Current != nil {
		metrics.PIDsCurrent = *stats.PIDsStats.Current
		metrics.PIDsAvailable = true
	}
	if inspect.State.PID > 0 {
		facts, err := readDockerCgroupFacts(inspect.State.PID, r.procRoot, r.cgroupRoot)
		if err != nil {
			return DockerRuntimeMetrics{}, err
		}
		metrics.CgroupVerified = true
		metrics.PIDsCurrent = facts.PIDsCurrent
		metrics.PIDsAvailable = true
		metrics.AppliedLimits = facts.Limits
		if inspect.appliedLimits() != metrics.AppliedLimits {
			return DockerRuntimeMetrics{}, errors.New("docker inspect and cgroup resource limits differ")
		}
	}
	metrics.Healthy = metrics.HealthStatus == "healthy"
	metrics.ExitReason = dockerExitReason(metrics.Status, inspect.State.ExitCode, inspect.State.Error)
	if !r.options.OmitWritableLayerSize && inspect.SizeRw != nil && *inspect.SizeRw >= 0 {
		metrics.WritableLayerBytes = *inspect.SizeRw
		metrics.WritableLayerSizeKnown = true
	}

	if rx, tx, available, err := dockerNetworkTotals(stats.Networks); err != nil {
		return DockerRuntimeMetrics{}, err
	} else {
		metrics.NetworkRxBytes, metrics.NetworkTxBytes = rx, tx
		metrics.NetworkAvailable = available
	}
	if stats.CPUStats != nil {
		if err := metrics.applyCPU(stats); err != nil {
			return DockerRuntimeMetrics{}, err
		}
	}
	return metrics, nil
}

// Read is a short alias useful when this reader is injected behind a local
// Agent adapter. It has the same read-only and ownership preconditions.
func (r *UnixDockerRuntimeMetricsReader) Read(ctx context.Context, containerID string) (DockerRuntimeMetrics, error) {
	return r.ReadContainerMetrics(ctx, containerID)
}

func dockerRuntimeContainerPath(containerID, suffix string) string {
	return "/containers/" + url.PathEscape(containerID) + suffix
}

func (r *UnixDockerRuntimeMetricsReader) getJSON(ctx context.Context, operation, path string, limit int64, expectedFirst byte, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return fmt.Errorf("docker runtime metrics %s request could not be created", operation)
	}
	response, err := r.client.Do(request)
	if err != nil {
		// Do not wrap the transport error: a Unix dial error can contain the
		// configured socket path, which is process-local configuration.
		return fmt.Errorf("docker runtime metrics %s request failed", operation)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("docker runtime metrics %s returned status %d", operation, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return fmt.Errorf("docker runtime metrics %s response exceeded the safety limit", operation)
	}
	trimmed := bytes.TrimSpace(body)
	// Docker returns JSON null rather than [] when a container has no writable
	// layer changes. Treat that documented empty value as an empty allowlisted
	// collection; no path or other raw response data crosses this boundary.
	if operation == "changes" && expectedFirst == '[' && bytes.Equal(trimmed, []byte("null")) {
		trimmed = []byte("[]")
	}
	if len(trimmed) == 0 || trimmed[0] != expectedFirst {
		return fmt.Errorf("docker runtime metrics %s response was malformed", operation)
	}
	if err := json.Unmarshal(trimmed, target); err != nil {
		return fmt.Errorf("docker runtime metrics %s response was malformed", operation)
	}
	return nil
}

type dockerRuntimeInspectResponse struct {
	ID           string                     `json:"Id"`
	RestartCount uint64                     `json:"RestartCount"`
	SizeRw       *int64                     `json:"SizeRw"`
	State        *dockerRuntimeInspectState `json:"State"`
	HostConfig   dockerRuntimeHostConfig    `json:"HostConfig"`
}

type dockerRuntimeInspectState struct {
	Status    string               `json:"Status"`
	Running   bool                 `json:"Running"`
	StartedAt string               `json:"StartedAt"`
	ExitCode  int                  `json:"ExitCode"`
	Error     string               `json:"Error"`
	PID       int                  `json:"Pid"`
	Health    *dockerRuntimeHealth `json:"Health"`
}

type dockerRuntimeHostConfig struct {
	Memory    int64  `json:"Memory"`
	CPUPeriod int64  `json:"CpuPeriod"`
	CPUQuota  int64  `json:"CpuQuota"`
	PIDsLimit *int64 `json:"PidsLimit"`
}

type dockerRuntimeHealth struct {
	Status string `json:"Status"`
}

type dockerRuntimeStatsResponse struct {
	Read        string                          `json:"read"`
	PreRead     string                          `json:"preread"`
	CPUStats    *dockerRuntimeCPUStats          `json:"cpu_stats"`
	PreCPUStats *dockerRuntimeCPUStats          `json:"precpu_stats"`
	MemoryStats *dockerRuntimeMemoryStats       `json:"memory_stats"`
	Networks    map[string]dockerRuntimeNetwork `json:"networks"`
	PIDsStats   *dockerRuntimePIDsStats         `json:"pids_stats"`
}

type dockerRuntimePIDsStats struct {
	Current *uint64 `json:"current"`
}

type dockerRuntimeCPUStats struct {
	CPUUsage       dockerRuntimeCPUUsage `json:"cpu_usage"`
	SystemCPUUsage uint64                `json:"system_cpu_usage"`
	OnlineCPUs     uint64                `json:"online_cpus"`
}

type dockerRuntimeCPUUsage struct {
	TotalUsage *uint64 `json:"total_usage"`
}

type dockerRuntimeMemoryStats struct {
	Usage *uint64 `json:"usage"`
	Limit *uint64 `json:"limit"`
}

type dockerRuntimeNetwork struct {
	RxBytes *uint64 `json:"rx_bytes"`
	TxBytes *uint64 `json:"tx_bytes"`
}

// When the legacy changes read is requested, Path is intentionally not
// decoded. Paths can contain secrets and are never returned as metrics.
type dockerRuntimeChange struct {
	Kind int `json:"Kind"`
}

type dockerCgroupFacts struct {
	Limits      contracts.ResourceLimits
	PIDsCurrent uint64
}

func (v dockerRuntimeInspectResponse) appliedLimits() contracts.ResourceLimits {
	pids := int64(0)
	if v.HostConfig.PIDsLimit != nil && *v.HostConfig.PIDsLimit > 0 {
		pids = *v.HostConfig.PIDsLimit
	}
	cpu := int64(0)
	if v.HostConfig.CPUQuota > 0 && v.HostConfig.CPUPeriod > 0 {
		cpu = v.HostConfig.CPUQuota * 1000 / v.HostConfig.CPUPeriod
	}
	return contracts.ResourceLimits{CPUMillis: cpu, MemoryBytes: v.HostConfig.Memory, PIDs: pids}
}

// readDockerCgroupFacts resolves a running container's cgroup only from its
// inspect PID. It returns numeric limits and process count, never the cgroup
// path itself. This keeps host paths out of Agent observations while proving
// that Docker's inspect limits match the kernel-enforced cgroup.
func readDockerCgroupFacts(pid int, procRoot, cgroupRoot string) (dockerCgroupFacts, error) {
	if pid <= 0 || strings.TrimSpace(procRoot) == "" || strings.TrimSpace(cgroupRoot) == "" {
		return dockerCgroupFacts{}, errors.New("docker runtime cgroup identity is unavailable")
	}
	payload, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return dockerCgroupFacts{}, errors.New("docker runtime cgroup identity could not be read")
	}
	var relative string
	for _, line := range strings.Split(string(payload), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" && strings.HasPrefix(parts[2], "/") {
			relative = filepath.Clean(parts[2])
			break
		}
	}
	if relative == "" || relative == "." || relative == "/" {
		return dockerCgroupFacts{}, errors.New("docker runtime cgroup identity is invalid")
	}
	root := filepath.Clean(cgroupRoot)
	directory := filepath.Join(root, strings.TrimPrefix(relative, "/"))
	if !strings.HasPrefix(directory, root+string(os.PathSeparator)) {
		return dockerCgroupFacts{}, errors.New("docker runtime cgroup identity escaped its root")
	}
	cpuBytes, err := os.ReadFile(filepath.Join(directory, "cpu.max"))
	if err != nil {
		return dockerCgroupFacts{}, errors.New("docker runtime cpu cgroup could not be read")
	}
	fields := strings.Fields(string(cpuBytes))
	if len(fields) != 2 || fields[0] == "max" {
		return dockerCgroupFacts{}, errors.New("docker runtime cpu cgroup is unbounded")
	}
	quota, quotaErr := strconv.ParseInt(fields[0], 10, 64)
	period, periodErr := strconv.ParseInt(fields[1], 10, 64)
	if quotaErr != nil || periodErr != nil || quota <= 0 || period <= 0 {
		return dockerCgroupFacts{}, errors.New("docker runtime cpu cgroup is invalid")
	}
	memory, err := readDockerCgroupUint(directory, "memory.max", false)
	if err != nil {
		return dockerCgroupFacts{}, err
	}
	pidsLimit, err := readDockerCgroupUint(directory, "pids.max", false)
	if err != nil {
		return dockerCgroupFacts{}, err
	}
	pidsCurrent, err := readDockerCgroupUint(directory, "pids.current", true)
	if err != nil {
		return dockerCgroupFacts{}, err
	}
	maxInt64 := uint64(^uint64(0) >> 1)
	if memory > maxInt64 || pidsLimit > maxInt64 {
		return dockerCgroupFacts{}, errors.New("docker runtime cgroup limit exceeds the supported range")
	}
	return dockerCgroupFacts{Limits: contracts.ResourceLimits{CPUMillis: quota * 1000 / period, MemoryBytes: int64(memory), PIDs: int64(pidsLimit)}, PIDsCurrent: pidsCurrent}, nil
}

func readDockerCgroupUint(directory, name string, allowZero bool) (uint64, error) {
	payload, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		return 0, errors.New("docker runtime " + name + " cgroup could not be read")
	}
	value := strings.TrimSpace(string(payload))
	if value == "" || value == "max" {
		return 0, errors.New("docker runtime " + name + " cgroup is unbounded")
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || (!allowZero && parsed == 0) {
		return 0, errors.New("docker runtime " + name + " cgroup is invalid")
	}
	return parsed, nil
}

func (m *DockerRuntimeMetrics) applyCPU(stats dockerRuntimeStatsResponse) error {
	if stats.CPUStats.CPUUsage.TotalUsage == nil {
		return nil
	}
	current := *stats.CPUStats.CPUUsage.TotalUsage
	m.CPUUsageAvailable = true
	m.CPUUsageMillis = current / uint64(time.Millisecond)
	if stats.PreCPUStats == nil || stats.PreCPUStats.CPUUsage.TotalUsage == nil || current < *stats.PreCPUStats.CPUUsage.TotalUsage {
		return nil
	}
	previous := *stats.PreCPUStats.CPUUsage.TotalUsage
	delta := current - previous
	m.CPUUsageDeltaMillis = delta / uint64(time.Millisecond)

	readAt, readOK := parseDockerStatsTime(stats.Read)
	preReadAt, preReadOK := parseDockerStatsTime(stats.PreRead)
	if !readOK || !preReadOK || !readAt.After(preReadAt) {
		return nil
	}
	interval := readAt.Sub(preReadAt)
	if interval <= 0 || interval > 24*time.Hour {
		return nil
	}
	sampleMillis := interval.Milliseconds()
	if sampleMillis <= 0 {
		return nil
	}
	m.SampleIntervalMillis = sampleMillis
	m.CPURateWindowStartedAt = preReadAt
	onlineCPUs := stats.CPUStats.OnlineCPUs
	if stats.CPUStats.SystemCPUUsage < stats.PreCPUStats.SystemCPUUsage || onlineCPUs == 0 {
		return nil
	}
	systemDelta := stats.CPUStats.SystemCPUUsage - stats.PreCPUStats.SystemCPUUsage
	if systemDelta == 0 {
		return nil
	}
	m.CPUUsageRatePercent = float64(delta) / float64(systemDelta) * float64(onlineCPUs) * 100
	if m.CPUUsageRatePercent < 0 || m.CPUUsageRatePercent > 100*float64(onlineCPUs) {
		m.CPUUsageRatePercent = 0
		return nil
	}
	m.CPUUsageRateKnown = true
	return nil
}

func parseDockerStatsTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return parsed, err == nil
}

func dockerNetworkTotals(networks map[string]dockerRuntimeNetwork) (uint64, uint64, bool, error) {
	var rx, tx uint64
	available := len(networks) > 0
	for _, network := range networks {
		if network.RxBytes == nil || network.TxBytes == nil {
			available = false
			continue
		}
		if ^uint64(0)-rx < *network.RxBytes || ^uint64(0)-tx < *network.TxBytes {
			return 0, 0, false, errors.New("docker stats network totals overflowed")
		}
		rx += *network.RxBytes
		tx += *network.TxBytes
	}
	return rx, tx, available, nil
}

func normalizeDockerStatus(status string) string {
	switch strings.ToLower(status) {
	case "created", "running", "restarting", "removing", "paused", "exited", "dead":
		return strings.ToLower(status)
	default:
		return "unknown"
	}
}

func normalizeDockerHealth(health *dockerRuntimeHealth) string {
	if health == nil {
		return ""
	}
	switch strings.ToLower(health.Status) {
	case "starting", "healthy", "unhealthy", "none":
		return strings.ToLower(health.Status)
	default:
		return "unknown"
	}
}

func dockerExitReason(status string, exitCode int, runtimeError string) string {
	if status == "running" || status == "restarting" || status == "paused" {
		return ""
	}
	if exitCode != 0 {
		return fmt.Sprintf("exit_code_%d", exitCode)
	}
	if strings.TrimSpace(runtimeError) != "" {
		return "runtime_error"
	}
	if status == "unknown" {
		return "runtime_status_unknown"
	}
	return status
}

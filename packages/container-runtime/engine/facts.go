package engine

import (
	"time"
)

// EngineHealth represents the availability and health status of the Docker Engine.
type EngineHealth struct {
	Available  bool      `json:"available"`
	Message    string    `json:"message,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// EngineInfo represents safe node-level facts gathered from Docker ServerVersion and Info.
// It deliberately omits registry credentials, swarm secrets, plugins, daemon paths, and internal flags.
type EngineInfo struct {
	ServerVersion     string    `json:"server_version"`
	APIVersion        string    `json:"api_version"`
	MinAPIVersion     string    `json:"min_api_version,omitempty"`
	OperatingSystem   string    `json:"operating_system"`
	Architecture      string    `json:"architecture"`
	KernelVersion     string    `json:"kernel_version,omitempty"`
	CPUs              int       `json:"cpus"`
	MemoryBytes       int64     `json:"memory_bytes"`
	Containers        int       `json:"containers"`
	ContainersRunning int       `json:"containers_running"`
	ContainersPaused  int       `json:"containers_paused"`
	ContainersStopped int       `json:"containers_stopped"`
	Images            int       `json:"images"`
	ObservedAt        time.Time `json:"observed_at"`
}

// PortBinding represents a single container-to-host port mapping fact.
type PortBinding struct {
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      int    `json:"host_port,omitempty"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"` // "tcp" or "udp"
}

// MountFact represents an active filesystem mount inside a container.
// It contains only destination, type, volume name, and read-only status.
// Host filesystem paths (Mount.Source) are strictly omitted to prevent host layout leaks.
type MountFact struct {
	Type        string `json:"type"`           // "bind" or "volume"
	Name        string `json:"name,omitempty"` // volume name if volume-backed
	Destination string `json:"destination"`    // container target mount path
	ReadOnly    bool   `json:"read_only"`
}

// ContainerNetworkFact preserves the association between network name, ID, and IP address.
type ContainerNetworkFact struct {
	NetworkName string `json:"network_name"`
	NetworkID   string `json:"network_id,omitempty"`
	IPAddress   string `json:"ip_address,omitempty"`
	Gateway     string `json:"gateway,omitempty"`
	MacAddress  string `json:"mac_address,omitempty"`
}

// ContainerFacts represents the minimal stable fact boundary for an inspected container.
// Strictly excludes environment variables, commands, raw JSON inspect payloads, and host paths.
type ContainerFacts struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ImageID          string                 `json:"image_id"`
	ImageRef         string                 `json:"image_ref,omitempty"`
	Status           string                 `json:"status"` // "running", "exited", "created", "paused", etc.
	Running          bool                   `json:"running"`
	Paused           bool                   `json:"paused"`
	Restarting       bool                   `json:"restarting"`
	HealthStatus     string                 `json:"health_status,omitempty"` // "healthy", "unhealthy", "starting"
	Healthy          bool                   `json:"healthy"`
	ExitCode         int                    `json:"exit_code,omitempty"`
	RestartCount     uint64                 `json:"restart_count"`
	StartedAt        time.Time              `json:"started_at,omitempty"`
	FinishedAt       time.Time              `json:"finished_at,omitempty"`
	CPUMillis        int64                  `json:"cpu_millis"`
	CPULimitKnown    bool                   `json:"cpu_limit_known"`
	CPUUnlimited     bool                   `json:"cpu_unlimited"`
	MemoryLimitBytes int64                  `json:"memory_limit_bytes"`
	MemoryLimitKnown bool                   `json:"memory_limit_known"`
	MemoryUnlimited  bool                   `json:"memory_unlimited"`
	PIDsLimit        int64                  `json:"pids_limit,omitempty"`
	PortBindings     []PortBinding          `json:"port_bindings,omitempty"`
	Mounts           []MountFact            `json:"mounts,omitempty"`
	Networks         []ContainerNetworkFact `json:"networks,omitempty"`
	Labels           map[string]string      `json:"labels,omitempty"` // Filtered by allowlist only
	ObservedAt       time.Time              `json:"observed_at"`
}

// ImageFacts represents the minimal stable fact boundary for an inspected image.
// It excludes layer history, build arguments, author identity, and environment variables.
type ImageFacts struct {
	ID           string    `json:"id"`
	RepoTags     []string  `json:"repo_tags,omitempty"`
	RepoDigests  []string  `json:"repo_digests,omitempty"`
	SizeBytes    int64     `json:"size_bytes"`
	CreatedAt    time.Time `json:"created_at,omitempty"`
	Architecture string    `json:"architecture,omitempty"`
	OS           string    `json:"os,omitempty"`
	ExposedPorts []string  `json:"exposed_ports,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
}

// NetworkFacts represents the minimal stable fact boundary for an inspected network.
type NetworkFacts struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Scope      string            `json:"scope"`
	Internal   bool              `json:"internal"`
	Labels     map[string]string `json:"labels,omitempty"` // Filtered by allowlist only
	Subnet     string            `json:"subnet,omitempty"`
	Gateway    string            `json:"gateway,omitempty"`
	ObservedAt time.Time         `json:"observed_at"`
}

// VolumeFacts represents the minimal stable fact boundary for an inspected volume.
// Mountpoint is strictly omitted to prevent host filesystem path leakage.
type VolumeFacts struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	CreatedAt  time.Time         `json:"created_at,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"` // Filtered by allowlist only
	ObservedAt time.Time         `json:"observed_at"`
}

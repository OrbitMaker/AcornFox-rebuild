// Package runner is the only AcornFox component that talks to Docker.
//
// acornfox runner runs as account acornfox-exec (docker group), keeps no
// state of its own and serves the typed HTTP+JSON API below on a Unix socket
// (internal/peer) that only acornfox server may connect to. Every action is
// idempotent: resources have fixed names derived from app and deployment IDs,
// so repeating a request either does nothing or yields the same result.
//
// The runner refuses anything outside its contract: it only touches Docker
// objects carrying LabelManaged=1, never creates privileged or host-network
// containers, never bind-mounts host paths or the Docker socket, and only
// mounts named volumes whose name starts with "af-<app>-".
package runner

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// Labels on every managed Docker object.
const (
	LabelManaged    = "acornfox.managed"    // always "1"
	LabelApp        = "acornfox.app"        // app name
	LabelDeployment = "acornfox.deployment" // deployment ID (containers and images of app deployments)
	LabelRole       = "acornfox.role"       // RoleApp | RoleAddon
	RoleApp         = "app"
	RoleAddon       = "addon"
)

var (
	appPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,38}[a-z0-9]$`)
	idPattern  = regexp.MustCompile(`^[0-9a-f]{12}$`)
)

// ValidApp and ValidDeploymentID validate the two identifiers every request carries.
func ValidApp(app string) bool         { return appPattern.MatchString(app) }
func ValidDeploymentID(id string) bool { return idPattern.MatchString(id) }

// Fixed resource names. Both sides use these; neither side invents others.
func ContainerName(app, deploymentID string) string {
	return fmt.Sprintf("af-%s-%s", app, deploymentID)
}
func ImageTag(app, deploymentID string) string {
	return fmt.Sprintf("acornfox/%s:%s", app, deploymentID)
}
func NetworkName(app string) string  { return "af-" + app }
func VolumePrefix(app string) string { return "af-" + app + "-" }

// Default container limits (the server passes explicit values).
const (
	DefaultPidsLimit  = 512
	LogMaxSize        = "10m" // json-file log rotation, protects the disk
	LogMaxFiles       = "3"
	MaxLogExcerptLine = 40
)

// Socket paths and HTTP routes. All requests and responses are JSON unless
// noted; errors are returned as ErrorResponse with a non-2xx status.
const (
	PathPing            = "/v1/ping"              // GET  -> PingResponse
	PathBuild           = "/v1/images/build"      // POST BuildRequest -> BuildResponse (long: up to 20 min)
	PathImagePull       = "/v1/images/pull"       // POST PullRequest -> PullResponse (long: up to 10 min)
	PathImageInspect    = "/v1/images/inspect"    // POST ImageRef -> ImageInfo (404 when missing)
	PathImageList       = "/v1/images/list"       // POST AppRef -> ImageListResponse
	PathImageRemove     = "/v1/images/remove"     // POST ImageRef -> OK (missing is success)
	PathContainerEnsure = "/v1/containers/ensure" // POST EnsureContainerRequest -> ContainerInfo
	PathContainerList   = "/v1/containers/list"   // POST AppRef (App "" = all managed) -> ContainerListResponse
	PathContainerStop   = "/v1/containers/stop"   // POST ContainerRef -> OK (missing is success)
	PathContainerStart  = "/v1/containers/start"  // POST ContainerRef -> ContainerInfo
	PathContainerRemove = "/v1/containers/remove" // POST ContainerRef -> OK (missing is success)
	PathContainerLogs   = "/v1/containers/logs"   // POST LogsRequest -> LogsResponse
	PathContainerDiff   = "/v1/containers/diff"   // POST ContainerRef -> DiffResponse
	PathVolumeEnsure    = "/v1/volumes/ensure"    // POST VolumeRef -> OK
	PathVolumeList      = "/v1/volumes/list"      // POST AppRef -> VolumeListResponse
)

type ErrorResponse struct {
	Code    string `json:"code"` // invalid_request | not_found | refused | docker_error | build_failed
	Message string `json:"message"`
}

type OK struct {
	OK bool `json:"ok"`
}

type PingResponse struct {
	DockerAPIVersion string `json:"docker_api_version"`
	ServerVersion    string `json:"server_version"`
}

type AppRef struct {
	App string `json:"app"`
}

type ImageRef struct {
	App string `json:"app"`
	Ref string `json:"ref"` // must be an acornfox/<app>:<id> tag or an image ID of an image labeled for App
}

type ContainerRef struct {
	App  string `json:"app"`
	Name string `json:"name"` // must start with "af-<app>-"
}

type VolumeRef struct {
	App  string `json:"app"`
	Name string `json:"name"` // must start with VolumePrefix(app)
}

// BuildRequest builds ImageTag(App, DeploymentID) from a tar or tar.gz file
// on disk. If an image with that tag already exists it returns it without
// building. Concurrent identical requests share one build.
type BuildRequest struct {
	App          string `json:"app"`
	DeploymentID string `json:"deployment_id"`
	ContextPath  string `json:"context_path"` // absolute path of the upload file, readable by the runner
}

// BuildResponse: OK=false means the build itself failed (user error); the
// runner then returns HTTP 200 with a classified Failure. Transport or Docker
// daemon problems are returned as ErrorResponse instead.
type BuildResponse struct {
	OK      bool       `json:"ok"`
	Image   *ImageInfo `json:"image,omitempty"`
	Failure *Failure   `json:"failure,omitempty"`
}

// Failure mirrors state.Diagnosis without importing it.
type Failure struct {
	Stage      string `json:"stage"`
	Code       string `json:"code"` // upload_invalid | dockerfile_missing | build_failed | dependency_missing | registry_timeout | base_image_not_found | pull_timeout | image_not_found | pull_failed
	Message    string `json:"message"`
	LogExcerpt string `json:"log_excerpt,omitempty"` // <= 40 lines, ANSI and step noise removed
	Hint       string `json:"hint,omitempty"`
}

type ImageInfo struct {
	ID           string   `json:"id"`
	Tags         []string `json:"tags"`
	App          string   `json:"app"`
	DeploymentID string   `json:"deployment_id"`
	ExposedPorts []int    `json:"exposed_ports"` // TCP only, ascending
	Volumes      []string `json:"volumes"`       // VOLUME paths from the image config, sorted
	Created      int64    `json:"created"`       // unix seconds
	Size         int64    `json:"size"`
}

type ImageListResponse struct {
	Images []ImageInfo `json:"images"`
}

// PullRequest pulls a public image Ref and tags it ImageTag(App, DeploymentID).
// If an image already carries that tag it is returned without pulling again.
type PullRequest struct {
	App          string `json:"app"`
	DeploymentID string `json:"deployment_id"`
	Ref          string `json:"ref"` // an external image reference, e.g. nginx:1.27-alpine
}

// PullResponse mirrors BuildResponse: OK=false means a user-caused failure
// (image not found, pull timeout, registry error) classified in Failure and
// returned with HTTP 200; transport or daemon problems come back as an error.
type PullResponse struct {
	OK      bool       `json:"ok"`
	Image   *ImageInfo `json:"image,omitempty"`
	Failure *Failure   `json:"failure,omitempty"`
}

type Mount struct {
	Volume string `json:"volume"` // must start with VolumePrefix(app); created if missing
	Path   string `json:"path"`   // absolute clean container path
}

// EnsureContainerRequest creates ContainerName(App, DeploymentID) if it does
// not exist (attached to NetworkName(App), created if missing, with labels,
// restart policy unless-stopped, no-new-privileges, PidsLimit, memory/CPU
// limits and json-file log rotation), then starts it if it is not running, and
// returns its state. If a
// container with that name exists it is reused as is (its config is not
// compared): the name is the idempotency key.
type EnsureContainerRequest struct {
	App          string            `json:"app"`
	DeploymentID string            `json:"deployment_id"`
	Image        string            `json:"image"` // ImageTag(App, DeploymentID) or an image ID labeled for App (rollback)
	Port         int               `json:"port"`  // container TCP port published on 127.0.0.1:<random>
	Env          map[string]string `json:"env"`
	Mounts       []Mount           `json:"mounts"`
	MemoryMB     int               `json:"memory_mb"` // >= 64
	CPUMilli     int               `json:"cpu_milli"` // >= 100
}

// ContainerInfo is the observed state of one managed container.
type ContainerInfo struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	App          string `json:"app"`
	DeploymentID string `json:"deployment_id"`
	Role         string `json:"role"`
	Image        string `json:"image"` // image ID
	State        string `json:"state"` // docker state: created | running | restarting | exited | paused | dead | removing
	Running      bool   `json:"running"`
	Restarting   bool   `json:"restarting"`
	RestartCount int    `json:"restart_count"`
	ExitCode     int    `json:"exit_code"`
	OOMKilled    bool   `json:"oom_killed"`
	HostPort     int    `json:"host_port"`  // published port on 127.0.0.1, 0 if none
	StartedAt    string `json:"started_at"` // RFC3339 from Docker, may be empty
}

type ContainerListResponse struct {
	Containers []ContainerInfo `json:"containers"`
}

type LogsRequest struct {
	App  string `json:"app"`
	Name string `json:"name"`
	Tail int    `json:"tail"` // 1..1000, default 40
}

type LogsResponse struct {
	Lines []string `json:"lines"` // stdout and stderr interleaved, ANSI removed
}

// DiffResponse lists files added or changed in the container's writable
// layer whose names look like database files (*.db, *.sqlite, *.sqlite3,
// *.db-wal, *.db-journal), excluding paths under the container's mounts.
type DiffResponse struct {
	DatabaseFiles []string `json:"database_files"`
}

type VolumeInfo struct {
	Name    string `json:"name"`
	App     string `json:"app"`
	Created string `json:"created"`
}

type VolumeListResponse struct {
	Volumes []VolumeInfo `json:"volumes"`
}

// API is the runner's method set as seen by acornfox server. Client (client.go)
// implements it over the peer socket; tests use fakes. Errors: ErrNotFound for
// missing objects on inspect, ErrUnavailable when the socket cannot be reached,
// *RemoteError for ErrorResponse replies.
type API interface {
	Ping(ctx context.Context) (PingResponse, error)
	Build(ctx context.Context, req BuildRequest) (BuildResponse, error)
	PullImage(ctx context.Context, app, deploymentID, ref string) (PullResponse, error)
	ImageInspect(ctx context.Context, app, ref string) (ImageInfo, error)
	ListImages(ctx context.Context, app string) ([]ImageInfo, error)
	RemoveImage(ctx context.Context, app, ref string) error
	EnsureContainer(ctx context.Context, req EnsureContainerRequest) (ContainerInfo, error)
	ListContainers(ctx context.Context, app string) ([]ContainerInfo, error) // app "" = all managed
	StopContainer(ctx context.Context, app, name string) error
	StartContainer(ctx context.Context, app, name string) (ContainerInfo, error)
	RemoveContainer(ctx context.Context, app, name string) error
	Logs(ctx context.Context, app, name string, tail int) ([]string, error)
	Diff(ctx context.Context, app, name string) ([]string, error)
	EnsureVolume(ctx context.Context, app, name string) error
	ListVolumes(ctx context.Context, app string) ([]VolumeInfo, error)
}

var (
	ErrNotFound    = errors.New("runner: not found")
	ErrUnavailable = errors.New("runner: unavailable")
)

// RemoteError is an ErrorResponse returned by the runner.
type RemoteError struct {
	Status int
	ErrorResponse
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("runner %d %s: %s", e.Status, e.Code, e.Message)
}

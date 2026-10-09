// Package state is the SQLite store of desired state for AcornFox v2.
//
// It records what each app should be (apps, env, volumes, add-ons) and the
// history of deployments and events. It never records what Docker is actually
// running: that is always read from Docker through the runner.
//
// Only acornfox server opens this database. Every method is safe for
// concurrent use.
package state

import (
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

var (
	ErrNotFound  = errors.New("state: not found")
	ErrConflict  = errors.New("state: conflict")
	ErrInvalid   = errors.New("state: invalid input")
	ErrLocked    = errors.New("state: database is locked by another process")
	ErrBadSchema = errors.New("state: incompatible schema")
)

// AppNamePattern is the only accepted app name form. It is also a valid
// Docker name fragment and a valid DNS label.
var AppNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,38}[a-z0-9]$`)

// ValidAppName reports whether name matches AppNamePattern.
func ValidAppName(name string) bool { return AppNamePattern.MatchString(name) }

// Desired run state of an app.
const (
	DesiredRunning = "running"
	DesiredStopped = "stopped"
)

// Deployment statuses. Pending statuses are driven by the reconciler; the
// rest are terminal.
const (
	StatusQueued     = "queued"     // accepted, upload on disk, waiting for its turn
	StatusBuilding   = "building"   // image being built (or resolved for image sources)
	StatusStarting   = "starting"   // container being created and started
	StatusChecking   = "checking"   // health check in progress
	StatusRouting    = "routing"    // switching Caddy to the new container
	StatusLive       = "live"       // currently serving (at most one per app)
	StatusRetired    = "retired"    // previously live, replaced by a newer deployment
	StatusFailed     = "failed"     // stopped with a diagnosis; the previous live version keeps serving
	StatusSuperseded = "superseded" // replaced by a newer submission before it went live
)

// PendingStatuses are the statuses the reconciler must still drive forward.
var PendingStatuses = []string{StatusQueued, StatusBuilding, StatusStarting, StatusChecking, StatusRouting}

// IsPending reports whether status is one of PendingStatuses.
func IsPending(status string) bool {
	for _, s := range PendingStatuses {
		if s == status {
			return true
		}
	}
	return false
}

// Source kinds.
const (
	SourceUpload = "upload" // gzip or plain tar of a project directory, stored on disk at SourceRef
	SourceImage  = "image"  // an existing local image reference (used by rollback in N1)
)

// Defaults for new apps.
const (
	DefaultMemoryMB   = 512
	DefaultCPUMilli   = 1000
	DefaultHealthPath = "/"
	KeepVersions      = 3 // successful versions whose images are kept for rollback
	MaxBuildAttempts  = 2 // a build interrupted by a crash is retried once
)

// App is the desired state of one app.
type App struct {
	Name              string    `json:"name"`
	Desired           string    `json:"desired"`            // DesiredRunning | DesiredStopped
	Port              int       `json:"port"`               // container port; 0 = detect from image EXPOSE, else 8080
	HealthPath        string    `json:"health_path"`        // default "/"
	PublicPort        int       `json:"public_port"`        // host port Caddy listens on for this app; unique per host
	CurrentDeployment string    `json:"current_deployment"` // ID of the live deployment, "" if none
	MemoryMB          int       `json:"memory_mb"`          // default DefaultMemoryMB
	CPUMilli          int       `json:"cpu_milli"`          // default DefaultCPUMilli (1000 = 1 CPU)
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// Diagnosis is the stable, structured failure/warning contract shared by the
// API, CLI and Skill. Codes are never renamed; new codes may be added.
type Diagnosis struct {
	Stage      string `json:"stage"`                 // upload | build | start | health | route | data | runner
	Code       string `json:"code"`                  // e.g. build_failed, port_not_listening, container_exited, unpersisted_database, unavailable
	Message    string `json:"message"`               // one human sentence
	LogExcerpt string `json:"log_excerpt,omitempty"` // at most 40 lines, secrets redacted
	Hint       string `json:"hint,omitempty"`        // what to change or run next
}

// Deployment is one attempt to put a version of an app live.
type Deployment struct {
	ID           string      `json:"id"` // 12 lowercase hex chars
	App          string      `json:"app"`
	Seq          int         `json:"seq"`                   // per-app version number shown as "第 N 版", starts at 1
	SourceKind   string      `json:"source_kind"`           // SourceUpload | SourceImage
	SourceRef    string      `json:"source_ref"`            // upload file path, or image reference
	SourceDigest string      `json:"source_digest"`         // sha256 hex of the upload bytes, or image ID for image sources
	RequestKey   string      `json:"request_key,omitempty"` // client idempotency key, unique per app when non-empty
	ImageID      string      `json:"image_id,omitempty"`    // set once the image exists
	Status       string      `json:"status"`
	Attempts     int         `json:"attempts"`            // build attempts started
	Diagnosis    *Diagnosis  `json:"diagnosis,omitempty"` // set when failed
	Warnings     []Diagnosis `json:"warnings,omitempty"`  // non-fatal, e.g. data/unpersisted_database
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
	FinishedAt   *time.Time  `json:"finished_at,omitempty"`
	// Set when this deployment re-uses an existing image (redeploy, rollback,
	// addon change): the version it was based on, that version's original
	// source kind, and why it was created (see Reason*).
	BasedOnSeq int    `json:"based_on_seq,omitempty"`
	OriginKind string `json:"origin_kind,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// EnvVar is one environment variable. Secret values are never returned by
// read APIs of the server; the store itself returns them so the reconciler can
// pass them to the runner.
type EnvVar struct {
	App    string `json:"app"`
	Key    string `json:"key"`
	Value  string `json:"value"`
	Secret bool   `json:"secret"`
}

// Volume is one container directory persisted in a Docker named volume.
type Volume struct {
	App        string    `json:"app"`
	Path       string    `json:"path"`        // absolute, clean container path
	VolumeName string    `json:"volume_name"` // af-<app>-<n>, assigned by the store, never reused for another path
	Auto       bool      `json:"auto"`        // true when detected from the image's VOLUME
	CreatedAt  time.Time `json:"created_at"`
}

// Addon kinds (commands arrive in N4; the table exists from N1).
const (
	AddonPostgres = "postgres"
	AddonMySQL    = "mysql"
	AddonRedis    = "redis"
)

// Addon is a database container attached to one app.
type Addon struct {
	App         string          `json:"app"`
	Kind        string          `json:"kind"`
	Image       string          `json:"image"` // pinned official image
	VolumeName  string          `json:"volume_name"`
	Credentials json.RawMessage `json:"-"`       // generated secrets, never exposed
	EnvVar      string          `json:"env_var"` // e.g. DATABASE_URL
	CreatedAt   time.Time       `json:"created_at"`
}

// Event is one line of deployment/operation history.
type Event struct {
	ID           int64     `json:"id"`
	App          string    `json:"app"`
	DeploymentID string    `json:"deployment_id,omitempty"`
	At           time.Time `json:"at"`
	Stage        string    `json:"stage"`
	Message      string    `json:"message"`
}

// NewDeployment is the input to Store.CreateDeployment.
type NewDeployment struct {
	App          string
	SourceKind   string
	SourceRef    string
	SourceDigest string
	RequestKey   string
	BypassDedup  bool   // when true, skip digest-based deduplication (used by redeploy)
	BasedOnSeq   int    // version this deployment re-uses, 0 for a fresh source
	OriginKind   string // original source kind of the re-used version
	Reason       string // Reason* value, empty for a fresh source
}

// Reasons for a deployment that re-uses an existing image. Addon changes carry
// the addon kind after a colon, e.g. "addon_add:postgres".
const (
	ReasonRedeploy    = "redeploy"
	ReasonRollback    = "rollback"
	ReasonAddonAdd    = "addon_add"
	ReasonAddonRemove = "addon_remove"
)

// Config configures Open.
type Config struct {
	Path          string // database file path, e.g. /var/lib/acornfox/acornfox.db
	PublicPortMin int    // inclusive; default 18810
	PublicPortMax int    // inclusive; default 18899
}

/*
Store method set (implemented in store.go; the reconciler and server depend on
exactly these signatures):

	Open(cfg Config) (*Store, error)           // creates dir 0700, file 0600, exclusive flock on Path+".lock" (ErrLocked), WAL, FK on, runs migrations
	(*Store) Close() error

	// Apps
	EnsureApp(ctx, name string) (App, bool, error)      // creates with defaults + next free PublicPort if missing; bool = created
	GetApp(ctx, name string) (App, error)
	ListApps(ctx) ([]App, error)
	UpdateApp(ctx, name string, fn func(*App) error) (App, error) // read-modify-write in one transaction; Name/CreatedAt/PublicPort immutable via fn
	SetCurrentDeployment(ctx, app, deploymentID string) error     // in one tx: previous live -> retired (FinishedAt kept), new -> live, apps.current_deployment = id

	// Deployments
	CreateDeployment(ctx, in NewDeployment) (Deployment, bool, error)
	    // bool=false with the existing row when RequestKey matches an existing deployment of the app,
	    // or when the newest pending-or-live deployment of the app has the same SourceDigest.
	    // Otherwise inserts status=queued, Seq=max(seq)+1, ID random 12 hex.
	GetDeployment(ctx, id string) (Deployment, error)
	ListDeployments(ctx, app string, limit int) ([]Deployment, error)   // newest first
	PendingDeployments(ctx, app string) ([]Deployment, error)          // pending statuses, oldest first
	UpdateDeployment(ctx, id string, fn func(*Deployment) error) (Deployment, error)
	    // read-modify-write; sets UpdatedAt; sets FinishedAt when status becomes terminal; rejects leaving a terminal status (ErrConflict)
	KeptImageDeployments(ctx, app string) ([]Deployment, error)
	    // the live deployment plus the newest KeepVersions retired ones that have ImageID; everything else may be garbage collected

	// Env, volumes, add-ons
	SetEnv(ctx, v EnvVar) error                  // key must match ^[A-Za-z_][A-Za-z0-9_]{0,127}$
	DeleteEnv(ctx, app, key string) error
	ListEnv(ctx, app string) ([]EnvVar, error)   // includes secret values
	AddVolume(ctx, app, path string, auto bool) (Volume, bool, error) // idempotent per (app,path); bool = created
	ListVolumes(ctx, app string) ([]Volume, error)
	ListAddons(ctx, app string) ([]Addon, error) // active add-ons only
	ListRemovedAddons(ctx, app string) ([]Addon, error)
	AddAddon(ctx context.Context, addon Addon) (bool, error) // bool=true when restoring retained credentials
	RemoveAddon(ctx context.Context, app, kind string, deleteVolume bool) error

	// Events
	AddEvent(ctx, e Event) error
	ListEvents(ctx, app, deploymentID string, afterID int64, limit int) ([]Event, error)
*/

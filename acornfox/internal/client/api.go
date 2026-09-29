// Package client is the CLI's typed client of the acornfox server API, over
// SSH (system ssh + "acornfox proxy") or a direct URL for development.
// See docs/n2-contract.md sections 1 and 4.
package client

import (
	"context"
	"encoding/json"
	"io"
	"time"
)

// APIVersion is the server API version this client speaks.
const APIVersion = 1

// Target is one server entry from targets.json.
type Target struct {
	Name          string `json:"-"`
	SSH           string `json:"ssh,omitempty"`            // user@host or ~/.ssh/config alias
	Port          int    `json:"port,omitempty"`           // 0 = ssh default
	Identity      string `json:"identity,omitempty"`       // private key path, optional
	RemoteCommand string `json:"remote_command,omitempty"` // default "acornfox proxy"
	URL           string `json:"url,omitempty"`            // direct http://127.0.0.1:port, bypasses SSH
}

// Diagnosis mirrors state.Diagnosis on the wire.
type Diagnosis struct {
	Stage      string `json:"stage"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	LogExcerpt string `json:"log_excerpt,omitempty"`
	Hint       string `json:"hint,omitempty"`
}

// Error is returned by every Client method on failure. Connect failures have
// Diag.Stage == "connect" (codes in contract section 1); server error replies
// have Status > 0 and Diag.Stage == "server", Diag.Code = the server error code.
type Error struct {
	Status int
	Diag   Diagnosis
}

func (e *Error) Error() string { return e.Diag.Stage + "/" + e.Diag.Code + ": " + e.Diag.Message }

// Deployment, Event and App are the server's wire views (apiserver). Unknown
// fields are ignored so the server may add fields.
type Deployment struct {
	ID         string      `json:"id"`
	App        string      `json:"app"`
	Seq        int         `json:"seq"`
	SourceKind string      `json:"source_kind"`
	Status     string      `json:"status"`
	Diagnosis  *Diagnosis  `json:"diagnosis,omitempty"`
	Warnings   []Diagnosis `json:"warnings,omitempty"`
	CreatedAt  time.Time   `json:"created_at"`
	FinishedAt *time.Time  `json:"finished_at,omitempty"`
}

type Event struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Stage   string    `json:"stage"`
	Message string    `json:"message"`
}

type EnvKey struct {
	Key    string `json:"key"`
	Secret bool   `json:"secret"`
	Value  string `json:"value,omitempty"`
}

type Volume struct {
	Path       string `json:"path"`
	VolumeName string `json:"volume_name"`
	Auto       bool   `json:"auto"`
}

type App struct {
	Name              string      `json:"name"`
	Desired           string      `json:"desired"`
	Port              int         `json:"port"`
	HealthPath        string      `json:"health_path"`
	PublicPort        int         `json:"public_port"`
	CurrentDeployment string      `json:"current_deployment"`
	MemoryMB          int         `json:"memory_mb"`
	CPUMilli          int         `json:"cpu_milli"`
	URL               string      `json:"url"`
	ObservedState     string      `json:"observed_state"`
	Live              *Deployment `json:"live,omitempty"`
	Env               []EnvKey    `json:"env,omitempty"`
	Volumes           []Volume    `json:"volumes,omitempty"`
	Domains           []Domain    `json:"domains,omitempty"`
}

type Status struct {
	APIVersion    int    `json:"api_version"`
	Runner        string `json:"runner"`
	DockerVersion string `json:"docker_version"`
	Apps          int    `json:"apps"`
}

// DeployOptions select the source (exactly one of Upload, Image, Git) and
// optional app settings applied before the deployment.
type DeployOptions struct {
	Upload         io.Reader // tar.gz stream
	UploadSize     int64
	Image          string
	Git            string
	Ref            string
	IdempotencyKey string
	Port           int
	HealthPath     string
}

// AppSettings for PATCH /v1/apps/{app}; nil fields are unchanged.
type AppSettings struct {
	MemoryMB   *int    `json:"memory_mb,omitempty"`
	CPUMilli   *int    `json:"cpu_milli,omitempty"`
	Port       *int    `json:"port,omitempty"`
	HealthPath *string `json:"health_path,omitempty"`
}

// API is what internal/cli depends on. Connect returns a *Client implementing it.
type API interface {
	Status(ctx context.Context) (Status, error)                                          // also verifies APIVersion (connect/version_mismatch)
	Deploy(ctx context.Context, app string, opt DeployOptions) (Deployment, bool, error) // bool = newly created (false = duplicate)
	Rollback(ctx context.Context, app string) (Deployment, error)
	Deployment(ctx context.Context, id string, afterEvent int64) (Deployment, []Event, error)
	Apps(ctx context.Context) ([]App, error)
	App(ctx context.Context, app string) (App, error)
	UpdateApp(ctx context.Context, app string, s AppSettings) (App, error)
	Logs(ctx context.Context, app string, tail int) ([]string, error)
	SetEnv(ctx context.Context, app, key, value string, secret bool) error
	UnsetEnv(ctx context.Context, app, key string) error
	AddVolume(ctx context.Context, app, path string) error
	Stop(ctx context.Context, app string) error
	Start(ctx context.Context, app string) error
	Close() error // ends the SSH session

	// N3
	ConsoleToken(ctx context.Context) (string, error)                // POST /v1/console/tokens (trusted socket only)
	Domains(ctx context.Context, app string) ([]Domain, error)       // GET  /v1/apps/{app}/domains
	AddDomain(ctx context.Context, app, name string) (Domain, error) // POST /v1/apps/{app}/domains {"name"}
	RemoveDomain(ctx context.Context, app, name string) error        // DELETE /v1/apps/{app}/domains/{name}
}

// Domain mirrors state.Domain on the wire.
type Domain struct {
	App       string     `json:"app"`
	Name      string     `json:"name"`
	Status    string     `json:"status"` // pending | ready | failed
	Diagnosis *Diagnosis `json:"diagnosis,omitempty"`
	// Warnings carries non-fatal diagnoses returned by AddDomain (e.g. a
	// dns_mismatch when the name's A/AAAA record does not point at this server).
	// Additive to the state.Domain shape: it only appears on the POST response
	// and is surfaced so the CLI can print it. See N3 contract section 2.
	Warnings []Diagnosis `json:"warnings,omitempty"`
}

// Raw is used for debugging/--json passthrough when needed.
type Raw = json.RawMessage

/*
Implemented in client.go / ssh.go:

	Connect(ctx context.Context, t Target) (*Client, error)
	    // Direct when t.URL != ""; else starts `ssh -T -o BatchMode=yes -o ServerAliveInterval=15
	    // [-p Port] [-i Identity] SSH RemoteCommand` lazily on first request, wraps its
	    // stdin/stdout as a net.Conn for http.Transport (keep-alive, MaxConnsPerHost=1),
	    // and classifies ssh exit/stderr into connect diagnoses (contract table).
	    // Uses exec.LookPath("ssh") -> connect/ssh_missing.
*/

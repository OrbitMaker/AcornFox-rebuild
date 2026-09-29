// Package apiserver implements the N1 HTTP API of acornfox server.
//
// N1 is unauthenticated and may only listen on 127.0.0.1 or a Unix socket
// (see ValidateListen); authentication and SSH ingress arrive in N2/N3. All
// responses are JSON. Errors use the body {"error":{"code","message"}}.
//
// The server never touches Docker directly: it reads observed container state
// through a Runner (best-effort; runner errors degrade to "unavailable") and
// writes desired state through a Store. Secret environment values are never
// returned by any endpoint.
package apiserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/acornfox/acornfox/internal/runner"
	"github.com/acornfox/acornfox/internal/state"
)

// DefaultMaxUploadBytes is the default upload cap when Config.MaxUploadBytes is
// zero: 200 MB.
const DefaultMaxUploadBytes int64 = 200 << 20

// Store is the subset of *state.Store the API server depends on. The signatures
// match state.Store exactly so the concrete store satisfies this interface.
type Store interface {
	EnsureApp(ctx context.Context, name string) (state.App, bool, error)
	GetApp(ctx context.Context, name string) (state.App, error)
	ListApps(ctx context.Context) ([]state.App, error)
	UpdateApp(ctx context.Context, name string, fn func(*state.App) error) (state.App, error)

	CreateDeployment(ctx context.Context, in state.NewDeployment) (state.Deployment, bool, error)
	GetDeployment(ctx context.Context, id string) (state.Deployment, error)
	ListDeployments(ctx context.Context, app string, limit int) ([]state.Deployment, error)
	UpdateDeployment(ctx context.Context, id string, fn func(*state.Deployment) error) (state.Deployment, error)

	SetEnv(ctx context.Context, v state.EnvVar) error
	DeleteEnv(ctx context.Context, app, key string) error
	ListEnv(ctx context.Context, app string) ([]state.EnvVar, error)
	AddVolume(ctx context.Context, app, path string, auto bool) (state.Volume, bool, error)
	ListVolumes(ctx context.Context, app string) ([]state.Volume, error)

	ListEvents(ctx context.Context, app, deploymentID string, afterID int64, limit int) ([]state.Event, error)
}

// Kicker triggers one reconcile round for an app. It is non-blocking.
type Kicker interface {
	Kick(app string)
}

// Runner is the read-only subset of runner.API the API server uses to observe
// live container state and daemon health. Its methods must never mutate state.
type Runner interface {
	Ping(ctx context.Context) (runner.PingResponse, error)
	ListContainers(ctx context.Context, app string) ([]runner.ContainerInfo, error)
}

// Config configures New. Store, Kicker, Runner and UploadDir are required.
type Config struct {
	Store          Store
	Kicker         Kicker
	Runner         Runner
	UploadDir      string       // directory for streamed uploads; must exist and be writable
	PublicHost     string       // host used in app URLs, e.g. the server's LAN IP
	MaxUploadBytes int64        // per-upload cap; 0 => DefaultMaxUploadBytes
	Logger         *slog.Logger // optional; defaults to slog.Default()
}

type server struct {
	store          Store
	kicker         Kicker
	runner         Runner
	uploadDir      string
	publicHost     string
	maxUploadBytes int64
	log            *slog.Logger
}

// New builds the N1 HTTP handler. It panics only on a nil required dependency,
// which is a programmer error at wiring time.
func New(cfg Config) http.Handler {
	if cfg.Store == nil {
		panic("apiserver: Config.Store is nil")
	}
	if cfg.Kicker == nil {
		panic("apiserver: Config.Kicker is nil")
	}
	if cfg.Runner == nil {
		panic("apiserver: Config.Runner is nil")
	}
	if cfg.UploadDir == "" {
		panic("apiserver: Config.UploadDir is empty")
	}
	max := cfg.MaxUploadBytes
	if max <= 0 {
		max = DefaultMaxUploadBytes
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	s := &server{
		store:          cfg.Store,
		kicker:         cfg.Kicker,
		runner:         cfg.Runner,
		uploadDir:      cfg.UploadDir,
		publicHost:     cfg.PublicHost,
		maxUploadBytes: max,
		log:            log,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/apps/{app}/deployments", s.createDeployment)
	mux.HandleFunc("POST /v1/apps/{app}/rollback", s.rollback)
	mux.HandleFunc("GET /v1/deployments/{id}", s.getDeployment)
	mux.HandleFunc("GET /v1/apps", s.listApps)
	mux.HandleFunc("GET /v1/apps/{app}", s.getApp)
	mux.HandleFunc("PUT /v1/apps/{app}/env/{key}", s.putEnv)
	mux.HandleFunc("DELETE /v1/apps/{app}/env/{key}", s.deleteEnv)
	mux.HandleFunc("POST /v1/apps/{app}/volumes", s.addVolume)
	mux.HandleFunc("POST /v1/apps/{app}/stop", s.stopApp)
	mux.HandleFunc("POST /v1/apps/{app}/start", s.startApp)
	mux.HandleFunc("GET /v1/status", s.status)
	return mux
}

// mapStoreError translates state sentinel errors into HTTP responses.
func (s *server) mapStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, state.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "对象不存在")
	case errors.Is(err, state.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", "状态冲突，操作被拒绝")
	case errors.Is(err, state.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid", "输入不合法")
	default:
		s.log.Error("store error", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "内部错误")
	}
}

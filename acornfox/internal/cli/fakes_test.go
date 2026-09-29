package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/acornfox/acornfox/internal/client"
)

// fakeAPI is a scriptable client.API for the command tests. Each field either
// supplies a canned value or a function to compute the reply.
type fakeAPI struct {
	statusFn     func(ctx context.Context) (client.Status, error)
	deployFn     func(ctx context.Context, app string, opt client.DeployOptions) (client.Deployment, bool, error)
	rollbackFn   func(ctx context.Context, app string) (client.Deployment, error)
	deploymentFn func(ctx context.Context, id string, after int64) (client.Deployment, []client.Event, error)
	appsFn       func(ctx context.Context) ([]client.App, error)
	appFn        func(ctx context.Context, app string) (client.App, error)
	updateAppFn  func(ctx context.Context, app string, s client.AppSettings) (client.App, error)
	logsFn       func(ctx context.Context, app string, tail int) ([]string, error)
	setEnvFn     func(ctx context.Context, app, key, value string, secret bool) error
	unsetEnvFn   func(ctx context.Context, app, key string) error
	addVolumeFn  func(ctx context.Context, app, path string) error
	stopFn       func(ctx context.Context, app string) error
	startFn      func(ctx context.Context, app string) error

	closed bool

	// captured inputs for assertions
	lastDeployApp string
	lastDeployOpt client.DeployOptions
	lastSetEnv    struct {
		app, key, value string
		secret          bool
	}
}

func (f *fakeAPI) Status(ctx context.Context) (client.Status, error) {
	if f.statusFn != nil {
		return f.statusFn(ctx)
	}
	return client.Status{APIVersion: client.APIVersion, Runner: "ok", Apps: 0}, nil
}

func (f *fakeAPI) Deploy(ctx context.Context, app string, opt client.DeployOptions) (client.Deployment, bool, error) {
	f.lastDeployApp = app
	f.lastDeployOpt = opt
	if f.deployFn != nil {
		return f.deployFn(ctx, app, opt)
	}
	return client.Deployment{ID: "abc123", App: app, Seq: 1, Status: "live"}, true, nil
}

func (f *fakeAPI) Rollback(ctx context.Context, app string) (client.Deployment, error) {
	if f.rollbackFn != nil {
		return f.rollbackFn(ctx, app)
	}
	return client.Deployment{ID: "roll1", App: app, Seq: 2, Status: "live"}, nil
}

func (f *fakeAPI) Deployment(ctx context.Context, id string, after int64) (client.Deployment, []client.Event, error) {
	if f.deploymentFn != nil {
		return f.deploymentFn(ctx, id, after)
	}
	return client.Deployment{ID: id, Status: "live"}, nil, nil
}

func (f *fakeAPI) Apps(ctx context.Context) ([]client.App, error) {
	if f.appsFn != nil {
		return f.appsFn(ctx)
	}
	return nil, nil
}

func (f *fakeAPI) App(ctx context.Context, app string) (client.App, error) {
	if f.appFn != nil {
		return f.appFn(ctx, app)
	}
	return client.App{Name: app, URL: "http://192.168.1.10:12345"}, nil
}

func (f *fakeAPI) UpdateApp(ctx context.Context, app string, s client.AppSettings) (client.App, error) {
	if f.updateAppFn != nil {
		return f.updateAppFn(ctx, app, s)
	}
	return client.App{Name: app}, nil
}

func (f *fakeAPI) Logs(ctx context.Context, app string, tail int) ([]string, error) {
	if f.logsFn != nil {
		return f.logsFn(ctx, app, tail)
	}
	return nil, nil
}

func (f *fakeAPI) SetEnv(ctx context.Context, app, key, value string, secret bool) error {
	f.lastSetEnv.app, f.lastSetEnv.key, f.lastSetEnv.value, f.lastSetEnv.secret = app, key, value, secret
	if f.setEnvFn != nil {
		return f.setEnvFn(ctx, app, key, value, secret)
	}
	return nil
}

func (f *fakeAPI) UnsetEnv(ctx context.Context, app, key string) error {
	if f.unsetEnvFn != nil {
		return f.unsetEnvFn(ctx, app, key)
	}
	return nil
}

func (f *fakeAPI) AddVolume(ctx context.Context, app, path string) error {
	if f.addVolumeFn != nil {
		return f.addVolumeFn(ctx, app, path)
	}
	return nil
}

func (f *fakeAPI) Stop(ctx context.Context, app string) error {
	if f.stopFn != nil {
		return f.stopFn(ctx, app)
	}
	return nil
}

func (f *fakeAPI) Start(ctx context.Context, app string) error {
	if f.startFn != nil {
		return f.startFn(ctx, app)
	}
	return nil
}

func (f *fakeAPI) Close() error { f.closed = true; return nil }

// harness wires a test invocation with an injected fake API, config dir and
// working dir.
type harness struct {
	t         *testing.T
	api       *fakeAPI
	connect   Connector
	configDir string
	workDir   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	api := &fakeAPI{}
	// Use a work directory whose base name is a valid app name so deploy can
	// default the app without --app.
	wd := filepath.Join(t.TempDir(), "notes")
	if err := os.MkdirAll(wd, 0o755); err != nil {
		t.Fatalf("mkdir workdir: %v", err)
	}
	h := &harness{
		t:         t,
		api:       api,
		configDir: t.TempDir(),
		workDir:   wd,
	}
	h.connect = func(ctx context.Context, tgt client.Target) (client.API, error) {
		return api, nil
	}
	return h
}

// run invokes the CLI with the given args and returns exit code, stdout and
// stderr.
func (h *harness) run(args ...string) (int, string, string) {
	h.t.Helper()
	var out, errBuf bytes.Buffer
	code := MainWithConnector(context.Background(), args, io.NopCloser(bytes.NewReader(nil)), &out, &errBuf, func(string) string { return "" }, h.connect, h.configDir, h.workDir)
	return code, out.String(), errBuf.String()
}

// addTarget writes a target into the harness config dir and marks it default.
func (h *harness) addTarget(name, url string) {
	h.t.Helper()
	tf, err := loadTargets(h.configDir)
	if err != nil {
		h.t.Fatalf("loadTargets: %v", err)
	}
	tf.Targets[name] = &client.Target{Name: name, URL: url}
	if tf.Default == "" {
		tf.Default = name
	}
	if err := saveTargets(h.configDir, tf); err != nil {
		h.t.Fatalf("saveTargets: %v", err)
	}
}

// writeDockerfile creates a minimal Dockerfile in the working directory so
// deploy can pack it.
func (h *harness) writeDockerfile() {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.workDir, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		h.t.Fatalf("write Dockerfile: %v", err)
	}
}

// decodeJSON parses a single JSON object from s.
func decodeJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, s)
	}
	return m
}

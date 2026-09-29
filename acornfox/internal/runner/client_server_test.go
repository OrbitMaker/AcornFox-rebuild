package runner

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/acornfox/acornfox/internal/peer"
)

// fakeAPI is an in-memory API used to test the server/client round-trip. Each
// method records its last call and returns a preset result or error.
type fakeAPI struct {
	mu sync.Mutex

	pingResp PingResponse
	pingErr  error

	buildResp BuildResponse
	buildErr  error
	buildReq  BuildRequest

	inspectResp ImageInfo
	inspectErr  error
	inspectApp  string
	inspectRef  string

	images    []ImageInfo
	imagesErr error

	removeImageErr error

	ensureResp ContainerInfo
	ensureErr  error
	ensureReq  EnsureContainerRequest

	containers    []ContainerInfo
	containersErr error
	listApp       string

	stopErr  error
	stopName string

	startResp ContainerInfo
	startErr  error

	removeErr  error
	removeName string

	logLines []string
	logsErr  error
	logTail  int

	diffFiles []string
	diffErr   error

	ensureVolErr  error
	ensureVolName string

	volumes    []VolumeInfo
	volumesErr error
}

func (f *fakeAPI) Ping(context.Context) (PingResponse, error) { return f.pingResp, f.pingErr }

func (f *fakeAPI) Build(_ context.Context, req BuildRequest) (BuildResponse, error) {
	f.mu.Lock()
	f.buildReq = req
	f.mu.Unlock()
	return f.buildResp, f.buildErr
}

func (f *fakeAPI) ImageInspect(_ context.Context, app, ref string) (ImageInfo, error) {
	f.inspectApp, f.inspectRef = app, ref
	return f.inspectResp, f.inspectErr
}

func (f *fakeAPI) ListImages(context.Context, string) ([]ImageInfo, error) {
	return f.images, f.imagesErr
}

func (f *fakeAPI) RemoveImage(context.Context, string, string) error { return f.removeImageErr }

func (f *fakeAPI) EnsureContainer(_ context.Context, req EnsureContainerRequest) (ContainerInfo, error) {
	f.ensureReq = req
	return f.ensureResp, f.ensureErr
}

func (f *fakeAPI) ListContainers(_ context.Context, app string) ([]ContainerInfo, error) {
	f.listApp = app
	return f.containers, f.containersErr
}

func (f *fakeAPI) StopContainer(_ context.Context, _, name string) error {
	f.stopName = name
	return f.stopErr
}

func (f *fakeAPI) StartContainer(context.Context, string, string) (ContainerInfo, error) {
	return f.startResp, f.startErr
}

func (f *fakeAPI) RemoveContainer(_ context.Context, _, name string) error {
	f.removeName = name
	return f.removeErr
}

func (f *fakeAPI) Logs(_ context.Context, _, _ string, tail int) ([]string, error) {
	f.logTail = tail
	return f.logLines, f.logsErr
}

func (f *fakeAPI) Diff(context.Context, string, string) ([]string, error) {
	return f.diffFiles, f.diffErr
}

func (f *fakeAPI) EnsureVolume(_ context.Context, _, name string) error {
	f.ensureVolName = name
	return f.ensureVolErr
}

func (f *fakeAPI) ListVolumes(context.Context, string) ([]VolumeInfo, error) {
	return f.volumes, f.volumesErr
}

var _ API = (*fakeAPI)(nil)

// startTestServer serves srv over a real peer socket in a temp dir and returns
// a Client that talks to it. It registers cleanup with t.
func startTestServer(t *testing.T, srv *Server) *Client {
	t.Helper()
	uid := uint32(os.Getuid())
	dir := t.TempDir()
	sock := filepath.Join(dir, "runner.sock")

	ln, err := peer.Listen(sock, 0, uid)
	if err != nil {
		t.Fatalf("peer.Listen: %v", err)
	}
	hs := &http.Server{Handler: srv}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
	})
	return NewClient(sock, uid)
}

func newTestServer(t *testing.T, api API) (*Server, *Client) {
	t.Helper()
	srv := NewServer(api, t.TempDir())
	return srv, startTestServer(t, srv)
}

func TestClientPingRoundTrip(t *testing.T) {
	api := &fakeAPI{pingResp: PingResponse{DockerAPIVersion: "1.51", ServerVersion: "27.0"}}
	_, cli := newTestServer(t, api)

	resp, err := cli.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if resp.DockerAPIVersion != "1.51" || resp.ServerVersion != "27.0" {
		t.Fatalf("unexpected ping response: %+v", resp)
	}
}

func TestClientNotFoundMapping(t *testing.T) {
	api := &fakeAPI{inspectErr: ErrNotFound}
	_, cli := newTestServer(t, api)

	_, err := cli.ImageInspect(context.Background(), "demo", "acornfox/demo:0123456789ab")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestClientUnavailableMapping(t *testing.T) {
	// Point the client at a socket that does not exist.
	dir := t.TempDir()
	cli := NewClient(filepath.Join(dir, "missing.sock"), uint32(os.Getuid()))

	_, err := cli.Ping(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestClientRemoteErrorMapping(t *testing.T) {
	// A generic Docker error surfaces as *RemoteError with a 500 status.
	api := &fakeAPI{containersErr: errors.New("boom")}
	_, cli := newTestServer(t, api)

	_, err := cli.ListContainers(context.Background(), "demo")
	var re *RemoteError
	if !errors.As(err, &re) {
		t.Fatalf("want *RemoteError, got %v", err)
	}
	if re.Status != http.StatusInternalServerError || re.Code != "docker_error" {
		t.Fatalf("unexpected remote error: %+v", re)
	}
}

func TestClientBuildRoundTrip(t *testing.T) {
	want := BuildResponse{OK: true, Image: &ImageInfo{ID: "sha256:abc", App: "demo", DeploymentID: "0123456789ab"}}
	api := &fakeAPI{buildResp: want}
	uploadDir := t.TempDir()
	srv := NewServer(api, uploadDir)
	cli := startTestServer(t, srv)

	resp, err := cli.Build(context.Background(), BuildRequest{
		App:          "demo",
		DeploymentID: "0123456789ab",
		ContextPath:  filepath.Join(uploadDir, "0123456789ab.tar.gz"),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !resp.OK || resp.Image == nil || resp.Image.ID != "sha256:abc" {
		t.Fatalf("unexpected build response: %+v", resp)
	}
}

func TestClientEnsureContainerRoundTrip(t *testing.T) {
	api := &fakeAPI{ensureResp: ContainerInfo{ID: "cid", Name: "af-demo-0123456789ab", HostPort: 34567, Running: true}}
	_, cli := newTestServer(t, api)

	info, err := cli.EnsureContainer(context.Background(), EnsureContainerRequest{
		App:          "demo",
		DeploymentID: "0123456789ab",
		Image:        "acornfox/demo:0123456789ab",
		Port:         8080,
		MemoryMB:     512,
		CPUMilli:     1000,
	})
	if err != nil {
		t.Fatalf("EnsureContainer: %v", err)
	}
	if info.HostPort != 34567 || !info.Running {
		t.Fatalf("unexpected info: %+v", info)
	}
	if api.ensureReq.App != "demo" || api.ensureReq.Port != 8080 {
		t.Fatalf("server did not receive request faithfully: %+v", api.ensureReq)
	}
}

func TestClientLogsAndDiffRoundTrip(t *testing.T) {
	api := &fakeAPI{
		logLines:  []string{"line1", "line2"},
		diffFiles: []string{"/app/data.db"},
	}
	_, cli := newTestServer(t, api)

	lines, err := cli.Logs(context.Background(), "demo", "af-demo-0123456789ab", 40)
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if len(lines) != 2 || lines[0] != "line1" {
		t.Fatalf("unexpected logs: %v", lines)
	}
	files, err := cli.Diff(context.Background(), "demo", "af-demo-0123456789ab")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(files) != 1 || files[0] != "/app/data.db" {
		t.Fatalf("unexpected diff: %v", files)
	}
}

// ---- server validation tests (exercised directly through the client) ----

func TestServerValidatesAppName(t *testing.T) {
	_, cli := newTestServer(t, &fakeAPI{})
	// Invalid app should be rejected by the server before reaching the API.
	_, err := cli.EnsureContainer(context.Background(), EnsureContainerRequest{
		App:          "Bad_App",
		DeploymentID: "0123456789ab",
		Image:        "img",
		Port:         8080,
		MemoryMB:     512,
		CPUMilli:     1000,
	})
	assertInvalidRequest(t, err)
}

func TestServerValidatesDeploymentID(t *testing.T) {
	_, cli := newTestServer(t, &fakeAPI{})
	_, err := cli.EnsureContainer(context.Background(), EnsureContainerRequest{
		App:          "demo",
		DeploymentID: "not-hex",
		Image:        "img",
		Port:         8080,
		MemoryMB:     512,
		CPUMilli:     1000,
	})
	assertInvalidRequest(t, err)
}

func TestServerValidatesContainerNamePrefix(t *testing.T) {
	_, cli := newTestServer(t, &fakeAPI{})
	err := cli.StopContainer(context.Background(), "demo", "wrong-prefix-0123456789ab")
	assertInvalidRequest(t, err)
}

func TestServerValidatesVolumePrefix(t *testing.T) {
	_, cli := newTestServer(t, &fakeAPI{})
	err := cli.EnsureVolume(context.Background(), "demo", "notprefixed")
	assertInvalidRequest(t, err)
}

func TestServerValidatesMemoryFloor(t *testing.T) {
	_, cli := newTestServer(t, &fakeAPI{})
	_, err := cli.EnsureContainer(context.Background(), EnsureContainerRequest{
		App:          "demo",
		DeploymentID: "0123456789ab",
		Image:        "img",
		Port:         8080,
		MemoryMB:     16, // below floor
		CPUMilli:     1000,
	})
	assertInvalidRequest(t, err)
}

func TestServerRejectsContextPathOutsideUploadDir(t *testing.T) {
	api := &fakeAPI{}
	srv := NewServer(api, "/var/lib/acornfox/uploads")
	cli := startTestServer(t, srv)

	_, err := cli.Build(context.Background(), BuildRequest{
		App:          "demo",
		DeploymentID: "0123456789ab",
		ContextPath:  "/etc/passwd",
	})
	var re *RemoteError
	if !errors.As(err, &re) {
		t.Fatalf("want *RemoteError, got %v", err)
	}
	if re.Status != http.StatusBadRequest || re.Code != "refused" {
		t.Fatalf("unexpected error: %+v", re)
	}
}

func TestServerRejectsRelativeContextPath(t *testing.T) {
	api := &fakeAPI{}
	srv := NewServer(api, "/var/lib/acornfox/uploads")
	cli := startTestServer(t, srv)

	_, err := cli.Build(context.Background(), BuildRequest{
		App:          "demo",
		DeploymentID: "0123456789ab",
		ContextPath:  "relative/path.tar.gz",
	})
	assertInvalidRequest(t, err)
}

func TestServerAcceptsContextPathUnderUploadDir(t *testing.T) {
	api := &fakeAPI{buildResp: BuildResponse{OK: true, Image: &ImageInfo{ID: "x"}}}
	srv := NewServer(api, "/var/lib/acornfox/uploads")
	cli := startTestServer(t, srv)

	resp, err := cli.Build(context.Background(), BuildRequest{
		App:          "demo",
		DeploymentID: "0123456789ab",
		ContextPath:  "/var/lib/acornfox/uploads/0123456789ab.tar.gz",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected OK build, got %+v", resp)
	}
}

// assertInvalidRequest asserts err is a 400 invalid_request RemoteError.
func assertInvalidRequest(t *testing.T, err error) {
	t.Helper()
	var re *RemoteError
	if !errors.As(err, &re) {
		t.Fatalf("want *RemoteError, got %v", err)
	}
	if re.Status != http.StatusBadRequest || re.Code != "invalid_request" {
		t.Fatalf("unexpected error: %+v", re)
	}
}

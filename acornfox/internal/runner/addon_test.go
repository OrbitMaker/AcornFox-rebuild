package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// validAddonReq returns an add-on EnsureContainer request that matches the
// pinned spec of kind for app "demo".
func validAddonReq(kind string) EnsureContainerRequest {
	spec, _ := AddonSpecFor(kind)
	return EnsureContainerRequest{
		App:          "demo",
		DeploymentID: AddonDeploymentID(kind),
		Image:        spec.Image,
		Port:         spec.Port,
		Env:          map[string]string{"X": "y"},
		Mounts:       []Mount{{Volume: AddonVolumeName("demo", kind), Path: spec.DataPath}},
		MemoryMB:     spec.MemoryMB,
		CPUMilli:     spec.CPUMilli,
		Role:         RoleAddon,
	}
}

func TestAddonNames(t *testing.T) {
	if got := AddonContainerName("shop", AddonPostgres); got != "af-shop-addon-postgres" {
		t.Fatalf("container name = %q", got)
	}
	if got := AddonVolumeName("shop", AddonRedis); got != "af-shop-addon-redis-data" {
		t.Fatalf("volume name = %q", got)
	}
	want := map[string]struct {
		image string
		port  int
		mem   int
	}{
		AddonPostgres: {"postgres:16-alpine", 5432, 512},
		AddonMySQL:    {"mysql:8.4", 3306, 512},
		AddonRedis:    {"redis:7-alpine", 6379, 256},
	}
	if len(AddonKinds()) != len(want) {
		t.Fatalf("kinds = %v", AddonKinds())
	}
	for kind, w := range want {
		s, ok := AddonSpecFor(kind)
		if !ok || s.Image != w.image || s.Port != w.port || s.MemoryMB != w.mem {
			t.Fatalf("%s spec = %+v", kind, s)
		}
	}
}

func TestValidateAddonRequest(t *testing.T) {
	for _, kind := range AddonKinds() {
		if _, err := validateAddonRequest(validAddonReq(kind)); err != nil {
			t.Fatalf("%s: valid request refused: %v", kind, err)
		}
	}

	cases := map[string]func(*EnsureContainerRequest){
		"unknown kind":     func(r *EnsureContainerRequest) { r.DeploymentID = "addon-mongo" },
		"hex id":           func(r *EnsureContainerRequest) { r.DeploymentID = "0123456789ab" },
		"other image":      func(r *EnsureContainerRequest) { r.Image = "evil/postgres:16" },
		"other port":       func(r *EnsureContainerRequest) { r.Port = 8080 },
		"no mount":         func(r *EnsureContainerRequest) { r.Mounts = nil },
		"extra mount":      func(r *EnsureContainerRequest) { r.Mounts = append(r.Mounts, Mount{Volume: "af-demo-1", Path: "/x"}) },
		"other volume":     func(r *EnsureContainerRequest) { r.Mounts[0].Volume = "af-demo-1" },
		"other mount path": func(r *EnsureContainerRequest) { r.Mounts[0].Path = "/etc" },
	}
	for name, mutate := range cases {
		req := validAddonReq(AddonPostgres)
		mutate(&req)
		if _, err := validateAddonRequest(req); err == nil {
			t.Fatalf("%s: expected refusal", name)
		}
	}
}

func TestValidContainerSuffix(t *testing.T) {
	for _, ok := range []string{"0123456789ab", "addon-postgres", "addon-mysql", "addon-redis"} {
		if !validContainerSuffix(ok) {
			t.Fatalf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"addon-", "addon-mongo", "addon-postgres-x", "not-hex", ""} {
		if validContainerSuffix(bad) {
			t.Fatalf("%q should be invalid", bad)
		}
	}
}

// serve sends one JSON request straight to the server's handler (no peer
// socket, so these tests also run where SO_PEERCRED is unavailable).
func serve(t *testing.T, api API, path string, body any) (int, ErrorResponse) {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(api, t.TempDir())
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(buf)))
	var er ErrorResponse
	if rec.Code >= 300 {
		_ = json.Unmarshal(rec.Body.Bytes(), &er)
	}
	return rec.Code, er
}

func TestServerAcceptsPinnedAddonRequest(t *testing.T) {
	api := &fakeAPI{ensureResp: ContainerInfo{Name: "af-demo-addon-postgres", Role: RoleAddon, Running: true}}
	code, er := serve(t, api, PathContainerEnsure, validAddonReq(AddonPostgres))
	if code != http.StatusOK {
		t.Fatalf("status %d: %+v", code, er)
	}
	if api.ensureReq.Role != RoleAddon || api.ensureReq.DeploymentID != "addon-postgres" {
		t.Fatalf("server did not forward the add-on request: %+v", api.ensureReq)
	}
}

func TestServerRefusesUnpinnedAddonRequest(t *testing.T) {
	api := &fakeAPI{}
	req := validAddonReq(AddonPostgres)
	req.Image = "attacker/image:latest"
	code, er := serve(t, api, PathContainerEnsure, req)
	if code != http.StatusBadRequest || er.Code != "refused" {
		t.Fatalf("want 400 refused, got %d %+v", code, er)
	}
	if api.ensureReq.App != "" {
		t.Fatalf("refused request reached the API: %+v", api.ensureReq)
	}
}

func TestServerRejectsUnknownRole(t *testing.T) {
	req := validAddonReq(AddonPostgres)
	req.Role = "sidecar"
	code, er := serve(t, &fakeAPI{}, PathContainerEnsure, req)
	if code != http.StatusBadRequest || er.Code != "invalid_request" {
		t.Fatalf("want 400 invalid_request, got %d %+v", code, er)
	}
}

func TestServerAppRoleStillRequiresHexID(t *testing.T) {
	req := validAddonReq(AddonPostgres)
	req.Role = "" // an app request cannot borrow the add-on pseudo ID
	code, er := serve(t, &fakeAPI{}, PathContainerEnsure, req)
	if code != http.StatusBadRequest || er.Code != "invalid_request" {
		t.Fatalf("want 400 invalid_request, got %d %+v", code, er)
	}
}

func TestServerAcceptsAddonContainerNames(t *testing.T) {
	api := &fakeAPI{}
	code, er := serve(t, api, PathContainerRemove, ContainerRef{App: "demo", Name: "af-demo-addon-redis"})
	if code != http.StatusOK || api.removeName != "af-demo-addon-redis" {
		t.Fatalf("remove addon container: %d %+v name=%q", code, er, api.removeName)
	}
	code, er = serve(t, api, PathContainerRemove, ContainerRef{App: "demo", Name: "af-demo-addon-mongo"})
	if code != http.StatusBadRequest || er.Code != "invalid_request" {
		t.Fatalf("unknown add-on name: %d %+v", code, er)
	}
}

func TestServerRemoveVolume(t *testing.T) {
	api := &fakeAPI{}
	code, er := serve(t, api, PathVolumeRemove, VolumeRef{App: "demo", Name: "af-demo-addon-postgres-data"})
	if code != http.StatusOK || api.removeVolName != "af-demo-addon-postgres-data" {
		t.Fatalf("remove volume: %d %+v name=%q", code, er, api.removeVolName)
	}
	code, er = serve(t, api, PathVolumeRemove, VolumeRef{App: "demo", Name: "af-other-addon-postgres-data"})
	if code != http.StatusBadRequest || er.Code != "invalid_request" {
		t.Fatalf("foreign volume: %d %+v", code, er)
	}
}

// Pull failures must stay distinguishable from other errors across the socket.
func TestServerMapsAddonPullFailure(t *testing.T) {
	api := &fakeAPI{ensureErr: fmt.Errorf("%w: postgres:16-alpine: timeout", ErrPullFailed)}
	code, er := serve(t, api, PathContainerEnsure, validAddonReq(AddonPostgres))
	if code != http.StatusBadGateway || er.Code != "pull_failed" {
		t.Fatalf("want 502 pull_failed, got %d %+v", code, er)
	}
	if !IsPullFailed(&RemoteError{Status: code, ErrorResponse: er}) || !IsPullFailed(api.ensureErr) {
		t.Fatal("IsPullFailed must recognise both forms")
	}
	if IsPullFailed(&RemoteError{Status: 500, ErrorResponse: ErrorResponse{Code: "docker_error"}}) || IsPullFailed(ErrUnavailable) {
		t.Fatal("IsPullFailed false positive")
	}
}

// Readiness means "accepts TCP connections", and no password may be in argv.
func TestAddonHealthchecks(t *testing.T) {
	for _, kind := range AddonKinds() {
		s, _ := AddonSpecFor(kind)
		if s.Health == nil || len(s.Health.Test) != 2 || s.Health.Test[0] != "CMD-SHELL" {
			t.Fatalf("%s: healthcheck = %+v", kind, s.Health)
		}
		cmd := s.Health.Test[1]
		if !strings.Contains(cmd, "-h 127.0.0.1") {
			t.Fatalf("%s: healthcheck must probe TCP, not the Unix socket: %q", kind, cmd)
		}
		if strings.Contains(cmd, "-p$") || strings.Contains(cmd, "--password") || strings.Contains(cmd, "-a ") {
			t.Fatalf("%s: password passed as an argument: %q", kind, cmd)
		}
		if s.Health.StartPeriod < 60*time.Second || s.Health.Interval <= 0 || s.Health.Retries <= 0 {
			t.Fatalf("%s: timing = %+v", kind, s.Health)
		}
	}
}

// TestDockerEnsureContainerRefusesUnpinnedAddon checks the second, in-process
// guard: Docker itself refuses before touching the daemon (nil client).
func TestDockerEnsureContainerRefusesUnpinnedAddon(t *testing.T) {
	d := NewDocker(nil)
	req := validAddonReq(AddonRedis)
	req.Mounts[0].Path = "/"
	if _, err := d.EnsureContainer(context.Background(), req); err == nil {
		t.Fatal("expected refusal")
	}
	req = validAddonReq(AddonRedis)
	req.Role = "sidecar"
	if _, err := d.EnsureContainer(context.Background(), req); err == nil {
		t.Fatal("expected refusal of unknown role")
	}
}

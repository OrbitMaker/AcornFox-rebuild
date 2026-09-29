package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
)

// setupTestUnixSocket creates a compact local Unix domain socket listener for connection tests.
func setupTestUnixSocket(t *testing.T) (string, func()) {
	t.Helper()
	tempDir, err := os.MkdirTemp("/tmp", "dockertest-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	socketPath := filepath.Join(tempDir, "docker.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		t.Fatalf("failed to listen on unix socket %s: %v", socketPath, err)
	}

	cleanup := func() {
		_ = listener.Close()
		_ = os.RemoveAll(tempDir)
	}
	return socketPath, cleanup
}

func TestExplicitSocketIgnoresHostileEnvAndRespectsCancellation(t *testing.T) {
	// Set hostile environment variables that must NOT affect explicit socket client
	t.Setenv("DOCKER_HOST", "tcp://hostile-remote-daemon.invalid:2375")
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	t.Setenv("DOCKER_API_VERSION", "9.99")

	socketPath, cleanup := setupTestUnixSocket(t)
	defer cleanup()

	client, err := NewClient(Config{
		SocketPath:     socketPath,
		RequestTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected NewClient error: %v", err)
	}
	defer client.Close()

	// 1. Cancellation boundary: cancelled context must return context.Canceled
	ctxCanceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.Ping(ctxCanceled)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}

	// 2. Deadline boundary: expired deadline must return context.DeadlineExceeded
	ctxDeadline, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	_, err = client.Ping(ctxDeadline)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}

	// 3. Error boundary: uncontactable or closed socket maps to ErrUnavailable
	cleanup() // close socket listener now
	_, err = client.Ping(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("expected ErrUnavailable on closed socket, got: %v", err)
	}
}

func TestSocketValidation(t *testing.T) {
	tests := []struct {
		name       string
		socketPath string
		wantErr    bool
	}{
		{"valid absolute path", "/var/run/docker.sock", false},
		{"valid absolute unix prefix", "unix:///var/run/docker.sock", false},
		{"empty socket path", "", true},
		{"whitespace only", "   ", true},
		{"relative path", "docker.sock", true},
		{"relative path with dot", "./var/run/docker.sock", true},
		{"tcp scheme rejected", "tcp://127.0.0.1:2375", true},
		{"http scheme rejected", "http://localhost:2375", true},
		{"control characters rejected", "/var/run/docker\nsock", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSocketPath(tt.socketPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSocketPath(%q) err = %v, wantErr %v", tt.socketPath, err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("expected ErrInvalidConfig, got: %v", err)
			}
		})
	}
}

func TestProjectionCPULimits(t *testing.T) {
	tests := []struct {
		name          string
		nanoCPUs      int64
		cpuQuota      int64
		cpuPeriod     int64
		wantMillis    int64
		wantKnown     bool
		wantUnlimited bool
	}{
		{
			name:          "normal nanoCPUs=500000000 with default zero CFS quota=0 period=0",
			nanoCPUs:      500_000_000,
			cpuQuota:      0,
			cpuPeriod:     0,
			wantMillis:    500,
			wantKnown:     true,
			wantUnlimited: false,
		},
		{
			name:          "nanoCPUs only (2 cores)",
			nanoCPUs:      2_000_000_000,
			cpuQuota:      0,
			cpuPeriod:     0,
			wantMillis:    2000,
			wantKnown:     true,
			wantUnlimited: false,
		},
		{
			name:          "CFS quota and period only (0.5 core)",
			nanoCPUs:      0,
			cpuQuota:      50_000,
			cpuPeriod:     100_000,
			wantMillis:    500,
			wantKnown:     true,
			wantUnlimited: false,
		},
		{
			name:          "both nanoCPUs and CFS supplied and consistent (1.5 cores)",
			nanoCPUs:      1_500_000_000,
			cpuQuota:      150_000,
			cpuPeriod:     100_000,
			wantMillis:    1500,
			wantKnown:     true,
			wantUnlimited: false,
		},
		{
			name:          "both supplied but contradictory (1 core nano vs 0.5 core CFS)",
			nanoCPUs:      1_000_000_000,
			cpuQuota:      50_000,
			cpuPeriod:     100_000,
			wantMillis:    0,
			wantKnown:     false,
			wantUnlimited: false,
		},
		{
			name:          "nanoCPUs set while CFS specifies unlimited (contradictory)",
			nanoCPUs:      1_000_000_000,
			cpuQuota:      -1,
			cpuPeriod:     100_000,
			wantMillis:    0,
			wantKnown:     false,
			wantUnlimited: false,
		},
		{
			name:          "CPU unlimited (quota 0, nanoCPUs 0)",
			nanoCPUs:      0,
			cpuQuota:      0,
			cpuPeriod:     100_000,
			wantMillis:    0,
			wantKnown:     true,
			wantUnlimited: true,
		},
		{
			name:          "CPU unlimited (quota -1, nanoCPUs 0)",
			nanoCPUs:      0,
			cpuQuota:      -1,
			cpuPeriod:     100_000,
			wantMillis:    0,
			wantKnown:     true,
			wantUnlimited: true,
		},
		{
			name:          "overflow quota rejected",
			nanoCPUs:      0,
			cpuQuota:      maxSafeQuota + 10,
			cpuPeriod:     100_000,
			wantMillis:    0,
			wantKnown:     false,
			wantUnlimited: false,
		},
		{
			name:          "negative nanoCPUs rejected",
			nanoCPUs:      -1_000_000,
			cpuQuota:      50_000,
			cpuPeriod:     100_000,
			wantMillis:    0,
			wantKnown:     false,
			wantUnlimited: false,
		},
		{
			name:          "negative period rejected",
			nanoCPUs:      0,
			cpuQuota:      50_000,
			cpuPeriod:     -100,
			wantMillis:    0,
			wantKnown:     false,
			wantUnlimited: false,
		},
		{
			name:          "negative quota < -1 rejected",
			nanoCPUs:      0,
			cpuQuota:      -5,
			cpuPeriod:     100_000,
			wantMillis:    0,
			wantKnown:     false,
			wantUnlimited: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			millis, known, unlimited := calculateCPULimits(tt.nanoCPUs, tt.cpuQuota, tt.cpuPeriod)
			if millis != tt.wantMillis || known != tt.wantKnown || unlimited != tt.wantUnlimited {
				t.Errorf("got (%d, %v, %v), want (%d, %v, %v)", millis, known, unlimited, tt.wantMillis, tt.wantKnown, tt.wantUnlimited)
			}
		})
	}
}

func TestProjectionMultiNetworks(t *testing.T) {
	raw := map[string]*network.EndpointSettings{
		"frontend-net": {
			NetworkID:  "id-front",
			IPAddress:  netip.MustParseAddr("172.20.0.10"),
			Gateway:    netip.MustParseAddr("172.20.0.1"),
			MacAddress: network.HardwareAddr{0x02, 0x42, 0xac, 0x14, 0x00, 0x0a},
		},
		"backend-net": {
			NetworkID:  "id-back",
			IPAddress:  netip.MustParseAddr("172.21.0.20"),
			Gateway:    netip.MustParseAddr("172.21.0.1"),
			MacAddress: network.HardwareAddr{0x02, 0x42, 0xac, 0x15, 0x00, 0x14},
		},
		"admin-net": {
			NetworkID:  "id-admin",
			IPAddress:  netip.MustParseAddr("172.22.0.30"),
			Gateway:    netip.MustParseAddr("172.22.0.1"),
			MacAddress: network.HardwareAddr{0x02, 0x42, 0xac, 0x16, 0x00, 0x1e},
		},
	}

	projected := projectNetworks(raw)
	if len(projected) != 3 {
		t.Fatalf("expected 3 projected networks, got %d", len(projected))
	}

	// Verify stable deterministic alphabetical sorting
	if projected[0].NetworkName != "admin-net" ||
		projected[1].NetworkName != "backend-net" ||
		projected[2].NetworkName != "frontend-net" {
		t.Errorf("networks not stably sorted alphabetically: %#v", projected)
	}

	// Verify exact association preserved
	if projected[0].IPAddress != "172.22.0.30" || projected[0].NetworkID != "id-admin" {
		t.Errorf("network association corrupted for admin-net: %#v", projected[0])
	}
	if projected[1].IPAddress != "172.21.0.20" || projected[1].NetworkID != "id-back" {
		t.Errorf("network association corrupted for backend-net: %#v", projected[1])
	}
	if projected[2].IPAddress != "172.20.0.10" || projected[2].NetworkID != "id-front" {
		t.Errorf("network association corrupted for frontend-net: %#v", projected[2])
	}
}

func TestProjectionSafetyAndHostOmission(t *testing.T) {
	cResp := &container.InspectResponse{
		ID:   "c0123456789abcde0123456789abcdef0123456789abcdef0123456789abcdef",
		Name: "/app-service",
		Config: &container.Config{
			Image: "app:v1",
			Env:   []string{"DB_PASSWORD=secret-db-pass", "API_TOKEN=super-token"},
			Cmd:   []string{"entrypoint.sh", "--secret=123"},
			Labels: map[string]string{
				"open-card.managed":     "true",
				"open-card.task-prefix": "acorn",
				"internal.user.token":   "secret-token",
			},
		},
		Mounts: []container.MountPoint{
			{
				Type:        "volume",
				Name:        "vol-data",
				Source:      "/var/lib/docker/volumes/vol-data/_data", // Host path
				Destination: "/app/data",
				RW:          true,
			},
		},
		HostConfig: &container.HostConfig{
			Resources: container.Resources{
				Memory:   256 << 20,
				NanoCPUs: 1_000_000_000,
			},
		},
	}

	cFacts := projectContainerFacts(cResp)

	// Verify MountFact destination preserved, host Source path omitted
	if len(cFacts.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got: %d", len(cFacts.Mounts))
	}
	if cFacts.Mounts[0].Destination != "/app/data" || cFacts.Mounts[0].Name != "vol-data" {
		t.Errorf("unexpected mount facts: %#v", cFacts.Mounts[0])
	}

	// Verify label allowlist: only open-card.* labels preserved, internal.user.token dropped
	if len(cFacts.Labels) != 2 || cFacts.Labels["open-card.managed"] != "true" || cFacts.Labels["open-card.task-prefix"] != "acorn" {
		t.Errorf("unexpected filtered labels: %#v", cFacts.Labels)
	}

	// Verify JSON serialization does not contain passwords, tokens, commands, or host source paths
	cEncoded, err := json.Marshal(cFacts)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	cJSON := string(cEncoded)
	for _, forbidden := range []string{"secret-db-pass", "super-token", "entrypoint.sh", "/var/lib/docker", "internal.user.token"} {
		if strings.Contains(cJSON, forbidden) {
			t.Errorf("container facts JSON leaked forbidden item %q: %s", forbidden, cJSON)
		}
	}

	// Volume projection: verify Mountpoint is omitted
	vResp := &volume.Volume{
		Name:       "vol-data",
		Driver:     "local",
		Mountpoint: "/var/lib/docker/volumes/vol-data/_data",
		Labels: map[string]string{
			"open-card.managed": "true",
			"arbitrary.label":   "sensitive-value",
		},
	}
	vFacts := projectVolumeFacts(vResp)
	vEncoded, err := json.Marshal(vFacts)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	vJSON := string(vEncoded)
	if strings.Contains(vJSON, "/var/lib/docker") || strings.Contains(vJSON, "arbitrary.label") {
		t.Errorf("volume facts JSON leaked host mountpoint or arbitrary label: %s", vJSON)
	}
}

func TestIdentityResolutionAndMismatch(t *testing.T) {
	const canonicalID = "c0123456789abcde0123456789abcdef0123456789abcdef0123456789abcdef"
	cResp := &container.InspectResponse{
		ID:   canonicalID,
		Name: "/app-production-web",
	}

	// 1. Valid 12+ char hex prefix
	isHex, err := ValidateContainerIdentifier(canonicalID[:12])
	if err != nil || !isHex {
		t.Errorf("expected valid 12-char hex prefix, got isHex=%v, err=%v", isHex, err)
	}
	if err := MatchContainerIdentity(canonicalID[:12], isHex, cResp); err != nil {
		t.Errorf("expected matching identity for valid prefix, got: %v", err)
	}

	// 2. Reject short hex prefix (< 12 chars)
	_, err = ValidateContainerIdentifier(canonicalID[:11])
	if err == nil || !errors.Is(err, ErrInvalidIdentifier) {
		t.Errorf("expected ErrInvalidIdentifier for 11-char hex prefix, got: %v", err)
	}

	// 3. Exact legal container name
	isHex, err = ValidateContainerIdentifier("app-production-web")
	if err != nil || isHex {
		t.Errorf("expected valid container name, got isHex=%v, err=%v", isHex, err)
	}
	if err := MatchContainerIdentity("app-production-web", isHex, cResp); err != nil {
		t.Errorf("expected matching identity for exact name, got: %v", err)
	}

	// 4. Reject arbitrary name prefix matching
	if err := MatchContainerIdentity("app-prod", false, cResp); !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("expected ErrIdentityMismatch on partial name prefix, got: %v", err)
	}

	// 5. Malicious/non-canonical container response ID rejected (must be full 64-hex)
	maliciousResp := &container.InspectResponse{
		ID:   "../bad_id",
		Name: "/app-production-web",
	}
	if err := MatchContainerIdentity("app-production-web", false, maliciousResp); !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("expected ErrIdentityMismatch on malicious container ID, got: %v", err)
	}

	// 6. Image identity matching with distribution/reference and go-digest
	const configDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const manifestDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	imgResp := &image.InspectResponse{
		ID:          configDigest,
		RepoTags:    []string{"docker.io/library/redis:latest", "docker.io/library/redis:7.0"},
		RepoDigests: []string{"docker.io/library/redis@" + manifestDigest},
	}

	// 6a. Bare image config ID query matches resp.ID exactly
	parsedBare, err := ParseImageReference(configDigest)
	if err != nil || !parsedBare.isDigest {
		t.Fatalf("failed to parse bare config digest: %v", err)
	}
	if err := MatchImageIdentity(configDigest, parsedBare, imgResp); err != nil {
		t.Errorf("bare config digest match failed: %v", err)
	}

	// 6b. Named canonical reference matches full normalized RepoDigest
	canonicalRef := "redis@" + manifestDigest
	parsedCanonical, err := ParseImageReference(canonicalRef)
	if err != nil || !parsedCanonical.isDigest {
		t.Fatalf("failed to parse canonical image ref: %v", err)
	}
	if err := MatchImageIdentity(canonicalRef, parsedCanonical, imgResp); err != nil {
		t.Errorf("named canonical match failed: %v", err)
	}

	// 6c. Named canonical reference with wrong repo does NOT match
	wrongRepoRef := "otherrepo@" + manifestDigest
	parsedWrongRepo, err := ParseImageReference(wrongRepoRef)
	if err != nil {
		t.Fatalf("failed to parse wrong repo ref: %v", err)
	}
	if err := MatchImageIdentity(wrongRepoRef, parsedWrongRepo, imgResp); !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("expected ErrIdentityMismatch on wrong repo named digest, got: %v", err)
	}

	// 6d. Bare name "redis" resolves to latest and matches normalized RepoTags
	parsedBareName, err := ParseImageReference("redis")
	if err != nil || parsedBareName.isDigest {
		t.Fatalf("failed to parse bare name redis: %v", err)
	}
	if err := MatchImageIdentity("redis", parsedBareName, imgResp); err != nil {
		t.Errorf("bare name redis -> latest match failed: %v", err)
	}

	// 6e. Invalid repo prefix before @ rejected
	_, err = ParseImageReference("invalid$$repo@" + manifestDigest)
	if err == nil || !errors.Is(err, ErrInvalidIdentifier) {
		t.Errorf("expected ErrInvalidIdentifier for invalid repo before @, got: %v", err)
	}

	// 6f. Incomplete bare sha256: syntax rejected as ErrInvalidIdentifier (never reinterpreted as repo:tag)
	_, err = ParseImageReference("sha256:11111111")
	if err == nil || !errors.Is(err, ErrInvalidIdentifier) {
		t.Errorf("expected ErrInvalidIdentifier for incomplete bare sha256, got: %v", err)
	}

	// 7. Network identity match with valid canonical 64-hex ID
	const canonicalNetID = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	netResp := &network.Inspect{
		Network: network.Network{
			ID:   canonicalNetID,
			Name: "isolated-net",
		},
	}
	isNetHex, err := ValidateNetworkIdentifier(canonicalNetID[:16])
	if err != nil || !isNetHex {
		t.Fatalf("valid network prefix rejected: %v", err)
	}
	if err := MatchNetworkIdentity(canonicalNetID[:16], isNetHex, netResp); err != nil {
		t.Errorf("network prefix match failed: %v", err)
	}
	if err := MatchNetworkIdentity("isolated-net", false, netResp); err != nil {
		t.Errorf("network name match failed: %v", err)
	}
	if err := MatchNetworkIdentity("different-net", false, netResp); !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("expected ErrIdentityMismatch on network mismatch, got: %v", err)
	}

	// Malicious network response ID rejected
	maliciousNet := &network.Inspect{
		Network: network.Network{
			ID:   "net-short",
			Name: "isolated-net",
		},
	}
	if err := MatchNetworkIdentity("isolated-net", false, maliciousNet); !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("expected ErrIdentityMismatch on non-canonical network ID, got: %v", err)
	}

	// 8. Volume identity match
	volResp := &volume.Volume{Name: "data-volume"}
	if err := MatchVolumeIdentity("data-volume", volResp); err != nil {
		t.Errorf("expected volume name match, got: %v", err)
	}
	if err := MatchVolumeIdentity("wrong-volume", volResp); !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("expected ErrIdentityMismatch on volume mismatch, got: %v", err)
	}
}

func TestFixedErrorIdentities(t *testing.T) {
	tests := []struct {
		name     string
		inputErr error
		wantIs   error
	}{
		{"errdefs NotFound", cerrdefs.ErrNotFound, ErrNotFound},
		{"errdefs InvalidArgument", cerrdefs.ErrInvalidArgument, ErrInvalidParameter},
		{"errdefs Conflict", cerrdefs.ErrConflict, ErrConflict},
		{"errdefs Unavailable", cerrdefs.ErrUnavailable, ErrUnavailable},
		{"context Canceled", context.Canceled, context.Canceled},
		{"context DeadlineExceeded", context.DeadlineExceeded, context.DeadlineExceeded},
		{"custom sentinel ErrIdentityMismatch", ErrIdentityMismatch, ErrIdentityMismatch},
		{"unknown error", errors.New("internal daemon error"), ErrEngineError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapSDKError(tt.inputErr)
			if !errors.Is(got, tt.wantIs) {
				t.Errorf("mapSDKError(%v) = %v, want errors.Is %v", tt.inputErr, got, tt.wantIs)
			}
		})
	}

	// Boundary proof: wrapped error with confidential details must return fixed sentinel and not leak details
	wrappedSecretErr := fmt.Errorf("daemon token=SECRET_ACCESS_KEY_123 failed: %w", cerrdefs.ErrNotFound)
	mapped := mapSDKError(wrappedSecretErr)
	if !errors.Is(mapped, ErrNotFound) {
		t.Errorf("expected ErrNotFound for wrapped not-found, got: %v", mapped)
	}
	if strings.Contains(mapped.Error(), "SECRET_ACCESS_KEY") {
		t.Errorf("wrapped secret leaked through error mapping: %s", mapped.Error())
	}
}
